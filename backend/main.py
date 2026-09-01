"""FastAPI application for the SPECTRA-GUARD SOC prototype.

This backend exposes a small set of endpoints for device status, RF assessment,
firmware verification, network analysis, evidence fusion, alerts, and devices.
"""

from __future__ import annotations

import csv
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config import CAPTURE_SECONDS, CENTER_FREQ, LNA_GAIN, SAMPLE_RATE, VGA_GAIN
from backend.database import DATABASE_URL, SecurityAlert, SessionLocal, init_db, Device
from rf_monitoring.fft_analysis import (
    apply_window,
    compute_fft,
    compute_power_spectrum_db,
    detect_suspicious_peaks,
    downsample_spectrum,
)
from rf_monitoring.iq_loader import convert_to_complex, load_raw_iq
from backend.schemas import (
    AlertRecord,
    DeviceStatusResponse,
    DeviceProfileRequest,
    DeviceProfileResponse,
    FirmwareVerificationRequest,
    FirmwareVerificationResponse,
    FusionRequest,
    FusionResponse,
    HealthResponse,
    NetworkAnalysisRequest,
    NetworkAnalysisResponse,
    RFAnalysisRequest,
    RFAnalysisResponse,
    SystemStatusResponse,
)
from backend.services import (
    analyze_network_service,
    analyze_rf_capture,
    fuse_service,
    get_device_status,
    list_alerts,
    list_devices,
    verify_firmware_service,
)
from rf_monitoring.capture_rf import capture_iq_samples
from firmware_integrity.hash_verifier import calculate_sha256, load_trusted_hash, resolve_input_path, save_trusted_hash

# ML training/prediction utilities
from ml_engine.train_rf_model import (
    train_rf_isolation_forest,
    get_model_status as ml_get_model_status,
    predict_from_feature_row,
    predict_latest_from_csv,
)
import json

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
FIRMWARE_STATUS_PATH = PROJECT_ROOT / "firmware_integrity" / "latest_verification.json"
FIRMWARE_BASELINE_PATH = PROJECT_ROOT / "firmware_integrity" / "baselines" / "firmware_baselines.json"
NETWORK_EVENTS_DIR = PROJECT_ROOT / "data" / "network_events"
NETWORK_EVENTS_PATH = NETWORK_EVENTS_DIR / "network_event_history.csv"
HACKRF_INFO_PATH = Path(r"C:\Users\claim\radioconda\Library\bin\hackrf_info.exe")


def get_hackrf_status() -> str:
    """Run hackrf_info and return CONNECTED, DISCONNECTED, or ERROR."""
    if not HACKRF_INFO_PATH.exists():
        return "ERROR"
    try:
        result = subprocess.run(
            [str(HACKRF_INFO_PATH)],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        combined = ((result.stdout or "") + "\n" + (result.stderr or "")).lower()
        if "found hackrf" in combined or "serial number" in combined:
            return "CONNECTED"
        elif "no hackrf" in combined or "hackrf_open" in combined or "no device" in combined or "no hackrf boards found" in combined:
            return "DISCONNECTED"
        else:
            return "ERROR"
    except subprocess.TimeoutExpired:
        return "ERROR"
    except Exception:
        return "ERROR"


class RFMonitorState:
    def __init__(self):
        self._lock = threading.Lock()
        self.hackrf_status = "DISCONNECTED"
        self.last_seen = None
        self.last_capture_time = None
        
        # Latest spectrum data
        self.spectrum_available = False
        self.source_file = None
        self.center_frequency = 433_000_000
        self.sample_rate = 10_000_000
        self.peak_frequency = None
        self.peak_power_db = None
        self.frequencies = []
        self.power_db = []
        
        # Anomalies & features
        self.noise_floor_db = None
        self.threshold_db = None
        self.anomaly_count = 0
        self.anomalies = []
        
        # ML & Risk state
        self.rf_risk_result = None

    def update_status(self, status: str):
        with self._lock:
            self.hackrf_status = status
            if status == "CONNECTED":
                self.last_seen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def update_capture(self, spectrum_data: dict, anomalies_data: dict, risk_result: dict, source_file: str):
        with self._lock:
            self.spectrum_available = True
            self.last_capture_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.source_file = source_file
            self.center_frequency = spectrum_data.get("center_frequency", 433_000_000)
            self.sample_rate = spectrum_data.get("sample_rate", 10_000_000)
            self.peak_frequency = spectrum_data.get("peak_frequency")
            self.peak_power_db = spectrum_data.get("peak_power_db")
            self.frequencies = spectrum_data.get("frequencies", [])
            self.power_db = spectrum_data.get("power_db", [])
            
            self.noise_floor_db = anomalies_data.get("noise_floor_db")
            self.threshold_db = anomalies_data.get("threshold_db")
            self.anomaly_count = anomalies_data.get("anomaly_count", 0)
            self.anomalies = anomalies_data.get("anomalies", [])
            
            self.rf_risk_result = risk_result

    def mark_unavailable(self):
        with self._lock:
            self.spectrum_available = False

    def get_state(self) -> dict:
        with self._lock:
            return {
                "hackrf_status": self.hackrf_status,
                "last_seen": self.last_seen,
                "last_capture_time": self.last_capture_time,
                "spectrum_available": self.spectrum_available,
                "source_file": self.source_file,
                "center_frequency": self.center_frequency,
                "sample_rate": self.sample_rate,
                "peak_frequency": self.peak_frequency,
                "peak_power_db": self.peak_power_db,
                "frequencies": self.frequencies,
                "power_db": self.power_db,
                "noise_floor_db": self.noise_floor_db,
                "threshold_db": self.threshold_db,
                "anomaly_count": self.anomaly_count,
                "anomalies": self.anomalies,
                "rf_risk_result": self.rf_risk_result
            }


rf_state = RFMonitorState()
hackrf_lock = threading.Lock()


def _load_firmware_baselines() -> dict[str, Any]:
    """Load the enrollment record for trusted firmware baselines."""
    if not FIRMWARE_BASELINE_PATH.exists():
        return {"devices": {}}
    try:
        with FIRMWARE_BASELINE_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"devices": {}}
    if not isinstance(data, dict):
        return {"devices": {}}
    devices = data.get("devices", {})
    if not isinstance(devices, dict):
        return {"devices": {}}
    return {"devices": devices}


def _save_firmware_baselines(data: dict[str, Any]) -> None:
    """Persist the firmware baseline registry."""
    FIRMWARE_BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with FIRMWARE_BASELINE_PATH.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def _normalize_firmware_status(raw_status: str | None) -> str:
    """Map internal verifier statuses to the supported public firmware states."""
    value = str(raw_status or "ERROR").upper()
    if value == "VERIFIED":
        return "VERIFIED"
    if value == "MISMATCH":
        return "MODIFIED"
    if value in {"NO_BASELINE", "NONE"}:
        return "NO_BASELINE"
    if value in {"FILE_NOT_FOUND", "NOT_FOUND"}:
        return "FILE_NOT_FOUND"
    return "ERROR"


def _load_latest_firmware_state() -> dict[str, Any] | None:
    """Load the latest cached firmware verification result if it exists."""
    if not FIRMWARE_STATUS_PATH.exists():
        return None

    try:
        with FIRMWARE_STATUS_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(data, dict):
        return None
    return data


def _save_latest_firmware_state(result: dict[str, Any]) -> dict[str, Any]:
    """Persist the latest firmware verification result for faster dashboard polling."""
    FIRMWARE_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with FIRMWARE_STATUS_PATH.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    return result


def _normalize_network_risk(score: float | int) -> str:
    """Map a numeric network risk score to a public level."""
    value = float(score)
    if value <= 19:
        return "NORMAL"
    if value <= 39:
        return "LOW"
    if value <= 69:
        return "MEDIUM"
    return "HIGH"


def _normalize_device_risk_level(score: float | int) -> str:
    """Map a final device risk score to the unified security posture level."""
    value = float(score)
    if value <= 19:
        return "NORMAL"
    if value <= 39:
        return "LOW"
    if value <= 69:
        return "MEDIUM"
    return "HIGH"


def _latest_network_capture_path() -> Path | None:
    """Find the newest packet capture or packet log in the passive network directory."""
    base_dir = PROJECT_ROOT / "data" / "network"
    if not base_dir.exists():
        return None

    candidates = sorted(
        [
            *base_dir.glob("*.csv"),
            *base_dir.glob("*.pcap"),
            *base_dir.glob("*.pcapng"),
            *base_dir.glob("*.log"),
        ],
        key=lambda path: path.stat().st_mtime,
    )
    if not candidates:
        return None
    return candidates[-1]


def _load_network_events() -> list[dict[str, Any]]:
    """Return stored network events as dictionaries."""
    if not NETWORK_EVENTS_PATH.exists():
        return []
    with NETWORK_EVENTS_PATH.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    return rows


def _save_network_event(event: dict[str, Any]) -> dict[str, Any]:
    """Persist a passive network analysis result in CSV form for dashboard polling."""
    NETWORK_EVENTS_DIR.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "event_id",
        "timestamp",
        "device_id",
        "source_file",
        "network_risk_score",
        "network_risk_level",
        "anomaly_score",
        "reasons",
        "status",
    ]

    rows = _load_network_events()
    if any(
        row.get("source_file") == event.get("source_file")
        and row.get("network_risk_score") == str(event.get("network_risk_score", 0))
        for row in rows
    ):
        return event

    rows.append(event)
    with NETWORK_EVENTS_PATH.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return event


def _evaluate_network_path(device_id: str, capture_path: str | Path) -> dict[str, Any]:
    """Analyze a passive network capture and return a structured result."""
    result = analyze_network_service(str(device_id), str(capture_path))
    risk_score = int(result.get("network_risk_score", 0))
    risk_level = _normalize_network_risk(risk_score)
    reason_text = " | ".join(result.get("reasons") or ["No suspicious network activity detected."])
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device_id": str(device_id),
        "source_file": str(capture_path),
        "network_risk_score": risk_score,
        "network_risk_level": risk_level,
        "anomaly_score": int(result.get("network_anomaly_score", 0)),
        "reasons": reason_text,
        "status": "PASSIVE_MONITOR",
    }
    _save_network_event(event)

    return {
        "status": "SUCCESS",
        "device_id": str(device_id),
        "source_file": str(capture_path),
        "network_risk_score": risk_score,
        "network_risk_level": risk_level,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "network_anomaly_score": int(result.get("network_anomaly_score", 0)),
        "features": result.get("features", {}),
        "reasons": result.get("reasons") or ["No suspicious network activity detected."],
        "timestamp": event["timestamp"],
    }


def detect_hackrf() -> dict[str, Any]:
    """Run hackrf_info and return a structured status, serial, and firmware version."""
    if not HACKRF_INFO_PATH.exists():
        return {
            "hackrf_status": "ERROR",
            "hackrf_serial": None,
            "hackrf_firmware": None,
        }

    try:
        result = subprocess.run(
            [str(HACKRF_INFO_PATH)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {
            "hackrf_status": "ERROR",
            "hackrf_serial": None,
            "hackrf_firmware": None,
        }

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    combined = output.lower()

    serial = None
    firmware = None

    serial_match = re.search(r"serial\s*(?:number)?\s*[:=]?\s*([A-Za-z0-9-]+)", output, flags=re.IGNORECASE)
    if serial_match:
        serial = serial_match.group(1).strip()

    firmware_match = re.search(r"firmware\s*(?:version)?\s*[:=]?\s*([0-9A-Za-z_.-]+)", output, flags=re.IGNORECASE)
    if firmware_match:
        firmware = firmware_match.group(1).strip()

    if "found hackrf" in combined:
        status = "CONNECTED"
    elif "hackrf" in combined or "libusb" in combined:
        status = "DISCONNECTED"
    else:
        status = "ERROR"

    return {
        "hackrf_status": status,
        "hackrf_serial": serial,
        "hackrf_firmware": firmware,
    }


def _determine_overall_severity(anomaly_count: int, highest_severity: str | None = None) -> str:
    """Map anomaly counts and severity to a coarse event level."""
    if anomaly_count == 0:
        return "NONE"
    if highest_severity == "HIGH":
        return "HIGH"
    if highest_severity == "MEDIUM":
        return "MEDIUM"
    if highest_severity == "LOW":
        return "LOW"
    return "NONE"


def _save_rf_feature_record(spectrum: dict[str, Any]) -> dict[str, Any]:
    """Save a single feature record for the newest capture and avoid duplicates by source file."""
    if spectrum.get("status") != "SUCCESS":
        return spectrum

    anomalies = detect_suspicious_peaks(np.asarray(spectrum["frequencies"], dtype=float), np.asarray(spectrum["power_db"], dtype=float))
    noise_floor_db = float(anomalies["noise_floor_db"])
    threshold_db = float(anomalies["threshold_db"])
    strongest_peak = anomalies["anomalies"][0] if anomalies["anomalies"] else None
    peak_frequency_hz = float(spectrum["peak_frequency"])
    peak_power_db = float(spectrum["peak_power_db"])
    peak_delta_db = float(peak_power_db - noise_floor_db) if strongest_peak is None else float(strongest_peak["difference_from_noise_db"])

    feature_record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_file": Path(spectrum["source_file"]).name if spectrum.get("source_file") else "unknown",
        "center_frequency_hz": float(spectrum["center_frequency"]),
        "sample_rate_hz": float(spectrum["sample_rate"]),
        "noise_floor_db": noise_floor_db,
        "threshold_db": threshold_db,
        "peak_frequency_hz": peak_frequency_hz,
        "peak_power_db": peak_power_db,
        "peak_delta_db": peak_delta_db,
        "anomaly_count": int(anomalies["anomaly_count"]),
        "mean_power_db": float(np.mean(np.asarray(spectrum["power_db"], dtype=float))),
        "std_power_db": float(np.std(np.asarray(spectrum["power_db"], dtype=float))),
        "max_power_db": float(np.max(np.asarray(spectrum["power_db"], dtype=float))),
        "min_power_db": float(np.min(np.asarray(spectrum["power_db"], dtype=float))),
        "occupied_bandwidth_hz": float(np.max(np.asarray(spectrum["frequencies"], dtype=float)) - np.min(np.asarray(spectrum["frequencies"], dtype=float))),
        "overall_severity": _determine_overall_severity(int(anomalies["anomaly_count"]), strongest_peak["severity"] if strongest_peak else None),
    }

    features_dir = PROJECT_ROOT / "data" / "rf_features"
    features_dir.mkdir(parents=True, exist_ok=True)
    csv_path = features_dir / "rf_feature_history.csv"
    fieldnames = [
        "timestamp",
        "source_file",
        "center_frequency_hz",
        "sample_rate_hz",
        "noise_floor_db",
        "threshold_db",
        "peak_frequency_hz",
        "peak_power_db",
        "peak_delta_db",
        "anomaly_count",
        "mean_power_db",
        "std_power_db",
        "max_power_db",
        "min_power_db",
        "occupied_bandwidth_hz",
        "overall_severity",
    ]

    existing_rows: list[dict[str, Any]] = []
    if csv_path.exists():
        with csv_path.open("r", newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            existing_rows = list(reader)

    if any(row.get("source_file") == feature_record["source_file"] for row in existing_rows):
        return feature_record

    existing_rows.append(feature_record)
    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(existing_rows)

    logs_dir = PROJECT_ROOT / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    with (logs_dir / "rf_feature_log.txt").open("a", encoding="utf-8") as log_file:
        log_file.write(f"{feature_record['timestamp']} | {feature_record['source_file']} | {feature_record['anomaly_count']} | {feature_record['overall_severity']}\n")

    return feature_record


def _save_rf_alert(risk_result: dict[str, Any]) -> dict[str, Any]:
    """Persist an RF alert into data/alerts/rf_alert_history.csv while avoiding duplicates.

    The risk_result should contain keys: source_file, risk_level, risk_score, threshold_severity,
    ml_classification, ml_anomaly_score, and reasons.
    """
    alerts_dir = PROJECT_ROOT / "data" / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    csv_path = alerts_dir / "rf_alert_history.csv"

    fieldnames = [
        "alert_id",
        "timestamp",
        "source_file",
        "category",
        "risk_score",
        "severity",
        "threshold_severity",
        "ml_classification",
        "ml_anomaly_score",
        "title",
        "description",
        "status",
    ]

    # Load existing rows to prevent duplicates for same source_file + risk_level
    existing = []
    if csv_path.exists():
        with csv_path.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            existing = list(reader)

    # Duplicate rule: source_file + severity (risk_level)
    src = risk_result.get("source_file")
    sev = risk_result.get("risk_level")
    if any((r.get("source_file") == src and r.get("severity") == sev) for r in existing):
        return {"status": "SKIPPED", "reason": "duplicate_alert"}

    alert_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    title = "Abnormal RF Activity Detected"
    description = (
        "RF activity deviated from the learned baseline and exceeded the configured detection threshold."
    )

    row = {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "source_file": src,
        "category": "RF_ANOMALY",
        "risk_score": int(risk_result.get("risk_score", 0)),
        "severity": sev,
        "threshold_severity": risk_result.get("threshold_severity"),
        "ml_classification": risk_result.get("ml_classification"),
        "ml_anomaly_score": risk_result.get("ml_anomaly_score"),
        "title": title,
        "description": description,
        "status": "OPEN",
    }

    # Append and write back
    existing.append(row)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(existing)

    return {"status": "SAVED", "alert_id": alert_id}


def _save_device_alert(device_record: dict[str, Any]) -> dict[str, Any] | None:
    """Persist a correlated device-level SOC alert when the unified risk is significant."""
    device_level = str(device_record.get("device_risk_level", "NORMAL")).upper()
    if device_level not in {"MEDIUM", "HIGH"}:
        return None

    alerts_dir = PROJECT_ROOT / "data" / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    csv_path = alerts_dir / "device_alert_history.csv"

    fieldnames = [
        "alert_id",
        "timestamp",
        "device_id",
        "category",
        "risk_score",
        "severity",
        "rf_risk_level",
        "firmware_status",
        "network_risk_level",
        "title",
        "description",
        "status",
    ]

    existing: list[dict[str, Any]] = []
    if csv_path.exists():
        with csv_path.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            existing = list(reader)

    device_id = str(device_record.get("device_id") or "unknown")
    evidence_signature = (
        device_id,
        device_level,
        int(device_record.get("device_risk_score", 0)),
        str(device_record.get("rf_risk_level", "NORMAL")).upper(),
        str(device_record.get("firmware_status", "NO_BASELINE")).upper(),
        str(device_record.get("network_risk_level", "NORMAL")).upper(),
    )
    if any(
        row.get("device_id") == device_id
        and row.get("severity") == device_level
        and int(row.get("risk_score", 0)) == int(device_record.get("device_risk_score", 0))
        and row.get("rf_risk_level") == str(device_record.get("rf_risk_level", "NORMAL")).upper()
        and row.get("firmware_status") == str(device_record.get("firmware_status", "NO_BASELINE")).upper()
        and row.get("network_risk_level") == str(device_record.get("network_risk_level", "NORMAL")).upper()
        for row in existing
    ):
        return {"status": "SKIPPED", "reason": "duplicate_device_alert"}

    alert_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    title = "Multiple security signals require investigation"
    description = (
        "Multiple security signals require investigation. "
        f"RF={str(device_record.get('rf_risk_level', 'NORMAL')).upper()}, "
        f"Firmware={str(device_record.get('firmware_status', 'NO_BASELINE')).upper()}, "
        f"Network={str(device_record.get('network_risk_level', 'NORMAL')).upper()}."
    )
    row = {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "device_id": device_id,
        "category": "DEVICE_SECURITY_RISK",
        "risk_score": int(device_record.get("device_risk_score", 0)),
        "severity": device_level,
        "rf_risk_level": str(device_record.get("rf_risk_level", "NORMAL")).upper(),
        "firmware_status": str(device_record.get("firmware_status", "NO_BASELINE")).upper(),
        "network_risk_level": str(device_record.get("network_risk_level", "NORMAL")).upper(),
        "title": title,
        "description": description,
        "status": "OPEN",
    }
    existing.append(row)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(existing)

    db = SessionLocal()
    try:
        alert = SecurityAlert(
            alert_id=alert_id,
            device_id=device_id,
            category="DEVICE_SECURITY_RISK",
            timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
            risk_level=device_level,
            overall_risk=float(device_record.get("device_risk_score", 0)),
            rf_risk_level=str(device_record.get("rf_risk_level", "NORMAL")).upper(),
            firmware_status=str(device_record.get("firmware_status", "NO_BASELINE")).upper(),
            network_risk_level=str(device_record.get("network_risk_level", "NORMAL")).upper(),
            reasons=" | ".join(device_record.get("reasons") or []),
            title=title,
            description=description,
            recommendation="Multiple security signals require investigation.",
            status="OPEN",
        )
        db.add(alert)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    return {"status": "SAVED", "alert_id": alert_id}


def get_latest_spectrum_data() -> dict[str, Any]:
    """Load the newest HackRF capture and compute its FFT power spectrum."""
    rf_raw_dir = PROJECT_ROOT / "data" / "rf_raw"
    captures = sorted(rf_raw_dir.glob("hackrf_capture_*.iq"))
    if not captures:
        return {
            "status": "ERROR",
            "error": "No HackRF capture file was found under data/rf_raw.",
            "source_file": None,
            "center_frequency": CENTER_FREQ,
            "sample_rate": SAMPLE_RATE,
            "peak_frequency": None,
            "peak_power_db": None,
            "frequencies": [],
            "power_db": [],
        }

    latest_capture = captures[-1]
    try:
        samples = load_raw_iq(latest_capture)
    except Exception as exc:
        return {
            "status": "ERROR",
            "error": f"Invalid IQ file: {exc}",
            "source_file": str(latest_capture),
            "center_frequency": CENTER_FREQ,
            "sample_rate": SAMPLE_RATE,
            "peak_frequency": None,
            "peak_power_db": None,
            "frequencies": [],
            "power_db": [],
        }

    if samples.shape[0] < 4096:
        return {
            "status": "ERROR",
            "error": "Insufficient IQ samples for spectrum analysis.",
            "source_file": str(latest_capture),
            "center_frequency": CENTER_FREQ,
            "sample_rate": SAMPLE_RATE,
            "peak_frequency": None,
            "peak_power_db": None,
            "frequencies": [],
            "power_db": [],
        }

    complex_signal = convert_to_complex(samples)
    signal_window = apply_window(complex_signal[:131072])
    freqs, fft_values = compute_fft(signal_window, sample_rate=float(SAMPLE_RATE))
    fft_shifted = np.fft.fftshift(fft_values)
    freqs_shifted = np.fft.fftshift(freqs)
    absolute_freqs = CENTER_FREQ + freqs_shifted
    power_db = compute_power_spectrum_db(fft_shifted)

    if power_db.size == 0:
        return {
            "status": "ERROR",
            "error": "FFT produced no power data.",
            "source_file": str(latest_capture),
            "center_frequency": CENTER_FREQ,
            "sample_rate": SAMPLE_RATE,
            "peak_frequency": None,
            "peak_power_db": None,
            "frequencies": [],
            "power_db": [],
        }

    min_frequency = float(np.min(absolute_freqs))
    max_frequency = float(np.max(absolute_freqs))
    expected_min = CENTER_FREQ - (SAMPLE_RATE / 2.0) - 1000.0
    expected_max = CENTER_FREQ + (SAMPLE_RATE / 2.0) + 1000.0
    if not (expected_min <= min_frequency <= expected_max and expected_min <= max_frequency <= expected_max):
        return {
            "status": "ERROR",
            "error": (
                "Invalid FFT frequency axis detected: expected approximately "
                f"{expected_min} Hz to {expected_max} Hz for center frequency {CENTER_FREQ} Hz, "
                f"but observed {min_frequency} Hz to {max_frequency} Hz."
            ),
            "source_file": str(latest_capture),
            "center_frequency": CENTER_FREQ,
            "sample_rate": SAMPLE_RATE,
            "peak_frequency": None,
            "peak_power_db": None,
            "frequencies": [],
            "power_db": [],
        }

    freqs_down, power_down = downsample_spectrum(absolute_freqs, power_db, target_points=1200)
    peak_index = int(np.argmax(power_down))
    peak_frequency = float(freqs_down[peak_index])
    peak_power_db = float(power_down[peak_index])

    return {
        "status": "SUCCESS",
        "source_file": str(latest_capture),
        "center_frequency": CENTER_FREQ,
        "sample_rate": SAMPLE_RATE,
        "peak_frequency": peak_frequency,
        "peak_power_db": peak_power_db,
        "frequencies": [float(value) for value in freqs_down.tolist()],
        "power_db": [float(value) for value in power_down.tolist()],
    }


app = FastAPI(title="SPECTRA-GUARD", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="dashboard_static")


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    """Return a consistent JSON payload for handled API errors."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "ERROR",
            "module": "API",
            "message": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    """Ensure unexpected failures return structured JSON rather than a generic HTML error."""
    return JSONResponse(
        status_code=500,
        content={
            "status": "ERROR",
            "module": "API",
            "message": str(exc),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )


@app.get("/", include_in_schema=False)
def dashboard_root() -> FileResponse:
    """Serve the dashboard landing page from the FastAPI app root."""
    return FileResponse(DASHBOARD_DIR / "index.html")


def _health_state_from_bool(passed: bool, *, warning_on_false: bool = False) -> str:
    """Normalize booleans into the demo health states."""
    if passed:
        return "OK"
    if warning_on_false:
        return "WARNING"
    return "ERROR"


def _check_dashboard_files() -> tuple[str, dict[str, Any]]:
    """Check whether the static dashboard files are present."""
    root_file = DASHBOARD_DIR / "index.html"
    js_file = DASHBOARD_DIR / "dashboard.js"
    css_file = DASHBOARD_DIR / "style.css"
    missing = [name for name, path in {"index.html": root_file, "dashboard.js": js_file, "style.css": css_file}.items() if not path.exists()]
    if missing:
        return "ERROR", {"missing_files": missing}
    return "OK", {"files_present": ["index.html", "dashboard.js", "style.css"]}


def _check_model_status() -> tuple[str, dict[str, Any]]:
    """Check whether the RF model is trained and ready without running expensive inference."""
    status = ml_get_model_status()
    model_ok = bool(status.get("model_exists")) and status.get("model_status") == "TRAINED"
    if model_ok:
        return "OK", status
    return "WARNING", status


def _check_firmware_baseline_status() -> tuple[str, dict[str, Any]]:
    """Check whether any baseline exists and whether the latest verification record is available."""
    baselines = _load_firmware_baselines()
    devices = baselines.get("devices") or {}
    latest = _load_latest_firmware_state() or {}
    has_baseline = bool(devices)
    has_latest = bool(latest.get("firmware_status"))
    if has_baseline:
        return "OK", {"device_count": len(devices), "latest_status": latest.get("firmware_status") if has_latest else None}
    return "WARNING", {"device_count": 0, "latest_status": latest.get("firmware_status") if has_latest else None}


def _check_database_status() -> tuple[str, dict[str, Any]]:
    """Verify the SQLite database file and core table presence without a heavy workload."""
    db_path = Path(DATABASE_URL.replace("sqlite:///", ""))
    if not db_path.exists():
        return "ERROR", {"db_path": str(db_path), "exists": False}
    try:
        connection = sqlite3.connect(str(db_path))
        tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
        connection.close()
    except Exception as exc:  # pragma: no cover - defensive failure handling
        return "ERROR", {"db_path": str(db_path), "exists": True, "error": str(exc)}
    return "OK", {"db_path": str(db_path), "exists": True, "tables": [table[0] for table in tables]}


def _check_rf_pipeline_status() -> tuple[str, dict[str, Any]]:
    """Lightweight RF pipeline viability check without performing an FFT capture."""
    rf_raw_dir = PROJECT_ROOT / "data" / "rf_raw"
    captures = sorted(rf_raw_dir.glob("hackrf_capture_*.iq"))
    if captures:
        return "OK", {"capture_count": len(captures), "latest_capture": str(captures[-1])}
    return "WARNING", {"capture_count": 0, "latest_capture": None}


def _check_hackrf_status() -> tuple[str, dict[str, Any]]:
    """Return a non-blocking HackRF availability check."""
    path_exists = HACKRF_INFO_PATH.exists()
    if not path_exists:
        return "WARNING", {"tool_path": str(HACKRF_INFO_PATH), "device_detected": False, "message": "HackRF tool not installed"}
    result = detect_hackrf()
    device_ok = result.get("hackrf_status") == "CONNECTED"
    if device_ok:
        return "OK", {"tool_path": str(HACKRF_INFO_PATH), "device_detected": True, "details": result}
    return "WARNING", {"tool_path": str(HACKRF_INFO_PATH), "device_detected": False, "details": result}


def _log_startup_validation() -> None:
    """Log lightweight startup validation details so the app can report degraded health cleanly."""
    print(f"[startup] Python version: {sys.version.split()[0]}")
    print(f"[startup] Project root: {PROJECT_ROOT}")
    print(f"[startup] HackRF executable path: {HACKRF_INFO_PATH}")
    model_status = ml_get_model_status()
    print(f"[startup] Model status: {model_status}")
    baseline_status = _check_firmware_baseline_status()
    print(f"[startup] Firmware baseline status: {baseline_status[1]}")
    database_status = _check_database_status()
    print(f"[startup] Database status: {database_status[1]}")
    dashboard_status = _check_dashboard_files()
    print(f"[startup] Dashboard files: {dashboard_status[1]}")


rf_monitor_running = True
rf_monitor_thread = None


def rf_monitor_loop() -> None:
    """Background monitoring loop that runs every 3 seconds to check and capture RF data."""
    print("[RFMonitor] Background thread starting.")
    while rf_monitor_running:
        try:
            status = get_hackrf_status()
            rf_state.update_status(status)
            
            if status != "CONNECTED":
                rf_state.mark_unavailable()
                time.sleep(3)
                continue
            
            with hackrf_lock:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                output_dir = PROJECT_ROOT / "data" / "rf_raw"
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / f"hackrf_realtime_{timestamp}.iq"
                
                try:
                    # capture duration = 1 second
                    # center frequency = 433000000 Hz
                    # sample rate = 10000000
                    # LNA = 24
                    # VGA = 20
                    saved_path = capture_iq_samples(
                        output_file=output_path,
                        center_freq=433_000_000,
                        sample_rate=10_000_000,
                        lna_gain=24,
                        vga_gain=20,
                        duration_seconds=1,
                        timeout=5,
                    )
                except Exception as capture_err:
                    print(f"[RFMonitor] Capture failed: {capture_err}")
                    rf_state.mark_unavailable()
                    if output_path.exists():
                        try:
                            output_path.unlink()
                        except Exception:
                            pass
                    time.sleep(3)
                    continue

                # Clean up old realtime capture files, keeping only the latest 5
                try:
                    realtime_files = sorted(
                        list(output_dir.glob("hackrf_realtime_*.iq")),
                        key=lambda p: p.stat().st_mtime
                    )
                    if len(realtime_files) > 5:
                        for old_file in realtime_files[:-5]:
                            try:
                                old_file.unlink()
                                print(f"[RFMonitor] Deleted old capture file: {old_file.name}")
                            except Exception as del_err:
                                print(f"[RFMonitor] Error deleting old capture: {del_err}")
                except Exception as cleanup_err:
                    print(f"[RFMonitor] Cleanup error: {cleanup_err}")

                # Run FFT processing
                try:
                    samples = load_raw_iq(saved_path)
                    if samples.shape[0] < 4096:
                        raise ValueError("Insufficient samples for analysis")
                        
                    complex_signal = convert_to_complex(samples)
                    signal_window = apply_window(complex_signal[:131072])
                    freqs, fft_values = compute_fft(signal_window, sample_rate=10_000_000.0)
                    fft_shifted = np.fft.fftshift(fft_values)
                    freqs_shifted = np.fft.fftshift(freqs)
                    absolute_freqs = 433_000_000 + freqs_shifted
                    power_db = compute_power_spectrum_db(fft_shifted)
                    
                    if power_db.size == 0:
                        raise ValueError("FFT produced no power data.")
                        
                    freqs_down, power_down = downsample_spectrum(absolute_freqs, power_db, target_points=1200)
                    peak_index = int(np.argmax(power_down))
                    peak_frequency = float(freqs_down[peak_index])
                    peak_power_db = float(power_down[peak_index])
                    
                    spectrum_data = {
                        "center_frequency": 433_000_000,
                        "sample_rate": 10_000_000,
                        "peak_frequency": peak_frequency,
                        "peak_power_db": peak_power_db,
                        "frequencies": [float(v) for v in freqs_down.tolist()],
                        "power_db": [float(v) for v in power_down.tolist()],
                    }
                    
                    # 2. Run existing threshold anomaly analysis
                    anomalies_data = detect_suspicious_peaks(freqs_down, power_down)
                    
                    # Log features to CSV via _save_rf_feature_record
                    spectrum_for_saving = {
                        "status": "SUCCESS",
                        "source_file": str(saved_path),
                        "center_frequency": 433_000_000,
                        "sample_rate": 10_000_000,
                        "peak_frequency": peak_frequency,
                        "peak_power_db": peak_power_db,
                        "frequencies": freqs_down.tolist(),
                        "power_db": power_down.tolist()
                    }
                    _save_rf_feature_record(spectrum_for_saving)
                    
                    # 3. Run ML classification
                    features_resp = api_rf_features_latest()
                    ml_classification = "UNKNOWN"
                    ml_anomaly_score = None
                    if features_resp.get("status") == "SUCCESS" and features_resp.get("record"):
                        record = features_resp["record"]
                        feature_row = {
                            "noise_floor_db": record.get("noise_floor_db"),
                            "peak_power_db": record.get("peak_power_db"),
                            "peak_delta_db": record.get("peak_delta_db"),
                            "anomaly_count": record.get("anomaly_count"),
                            "mean_power_db": record.get("mean_power_db"),
                            "std_power_db": record.get("std_power_db"),
                            "max_power_db": record.get("max_power_db"),
                            "min_power_db": record.get("min_power_db"),
                            "occupied_bandwidth_hz": record.get("occupied_bandwidth_hz"),
                        }
                        pred = predict_from_feature_row(feature_row)
                        if pred.get("status") == "SUCCESS":
                            ml_classification = "NORMAL" if pred["prediction"] == 1 else "ANOMALOUS"
                            ml_anomaly_score = float(pred["anomaly_score"])
                            
                    # 4. Calculate consolidated RF risk score
                    threshold_anomaly_count = int(anomalies_data.get("anomaly_count", 0))
                    anomalies = anomalies_data.get("anomalies", [])
                    threshold_severity = "NONE"
                    if anomalies:
                        severity_levels = [a.get("severity", "NONE") for a in anomalies]
                        if "HIGH" in severity_levels:
                            threshold_severity = "HIGH"
                        elif "MEDIUM" in severity_levels:
                            threshold_severity = "MEDIUM"
                        elif "LOW" in severity_levels:
                            threshold_severity = "LOW"
                    
                    score = 0
                    reasons = []
                    if threshold_severity == "NONE":
                        reasons.append("No threshold-based suspicious RF peaks detected")
                    elif threshold_severity == "LOW":
                        score += 20
                        reasons.append("Threshold detector: LOW severity suspicious peaks detected")
                    elif threshold_severity == "MEDIUM":
                        score += 40
                        reasons.append("Threshold detector: MEDIUM severity suspicious peaks detected")
                    elif threshold_severity == "HIGH":
                        score += 60
                        reasons.append("Threshold detector: HIGH severity suspicious peaks detected")
                        
                    if ml_classification == "NORMAL":
                        reasons.append("Isolation Forest classified the latest feature record as NORMAL")
                    elif ml_classification == "ANOMALOUS":
                        score += 30
                        reasons.append("Isolation Forest classified the latest feature record as ANOMALOUS")
                    else:
                        reasons.append("Isolation Forest result unavailable")
                        
                    if ml_anomaly_score is not None:
                        if ml_anomaly_score >= 0.10:
                            adj = 0
                        elif ml_anomaly_score >= 0.00:
                            adj = 5
                        else:
                            adj = 15
                        score += adj
                        reasons.append(f"ML anomaly score adjustment: {adj} points (score={ml_anomaly_score:.4f})")
                        
                    if score > 100:
                        score = 100
                        
                    risk_level = "NORMAL"
                    if score <= 19:
                        risk_level = "NORMAL"
                    elif score <= 39:
                        risk_level = "LOW"
                    elif score <= 69:
                        risk_level = "MEDIUM"
                    else:
                        risk_level = "HIGH"
                        
                    risk_result = {
                        "status": "SUCCESS",
                        "source_file": saved_path.name,
                        "threshold_anomaly_count": threshold_anomaly_count,
                        "threshold_severity": threshold_severity,
                        "ml_classification": ml_classification,
                        "ml_anomaly_score": ml_anomaly_score,
                        "risk_score": int(score),
                        "risk_level": risk_level,
                        "reasons": reasons,
                    }
                    
                    try:
                        if risk_level in ("MEDIUM", "HIGH"):
                            _save_rf_alert(risk_result)
                    except Exception as alert_err:
                        print(f"[RFMonitor] Failed to persist RF alert: {alert_err}")
                        
                    # Update global shared state
                    rf_state.update_capture(
                        spectrum_data=spectrum_data,
                        anomalies_data=anomalies_data,
                        risk_result=risk_result,
                        source_file=str(saved_path)
                    )
                except Exception as process_err:
                    print(f"[RFMonitor] Processing capture failed: {process_err}")
                    rf_state.mark_unavailable()
            
            time.sleep(3)
        except Exception as loop_err:
            print(f"[RFMonitor] Loop error: {loop_err}")
            time.sleep(3)
    print("[RFMonitor] Background thread stopped.")


@app.on_event("startup")
def startup_event() -> None:
    """Initialize the SQLite database and log the lightweight demo validation state."""
    init_db()
    _log_startup_validation()
    # Start background RF monitor thread
    global rf_monitor_running, rf_monitor_thread
    rf_monitor_running = True
    rf_monitor_thread = threading.Thread(target=rf_monitor_loop, daemon=True, name="RFMonitorThread")
    rf_monitor_thread.start()


@app.on_event("shutdown")
def shutdown_event() -> None:
    """Clean shutdown of background threads."""
    global rf_monitor_running, rf_monitor_thread
    print("[shutdown] Stopping background RF monitor thread...")
    rf_monitor_running = False
    if rf_monitor_thread:
        rf_monitor_thread.join(timeout=5)
    print("[shutdown] Clean shutdown complete.")



@app.get("/health", response_model=HealthResponse)
def health() -> dict[str, str]:
    """Return a basic health status for the backend."""
    return {"status": "ok", "service": "SPECTRA-GUARD API"}


@app.get("/api/health")
def api_health() -> dict[str, Any]:
    """Return a lightweight, non-invasive system health summary for demo reliability."""
    backend_ok = True
    hackrf_tool_state, hackrf_tool_details = _check_hackrf_status()
    rf_pipeline_state, rf_pipeline_details = _check_rf_pipeline_status()
    model_state, model_details = _check_model_status()
    baseline_state, baseline_details = _check_firmware_baseline_status()
    latest_status_raw = _load_latest_firmware_state() or {}
    latest_status = str(latest_status_raw.get("firmware_status") or "NO_BASELINE").upper()
    database_state, database_details = _check_database_status()
    dashboard_state, dashboard_details = _check_dashboard_files()

    checks = {
        "backend": "OK" if backend_ok else "ERROR",
        "hackrf_tool_availability": hackrf_tool_state,
        "hackrf_device_detection": hackrf_tool_state,
        "rf_spectrum_pipeline": rf_pipeline_state,
        "ml_model_availability": model_state,
        "firmware_baseline_availability": baseline_state,
        "firmware_latest_status": _health_state_from_bool(latest_status in {"VERIFIED", "MODIFIED", "NO_BASELINE", "FILE_NOT_FOUND"}, warning_on_false=True),
        "network_monitor": "OK" if (PROJECT_ROOT / "data" / "network").exists() else "WARNING",
        "database": database_state,
        "dashboard_static_files": dashboard_state,
    }

    worst = "OK"
    for state in checks.values():
        if state == "ERROR":
            worst = "ERROR"
            break
        if state == "WARNING":
            worst = "WARNING"
    if worst == "OK" and any(v == "WARNING" for v in checks.values()):
        worst = "WARNING"

    return {
        "status": worst,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks": checks,
        "details": {
            "hackrf": hackrf_tool_details,
            "rf_pipeline": rf_pipeline_details,
            "ml_model": model_details,
            "firmware_baseline": baseline_details,
            "firmware_latest_status": latest_status_raw,
            "database": database_details,
            "dashboard": dashboard_details,
        },
    }


@app.get("/api/status", response_model=SystemStatusResponse)
def api_status() -> dict[str, Any]:
    """Return real HackRF detection plus other dashboard status values."""
    status = get_hackrf_status()
    rf_state.update_status(status)
    
    serial = None
    firmware = None
    if status == "CONNECTED":
        hackrf = detect_hackrf()
        serial = hackrf["hackrf_serial"]
        firmware = hackrf["hackrf_firmware"]
        
    state = rf_state.get_state()
    return {
        "system_status": "ONLINE",
        "hackrf_status": status,
        "hackrf_serial": serial,
        "hackrf_firmware": firmware,
        "ml_engine_status": "READY",
        "firmware_monitor_status": "ACTIVE",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": state["last_seen"],
        "last_capture_time": state["last_capture_time"]
    }


@app.get("/api/network/status")
def api_network_status() -> dict[str, Any]:
    """Return the latest passive network assessment for the monitored device."""
    capture_path = _latest_network_capture_path() or (PROJECT_ROOT / "data" / "network" / "sample_lab_traffic.csv")
    if not capture_path.exists():
        return {
            "status": "EMPTY",
            "device_id": "esp32_lab_device_01",
            "network_risk_score": 0,
            "network_risk_level": "NORMAL",
            "network_anomaly_score": 0,
            "reasons": ["No passive network capture has been loaded yet."],
            "source_file": str(capture_path),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    try:
        return _evaluate_network_path("esp32_lab_device_01", capture_path)
    except (FileNotFoundError, ValueError, ImportError) as exc:
        return {
            "status": "ERROR",
            "device_id": "esp32_lab_device_01",
            "network_risk_score": 0,
            "network_risk_level": "NORMAL",
            "network_anomaly_score": 0,
            "reasons": [f"Network analysis could not run: {exc}"],
            "source_file": str(capture_path),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


@app.get("/api/network/events")
def api_network_events() -> dict[str, Any]:
    """Return stored passive network events ordered newest-first."""
    rows = _load_network_events()
    if not rows:
        return {"status": "EMPTY", "events": []}

    events = []
    for row in reversed(rows):
        events.append(
            {
                "event_id": row.get("event_id"),
                "timestamp": row.get("timestamp"),
                "device_id": row.get("device_id"),
                "source_file": row.get("source_file"),
                "network_risk_score": int(row.get("network_risk_score", 0)),
                "network_risk_level": row.get("network_risk_level", "NORMAL"),
                "anomaly_score": int(row.get("anomaly_score", 0)),
                "reasons": row.get("reasons", "").split(" | ") if row.get("reasons") else [],
                "status": row.get("status", "PASSIVE_MONITOR"),
            }
        )
    return {"status": "SUCCESS", "events": events}


@app.get("/api/network/risk")
def api_network_risk() -> dict[str, Any]:
    """Run the passive network risk check and return the latest score."""
    capture_path = _latest_network_capture_path() or (PROJECT_ROOT / "data" / "network" / "sample_lab_traffic.csv")
    if not capture_path.exists():
        return {
            "status": "ERROR",
            "device_id": "esp32_lab_device_01",
            "network_risk_score": 0,
            "network_risk_level": "NORMAL",
            "network_anomaly_score": 0,
            "reasons": ["No passive network capture is available for evaluation."],
            "source_file": str(capture_path),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    try:
        result = _evaluate_network_path("esp32_lab_device_01", capture_path)
        return {
            "status": result["status"],
            "device_id": result["device_id"],
            "source_file": result["source_file"],
            "network_risk_score": result["network_risk_score"],
            "network_risk_level": result["network_risk_level"],
            "network_anomaly_score": result["network_anomaly_score"],
            "reasons": result["reasons"],
            "timestamp": result["timestamp"],
        }
    except (FileNotFoundError, ValueError, ImportError) as exc:
        return {
            "status": "ERROR",
            "device_id": "esp32_lab_device_01",
            "network_risk_score": 0,
            "network_risk_level": "NORMAL",
            "network_anomaly_score": 0,
            "reasons": [f"Unable to evaluate network risk: {exc}"],
            "source_file": str(capture_path),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


@app.get("/api/firmware/status")
def api_firmware_status() -> dict[str, Any]:
    """Return the latest cached firmware verification result for the dashboard."""
    cached = _load_latest_firmware_state()
    if cached:
        return {
            "status": "SUCCESS",
            "device_id": cached.get("device_id") or "unknown",
            "firmware_status": cached.get("firmware_status") or "NO_BASELINE",
            "current_hash": cached.get("current_hash"),
            "baseline_hash": cached.get("baseline_hash"),
            "checked_at": cached.get("checked_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "firmware_file": cached.get("firmware_file"),
        }

    default = {
        "status": "SUCCESS",
        "device_id": "esp32_lab_device_01",
        "firmware_status": "NO_BASELINE",
        "current_hash": None,
        "baseline_hash": None,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "firmware_file": None,
    }
    return default


@app.get("/api/device/risk")
def api_device_risk() -> dict[str, Any]:
    """Combine RF, network, and firmware posture into a single explainable device risk score."""
    rf_result = api_rf_risk()
    firmware_result = api_firmware_status()
    network_result = api_network_risk()

    rf_score = 0
    rf_level = "NORMAL"
    if rf_result.get("status") == "SUCCESS":
        rf_score = int(rf_result.get("risk_score", 0))
        rf_level = str(rf_result.get("risk_level", "NORMAL")).upper()

    network_score = 0
    network_level = "NORMAL"
    network_reasons: list[str] = []
    if network_result.get("status") == "SUCCESS":
        network_score = int(network_result.get("network_risk_score", 0))
        network_level = str(network_result.get("network_risk_level", "NORMAL")).upper()
        network_reasons = list(network_result.get("reasons") or [])
    else:
        network_reasons.append("Network risk information unavailable")

    firmware_status = str(firmware_result.get("firmware_status", "NO_BASELINE")).upper()
    device_id = str(firmware_result.get("device_id") or "esp32_01")
    firmware_risk_contribution = {
        "VERIFIED": 0,
        "NO_BASELINE": 15,
        "FILE_NOT_FOUND": 20,
        "ERROR": 25,
        "MODIFIED": 50,
    }.get(firmware_status, 0)

    device_score = min(100, rf_score + firmware_risk_contribution + network_score)
    device_level = _normalize_device_risk_level(device_score)

    reasons: list[str] = []
    if rf_result.get("status") == "SUCCESS":
        if rf_level == "NORMAL":
            reasons.append("RF behavior is within the learned baseline")
        else:
            reasons.append(f"RF behavior is outside the learned baseline ({rf_level})")
    else:
        reasons.append("RF risk information unavailable")

    if firmware_status == "VERIFIED":
        reasons.append("Firmware hash matches the trusted baseline")
    elif firmware_status == "NO_BASELINE":
        reasons.append("No trusted firmware baseline is enrolled for this device")
    elif firmware_status == "FILE_NOT_FOUND":
        reasons.append("Firmware file could not be found during verification")
    elif firmware_status == "ERROR":
        reasons.append("Firmware verification encountered an error")
    elif firmware_status == "MODIFIED":
        reasons.append("Firmware hash differs from the trusted baseline")

    if network_result.get("status") == "SUCCESS":
        if network_level == "NORMAL":
            reasons.append("Network behavior is consistent with the monitored lab baseline")
        elif network_level == "HIGH":
            reasons.append("Network behavior produced HIGH risk")
        else:
            reasons.append("Unexpected network destination detected")
    else:
        reasons.append("Network risk information unavailable")

    record = {
        "status": "SUCCESS",
        "device_id": device_id,
        "rf_risk_score": rf_score,
        "rf_risk_level": rf_level,
        "firmware_status": firmware_status,
        "firmware_risk_contribution": firmware_risk_contribution,
        "network_risk_score": network_score,
        "network_risk_level": network_level,
        "device_risk_score": device_score,
        "device_risk_level": device_level,
        "reasons": reasons,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if device_level in {"MEDIUM", "HIGH"}:
        try:
            _save_device_alert(record)
        except Exception as exc:  # pragma: no cover - alert persistence must not break the API
            print(f"Failed to persist device-level SOC alert: {exc}")

    return record


@app.post("/api/firmware/baseline")
def api_firmware_baseline(request: FirmwareVerificationRequest) -> dict[str, Any]:
    """Enroll a trusted firmware baseline for a device without overwriting an existing one."""
    resolved_path = resolve_input_path(request.firmware_path)
    if not resolved_path.exists():
        return {
            "status": "FILE_NOT_FOUND",
            "device_id": request.device_id,
            "firmware_file": request.firmware_path,
            "baseline_hash": None,
            "enrolled_at": None,
        }

    baseline_store = _load_firmware_baselines()
    devices = baseline_store.get("devices", {})
    if request.device_id in devices and isinstance(devices[request.device_id], dict):
        record = devices[request.device_id]
        return {
            "status": "BASELINE_ALREADY_EXISTS",
            "device_id": request.device_id,
            "baseline_hash": record.get("baseline_hash"),
            "firmware_file": record.get("firmware_file"),
            "enrolled_at": record.get("enrolled_at"),
        }

    if load_trusted_hash(request.device_id) is not None:
        return {
            "status": "BASELINE_ALREADY_EXISTS",
            "device_id": request.device_id,
            "baseline_hash": load_trusted_hash(request.device_id),
            "firmware_file": request.firmware_path,
            "enrolled_at": None,
        }

    baseline_hash = calculate_sha256(resolved_path)
    enrolled_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    save_trusted_hash(request.device_id, baseline_hash)
    devices[request.device_id] = {
        "device_id": request.device_id,
        "baseline_hash": baseline_hash,
        "firmware_file": str(request.firmware_path),
        "enrolled_at": enrolled_at,
    }
    _save_firmware_baselines({"devices": devices})

    _save_latest_firmware_state({
        "status": "SUCCESS",
        "device_id": request.device_id,
        "firmware_status": "VERIFIED",
        "current_hash": baseline_hash,
        "baseline_hash": baseline_hash,
        "checked_at": enrolled_at,
        "firmware_file": str(request.firmware_path),
    })

    return {
        "status": "SUCCESS",
        "device_id": request.device_id,
        "baseline_hash": baseline_hash,
        "firmware_file": str(request.firmware_path),
        "enrolled_at": enrolled_at,
    }


@app.post("/api/firmware/verify")
def api_verify_firmware(request: FirmwareVerificationRequest) -> dict[str, Any]:
    """Verify a firmware image against the trusted baseline and cache the latest result."""
    try:
        verification = verify_firmware_service(request.device_id, request.firmware_path)
    except FileNotFoundError:
        payload = {
            "status": "SUCCESS",
            "device_id": request.device_id,
            "firmware_status": "FILE_NOT_FOUND",
            "current_hash": None,
            "baseline_hash": None,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "firmware_file": request.firmware_path,
        }
        return _save_latest_firmware_state(payload)
    except Exception as exc:  # pragma: no cover - surfaces runtime validation errors cleanly.
        payload = {
            "status": "SUCCESS",
            "device_id": request.device_id,
            "firmware_status": "ERROR",
            "current_hash": None,
            "baseline_hash": None,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "firmware_file": request.firmware_path,
            "error": str(exc),
        }
        return _save_latest_firmware_state(payload)

    expected_hash = verification.get("expected_hash")
    raw_status = str(verification.get("status") or "ERROR").upper()
    normalized = {
        "status": "SUCCESS",
        "device_id": request.device_id,
        "firmware_status": _normalize_firmware_status(raw_status if raw_status not in {"MISMATCH"} else "MISMATCH"),
        "current_hash": verification.get("current_hash"),
        "baseline_hash": expected_hash,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "firmware_file": request.firmware_path,
    }
    if expected_hash is None:
        normalized["firmware_status"] = "NO_BASELINE"
    elif raw_status == "MISMATCH":
        normalized["firmware_status"] = "MODIFIED"
    elif raw_status == "VERIFIED":
        normalized["firmware_status"] = "VERIFIED"
    elif raw_status in {"FILE_NOT_FOUND", "NOT_FOUND"}:
        normalized["firmware_status"] = "FILE_NOT_FOUND"
    else:
        normalized["firmware_status"] = "ERROR"

    return _save_latest_firmware_state(normalized)


@app.get("/api/rf/spectrum")
def api_rf_spectrum() -> dict[str, Any]:
    """Return the newest HackRF capture's FFT-based spectrum summary."""
    state = rf_state.get_state()
    if state["hackrf_status"] == "DISCONNECTED":
        return {
            "status": "UNAVAILABLE",
            "hackrf_status": "DISCONNECTED",
            "message": "HackRF One is not connected"
        }

    if not state["spectrum_available"]:
        return {
            "status": "UNAVAILABLE",
            "hackrf_status": state["hackrf_status"],
            "message": "RF spectrum is not available yet"
        }

    try:
        captured_at_dt = datetime.fromisoformat(state["last_capture_time"])
        data_age_seconds = (datetime.now(timezone.utc) - captured_at_dt).total_seconds()
    except Exception:
        data_age_seconds = 0.0

    return {
        "status": "SUCCESS",
        "hackrf_status": state["hackrf_status"],
        "data_age_seconds": data_age_seconds,
        "source_file": state["source_file"],
        "captured_at": state["last_capture_time"],
        "center_frequency": state["center_frequency"],
        "sample_rate": state["sample_rate"],
        "peak_frequency": state["peak_frequency"],
        "peak_power_db": state["peak_power_db"],
        "frequencies": state["frequencies"],
        "power_db": state["power_db"]
    }


@app.get("/api/rf/features/latest")
def api_rf_features_latest() -> dict[str, Any]:
    """Return the most recent RF feature record for the newest capture."""
    features_dir = PROJECT_ROOT / "data" / "rf_features"
    csv_path = features_dir / "rf_feature_history.csv"
    if not csv_path.exists():
        return {"status": "EMPTY", "record": None}

    with csv_path.open("r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        rows = list(reader)

    if not rows:
        return {"status": "EMPTY", "record": None}

    latest_row = rows[-1]
    return {
        "status": "SUCCESS",
        "record": {
            "timestamp": latest_row.get("timestamp"),
            "source_file": latest_row.get("source_file"),
            "center_frequency_hz": float(latest_row.get("center_frequency_hz", 0.0)),
            "sample_rate_hz": float(latest_row.get("sample_rate_hz", 0.0)),
            "noise_floor_db": float(latest_row.get("noise_floor_db", 0.0)),
            "threshold_db": float(latest_row.get("threshold_db", 0.0)),
            "peak_frequency_hz": float(latest_row.get("peak_frequency_hz", 0.0)),
            "peak_power_db": float(latest_row.get("peak_power_db", 0.0)),
            "peak_delta_db": float(latest_row.get("peak_delta_db", 0.0)),
            "anomaly_count": int(latest_row.get("anomaly_count", 0)),
            "mean_power_db": float(latest_row.get("mean_power_db", 0.0)),
            "std_power_db": float(latest_row.get("std_power_db", 0.0)),
            "max_power_db": float(latest_row.get("max_power_db", 0.0)),
            "min_power_db": float(latest_row.get("min_power_db", 0.0)),
            "occupied_bandwidth_hz": float(latest_row.get("occupied_bandwidth_hz", 0.0)),
            "overall_severity": latest_row.get("overall_severity", "NONE"),
        },
    }


@app.get("/api/rf/events")
def api_rf_events() -> dict[str, Any]:
    """Return stored RF event records ordered newest-first."""
    features_dir = PROJECT_ROOT / "data" / "rf_features"
    csv_path = features_dir / "rf_feature_history.csv"
    if not csv_path.exists():
        return {"status": "EMPTY", "events": []}

    with csv_path.open("r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        rows = list(reader)

    events = []
    for row in reversed(rows):
        events.append(
            {
                "timestamp": row.get("timestamp"),
                "source_file": row.get("source_file"),
                "anomaly_count": int(row.get("anomaly_count", 0)),
                "strongest_peak_frequency_hz": float(row.get("peak_frequency_hz", 0.0)),
                "strongest_peak_power_db": float(row.get("peak_power_db", 0.0)),
                "noise_floor_db": float(row.get("noise_floor_db", 0.0)),
                "overall_severity": row.get("overall_severity", "NONE"),
            }
        )

    return {"status": "SUCCESS", "events": events}


@app.get("/api/alerts")
def api_alerts(severity: str | None = None) -> dict[str, Any]:
    """Return RF alerts ordered newest-first. Optional severity filter via query param."""
    alerts_dir = PROJECT_ROOT / "data" / "alerts"
    csv_path = alerts_dir / "rf_alert_history.csv"
    if not csv_path.exists():
        return {"status": "SUCCESS", "alerts": []}

    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    # Convert to proper types and newest-first
    alerts = []
    for row in reversed(rows):
        if severity and row.get("severity") != severity:
            continue
        alerts.append(
            {
                "alert_id": row.get("alert_id"),
                "timestamp": row.get("timestamp"),
                "source_file": row.get("source_file"),
                "category": row.get("category"),
                "risk_score": int(row.get("risk_score", 0)),
                "severity": row.get("severity"),
                "threshold_severity": row.get("threshold_severity"),
                "ml_classification": row.get("ml_classification"),
                "ml_anomaly_score": float(row.get("ml_anomaly_score")) if row.get("ml_anomaly_score") not in (None, "") else None,
                "title": row.get("title"),
                "description": row.get("description"),
                "status": row.get("status"),
            }
        )

    return {"status": "SUCCESS", "alerts": alerts}


@app.get("/api/alerts/simulate")
def api_alerts_simulate(risk_level: str = "MEDIUM") -> dict[str, Any]:
    """Internal test endpoint: simulate creating an alert from the latest RF risk result.

    This is only for internal validation and does not interact with RF hardware.
    """
    if os.getenv("ENABLE_TEST_ENDPOINTS", "").lower() != "true":
        raise HTTPException(status_code=403, detail="Test endpoint disabled. Set ENABLE_TEST_ENDPOINTS=true to enable it.")

    risk = api_rf_risk()
    if not risk or risk.get("status") != "SUCCESS":
        return {"status": "ERROR", "message": "No risk data available to simulate"}

    risk["risk_level"] = risk_level
    risk["risk_score"] = 50 if risk_level == "MEDIUM" else 80

    res = _save_rf_alert(risk)
    return {"status": "SUCCESS", "simulated": res}


@app.get("/api/alerts/{alert_id}")
def api_alert_by_id(alert_id: str) -> dict[str, Any]:
    """Return a single alert by ID."""
    alerts_dir = PROJECT_ROOT / "data" / "alerts"
    csv_path = alerts_dir / "rf_alert_history.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="Alert not found")

    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    for row in rows:
        if row.get("alert_id") == alert_id:
            return {"status": "SUCCESS", "alert": {
                "alert_id": row.get("alert_id"),
                "timestamp": row.get("timestamp"),
                "source_file": row.get("source_file"),
                "category": row.get("category"),
                "risk_score": int(row.get("risk_score", 0)),
                "severity": row.get("severity"),
                "threshold_severity": row.get("threshold_severity"),
                "ml_classification": row.get("ml_classification"),
                "ml_anomaly_score": float(row.get("ml_anomaly_score")) if row.get("ml_anomaly_score") not in (None, "") else None,
                "title": row.get("title"),
                "description": row.get("description"),
                "status": row.get("status"),
            }}

    raise HTTPException(status_code=404, detail="Alert not found")


@app.put("/api/alerts/{alert_id}/status")
def api_update_alert_status(alert_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Update an alert status to OPEN, ACKNOWLEDGED, or CLOSED."""
    allowed_statuses = {"OPEN", "ACKNOWLEDGED", "CLOSED"}
    if not payload or "status" not in payload:
        raise HTTPException(status_code=400, detail="Status is required")

    new_status = str(payload["status"]).upper()
    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload['status']}'. Allowed values: OPEN, ACKNOWLEDGED, CLOSED",
        )

    alerts_dir = PROJECT_ROOT / "data" / "alerts"
    csv_path = alerts_dir / "rf_alert_history.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="Alert not found")

    rows = []
    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    target_index = None
    for index, row in enumerate(rows):
        if row.get("alert_id") == alert_id:
            target_index = index
            break

    if target_index is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    rows[target_index]["status"] = new_status

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    return {"status": "SUCCESS", "alert": {
        "alert_id": rows[target_index].get("alert_id"),
        "timestamp": rows[target_index].get("timestamp"),
        "source_file": rows[target_index].get("source_file"),
        "category": rows[target_index].get("category"),
        "risk_score": int(rows[target_index].get("risk_score", 0)),
        "severity": rows[target_index].get("severity"),
        "threshold_severity": rows[target_index].get("threshold_severity"),
        "ml_classification": rows[target_index].get("ml_classification"),
        "ml_anomaly_score": float(rows[target_index].get("ml_anomaly_score")) if rows[target_index].get("ml_anomaly_score") not in (None, "") else None,
        "title": rows[target_index].get("title"),
        "description": rows[target_index].get("description"),
        "status": rows[target_index].get("status"),
    }}


@app.get("/api/rf/anomalies")
def api_rf_anomalies() -> dict[str, Any]:
    """Detect suspicious RF peaks above a median-based noise floor."""
    state = rf_state.get_state()
    if state["hackrf_status"] == "DISCONNECTED":
        return {
            "status": "ERROR",
            "error": "HackRF One is not connected",
            "noise_floor_db": None,
            "threshold_db": None,
            "anomaly_count": 0,
            "anomalies": [],
        }

    if not state["spectrum_available"]:
        return {
            "status": "ERROR",
            "error": "No spectrum data available",
            "noise_floor_db": None,
            "threshold_db": None,
            "anomaly_count": 0,
            "anomalies": [],
        }

    return {
        "status": "SUCCESS",
        "noise_floor_db": state["noise_floor_db"],
        "threshold_db": state["threshold_db"],
        "anomaly_count": state["anomaly_count"],
        "anomalies": state["anomalies"],
    }


# -----------------------------
# ML: IsolationForest training
# -----------------------------


@app.post("/api/ml/rf/train")
def api_ml_rf_train() -> dict[str, Any]:
    """Train or retrain the RF IsolationForest using stored feature history."""
    result = train_rf_isolation_forest()
    return result


@app.get("/api/ml/rf/status")
def api_ml_rf_status() -> dict[str, Any]:
    """Return training status and metadata for the RF model."""
    return ml_get_model_status()


@app.get("/api/ml/rf/predict/latest")
def api_ml_rf_predict_latest() -> dict[str, Any]:
    """Run the trained model on the latest RF feature record and return the score."""
    features_resp = api_rf_features_latest()
    if features_resp.get("status") != "SUCCESS" or not features_resp.get("record"):
        return {"status": "NO_FEATURES", "message": "No latest feature record available"}

    record = features_resp["record"]
    # Map fields expected by predict_from_feature_row
    feature_row = {
        "noise_floor_db": record.get("noise_floor_db"),
        "peak_power_db": record.get("peak_power_db"),
        "peak_delta_db": record.get("peak_delta_db"),
        "anomaly_count": record.get("anomaly_count"),
        "mean_power_db": record.get("mean_power_db"),
        "std_power_db": record.get("std_power_db"),
        "max_power_db": record.get("max_power_db"),
        "min_power_db": record.get("min_power_db"),
        "occupied_bandwidth_hz": record.get("occupied_bandwidth_hz"),
    }

    pred = predict_from_feature_row(feature_row)
    if pred.get("status") != "SUCCESS":
        return {"status": "NO_MODEL", "message": "No trained model available"}

    classification = "NORMAL" if pred["prediction"] == 1 else "ANOMALOUS"
    return {
        "status": "SUCCESS",
        "source_file": record.get("source_file"),
        "prediction": int(pred.get("prediction")),
        "anomaly_score": float(pred.get("anomaly_score")),
        "ml_classification": classification,
    }


@app.get("/api/rf/risk")
def api_rf_risk() -> dict[str, Any]:
    """Combine threshold anomalies and ML prediction into an explainable RF risk score."""
    state = rf_state.get_state()
    if state["hackrf_status"] == "DISCONNECTED":
        return {
            "status": "UNAVAILABLE",
            "hackrf_status": "DISCONNECTED",
            "message": "HackRF One is not connected"
        }

    if not state["spectrum_available"] or state["rf_risk_result"] is None:
        return {
            "status": "UNAVAILABLE",
            "hackrf_status": state["hackrf_status"],
            "message": "RF risk data is not available yet"
        }

    return state["rf_risk_result"]


@app.post("/api/rf/capture")
def api_rf_capture(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Capture raw IQ samples in receive-only mode and return capture metadata."""
    settings = payload or {}

    center_frequency = int(settings.get("center_frequency", CENTER_FREQ))
    sample_rate = int(settings.get("sample_rate", SAMPLE_RATE))
    duration_seconds = int(settings.get("duration", CAPTURE_SECONDS))
    lna_gain = int(settings.get("lna_gain", LNA_GAIN))
    vga_gain = int(settings.get("vga_gain", VGA_GAIN))
    output_dir = Path(settings.get("output_dir", PROJECT_ROOT / "data" / "rf_raw"))

    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = output_dir / f"hackrf_capture_{timestamp}.iq"

    try:
        with hackrf_lock:
            saved_path = capture_iq_samples(
                output_file=output_path,
                center_freq=center_frequency,
                sample_rate=sample_rate,
                lna_gain=lna_gain,
                vga_gain=vga_gain,
                duration_seconds=duration_seconds,
                timeout=20,
            )
        file_size = saved_path.stat().st_size
        return {
            "status": "success",
            "file_name": saved_path.name,
            "file_size": file_size,
            "center_frequency": center_frequency,
            "sample_rate": sample_rate,
            "capture_duration": duration_seconds,
        }
    except Exception as exc:  # pragma: no cover - API surfaces the runtime error to the caller.
        return {
            "status": "error",
            "file_name": None,
            "file_size": 0,
            "center_frequency": center_frequency,
            "sample_rate": sample_rate,
            "capture_duration": duration_seconds,
            "error": str(exc),
        }


@app.get("/device/{device_id}/status", response_model=DeviceStatusResponse)
def device_status(device_id: str) -> DeviceStatusResponse:
    """Return a summary of a device's current security status."""
    return get_device_status(device_id)


@app.post("/analyze/rf", response_model=RFAnalysisResponse)
def analyze_rf(request: RFAnalysisRequest) -> dict[str, Any]:
    """Run RF anomaly detection on a capture file."""
    result = analyze_rf_capture(request.device_id, request.iq_file)
    return result


@app.post("/verify/firmware", response_model=FirmwareVerificationResponse)
def verify_firmware(request: FirmwareVerificationRequest) -> dict[str, Any]:
    """Verify device firmware against the trusted hash database."""
    result = verify_firmware_service(request.device_id, request.firmware_path)
    return result


@app.post("/analyze/network", response_model=NetworkAnalysisResponse)
def analyze_network(request: NetworkAnalysisRequest) -> dict[str, Any]:
    """Run network behaviour analysis on a packet trace."""
    result = analyze_network_service(request.device_id, request.capture_path)
    return result


@app.post("/fusion", response_model=FusionResponse)
def fusion(request: FusionRequest) -> dict[str, Any]:
    """Combine RF, firmware, and network evidence into a final compromise-risk score."""
    result = fuse_service(request)
    return result["fused_result"]


@app.get("/alerts", response_model=list[AlertRecord])
def alerts() -> list[dict[str, Any]]:
    """Return all security alerts stored in the database."""
    return list_alerts()


@app.get("/devices", response_model=list[dict[str, Any]])
def devices() -> list[dict[str, Any]]:
    """Return the current list of known devices."""
    return list_devices()


@app.post("/api/devices", response_model=DeviceProfileResponse)
def register_device(profile: DeviceProfileRequest) -> dict[str, Any]:
    """Register a new device profile or update an existing one (upsert)."""
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.device_id == profile.device_id).first()
        tags_str = ",".join(profile.tags) if profile.tags else None
        if device:
            device.device_type = profile.device_type
            device.manufacturer = profile.manufacturer
            device.model = profile.model
            device.mac_address = profile.mac_address
            device.hw_version = profile.hw_version
            device.sw_version = profile.sw_version
            device.location = profile.location
            device.tags = tags_str
        else:
            device = Device(
                device_id=profile.device_id,
                device_type=profile.device_type,
                status="LOW",
                manufacturer=profile.manufacturer,
                model=profile.model,
                mac_address=profile.mac_address,
                hw_version=profile.hw_version,
                sw_version=profile.sw_version,
                location=profile.location,
                tags=tags_str,
            )
            db.add(device)
        db.commit()
        db.refresh(device)

        return DeviceProfileResponse(
            id=device.id,
            device_id=device.device_id,
            device_type=device.device_type,
            manufacturer=device.manufacturer,
            model=device.model,
            mac_address=device.mac_address,
            hw_version=device.hw_version,
            sw_version=device.sw_version,
            location=device.location,
            tags=(device.tags.split(",") if device.tags else []),
            last_seen=device.last_seen.isoformat() if device.last_seen else None,
        )
    finally:
        db.close()


@app.put("/api/devices/{device_id}", response_model=DeviceProfileResponse)
def update_device(device_id: str, profile: DeviceProfileRequest) -> dict[str, Any]:
    """Update an existing device profile."""
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail=f"Device not found: {device_id}")
        device.device_type = profile.device_type
        device.manufacturer = profile.manufacturer
        device.model = profile.model
        device.mac_address = profile.mac_address
        device.hw_version = profile.hw_version
        device.sw_version = profile.sw_version
        device.location = profile.location
        device.tags = ",".join(profile.tags) if profile.tags else None
        db.commit()
        db.refresh(device)
        return DeviceProfileResponse(
            id=device.id,
            device_id=device.device_id,
            device_type=device.device_type,
            manufacturer=device.manufacturer,
            model=device.model,
            mac_address=device.mac_address,
            hw_version=device.hw_version,
            sw_version=device.sw_version,
            location=device.location,
            tags=(device.tags.split(",") if device.tags else []),
            last_seen=device.last_seen.isoformat() if device.last_seen else None,
        )
    finally:
        db.close()


@app.get("/api/devices/{device_id}", response_model=DeviceProfileResponse)
def get_device_profile(device_id: str) -> dict[str, Any]:
    """Return a single device profile by device_id."""
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail=f"Device not found: {device_id}")
        return DeviceProfileResponse(
            id=device.id,
            device_id=device.device_id,
            device_type=device.device_type,
            manufacturer=device.manufacturer,
            model=device.model,
            mac_address=device.mac_address,
            hw_version=device.hw_version,
            sw_version=device.sw_version,
            location=device.location,
            tags=(device.tags.split(",") if device.tags else []),
            last_seen=device.last_seen.isoformat() if device.last_seen else None,
        )
    finally:
        db.close()


@app.post("/api/telemetry/identify")
def identify_telemetry(payload: dict[str, Any]) -> dict[str, Any]:
    """Attempt to identify a device from telemetry fields (mac_address or device_id)."""
    mac = payload.get("mac_address") or payload.get("mac")
    declared = payload.get("device_id")
    db = SessionLocal()
    try:
        if mac:
            device = db.query(Device).filter(Device.mac_address == mac).first()
            if device:
                return {"device_id": device.device_id, "matched_on": "mac_address", "confidence": 100}
            raise HTTPException(status_code=404, detail="No device matched the provided MAC address.")
        if declared:
            device = db.query(Device).filter(Device.device_id == declared).first()
            if device:
                return {"device_id": device.device_id, "matched_on": "device_id", "confidence": 100}
            raise HTTPException(status_code=404, detail="Declared device_id not found.")
        raise HTTPException(status_code=400, detail="Telemetry must include mac_address or device_id for identification.")
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
