"""Service-layer logic for the SPECTRA-GUARD backend.

This module keeps the API calls organized and uses the existing project modules to
perform RF, firmware, and network analysis as reusable services.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.database import Device, SecurityAlert, SessionLocal
from backend.schemas import DeviceStatusResponse, FusionRequest
from evidence_fusion.explain_alert import explain_from_fusion
from evidence_fusion.fusion_engine import fuse_evidence
from firmware_integrity.hash_verifier import verify_firmware
from network_monitoring.network_anomaly_detector import analyze_network_capture
from rf_monitoring.rf_anomaly_detector import predict_rf_anomaly


def get_device_status(device_id: str) -> DeviceStatusResponse:
    """Build a status response for a known device or a safe default if not found."""
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if device is None:
            device = Device(
                device_id=device_id,
                device_type="Unknown",
                status="LOW",
            )

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return DeviceStatusResponse(
            device_id=device.device_id,
            device_type=device.device_type,
            status=device.status,
            rf_risk=0.0,
            firmware_integrity="VERIFIED",
            network_risk=0.0,
            overall_risk=0.0,
            risk_level="LOW",
            reasons=[],
            timestamp=timestamp,
        )
    finally:
        db.close()


def analyze_rf_capture(device_id: str, iq_file: str) -> dict[str, Any]:
    """Run RF analysis on a capture file and return prediction results."""
    return predict_rf_anomaly(iq_file=iq_file, device_id=device_id)


def verify_firmware_service(device_id: str, firmware_path: str) -> dict[str, Any]:
    """Run firmware verification and return the structured result."""
    return verify_firmware(device_id=device_id, firmware_path=firmware_path)


def analyze_network_service(device_id: str, capture_path: str) -> dict[str, Any]:
    """Run network analysis for a provided packet log or capture."""
    result = analyze_network_capture(capture_path)
    return {
        "device_id": device_id,
        "network_anomaly_score": result["network_anomaly_score"],
        "network_risk_score": result["network_risk_score"],
        "reasons": result["reasons"],
        "features": result["features"],
    }


def fuse_service(request: FusionRequest) -> dict[str, Any]:
    """Fuse RF, firmware, and network evidence into a combined risk response."""
    fused_result = fuse_evidence(
        rf_risk=request.rf_risk,
        firmware_risk=request.firmware_risk,
        network_risk=request.network_risk,
    )
    alert = explain_from_fusion(fused_result)
    return {
        "fused_result": fused_result,
        "alert": alert,
    }


def list_alerts() -> list[dict[str, Any]]:
    """Return the current security alerts stored in SQLite."""
    db = SessionLocal()
    try:
        alerts = db.query(SecurityAlert).all()
        return [
            {
                "id": alert.id,
                "device_id": alert.device_id,
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "risk_level": alert.risk_level,
                "overall_risk": alert.overall_risk,
                "reasons": alert.reasons,
                "recommendation": alert.recommendation,
            }
            for alert in alerts
        ]
    finally:
        db.close()


def list_devices() -> list[dict[str, Any]]:
    """Return all registered devices from SQLite."""
    db = SessionLocal()
    try:
        devices = db.query(Device).all()
        return [
            {
                "id": device.id,
                "device_id": device.device_id,
                "device_type": device.device_type,
                "status": device.status,
                "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            }
            for device in devices
        ]
    finally:
        db.close()
