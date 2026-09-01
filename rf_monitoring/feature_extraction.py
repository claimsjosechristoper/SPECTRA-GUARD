"""RF feature extraction and dataset-row creation for SPECTRA-GUARD.

This module assembles the signal-processing outputs from the raw IQ capture and
FFT analysis stage into a row of labelled feature data. It is intended for safe
training and evaluation workflows, not for real malware detection.
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import DATA_DIR, RF_FEATURE_DIR, SAMPLE_RATE
from rf_monitoring.fft_analysis import extract_rf_features
from rf_monitoring.iq_loader import convert_to_complex, load_raw_iq, remove_dc_offset, resolve_input_path


def build_feature_row(
    iq_file: str | Path,
    device_id: str,
    operating_state: str,
    ground_truth: str,
    sample_rate: float = SAMPLE_RATE,
) -> dict[str, str | float | int]:
    """Build a single dataset row for an RF capture file."""
    input_path = resolve_input_path(iq_file)
    if not input_path.exists():
        raise FileNotFoundError(f"IQ file not found: {input_path}")

    raw_samples = load_raw_iq(input_path)
    complex_signal = convert_to_complex(raw_samples)
    centered_signal = remove_dc_offset(complex_signal)

    features = extract_rf_features(centered_signal, sample_rate=sample_rate)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = {
        "timestamp": timestamp,
        "device_id": device_id,
        "operating_state": operating_state,
        "peak_power": float(features["peak_power"]),
        "average_power": float(features["average_power"]),
        "spectral_centroid": float(features["spectral_centroid"]),
        "spectral_entropy": float(features["spectral_entropy"]),
        "bandwidth": float(features["occupied_bandwidth"]),
        "peak_count": int(features["peak_count"]),
        "ground_truth": ground_truth,
    }
    return row


def ensure_dataset_path(csv_path: str | Path) -> Path:
    """Create parent folder for the dataset if needed."""
    path = Path(csv_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def append_feature_row(row: dict[str, str | float | int], csv_path: str | Path = DATA_DIR / "rf_features" / "rf_dataset.csv") -> Path:
    """Append a feature record to a CSV file, creating the file if it does not exist."""
    output_path = ensure_dataset_path(csv_path)
    fieldnames = [
        "timestamp",
        "device_id",
        "operating_state",
        "peak_power",
        "average_power",
        "spectral_centroid",
        "spectral_entropy",
        "bandwidth",
        "peak_count",
        "ground_truth",
    ]

    file_exists = output_path.exists()
    with output_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in fieldnames})

    print(f"Appended RF feature row to: {output_path}")
    return output_path


def build_and_append_dataset_row(
    iq_file: str | Path,
    device_id: str,
    operating_state: str,
    ground_truth: str,
    csv_path: str | Path = DATA_DIR / "rf_features" / "rf_dataset.csv",
    sample_rate: float = SAMPLE_RATE,
) -> dict[str, str | float | int]:
    """Create a dataset row from a raw IQ capture and store it in CSV."""
    row = build_feature_row(
        iq_file=iq_file,
        device_id=device_id,
        operating_state=operating_state,
        ground_truth=ground_truth,
        sample_rate=sample_rate,
    )
    append_feature_row(row=row, csv_path=csv_path)
    return row


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for building a labelled feature row."""
    parser = argparse.ArgumentParser(description="Create a labelled RF dataset row from a raw HackRF capture.")
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to the raw IQ capture file.",
    )
    parser.add_argument(
        "--device-id",
        type=str,
        default="esp32_lab_device_01",
        help="Unique device identifier for the recording.",
    )
    parser.add_argument(
        "--operating-state",
        type=str,
        default="NORMAL_IDLE",
        help="Safe operating state label such as NORMAL_IDLE or CONTROLLED_RF_CHANGE.",
    )
    parser.add_argument(
        "--ground-truth",
        type=str,
        default="NORMAL",
        help="Ground-truth label for the sample.",
    )
    parser.add_argument(
        "--csv",
        type=str,
        default=str(DATA_DIR / "rf_features" / "rf_dataset.csv"),
        help="Output CSV file path for the RF dataset. Default: data/rf_features/rf_dataset.csv",
    )
    parser.add_argument(
        "--sample-rate",
        type=float,
        default=SAMPLE_RATE,
        help=f"Sample rate in Hz. Default: {SAMPLE_RATE}",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for generating one labelled RF feature row."""
    args = parse_args()
    row = build_and_append_dataset_row(
        iq_file=args.input,
        device_id=args.device_id,
        operating_state=args.operating_state,
        ground_truth=args.ground_truth,
        csv_path=args.csv,
        sample_rate=args.sample_rate,
    )
    print(row)


if __name__ == "__main__":
    main()
