"""Load an RF IsolationForest model and score a new capture.

This module provides model-loading and prediction functions for RF anomaly
assessment. It is a baseline prototype and does not represent final hardware
security validation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import DATA_DIR
from rf_monitoring.feature_extraction import build_feature_row

MODEL_PATH = PROJECT_ROOT / "ml_engine" / "models" / "rf_isolation_forest.joblib"


def load_model(model_path: str | Path = MODEL_PATH):
    """Load the RF anomaly model from disk."""
    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(f"RF model file not found: {path}")
    return joblib.load(path)


def determine_rf_risk(score: float) -> int:
    """Convert a raw anomaly score into a 0-100 risk score.

    The IsolationForest score is directional: lower values indicate more abnormal
    samples. This mapping is a simple prototype and should be tuned with real data.
    """
    if score >= 0.0:
        return 0
    value = abs(score)
    scaled = min(100, int(value * 100))
    return max(0, scaled)


def predict_rf_anomaly(
    iq_file: str | Path,
    model_path: str | Path = MODEL_PATH,
    sample_rate: float = 10_000_000,
    device_id: str = "esp32_lab_device_01",
) -> dict[str, float | int | str]:
    """Predict whether a new RF capture is anomalous and compute an RF risk score."""
    model = load_model(model_path)
    row = build_feature_row(
        iq_file=iq_file,
        device_id=device_id,
        operating_state="LIVE_CHECK",
        ground_truth="UNKNOWN",
        sample_rate=sample_rate,
    )

    features = pd.DataFrame([
        {
            "peak_power": row["peak_power"],
            "average_power": row["average_power"],
            "spectral_centroid": row["spectral_centroid"],
            "spectral_entropy": row["spectral_entropy"],
            "bandwidth": row["bandwidth"],
            "peak_count": row["peak_count"],
        }
    ])

    prediction = model.predict(features)[0]
    anomaly_score = float(model.score_samples(features)[0])
    rf_risk = determine_rf_risk(anomaly_score)

    return {
        "prediction": int(prediction),
        "anomaly_score": anomaly_score,
        "rf_risk_score": rf_risk,
        "device_id": device_id,
        "status": "ANOMALY" if prediction == -1 else "NORMAL",
    }


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for RF anomaly detection."""
    parser = argparse.ArgumentParser(description="Load a trained RF IsolationForest model and score a capture.")
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to the raw IQ file to evaluate.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=str(MODEL_PATH),
        help=f"Path to the trained RF model. Default: {MODEL_PATH}",
    )
    parser.add_argument(
        "--device-id",
        type=str,
        default="esp32_lab_device_01",
        help="Identifier for the device being evaluated.",
    )
    parser.add_argument(
        "--sample-rate",
        type=float,
        default=10_000_000,
        help="Sample rate in Hz. Default: 10000000",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for RF anomaly scoring."""
    args = parse_args()
    result = predict_rf_anomaly(
        iq_file=args.input,
        model_path=args.model,
        sample_rate=args.sample_rate,
        device_id=args.device_id,
    )
    print(result)


if __name__ == "__main__":
    main()
