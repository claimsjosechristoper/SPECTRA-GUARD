"""Train an IsolationForest baseline model for RF anomaly detection.

The initial model is trained on legitimate operating states only:
- NORMAL_IDLE
- NORMAL_TELEMETRY
- NORMAL_HIGH_LOAD

It is intentionally a baseline prototype. We do not claim performance until the
model is evaluated on labelled test data.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from datetime import datetime, timezone
import json

import numpy as np
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import DATA_DIR

DEFAULT_DATASET = DATA_DIR / "rf_features" / "rf_dataset.csv"
MODEL_DIR = PROJECT_ROOT / "ml_engine" / "models"
MODEL_PATH = MODEL_DIR / "rf_isolation_forest.joblib"


FEATURE_COLUMNS = [
    "peak_power",
    "average_power",
    "spectral_centroid",
    "spectral_entropy",
    "bandwidth",
    "peak_count",
]


def load_rf_dataset(csv_path: str | Path) -> pd.DataFrame:
    """Load the RF feature dataset from CSV."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"RF dataset not found: {path}")

    df = pd.read_csv(path)
    required = {"operating_state"} | set(FEATURE_COLUMNS)
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")
    return df


def prepare_training_data(df: pd.DataFrame) -> pd.DataFrame:
    """Filter to legitimate RF operating states and keep the numeric feature columns."""
    allowed = {"NORMAL_IDLE", "NORMAL_TELEMETRY", "NORMAL_HIGH_LOAD"}
    subset = df[df["operating_state"].isin(allowed)].copy()

    if subset.empty:
        raise ValueError(
            "No legitimate training data was found. "
            "Ensure the dataset contains NORMAL_IDLE, NORMAL_TELEMETRY, and NORMAL_HIGH_LOAD samples."
        )

    return subset[FEATURE_COLUMNS].dropna().reset_index(drop=True)


def train_isolation_forest(X: pd.DataFrame, contamination: float = 0.05, random_state: int = 42) -> IsolationForest:
    """Train the baseline IsolationForest model on legitimate RF features."""
    model = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=200,
    )
    model.fit(X)
    return model


def save_model(model: IsolationForest, output_path: str | Path = MODEL_PATH) -> Path:
    """Persist the trained model to disk using joblib."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    print(f"Saved RF model to: {path}")
    return path


def train_model_from_csv(
    csv_path: str | Path = DEFAULT_DATASET,
    output_path: str | Path = MODEL_PATH,
    contamination: float = 0.05,
    random_state: int = 42,
) -> tuple[IsolationForest, pd.DataFrame]:
    """Load the CSV, train the anomaly model, and save the output."""
    df = load_rf_dataset(csv_path)
    training_data = prepare_training_data(df)
    model = train_isolation_forest(training_data, contamination=contamination, random_state=random_state)
    save_model(model, output_path)
    return model, training_data


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for RF model training."""
    parser = argparse.ArgumentParser(description="Train the baseline RF IsolationForest anomaly model.")
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(DEFAULT_DATASET),
        help=f"Path to the RF feature dataset CSV. Default: {DEFAULT_DATASET}",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(MODEL_PATH),
        help=f"Path for the trained model file. Default: {MODEL_PATH}",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Expected anomaly fraction used by IsolationForest. Default: 0.05",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for RF model training."""
    args = parse_args()
    model, training_data = train_model_from_csv(
        csv_path=args.dataset,
        output_path=args.output,
        contamination=args.contamination,
    )
    print(f"Training rows used: {len(training_data)}")
    print(f"Model type: {type(model).__name__}")
    print(f"Mean anomaly score: {model.score_samples(training_data).mean():.6f}")



# -----------------------------------------------------------------------------
# Backwards-compatible CLI entrypoint retained above.
# The following functions provide the programmatic API used by the FastAPI
# backend for on-demand training and prediction per the SPECTRA-GUARD design.
# -----------------------------------------------------------------------------

# Required feature set for backend ML integration (numeric-only features)
RF_FEATURE_COLUMNS = [
    "noise_floor_db",
    "peak_power_db",
    "peak_delta_db",
    "anomaly_count",
    "mean_power_db",
    "std_power_db",
    "max_power_db",
    "min_power_db",
    "occupied_bandwidth_hz",
]

MODEL_META_PATH = MODEL_DIR / "rf_isolation_forest_meta.json"


def _read_feature_history(csv_path: Path | str | None = None) -> pd.DataFrame:
    if csv_path is None:
        csv_path = PROJECT_ROOT / "data" / "rf_features" / "rf_feature_history.csv"
    path = Path(csv_path)
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path)
    # Ensure the RF_FEATURE_COLUMNS exist and are numeric
    for col in RF_FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def train_rf_isolation_forest(
    csv_path: Path | str | None = None,
    n_estimators: int = 100,
    contamination: float = 0.05,
    random_state: int = 42,
    min_rows: int = 20,
) -> dict:
    """Train an IsolationForest using the numeric RF feature history.

    Returns a dict with keys: status, message (optional), model_path, meta_path, training_rows.
    """
    df = _read_feature_history(csv_path)
    rows = len(df)
    if rows < min_rows:
        return {"status": "INSUFFICIENT_BASELINE_DATA", "message": "Not enough baseline rows", "training_rows": rows}

    X = df[RF_FEATURE_COLUMNS].copy()
    # Impute missing numeric values with column medians
    medians = X.median(skipna=True)
    X = X.fillna(medians)

    model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state)
    model.fit(X.values)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    meta = {
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "training_rows": int(rows),
        "feature_names": RF_FEATURE_COLUMNS,
        "model_parameters": {"n_estimators": n_estimators, "contamination": contamination, "random_state": random_state},
        "feature_medians": medians.to_dict(),
    }
    with MODEL_META_PATH.open("w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    return {"status": "SUCCESS", "model_path": str(MODEL_PATH), "meta_path": str(MODEL_META_PATH), "training_rows": int(rows)}


def get_model_status() -> dict:
    """Return metadata about the trained model (if present)."""
    model_exists = MODEL_PATH.exists()
    meta_exists = MODEL_META_PATH.exists()
    if not meta_exists:
        return {"model_status": "NOT_TRAINED", "model_exists": model_exists, "training_rows": 0, "trained_at": None, "features_used": []}

    with MODEL_META_PATH.open("r", encoding="utf-8") as fh:
        meta = json.load(fh)

    return {
        "model_status": "TRAINED",
        "model_exists": model_exists,
        "training_rows": int(meta.get("training_rows", 0)),
        "trained_at": meta.get("trained_at"),
        "features_used": meta.get("feature_names", []),
    }


def predict_from_feature_row(row: dict) -> dict:
    """Predict on a single feature row mapping. Returns status, prediction, anomaly_score."""
    if not MODEL_PATH.exists() or not MODEL_META_PATH.exists():
        return {"status": "NO_MODEL"}

    model = joblib.load(MODEL_PATH)
    with MODEL_META_PATH.open("r", encoding="utf-8") as fh:
        meta = json.load(fh)

    medians = meta.get("feature_medians", {})
    values = []
    for col in RF_FEATURE_COLUMNS:
        v = row.get(col, None)
        if v is None or (isinstance(v, float) and np.isnan(v)):
            v = medians.get(col, 0.0)
        try:
            values.append(float(v))
        except Exception:
            values.append(float(medians.get(col, 0.0)))

    arr = np.asarray([values], dtype=float)
    pred = int(model.predict(arr)[0])
    score = float(model.decision_function(arr)[0])
    return {"status": "SUCCESS", "prediction": pred, "anomaly_score": score}


def predict_latest_from_csv() -> dict:
    df = _read_feature_history()
    if df.empty:
        return {"status": "EMPTY"}
    latest = df.iloc[-1].to_dict()
    return predict_from_feature_row(latest)


if __name__ == "__main__":
    main()
