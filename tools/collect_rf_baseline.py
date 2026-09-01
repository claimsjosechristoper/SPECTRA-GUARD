"""Collect a real RF baseline dataset using the receive-only HackRF capture and
existing analysis pipeline.

Requirements followed:
- performs N separate receive-only captures using the project's capture utility
- processes each capture through the existing analysis logic
- writes exactly one feature-history row per unique source_file
- stops safely on capture/analysis failure
- does NOT retrain automatically

Usage example (Windows PowerShell):
  Set-Location 'C:\SPECTRA_GUARD'; python tools\collect_rf_baseline.py --count 20
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone
from pathlib import Path
import sys
import csv
from collections import Counter

# Ensure project root on path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rf_monitoring.capture_rf import capture_iq_samples
# Reuse backend analysis helpers to avoid duplicating FFT/feature logic
import backend.main as backend_main

# Capture defaults from project requirements
DEFAULT_CENTER_FREQ = 433_000_000
DEFAULT_SAMPLE_RATE = 10_000_000
DEFAULT_DURATION = 2
DEFAULT_LNA_GAIN = 24
DEFAULT_VGA_GAIN = 20

# Where captures are stored by default
RF_RAW_DIR = PROJECT_ROOT / "data" / "rf_raw"
FEATURE_CSV = PROJECT_ROOT / "data" / "rf_features" / "rf_feature_history.csv"


def collect_baseline(count: int = 20, pause_seconds: float = 1.0, dry_run: bool = False) -> dict:
    created_iq_files: list[Path] = []
    new_feature_files: list[str] = []

    # Snapshot existing feature source_files to avoid duplicates counting
    existing_source_files = set()
    if FEATURE_CSV.exists():
        with FEATURE_CSV.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                existing_source_files.add(r.get("source_file"))

    for i in range(1, count + 1):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_name = f"hackrf_capture_{timestamp}.iq"
        out_path = RF_RAW_DIR / out_name

        print(f"Starting capture {i}/{count} -> {out_path.name}")
        if dry_run:
            print("Dry run enabled: skipping actual capture")
            # allow downstream logic to simulate a produced file by touch
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(b"")
            created_iq_files.append(out_path)
            print(f"Dry-run: created placeholder {out_path.name}")
        else:
            try:
                saved_path = capture_iq_samples(
                    output_file=out_path,
                    center_freq=int(DEFAULT_CENTER_FREQ),
                    sample_rate=int(DEFAULT_SAMPLE_RATE),
                    lna_gain=int(DEFAULT_LNA_GAIN),
                    vga_gain=int(DEFAULT_VGA_GAIN),
                    duration_seconds=int(DEFAULT_DURATION),
                    timeout=30,
                )
            except Exception as exc:
                print(f"Capture failed at iteration {i}: {exc}")
                print("Stopping baseline collection safely.")
                break

            created_iq_files.append(Path(saved_path))
            print(f"Capture saved: {Path(saved_path).name}")

        # Give the analysis pipeline a moment to see the new file
        time.sleep(0.5)

        # Run the existing analysis flow (get_latest_spectrum_data reads newest file)
        try:
            spectrum = backend_main.get_latest_spectrum_data()
        except Exception as exc:
            print(f"Analysis failed for capture {out_path.name}: {exc}")
            print("Stopping baseline collection safely.")
            break

        if spectrum.get("status") != "SUCCESS":
            print(f"Analysis returned error for {out_path.name}: {spectrum.get('error')}")
            print("Stopping baseline collection safely.")
            break

        # Save a feature record (this avoids duplicates by source_file)
        try:
            feature_record = backend_main._save_rf_feature_record(spectrum)
        except Exception as exc:
            print(f"Failed to save feature record for {out_path.name}: {exc}")
            print("Stopping baseline collection safely.")
            break

        if feature_record.get("source_file") not in existing_source_files:
            new_feature_files.append(feature_record.get("source_file"))
            existing_source_files.add(feature_record.get("source_file"))

        print(f"Baseline {i}/{count} complete")
        time.sleep(pause_seconds)

    # Summarize results
    total_iq = len(created_iq_files)
    total_feature_rows = 0
    noise_floor_vals = []
    peak_power_vals = []
    anomaly_counts = []

    if FEATURE_CSV.exists():
        with FEATURE_CSV.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
            total_feature_rows = len(rows)
            for r in rows:
                try:
                    noise_floor_vals.append(float(r.get("noise_floor_db", "nan")))
                except Exception:
                    pass
                try:
                    peak_power_vals.append(float(r.get("peak_power_db", "nan")))
                except Exception:
                    pass
                try:
                    anomaly_counts.append(int(r.get("anomaly_count", 0)))
                except Exception:
                    pass

    stats = {
        "total_iq_captures_created": total_iq,
        "total_feature_history_rows": total_feature_rows,
        "new_baseline_rows_added": len(new_feature_files),
        "mean_noise_floor_db": (sum(noise_floor_vals) / len(noise_floor_vals)) if noise_floor_vals else None,
        "min_noise_floor_db": (min(noise_floor_vals) if noise_floor_vals else None),
        "max_noise_floor_db": (max(noise_floor_vals) if noise_floor_vals else None),
        "mean_peak_power_db": (sum(peak_power_vals) / len(peak_power_vals)) if peak_power_vals else None,
        "anomaly_count_distribution": dict(Counter(anomaly_counts)),
        "created_iq_files": [str(p.name) for p in created_iq_files],
        "new_feature_files": new_feature_files,
    }

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect a real RF baseline dataset (receive-only).")
    parser.add_argument("--count", type=int, default=20, help="Number of baseline captures to collect")
    parser.add_argument("--pause", type=float, default=1.0, help="Seconds to wait between captures")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run (no real capture) for testing")
    args = parser.parse_args()

    print(f"Collecting {args.count} baseline captures (dry_run={args.dry_run})")
    stats = collect_baseline(count=args.count, pause_seconds=args.pause, dry_run=args.dry_run)

    print("\nBaseline collection summary:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    print("\nAfter verifying the baseline rows, run POST /api/ml/rf/train to train the IsolationForest model.")


if __name__ == "__main__":
    main()
