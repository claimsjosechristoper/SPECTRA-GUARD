"""FFT and spectrum analysis for HackRF IQ captures.

This module turns raw complex I/Q data into a power spectrum and extracts a
small set of RF features. It is intentionally modular so it can be used by
later training and anomaly detection pipelines.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import signal as scipy_signal

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import RF_FEATURE_DIR, SAMPLE_RATE
from rf_monitoring.iq_loader import convert_to_complex, load_raw_iq, remove_dc_offset, resolve_input_path


def apply_window(signal: np.ndarray) -> np.ndarray:
    """Apply a Hann window to reduce spectral leakage before the FFT."""
    if signal.size == 0:
        raise ValueError("Cannot apply a window to an empty signal.")
    window = scipy_signal.windows.hann(signal.size, sym=False)
    return signal * window


def compute_fft(signal: np.ndarray, sample_rate: float = SAMPLE_RATE) -> tuple[np.ndarray, np.ndarray]:
    """Compute the FFT and corresponding frequency bins for a complex signal."""
    if signal.size == 0:
        raise ValueError("Cannot compute FFT for an empty signal.")

    fft_values = np.fft.fft(signal)
    freqs = np.fft.fftfreq(signal.size, d=1.0 / sample_rate)
    return freqs, fft_values


def compute_power_spectrum(fft_values: np.ndarray) -> np.ndarray:
    """Calculate the one-sided power spectrum in linear scale."""
    if fft_values.size == 0:
        raise ValueError("FFT output is empty; cannot compute power spectrum.")

    power = np.abs(fft_values) ** 2
    return power[: len(power) // 2]


def compute_power_spectrum_db(fft_values: np.ndarray) -> np.ndarray:
    """Convert the magnitude spectrum to dB power.

    The returned values are centered around the signal power and safely clip at
    a floor to avoid log(0) issues."""
    power = np.abs(fft_values) ** 2
    if power.size == 0:
        raise ValueError("FFT output is empty; cannot compute power spectrum in dB.")
    power = np.maximum(power, 1e-30)
    return 10.0 * np.log10(power)


def downsample_spectrum(freqs: np.ndarray, power_db: np.ndarray, target_points: int = 1200) -> tuple[np.ndarray, np.ndarray]:
    """Downsample the frequency and power arrays while preserving range."""
    if freqs.size == 0 or power_db.size == 0:
        raise ValueError("Cannot downsample empty spectrum arrays.")
    if freqs.size <= target_points:
        return freqs, power_db
    indices = np.linspace(0, freqs.size - 1, num=target_points, dtype=int)
    return freqs[indices], power_db[indices]


def detect_suspicious_peaks(
    frequencies_hz: np.ndarray,
    power_db: np.ndarray,
    threshold_offset_db: float = 12.0,
    min_distance: int = 8,
    prominence: float = 3.0,
) -> dict[str, Any]:
    """Detect spectrum peaks above a median-based noise floor.

    The returned structure includes the computed noise floor, a detection threshold,
    and a list of suspicious peaks with severity labels.
    """
    if frequencies_hz.size == 0 or power_db.size == 0:
        raise ValueError("Cannot detect peaks for empty spectrum arrays.")
    if frequencies_hz.size != power_db.size:
        raise ValueError("Frequency and power arrays must be the same length.")

    noise_floor_db = float(np.median(power_db))
    threshold_db = noise_floor_db + threshold_offset_db
    peaks, _ = scipy_signal.find_peaks(power_db, distance=min_distance, prominence=prominence)

    anomalies: list[dict[str, float | str | int]] = []
    for idx in peaks:
        peak_power_db = float(power_db[idx])
        if peak_power_db <= threshold_db:
            continue

        difference = peak_power_db - noise_floor_db
        if difference >= 25.0:
            severity = "HIGH"
        elif difference >= 18.0:
            severity = "MEDIUM"
        elif difference >= 12.0:
            severity = "LOW"
        else:
            continue

        anomalies.append(
            {
                "frequency_hz": float(frequencies_hz[idx]),
                "frequency_mhz": float(frequencies_hz[idx] / 1_000_000.0),
                "power_db": peak_power_db,
                "noise_floor_db": noise_floor_db,
                "difference_from_noise_db": float(difference),
                "severity": severity,
            }
        )

    anomalies.sort(key=lambda anomaly: float(anomaly["difference_from_noise_db"]), reverse=True)
    return {
        "noise_floor_db": noise_floor_db,
        "threshold_db": threshold_db,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }


def compute_spectral_centroid(freqs: np.ndarray, power_spectrum: np.ndarray) -> float:
    """Compute the spectral centroid in Hz."""
    if np.sum(power_spectrum) == 0:
        return 0.0
    return float(np.sum(freqs[: len(power_spectrum)] * power_spectrum) / np.sum(power_spectrum))


def compute_spectral_entropy(power_spectrum: np.ndarray) -> float:
    """Compute normalized spectral entropy from power distribution."""
    if power_spectrum.size == 0:
        return 0.0

    power = power_spectrum.copy()
    total = np.sum(power)
    if total <= 0:
        return 0.0

    distribution = power / total
    distribution = distribution[distribution > 0]
    entropy = -np.sum(distribution * np.log2(distribution + 1e-12))
    max_entropy = np.log2(len(distribution)) if len(distribution) > 1 else 1.0
    return float(entropy / max_entropy) if max_entropy > 0 else 0.0


def compute_occupied_bandwidth(freqs: np.ndarray, power_spectrum: np.ndarray, threshold: float = 0.5) -> float:
    """Compute bandwidth that contains the central energy portion.

    The threshold defines the energy fraction used for the occupied bandwidth.
    """
    if power_spectrum.size == 0:
        return 0.0

    total_power = np.sum(power_spectrum)
    if total_power <= 0:
        return 0.0

    cumulative = np.cumsum(power_spectrum)
    energy_limit = threshold * total_power
    idx = np.searchsorted(cumulative, energy_limit, side="left")
    if idx >= len(freqs):
        idx = len(freqs) - 1
    return float(freqs[idx] - freqs[0])


def extract_rf_features(signal: np.ndarray, sample_rate: float = SAMPLE_RATE) -> dict[str, float | int]:
    """Extract core RF features from a complex signal."""
    if signal.size == 0:
        raise ValueError("Signal is empty; cannot extract RF features.")

    centered_signal = remove_dc_offset(signal)
    windowed_signal = apply_window(centered_signal)
    freqs, fft_values = compute_fft(windowed_signal, sample_rate=sample_rate)
    power_spectrum = compute_power_spectrum(np.abs(fft_values))
    positive_freqs = freqs[: len(power_spectrum)]
    power_values = power_spectrum.astype(np.float64)

    peak_power = float(np.max(power_values)) if power_values.size else 0.0
    average_power = float(np.mean(power_values)) if power_values.size else 0.0
    std_power = float(np.std(power_values)) if power_values.size else 0.0
    spectral_centroid = compute_spectral_centroid(positive_freqs, power_values)
    spectral_entropy = compute_spectral_entropy(power_values)
    occupied_bandwidth = compute_occupied_bandwidth(positive_freqs, power_values)
    peak_count = int(np.sum(power_values > (np.mean(power_values) + 3 * np.std(power_values)))) if power_values.size else 0

    return {
        "peak_power": peak_power,
        "average_power": average_power,
        "standard_deviation_power": std_power,
        "spectral_centroid": spectral_centroid,
        "spectral_entropy": spectral_entropy,
        "occupied_bandwidth": occupied_bandwidth,
        "peak_count": peak_count,
    }


def save_spectrum_plot(
    freqs: np.ndarray,
    power_spectrum: np.ndarray,
    output_path: str | Path,
    title: str = "RF power spectrum",
) -> Path:
    """Save a spectrum plot as a PNG file."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(freqs[: len(power_spectrum)], power_spectrum, color="tab:blue")
    ax.set_title(title)
    ax.set_xlabel("Frequency (Hz)")
    ax.set_ylabel("Power")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output, dpi=200)
    plt.close(fig)
    return output


def save_features_csv(features: dict[str, float | int], output_path: str | Path) -> Path:
    """Save extracted feature values to a CSV row."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    frame = pd.DataFrame([features])
    frame.to_csv(output, index=False)
    return output


def analyze_capture(
    iq_file: str | Path,
    output_plot: str | Path | None = None,
    output_csv: str | Path | None = None,
    sample_rate: float = SAMPLE_RATE,
) -> dict[str, float | int]:
    """Analyze a captured IQ file and save outputs for later model training.

    Returns the extracted feature dictionary.
    """
    input_path = resolve_input_path(iq_file)
    if not input_path.exists():
        raise FileNotFoundError(f"IQ file not found: {input_path}")

    raw_samples = load_raw_iq(input_path)
    complex_signal = convert_to_complex(raw_samples)
    centered_signal = remove_dc_offset(complex_signal)

    freqs, fft_values = compute_fft(apply_window(centered_signal), sample_rate=sample_rate)
    power_spectrum = compute_power_spectrum(np.abs(fft_values))
    features = extract_rf_features(centered_signal, sample_rate=sample_rate)

    if output_plot is None:
        output_plot = RF_FEATURE_DIR / "spectrum.png"
    if output_csv is None:
        output_csv = RF_FEATURE_DIR / "features.csv"

    save_spectrum_plot(freqs, power_spectrum, output_plot, title=f"RF spectrum for {input_path.name}")
    save_features_csv(features, output_csv)

    print(f"Saved spectrum plot to: {output_plot}")
    print(f"Saved RF features CSV to: {output_csv}")
    print(features)
    return features


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for quick RF analysis runs."""
    parser = argparse.ArgumentParser(description="Analyze captured RF IQ samples and extract feature values.")
    parser.add_argument(
        "--input",
        type=str,
        default="data/rf_raw/manual_capture/sample.iq",
        help="Path to the raw IQ capture. Default: data/rf_raw/manual_capture/sample.iq",
    )
    parser.add_argument(
        "--plot",
        type=str,
        default=str(RF_FEATURE_DIR / "spectrum.png"),
        help="Output path for the spectrum PNG plot.",
    )
    parser.add_argument(
        "--csv",
        type=str,
        default=str(RF_FEATURE_DIR / "features.csv"),
        help="Output path for the extracted RF feature CSV.",
    )
    parser.add_argument(
        "--sample-rate",
        type=float,
        default=SAMPLE_RATE,
        help=f"Sample rate in Hz. Default: {SAMPLE_RATE}",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for quick spectral analysis."""
    args = parse_args()
    analyze_capture(
        iq_file=args.input,
        output_plot=args.plot,
        output_csv=args.csv,
        sample_rate=args.sample_rate,
    )


if __name__ == "__main__":
    main()
