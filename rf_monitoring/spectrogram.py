"""Create spectrogram visualizations from raw IQ captures.

This module is a companion to the FFT analysis workflow. It converts captured I/Q
samples into a complex signal and renders a time-frequency spectrogram that can be
used to visually inspect RF behaviour.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import signal as scipy_signal

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import RF_FEATURE_DIR, SAMPLE_RATE
from rf_monitoring.iq_loader import convert_to_complex, load_raw_iq, remove_dc_offset, resolve_input_path


def compute_spectrogram(
    signal: np.ndarray,
    sample_rate: float = SAMPLE_RATE,
    nperseg: int = 256,
    noverlap: int = 128,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Compute a spectrogram for a complex RF signal."""
    if signal.size == 0:
        raise ValueError("Signal is empty; cannot compute a spectrogram.")

    frequencies, times, spectrum = scipy_signal.spectrogram(
        signal,
        fs=sample_rate,
        window="hann",
        nperseg=nperseg,
        noverlap=noverlap,
        scaling="spectrum",
        mode="psd",
    )
    return frequencies, times, spectrum


def save_spectrogram_plot(
    freqs: np.ndarray,
    times: np.ndarray,
    spectrum: np.ndarray,
    output_path: str | Path,
    title: str = "RF spectrogram",
) -> Path:
    """Save a spectrogram as a PNG plot."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(12, 6))
    image = ax.pcolormesh(times, freqs, 10 * np.log10(spectrum + 1e-12), shading="auto")
    ax.set_title(title)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Frequency (Hz)")
    fig.colorbar(image, ax=ax, label="Power (dB)")
    fig.tight_layout()
    fig.savefig(output, dpi=200)
    plt.close(fig)
    return output


def create_spectrogram(
    iq_file: str | Path,
    output_plot: str | Path | None = None,
    sample_rate: float = SAMPLE_RATE,
    nperseg: int = 256,
    noverlap: int = 128,
) -> Path:
    """Load an IQ file, compute a spectrogram, and save it to disk."""
    input_path = resolve_input_path(iq_file)
    if not input_path.exists():
        raise FileNotFoundError(f"IQ file not found: {input_path}")

    samples = load_raw_iq(input_path)
    complex_signal = convert_to_complex(samples)
    centered_signal = remove_dc_offset(complex_signal)
    freqs, times, spectrum = compute_spectrogram(centered_signal, sample_rate=sample_rate, nperseg=nperseg, noverlap=noverlap)

    if output_plot is None:
        output_plot = RF_FEATURE_DIR / "spectrogram.png"

    output_path = save_spectrogram_plot(freqs, times, spectrum, output_plot, title=f"RF spectrogram for {input_path.name}")
    print(f"Saved spectrogram to: {output_path}")
    return output_path


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for spectrogram generation."""
    parser = argparse.ArgumentParser(description="Create a time-frequency spectrogram from a HackRF IQ capture.")
    parser.add_argument(
        "--input",
        type=str,
        default="data/rf_raw/manual_capture/sample.iq",
        help="Path to the IQ capture. Default: data/rf_raw/manual_capture/sample.iq",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(RF_FEATURE_DIR / "spectrogram.png"),
        help="Output path for the spectrogram PNG. Default: data/rf_features/spectrogram.png",
    )
    parser.add_argument(
        "--sample-rate",
        type=float,
        default=SAMPLE_RATE,
        help=f"Sample rate in Hz. Default: {SAMPLE_RATE}",
    )
    parser.add_argument(
        "--nperseg",
        type=int,
        default=256,
        help="Window length for the spectrogram. Default: 256",
    )
    parser.add_argument(
        "--noverlap",
        type=int,
        default=128,
        help="Overlap between spectrogram windows. Default: 128",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for spectrogram generation."""
    args = parse_args()
    create_spectrogram(
        iq_file=args.input,
        output_plot=args.output,
        sample_rate=args.sample_rate,
        nperseg=args.nperseg,
        noverlap=args.noverlap,
    )


if __name__ == "__main__":
    main()
