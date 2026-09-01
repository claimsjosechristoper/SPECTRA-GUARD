"""Utilities for loading raw HackRF I/Q samples into NumPy arrays.

This module expects interleaved I/Q data captured using hackrf_transfer in raw
signed 16-bit format. Each sample is represented by two 16-bit values:
I, Q. These are converted into a complex signal for FFT and spectrum analysis.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def resolve_input_path(file_path: str | Path) -> Path:
    """Resolve a relative file path against the project root."""
    path = Path(file_path)
    if not path.is_absolute():
        project_relative = PROJECT_ROOT / path
        if project_relative.exists():
            return project_relative
        return path
    return path


def load_raw_iq(file_path: str | Path, sample_dtype: str | np.dtype | type | None = None) -> np.ndarray:
    """Load interleaved raw IQ samples from a .iq or .bin file.

    HackRF captures are often stored as signed 8-bit I/Q pairs, but older or
    alternate workflows may use 16-bit little-endian values. The dtype is chosen
    automatically when omitted, then can be overridden explicitly for testing.
    """
    path = resolve_input_path(file_path)
    if not path.exists():
        raise FileNotFoundError(
            f"IQ file not found: {path}. Run the capture script first to generate a raw sample, "
            "or pass an absolute path to an existing .iq/.bin file."
        )

    try:
        raw_data = path.read_bytes()
    except OSError as exc:
        raise OSError(f"Unable to read IQ file: {path}") from exc

    if len(raw_data) == 0:
        raise ValueError(f"IQ file is empty: {path}")

    if sample_dtype is None:
        sample_dtype = np.int8

    dtype = np.dtype(sample_dtype)
    if dtype.itemsize == 1 and len(raw_data) % 2 != 0:
        raise ValueError(
            f"Unexpected IQ file length for {path}: {len(raw_data)} bytes. "
            "Expected an even byte count for signed 8-bit I/Q samples."
        )
    if dtype.itemsize == 2 and len(raw_data) % 4 != 0:
        raise ValueError(
            f"Unexpected IQ file length for {path}: {len(raw_data)} bytes. "
            "Expected a multiple of 4 bytes for signed 16-bit I/Q samples."
        )

    samples = np.frombuffer(raw_data, dtype=dtype)
    samples = samples.reshape(-1, 2)
    return samples


def convert_to_complex(samples: np.ndarray) -> np.ndarray:
    """Convert interleaved I/Q samples into a complex signal."""
    if samples.ndim != 2 or samples.shape[1] != 2:
        raise ValueError("Expected a 2D array shaped like (n_samples, 2) containing [I, Q].")

    i_data = samples[:, 0].astype(np.float64)
    q_data = samples[:, 1].astype(np.float64)
    return i_data + 1j * q_data


def remove_dc_offset(signal: np.ndarray) -> np.ndarray:
    """Subtract the mean complex DC offset from the signal."""
    if signal.size == 0:
        raise ValueError("Signal is empty; cannot remove DC offset from an empty array.")
    return signal - np.mean(signal)


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for quick testing."""
    parser = argparse.ArgumentParser(description="Load and inspect raw HackRF IQ samples.")
    parser.add_argument(
        "--input",
        type=str,
        default="data/rf_raw/manual_capture/sample.iq",
        help="Path to the captured IQ file (.iq or .bin). Default: data/rf_raw/manual_capture/sample.iq",
    )
    return parser.parse_args()


def main() -> None:
    """Simple CLI for validating the IQ loader."""
    args = parse_args()
    input_path = resolve_input_path(args.input)
    samples = load_raw_iq(input_path)
    complex_signal = convert_to_complex(samples)
    centered_signal = remove_dc_offset(complex_signal)

    print(f"Loaded {len(samples)} interleaved IQ samples from: {input_path}")
    print(f"Data shape: {samples.shape}")
    print(f"Complex signal length: {len(complex_signal)}")
    print(f"Signal mean before centering: {np.mean(complex_signal):.6f}")
    print(f"Signal mean after centering: {np.mean(centered_signal):.6f}")


if __name__ == "__main__":
    main()
