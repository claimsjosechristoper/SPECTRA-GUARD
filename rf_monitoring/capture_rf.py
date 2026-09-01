"""Safe receive-only HackRF capture workflow for SPECTRA-GUARD.

This module is intentionally limited to passive monitoring. It does not transmit,
transmit jamming signals, or perform any active attacks. It captures raw IQ data
from the radio frontend for later FFT and feature analysis.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import CAPTURE_SECONDS, CENTER_FREQ, LNA_GAIN, RF_CAPTURE_DIR, SAMPLE_RATE, VGA_GAIN


def validate_hackrf_available() -> str:
    """Return the HackRF CLI path or raise a clear error if it is unavailable."""
    explicit_path = Path(r"C:\Users\claim\radioconda\Library\bin\hackrf_transfer.exe")
    tool_path = str(explicit_path) if explicit_path.exists() else shutil.which("hackrf_transfer")
    if not tool_path:
        raise FileNotFoundError(
            "hackrf_transfer was not found in PATH. Install the HackRF command-line tools "
            "and confirm 'hackrf_info' works before attempting RF capture."
        )
    return tool_path


def build_capture_command(
    output_file: Path,
    center_freq: int = CENTER_FREQ,
    sample_rate: int = SAMPLE_RATE,
    lna_gain: int = LNA_GAIN,
    vga_gain: int = VGA_GAIN,
    duration_seconds: int = CAPTURE_SECONDS,
    tool_path: str | None = None,
) -> list[str]:
    """Build a receive-only hackrf_transfer command.

    The command only captures raw samples; it never transmits. The exact sample
    count is derived from the sample rate and capture duration.
    """
    sample_count = int(sample_rate * duration_seconds)
    command = [
        tool_path or "hackrf_transfer",
        "-f",
        str(center_freq),
        "-s",
        str(sample_rate),
        "-l",
        str(lna_gain),
        "-g",
        str(vga_gain),
        "-n",
        str(sample_count),
        "-r",
        str(output_file),
    ]
    return command


def ensure_capture_directory(output_file: Path) -> None:
    """Create the directory that will hold the raw capture file."""
    output_file.parent.mkdir(parents=True, exist_ok=True)


def capture_iq_samples(
    output_file: Path | str,
    center_freq: int = CENTER_FREQ,
    sample_rate: int = SAMPLE_RATE,
    lna_gain: int = LNA_GAIN,
    vga_gain: int = VGA_GAIN,
    duration_seconds: int = CAPTURE_SECONDS,
    timeout: int = 20,
) -> Path:
    """Capture raw IQ samples using HackRF in receive-only mode.

    Returns the path to the generated file.
    """
    output_path = Path(output_file)
    ensure_capture_directory(output_path)
    tool_path = validate_hackrf_available()

    command = build_capture_command(
        output_file=output_path,
        center_freq=center_freq,
        sample_rate=sample_rate,
        lna_gain=lna_gain,
        vga_gain=vga_gain,
        duration_seconds=duration_seconds,
        tool_path=tool_path,
    )

    print(f"Using HackRF CLI: {tool_path}")
    print(f"Receive-only capture command: {' '.join(command)}")
    print(f"Saving raw IQ samples to: {output_path}")

    try:
        subprocess.run(command, check=True, timeout=timeout, capture_output=True, text=True)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"HackRF capture timed out after {timeout} seconds while receiving samples from "
            f"{center_freq} Hz."
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or ""
        stdout = exc.stdout or ""
        details = (stderr or stdout).strip() or "No detailed error output was returned."
        raise RuntimeError(
            "HackRF capture failed. Check the device connection, the selected frequency, "
            f"and the HackRF command-line tools installation. Details: {details}"
        ) from exc

    if not output_path.exists():
        raise FileNotFoundError(f"Capture did not create the expected output file: {output_path}")

    print(f"Success: raw capture saved to {output_path}")
    return output_path


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for the safe receiver script."""
    parser = argparse.ArgumentParser(
        description="Safely capture raw IQ samples from a HackRF device in receive-only mode."
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(RF_CAPTURE_DIR / "manual_capture" / "sample.iq"),
        help="Destination path for the captured IQ sample file. Default: data/rf_raw/manual_capture/sample.iq",
    )
    parser.add_argument(
        "--frequency",
        type=int,
        default=CENTER_FREQ,
        help=f"Center frequency in Hz. Default: {CENTER_FREQ}",
    )
    parser.add_argument(
        "--sample-rate",
        type=int,
        default=SAMPLE_RATE,
        help=f"Sample rate in Hz. Default: {SAMPLE_RATE}",
    )
    parser.add_argument(
        "--lna-gain",
        type=int,
        default=LNA_GAIN,
        help=f"LNA gain in dB. Default: {LNA_GAIN}",
    )
    parser.add_argument(
        "--vga-gain",
        type=int,
        default=VGA_GAIN,
        help=f"VGA gain in dB. Default: {VGA_GAIN}",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=CAPTURE_SECONDS,
        help=f"Capture duration in seconds. Default: {CAPTURE_SECONDS}",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the safe receive-only capture workflow."""
    args = parse_args()

    output_path = PROJECT_ROOT / args.output if not Path(args.output).is_absolute() else Path(args.output)

    print("SPECTRA-GUARD: safe receive-only RF capture")
    print("This tool only captures samples in passive receive mode and does not transmit.")
    print("Do not use this workflow for active jamming, unauthorized interception, or any transmission-based testing.")

    capture_iq_samples(
        output_file=output_path,
        center_freq=args.frequency,
        sample_rate=args.sample_rate,
        lna_gain=args.lna_gain,
        vga_gain=args.vga_gain,
        duration_seconds=args.duration,
    )


if __name__ == "__main__":
    main()
