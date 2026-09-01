"""Network feature extraction for the SPECTRA-GUARD isolated lab network.

This module creates a safe baseline for monitoring an embedded device's network
behaviour in a lab environment. It calculates packet-level features and can be
used before training a simple anomaly model.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import pyshark
except ImportError:  # pragma: no cover
    pyshark = None


DEFAULT_NETWORK_DIR = PROJECT_ROOT / "data" / "network"


def resolve_input_path(file_path: str | Path) -> Path:
    """Resolve a relative path against the project root."""
    path = Path(file_path)
    if not path.is_absolute():
        candidate = PROJECT_ROOT / path
        if candidate.exists():
            return candidate
        return path
    return path


def parse_csv_packet_log(csv_path: str | Path) -> list[dict[str, Any]]:
    """Read a simple packet CSV with keys: timestamp, src_ip, dst_ip, protocol, length."""
    path = resolve_input_path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Network CSV not found: {path}")

    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "src_ip", "dst_ip", "protocol", "length"}
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise ValueError(f"CSV is missing required columns: {missing}")

        for row in reader:
            rows.append(
                {
                    "timestamp": row["timestamp"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "protocol": str(row["protocol"]).upper(),
                    "length": int(float(row["length"])),
                }
            )
    return rows


def parse_pcap_with_pyshark(pcap_path: str | Path) -> list[dict[str, Any]]:
    """Read a packet capture using pyshark when available."""
    if pyshark is None:
        raise ImportError(
            "pyshark is not installed. Install it with pip install pyshark or provide a CSV log instead."
        )

    path = resolve_input_path(pcap_path)
    capture = pyshark.FileCapture(str(path), keep_packets=False)
    rows: list[dict[str, Any]] = []
    for packet in capture:
        packet_obj = {
            "timestamp": getattr(packet, "sniff_time", None),
            "src_ip": getattr(packet.ip, "src", None) if hasattr(packet, "ip") else None,
            "dst_ip": getattr(packet.ip, "dst", None) if hasattr(packet, "ip") else None,
            "protocol": (
                packet.highest_layer.lower() if hasattr(packet, "highest_layer") else "UNKNOWN"
            ),
            "length": int(getattr(packet, "length", 0) or 0),
        }
        rows.append(packet_obj)
    return rows


def convert_timestamp_to_seconds(value: str) -> float:
    """Convert packet timestamps into seconds since the first packet."""
    if value is None or value == "":
        return 0.0

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.timestamp()
    except ValueError:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0


def compute_network_features(packet_rows: list[dict[str, Any]]) -> dict[str, float | int | list[str]]:
    """Create network behaviour features from a list of packets."""
    if not packet_rows:
        raise ValueError("No packets were supplied to compute network features.")

    packet_count = len(packet_rows)
    byte_count = sum(int(row.get("length", 0) or 0) for row in packet_rows)
    destinations = [row.get("dst_ip") for row in packet_rows if row.get("dst_ip")]
    unique_destination_count = len(set(destinations))

    protocol_counts = Counter(str(row.get("protocol", "UNKNOWN")).upper() for row in packet_rows)
    tcp_count = int(protocol_counts.get("TCP", 0))
    udp_count = int(protocol_counts.get("UDP", 0))
    icmp_count = int(protocol_counts.get("ICMP", 0))

    timestamps = [convert_timestamp_to_seconds(row.get("timestamp")) for row in packet_rows if row.get("timestamp") is not None]
    if not timestamps:
        connections_per_minute = 0.0
    else:
        start_time = min(timestamps)
        end_time = max(timestamps)
        elapsed_seconds = max(1.0, end_time - start_time)
        connections_per_minute = float(packet_count / (elapsed_seconds / 60.0))

    average_packet_size = float(byte_count / packet_count) if packet_count else 0.0

    # This is intentionally a simple rule-based baseline. It does not treat any
    # single high packet count as malicious by itself.
    new_destination_count = 0
    seen_destinations: set[str] = set()
    for row in packet_rows:
        dst = row.get("dst_ip")
        if dst and dst not in seen_destinations:
            seen_destinations.add(dst)
            new_destination_count += 1

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "unique_destination_count": unique_destination_count,
        "new_destination_count": new_destination_count,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "connections_per_minute": connections_per_minute,
        "average_packet_size": average_packet_size,
        "protocol_counts": dict(protocol_counts),
    }


def extract_network_features(file_path: str | Path) -> dict[str, float | int | list[str]]:
    """Read a PCAP or CSV and return a structured feature dictionary."""
    path = resolve_input_path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Network capture not found: {path}")

    if path.suffix.lower() in {".csv"}:
        packet_rows = parse_csv_packet_log(path)
    elif path.suffix.lower() in {".pcap", ".pcapng"}:
        packet_rows = parse_pcap_with_pyshark(path)
    else:
        raise ValueError(
            "Unsupported network capture format. Use a .csv packet log or a .pcap/.pcapng file."
        )

    return compute_network_features(packet_rows)


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for network feature extraction."""
    parser = argparse.ArgumentParser(description="Extract safe lab-network features from a packet trace.")
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to a packet CSV or .pcap/.pcapng file.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for this module."""
    args = parse_args()
    result = extract_network_features(args.input)
    print(result)


if __name__ == "__main__":
    main()
