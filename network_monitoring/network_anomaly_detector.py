"""Safe baseline network anomaly detector for SPECTRA-GUARD.

This module does not perform scanning or active attacks. It evaluates traffic
summary features against a simple lab baseline and returns a network risk score
plus explanation text. It may later be extended with an IsolationForest model.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from network_monitoring.network_features import extract_network_features


def get_baseline_thresholds() -> dict[str, float]:
    """Define a simple baseline for lab network behaviour."""
    return {
        "packet_count": 200.0,
        "byte_count": 5000.0,
        "unique_destination_count": 5.0,
        "new_destination_count": 3.0,
        "connections_per_minute": 120.0,
        "average_packet_size": 500.0,
    }


def compute_network_anomaly_score(features: dict[str, Any]) -> tuple[int, list[str]]:
    """Return a 0-100 risk score and human-readable reasons.

    This is a rule-based baseline. It is intentionally conservative and does not
    treat a single feature as direct proof of compromise.
    """
    thresholds = get_baseline_thresholds()
    reasons: list[str] = []
    risk_score = 0

    packet_count = float(features.get("packet_count", 0))
    if packet_count > thresholds["packet_count"]:
        risk_score += 20
        reasons.append("Traffic volume is above the lab baseline.")

    byte_count = float(features.get("byte_count", 0))
    if byte_count > thresholds["byte_count"]:
        risk_score += 20
        reasons.append("Network byte volume is elevated above the safe baseline.")

    unique_destinations = float(features.get("unique_destination_count", 0))
    if unique_destinations > thresholds["unique_destination_count"]:
        risk_score += 15
        reasons.append("Connections are spreading to more destinations than expected.")

    new_destinations = float(features.get("new_destination_count", 0))
    if new_destinations > thresholds["new_destination_count"]:
        risk_score += 15
        reasons.append("Several new external lab destinations are being contacted.")

    conn_per_min = float(features.get("connections_per_minute", 0))
    if conn_per_min > thresholds["connections_per_minute"]:
        risk_score += 15
        reasons.append("Connection rate has increased beyond the normal lab pattern.")

    avg_packet_size = float(features.get("average_packet_size", 0))
    if avg_packet_size > thresholds["average_packet_size"]:
        risk_score += 15
        reasons.append("Average packet size deviates significantly from baseline traffic.")

    # Small additional emphasis for protocol mix anomalies
    tcp_count = int(features.get("tcp_count", 0))
    udp_count = int(features.get("udp_count", 0))
    icmp_count = int(features.get("icmp_count", 0))
    if tcp_count > 0 and udp_count > 0 and icmp_count > 0:
        # Not malicious by itself, but we flag a mixed traffic pattern if it is
        # combined with other anomalies.
        if risk_score > 0:
            risk_score += 10
            reasons.append("Protocol mix is unusual for the monitored lab profile.")

    risk_score = max(0, min(100, risk_score))
    if not reasons:
        reasons.append("Network behaviour is consistent with the monitored lab baseline.")

    return risk_score, reasons


def analyze_network_capture(input_path: str | Path) -> dict[str, Any]:
    """Extract network features from a capture and score the network behaviour."""
    features = extract_network_features(input_path)
    risk_score, reasons = compute_network_anomaly_score(features)

    result = {
        "network_anomaly_score": risk_score,
        "network_risk_score": risk_score,
        "reasons": reasons,
        "features": features,
    }
    return result


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for network anomaly analysis."""
    parser = argparse.ArgumentParser(description="Compute a safe baseline network risk score for an isolated lab capture.")
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to a network packet CSV or a .pcap/.pcapng file.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for network anomaly analysis."""
    args = parse_args()
    result = analyze_network_capture(args.input)
    print(result)


if __name__ == "__main__":
    main()
