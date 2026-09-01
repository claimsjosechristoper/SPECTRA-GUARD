"""Evidence fusion engine for combining RF, firmware, and network risk signals.

This is a prototype layer intended to combine independent indicators into a
single compromise-risk score. The weights are intentionally documented as
prototype values that must later be tuned using real experimental validation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def compute_overall_risk(rf_risk: float, firmware_risk: float, network_risk: float) -> float:
    """Compute an overall risk score using prototype weights.

    Initial prototype weights:
    - RF: 0.40
    - Firmware: 0.35
    - Network: 0.25

    These weights are placeholders and must be validated with real experimental
    data before claims about operational performance are made.
    """
    overall = (0.40 * rf_risk) + (0.35 * firmware_risk) + (0.25 * network_risk)
    return float(max(0.0, min(100.0, overall)))


def classify_risk(score: float) -> str:
    """Map a numeric risk score to LOW / MEDIUM / HIGH."""
    if score <= 29:
        return "LOW"
    if score <= 69:
        return "MEDIUM"
    return "HIGH"


def fuse_evidence(rf_risk: float, firmware_risk: float, network_risk: float) -> dict:
    """Combine the evidence and apply guard logic for explainable outcomes."""
    overall_risk = compute_overall_risk(rf_risk, firmware_risk, network_risk)
    risk_level = classify_risk(overall_risk)

    reasons: list[str] = []
    if rf_risk >= 70:
        reasons.append("RF behavioural anomaly is elevated.")
    elif rf_risk >= 30:
        reasons.append("RF behaviour deviates from the trusted baseline.")

    if firmware_risk >= 50:
        reasons.append("Firmware integrity check indicates a mismatch from the trusted baseline.")
    elif firmware_risk > 0:
        reasons.append("Firmware integrity differs from the expected trusted hash.")

    if network_risk >= 70:
        reasons.append("Network behaviour is strongly elevated relative to the lab baseline.")
    elif network_risk >= 30:
        reasons.append("Network activity is above the monitored baseline.")

    # Guard logic: RF alone does not prove malware.
    if rf_risk >= 70 and firmware_risk == 0 and network_risk < 30:
        risk_level = "MEDIUM"
        reasons.append("RF anomaly is present, but firmware integrity is verified and network behaviour is normal. Investigation recommended.")

    if rf_risk >= 70 and firmware_risk == 0 and network_risk == 0:
        risk_level = "MEDIUM"
        reasons.append("RF evidence alone is not enough to confirm malware. Further investigation is required.")

    if rf_risk >= 70 and firmware_risk >= 50 and network_risk >= 30:
        risk_level = "HIGH"
        reasons.append("Multiple independent indicators are elevated: RF anomaly, firmware mismatch, and abnormal network behaviour.")

    if not reasons:
        reasons.append("Device behaviour is consistent with the trusted baseline.")

    return {
        "overall_risk": round(overall_risk, 2),
        "risk_level": risk_level,
        "reasons": reasons,
        "rf_risk": rf_risk,
        "firmware_risk": firmware_risk,
        "network_risk": network_risk,
        "weights": {
            "rf": 0.40,
            "firmware": 0.35,
            "network": 0.25,
        },
    }


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for evidence fusion."""
    parser = argparse.ArgumentParser(description="Combine RF, firmware, and network risk into a single compromise-risk score.")
    parser.add_argument("--rf-risk", type=float, required=True, help="RF risk score between 0 and 100.")
    parser.add_argument("--firmware-risk", type=float, required=True, help="Firmware risk score between 0 and 100.")
    parser.add_argument("--network-risk", type=float, required=True, help="Network risk score between 0 and 100.")
    return parser.parse_args()


def main() -> None:
    """Entry point for evidence fusion."""
    args = parse_args()
    result = fuse_evidence(args.rf_risk, args.firmware_risk, args.network_risk)
    print(result)


if __name__ == "__main__":
    main()
