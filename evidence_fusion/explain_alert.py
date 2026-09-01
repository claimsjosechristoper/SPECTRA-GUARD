"""Explainable alert generation for SPECTRA-GUARD.

This module turns the fused risk result into a structured response with a risk
level, overall score, reasons, and recommendation.
"""

from __future__ import annotations

from typing import Any


def build_alert(risk_level: str, overall_risk: float, reasons: list[str]) -> dict[str, Any]:
    """Create a structured, explainable alert payload."""
    if risk_level == "LOW":
        recommendation = "No immediate intervention needed. Keep monitoring the device."
        summary = "Device behaviour is consistent with trusted baseline."
    elif risk_level == "MEDIUM":
        recommendation = "Investigate the device and review the supporting evidence."
        summary = "Evidence is elevated but not enough to confirm compromise."
    else:
        recommendation = "Isolate the test device and investigate immediately."
        summary = "Multiple independent indicators detected."

    return {
        "risk_level": risk_level,
        "overall_risk": round(float(overall_risk), 2),
        "summary": summary,
        "reasons": reasons,
        "recommendation": recommendation,
    }


def explain_from_fusion(result: dict[str, Any]) -> dict[str, Any]:
    """Turn a fused-risk result into a JSON-friendly alert object."""
    risk_level = result.get("risk_level", "LOW")
    overall_risk = float(result.get("overall_risk", 0.0))
    reasons = result.get("reasons", [])
    return build_alert(risk_level, overall_risk, reasons)
