"""Risk scoring helpers for SPECTRA-GUARD.

This module organizes numeric risk values and class labels for the evidence
fusion engine and downstream alert generation.
"""

from __future__ import annotations


def clamp_risk(value: float) -> float:
    """Clamp a risk value to the 0-100 range."""
    return max(0.0, min(100.0, float(value)))


def risk_to_label(risk_score: float) -> str:
    """Convert a numeric risk score into LOW / MEDIUM / HIGH."""
    if risk_score <= 29:
        return "LOW"
    if risk_score <= 69:
        return "MEDIUM"
    return "HIGH"


def normalize_component(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    """Normalize a risk-like value to a 0-100 scale."""
    if maximum == minimum:
        return 0.0
    return clamp_risk((value - minimum) / (maximum - minimum) * 100.0)
