"""Pydantic schemas for the SPECTRA-GUARD FastAPI backend.

These models define the shapes used by the API for device status, RF analysis,
firmware verification, network analysis, and evidence fusion.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class RFAnalysisRequest(BaseModel):
    """Request payload for RF behavior analysis."""

    device_id: str = Field(..., description="Unique device identifier")
    iq_file: str = Field(..., description="Path to the RF IQ capture file")
    sample_rate: float = Field(10_000_000.0, description="Capture sample rate in Hz")


class FirmwareVerificationRequest(BaseModel):
    """Request payload for firmware verification."""

    device_id: str = Field(..., description="Unique device identifier")
    firmware_path: str = Field(..., description="Path to the firmware binary to verify")


class NetworkAnalysisRequest(BaseModel):
    """Request payload for network behaviour analysis."""

    device_id: str = Field(..., description="Unique device identifier")
    capture_path: str = Field(..., description="Path to the packet capture or CSV log")


class FusionRequest(BaseModel):
    """Request payload for evidence fusion."""

    device_id: str = Field(..., description="Unique device identifier")
    rf_risk: float = Field(0.0, ge=0.0, le=100.0, description="RF risk score from 0 to 100")
    firmware_risk: float = Field(0.0, ge=0.0, le=100.0, description="Firmware risk score from 0 to 100")
    network_risk: float = Field(0.0, ge=0.0, le=100.0, description="Network risk score from 0 to 100")


class DeviceStatusResponse(BaseModel):
    """Response payload for a device status query."""

    device_id: str
    device_type: str
    status: str = "LOW"
    rf_risk: float = 0.0
    firmware_integrity: str = "VERIFIED"
    network_risk: float = 0.0
    overall_risk: float = 0.0
    risk_level: str = "LOW"
    reasons: list[str] = []
    timestamp: str


class DeviceProfileRequest(BaseModel):
    """Request model to register or update a device profile."""

    device_id: str = Field(..., description="Unique device identifier")
    device_type: str = Field(..., description="High-level device type, e.g. ESP32, Raspberry Pi")
    manufacturer: Optional[str] = Field(None, description="Device manufacturer")
    model: Optional[str] = Field(None, description="Device model")
    mac_address: Optional[str] = Field(None, description="Primary MAC address for the device")
    hw_version: Optional[str] = Field(None, description="Hardware revision/version")
    sw_version: Optional[str] = Field(None, description="Software/firmware version")
    location: Optional[str] = Field(None, description="Logical/physical location of the device")
    tags: Optional[list[str]] = Field(None, description="Optional list of tags to classify the device")


class DeviceProfileResponse(BaseModel):
    """Response model for registered device profiles."""

    id: Optional[int]
    device_id: str
    device_type: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    mac_address: Optional[str] = None
    hw_version: Optional[str] = None
    sw_version: Optional[str] = None
    location: Optional[str] = None
    tags: list[str] = []
    last_seen: Optional[str] = None


class AlertRecord(BaseModel):
    """Security alert data returned by the API."""

    id: Optional[int] = None
    device_id: str
    timestamp: str
    risk_level: str
    overall_risk: float
    reasons: list[str] = []
    recommendation: str


class RFAnalysisResponse(BaseModel):
    """Response from the RF analysis endpoint."""

    prediction: int
    anomaly_score: float
    rf_risk_score: int
    device_id: str
    status: str


class FirmwareVerificationResponse(BaseModel):
    """Response from the firmware verification endpoint."""

    device_id: str
    status: str
    expected_hash: Optional[str] = None
    current_hash: Optional[str] = None
    firmware_risk: int = 0
    message: Optional[str] = None


class NetworkAnalysisResponse(BaseModel):
    """Response from the network analysis endpoint."""

    network_anomaly_score: int
    network_risk_score: int
    reasons: list[str]
    features: dict[str, Any]


class FusionResponse(BaseModel):
    """Response from the evidence fusion endpoint."""

    overall_risk: float
    risk_level: str
    reasons: list[str]
    rf_risk: float
    firmware_risk: float
    network_risk: float
    weights: dict[str, float]


class HealthResponse(BaseModel):
    """Simple health-check response."""

    status: str = "ok"
    service: str = "SPECTRA-GUARD API"


class SystemStatusResponse(BaseModel):
    """System health response for the dashboard and API status view."""

    system_status: str
    hackrf_status: str
    hackrf_serial: Optional[str] = None
    hackrf_firmware: Optional[str] = None
    ml_engine_status: str
    firmware_monitor_status: str
    timestamp: str
    last_seen: Optional[str] = None
    last_capture_time: Optional[str] = None

