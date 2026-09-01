"""SQLite database setup for the SPECTRA-GUARD FastAPI backend.

This module defines the schema for devices and security events, creates the
SQLite database, and seeds sample rows for the lab prototype dashboard.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_DIR = PROJECT_ROOT / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_URL = f"sqlite:///{DB_DIR / 'spectra_guard.db'}"


class Base(DeclarativeBase):
    """Base class for all ORM tables."""


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, nullable=False, index=True)
    device_type = Column(String, nullable=False)
    status = Column(String, nullable=False, default="LOW")
    last_seen = Column(DateTime, nullable=True)

    # Device profile fields (added for Phase 2: asset/device profiles)
    manufacturer = Column(String, nullable=True)
    model = Column(String, nullable=True)
    mac_address = Column(String, nullable=True, index=True)
    hw_version = Column(String, nullable=True)
    sw_version = Column(String, nullable=True)
    location = Column(String, nullable=True)
    tags = Column(Text, nullable=True)  # comma-separated tags


class RFEvent(Base):
    __tablename__ = "rf_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    rf_risk = Column(Float, nullable=False, default=0.0)
    anomaly_score = Column(Float, nullable=False, default=0.0)
    notes = Column(Text, nullable=True)


class FirmwareEvent(Base):
    __tablename__ = "firmware_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    status = Column(String, nullable=False)
    current_hash = Column(String, nullable=False)
    expected_hash = Column(String, nullable=True)
    firmware_risk = Column(Float, nullable=False, default=0.0)


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    network_risk = Column(Float, nullable=False, default=0.0)
    anomaly_score = Column(Float, nullable=False, default=0.0)
    reasons = Column(Text, nullable=True)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, nullable=True, index=True)
    device_id = Column(String, index=True, nullable=False)
    category = Column(String, nullable=True, index=True)
    timestamp = Column(DateTime, nullable=False)
    risk_level = Column(String, nullable=False)
    overall_risk = Column(Float, nullable=False, default=0.0)
    rf_risk_level = Column(String, nullable=True)
    firmware_status = Column(String, nullable=True)
    network_risk_level = Column(String, nullable=True)
    reasons = Column(Text, nullable=True)
    title = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    status = Column(String, nullable=True, default="OPEN")


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def ensure_security_alert_schema() -> None:
    """Add alert columns needed for device-level SOC correlation without breaking older data."""
    db_path = Path(DATABASE_URL.replace("sqlite:///", ""))
    if not db_path.exists():
        return

    connection = sqlite3.connect(str(db_path))
    try:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(security_alerts)").fetchall()
        }
        for column_name, column_type in {
            "alert_id": "TEXT",
            "category": "TEXT",
            "rf_risk_level": "TEXT",
            "firmware_status": "TEXT",
            "network_risk_level": "TEXT",
            "title": "TEXT",
            "description": "TEXT",
            "status": "TEXT",
        }.items():
            if column_name not in columns:
                connection.execute(
                    f"ALTER TABLE security_alerts ADD COLUMN {column_name} {column_type};"
                )
        connection.commit()
    finally:
        connection.close()


def ensure_device_profile_schema() -> None:
    """Add device profile columns to the devices table when upgrading older databases."""
    db_path = Path(DATABASE_URL.replace("sqlite:///", ""))
    if not db_path.exists():
        return

    connection = sqlite3.connect(str(db_path))
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)").fetchall()}
        for column_name, column_type in {
            "manufacturer": "TEXT",
            "model": "TEXT",
            "mac_address": "TEXT",
            "hw_version": "TEXT",
            "sw_version": "TEXT",
            "location": "TEXT",
            "tags": "TEXT",
        }.items():
            if column_name not in columns:
                connection.execute(f"ALTER TABLE devices ADD COLUMN {column_name} {column_type};")
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    """Create all tables in the configured SQLite database."""
    Base.metadata.create_all(bind=engine)
    ensure_security_alert_schema()
    ensure_device_profile_schema()
    print(f"Database initialized at: {DATABASE_URL}")


def seed_demo_data() -> None:
    """Insert a minimal set of harmless sample records for dashboard testing."""
    db: Session = SessionLocal()
    try:
        existing = db.query(Device).count()
        if existing == 0:
            db.add_all(
                [
                    Device(
                        device_id="esp32_lab_device_01",
                        device_type="ESP32",
                        status="LOW",
                    ),
                    Device(
                        device_id="rpi_lab_device_02",
                        device_type="Raspberry Pi",
                        status="MEDIUM",
                    ),
                ]
            )
        db.commit()
        print("Sample device data inserted.")
    finally:
        db.close()


def verify_database() -> None:
    """Check whether the database file exists and list tables."""
    db_path = Path(DATABASE_URL.replace("sqlite:///", ""))
    if not db_path.exists():
        raise FileNotFoundError(f"Database file was not created: {db_path}")

    connection = sqlite3.connect(str(db_path))
    try:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        ).fetchall()
        print(f"Tables in database: {[table[0] for table in tables]}")
    finally:
        connection.close()


if __name__ == "__main__":
    init_db()
    seed_demo_data()
    verify_database()
