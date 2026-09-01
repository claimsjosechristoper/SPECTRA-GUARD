"""Firmware integrity verification for SPECTRA-GUARD.

This module calculates SHA-256 hashes for firmware images, compares them against
trusted values stored in trusted_hashes.json, and returns a risk result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

HASH_DB_PATH = Path(__file__).resolve().parent / "trusted_hashes.json"


def resolve_input_path(file_path: str | Path) -> Path:
    """Resolve relative firmware paths against the project root."""
    path = Path(file_path)
    if not path.is_absolute():
        project_relative = PROJECT_ROOT / path
        if project_relative.exists():
            return project_relative
        return path
    return path


def calculate_sha256(file_path: str | Path) -> str:
    """Calculate the SHA-256 digest for a file."""
    path = resolve_input_path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Firmware file not found: {path}")

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_trusted_hashes(json_path: str | Path = HASH_DB_PATH) -> dict:
    """Load the trusted firmware hash database from JSON."""
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"Trusted hash database not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Trusted hash database is not valid JSON: {path}") from exc

    if not isinstance(data, dict):
        raise ValueError("Trusted hash database must contain a JSON object.")
    return data


def load_trusted_hash(device_id: str, json_path: str | Path = HASH_DB_PATH) -> str | None:
    """Return the trusted SHA-256 hash for a device, if one is registered."""
    database = load_trusted_hashes(resolve_input_path(json_path) if not Path(json_path).is_absolute() else Path(json_path))
    devices = database.get("devices", {})
    if not isinstance(devices, dict):
        raise ValueError("The trusted hash database has an invalid 'devices' structure.")
    return devices.get(device_id)


def save_trusted_hash(device_id: str, hash_value: str, json_path: str | Path = HASH_DB_PATH) -> None:
    """Persist a trusted hash for a device in the JSON database."""
    path = Path(json_path)
    path = resolve_input_path(path) if not path.is_absolute() else path
    path.parent.mkdir(parents=True, exist_ok=True)

    database = load_trusted_hashes(path) if path.exists() else {"devices": {}}
    devices = database.get("devices", {})
    if not isinstance(devices, dict):
        raise ValueError("The trusted hash database has an invalid 'devices' structure.")

    devices[device_id] = hash_value
    database["devices"] = devices

    with path.open("w", encoding="utf-8") as handle:
        json.dump(database, handle, indent=2)
        handle.write("\n")

    print(f"Saved trusted firmware hash for device '{device_id}' to {path}")


def verify_firmware(device_id: str, firmware_path: str | Path, json_path: str | Path = HASH_DB_PATH) -> dict:
    """Verify a firmware file against the trusted hash for a device."""
    resolved_firmware = resolve_input_path(firmware_path)
    current_hash = calculate_sha256(resolved_firmware)
    expected_hash = load_trusted_hash(device_id, json_path=json_path)

    if expected_hash is None:
        return {
            "device_id": device_id,
            "status": "MISMATCH",
            "expected_hash": None,
            "current_hash": current_hash,
            "firmware_risk": 100,
            "message": "No trusted firmware hash is registered for this device.",
        }

    status = "VERIFIED" if current_hash == expected_hash else "MISMATCH"
    risk = 0 if status == "VERIFIED" else 100

    return {
        "device_id": device_id,
        "status": status,
        "expected_hash": expected_hash,
        "current_hash": current_hash,
        "firmware_risk": risk,
        "message": "Firmware matches the trusted baseline." if status == "VERIFIED" else "Firmware differs from the trusted baseline.",
    }


def register_trusted_hash(device_id: str, firmware_path: str | Path, json_path: str | Path = HASH_DB_PATH) -> str:
    """Register the SHA-256 hash of a harmless lab firmware file for a device."""
    resolved_firmware = resolve_input_path(firmware_path)
    hash_value = calculate_sha256(resolved_firmware)
    save_trusted_hash(device_id, hash_value, json_path=json_path)
    return hash_value


def parse_args() -> argparse.Namespace:
    """Prepare CLI arguments for firmware verification and registration."""
    parser = argparse.ArgumentParser(description="Verify or register trusted firmware hashes for a lab device.")
    parser.add_argument(
        "--device-id",
        type=str,
        required=True,
        help="Device ID to verify or register.",
    )
    parser.add_argument(
        "--firmware",
        type=str,
        help="Path to the firmware image file to verify.",
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="Register the SHA-256 hash of the provided firmware file as trusted for the device.",
    )
    parser.add_argument(
        "--json",
        type=str,
        default=str(HASH_DB_PATH),
        help=f"Path to the trusted hash database JSON. Default: {HASH_DB_PATH}",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for firmware hash verification and registration."""
    args = parse_args()

    if not args.firmware:
        raise ValueError("A firmware file path is required. Use --firmware with the file to verify or register.")

    if args.register:
        hash_value = register_trusted_hash(args.device_id, args.firmware, json_path=args.json)
        print({
            "device_id": args.device_id,
            "status": "REGISTERED",
            "expected_hash": hash_value,
            "current_hash": hash_value,
            "firmware_risk": 0,
        })
    else:
        result = verify_firmware(args.device_id, args.firmware, json_path=args.json)
        print(result)


if __name__ == "__main__":
    main()
