"""Global configuration for the SPECTRA-GUARD lab prototype.

Keep all operational parameters here so they are easy to adjust for different
embedded devices and bench setups.
"""

from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent

# RF / HackRF capture settings.
# NOTE: The best monitoring frequency must be identified experimentally for the
# selected test device and enclosure. There is no single "correct" frequency to
# use for all hardware and lab conditions.
CENTER_FREQ = 433_000_000
SAMPLE_RATE = 10_000_000
LNA_GAIN = 24
VGA_GAIN = 20
CAPTURE_SECONDS = 2

# File locations
RF_CAPTURE_DIR = PROJECT_ROOT / "data" / "rf_raw"
RF_FEATURE_DIR = PROJECT_ROOT / "data" / "rf_features"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"

# Example device metadata
DEVICE_ID = "esp32_lab_device_01"
DEVICE_TYPE = "ESP32"

# Optional: disable or enable logging for experiments
ENABLE_DETAILED_LOGGING = True
