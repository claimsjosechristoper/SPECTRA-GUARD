# SPECTRA-GUARD

SPECTRA-GUARD is a safe laboratory prototype for detecting suspicious behaviour in embedded devices used in the power sector. It combines three independent evidence sources:

- RF / electromagnetic behaviour monitoring
- Firmware integrity verification
- Network behaviour monitoring

The final output is a risk assessment that combines these signals, rather than treating RF anomalies as proof of malware.

## Architecture overview

The project is organized into these main areas:

- `rf_monitoring/` for IQ capture, FFT-based analysis, feature extraction, and RF anomaly detection
- `firmware_integrity/` for trusted hash management and firmware verification
- `network_monitoring/` for traffic capture and network anomaly analysis
- `ml_engine/` for training and evaluating anomaly models
- `evidence_fusion/` for combining risk scores and producing explainable alerts
- `backend/` for the FastAPI API and SQLite-backed persistence
- `dashboard/` for the SOC-style monitoring interface
- `data/` for raw signals, extracted features, and results

## Safety note

SPECTRA-GUARD does not treat RF/EM anomalies as direct proof of malware. RF evidence is correlated with firmware integrity and network behaviour to generate a compromise-risk score.

## Phase 1 setup

This repository currently contains the initial project skeleton and environment setup files required before RF capture work begins.

## Windows + VS Code terminal commands

Open a VS Code terminal in the project root and run:

```powershell
cd C:\SPECTRA_GUARD
python -m venv venv
.\venv\Scripts\activate
python --version
pip install --upgrade pip
pip install -r requirements.txt
```

## Verify Python

Run:

```powershell
python --version
python -c "import sys; print(sys.executable)"
```

You should see a valid Python version and a path inside the `venv` environment.

## Verify HackRF One

On Windows, confirm the HackRF toolchain is installed and visible in PATH:

```powershell
hackrf_info
```

If it returns device information or a valid CLI banner, the HackRF tools are available. If it fails, install the HackRF command-line utilities separately and confirm the path is configured before continuing to RF processing.

## Demo Run Instructions

1. Activate the project environment:

   ```powershell
   cd C:\SPECTRA_GUARD
   .\venv\Scripts\activate
   ```

2. Start the FastAPI app:

   ```powershell
   uvicorn backend.main:app --host 127.0.0.1 --port 8000
   ```

3. Open the dashboard in a browser:

   ```text
   http://127.0.0.1:8000/
   ```

4. Optional baseline collection:

   - Enroll a known-good firmware baseline through the /api/firmware/baseline endpoint.
   - Use the RF capture endpoints only for receive-only testing and avoid any active transmission.

5. Optional test endpoints:

   ```powershell
   $env:ENABLE_TEST_ENDPOINTS = "true"
   ```

   Then reload the app and use the test endpoints under /api/alerts/simulate if you need a quick synthetic check.

6. Common troubleshooting:

   - If the dashboard loads but a module is unavailable, use /api/health to inspect which component is degraded.
   - If HackRF is not connected, the UI will keep running using degraded status instead of crashing.
   - If the ML model is not trained, /api/ml/rf/status and /api/ml/rf/predict/latest return clean status responses rather than HTTP 500s.
   - If a dashboard API fails unexpectedly, the backend now returns structured JSON with a status, module, message, and timestamp.

## Next step

The next phase will begin with safe receive-only HackRF capture and FFT analysis once the environment and `hackrf_info` validation are confirmed.
