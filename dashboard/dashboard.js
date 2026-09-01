const dashboardData = {
  overallRisk: 'NORMAL',
  overallScore: 0,
  rfRisk: 'NORMAL',
  rfScore: 0,
  firmwareStatus: 'VERIFIED',
  firmwareDeviceId: 'esp32_01',
  firmwareLastChecked: null,
  firmwareCurrentHash: null,
  firmwareBaselineHash: null,
  deviceRiskLevel: 'NORMAL',
  deviceRiskScore: 0,
  networkRisk: 'LOW',
  networkScore: 10,
  systemStatus: 'ONLINE',
  hackrfStatus: 'CONNECTED',
  mlEngineStatus: 'READY',
  firmwareMonitorStatus: 'ACTIVE',
  alerts: [
    {
      time: '2026-08-23 13:00',
      device: 'esp32_lab_device_01',
      level: 'MEDIUM',
      reason: 'RF anomaly observed with verified firmware.'
    },
    {
      time: '2026-08-23 13:02',
      device: 'esp32_lab_device_01',
      level: 'HIGH',
      reason: 'Firmware mismatch plus elevated RF behaviour.'
    }
  ],
  spectrum: {
    labels: ['0', '2', '4', '6', '8', '10'],
    values: [18, 26, 24, 39, 30, 22]
  }
};

let spectrumChart = null;

async function fetchSystemStatus() {
  try {
    const response = await fetch('/api/status');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    dashboardData.systemStatus = data.system_status || dashboardData.systemStatus;
    dashboardData.hackrfStatus = data.hackrf_status || dashboardData.hackrfStatus;
    dashboardData.mlEngineStatus = data.ml_engine_status || dashboardData.mlEngineStatus;
    dashboardData.firmwareMonitorStatus = data.firmware_monitor_status || dashboardData.firmwareMonitorStatus;
    dashboardData.timestamp = data.timestamp || new Date().toISOString();

    const rfPanel = document.querySelector('#rf');
    if (rfPanel) {
      const tag = rfPanel.querySelector('.tag');
      if (tag) {
        if (dashboardData.hackrfStatus === 'CONNECTED') {
          tag.textContent = 'HackRF One Connected';
          tag.className = 'tag ok';
        } else {
          tag.textContent = 'HackRF One Disconnected';
          tag.className = 'tag red';
        }
      }
    }
  } catch (error) {
    console.warn('Unable to fetch /api/status. Using placeholder data instead.', error);
  }
}

function shortenHash(hashValue, length = 10) {
  if (!hashValue) {
    return '—';
  }
  if (hashValue.length <= length) {
    return hashValue;
  }
  return `${hashValue.slice(0, Math.max(4, length / 2))}…${hashValue.slice(-Math.max(4, length / 2))}`;
}

function firmwareStyleForStatus(status) {
  const normalized = (status || 'ERROR').toUpperCase();
  if (normalized === 'VERIFIED') {
    return { tag: 'ok', card: 'green', text: 'VERIFIED' };
  }
  if (normalized === 'MODIFIED') {
    return { tag: 'red', card: 'red', text: 'MODIFIED' };
  }
  if (normalized === 'NO_BASELINE') {
    return { tag: 'amber', card: 'amber', text: 'NO_BASELINE' };
  }
  return { tag: 'red', card: 'red', text: 'ERROR' };
}

async function fetchFirmwareStatus() {
  try {
    const response = await fetch('/api/firmware/status');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    if (!data || data.status !== 'SUCCESS') {
      throw new Error('Invalid firmware status payload');
    }

    dashboardData.firmwareStatus = data.firmware_status || dashboardData.firmwareStatus;
    dashboardData.firmwareDeviceId = data.device_id || dashboardData.firmwareDeviceId;
    dashboardData.firmwareLastChecked = data.checked_at || dashboardData.firmwareLastChecked;
    dashboardData.firmwareCurrentHash = data.current_hash || dashboardData.firmwareCurrentHash;
    dashboardData.firmwareBaselineHash = data.baseline_hash || dashboardData.firmwareBaselineHash;

    const firmwareCard = document.querySelectorAll('.status-card')[2];
    if (firmwareCard) {
      const value = firmwareCard.querySelector('.value');
      const small = firmwareCard.querySelector('small');
      const style = firmwareStyleForStatus(dashboardData.firmwareStatus);
      firmwareCard.classList.remove('green', 'amber', 'red');
      firmwareCard.classList.add(style.card);
      if (value) {
        value.textContent = style.text;
      }
      if (small) {
        const statusText = (dashboardData.firmwareStatus || 'UNKNOWN').toUpperCase();
        small.textContent = statusText === 'VERIFIED' ? 'Healthy' : statusText === 'MODIFIED' ? 'Attention required' : statusText === 'NO_BASELINE' ? 'Trust baseline missing' : 'Check device';
      }
    }

    const firmwarePanel = document.querySelector('#firmware-integrity');
    if (!firmwarePanel) {
      return;
    }

    const tag = firmwarePanel.querySelector('.tag');
    const items = firmwarePanel.querySelectorAll('.info-list li strong');
    const style = firmwareStyleForStatus(dashboardData.firmwareStatus);
    if (tag) {
      tag.className = `tag ${style.tag}`;
      tag.textContent = style.text;
    }

    if (items.length >= 4) {
      items[0].textContent = dashboardData.firmwareDeviceId || 'Unknown';
      items[1].textContent = dashboardData.firmwareStatus || 'UNKNOWN';
      items[2].textContent = dashboardData.firmwareLastChecked ? new Date(dashboardData.firmwareLastChecked).toLocaleString() : '—';
      items[3].textContent = shortenHash(dashboardData.firmwareCurrentHash, 12);
      if (items.length >= 5) {
        items[4].textContent = shortenHash(dashboardData.firmwareBaselineHash, 12);
      }
    }
  } catch (error) {
    console.warn('Unable to fetch /api/firmware/status', error);
  }
}

async function fetchNetworkStatus() {
  try {
    const response = await fetch('/api/network/status');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    if (!data || data.status !== 'SUCCESS') {
      throw new Error('Invalid network status payload');
    }

    dashboardData.networkScore = data.network_risk_score ?? dashboardData.networkScore;
    dashboardData.networkRisk = data.network_risk_level ?? dashboardData.networkRisk;

    const cards = document.querySelectorAll('.status-card');
    if (cards.length >= 4) {
      const networkCard = cards[3];
      networkCard.querySelector('.value').textContent = dashboardData.networkRisk;
      networkCard.querySelector('small').textContent = `${dashboardData.networkScore} / 100`;
    }
  } catch (error) {
    console.warn('Unable to fetch /api/network/status', error);
  }
}

function renderOverview() {
  const cards = document.querySelectorAll('.status-card');

  if (!cards.length) {
    return;
  }

  const overall = cards[0].querySelector('.value');
  const rf = cards[1].querySelector('.value');
  const firmware = cards[2].querySelector('.value');
  const network = cards[3].querySelector('.value');

  const systemStatus = document.querySelector('.status-pill');
  if (systemStatus) {
    systemStatus.textContent = dashboardData.systemStatus;
  }

  cards[0].querySelector('.label').textContent = 'Unified Device Risk';
  cards[0].classList.remove('green', 'amber', 'red');
  cards[0].classList.add(dashboardData.deviceRiskLevel === 'HIGH' ? 'red' : dashboardData.deviceRiskLevel === 'MEDIUM' ? 'amber' : 'green');
  overall.textContent = dashboardData.deviceRiskLevel || 'NORMAL';
  cards[0].querySelector('small').textContent = `${dashboardData.deviceRiskScore ?? 0} / 100`;

  cards[1].querySelector('.label').textContent = 'RF Risk';
  rf.textContent = dashboardData.rfRisk || 'NORMAL';
  cards[1].querySelector('small').textContent = `${dashboardData.rfScore ?? 0} / 100`;

  cards[2].querySelector('.label').textContent = 'Firmware Status';
  firmware.textContent = dashboardData.firmwareStatus || 'VERIFIED';
  cards[2].querySelector('small').textContent = `${dashboardData.firmwareStatus || 'VERIFIED'}`;

  cards[3].querySelector('.label').textContent = 'Network Risk';
  network.textContent = dashboardData.networkRisk || 'LOW';
  cards[3].querySelector('small').textContent = `${dashboardData.networkScore ?? 0} / 100`;
}

async function updateAlertStatus(alertId, newStatus) {
  try {
    const response = await fetch(`/api/alerts/${alertId}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `HTTP ${response.status}`);
    }

    await fetchAlerts();
  } catch (error) {
    console.error(`Unable to update alert ${alertId} to ${newStatus}`, error);
  }
}

async function fetchAlerts() {
  const tbody = document.querySelector('tbody');
  if (!tbody) return;

  try {
    const resp = await fetch('/api/alerts');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    if (!data || data.status !== 'SUCCESS') throw new Error('Invalid alerts payload');

    const alerts = data.alerts || [];
    if (!alerts.length) {
      tbody.innerHTML = '<tr><td colspan="7">No security alerts</td></tr>';
      return;
    }

    tbody.innerHTML = alerts
      .map((a) => {
        const severity = a.severity || 'LOW';
        const levelClass = severity.toLowerCase() === 'high' ? 'high' : severity.toLowerCase() === 'medium' ? 'medium' : 'low';
        const status = a.status || 'OPEN';
        let actionCell = '<span>—</span>';
        let nextStatus = '';
        if (status === 'OPEN') {
          nextStatus = 'ACKNOWLEDGED';
          actionCell = `<button type="button" class="alert-action" data-alert-id="${a.alert_id}" data-next-status="${nextStatus}">Acknowledge</button>`;
        } else if (status === 'ACKNOWLEDGED') {
          nextStatus = 'CLOSED';
          actionCell = `<button type="button" class="alert-action" data-alert-id="${a.alert_id}" data-next-status="${nextStatus}">Close</button>`;
        }

        return `
          <tr>
            <td>${a.timestamp}</td>
            <td>${a.category}</td>
            <td class="alert ${levelClass}">${severity}</td>
            <td>${a.risk_score}</td>
            <td>${a.description}</td>
            <td>${status}</td>
            <td>${actionCell}</td>
          </tr>
        `;
      })
      .join('');

    document.querySelectorAll('.alert-action').forEach((button) => {
      button.addEventListener('click', async () => {
        const alertId = button.getAttribute('data-alert-id');
        const nextStatus = button.getAttribute('data-next-status');
        if (!alertId || !nextStatus) {
          return;
        }
        await updateAlertStatus(alertId, nextStatus);
      });
    });
  } catch (err) {
    console.warn('Failed to fetch alerts', err);
    tbody.innerHTML = '<tr><td colspan="7">No security alerts</td></tr>';
  }
}

function renderSpectrumPlaceholder() {
  const chartBox = document.querySelector('.chart-box');
  if (!chartBox) {
    return;
  }

  chartBox.innerHTML = `
    <div class="chart-panel">
      <div class="chart-metrics">
        <span><strong>Center:</strong> 433.0 MHz</span>
        <span><strong>Peak:</strong> --</span>
        <span><strong>Power:</strong> --</span>
        <span><strong>Source:</strong> --</span>
      </div>
      <canvas aria-label="RF spectrum plot"></canvas>
    </div>
  `;
}

function updateSpectrumChart(spectrumData) {
  const chartBox = document.querySelector('.chart-box');
  if (!chartBox) {
    return;
  }

  // Restore chart elements if wiped by error/disconnect state
  if (!chartBox.querySelector('.chart-panel')) {
    renderSpectrumPlaceholder();
  }

  const labels = spectrumData.frequencies.map((freq) => (freq / 1_000_000).toFixed(3));
  const values = spectrumData.power_db;
  const peakIndex = values.indexOf(Math.max(...values));
  const peakFrequency = spectrumData.frequencies[peakIndex];
  const peakPower = values[peakIndex];

  // Update tag to LIVE or STALE based on data age
  const spectrumPanel = document.querySelector('#reports');
  if (spectrumPanel) {
    const tag = spectrumPanel.querySelector('.tag');
    if (tag) {
      if (spectrumData.data_age_seconds <= 6) {
        tag.textContent = 'LIVE';
        tag.className = 'tag ok';
      } else {
        tag.textContent = 'STALE';
        tag.className = 'tag amber';
      }
    }
  }

  const metrics = chartBox.querySelector('.chart-metrics');
  if (metrics) {
    metrics.innerHTML = `
      <span><strong>Center:</strong> ${(spectrumData.center_frequency / 1_000_000).toFixed(1)} MHz</span>
      <span><strong>Peak:</strong> ${(peakFrequency / 1_000_000).toFixed(3)} MHz</span>
      <span><strong>Power:</strong> ${peakPower.toFixed(2)} dB</span>
      <span><strong>Source:</strong> ${spectrumData.source_file ? spectrumData.source_file.split('\\').pop() : 'Unknown'}</span>
      <span><strong>Last RF Capture:</strong> ${Math.round(spectrumData.data_age_seconds)}s ago</span>
    `;
  }

  const canvas = chartBox.querySelector('canvas');
  if (!canvas) {
    return;
  }

  const configuration = {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'RF spectrum',
          data: values,
          borderColor: '#52a4ff',
          backgroundColor: 'rgba(82, 164, 255, 0.18)',
          borderWidth: 2,
          pointRadius: 0,
          fill: true,
          tension: 0.15
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          callbacks: {
            title(items) {
              const item = items[0];
              if (!item) {
                return '';
              }
              return `${Number(item.label).toFixed(3)} MHz`;
            },
            label(context) {
              return `${context.parsed.y.toFixed(2)} dB`;
            }
          }
        }
      },
      scales: {
        x: {
          title: {
            display: true,
            text: 'Frequency (MHz)'
          },
          ticks: {
            maxTicksLimit: 8,
            callback(value) {
              return `${Number(value).toFixed(1)} M`;
            }
          }
        },
        y: {
          title: {
            display: true,
            text: 'Power (dB)'
          }
        }
      }
    }
  };

  if (spectrumChart) {
    spectrumChart.data.labels = labels;
    spectrumChart.data.datasets[0].data = values;
    spectrumChart.update();
    return;
  }

  spectrumChart = new Chart(canvas.getContext('2d'), configuration);
  window.spectrumChart = spectrumChart;
}

function showSpectrumUnavailable(message) {
  const chartBox = document.querySelector('.chart-box');
  if (!chartBox) {
    return;
  }

  let displayMsg = 'RF spectrum unavailable — HackRF disconnected';
  if (message && !message.includes('HackRF One is not connected') && !message.includes('HTTP')) {
    displayMsg = message;
  }

  console.error('RF spectrum unavailable:', message);
  chartBox.innerHTML = `<div style="font-size: 1.1em; color: var(--muted); text-align: center;">${displayMsg}</div>`;

  spectrumChart = null;

  const spectrumPanel = document.querySelector('#reports');
  if (spectrumPanel) {
    const tag = spectrumPanel.querySelector('.tag');
    if (tag) {
      tag.textContent = 'UNAVAILABLE';
      tag.className = 'tag red';
    }
  }
}

async function fetchSpectrum() {
  try {
    const response = await fetch('/api/rf/spectrum');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    if (!data || data.status !== 'SUCCESS' || !Array.isArray(data.frequencies) || !Array.isArray(data.power_db)) {
      throw new Error(data && data.message ? data.message : 'Spectrum payload invalid');
    }

    updateSpectrumChart(data);
  } catch (error) {
    showSpectrumUnavailable(error.message);
  }
}

function renderAnomalies(anomalyData) {
  const anomalyPanel = document.querySelector('#firmware');
  if (!anomalyPanel) {
    return;
  }

  const anomalyText = anomalyPanel.querySelector('.metric-text');
  const anomalyBar = anomalyPanel.querySelector('.mini-bars span');

  if (!anomalyText) {
    return;
  }

  if (!anomalyData || anomalyData.status !== 'SUCCESS' || !Array.isArray(anomalyData.anomalies)) {
    anomalyText.textContent = 'RF anomalies unavailable';
    if (anomalyBar) {
      anomalyBar.style.width = '0%';
    }
    return;
  }

  const strongest = anomalyData.anomalies[0] || null;
  const anomalyCount = anomalyData.anomaly_count || 0;
  const noiseFloor = anomalyData.noise_floor_db ?? 0;

  if (!strongest) {
    anomalyText.innerHTML = `
      <strong>Total:</strong> ${anomalyCount} suspicious peaks<br>
      <strong>Noise floor:</strong> ${noiseFloor.toFixed(2)} dB<br>
      <strong>Severity:</strong> NONE
    `;
    if (anomalyBar) {
      anomalyBar.style.width = '8%';
    }
    return;
  }

  anomalyText.innerHTML = `
    <strong>Peaks:</strong> ${anomalyCount}<br>
    <strong>Freq:</strong> ${strongest.frequency_mhz.toFixed(3)} MHz<br>
    <strong>Power:</strong> ${strongest.power_db.toFixed(2)} dB<br>
    <strong>Severity:</strong> ${strongest.severity}<br>
    <strong>Noise floor:</strong> ${noiseFloor.toFixed(2)} dB
  `;

  if (anomalyBar) {
    const width = Math.min(100, Math.max(10, (strongest.difference_from_noise_db / 30) * 100));
    anomalyBar.style.width = `${width}%`;
  }
}

async function fetchAnomalies() {
  try {
    const response = await fetch('/api/rf/anomalies');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    if (!data || (data.status !== 'SUCCESS' && data.status !== 'ERROR')) {
      throw new Error('Anomaly payload invalid');
    }

    if (data.status === 'ERROR') {
      console.warn('RF anomalies unavailable:', data.error || 'Unknown error');
      renderAnomalies({ status: 'ERROR', anomaly_count: 0, anomalies: [] });
      return;
    }

    renderAnomalies(data);
  } catch (error) {
    console.error('RF anomaly fetch failed', error);
    renderAnomalies({ status: 'ERROR', anomaly_count: 0, anomalies: [] });
  }
}

async function fetchRisk() {
  try {
    const response = await fetch('/api/rf/risk');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    if (!data || data.status !== 'SUCCESS') {
      throw new Error('Risk payload invalid');
    }

    dashboardData.rfScore = data.risk_score ?? dashboardData.rfScore;
    dashboardData.rfRisk = data.risk_level ?? dashboardData.rfRisk;
    dashboardData.mlResult = data.ml_classification ?? dashboardData.mlResult;
    dashboardData.mlScore = data.ml_anomaly_score ?? dashboardData.mlScore;

    const cards = document.querySelectorAll('.status-card');
    if (cards && cards.length >= 2) {
      cards[1].querySelector('.value').textContent = dashboardData.rfRisk;
      cards[1].querySelector('small').textContent = `${dashboardData.rfScore} / 100`;
    }

    const rfPanel = document.querySelector('#rf');
    if (rfPanel) {
      let details = rfPanel.querySelector('.rf-details');
      if (!details) {
        details = document.createElement('div');
        details.className = 'rf-details';
        details.style.marginTop = '8px';
        details.style.fontSize = '0.9em';
        rfPanel.appendChild(details);
      }

      const mlScoreText = (dashboardData.mlScore !== undefined && dashboardData.mlScore !== null) ? Number(dashboardData.mlScore).toFixed(4) : '--';
      details.innerHTML = `
        <div><strong>RF Risk Score:</strong> ${dashboardData.rfScore} (${dashboardData.rfRisk})</div>
        <div><strong>Threshold anomalies:</strong> ${data.threshold_anomaly_count} (${data.threshold_severity})</div>
        <div><strong>ML:</strong> ${data.ml_classification} (score: ${mlScoreText})</div>
      `;
    }

    return data;
  } catch (error) {
    console.warn('Unable to fetch /api/rf/risk', error);
    return null;
  }
}

async function fetchDeviceRisk() {
  try {
    const response = await fetch('/api/device/risk');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    if (!data || data.status !== 'SUCCESS') {
      throw new Error('Device risk payload invalid');
    }

    dashboardData.deviceRiskScore = data.device_risk_score ?? 0;
    dashboardData.deviceRiskLevel = data.device_risk_level ?? 'NORMAL';
    dashboardData.firmwareStatus = data.firmware_status || dashboardData.firmwareStatus;
    dashboardData.rfRisk = data.rf_risk_level || dashboardData.rfRisk;
    dashboardData.rfScore = data.rf_risk_score ?? dashboardData.rfScore;

    const cards = document.querySelectorAll('.status-card');
    if (cards.length >= 1) {
      cards[0].querySelector('.value').textContent = dashboardData.deviceRiskLevel;
      cards[0].querySelector('small').textContent = `${dashboardData.deviceRiskScore} / 100`;
      cards[0].classList.remove('green', 'amber', 'red');
      cards[0].classList.add(dashboardData.deviceRiskLevel === 'HIGH' ? 'red' : dashboardData.deviceRiskLevel === 'MEDIUM' ? 'amber' : 'green');
    }

    if (cards.length >= 3) {
      cards[2].querySelector('.value').textContent = dashboardData.firmwareStatus;
      cards[2].querySelector('small').textContent = dashboardData.firmwareStatus;
    }

    return data;
  } catch (error) {
    console.warn('Unable to fetch /api/device/risk', error);
    return null;
  }
}

async function initDashboard() {
  await fetchSystemStatus();
  await fetchFirmwareStatus();
  await fetchNetworkStatus();
  renderOverview();
  await fetchAlerts();
  renderSpectrumPlaceholder();
  await fetchSpectrum();
  await fetchAnomalies();
  await fetchRisk();
  await fetchDeviceRisk();
  await fetchNetworkStatus();
  renderOverview();

  // Poll /api/status approximately every 2 seconds
  window.setInterval(async () => {
    await fetchSystemStatus();
    renderOverview();
  }, 2000);

  // Poll RF latest data approximately every 3 seconds
  window.setInterval(async () => {
    await fetchFirmwareStatus();
    await fetchSpectrum();
    await fetchAnomalies();
    await fetchRisk();
    await fetchDeviceRisk();
    await fetchNetworkStatus();
    await fetchAlerts();
    renderOverview();
  }, 3000);
}

document.addEventListener('DOMContentLoaded', initDashboard);
