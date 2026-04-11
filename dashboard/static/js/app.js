/* ═══════════════════════════════════════════════════════════════════════
   DPI Engine Dashboard — Application Logic
   Real-time charts, SSE, flow replay, and interactive UI
   ═══════════════════════════════════════════════════════════════════════ */

const API = '';
let currentData = null;
let liveEventSource = null;
let allFlows = [];

// ── Chart Colors ─────────────────────────────────────────────────────────
const COLORS = [
  '#6366f1', '#22d3ee', '#10b981', '#f59e0b', '#f43f5e',
  '#8b5cf6', '#3b82f6', '#ec4899', '#14b8a6', '#f97316',
  '#a855f7', '#06b6d4', '#84cc16', '#ef4444', '#0ea5e9',
];

// ── Navigation ───────────────────────────────────────────────────────────
document.querySelectorAll('.nav-item[data-page]').forEach(item => {
  item.addEventListener('click', () => {
    const page = item.dataset.page;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const target = document.getElementById(`page-${page}`);
    if (target) target.classList.add('active');
  });
});

// ── Upload / Drag & Drop ─────────────────────────────────────────────────
const uploadArea = document.getElementById('upload-area');
if (uploadArea) {
  uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('dragover');
  });
  uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragover');
  });
  uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
    if (e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]);
  });
}

// ── Analyze Test PCAP ────────────────────────────────────────────────────
async function analyzeTestPcap() {
  const btn = document.getElementById('btn-analyze-test');
  btn.innerHTML = '<span class="loading-spinner"></span> Analyzing...';
  btn.disabled = true;

  try {
    const form = new FormData();
    form.append('filename', 'test_dpi.pcap');
    const res = await fetch(`${API}/api/analyze`, { method: 'POST', body: form });
    const data = await res.json();

    if (data.error) {
      alert('Error: ' + data.error);
    } else {
      currentData = data;
      renderDashboard(data);
      renderAnomalies(data.anomalies);
      renderFlows(data.flow_replay);
      renderMLClassification(data.ml_classification);
      loadRules();
    }
  } catch (err) {
    alert('Failed to analyze: ' + err.message);
  } finally {
    btn.innerHTML = '⚡ Analyze Test PCAP';
    btn.disabled = false;
  }
}

// ── Upload File ──────────────────────────────────────────────────────────
async function uploadFile(file) {
  if (!file) return;
  const progress = document.getElementById('upload-progress');
  progress.classList.remove('hidden');

  try {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(`${API}/api/analyze`, { method: 'POST', body: form });
    const data = await res.json();

    if (data.error) {
      alert('Error: ' + data.error);
    } else {
      currentData = data;
      renderDashboard(data);
      renderAnomalies(data.anomalies);
      renderFlows(data.flow_replay);
      renderMLClassification(data.ml_classification);
      loadRules();
      // Switch to dashboard
      document.querySelector('[data-page="dashboard"]').click();
    }
  } catch (err) {
    alert('Upload failed: ' + err.message);
  } finally {
    progress.classList.add('hidden');
  }
}

// ── Render Dashboard ─────────────────────────────────────────────────────
function renderDashboard(data) {
  const s = data.stats.summary;
  const el = (id) => document.getElementById(id);

  el('analysis-filename').textContent = `Analyzing: ${data.filename} — ${s.total_packets} packets, ${formatBytes(s.total_bytes)}`;
  el('stat-packets').textContent = s.total_packets.toLocaleString();
  el('stat-bytes').textContent = formatBytes(s.total_bytes);
  el('stat-flows').textContent = s.total_flows.toLocaleString();
  el('stat-snis').textContent = `${data.stats.detected_snis.length} domains detected`;
  el('stat-forwarded').textContent = s.forwarded_flows.toLocaleString();
  el('stat-blocked').textContent = s.blocked_flows.toLocaleString();
  el('stat-dropped').textContent = `${s.dropped_packets} packets dropped`;
  el('stat-anomalies').textContent = data.anomalies.length.toString();
  el('stat-time').textContent = `${s.analysis_time_ms}`;

  // Anomaly badge
  const badge = el('anomaly-count');
  if (data.anomalies.length > 0) {
    badge.textContent = data.anomalies.length;
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }

  // SNI table
  const sniTbody = el('sni-tbody');
  sniTbody.innerHTML = data.stats.detected_snis.map(s =>
    `<tr><td class="mono">${s.sni}</td><td><span class="badge badge-indigo">${s.app}</span></td></tr>`
  ).join('');

  // Top talkers
  const talkersTbody = el('talkers-tbody');
  talkersTbody.innerHTML = data.stats.top_talkers.map(t =>
    `<tr><td class="mono">${t.ip}</td><td>${formatBytes(t.bytes)}</td></tr>`
  ).join('');

  drawTimelineChart(data.stats.timeline);
  drawAppDonutChart(data.stats.app_distribution);
}

// ── Canvas Charts ────────────────────────────────────────────────────────

function drawTimelineChart(timeline) {
  const canvas = document.getElementById('chart-timeline');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = 220 * dpr;
  canvas.style.width = rect.width + 'px';
  canvas.style.height = '220px';
  ctx.scale(dpr, dpr);

  const W = rect.width, H = 220;
  const data = timeline.packets_per_sec;
  if (!data || data.length === 0) return;

  const maxVal = Math.max(...data, 1);
  const padL = 50, padR = 20, padT = 20, padB = 30;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  ctx.clearRect(0, 0, W, H);

  // Grid
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padT + (chartH / 4) * i;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillStyle = '#64748b'; ctx.font = '10px Inter';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), padL - 8, y + 4);
  }

  // Area fill
  const gradient = ctx.createLinearGradient(0, padT, 0, H - padB);
  gradient.addColorStop(0, 'rgba(99, 102, 241, 0.3)');
  gradient.addColorStop(1, 'rgba(99, 102, 241, 0.0)');
  ctx.beginPath();
  ctx.moveTo(padL, H - padB);
  data.forEach((v, i) => {
    const x = padL + (chartW / (data.length - 1 || 1)) * i;
    const y = padT + chartH - (v / maxVal) * chartH;
    if (i === 0) ctx.lineTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.lineTo(padL + chartW, H - padB);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.strokeStyle = '#6366f1';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  data.forEach((v, i) => {
    const x = padL + (chartW / (data.length - 1 || 1)) * i;
    const y = padT + chartH - (v / maxVal) * chartH;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Dots
  data.forEach((v, i) => {
    const x = padL + (chartW / (data.length - 1 || 1)) * i;
    const y = padT + chartH - (v / maxVal) * chartH;
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = '#6366f1';
    ctx.fill();
  });

  // X axis label
  ctx.fillStyle = '#64748b'; ctx.font = '10px Inter'; ctx.textAlign = 'center';
  ctx.fillText('Time →', W / 2, H - 4);
}

function drawAppDonutChart(distribution) {
  const canvas = document.getElementById('chart-apps');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = 220 * dpr; canvas.height = 220 * dpr;
  canvas.style.width = '220px'; canvas.style.height = '220px';
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, 220, 220);

  if (!distribution || distribution.length === 0) return;

  const cx = 110, cy = 100, R = 80, r = 50;
  const total = distribution.reduce((s, d) => s + d.packets, 0);
  let startAngle = -Math.PI / 2;

  distribution.slice(0, 8).forEach((d, i) => {
    const slice = (d.packets / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, R, startAngle, startAngle + slice);
    ctx.arc(cx, cy, r, startAngle + slice, startAngle, true);
    ctx.closePath();
    ctx.fillStyle = COLORS[i % COLORS.length];
    ctx.fill();
    startAngle += slice;
  });

  // Center text
  ctx.fillStyle = '#f1f5f9'; ctx.font = 'bold 18px Inter'; ctx.textAlign = 'center';
  ctx.fillText(total, cx, cy - 2);
  ctx.fillStyle = '#64748b'; ctx.font = '10px Inter';
  ctx.fillText('packets', cx, cy + 14);

  // Legend
  const legend = document.getElementById('app-legend');
  if (legend) {
    legend.innerHTML = distribution.slice(0, 8).map((d, i) =>
      `<div class="legend-item">
        <div class="legend-dot" style="background: ${COLORS[i % COLORS.length]}"></div>
        <span class="legend-label">${d.app}</span>
        <span class="legend-value">${d.percent}%</span>
      </div>`
    ).join('');
  }
}

function drawMLDonutChart(categories) {
  const canvas = document.getElementById('chart-ml');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = 220 * dpr; canvas.height = 220 * dpr;
  canvas.style.width = '220px'; canvas.style.height = '220px';
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, 220, 220);

  const entries = Object.entries(categories);
  if (entries.length === 0) return;
  const total = entries.reduce((s, [, v]) => s + v, 0);
  const cx = 110, cy = 100, R = 80, r = 50;
  let startAngle = -Math.PI / 2;

  entries.slice(0, 8).forEach(([, count], i) => {
    const slice = (count / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, R, startAngle, startAngle + slice);
    ctx.arc(cx, cy, r, startAngle + slice, startAngle, true);
    ctx.closePath();
    ctx.fillStyle = COLORS[i % COLORS.length];
    ctx.fill();
    startAngle += slice;
  });

  ctx.fillStyle = '#f1f5f9'; ctx.font = 'bold 18px Inter'; ctx.textAlign = 'center';
  ctx.fillText(total, cx, cy - 2);
  ctx.fillStyle = '#64748b'; ctx.font = '10px Inter';
  ctx.fillText('flows', cx, cy + 14);

  const legend = document.getElementById('ml-legend');
  if (legend) {
    legend.innerHTML = entries.slice(0, 8).map(([name, count], i) =>
      `<div class="legend-item">
        <div class="legend-dot" style="background: ${COLORS[i % COLORS.length]}"></div>
        <span class="legend-label">${name}</span>
        <span class="legend-value">${count}</span>
      </div>`
    ).join('');
  }
}

// ── Render Anomalies ─────────────────────────────────────────────────────
function renderAnomalies(anomalies) {
  const feed = document.getElementById('anomaly-feed');
  const critical = anomalies.filter(a => a.severity === 'critical').length;
  const warning = anomalies.filter(a => a.severity === 'warning').length;
  const info = anomalies.filter(a => a.severity === 'info').length;

  document.getElementById('anomaly-critical').textContent = critical;
  document.getElementById('anomaly-warning').textContent = warning;
  document.getElementById('anomaly-info').textContent = info;
  document.getElementById('anomaly-total').textContent = anomalies.length;

  if (anomalies.length === 0) {
    feed.innerHTML = '<div class="text-center text-muted" style="padding:40px;">✅ No anomalies detected — Network traffic appears normal</div>';
    return;
  }

  const icons = { critical: '🔴', warning: '🟠', info: '🔵' };
  feed.innerHTML = anomalies.map(a => `
    <div class="alert-card ${a.severity}">
      <div class="alert-icon">${icons[a.severity] || '🔵'}</div>
      <div style="flex:1;">
        <div class="alert-title">${a.title}</div>
        <div class="alert-desc">${a.description}</div>
        ${a.source_ip ? `<div class="text-sm mt-8"><span class="badge badge-rose">Source: ${a.source_ip}</span></div>` : ''}
        ${a.details && Object.keys(a.details).length > 0 ? `
          <div class="text-sm mt-8 text-muted">
            ${Object.entries(a.details).map(([k, v]) =>
              `<span class="badge badge-violet" style="margin-right:4px;">${k}: ${Array.isArray(v) ? v.slice(0,5).join(', ') : v}</span>`
            ).join('')}
          </div>` : ''}
      </div>
      <span class="badge badge-${a.severity === 'critical' ? 'rose' : a.severity === 'warning' ? 'amber' : 'cyan'}">${a.category}</span>
    </div>
  `).join('');
}

// ── Render Flows ─────────────────────────────────────────────────────────
function renderFlows(flowData) {
  if (!flowData || !flowData.flows) return;
  allFlows = flowData.flows;
  renderFlowTable(allFlows);
}

function renderFlowTable(flows) {
  const tbody = document.getElementById('flow-tbody');
  tbody.innerHTML = flows.map(f => `
    <tr>
      <td class="mono">${f.src}</td>
      <td class="mono">${f.dst}</td>
      <td><span class="badge ${f.protocol === 'TCP' ? 'badge-indigo' : 'badge-cyan'}">${f.protocol}</span></td>
      <td>${f.packets}</td>
      <td>${formatBytes(f.bytes)}</td>
      <td>${f.duration.toFixed(3)}s</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="viewFlow('${f.flow_id}')">🔍 Inspect</button>
      </td>
    </tr>
  `).join('');
}

function filterFlows(query) {
  const q = query.toLowerCase();
  const filtered = allFlows.filter(f => 
    f.src.toLowerCase().includes(q) || f.dst.toLowerCase().includes(q) ||
    f.protocol.toLowerCase().includes(q) || f.flow_id.toLowerCase().includes(q)
  );
  renderFlowTable(filtered);
}

async function viewFlow(flowId) {
  try {
    const res = await fetch(`${API}/api/flows/${encodeURIComponent(flowId)}`);
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    showFlowModal(data);
  } catch (err) { alert('Error loading flow: ' + err.message); }
}

function showFlowModal(data) {
  const modal = document.getElementById('flow-modal');
  const title = document.getElementById('flow-modal-title');
  const content = document.getElementById('flow-modal-content');

  title.textContent = `Flow: ${data.flow_id} (${data.packet_count} packets)`;
  content.innerHTML = `
    <div class="flex gap-16 mb-16">
      <span class="badge badge-indigo">${data.packet_count} packets</span>
      <span class="badge badge-cyan">${formatBytes(data.total_bytes)}</span>
      <a href="${API}/api/flows/${encodeURIComponent(data.flow_id)}/pcap" class="btn btn-secondary btn-sm" download>💾 Download PCAP</a>
    </div>
    <div style="max-height: 500px; overflow-y: auto;">
      ${data.packets.map((p, i) => `
        <div style="margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 12px;">
          <div class="flex items-center gap-8 mb-8">
            <span class="badge badge-violet">#${i + 1}</span>
            <span class="mono text-sm">${p.src_ip}:${p.src_port} → ${p.dst_ip}:${p.dst_port}</span>
            <span class="badge ${p.protocol === 'TCP' ? 'badge-indigo' : 'badge-cyan'}">${p.protocol}</span>
            ${p.tcp_flags ? `<span class="badge badge-amber">${p.tcp_flags}</span>` : ''}
            <span class="text-muted text-sm">${p.length} bytes</span>
          </div>
          ${p.payload_hex ? `<div class="hex-viewer">${p.payload_hex}</div>` : '<div class="text-muted text-sm">No payload</div>'}
        </div>
      `).join('')}
    </div>
  `;
  modal.classList.add('active');
}

function closeFlowModal() {
  document.getElementById('flow-modal').classList.remove('active');
}

// ── Render ML Classification ─────────────────────────────────────────────
function renderMLClassification(mlData) {
  if (!mlData) return;
  document.getElementById('ml-total').textContent = mlData.total_flows;
  document.getElementById('ml-confidence').textContent = (mlData.avg_confidence * 100).toFixed(1) + '%';
  document.getElementById('ml-heuristic').textContent = mlData.by_method?.['ML/Heuristic'] || 0;

  const tbody = document.getElementById('ml-tbody');
  if (mlData.classifications) {
    tbody.innerHTML = mlData.classifications.slice(0, 50).map(c => {
      const confClass = c.confidence >= 0.7 ? 'high' : c.confidence >= 0.4 ? 'medium' : 'low';
      const features = c.features || {};
      return `
        <tr>
          <td class="mono text-sm">${c.flow_id?.substring(0, 35) || '—'}...</td>
          <td><span class="badge badge-indigo">${c.classified_as}</span></td>
          <td><span class="badge ${c.method === 'SNI/Host' ? 'badge-emerald' : 'badge-violet'}">${c.method}</span></td>
          <td>
            <div class="confidence-meter">
              <div class="confidence-bar">
                <div class="confidence-fill ${confClass}" style="width: ${c.confidence * 100}%"></div>
              </div>
              <span class="text-sm">${(c.confidence * 100).toFixed(0)}%</span>
            </div>
          </td>
          <td class="text-sm text-muted">
            ${features.avg_packet_size ? `${features.avg_packet_size}B avg` : '—'}
          </td>
        </tr>
      `;
    }).join('');
  }

  if (mlData.by_category) {
    drawMLDonutChart(mlData.by_category);
  }
}

// ── Live Capture ─────────────────────────────────────────────────────────
async function startLiveReplay() {
  const btnStart = document.getElementById('btn-live-start');
  const btnStop = document.getElementById('btn-live-stop');
  const indicator = document.getElementById('live-indicator');
  const feed = document.getElementById('live-feed');

  try {
    const res = await fetch(`${API}/api/live/start`, { method: 'POST' });
    const data = await res.json();
    if (data.error) { alert(data.error); return; }

    btnStart.disabled = true;
    btnStop.disabled = false;
    indicator.classList.remove('hidden');
    feed.innerHTML = '';
    document.getElementById('live-status').textContent = '🟢 Capturing';

    // SSE connection
    liveEventSource = new EventSource(`${API}/api/live/stream`);
    let packetCount = 0;

    liveEventSource.onmessage = (event) => {
      const msg = JSON.parse(event.data);

      if (msg.type === 'packet') {
        packetCount++;
        document.getElementById('live-packets').textContent = msg.cumulative.packets.toLocaleString();
        document.getElementById('live-bytes').textContent = formatBytes(msg.cumulative.bytes);
        document.getElementById('live-progress').textContent = msg.progress + '%';
        document.getElementById('live-progress-fill').style.width = msg.progress + '%';

        const p = msg.packet;
        const entry = document.createElement('div');
        entry.className = 'packet-entry';
        entry.innerHTML = `
          <span class="packet-proto ${p.protocol.toLowerCase()}">${p.protocol}</span>
          <span class="mono">${p.src_ip}:${p.src_port}</span>
          <span class="text-muted">→</span>
          <span class="mono">${p.dst_ip}:${p.dst_port}</span>
          <span class="text-muted" style="margin-left:auto;">${p.length}B</span>
        `;
        feed.prepend(entry);

        // Limit entries
        while (feed.children.length > 100) feed.removeChild(feed.lastChild);
      }

      if (msg.type === 'complete') {
        stopLiveReplay();
        document.getElementById('live-status').textContent = '✅ Complete';
      }
    };
  } catch (err) { alert('Failed to start: ' + err.message); }
}

function stopLiveReplay() {
  if (liveEventSource) { liveEventSource.close(); liveEventSource = null; }
  fetch(`${API}/api/live/stop`, { method: 'POST' });
  document.getElementById('btn-live-start').disabled = false;
  document.getElementById('btn-live-stop').disabled = true;
  document.getElementById('live-indicator').classList.add('hidden');
  document.getElementById('live-status').textContent = 'Stopped';
}

// ── Blocking Rules ───────────────────────────────────────────────────────
async function loadRules() {
  try {
    const res = await fetch(`${API}/api/rules`);
    const data = await res.json();
    renderRules(data);
  } catch (err) { console.error('Failed to load rules:', err); }
}

function renderRules(data) {
  const container = document.getElementById('rules-list');
  const allRules = [
    ...data.blocked_ips.map(v => ({ type: 'ip', value: v, label: '🌐 IP' })),
    ...data.blocked_apps.map(v => ({ type: 'app', value: v, label: '📱 App' })),
    ...data.blocked_domains.map(v => ({ type: 'domain', value: v, label: '🔗 Domain' })),
  ];

  if (allRules.length === 0) {
    container.innerHTML = '<p class="text-muted text-sm">No rules configured</p>';
    return;
  }

  container.innerHTML = allRules.map(r =>
    `<span class="rule-pill">
      <span class="badge badge-${r.type === 'ip' ? 'rose' : r.type === 'app' ? 'amber' : 'cyan'}">${r.label}</span>
      ${r.value}
      <span class="remove-rule" onclick="removeRule('${r.type}', '${r.value}')">✕</span>
    </span>`
  ).join('');
}

async function addRule() {
  const type = document.getElementById('rule-type').value;
  const value = document.getElementById('rule-value').value.trim();
  if (!value) return;

  try {
    await fetch(`${API}/api/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, value }),
    });
    document.getElementById('rule-value').value = '';
    loadRules();
  } catch (err) { alert('Error: ' + err.message); }
}

async function removeRule(type, value) {
  try {
    await fetch(`${API}/api/rules`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, value }),
    });
    loadRules();
  } catch (err) { alert('Error: ' + err.message); }
}

async function quickBlock(type, value) {
  try {
    await fetch(`${API}/api/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, value }),
    });
    loadRules();
  } catch (err) { alert('Error: ' + err.message); }
}

// ── Helpers ──────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
}

// ── Init ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadRules();
  // Close modal on overlay click
  document.getElementById('flow-modal').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) closeFlowModal();
  });
});
