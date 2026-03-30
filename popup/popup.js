/**
 * HexPose — Popup JS
 * ES module — handles all popup UI interaction.
 */

// ─── Tab navigation ─────────────────────────────────────────────────────────

const tabs = document.querySelectorAll('.tab');
const panels = document.querySelectorAll('.panel');

tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    const target = tab.id.replace('tab-', 'panel-');
    tabs.forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
    panels.forEach(p => p.classList.add('hidden'));
    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    document.getElementById(target).classList.remove('hidden');

    if (target === 'panel-history') loadHistory();
    if (target === 'panel-settings') loadSettings();
  });
});

// ─── Scan tab ─────────────────────────────────────────────────────────────────

const dropZone    = document.getElementById('drop-zone');
const fileInput   = document.getElementById('file-input');
const browseLink  = document.getElementById('browse-link');
const scanProgress= document.getElementById('scan-progress');
const scanProgSub = document.getElementById('scan-progress-sub');
const resultCard  = document.getElementById('result-card');

// Drop zone events
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer?.files?.[0];
  if (file) processFile(file);
});

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
browseLink.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
fileInput.addEventListener('change', () => {
  const file = fileInput.files?.[0];
  if (file) processFile(file);
});

document.getElementById('btn-rescan').addEventListener('click', resetToDropZone);

// ─── File processing ──────────────────────────────────────────────────────────

async function processFile(file) {
  showScanning('Reading file…');

  let buffer;
  try {
    buffer = await file.arrayBuffer();
  } catch (err) {
    setProgressSub('Failed to read file');
    return;
  }

  setProgressSub('Running static analysis…');

  let result;
  try {
    result = await chrome.runtime.sendMessage({
      type: 'scanFile',
      buffer,
      filename: file.name,
      mimeType: file.type || '',
      useVT: true,
    });
  } catch (err) {
    setProgressSub('Analysis error: ' + err.message);
    return;
  }

  if (result?.error) {
    setProgressSub('Error: ' + result.error);
    return;
  }

  renderResult(result);
}

// ─── UI state helpers ─────────────────────────────────────────────────────────

function showScanning(msg) {
  dropZone.classList.add('hidden');
  resultCard.classList.add('hidden');
  scanProgress.classList.remove('hidden');
  setProgressSub(msg || 'Analyzing…');
}

function setProgressSub(msg) {
  scanProgSub.textContent = msg;
}

function resetToDropZone() {
  resultCard.classList.add('hidden');
  scanProgress.classList.add('hidden');
  dropZone.classList.remove('hidden');
  fileInput.value = '';
}

// ─── Result rendering ─────────────────────────────────────────────────────────

function renderResult(result) {
  // Hide scanning, show card
  scanProgress.classList.add('hidden');
  resultCard.classList.remove('hidden');
  dropZone.classList.add('hidden');

  const score   = result.score   ?? 0;
  const verdict = result.verdict ?? 'clean';

  // Gauge
  animateGauge(score, verdict);

  // Verdict badge
  const badge = document.getElementById('verdict-badge');
  badge.textContent = verdict.toUpperCase();
  badge.className = `verdict-badge ${verdict}`;

  // File meta
  renderFileMeta(result);

  // Findings
  renderFindings(result.findings || []);

  // Hashes
  renderHashes(result.hashes);

  // VirusTotal
  renderVT(result.virustotal);
}

function animateGauge(score, verdict) {
  const fill = document.getElementById('gauge-fill');
  const scoreEl = document.getElementById('gauge-score');

  // SVG arc length for the gauge path: approx 150 units
  const maxDash = 150;
  const dash = Math.round((score / 100) * maxDash);

  const colorMap = {
    clean:     '#34d399',
    caution:   '#fbbf24',
    suspicious:'#fb923c',
    malicious: '#f87171',
  };

  fill.style.strokeDasharray = `${dash} ${maxDash}`;
  fill.style.stroke = colorMap[verdict] || '#8b5cf6';

  // Animate score number
  let current = 0;
  const step = Math.ceil(score / 30);
  const interval = setInterval(() => {
    current = Math.min(current + step, score);
    scoreEl.textContent = current;
    if (current >= score) clearInterval(interval);
  }, 20);
}

function renderFileMeta(result) {
  const el = document.getElementById('file-meta');
  const rows = [
    ['Filename',  result.filename || '—'],
    ['Type',      result.detectedType  ? `${result.detectedType} (.${result.extension})` : (result.extension || '—')],
    ['Size',      result.fileSize != null ? formatBytes(result.fileSize) : '—'],
    ['MIME',      result.mimeType || '—'],
  ];
  el.innerHTML = rows.map(([label, value]) => `
    <div class="meta-row">
      <span class="meta-label">${label}</span>
      <span class="meta-value">${escHtml(value)}</span>
    </div>
  `).join('');
}

function renderFindings(findings) {
  document.getElementById('findings-count').textContent = findings.length;
  const list = document.getElementById('findings-list');

  if (findings.length === 0) {
    list.innerHTML = '<li class="findings-empty">✅ No threats detected</li>';
    return;
  }

  list.innerHTML = findings.map(f => `
    <li class="finding-item">
      <span class="finding-sev sev-${f.severity}">${escHtml(f.severity)}</span>
      <div class="finding-content">
        <span class="finding-name">${escHtml(f.name)}</span>
        <span class="finding-desc">${escHtml(f.description)}</span>
      </div>
    </li>
  `).join('');
}

function renderHashes(hashes) {
  document.getElementById('hash-sha256').textContent = hashes?.sha256 ?? '—';
  document.getElementById('hash-sha1').textContent   = hashes?.sha1   ?? '—';
  document.getElementById('hash-md5').textContent    = hashes?.md5    ?? '—';
}

function renderVT(vt) {
  const vtSection  = document.getElementById('vt-section');
  const vtStatus   = document.getElementById('vt-status');
  const vtBarWrap  = document.getElementById('vt-bar-wrap');
  const vtBar      = document.getElementById('vt-bar');
  const vtLinkWrap = document.getElementById('vt-link-wrap');
  const vtLinkEl   = document.getElementById('vt-link');

  if (!vt) {
    vtSection.classList.add('hidden');
    return;
  }

  vtSection.classList.remove('hidden');

  if (vt.status === 'error') {
    vtStatus.textContent = vt.errorCode === 'NO_API_KEY' ? 'No API key' : `Error: ${vt.message}`;
    vtBarWrap.hidden = true;
    vtLinkWrap.classList.add('hidden');
    return;
  }

  if (vt.status === 'not_found') {
    vtStatus.textContent = 'Not seen before';
    vtBarWrap.hidden = true;
    vtLinkWrap.classList.remove('hidden');
    vtLinkEl.href = vt.vtLink;
    return;
  }

  if (vt.status === 'found') {
    const pct = vt.total > 0 ? Math.round((vt.malicious / vt.total) * 100) : 0;
    vtStatus.textContent = `${vt.malicious}/${vt.total} engines${vt.threatName ? ' — ' + vt.threatName : ''}`;
    vtBarWrap.hidden = false;
    vtBar.style.width = `${Math.min(pct, 100)}%`;
    vtLinkWrap.classList.remove('hidden');
    vtLinkEl.href = vt.vtLink;
  }
}

// ─── History tab ─────────────────────────────────────────────────────────────

async function loadHistory() {
  const list = document.getElementById('history-list');
  const emptyEl = document.getElementById('history-empty');

  list.innerHTML = '';

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'getHistory' });
    const history = resp.history || [];

    if (history.length === 0) {
      list.appendChild(emptyEl);
      emptyEl.style.display = 'block';
      return;
    }

    emptyEl.style.display = 'none';

    history.slice(0, 20).forEach(item => {
      const li = document.createElement('li');
      li.className = 'history-item';
      li.innerHTML = `
        <span class="history-verdict hv-${item.verdict}">${escHtml(item.verdict ?? '?')}</span>
        <div class="history-info">
          <div class="history-name" title="${escHtml(item.filename)}">${escHtml(shortFilename(item.filename))}</div>
          <div class="history-meta">${formatTime(item.timestamp)} · ${escHtml(item.detectedType ?? item.extension ?? '?')}</div>
        </div>
        <span class="history-score" style="color:${scoreColor(item.score)}">${item.score ?? 0}</span>
      `;
      list.appendChild(li);
    });
  } catch (e) {
    list.innerHTML = `<li class="history-empty">Failed to load history</li>`;
  }
}

document.getElementById('btn-clear-history').addEventListener('click', async () => {
  await chrome.storage.local.remove('scanHistory');
  loadHistory();
});

// ─── Settings tab ─────────────────────────────────────────────────────────────

async function loadSettings() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'getSettings' });
    const s = resp.settings || {};

    document.getElementById('vt-api-key').value = s.vtApiKey || '';
    document.getElementById('toggle-auto-scan').checked = s.autoScan !== false;
    document.getElementById('toggle-block-malicious').checked = !!s.blockMalicious;
    document.getElementById('toggle-notifications').checked = s.notifications !== false;
  } catch {
    // Defaults already set in HTML
  }
}

document.getElementById('btn-save-settings').addEventListener('click', async () => {
  const saved = document.getElementById('settings-saved');
  const settings = {
    vtApiKey:        document.getElementById('vt-api-key').value.trim(),
    autoScan:        document.getElementById('toggle-auto-scan').checked,
    blockMalicious:  document.getElementById('toggle-block-malicious').checked,
    notifications:   document.getElementById('toggle-notifications').checked,
  };

  try {
    await chrome.runtime.sendMessage({ type: 'updateSettings', settings });
    saved.classList.remove('hidden');
    setTimeout(() => saved.classList.add('hidden'), 2500);
  } catch (e) {
    saved.textContent = '✗ Failed to save';
    saved.classList.remove('hidden');
    setTimeout(() => { saved.classList.add('hidden'); saved.textContent = '✓ Saved'; }, 2500);
  }
});

// Toggle API key visibility
document.getElementById('btn-toggle-key').addEventListener('click', () => {
  const input = document.getElementById('vt-api-key');
  input.type = input.type === 'password' ? 'text' : 'password';
});

// ─── Utilities ────────────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function formatTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
}

function shortFilename(name, maxLen = 28) {
  if (!name) return 'unknown';
  if (name.length <= maxLen) return name;
  const ext = name.includes('.') ? '.' + name.split('.').pop() : '';
  return name.slice(0, maxLen - ext.length - 1) + '…' + ext;
}

function scoreColor(score) {
  if (score >= 70) return '#f87171';
  if (score >= 40) return '#fb923c';
  if (score >= 15) return '#fbbf24';
  return '#34d399';
}

function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
