/**
 * HexPose — Background Service Worker (MV3)
 * 
 * Responsibilities:
 * - Intercept all downloads via chrome.downloads.onCreated / onChanged
 * - Handle messages from popup and content script
 * - Run FileAnalyzer + HashChecker
 * - Store scan history in chrome.storage.local
 * - Fire notifications for malicious verdicts
 */

import { FileAnalyzer, computeHashes } from '../analysis/file-analyzer.js';
import { HashChecker } from '../analysis/hash-checker.js';
import { SparkMD5 } from '../lib/spark-md5.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_HISTORY = 100;
const MAX_FETCH_SIZE_MB = 50;
const MAX_FETCH_BYTES = MAX_FETCH_SIZE_MB * 1024 * 1024;

// Fast-check dangerous extensions (no bytes needed)
const DANGEROUS_EXTS = new Set([
  'exe','dll','sys','drv','scr','pif','com','bat','cmd','ps1','ps2','psm1',
  'psd1','vbs','vbe','js','jse','wsf','wsh','hta','msi','msp','msc','reg',
  'lnk','jar','apk','app','gadget','ws','wsc','csh','sh','bash','run',
]);

// ─── State ────────────────────────────────────────────────────────────────────

let settings = {
  autoScan: true,
  blockMalicious: false,
  notifications: true,
  vtApiKey: '',
};

const hashChecker = new HashChecker('');

// ─── Initialization ───────────────────────────────────────────────────────────

async function loadSettings() {
  try {
    const stored = await chrome.storage.local.get('settings');
    if (stored.settings) {
      settings = { ...settings, ...stored.settings };
      hashChecker.apiKey = settings.vtApiKey || '';
    }
  } catch (e) {
    console.warn('[HexPose] Failed to load settings:', e);
  }
}

loadSettings();

// ─── Download Interceptor ─────────────────────────────────────────────────────

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  if (!settings.autoScan) return;

  const { id, filename, url, mime } = downloadItem;
  
  // Fast heuristic check on filename/extension/MIME
  const heuristicResult = runFastHeuristics(filename, url, mime);
  
  if (heuristicResult.verdict === 'malicious' && settings.blockMalicious) {
    try {
      await chrome.downloads.cancel(id);
      fireNotification(
        `download_blocked_${id}`,
        '⛔ Download Blocked',
        `${basename(filename)} was blocked — ${heuristicResult.reason}`,
        'malicious'
      );
    } catch (e) {
      console.warn('[HexPose] Could not cancel download:', e);
    }
  }
});

chrome.downloads.onChanged.addListener(async (delta) => {
  if (!settings.autoScan) return;
  // Only process when download completes
  if (!delta.state || delta.state.current !== 'complete') return;

  try {
    const [item] = await chrome.downloads.search({ id: delta.id });
    if (!item) return;
    
    // Fetch bytes from the local file path after download
    const result = await analyzeDownloadedFile(item);
    if (!result) return;

    await saveScanResult(result);

    if (result.verdict === 'malicious') {
      if (settings.notifications) {
        const topFinding = result.findings[0];
        fireNotification(
          `scan_${delta.id}`,
          '🚨 Malicious File Detected',
          `${basename(item.filename)} — Score: ${result.score}/100\n${topFinding ? topFinding.name : ''}`,
          'malicious'
        );
      }
    } else if (result.verdict === 'suspicious' && settings.notifications) {
      fireNotification(
        `scan_sus_${delta.id}`,
        '⚠️ Suspicious File',
        `${basename(item.filename)} — Score: ${result.score}/100`,
        'suspicious'
      );
    }
  } catch (e) {
    console.error('[HexPose] Download analysis error:', e);
  }
});

async function analyzeDownloadedFile(downloadItem) {
  // Read via fetch using file:// — only works for completed downloads
  const fileUrl = downloadItem.url; // Original URL for re-fetch
  const filename = basename(downloadItem.filename);
  const mime = downloadItem.mime || '';

  // For local files, we'll try to fetch the original URL
  // (local file:// URLs aren't fetchable from service workers, so we re-fetch from original src)
  // If original URL requires auth, we can only do heuristics
  let bytes = null;
  
  if (downloadItem.url && !downloadItem.url.startsWith('file://')) {
    bytes = await fetchFileBytes(downloadItem.url);
  }

  if (!bytes) {
    // Fallback: heuristic-only result
    const heuristic = runFastHeuristics(filename, downloadItem.url, mime);
    return buildHeuristicResult(filename, mime, heuristic);
  }

  return await analyzeBytes(bytes, filename, mime, true);
}

// ─── Core Analysis Runner ─────────────────────────────────────────────────────

async function analyzeBytes(bytes, filename, mimeType, includeVT = false) {
  const analyzer = new FileAnalyzer(bytes, filename, mimeType);
  const result = await analyzer.analyze();

  // Compute hashes
  const hashes = await computeHashes(bytes);
  const md5 = SparkMD5.ArrayBuffer.hash(bytes.buffer);

  result.hashes = { sha256: hashes.sha256, sha1: hashes.sha1, md5 };
  result.timestamp = new Date().toISOString();
  result.source = 'download';

  // Optional VirusTotal lookup
  if (includeVT && settings.vtApiKey && result.hashes.sha256) {
    try {
      const vtResult = await hashChecker.lookup(result.hashes.sha256);
      result.virustotal = vtResult;

      // VT detections score: 0–50 bonus
      if (vtResult.status === 'found' && vtResult.malicious > 0) {
        const vtScore = Math.min(50, Math.round((vtResult.malicious / Math.max(vtResult.total, 1)) * 50));
        result.score = Math.min(100, result.score + vtScore);
        // Re-calculate verdict
        result.verdict = result.score >= 70 ? 'malicious'
                       : result.score >= 40 ? 'suspicious'
                       : result.score >= 15 ? 'caution'
                       : 'clean';
      }
    } catch (e) {
      result.virustotal = { status: 'error', message: e.message };
    }
  }

  return result;
}

// ─── Fetch Helpers ────────────────────────────────────────────────────────────

async function fetchFileBytes(url) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    
    const resp = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);
    
    if (!resp.ok) return null;
    
    const contentLength = parseInt(resp.headers.get('content-length') || '0', 10);
    if (contentLength > MAX_FETCH_BYTES) return null;
    
    const buffer = await resp.arrayBuffer();
    if (buffer.byteLength > MAX_FETCH_BYTES) return null;
    
    return new Uint8Array(buffer);
  } catch {
    return null;
  }
}

// ─── Fast Heuristics (no bytes needed) ───────────────────────────────────────

function runFastHeuristics(filename, url, mime) {
  const lower = (filename || '').toLowerCase();
  const ext = lower.split('.').pop();
  const parts = lower.split('.');

  // Double extension
  if (parts.length >= 3) {
    const secondToLast = parts[parts.length - 2];
    const docLike = new Set(['pdf','doc','docx','xls','xlsx','txt','jpg','png']);
    if (docLike.has(secondToLast) && DANGEROUS_EXTS.has(ext)) {
      return { verdict: 'malicious', reason: `Double extension (.${secondToLast}.${ext})`, score: 80 };
    }
  }

  if (DANGEROUS_EXTS.has(ext)) {
    return { verdict: 'suspicious', reason: `Dangerous extension (.${ext})`, score: 40 };
  }

  // MIME mismatch
  if (mime && ext) {
    if (mime.includes('text/html') && ['exe','bat','ps1'].includes(ext)) {
      return { verdict: 'suspicious', reason: `MIME type mismatch (${mime} vs .${ext})`, score: 30 };
    }
  }

  return { verdict: 'clean', reason: 'No heuristic flags', score: 0 };
}

function buildHeuristicResult(filename, mime, heuristic) {
  return {
    filename,
    mimeType: mime,
    detectedType: 'UNKNOWN',
    extension: filename.split('.').pop(),
    score: heuristic.score,
    verdict: heuristic.verdict,
    findings: heuristic.reason !== 'No heuristic flags'
      ? [{ severity: 'medium', name: 'Heuristic Flag', description: heuristic.reason, scoreContribution: heuristic.score }]
      : [],
    hashes: null,
    analysisMode: 'heuristic-only',
    timestamp: new Date().toISOString(),
    source: 'download',
  };
}

// ─── Storage ──────────────────────────────────────────────────────────────────

async function saveScanResult(result) {
  try {
    const stored = await chrome.storage.local.get('scanHistory');
    const history = stored.scanHistory || [];
    history.unshift(result);
    if (history.length > MAX_HISTORY) history.splice(MAX_HISTORY);
    await chrome.storage.local.set({ scanHistory: history });
  } catch (e) {
    console.error('[HexPose] Failed to save scan result:', e);
  }
}

// ─── Notifications ────────────────────────────────────────────────────────────

function fireNotification(id, title, message, type) {
  const iconFile = type === 'malicious' ? 'icons/icon48.png' : 'icons/icon48.png';
  chrome.notifications.create(id, {
    type: 'basic',
    iconUrl: iconFile,
    title,
    message,
    priority: type === 'malicious' ? 2 : 1,
  }).catch(() => {});
}

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch(err => {
    sendResponse({ error: err.message });
  });
  return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
  switch (message.type) {

    // Popup: scan a file provided as ArrayBuffer
    case 'scanFile': {
      const { buffer, filename, mimeType, useVT } = message;
      if (!buffer) return { error: 'No buffer provided' };
      const bytes = new Uint8Array(buffer);
      const doVT = useVT && !!settings.vtApiKey;
      const result = await analyzeBytes(bytes, filename, mimeType, doVT);
      result.source = 'popup';
      await saveScanResult(result);
      return result;
    }

    // Content script / popup: scan a URL (fetch + analyze)
    case 'scanUrl': {
      const { url, filename, mimeType } = message;
      const bytes = await fetchFileBytes(url);
      if (!bytes) {
        return {
          error: 'fetch_failed',
          message: 'Could not fetch file (may require authentication). Try downloading and scanning manually via the popup.',
          filename,
        };
      }
      const result = await analyzeBytes(bytes, filename || urlFilename(url), mimeType || '', !!settings.vtApiKey);
      result.source = 'content_script';
      await saveScanResult(result);
      return result;
    }

    // Popup: get scan history
    case 'getHistory': {
      const stored = await chrome.storage.local.get('scanHistory');
      return { history: stored.scanHistory || [] };
    }

    // Popup: get settings
    case 'getSettings': {
      return { settings };
    }

    // Popup: update settings
    case 'updateSettings': {
      settings = { ...settings, ...message.settings };
      hashChecker.apiKey = settings.vtApiKey || '';
      hashChecker.clearCache();
      await chrome.storage.local.set({ settings });
      return { ok: true };
    }

    // Content script: fast heuristic check (no bytes)
    case 'heuristicCheck': {
      const { filename, url, mimeType } = message;
      return runFastHeuristics(filename, url, mimeType);
    }

    default:
      return { error: `Unknown message type: ${message.type}` };
  }
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function basename(path) {
  if (!path) return 'unknown';
  return path.split(/[/\\]/).pop() || path;
}

function urlFilename(url) {
  try {
    const u = new URL(url);
    return basename(u.pathname) || 'downloaded-file';
  } catch {
    return 'downloaded-file';
  }
}
