/**
 * HexPose — Universal Content Script
 * Injected on every page via <all_urls> match pattern.
 *
 * - Scans all <a href> pointing to file extensions, injects scan button
 * - MutationObserver for dynamically added links (SPAs, Gmail, Notion, Slack)
 * - Intercepts <input type="file"> change events
 * - Global drop event listener
 */

(function () {
  'use strict';

  // ─── Config ─────────────────────────────────────────────────────────────────

  const FILE_EXTENSIONS = new Set([
    'pdf','doc','docx','xls','xlsx','ppt','pptx','docm','xlsm','pptm',
    'exe','dll','msi','bat','cmd','ps1','vbs','hta','wsf','js',
    'zip','rar','7z','gz','tar','apk','jar','iso',
    'rtf','odt','ods','odp','csv',
  ]);

  const SCAN_BTN_CLASS = 'hexpose-scan-btn';
  const BANNER_CLASS   = 'hexpose-warning-banner';
  const PROCESSED_ATTR = 'data-hexpose-scanned';

  // ─── Link injection ──────────────────────────────────────────────────────────

  function getLinkExtension(href) {
    try {
      const u = new URL(href, location.href);
      const pathname = u.pathname.toLowerCase();
      const ext = pathname.split('.').pop().split('?')[0];
      return FILE_EXTENSIONS.has(ext) ? ext : null;
    } catch {
      return null;
    }
  }

  function getFilename(href) {
    try {
      const u = new URL(href, location.href);
      return u.pathname.split('/').pop() || 'file';
    } catch {
      return 'file';
    }
  }

  function injectScanButton(anchor) {
    if (anchor.hasAttribute(PROCESSED_ATTR)) return;
    const ext = getLinkExtension(anchor.href);
    if (!ext) return;
    anchor.setAttribute(PROCESSED_ATTR, '1');

    const btn = document.createElement('button');
    btn.className = SCAN_BTN_CLASS;
    btn.title = 'Scan with HexPose';
    btn.textContent = '🛡';
    btn.setAttribute('aria-label', 'Scan file with HexPose');

    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      await scanLink(anchor.href, getFilename(anchor.href), btn);
    });

    anchor.parentNode.insertBefore(btn, anchor.nextSibling);
  }

  async function scanLink(url, filename, btn) {
    btn.textContent = '⏳';
    btn.disabled = true;

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'scanUrl',
        url,
        filename,
        mimeType: '',
      });

      if (result.error) {
        showInlineBadge(btn, 'caution', '⚠ Auth-protected — scan manually');
        return;
      }

      const badge = verdictToBadge(result.verdict);
      btn.textContent = badge.icon;
      btn.className = `${SCAN_BTN_CLASS} hexpose-verdict-${result.verdict}`;
      btn.title = `HexPose: ${result.verdict.toUpperCase()} (${result.score}/100)`;
      btn.disabled = false;

      if (result.verdict === 'malicious' || result.verdict === 'suspicious') {
        showWarningBanner(btn, result);
      }
    } catch {
      btn.textContent = '?';
      btn.disabled = false;
      btn.title = 'HexPose: Scan failed';
    }
  }

  function processAllLinks() {
    document.querySelectorAll('a[href]').forEach(a => {
      if (a.href) injectScanButton(a);
    });
  }

  // ─── Warning banner ──────────────────────────────────────────────────────────

  function showWarningBanner(anchorEl, result) {
    // Remove existing banner near this element
    const existing = anchorEl.parentNode?.querySelector(`.${BANNER_CLASS}`);
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.className = `${BANNER_CLASS} hexpose-verdict-${result.verdict}`;

    const icon = result.verdict === 'malicious' ? '🚨' : '⚠️';
    const topFindings = result.findings.slice(0, 3).map(f => `• ${f.name}`).join('\n');

    banner.innerHTML = `
      <span class="hexpose-banner-icon">${icon}</span>
      <span class="hexpose-banner-text">
        <strong>HexPose: ${result.verdict.toUpperCase()}</strong> — Score: ${result.score}/100<br>
        <small>${result.filename}</small>
        ${topFindings ? `<pre class="hexpose-banner-findings">${topFindings}</pre>` : ''}
      </span>
      <button class="hexpose-banner-close" aria-label="Dismiss">✕</button>
    `;

    banner.querySelector('.hexpose-banner-close').addEventListener('click', () => banner.remove());
    anchorEl.parentNode.insertBefore(banner, anchorEl.nextSibling?.nextSibling || null);
  }

  function showInlineBadge(btn, verdict, message) {
    btn.textContent = verdict === 'caution' ? '⚠' : '?';
    btn.title = `HexPose: ${message}`;
    btn.disabled = false;
  }

  // ─── File input interception ─────────────────────────────────────────────────

  function attachFileInputListeners(inputs) {
    inputs.forEach(input => {
      if (input.hasAttribute(PROCESSED_ATTR)) return;
      input.setAttribute(PROCESSED_ATTR, '1');

      input.addEventListener('change', async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        const result = await scanFile(file);
        if (!result) return;

        if (result.verdict === 'malicious' || result.verdict === 'suspicious') {
          const proceed = confirm(
            `⚠️ HexPose Warning\n\n` +
            `File: ${file.name}\n` +
            `Verdict: ${result.verdict.toUpperCase()} (Score: ${result.score}/100)\n\n` +
            `Top finding: ${result.findings[0]?.name || 'Unknown'}\n\n` +
            `Do you want to proceed with uploading this file anyway?`
          );
          if (!proceed) {
            // Reset the input
            e.target.value = '';
          }
        }
      }, { capture: true });
    });
  }

  function processAllFileInputs() {
    attachFileInputListeners(document.querySelectorAll('input[type="file"]'));
  }

  // ─── Drop event listener ─────────────────────────────────────────────────────

  document.addEventListener('drop', async (e) => {
    const files = e.dataTransfer?.files;
    if (!files || files.length === 0) return;

    // Scan the first dropped file
    const file = files[0];
    const result = await scanFile(file);
    if (!result) return;

    if (result.verdict === 'malicious' || result.verdict === 'suspicious') {
      // Show a floating alert
      showDropAlert(result);
    }
  }, true);

  function showDropAlert(result) {
    const existing = document.getElementById('hexpose-drop-alert');
    if (existing) existing.remove();

    const alert = document.createElement('div');
    alert.id = 'hexpose-drop-alert';
    alert.className = `${BANNER_CLASS} hexpose-drop-alert hexpose-verdict-${result.verdict}`;

    const icon = result.verdict === 'malicious' ? '🚨' : '⚠️';
    alert.innerHTML = `
      <span class="hexpose-banner-icon">${icon}</span>
      <span class="hexpose-banner-text">
        <strong>HexPose: ${result.verdict.toUpperCase()}</strong> — ${result.filename} (${result.score}/100)<br>
        <small>${result.findings.slice(0, 2).map(f => f.name).join(' • ')}</small>
      </span>
      <button class="hexpose-banner-close" aria-label="Dismiss">✕</button>
    `;

    alert.querySelector('.hexpose-banner-close').addEventListener('click', () => alert.remove());
    document.body.appendChild(alert);

    // Auto dismiss after 10s
    setTimeout(() => alert.remove(), 10000);
  }

  // ─── File scanning helper ────────────────────────────────────────────────────

  async function scanFile(file) {
    try {
      const buffer = await file.arrayBuffer();
      const result = await chrome.runtime.sendMessage({
        type: 'scanFile',
        buffer,
        filename: file.name,
        mimeType: file.type || '',
        useVT: true,
      });
      return result;
    } catch (e) {
      console.warn('[HexPose] File scan error:', e);
      return null;
    }
  }

  // ─── Verdict helpers ─────────────────────────────────────────────────────────

  function verdictToBadge(verdict) {
    switch (verdict) {
      case 'malicious':  return { icon: '🚨', label: 'Malicious' };
      case 'suspicious': return { icon: '⚠️', label: 'Suspicious' };
      case 'caution':    return { icon: '⚡', label: 'Caution' };
      default:           return { icon: '✅', label: 'Clean' };
    }
  }

  // ─── MutationObserver ────────────────────────────────────────────────────────

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        
        // Check if the node itself is a link or input
        if (node.tagName === 'A' && node.href) injectScanButton(node);
        if (node.tagName === 'INPUT' && node.type === 'file') attachFileInputListeners([node]);
        
        // Check descendants
        node.querySelectorAll?.('a[href]').forEach(a => injectScanButton(a));
        node.querySelectorAll?.('input[type="file"]').forEach(inp => attachFileInputListeners([inp]));
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });

  // ─── Init ────────────────────────────────────────────────────────────────────

  processAllLinks();
  processAllFileInputs();

})();
