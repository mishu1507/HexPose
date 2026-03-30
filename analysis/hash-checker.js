

const VT_BASE = 'https://www.virustotal.com/api/v3';

export class HashChecker {
  constructor(apiKey) {
    this.apiKey = apiKey || '';
    // Session-level cache: sha256 → result object
    this._cache = new Map();
  }

  /**
   * Look up a SHA-256 hash on VirusTotal.
   * @param {string} sha256 — hex SHA-256 string
   * @returns {Promise<VtResult>}
   */
  async lookup(sha256) {
    if (!this.apiKey) {
      return this._error('NO_API_KEY', 'No VirusTotal API key configured. Add one in Settings.');
    }
    if (!sha256 || sha256.length !== 64) {
      return this._error('INVALID_HASH', 'Invalid SHA-256 hash provided.');
    }

    // Return cached result if available
    if (this._cache.has(sha256)) {
      return { ...this._cache.get(sha256), cached: true };
    }

    let response;
    try {
      response = await fetch(`${VT_BASE}/files/${sha256}`, {
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey,
          'Accept': 'application/json',
        },
      });
    } catch (err) {
      return this._error('NETWORK_ERROR', `Network request failed: ${err.message}`);
    }

    // 404 — file not in VT database (not necessarily clean, just not seen before)
    if (response.status === 404) {
      const result = {
        status: 'not_found',
        malicious: 0,
        suspicious: 0,
        total: 0,
        threatName: null,
        vtLink: `https://www.virustotal.com/gui/file/${sha256}`,
        message: 'Not found in VirusTotal database — file has not been seen before.',
        cached: false,
      };
      this._cache.set(sha256, result);
      return result;
    }

    // 429 — rate limited
    if (response.status === 429) {
      return this._error('RATE_LIMITED',
        'VirusTotal rate limit reached (free tier: 4 req/min, 500/day). Wait a moment and try again.');
    }

    // 401 / 403 — bad API key
    if (response.status === 401 || response.status === 403) {
      return this._error('AUTH_FAILED',
        'VirusTotal API key is invalid or has been banned. Check your key in Settings.');
    }

    if (!response.ok) {
      return this._error('HTTP_ERROR', `VirusTotal returned HTTP ${response.status}.`);
    }

    let json;
    try {
      json = await response.json();
    } catch {
      return this._error('PARSE_ERROR', 'Failed to parse VirusTotal response.');
    }

    const attrs = json?.data?.attributes;
    if (!attrs) {
      return this._error('UNEXPECTED_RESPONSE', 'Unexpected response structure from VirusTotal.');
    }

    const stats = attrs.last_analysis_stats || {};
    const malicious  = stats.malicious   || 0;
    const suspicious = stats.suspicious  || 0;
    const total      = Object.values(stats).reduce((a, b) => a + b, 0);

    // Get most common threat name from results
    const results = attrs.last_analysis_results || {};
    const threatName = this._dominantThreatName(results);

    const result = {
      status: 'found',
      malicious,
      suspicious,
      total,
      threatName,
      vtLink: `https://www.virustotal.com/gui/file/${sha256}`,
      message: `${malicious}/${total} engines detect this file as malicious.`,
      cached: false,
      // Additional context
      firstSeen: attrs.first_submission_date
        ? new Date(attrs.first_submission_date * 1000).toISOString()
        : null,
      lastSeen: attrs.last_submission_date
        ? new Date(attrs.last_submission_date * 1000).toISOString()
        : null,
      names: attrs.names?.slice(0, 3) || [],
    };

    this._cache.set(sha256, result);
    return result;
  }

  /**
   * Load API key from chrome.storage.local and set on this instance.
   * Call this before using the checker in the service worker.
   */
  async loadApiKey() {
    try {
      const data = await chrome.storage.local.get('vtApiKey');
      this.apiKey = data.vtApiKey || '';
    } catch {
      this.apiKey = '';
    }
    return this.apiKey;
  }

  /**
   * Clear the session cache (e.g. when API key changes).
   */
  clearCache() {
    this._cache.clear();
  }

  // ─── Private helpers ─────────────────────────────────────────────────────────

  _error(code, message) {
    return {
      status: 'error',
      errorCode: code,
      message,
      malicious: 0,
      suspicious: 0,
      total: 0,
      threatName: null,
      vtLink: null,
      cached: false,
    };
  }

  /**
   * Find the most commonly reported threat name across all engine results.
   */
  _dominantThreatName(results) {
    const names = {};
    for (const engine of Object.values(results)) {
      if (engine.category === 'malicious' && engine.result) {
        const n = engine.result.trim();
        if (n) names[n] = (names[n] || 0) + 1;
      }
    }
    if (Object.keys(names).length === 0) return null;
    return Object.entries(names).sort((a, b) => b[1] - a[1])[0][0];
  }
}
