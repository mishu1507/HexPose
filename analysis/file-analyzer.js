/**
 * HexPose — FileAnalyzer
 * Core static analysis engine. Runs entirely in the browser (or Node for testing).
 * Never makes network calls. Returns a structured result object.
 *
 * Usage:
 *   const analyzer = new FileAnalyzer(uint8Array, filename, mimeType);
 *   const result = await analyzer.analyze();
 */

export class FileAnalyzer {
  // ─── Magic bytes ────────────────────────────────────────────────────────────
  static MAGIC = {
    PDF:   [0x25, 0x50, 0x44, 0x46],           // %PDF
    PE:    [0x4D, 0x5A],                         // MZ — Windows PE/EXE/DLL
    ELF:   [0x7F, 0x45, 0x4C, 0x46],           // ELF
    ZIP:   [0x50, 0x4B, 0x03, 0x04],           // PK.. — ZIP / DOCX / XLSX / PPTX / JAR / APK
    ZIP_EMPTY: [0x50, 0x4B, 0x05, 0x06],       // PK empty
    RAR:   [0x52, 0x61, 0x72, 0x21],           // Rar!
    GZ:    [0x1F, 0x8B],                         // GZIP
    OLE:   [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], // OLE CFB — .doc .xls .ppt
    RTF:   [0x7B, 0x5C, 0x72, 0x74, 0x66],    // {\rtf
    HTML:  [0x3C, 0x68, 0x74, 0x6D, 0x6C],    // <html
    PS:    [0x25, 0x21, 0x50, 0x53],           // %!PS — PostScript
    CLASS: [0xCA, 0xFE, 0xBA, 0xBE],           // Java class
    MACH:  [0xCF, 0xFA, 0xED, 0xFE],           // Mach-O 64-bit
    MACH32:[0xCE, 0xFA, 0xED, 0xFE],           // Mach-O 32-bit
    SEVENZIP:[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], // 7z
  };

  // ─── Dangerous extensions ────────────────────────────────────────────────────
  static DANGEROUS_EXTENSIONS = new Set([
    'exe','dll','sys','drv','ocx','cpl','scr','pif','com',
    'bat','cmd','ps1','ps2','psm1','psd1','vbs','vbe','js',
    'jse','wsf','wsh','hta','msi','msp','msc','reg',
    'lnk','jar','apk','app','scf','inf','ins','isp',
    'gadget','ws','wsc','csh','sh','bash','run','bin',
    'dex','ipa','xap','xbap',
  ]);

  // ─── Office file extensions ──────────────────────────────────────────────────
  static OFFICE_EXTENSIONS = new Set([
    'doc','docx','docm','xls','xlsx','xlsm','ppt','pptx','pptm',
    'dot','dotx','dotm','xlt','xltx','xltm','pot','potx','potm',
    'rtf','odt','ods','odp',
  ]);

  // ─── URL shorteners ─────────────────────────────────────────────────────────
  static URL_SHORTENERS = [
    'bit.ly','tinyurl.com','goo.gl','ow.ly','t.co','is.gd',
    'buff.ly','adf.ly','tiny.cc','tr.im','cli.gs','url4.eu',
    'qr.net','1url.com','hyperurl.co','urlzs.com','v.gd',
  ];

  constructor(bytes, filename, mimeType = '') {
    /** @type {Uint8Array} */
    this.bytes = bytes;
    this.filename = filename || 'unknown';
    this.mimeType = mimeType || '';
    this.findings = [];
    this.score = 0;
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  async analyze() {
    const ext = this._getExtension(this.filename);
    const detectedType = this._detectMagicType();
    const textContent = this._decodeText();

    // Run all checks
    this._checkDangerousExtension(ext);
    this._checkExtensionMismatch(ext, detectedType);
    this._checkDoubleExtension(this.filename);
    this._checkEntropy();

    if (detectedType === 'PDF' || ext === 'pdf') {
      this._checkPDF(textContent);
    }
    if (detectedType === 'OLE' || FileAnalyzer.OFFICE_EXTENSIONS.has(ext)) {
      this._checkOffice(textContent);
    }
    if (detectedType === 'ZIP' && FileAnalyzer.OFFICE_EXTENSIONS.has(ext)) {
      // OOXML-based Office docs are ZIPs — still run office checks on text content
      this._checkOffice(textContent);
    }

    this._checkShellcode();
    this._checkObfuscation(textContent);
    this._checkNetworkIndicators(textContent);

    // Cap score
    this.score = Math.min(this.score, 100);

    return {
      filename: this.filename,
      fileSize: this.bytes.length,
      detectedType,
      extension: ext,
      mimeType: this.mimeType,
      score: this.score,
      verdict: this._verdict(this.score),
      findings: this.findings,
      entropy: this._shannonEntropy(this.bytes),
    };
  }

  // ─── File type detection ─────────────────────────────────────────────────────

  _detectMagicType() {
    const b = this.bytes;
    if (!b || b.length < 4) return 'UNKNOWN';

    if (this._matchMagic(b, FileAnalyzer.MAGIC.PDF)) return 'PDF';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.OLE)) return 'OLE';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.PE)) return 'PE';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.ELF)) return 'ELF';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.ZIP)) return 'ZIP';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.ZIP_EMPTY)) return 'ZIP';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.SEVENZIP)) return '7Z';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.RAR)) return 'RAR';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.GZ)) return 'GZ';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.RTF)) return 'RTF';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.PS)) return 'PS';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.CLASS)) return 'JAVA_CLASS';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.MACH)) return 'MACHO';
    if (this._matchMagic(b, FileAnalyzer.MAGIC.MACH32)) return 'MACHO';
    return 'UNKNOWN';
  }

  _matchMagic(bytes, magic) {
    if (bytes.length < magic.length) return false;
    for (let i = 0; i < magic.length; i++) {
      if (bytes[i] !== magic[i]) return false;
    }
    return true;
  }

  // ─── Extension helpers ───────────────────────────────────────────────────────

  _getExtension(filename) {
    const parts = filename.toLowerCase().split('.');
    return parts.length > 1 ? parts[parts.length - 1] : '';
  }

  _checkDangerousExtension(ext) {
    if (FileAnalyzer.DANGEROUS_EXTENSIONS.has(ext)) {
      this._addFinding('critical', 'Dangerous Extension',
        `File has a dangerous extension (.${ext}) that can execute arbitrary code.`);
    }
  }

  _checkExtensionMismatch(ext, detectedType) {
    const mismatches = {
      PE:  ['exe','dll','sys','drv','ocx','cpl','scr','pif','com'],
      ELF: ['elf','so','bin','run'],
      PDF: ['pdf'],
      OLE: ['doc','xls','ppt','dot','xlt','pot'],
      ZIP: ['zip','jar','apk','docx','xlsx','pptx','docm','xlsm','pptm'],
    };

    for (const [type, exts] of Object.entries(mismatches)) {
      if (detectedType === type && ext !== '' && !exts.includes(ext)) {
        // File has a non-matching extension for its actual content
        this._addFinding('high', 'File Type Mismatch',
          `File is detected as ${type} by magic bytes but has extension .${ext}. This is a common malware camouflage technique.`);
        return;
      }
    }

    // Check if a document extension is masking an executable
    const docExts = new Set(['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','jpg','jpeg','png','gif']);
    if (docExts.has(ext) && (detectedType === 'PE' || detectedType === 'ELF')) {
      this._addFinding('critical', 'Executable Masquerading as Document',
        `File has extension .${ext} but contains executable (${detectedType}) magic bytes. Classic malware technique.`);
    }
  }

  _checkDoubleExtension(filename) {
    // Match patterns like "document.pdf.exe" or "invoice.doc.js"
    const lower = filename.toLowerCase();
    const parts = lower.split('.');
    if (parts.length < 3) return;

    // Last extension plus second-to-last
    const lastExt = parts[parts.length - 1];
    const middleExt = parts[parts.length - 2];

    const docLike = new Set(['pdf','doc','docx','xls','xlsx','txt','jpg','jpeg','png','gif','zip']);
    const execLike = FileAnalyzer.DANGEROUS_EXTENSIONS;

    if (docLike.has(middleExt) && execLike.has(lastExt)) {
      this._addFinding('critical', 'Double Extension',
        `Filename "${filename}" uses a double extension (.${middleExt}.${lastExt}). This tricks users into thinking the file is a document while the OS executes the final extension.`);
    }
  }

  // ─── Entropy ─────────────────────────────────────────────────────────────────

  _shannonEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Float64Array(256);
    for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
    let entropy = 0;
    const len = bytes.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  _checkEntropy() {
    const entropy = this._shannonEntropy(this.bytes);
    if (entropy > 7.5) {
      this._addFinding('high', 'High Entropy',
        `File entropy is ${entropy.toFixed(2)}/8.0 — indicates the file may be encrypted, packed, or compressed to evade static analysis.`);
    } else if (entropy > 7.0) {
      this._addFinding('medium', 'Elevated Entropy',
        `File entropy is ${entropy.toFixed(2)}/8.0 — slightly elevated, may indicate packed or encrypted sections.`);
    }
  }

  // ─── Text helpers ─────────────────────────────────────────────────────────────

  _decodeText() {
    try {
      // For binary analysis we use latin-1 (preserves all bytes as characters)
      return new TextDecoder('latin1').decode(this.bytes);
    } catch {
      return '';
    }
  }

  // ─── PDF checks ──────────────────────────────────────────────────────────────

  _checkPDF(text) {
    const patterns = [
      { pattern: /\/JavaScript\b/gi,      severity: 'critical', name: '/JavaScript',    desc: 'Embedded JavaScript found — can execute arbitrary code when the PDF is opened.' },
      { pattern: /\/JS\b/gi,              severity: 'critical', name: '/JS',             desc: 'Embedded /JS action found — shorthand for JavaScript execution.' },
      { pattern: /\/OpenAction\b/gi,      severity: 'high',    name: '/OpenAction',     desc: '/OpenAction triggers actions automatically on PDF open without user interaction.' },
      { pattern: /\/AA\b/gi,              severity: 'high',    name: '/AA (Auto Action)',desc: '/AA (Additional Actions) key found — can trigger actions on various events.' },
      { pattern: /\/Launch\b/gi,          severity: 'critical', name: '/Launch',         desc: '/Launch action can execute external programs or open files when triggered.' },
      { pattern: /\/SubmitForm\b/gi,      severity: 'medium',  name: '/SubmitForm',     desc: '/SubmitForm action can silently exfiltrate form data to a remote server.' },
      { pattern: /\/ImportData\b/gi,      severity: 'medium',  name: '/ImportData',     desc: '/ImportData can pull data from external URLs into the PDF.' },
      { pattern: /\/EmbeddedFile\b/gi,    severity: 'high',    name: '/EmbeddedFile',   desc: 'Files embedded inside the PDF — could contain executable payloads.' },
      { pattern: /\/XFA\b/gi,            severity: 'high',    name: '/XFA',            desc: 'XFA (XML Forms Architecture) found — can contain executable scripts.' },
      { pattern: /\/ObjStm\b/gi,         severity: 'medium',  name: '/ObjStm',         desc: 'Object streams can hide PDF objects from simple parsers — common obfuscation.' },
      { pattern: /\/JBIG2Decode\b/gi,    severity: 'high',    name: '/JBIG2Decode',    desc: 'JBIG2Decode filter found — historically exploited (CVE-2009-0658, Acrobat RCE).' },
      { pattern: /\/GoToR\b/gi,          severity: 'medium',  name: '/GoToR',          desc: '/GoToR (Remote Go-To) can redirect to external files or resources.' },
      { pattern: /\/GoToE\b/gi,          severity: 'medium',  name: '/GoToE',          desc: '/GoToE (Embedded Go-To) navigates to embedded document targets.' },
      { pattern: /\/Flash\b/gi,          severity: 'high',    name: '/Flash',          desc: 'Flash RichMedia content found — Flash is end-of-life and historically exploited.' },
    ];

    for (const { pattern, severity, name, desc } of patterns) {
      if (pattern.test(text)) {
        this._addFinding(severity, `PDF: ${name}`, desc);
      }
    }

    // Large hex-encoded strings (obfuscation / shellcode)
    const hexStringPattern = /([0-9a-fA-F]{2}){20,}/g;
    const hexMatches = text.match(hexStringPattern);
    if (hexMatches && hexMatches.length > 0) {
      this._addFinding('medium', 'PDF: Large Hex-Encoded String',
        `${hexMatches.length} large hex-encoded sequence(s) found — common obfuscation / shellcode embedding technique.`);
    }
  }

  // ─── Office checks ───────────────────────────────────────────────────────────

  _checkOffice(text) {
    const patterns = [
      // VBA macro signatures
      { pattern: /Auto_Open\b/gi,         severity: 'critical', name: 'VBA: Auto_Open',      desc: 'Auto_Open macro — executes automatically when the document is opened.' },
      { pattern: /AutoOpen\b/gi,          severity: 'critical', name: 'VBA: AutoOpen',       desc: 'AutoOpen macro — automatically runs on document open.' },
      { pattern: /AutoExec\b/gi,          severity: 'critical', name: 'VBA: AutoExec',       desc: 'AutoExec macro — runs automatically on exec.' },
      { pattern: /Document_Open\b/gi,     severity: 'critical', name: 'VBA: Document_Open',  desc: 'Document_Open event — macro triggers when document opens.' },
      { pattern: /Workbook_Open\b/gi,     severity: 'critical', name: 'VBA: Workbook_Open',  desc: 'Workbook_Open event — macro runs when Excel workbook opens.' },
      // Execution via macro
      { pattern: /\bShell\s*\(/gi,        severity: 'critical', name: 'VBA: Shell()',         desc: 'Shell() call in macro — can execute arbitrary OS commands.' },
      { pattern: /\bWScript\b/gi,         severity: 'high',    name: 'VBA: WScript',         desc: 'WScript reference — Windows Script Host execution.' },
      { pattern: /CreateObject\s*\(/gi,   severity: 'high',    name: 'VBA: CreateObject()',   desc: 'CreateObject() — creates COM objects, commonly used for execution, persistence, or network access.' },
      { pattern: /\.Run\s*\(/gi,          severity: 'high',    name: 'VBA: .Run()',           desc: '.Run() call — executes commands, common in malicious macros.' },
      { pattern: /powershell/gi,          severity: 'critical', name: 'VBA: PowerShell',      desc: 'PowerShell invocation inside document/macro — common dropper technique.' },
      { pattern: /cmd\.exe/gi,            severity: 'critical', name: 'VBA: cmd.exe',         desc: 'cmd.exe reference inside document — direct OS shell execution.' },
      // DDE
      { pattern: /DDE\b/g,               severity: 'critical', name: 'Office: DDE',          desc: 'DDE (Dynamic Data Exchange) found — can execute arbitrary programs without macros.' },
      { pattern: /DDEAUTO\b/g,           severity: 'critical', name: 'Office: DDEAUTO',      desc: 'DDEAUTO field — auto-executes DDE command without user interaction.' },
      // Equation Editor
      { pattern: /Equation\s*Editor/gi,  severity: 'high',    name: 'Office: Equation Editor', desc: 'Equation Editor reference found — target of CVE-2017-11882 RCE exploit.' },
      { pattern: /EQNEDT32/gi,           severity: 'critical', name: 'Office: EQNEDT32',     desc: 'EQNEDT32 (Equation Editor binary) reference — strong indicator of CVE-2017-11882 exploit.' },
      // OLE Package
      { pattern: /OLE Package/gi,        severity: 'high',    name: 'Office: OLE Package',   desc: 'OLE Package object — can embed and execute arbitrary files.' },
      { pattern: /Package\s+Object/gi,   severity: 'medium',  name: 'Office: Package Object', desc: 'Package object found — may embed executable content.' },
      // Obfuscated content
      { pattern: /Chr\s*\(\s*\d+\s*\)/gi, severity: 'medium',  name: 'VBA: Chr() Obfuscation', desc: 'Chr() function calls — character-by-character string building, common obfuscation.' },
      { pattern: /\bStrReverse\b/gi,     severity: 'medium',  name: 'VBA: StrReverse',       desc: 'StrReverse() — reverses strings to bypass pattern detection.' },
    ];

    for (const { pattern, severity, name, desc } of patterns) {
      if (pattern.test(text)) {
        this._addFinding(severity, name, desc);
      }
    }
  }

  // ─── Shellcode heuristics ────────────────────────────────────────────────────

  _checkShellcode() {
    const bytes = this.bytes;
    const len = bytes.length;

    // NOP sled: 10+ consecutive 0x90 bytes
    let nopCount = 0;
    let maxNop = 0;
    for (let i = 0; i < len; i++) {
      if (bytes[i] === 0x90) {
        nopCount++;
        if (nopCount > maxNop) maxNop = nopCount;
      } else {
        nopCount = 0;
      }
    }
    if (maxNop >= 10) {
      this._addFinding('high', 'Shellcode: NOP Sled',
        `NOP sled detected — longest run of 0x90 bytes: ${maxNop}. Commonly used to slide execution to shellcode payload.`);
    }

    // XOR EAX, EAX (0x31 0xC0) or XOR ECX,ECX (0x31 0xC9) — register zeroing in shellcode
    let xorCount = 0;
    for (let i = 0; i < len - 1; i++) {
      if (bytes[i] === 0x31 && (bytes[i+1] === 0xC0 || bytes[i+1] === 0xC9 || bytes[i+1] === 0xD2 || bytes[i+1] === 0xDB)) {
        xorCount++;
      }
    }
    if (xorCount >= 3) {
      this._addFinding('high', 'Shellcode: XOR Register Pattern',
        `${xorCount} XOR register-zeroing instructions (e.g., XOR EAX,EAX) found — characteristic register initialization in shellcode.`);
    }

    // CALL+POP pattern (0xE8 followed closely by 0x58..0x5F) — GetPC technique
    let callPopCount = 0;
    for (let i = 0; i < len - 5; i++) {
      if (bytes[i] === 0xE8) {
        // Look for a POP r32 instruction (0x58-0x5F) within the next 6 bytes
        for (let j = i+1; j < Math.min(i+6, len); j++) {
          if (bytes[j] >= 0x58 && bytes[j] <= 0x5F) {
            callPopCount++;
            break;
          }
        }
      }
    }
    if (callPopCount >= 2) {
      this._addFinding('high', 'Shellcode: CALL+POP Pattern',
        `${callPopCount} CALL+POP patterns found — position-independent code technique used in shellcode to locate itself in memory.`);
    }

    // JMP SHORT (0xEB) followed by POP (0x58-0x5F)
    let jmpPopCount = 0;
    for (let i = 0; i < len - 2; i++) {
      if (bytes[i] === 0xEB && bytes[i+2] >= 0x58 && bytes[i+2] <= 0x5F) {
        jmpPopCount++;
      }
    }
    if (jmpPopCount >= 2) {
      this._addFinding('medium', 'Shellcode: JMP SHORT+POP Pattern',
        `${jmpPopCount} JMP SHORT followed by POP patterns — common in position-independent shellcode stubs.`);
    }

    // PUSH + RET sequences (0x68 <4 bytes> 0xC3) — jump-via-return
    let pushRetCount = 0;
    for (let i = 0; i < len - 5; i++) {
      if (bytes[i] === 0x68 && bytes[i+5] === 0xC3) {
        pushRetCount++;
      }
    }
    if (pushRetCount >= 3) {
      this._addFinding('medium', 'Shellcode: PUSH+RET Pattern',
        `${pushRetCount} PUSH+RET sequences found — can redirect control flow to pushed addresses.`);
    }
  }

  // ─── Obfuscation checks ──────────────────────────────────────────────────────

  _checkObfuscation(text) {
    const patterns = [
      { pattern: /\beval\s*\(/gi,                severity: 'high',   name: 'Obfuscation: eval()',          desc: 'eval() call found — executes dynamically constructed code strings.' },
      { pattern: /fromCharCode\s*\(/gi,          severity: 'high',   name: 'Obfuscation: fromCharCode()',  desc: 'String.fromCharCode() — reconstructs strings character-by-character to evade pattern matching.' },
      { pattern: /\batob\s*\(/gi,               severity: 'high',   name: 'Obfuscation: atob()',           desc: 'atob() — decodes Base64-encoded strings at runtime to hide payloads.' },
      { pattern: /unescape\s*\(/gi,             severity: 'medium', name: 'Obfuscation: unescape()',       desc: 'unescape() — decodes percent-encoded or hex-encoded strings.' },
      // Long hex string sequences \xNN\xNN... (10+ consecutive)
      { pattern: /(\\x[0-9a-fA-F]{2}){10,}/g, severity: 'high',   name: 'Obfuscation: Hex Escape String', desc: 'Long hex-escaped string (10+ \\xNN sequences) — common payload encoding.' },
      // Long unicode escapes \uNNNN
      { pattern: /(\\u[0-9a-fA-F]{4}){8,}/g,  severity: 'medium', name: 'Obfuscation: Unicode Escape String', desc: 'Long unicode-escaped string (8+ \\uNNNN sequences) — obfuscation technique.' },
      // document.write with something inside
      { pattern: /document\.write\s*\(/gi,      severity: 'medium', name: 'Obfuscation: document.write()', desc: 'document.write() — commonly used to inject content or scripts dynamically.' },
    ];

    for (const { pattern, severity, name, desc } of patterns) {
      if (pattern.test(text)) {
        this._addFinding(severity, name, desc);
      }
    }
  }

  // ─── Network indicators ──────────────────────────────────────────────────────

  _checkNetworkIndicators(text) {
    // Direct IP URLs — http://x.x.x.x/
    const ipUrlPattern = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[/:\s]/gi;
    if (ipUrlPattern.test(text)) {
      this._addFinding('high', 'Network: Direct IP URL',
        'URL with direct IP address found — bypasses domain reputation checks, common in malware C2 communication.');
    }

    // URL shorteners
    const shortenerPattern = new RegExp(
      'https?://(' + FileAnalyzer.URL_SHORTENERS.map(s => s.replace('.', '\\.')).join('|') + ')/',
      'gi'
    );
    if (shortenerPattern.test(text)) {
      this._addFinding('medium', 'Network: URL Shortener',
        'URL shortener service reference found — hides the true destination, common in phishing payloads.');
    }

    // PowerShell encoded command
    if (/powershell[^"']*-e(nc)?\s+[A-Za-z0-9+/=]{20,}/gi.test(text)) {
      this._addFinding('critical', 'Network: PowerShell Encoded Command',
        'powershell -enc (encoded command) found — executes Base64-encoded commands to evade logging and EDR detection.');
    }

    // Pastebin / paste sites
    if (/pastebin\.com|paste\.ee|hastebin\.com|privatebin\./gi.test(text)) {
      this._addFinding('high', 'Network: Paste Site Reference',
        'Pastebin or similar paste service URL found — frequently used to host second-stage payloads.');
    }

    // Cmd.exe reference
    if (/cmd\.exe/gi.test(text)) {
      this._addFinding('high', 'Network: cmd.exe Reference',
        'cmd.exe reference inside file — may indicate command execution capability.');
    }

    // Suspicious TLDs combined with download patterns
    if (/https?:\/\/[^\s"']+\.(ru|cn|tk|xyz|top|click|download|icu)[/\s]/gi.test(text)) {
      this._addFinding('medium', 'Network: Suspicious TLD',
        'URL with high-risk TLD (.ru, .cn, .tk, .xyz, etc.) found — frequently associated with malware hosting.');
    }
  }

  // ─── Scoring & verdict ────────────────────────────────────────────────────────

  _addFinding(severity, name, description) {
    const scoreMap = { critical: 40, high: 25, medium: 15, low: 5 };
    const contribution = scoreMap[severity] || 5;
    this.score += contribution;
    this.findings.push({ severity, name, description, scoreContribution: contribution });
  }

  _verdict(score) {
    if (score >= 70) return 'malicious';
    if (score >= 40) return 'suspicious';
    if (score >= 15) return 'caution';
    return 'clean';
  }
}

// ─── Static helper: compute SHA-256 and SHA-1 hashes ─────────────────────────

export async function computeHashes(bytes) {
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const [sha256Buf, sha1Buf] = await Promise.all([
    crypto.subtle.digest('SHA-256', buffer),
    crypto.subtle.digest('SHA-1', buffer),
  ]);
  return {
    sha256: _bufToHex(sha256Buf),
    sha1:   _bufToHex(sha1Buf),
  };
}

function _bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
