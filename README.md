# HexPose - Universal File Malware Scanner

A Chrome extension that intercepts files across every website and scans them for malware, exploits, and suspicious payloads **before you open them**. All analysis runs locally in your browser - file bytes never leave your machine.

![HexPose](icons/icon128.png)

## Quick Start

### 1. Load the Extension

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `HexPose` folder
5. The ⬡ icon appears in your toolbar - you're ready

### 2. Get a Free VirusTotal API Key (Optional)

1. Sign up at [virustotal.com](https://www.virustotal.com/gui/join-us) (free)
2. Go to your profile → API Key
3. Copy the key
4. Open HexPose popup → **Settings** tab → paste key → **Save**
5. Free tier: 500 lookups/day, 4/min - enough for personal use

> **Privacy**: Only the SHA-256 hash is sent to VirusTotal - never the file itself.

## What It Does

| Feature | How |
|---|---|
| **Manual scan** | Drag any file into the popup or click to browse |
| **Download interception** | All downloads auto-scanned via `chrome.downloads` API |
| **File link scanning** | Scan buttons injected next to file links on every page |
| **Upload interception** | Warns before uploading a suspicious file via `<input type="file">` |
| **Drag-and-drop** | Global drop listener catches files dragged onto any page |
| **VirusTotal lookup** | SHA-256 hash checked against 70+ AV engines (with API key) |
| **Scan history** | Last 100 scans stored locally |

## File Structure

```
HexPose/
├── manifest.json              # Chrome MV3 manifest
├── background/
│   └── service-worker.js      # Download interceptor, analysis runner, message router
├── analysis/
│   ├── file-analyzer.js       # Core static analysis engine (magic bytes, entropy, PDF/Office/shellcode checks)
│   └── hash-checker.js        # VirusTotal v3 API hash lookup with session cache
├── content/
│   └── universal-scanner.js   # Content script: link injection, file input, drop, MutationObserver
├── popup/
│   ├── popup.html             # 3-tab UI: Scan, History, Settings
│   ├── popup.css              # Dark theme styles
│   └── popup.js               # Popup interaction logic
├── styles/
│   └── scan-overlay.css       # Injected on all pages (hexpose- prefixed)
├── lib/
│   └── spark-md5.js           # MD5 hashing (VirusTotal requires MD5)
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── README.md
```

## Static Analysis Engine

The `FileAnalyzer` runs entirely in the browser with zero network calls:

**File identification**
- Magic byte detection: PDF, PE/EXE, ELF, ZIP/DOCX, RAR, OLE/CFB, RTF, 7z, Mach-O, Java CLASS
- Extension mismatch detection (e.g., `.pdf` containing EXE magic bytes)
- Double extension detection (e.g., `invoice.pdf.exe`)
- Dangerous extension blocklist (40+ extensions)

**Entropy analysis**
- Shannon entropy over all bytes - flags >7.5 as potentially packed/encrypted

**PDF checks** (13 patterns)
- `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/SubmitForm`, `/ImportData`
- `/EmbeddedFile`, `/XFA`, `/ObjStm`, `/JBIG2Decode`, `/GoToR`, `/GoToE`, `/Flash`
- Large hex-encoded strings

**Office document checks**
- VBA macros: `Auto_Open`, `Document_Open`, `Workbook_Open`, `AutoExec`
- Execution: `Shell()`, `WScript`, `CreateObject`, `.Run()`, PowerShell, `cmd.exe`
- DDE/DDEAUTO, Equation Editor (CVE-2017-11882), OLE Package
- Obfuscation: `Chr()`, `StrReverse`

**Shellcode heuristics**
- NOP sleds (10+ consecutive `0x90`)
- XOR register patterns (`XOR EAX,EAX`)
- CALL+POP / JMP SHORT+POP (position-independent code)
- PUSH+RET sequences

**Obfuscation detection**
- `eval()`, `fromCharCode()`, `atob()`, `unescape()`
- Long hex/unicode escape sequences

**Network indicators**
- Direct IP URLs, URL shorteners, paste site references
- `cmd.exe`, `powershell -enc` references
- Suspicious TLDs

## Risk Scoring

| Severity | Score | Examples |
|---|---|---|
| Critical | +40 | Executable masquerading as document, /Launch in PDF, Auto_Open macro |
| High | +25 | File type mismatch, NOP sled, eval(), direct IP URL |
| Medium | +15 | /ObjStm, URL shortener, elevated entropy |
| Low | +5 | Minor heuristic flags |

Multiple findings stack. Score capped at 100. VirusTotal adds up to +50 on top.

| Score | Verdict | UI |
|---|---|---|
| 0–14 | Clean | ✅ Green |
| 15–39 | Caution | ⚡ Yellow |
| 40–69 | Suspicious | ⚠️ Orange |
| 70–100 | Malicious | 🚨 Red + notification |

## Settings

| Setting | Default | Description |
|---|---|---|
| Auto-scan downloads | ✅ On | Scan every download automatically |
| Block malicious | ❌ Off | Cancel downloads scoring ≥70 |
| Notifications | ✅ On | Desktop notification on malicious verdict |
| VT API Key | — | Your free VirusTotal API key |

## Known Limitations

- **Authenticated URLs**: Files behind login (Google Drive, SharePoint) return 403 when fetched by the extension. For these, download the file first and scan manually via the popup.
- **Service worker file access**: MV3 service workers cannot read local `file://` paths after download. The extension re-fetches from the original URL; if that URL requires auth or is ephemeral, byte-level analysis may not be available.
- **Large files**: Files >50 MB are skipped for full analysis to avoid memory issues.
- **False positives**: Minified JavaScript, compressed assets, and legitimately obfuscated but clean files may trigger medium-severity findings. Review the specific findings to decide.
- **VT rate limits**: Free tier is 4 requests/minute, 500/day. Results are cached per session to minimize usage.

## Tech Stack

| Layer | Choice |
|---|---|
| Extension | Chrome Manifest V3 (service worker) |
| File parsing | Native `Uint8Array` + `TextDecoder` |
| SHA-256 / SHA-1 | `crypto.subtle.digest` (Web Crypto API) |
| MD5 | spark-md5 (bundled locally) |
| Storage | `chrome.storage.local` |
| External API | VirusTotal v3 REST (optional) |

## License

MIT
