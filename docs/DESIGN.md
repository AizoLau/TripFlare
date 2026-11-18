# TripFlare design notes

## Why TripFlare exists (threat model)

Real-world crypto-theft and infostealer incidents on Windows overwhelmingly
share the same post-exploitation shape: a payload is dropped into a
user-writable location (Downloads, Temp, AppData, the Startup folder), it
carries a random or masquerading name, it is unsigned or self-signed, and it
immediately creates a persistence mechanism (a `Run` value, a scheduled
task, a service, an IFEO debugger, a Startup-folder shortcut). Stealers
that grabbed exchange API keys and wallet files in the wild (the endless
stream of "my wallet was drained after I ran X" reports) almost all walked
through exactly this door.

Full antivirus looks for *known bad* content. TripFlare takes the tripwire
position instead: it assumes a clean baseline and screams when the
*environment* changes in ways that match the intrusion shape above. It
does not scan file contents, so it cannot be evaded by packers — but it
also cannot see fileless or in-memory attacks (see "Blind spots").

## What is monitored

| Surface | Detail | Cadence |
| --- | --- | --- |
| Files | Startup folders (x2), `ProgramData`, Downloads, Desktop, `AppData\Roaming`, `AppData\Local`, `Temp`, profile root; extensions exe/dll/bat/ps1/vbs/js/lnk/scr/com/sys/cpl/ocx; depth-limited | every round |
| Registry | HKCU/HKLM/Wow6432 `Run` + `RunOnce`, Winlogon `Shell`/`Userinit` | every round |
| Registry (heavy) | `StartupApproved` x3 (new entries only), IFEO `Debugger`, services `ImagePath` | every 5th round |
| Scheduled tasks | task-name diff via `schtasks /query /fo csv` | every 5th round |
| Processes | first-seen executable paths launched from Temp/Downloads/Desktop, with parent PID | every round |

New files get a SHA1 (skipped above 50 MB), an Authenticode check, and PE
`FileVersionInfo.OriginalFilename` inspection via a single batched
PowerShell call. Baseline creation does not hash or sign — only metadata —
so `--init` stays fast.

## Scoring rules

| Signal | Points |
| --- | --- |
| Unsigned / invalid signature | +3 |
| Valid signature but signer not in allowlist (suppressed for genuine un-renamed non-persistent Microsoft binaries when `system_noise_filter` is enabled) | +2 |
| Renamed signed system binary (`OriginalFilename` mismatch on a Microsoft-signed file) | +3 |
| Random-looking ASCII name (`X7K9Q2ZM`, vowel-less ASCII stem, GUID directory) | +3 |
| Masquerading runtime-library name (vcomp/msvcp/...) outside `C:\Windows` (not valid Microsoft-signed matching PE) | +4 |
| Located in Temp / Downloads / Desktop / hidden directory | +2 |
| Hidden file attribute | +1 |
| Persistence mechanism (Run key, Startup folder, service, task, IFEO) | +3 |
| Critical autostart value (Winlogon) | +2 |
| IFEO debugger primitive | +2 |

`>= 7` = **high**, `3-6` = **warn**, `< 3` = **info**. High alerts append
to `URGENT.txt` and are surfaced by the system tray agent
(`tripflare_tray.pyw`: persistent icon + coalesced balloon + right-click menu).
Fallbacks for tray-less setups: a classic PowerShell balloon
(`notify.balloon`, default on) and the deprecated desktop
`TripFlare-运行AI研判.bat` (`notify.desktop_bat`, default off).

The default signer allowlist is intentionally **empty**: a signed binary
that appears in a drop zone with a random name (a classic renamed-lolbin
move) or with a mismatched PE `OriginalFilename` (e.g. `certutil.exe`
renamed to `Invoice.exe`) must still reach the high threshold. Users
allowlist third-party signers they trust with
`tripflare.py allow "CN=Some Vendor"` or from the UI.

## System background noise filtering (`system_noise_filter`)

Enabled by default (`"system_noise_filter": true`). Targets high-volume OS
and background churn without weakening detection of real payloads or
renamed LOLBins:

- **Transient Microsoft `%TEMP%` extractions**: Valid Microsoft-signed
  files that have non-random stems, matching PE `OriginalFilename`, no
  hidden attribute, and no persistence are suppressed when extracted into
  `%TEMP%\<GUID>\*` (DISM servicing providers), `%TEMP%\_MEI*\` runtime
  DLLs, or `%TEMP%` Edge/Defender transient updaters. Unsigned or renamed
  binaries in `%TEMP%\<GUID>\` still score `>= 7` (`high`).
- **Ephemeral Temp probes**: Non-hidden PowerShell `__PSScriptPolicyTest_*`
  and `%TEMP%\<UUID>.tmp.js` files are skipped before alerting.
- **Per-user LUID services**: Session-scoped Windows services
  (`<Service>_<HEX_LUID>`) are suppressed when either their base template
  service exists with the identical `ImagePath` or the base name is a known
  Windows Unistack/user service pointing to `System32\svchost.exe` or
  `CredentialEnrollmentManager.exe`.
- **Routine browser updater churn**: Version-bumped Edge/Google Updater
  services verified inside `Program Files`, Edge `RunOnce` cleanup under
  `Program Files`, and GoogleUpdater/EdgeUpdate scheduled tasks are ignored;
  TripFlare's own scheduled tasks never alert.
- **Historical cleanup**: `tripflare.py prune-noise` (or the UI's cleanup
  button) backs up `data\alerts.jsonl` and `data\URGENT.txt` to `.bak` and
  removes historical OS background noise.

## Three AI modes

1. **recommend** (default): zero tokens unless the user clicks AI 研判未读 /
   研判选中项 in the console UI (or the tray menu / review balloon), which
   sends pending unread warn/high alerts (or explicitly selected alerts) to
   the AI backend once and produces Simplified Chinese reports.
2. **patrol**: the daemon triggers an immediate patrol on new high alerts
   (10-minute cooldown, alerts merge inside the window) and the
   `TripFlarePatrol` scheduled task triggers a routine patrol every
   `patrol_interval_minutes` (default 30). A daily circuit breaker
   (`max_calls_per_day`, default 20) caps quota burn. The patrol agent is
   read-only by prompt guardrail; auto-quarantine is off unless explicitly
   enabled.
3. **off**: local heuristics only; the AI backend is never invoked
   automatically (a manual `ai-review` remains possible).

The AI backend is any CLI that maps `-p "<prompt>"` to text on stdout
(kimi.exe by default, auto-detected).

## Performance budget

Metadata-only walking, depth limits, 20k-entry directory cut-off, batched
signature checks, heavy snapshots every 5th round. Target: average CPU
< 1%, memory < 150 MB, near-zero disk I/O in steady state. Measured numbers
are in the README.

## Blind spots

- No protection against rootkits, fileless/in-memory malware, or signed
  malware that never touches the watched surfaces.
- Process watching is path-first-seen, not behavioral.
- A baseline captured after compromise will treat the malware as normal.
- Complements, not replaces, periodic full scans (e.g. Emsisoft Emergency
  Kit) and a real AV.

## Self-protection

`pythonw.exe`/`python.exe`, the AI backend (`kimi.exe`), everything under
the install and data directories, and the helper tools TripFlare spawns each
round (`powershell`, `reg`, `schtasks`, ...) are whitelisted so TripFlare
never alerts on itself.


---

## v0.2.0 Architecture Updates

### 1. Real-Time Win32 File Watcher (`RealtimeDirectoryWatcher`)
- Uses `kernel32.CreateFileW`, `ReadDirectoryChangesW`, `CreateEventW`, and `GetOverlappedResult` via `ctypes` (zero external dependencies) across high-risk user directories:
  - Startup folders (`User` and `ProgramData`)
  - `Downloads`, `Desktop`, `%TEMP%`, and `%USERPROFILE%` root (`max_depth=1`)
- Coalesces bursty filesystem notifications over a `0.6s` debounce window before calling `scan_realtime_paths()`, applying high-frequency noise filtering (`_MEI*`, `dismhost.exe`, `.tmp.js`, Edge cache) prior to scoring (`SHA-256`, Authenticode verification, and PE `OriginalFilename` masquerade checks).
- Tray daemon alert tail (`tripflare_tray.pyw`) polls `data/alerts.jsonl` every `1500ms` (`TIMER_ALERTS`) so real-time `HIGH` alerts raise Windows toast notifications within ~2 seconds.

### 2. Universal Zero-Dependency AI Provider Engine
- Implemented purely with `urllib.request` and `json` in `tripflare.py`:
  - `ollama`: Local `http://127.0.0.1:11434/api/tags` + `/api/chat` (auto-detected when running locally; zero cloud egress).
  - `openai`: Any `/v1/chat/completions`-compatible endpoint (`OpenAI`, `DeepSeek`, `Groq`, `OpenRouter`, `LM Studio`, `vLLM`) with `Authorization: Bearer <api_key>`.
  - `cli`: Configurable local CLI subprocess (`cli_cmd` + `cli_args`, e.g., `kimi --print -p "{prompt}"`).
  - `auto` resolution precedence: configured `api_key` -> available local CLI (`cli_cmd` / `backend_path`) -> running local Ollama (`127.0.0.1:11434`).

### 3. Bilingual Auto-Detection & Portable `.exe` Distribution
- `resolve_language()` inspects `config.json` (`"auto" | "zh" | "en"`), falling back to Win32 `GetUserDefaultUILanguage()` (`0x04` primary Chinese language ID -> `"zh"`, otherwise `"en"`).
- `tripflare_ui.pyw` provides a live header toggle (`EN / 中文`) persisted to `config.json` and synchronizes AI report prompt language dynamically (`_english_lang_override` when `"en"` is active).
- `FROZEN` / `RESOURCE_DIR` path resolution enables single-folder portable PyInstaller builds (`TripFlare.exe`, `TripFlareDaemon.exe`, `TripFlareTray.exe`) alongside source-clone execution via `TripFlare.bat`.
