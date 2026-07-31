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

New files get a SHA1 (skipped above 50 MB) and an Authenticode check via a
single batched PowerShell call. Baseline creation does not hash or sign —
only metadata — so `--init` stays fast.

## Scoring rules

| Signal | Points |
| --- | --- |
| Unsigned / invalid signature | +3 |
| Valid signature but signer not in allowlist | +2 |
| Random-looking name (`^[A-Z0-9]{6,10}$`, vowel-less stem, GUID directory) | +3 |
| Masquerading runtime-library name (vcomp/msvcp/...) outside `C:\Windows` | +4 |
| Located in Temp / Downloads / Desktop / hidden directory | +2 |
| Hidden file attribute | +1 |
| Persistence mechanism (Run key, Startup folder, service, task, IFEO) | +3 |
| Critical autostart value (Winlogon) | +2 |
| IFEO debugger primitive | +2 |

`>= 7` = **high**, `3-6` = **warn**, `< 3` = **info**. High alerts append
to `URGENT.txt` and are surfaced by the system tray agent
(`tripflare_tray.pyw`: persistent icon + balloon + right-click menu).
Fallbacks for tray-less setups: a classic PowerShell balloon
(`notify.balloon`, default on) and the deprecated desktop
`TripFlare-运行AI研判.bat` (`notify.desktop_bat`, default off).

The default signer allowlist is intentionally **empty**: a signed binary
that appears in a drop zone with a random name (a classic renamed-lolbin
move) must still reach the high threshold. Users allowlist the signers
they trust with `tripflare.py allow "CN=Some Vendor"`.

## Three AI modes

1. **recommend** (default): zero tokens unless the user clicks AI 研判 in
   the console UI (or the tray menu / review balloon) after a high alert,
   which sends pending warn/high alerts to the AI backend once.
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
