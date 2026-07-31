#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TripFlare - lightweight Windows anomaly monitor with three-tier AI review.

Single file, standard library only, Python 3.8+.

Usage:
    tripflare.py --init          Build the baseline snapshot (no alerts).
    tripflare.py                 Daemon loop (scan every interval_seconds).
    tripflare.py digest          Print alerts since the last digest.
    tripflare.py ai-review       Send recent alerts to the AI backend once.
    tripflare.py allow <target>  Allowlist a path or a signer substring.
    tripflare.py status          Show configuration and runtime statistics.
    tripflare.py patrol-tick     Scheduled-task entry for AI patrol mode.
    tripflare.py --bench         Run one timed round and print stage timings.

Runtime data lives in <script dir>\\data\\ by default (state.json,
alerts.jsonl, reviews\\, URGENT.txt, tripflare.log); override with the
TRIPFLARE_DATA_DIR environment variable.
"""
from __future__ import annotations

import csv
import ctypes
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime

VERSION = "0.1.1"

# Prevent brief console windows from flashing when the windowless daemon
# (pythonw) spawns console subprocesses (reg / schtasks / powershell / AI CLI).
NO_WINDOW_KW = {"creationflags": 0x08000000} if os.name == "nt" else {}

# --------------------------------------------------------------------------
# Paths and constants
# --------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("TRIPFLARE_DATA_DIR") or os.path.join(
    SCRIPT_DIR, "data")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
ALERTS_PATH = os.path.join(DATA_DIR, "alerts.jsonl")
READ_ALERTS_PATH = os.path.join(DATA_DIR, "read_alerts.json")
URGENT_PATH = os.path.join(DATA_DIR, "URGENT.txt")
LOG_PATH = os.path.join(DATA_DIR, "tripflare.log")
REVIEWS_DIR = os.path.join(DATA_DIR, "reviews")
PROMPTS_DIR = os.path.join(SCRIPT_DIR, "prompts")

WATCH_EXTS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".lnk",
              ".scr", ".com", ".sys", ".cpl", ".ocx"}
SIGN_EXTS = {".exe", ".dll", ".sys", ".cpl", ".ocx", ".scr", ".com"}
SCRIPT_EXTS = WATCH_EXTS - SIGN_EXTS  # never Authenticode-signed in practice

# Runtime-library name prefixes often abused for masquerading.
MASQ_PREFIXES = ("vcomp", "msvcp", "msvcr", "vcruntime", "api-ms-win",
                 "ucrtbase", "mscoree", "mscor")

RANDOM_RE = re.compile(r"^[A-Z0-9]{6,10}$")
GUID_RE = re.compile(
    r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")
EXE_IN_CMD_RE = re.compile(
    r"([A-Za-z]:\\[^\"<>:|?*]+?\.(?:exe|dll|bat|ps1|vbs|js|scr|com))",
    re.IGNORECASE)

RUN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
]
STARTUP_APPROVED_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
]
WINLOGON_KEY = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO_KEY = (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            r"\Image File Execution Options")
SERVICES_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services"

# Processes that must never trigger self-alerts (TripFlare itself, its AI
# backend, and the helper tools it spawns every round).
OWN_PROCESS_NAMES = {"python.exe", "pythonw.exe", "python3.exe", "kimi.exe"}
HELPER_PROCESS_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "reg.exe", "schtasks.exe",
    "conhost.exe", "tasklist.exe", "wmic.exe", "whoami.exe", "systeminfo.exe",
    "svchost.exe", "dllhost.exe", "runtimebroker.exe", "searchindexer.exe",
    "backgroundtaskhost.exe", "sihost.exe", "applicationframehost.exe",
    "textinputhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "searchhost.exe", "searchapp.exe",
    "ctfmon.exe", "dwm.exe", "taskhostw.exe", "smartscreen.exe",
}

DEFAULT_CONFIG = {
    "interval_seconds": 60,
    "heavy_interval_rounds": 5,      # services/tasks/IFEO every N rounds
    "sha1_max_bytes": 52428800,      # skip hashing files larger than 50 MB
    "max_dir_entries": 20000,        # skip a directory with more entries
    "state_process_cap": 5000,       # bound the seen-process table
    "score_thresholds": {"warn": 3, "high": 7},
    "allowlist": {"paths": [], "signers": []},
    "exclude_dirs": [],
    "watch_dirs": None,              # None -> built-in defaults
    "ai": {
        "mode": "recommend",         # recommend | patrol | off
        "backend_path": "auto",      # "auto" -> detect kimi.exe
        "backend_args": ["-p", "{prompt}"],
        "timeout_seconds": 600,
        "max_calls_per_day": 20,
        "review_max_alerts": 20,
        "patrol_interval_minutes": 30,
        "patrol_immediate_cooldown_minutes": 10,
        "patrol": {"allow_auto_quarantine": False},
    },
    "notify": {"balloon": True, "desktop_bat": False},
}

STATE_LOCK = threading.Lock()
_alert_counter = [0]

# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def today_str():
    return datetime.now().strftime("%Y-%m-%d")


def stamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def log(msg):
    """Append one line to the log file (rotated at ~1 MB)."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 1048576:
            try:
                os.replace(LOG_PATH, LOG_PATH + ".1")
            except OSError:
                pass
        with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as fh:
            fh.write("%s %s\n" % (now_iso(), msg))
    except OSError:
        pass


def run_cmd(args, timeout=60, encoding="mbcs"):
    """Run a command, return stdout decoded (never raises)."""
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout,
                              **NO_WINDOW_KW)
        return proc.returncode, proc.stdout.decode(encoding, "replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)


def run_ps(script, timeout=120):
    """Run a PowerShell script, return (rc, stdout) decoded as UTF-8."""
    prefix = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
    return run_cmd(["powershell", "-NoProfile", "-NonInteractive",
                    "-Command", prefix + script],
                   timeout=timeout, encoding="utf-8")


def norm(path):
    return os.path.normpath(path)


def norm_lower(path):
    return norm(path).lower()


# --------------------------------------------------------------------------
# Config and state
# --------------------------------------------------------------------------

def deep_merge(base, override):
    out = dict(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def find_config_path():
    for cand in (os.path.join(SCRIPT_DIR, "config.json"),
                 os.path.join(DATA_DIR, "config.json")):
        if os.path.exists(cand):
            return cand
    default = os.path.join(SCRIPT_DIR, "config.default.json")
    if os.path.exists(default):
        return default
    return None


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    path = find_config_path()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                user_cfg = json.load(fh)
            user_cfg = {k: v for k, v in user_cfg.items()
                        if not k.startswith("_")}
            cfg = deep_merge(cfg, user_cfg)
        except (OSError, ValueError) as exc:
            log("config load failed (%s): %s" % (path, exc))
    cfg["_config_path"] = path
    return cfg


def writable_config_path(cfg):
    """Path that `allow` should persist to (never config.default.json)."""
    path = cfg.get("_config_path")
    if path and not path.endswith("config.default.json"):
        return path
    return os.path.join(SCRIPT_DIR, "config.json")


def save_config(cfg, path):
    data = {k: v for k, v in cfg.items() if not k.startswith("_")}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def empty_state():
    return {
        "version": VERSION,
        "created": now_iso(),
        "rounds": 0,
        "files": {},       # path -> [size, mtime, sha1, signer, sigstatus]
        "registry": {},    # key -> {value_name: "type|data"}
        "tasks": [],       # scheduled task names
        "services": {},    # service name -> image path
        "ifeo": {},        # subkey -> debugger command
        "processes": {},   # exe path -> first-seen ISO time
        "alerted": {},     # dedupe key -> ISO time
        "ai": {"date": today_str(), "calls_today": 0,
               "last_patrol": 0.0, "last_immediate_patrol": 0.0,
               "last_review": 0.0, "last_digest": 0.0},
        "last_round_ts": 0.0,
        "last_round_seconds": 0.0,
    }


def load_state():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        base = empty_state()
        base.update(state)
        base["ai"] = deep_merge(empty_state()["ai"], state.get("ai"))
        return base
    except (OSError, ValueError):
        return None


def save_state(state):
    with STATE_LOCK:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False)
        os.replace(tmp, STATE_PATH)


def rollover_ai_day(state):
    ai = state["ai"]
    if ai.get("date") != today_str():
        ai["date"] = today_str()
        ai["calls_today"] = 0


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

def append_alert(alert):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(ALERTS_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(alert, ensure_ascii=False) + "\n")


def read_alerts(since_epoch=0.0, levels=None, cap=None):
    alerts = []
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except ValueError:
                    continue
                if alert.get("epoch", 0) <= since_epoch:
                    continue
                if levels and alert.get("level") not in levels:
                    continue
                alerts.append(alert)
    except OSError:
        pass
    if cap:
        alerts = alerts[-cap:]
    return alerts


# --------------------------------------------------------------------------
# Read/unread tracking - read_alerts.json is the single source of truth
# shared by the CLI (digest / ai-review), the console UI and the tray.
# --------------------------------------------------------------------------

def alert_id(alert):
    """Stable id for one alert (fallback when old entries lack 'id')."""
    return str(alert.get("id") or "%s-%s-%s" % (
        alert.get("epoch"), alert.get("type"), alert.get("path")))


def load_read_ids():
    try:
        with open(READ_ALERTS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return set(str(x) for x in data.get("read", []))
    except (OSError, ValueError):
        return set()


def mark_alerts_read(ids):
    """Add ids to the read set (bounded at the newest 5000). Returns added."""
    read_list = []
    seen = set()
    try:
        with open(READ_ALERTS_PATH, "r", encoding="utf-8") as fh:
            for x in json.load(fh).get("read", []):
                x = str(x)
                if x not in seen:
                    seen.add(x)
                    read_list.append(x)
    except (OSError, ValueError):
        pass
    added = 0
    for i in ids:
        i = str(i)
        if i not in seen:
            seen.add(i)
            read_list.append(i)
            added += 1
    if added or len(read_list) > 5000:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(READ_ALERTS_PATH, "w", encoding="utf-8") as fh:
            json.dump({"read": read_list[-5000:]}, fh, ensure_ascii=False)
    return added


def unread_alerts(alerts):
    read = load_read_ids()
    return [a for a in alerts if alert_id(a) not in read]


def pending_review_alerts(cap):
    """Unread warn/high alerts awaiting AI review (newest-first capped)."""
    candidates = read_alerts(levels={"warn", "high"})
    pending = unread_alerts(candidates)
    return pending[-cap:], len(candidates)


def append_urgent(text):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(URGENT_PATH, "a", encoding="utf-8") as fh:
            fh.write(text.rstrip() + "\n\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# Notifications (all best-effort, never raise)
# --------------------------------------------------------------------------

def notify_balloon(title, message):
    """Show a Windows balloon tip via a detached PowerShell NotifyIcon."""
    try:
        title = title.replace("'", "''")
        message = message.replace("'", "''")[:240]
        ps = ("Add-Type -AssemblyName System.Windows.Forms; "
              "Add-Type -AssemblyName System.Drawing; "
              "$n = New-Object System.Windows.Forms.NotifyIcon; "
              "$n.Icon = [System.Drawing.SystemIcons]::Warning; "
              "$n.Visible = $true; "
              "$n.BalloonTipTitle = '%s'; $n.BalloonTipText = '%s'; "
              "$n.ShowBalloonTip(9000); Start-Sleep -Seconds 10; "
              "$n.Dispose()" % (title, message))
        subprocess.Popen(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden",
             "-Command", ps],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            **NO_WINDOW_KW)
    except OSError as exc:
        log("balloon notification failed silently: %s" % exc)


def console_python():
    """Resolve a console (windowed) python.exe for the desktop .bat."""
    exe = sys.executable or ""
    base = os.path.basename(exe).lower()
    if base == "pythonw.exe":
        cand = os.path.join(os.path.dirname(exe), "python.exe")
        if os.path.exists(cand):
            return cand
    if base.startswith("python"):
        return exe
    return shutil.which("python.exe") or "python.exe"


def windowless_python():
    """Resolve pythonw.exe for launching the UI without a console."""
    exe = sys.executable or ""
    base = os.path.basename(exe).lower()
    if base == "pythonw.exe":
        return exe
    if base.startswith("python"):
        cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(cand):
            return cand
    return shutil.which("pythonw.exe") or exe


def write_desktop_bat():
    """(Re)create the one-click launcher that opens the UI alerts page."""
    bat_path = desktop_bat_path()
    ui_script = os.path.join(SCRIPT_DIR, "tripflare_ui.pyw")
    content = (
        "chcp 65001 >nul\r\n"
        "@echo off\r\n"
        "start \"\" \"%s\" \"%s\" --alerts\r\n"
    ) % (windowless_python(), ui_script)
    try:
        with open(bat_path, "w", encoding="ascii", errors="replace",
                  newline="") as fh:
            fh.write(content)
        return bat_path
    except OSError as exc:
        log("desktop bat write failed: %s" % exc)
        return None

# --------------------------------------------------------------------------
# Watch surface definitions
# --------------------------------------------------------------------------

def long_path(path):
    """Expand 8.3 short names (e.g. ADMINI~1) so path dedupe is stable."""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.GetLongPathNameW(str(path), buf, 1024)
        if 0 < n < 1024:
            return buf.value
    except (OSError, AttributeError, ValueError):
        pass
    return path


def default_watch_dirs():
    """[(path, depth)] monitored file locations."""
    up = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", os.path.join(up, "AppData", "Roaming"))
    local = os.environ.get("LOCALAPPDATA", os.path.join(up, "AppData", "Local"))
    pdata = os.environ.get("ProgramData", r"C:\ProgramData")
    temp = os.environ.get("TEMP", os.path.join(local, "Temp"))
    return [
        [long_path(os.path.join(appdata, "Microsoft", "Windows",
                                "Start Menu", "Programs", "Startup")), 2],
        [long_path(os.path.join(pdata, "Microsoft", "Windows",
                                "Start Menu", "Programs", "StartUp")), 2],
        [long_path(pdata), 2],
        [long_path(os.path.join(up, "Downloads")), 3],
        [long_path(os.path.join(up, "Desktop")), 3],
        [long_path(appdata), 2],
        [long_path(local), 2],
        [long_path(temp), 1],
        [long_path(up), 1],
    ]


def get_watch_dirs(cfg):
    raw = cfg.get("watch_dirs") or default_watch_dirs()
    out = []
    for item in raw:
        path, depth = item[0], int(item[1])
        out.append((norm(long_path(os.path.expandvars(path))), depth))
    return out


def startup_dirs():
    dirs = []
    for path, _depth in default_watch_dirs()[:2]:
        dirs.append(norm_lower(path))
    return dirs


def risky_roots():
    """High-risk drop zones: Temp / Downloads / Desktop."""
    up = os.path.expanduser("~")
    local = os.environ.get("LOCALAPPDATA", os.path.join(up, "AppData", "Local"))
    temp = os.environ.get("TEMP", os.path.join(local, "Temp"))
    roots = [temp, os.path.join(up, "Downloads"), os.path.join(up, "Desktop")]
    return [norm_lower(long_path(r)) + os.sep for r in roots]


def get_exclusions(cfg):
    excl = [norm_lower(DATA_DIR)]
    for item in cfg.get("exclude_dirs") or []:
        excl.append(norm_lower(os.path.expandvars(item)))
    return excl


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def name_location_score(path):
    """Score a path by name and location heuristics.

    Returns (score, reasons). Name-based hits are a single rule group
    capped at +3 total (random name / GUID dir / vowel-less stem).
    """
    score = 0
    reasons = []
    stem = os.path.splitext(os.path.basename(path))[0]
    name_hits = []
    if RANDOM_RE.match(stem):
        name_hits.append("random-looking name '%s'" % stem)
    elif len(stem) >= 6 and stem.isalpha() and not re.search(
            r"[aeiouAEIOU]", stem):
        name_hits.append("vowel-less random-looking name '%s'" % stem)
    for comp in norm(path).split(os.sep):
        if GUID_RE.fullmatch(comp):
            name_hits.append("inside GUID-named directory '%s'" % comp)
            break
    if name_hits:
        score += 3
        reasons.append("; ".join(name_hits) + " (+3)")
    base = os.path.basename(path).lower()
    if (any(base.startswith(p) for p in MASQ_PREFIXES)
            and not norm_lower(path).startswith("c:" + os.sep + "windows")):
        score += 4
        reasons.append("masquerades as a runtime library name outside "
                       "the Windows directory (+4)")
    low = norm_lower(path)
    if any(low.startswith(r) for r in risky_roots()):
        score += 2
        reasons.append("located in a high-risk drop zone "
                       "(Temp/Downloads/Desktop) (+2)")
    elif hidden_dir_component(path):
        score += 2
        reasons.append("located inside a hidden directory (+2)")
    return score, reasons


def signature_score(sig_status, signer, cfg):
    """Score Authenticode results: +3 unsigned/invalid, +2 unknown signer."""
    score = 0
    reasons = []
    if sig_status is None:
        return score, reasons  # not a signable file type
    if sig_status != "Valid":
        score += 3
        reasons.append("unsigned or invalid signature (%s) (+3)" % sig_status)
        return score, reasons
    allowed = [s.lower() for s in cfg["allowlist"].get("signers", [])]
    signer_l = (signer or "").lower()
    if not signer_l or not any(a in signer_l for a in allowed):
        score += 2
        reasons.append("signer not in allowlist ('%s') (+2)"
                       % (signer or "unknown"))
    return score, reasons


def level_for_score(score, cfg):
    th = cfg.get("score_thresholds", {})
    if score >= th.get("high", 7):
        return "high"
    if score >= th.get("warn", 3):
        return "warn"
    return "info"


def is_allowed_path(path, cfg):
    low = norm_lower(path)
    for entry in cfg["allowlist"].get("paths", []):
        e = norm_lower(os.path.expandvars(entry))
        if low == e or low.startswith(e.rstrip(os.sep) + os.sep):
            return True
        if os.sep not in e and os.path.basename(low) == e:
            return True
    return False


def get_attrs(path):
    try:
        return ctypes.windll.kernel32.GetFileAttributesW(str(path))
    except (OSError, AttributeError, ValueError):
        return -1


def is_hidden_file(path):
    attrs = get_attrs(path)
    return attrs not in (-1, 0xFFFFFFFF) and bool(attrs & 0x2)


def hidden_dir_component(path):
    parent = os.path.dirname(norm(path))
    attrs = get_attrs(parent)
    return attrs not in (-1, 0xFFFFFFFF) and bool(attrs & 0x2)


def is_reparse_point(path):
    """True for junctions/symlinks (FILE_ATTRIBUTE_REPARSE_POINT)."""
    attrs = get_attrs(path)
    return attrs not in (-1, 0xFFFFFFFF) and bool(attrs & 0x400)


def desktop_bat_path():
    return norm(os.path.join(os.path.expanduser("~"), "Desktop",
                             "TripFlare-运行AI研判.bat"))


def OWN_FILES():
    """Artifacts TripFlare creates itself; never alert on them."""
    return {desktop_bat_path()}


def sha1_of(path, max_bytes):
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        digest = hashlib.sha1()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1048576), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


# --------------------------------------------------------------------------
# Signature verification (batched PowerShell, only for new files)
# --------------------------------------------------------------------------

def batch_sign(paths, timeout=300):
    """Return {path: (status, signer)} using one PowerShell process."""
    result = {}
    if not paths:
        return result
    os.makedirs(DATA_DIR, exist_ok=True)
    list_file = os.path.join(DATA_DIR, "sig_paths.txt")
    with open(list_file, "w", encoding="utf-8") as fh:
        for p in paths:
            fh.write(p + "\n")
    ps_list = list_file.replace("'", "''")
    script = (
        "$paths = Get-Content -LiteralPath '%s' -Encoding UTF8\n"
        "foreach ($p in $paths) {\n"
        "  if (-not $p) { continue }\n"
        "  try {\n"
        "    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop\n"
        "    $signer = ''\n"
        "    if ($s.SignerCertificate) {"
        " $signer = $s.SignerCertificate.Subject }\n"
        "    Write-Output ($p + \"`t\" + $s.Status.ToString()"
        " + \"`t\" + $signer)\n"
        "  } catch {\n"
        "    Write-Output ($p + \"`tError`t\")\n"
        "  }\n"
        "}\n" % ps_list)
    rc, out = run_ps(script, timeout=timeout)
    if rc == -1:
        log("signature batch failed: %s" % out[:300])
        return result
    for line in out.splitlines():
        parts = line.rstrip("\r").split("\t")
        if len(parts) >= 3 and parts[0] in paths:
            result[parts[0]] = (parts[1].strip(), parts[2].strip())
    try:
        os.remove(list_file)
    except OSError:
        pass
    return result


# --------------------------------------------------------------------------
# Scanners - each appends raw events; scoring happens afterwards
# --------------------------------------------------------------------------

def walk_limited(root, max_depth, max_entries, exclusions):
    """Yield (path, size, mtime) for watched files under root."""
    root = norm(root)
    if not os.path.isdir(root):
        return
    base_depth = root.rstrip("\\/").count(os.sep)

    def onerror(_err):
        return None

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
        low_dir = norm_lower(dirpath)
        if any(low_dir == e or low_dir.startswith(e + os.sep)
               for e in exclusions):
            dirnames[:] = []
            continue
        depth = dirpath.count(os.sep) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        # Skip reparse points (junctions such as "Application Data") and
        # symlinks to avoid duplicate walk paths, loops and huge trees.
        dirnames[:] = [d for d in dirnames
                       if not is_reparse_point(os.path.join(dirpath, d))]
        if len(dirnames) + len(filenames) > max_entries:
            dirnames[:] = []
            continue
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in WATCH_EXTS:
                continue
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            yield full, st.st_size, st.st_mtime


def scan_files(state, cfg, events):
    """Diff the watched directories against state['files']."""
    exclusions = get_exclusions(cfg)
    max_entries = int(cfg.get("max_dir_entries", 20000))
    current = {}
    for root, depth in get_watch_dirs(cfg):
        for path, size, mtime in walk_limited(root, depth, max_entries,
                                              exclusions):
            current[path] = (size, mtime)
    old = state.get("files", {})
    for path, (size, mtime) in current.items():
        prev = old.get(path)
        if prev is None:
            kind = "file_new"
        elif list(prev[:2]) != [size, mtime]:
            kind = "file_modified"
        else:
            continue
        if is_allowed_path(path, cfg) or path in OWN_FILES():
            continue
        ext = os.path.splitext(path)[1].lower()
        ev = {
            "type": kind,
            "path": path,
            "persistence": norm_lower(os.path.dirname(path)) in startup_dirs(),
            "needs_sig": ext in SIGN_EXTS,
            "sha1": sha1_of(path, int(cfg.get("sha1_max_bytes", 52428800))),
            "hidden": is_hidden_file(path),
            "extra": {"size": size},
        }
        events.append(ev)
    # Preserve hash/signer metadata for unchanged files; reset for changed.
    new_files = {}
    for path, (size, mtime) in current.items():
        prev = old.get(path)
        if prev is not None and list(prev[:2]) == [size, mtime]:
            new_files[path] = prev
        else:
            new_files[path] = [size, mtime, None, None, None]
    state["files"] = new_files


def reg_query_values(key):
    """Return {value_name: "type|data"} for one registry key."""
    rc, out = run_cmd(["reg", "query", key], timeout=60)
    values = {}
    if rc != 0:
        return None
    for line in out.splitlines():
        m = re.match(r"^\s{4}(\S(?:.*?\S)?)\s{2,}(REG_\w+)\s{2,}(.*)$", line)
        if m:
            values[m.group(1)] = "%s|%s" % (m.group(2), m.group(3).strip())
    return values


def score_registry_target(data):
    """Extra score for the command/exe referenced by a registry value."""
    score = 0
    reasons = []
    m = EXE_IN_CMD_RE.search(data or "")
    target = m.group(1) if m else (data or "")
    if target:
        s, r = name_location_score(target)
        score += s
        reasons.extend(r)
    return score, reasons, target


def scan_registry_light(state, cfg, events):
    """Run/RunOnce keys (new or changed values) and Winlogon values."""
    reg_state = state.setdefault("registry", {})
    for key in RUN_KEYS:
        values = reg_query_values(key)
        if values is None:
            continue
        prev = reg_state.get(key, {})
        for name, typed in values.items():
            data = typed.split("|", 1)[1] if "|" in typed else ""
            if name not in prev:
                kind = "registry_new"
            elif prev[name] != typed and "StartupApproved" not in key:
                kind = "registry_changed"
            else:
                continue
            if is_allowed_path(data, cfg):
                continue
            events.append({
                "type": kind,
                "path": "%s\\%s" % (key, name),
                "persistence": True,
                "needs_sig": False,
                "sha1": None,
                "hidden": False,
                "extra": {"data": data, "key": key, "value": name},
            })
        reg_state[key] = values
    # Winlogon Shell/Userinit are critical autostart values.
    values = reg_query_values(WINLOGON_KEY)
    if values is not None:
        prev = reg_state.get(WINLOGON_KEY, {})
        for name in ("Shell", "Userinit"):
            if name in values and prev.get(name) not in (None, values[name]):
                events.append({
                    "type": "registry_changed",
                    "path": "%s\\%s" % (WINLOGON_KEY, name),
                    "persistence": True,
                    "needs_sig": False,
                    "sha1": None,
                    "hidden": False,
                    "extra": {"data": values[name], "key": WINLOGON_KEY,
                              "value": name, "critical": True},
                })
        reg_state[WINLOGON_KEY] = values


def scan_startup_approved(state, cfg, events):
    """Only brand-new StartupApproved entries are alerted (data churns)."""
    reg_state = state.setdefault("registry", {})
    for key in STARTUP_APPROVED_KEYS:
        values = reg_query_values(key)
        if values is None:
            continue
        prev = reg_state.get(key, {})
        for name in values:
            if name not in prev:
                events.append({
                    "type": "registry_new",
                    "path": "%s\\%s" % (key, name),
                    "persistence": True,
                    "needs_sig": False,
                    "sha1": None,
                    "hidden": False,
                    "extra": {"data": "", "key": key, "value": name},
                })
        reg_state[key] = values


def scan_tasks(state, cfg, events):
    """Diff scheduled task names (schtasks CSV, first column)."""
    rc, out = run_cmd(["schtasks", "/query", "/fo", "csv"], timeout=120)
    if rc != 0:
        log("schtasks query failed: %s" % out[:200])
        return
    names = set()
    try:
        reader = csv.reader(io.StringIO(out))
        for row in reader:
            if row and row[0].startswith("\\"):
                names.add(row[0])
    except csv.Error:
        return
    prev = set(state.get("tasks", []))
    for name in sorted(names - prev):
        events.append({
            "type": "task_new",
            "path": "schtasks:%s" % name,
            "persistence": True,
            "needs_sig": False,
            "sha1": None,
            "hidden": False,
            "extra": {"task": name},
        })
    state["tasks"] = sorted(names)


def scan_services(state, cfg, events):
    """Diff service ImagePath values (heavy round)."""
    rc, out = run_cmd(["reg", "query", SERVICES_KEY, "/s", "/v", "ImagePath"],
                      timeout=180)
    if rc != 0:
        return
    current = {}
    cur_key = None
    prefix = SERVICES_KEY.upper() + "\\"
    for line in out.splitlines():
        if line.upper().startswith("HKEY"):
            cur_key = line.strip()
        elif cur_key:
            m = re.match(r"^\s{4}(ImagePath)\s{2,}(REG_\w+)\s{2,}(.*)$", line)
            if m:
                name = cur_key.upper().replace(prefix, "")
                current[name] = m.group(3).strip()
    prev = state.get("services", {})
    for name, image in current.items():
        if name not in prev:
            kind, changed = "service_new", False
        elif prev[name] != image:
            kind, changed = "service_changed", True
        else:
            continue
        m = EXE_IN_CMD_RE.search(image)
        if m and is_allowed_path(m.group(1), cfg):
            continue
        events.append({
            "type": kind,
            "path": "service:%s" % name,
            "persistence": True,
            "needs_sig": False,
            "sha1": None,
            "hidden": False,
            "extra": {"service": name, "image": image, "changed": changed},
        })
    state["services"] = current


def scan_ifeo(state, cfg, events):
    """Detect IFEO Debugger hijack entries (heavy round)."""
    rc, out = run_cmd(["reg", "query", IFEO_KEY, "/s", "/v", "Debugger"],
                      timeout=120)
    current = {}
    if rc == 0:
        cur_key = None
        prefix = IFEO_KEY.upper() + "\\"
        for line in out.splitlines():
            if line.upper().startswith("HKEY"):
                cur_key = line.strip()
            elif cur_key:
                m = re.match(r"^\s{4}(Debugger)\s{2,}(REG_\w+)\s{2,}(.*)$",
                             line)
                if m:
                    name = cur_key.upper().replace(prefix, "")
                    current[name] = m.group(3).strip()
    prev = state.get("ifeo", {})
    for name, debugger in current.items():
        if prev.get(name) == debugger:
            continue
        events.append({
            "type": "ifeo_debugger",
            "path": "ifeo:%s" % name,
            "persistence": True,
            "needs_sig": False,
            "sha1": None,
            "hidden": False,
            "extra": {"ifeo": name, "debugger": debugger},
        })
    state["ifeo"] = current


def snapshot_processes():
    """Return {exe_path: (pid, ppid, name)} for processes with a path."""
    script = (
        "Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,"
        "Name,ExecutablePath | ForEach-Object { "
        "$ep = ''; if ($_.ExecutablePath) { $ep = $_.ExecutablePath }; "
        "Write-Output ($_.ProcessId.ToString() + \"`t\" + "
        "$_.ParentProcessId.ToString() + \"`t\" + $_.Name + \"`t\" + $ep) }")
    rc, out = run_ps(script, timeout=120)
    procs = {}
    if rc == -1:
        log("process snapshot failed: %s" % out[:300])
        return procs
    for line in out.splitlines():
        parts = line.rstrip("\r").split("\t")
        if len(parts) >= 4 and parts[3]:
            procs[norm(parts[3])] = (parts[0], parts[1], parts[2])
    return procs


def is_own_process(path, name):
    """Built-in whitelist: TripFlare itself, its interpreters and AI backend."""
    low = norm_lower(path)
    base = (name or os.path.basename(path)).lower()
    if base in OWN_PROCESS_NAMES:
        return True
    if low.startswith(norm_lower(SCRIPT_DIR) + os.sep):
        return True
    if low.startswith(norm_lower(DATA_DIR) + os.sep):
        return True
    return False


def scan_processes(state, cfg, events):
    """Alert once per executable path launched from a high-risk location."""
    procs = snapshot_processes()
    seen = state.setdefault("processes", {})
    risky = risky_roots()
    new_paths = []
    for path, (pid, ppid, name) in procs.items():
        if path in seen:
            continue
        seen[path] = now_iso()
        low = norm_lower(path)
        if is_own_process(path, name):
            continue
        if (name or "").lower() in HELPER_PROCESS_NAMES:
            continue
        if is_allowed_path(path, cfg):
            continue
        if not any(low.startswith(r) for r in risky):
            continue  # only risky launch locations are scored
        new_paths.append(path)
        events.append({
            "type": "process_new",
            "path": path,
            "persistence": False,
            "needs_sig": os.path.splitext(path)[1].lower() in SIGN_EXTS,
            "sha1": None,
            "hidden": False,
            "extra": {"pid": pid, "ppid": ppid, "name": name},
        })
    # Bound the seen-process table.
    if len(seen) > int(cfg.get("state_process_cap", 5000)):
        items = sorted(seen.items(), key=lambda kv: kv[1])
        state["processes"] = dict(items[-2500:])


# --------------------------------------------------------------------------
# Event scoring and alert handling
# --------------------------------------------------------------------------

def finalize_scores(events, cfg):
    """Batch-verify signatures, then compute the final score per event."""
    pending = [e["path"] for e in events
               if e.get("needs_sig") and os.path.exists(e["path"])]
    signatures = batch_sign(sorted(set(pending))) if pending else {}
    for ev in events:
        score = 0
        reasons = []
        s, r = name_location_score(ev["path"])
        score += s
        reasons.extend(r)
        sig_status = signer = None
        if ev.get("needs_sig"):
            sig_status, signer = signatures.get(ev["path"], (None, None))
            s, r = signature_score(sig_status, signer, cfg)
            score += s
            reasons.extend(r)
        if ev.get("persistence"):
            score += 3
            reasons.append("creates or modifies a persistence mechanism (+3)")
        if ev.get("hidden"):
            score += 1
            reasons.append("hidden file attribute (+1)")
        data = (ev.get("extra") or {}).get("data") or \
            (ev.get("extra") or {}).get("image") or \
            (ev.get("extra") or {}).get("debugger")
        if data and ev["type"].startswith(("registry", "service", "ifeo")):
            s, r, target = score_registry_target(data)
            score += s
            reasons.extend(r)
            ev.setdefault("extra", {})["target"] = target
        if (ev.get("extra") or {}).get("critical"):
            score += 2
            reasons.append("critical autostart value (Winlogon) (+2)")
        if ev["type"] == "ifeo_debugger":
            score += 2
            reasons.append("IFEO debugger hijack primitive (+2)")
        ev["score"] = score
        ev["reasons"] = reasons
        ev["sig_status"] = sig_status
        ev["signer"] = signer


def handle_events(events, state, cfg):
    """Dedupe, persist alerts and fire high-severity actions."""
    alerted = state.setdefault("alerted", {})
    new_high = False
    for ev in events:
        if ev.get("score") is None:
            continue
        dedupe = alert_key(ev)
        if dedupe in alerted:
            continue
        alerted[dedupe] = now_iso()
        ev["level"] = level_for_score(ev["score"], cfg)
        ev["epoch"] = time.time()
        ev["ts"] = now_iso()
        _alert_counter[0] += 1
        ev["id"] = "%d-%d" % (int(ev["epoch"]), _alert_counter[0])
        append_alert(ev)
        log("alert %s score=%d %s %s" % (ev["level"], ev["score"],
                                         ev["type"], ev["path"]))
        if ev["level"] == "high":
            new_high = True
            escalate_high(ev, cfg)
    # Prune dedupe memory older than 30 days.
    if len(alerted) > 20000:
        cutoff = time.time() - 30 * 86400
        for key in list(alerted):
            try:
                when = datetime.fromisoformat(alerted[key]).timestamp()
            except ValueError:
                when = 0
            if when < cutoff:
                del alerted[key]
    return new_high


def alert_key(ev):
    extra = ev.get("extra") or {}
    if ev["type"].startswith("registry"):
        return "%s|%s|%s" % (ev["type"], ev["path"], extra.get("data", ""))
    if ev["type"].startswith("file"):
        return "%s|%s|%s" % (ev["type"], ev["path"],
                             extra.get("size", ""))
    return "%s|%s" % (ev["type"], ev["path"])


def escalate_high(ev, cfg):
    """High-severity actions: URGENT.txt plus optional fallbacks.

    The system tray agent owns user notification by default. The classic
    PowerShell balloon and the deprecated desktop .bat only fire when
    explicitly enabled in config (notify.balloon / notify.desktop_bat).
    """
    lines = [
        "================ %s HIGH score=%d ================" % (
            now_iso(), ev["score"]),
        "[%s] %s" % (ev["type"], ev["path"]),
    ]
    for reason in ev.get("reasons", []):
        lines.append("  - " + reason)
    if ev.get("sha1"):
        lines.append("  sha1: " + ev["sha1"])
    if ev.get("signer"):
        lines.append("  signer: " + ev["signer"])
    append_urgent("\n".join(lines))
    mode = cfg["ai"].get("mode", "recommend")
    if cfg.get("notify", {}).get("balloon", True):
        notify_balloon("TripFlare high alert",
                       "%s (%s) score=%d" % (os.path.basename(ev["path"]),
                                             ev["type"], ev["score"]))
    if mode != "patrol" and cfg.get("notify", {}).get("desktop_bat", False):
        write_desktop_bat()

# --------------------------------------------------------------------------
# AI backend (three modes: recommend / patrol / off)
# --------------------------------------------------------------------------

def detect_backend():
    """Locate a CLI backend that maps '-p <prompt>' to text on stdout."""
    env = os.environ.get("TRIPFLARE_AI_BACKEND")
    if env and os.path.exists(env):
        return env
    candidates = [
        os.path.join(os.path.expanduser("~"), ".kimi-code", "bin", "kimi.exe"),
        shutil.which("kimi.exe") or "",
        shutil.which("kimi") or "",
    ]
    for cand in candidates:
        if cand and os.path.exists(cand):
            return cand
    return None


def call_ai(cfg, prompt):
    """Invoke the AI backend once. Returns (text, error)."""
    ai = cfg.get("ai", {})
    backend = ai.get("backend_path") or "auto"
    if backend == "auto":
        backend = detect_backend()
    if not backend:
        return None, "no AI backend found (set ai.backend_path in config)"
    args = [backend] + [a.replace("{prompt}", prompt)
                        for a in ai.get("backend_args", ["-p", "{prompt}"])]
    try:
        proc = subprocess.run(args, capture_output=True,
                              timeout=int(ai.get("timeout_seconds", 600)),
                              **NO_WINDOW_KW)
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        if proc.returncode != 0:
            return None, "backend exited %d: %s" % (
                proc.returncode, (err or out)[:500])
        return out.strip(), None
    except subprocess.TimeoutExpired:
        return None, "backend timed out"
    except OSError as exc:
        return None, "backend launch failed: %s" % exc


def load_prompt(name):
    try:
        with open(os.path.join(PROMPTS_DIR, name), "r",
                  encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return "You are a Windows security analyst. Review the alerts below."


def build_review_prompt(alerts):
    body = json.dumps(alerts, ensure_ascii=False, indent=1)
    return ("%s\n\n## Alerts to review (JSON)\n\n```json\n%s\n```\n"
            % (load_prompt("review_prompt.md"), body))


def build_patrol_prompt(cfg, alerts, state):
    ai = cfg.get("ai", {})
    quarantine = ai.get("patrol", {}).get("allow_auto_quarantine", False)
    body = json.dumps(alerts, ensure_ascii=False, indent=1)
    context = [
        "",
        "## Runtime context",
        "",
        "- Host: Windows 11, user %s" % os.environ.get("USERNAME", "?"),
        "- Auto-quarantine allowed by config: %s" % (
            "YES (see guardrails)" if quarantine else "NO - read-only"),
        "- Data directory: %s" % DATA_DIR,
        "- Baseline entries: %d files, %d registry keys, %d tasks, "
        "%d services" % (len(state.get("files", {})),
                         len(state.get("registry", {})),
                         len(state.get("tasks", [])),
                         len(state.get("services", {}))),
        "",
        "## Pending alerts (JSON)",
        "",
        "```json",
        body,
        "```",
    ]
    return load_prompt("patrol_prompt.md") + "\n".join(context) + "\n"


HIGH_VERDICT_RE = re.compile(
    r"(?im)^\s*[-*>\s]*\**\s*verdict\s*\**\s*[:：]\s*\**\s*(high|critical)\b"
    r"|高危")


def report_has_high(report):
    return bool(report and HIGH_VERDICT_RE.search(report))


def save_review(prefix, content):
    os.makedirs(REVIEWS_DIR, exist_ok=True)
    path = os.path.join(REVIEWS_DIR, "%s-%s.md" % (prefix, stamp()))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def patrol_tick(cfg, trigger="scheduled", state=None):
    """Run one AI patrol if mode/cooldown/interval/daily-cap allow it.

    Returns (ran, reason).
    """
    ai = cfg.get("ai", {})
    if ai.get("mode", "recommend") != "patrol":
        return False, "ai.mode is '%s' (patrol-tick only works in patrol mode)" \
            % ai.get("mode", "recommend")
    own_state = state is None
    st = state or load_state()
    if st is None:
        return False, "no baseline state (run --init first)"
    rollover_ai_day(st)
    now = time.time()
    if st["ai"].get("calls_today", 0) >= int(ai.get("max_calls_per_day", 20)):
        return False, "daily AI call cap reached (%d)" % ai.get(
            "max_calls_per_day", 20)
    if trigger == "immediate":
        cooldown = float(ai.get("patrol_immediate_cooldown_minutes", 10)) * 60
        if now - st["ai"].get("last_immediate_patrol", 0) < cooldown:
            return False, "immediate patrol in cooldown"
    else:
        interval = float(ai.get("patrol_interval_minutes", 30)) * 60
        if now - st["ai"].get("last_patrol", 0) < interval:
            return False, "scheduled patrol interval not reached"
    since = max(st["ai"].get("last_patrol", 0),
                st["ai"].get("last_immediate_patrol", 0))
    if since == 0:
        since = now - 86400
    alerts = read_alerts(since_epoch=since, levels={"warn", "high"}, cap=10)
    prompt = build_patrol_prompt(cfg, alerts, st)
    report, err = call_ai(cfg, prompt)
    if err:
        log("patrol AI call failed: %s" % err)
        return False, "AI call failed: %s" % err
    header = ("# TripFlare patrol report (%s trigger)\n\n- time: %s\n"
              "- alerts supplied: %d\n\n" % (trigger, now_iso(), len(alerts)))
    path = save_review("patrol", header + report + "\n")
    st["ai"]["calls_today"] = st["ai"].get("calls_today", 0) + 1
    st["ai"]["last_patrol"] = now
    if trigger == "immediate":
        st["ai"]["last_immediate_patrol"] = now
    if own_state:
        save_state(st)
    log("patrol ran (%s), report: %s" % (trigger, path))
    if report_has_high(report):
        append_urgent("================ %s PATROL HIGH ================\n"
                      "AI patrol found a HIGH risk verdict.\n"
                      "Report: %s\n\n%s" % (now_iso(), path, report[:2000]))
        if cfg.get("notify", {}).get("balloon", True):
            notify_balloon("TripFlare patrol", "AI patrol verdict: HIGH risk. "
                           "See reviews\\ and URGENT.txt")
    return True, "patrol completed, report: %s" % path


def _immediate_patrol_async(cfg):
    try:
        patrol_tick(cfg, trigger="immediate")
    except Exception:
        log("immediate patrol crashed:\n%s" % traceback.format_exc())


# --------------------------------------------------------------------------
# Scan round
# --------------------------------------------------------------------------

def run_round(state, cfg, heavy=False, timings=None):
    """Execute one scan round: snapshot -> diff -> score -> alert."""
    t0 = time.perf_counter()

    def mark(name, start):
        if timings is not None:
            timings[name] = time.perf_counter() - start
        return time.perf_counter()

    events = []
    scan_files(state, cfg, events)
    t = mark("files", t0)
    scan_registry_light(state, cfg, events)
    t = mark("registry", t)
    if heavy:
        scan_startup_approved(state, cfg, events)
        t = mark("startup_approved", t)
        scan_tasks(state, cfg, events)
        t = mark("tasks", t)
        scan_services(state, cfg, events)
        t = mark("services", t)
        scan_ifeo(state, cfg, events)
        t = mark("ifeo", t)
    scan_processes(state, cfg, events)
    t = mark("processes", t)
    finalize_scores(events, cfg)
    t = mark("score", t)
    new_high = handle_events(events, state, cfg)
    mark("alerts", t)
    state["rounds"] = state.get("rounds", 0) + 1
    state["last_round_ts"] = time.time()
    state["last_round_seconds"] = time.perf_counter() - t0
    if timings is not None:
        timings["total"] = state["last_round_seconds"]
    if new_high and cfg.get("ai", {}).get("mode") == "patrol":
        threading.Thread(target=_immediate_patrol_async, args=(cfg,),
                         daemon=True, name="tripflare-patrol").start()
    return events


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_init(cfg):
    """Build the baseline snapshot without raising alerts."""
    os.makedirs(REVIEWS_DIR, exist_ok=True)
    state = empty_state()
    # Baseline records metadata only; sha1/signature are computed for
    # post-baseline changes, keeping --init fast (documented behavior).
    dummy_events = []
    scan_files(state, cfg, dummy_events)
    state["files"] = {p: [v[0], v[1], None, None, None]
                      for p, v in state["files"].items()}
    scan_registry_light(state, cfg, dummy_events)
    scan_startup_approved(state, cfg, dummy_events)
    scan_tasks(state, cfg, dummy_events)
    scan_services(state, cfg, dummy_events)
    scan_ifeo(state, cfg, dummy_events)
    for path in snapshot_processes():
        state["processes"][path] = now_iso()
    # Anything seen at baseline must never alert later.
    state["alerted"] = {}
    save_state(state)
    cfg_path = writable_config_path(cfg)
    if not os.path.exists(cfg_path):
        try:
            save_config(cfg, cfg_path)
        except OSError as exc:
            log("config seed write failed: %s" % exc)
    print("TripFlare baseline created.")
    print("  data dir : %s" % DATA_DIR)
    print("  config   : %s" % cfg_path)
    print("  files    : %d watched executables/scripts" % len(state["files"]))
    print("  registry : %d keys snapshotted" % len(state["registry"]))
    print("  tasks    : %d scheduled tasks" % len(state["tasks"]))
    print("  services : %d services" % len(state["services"]))
    print("  processes: %d process paths recorded" % len(state["processes"]))
    print("  ai.mode  : %s" % cfg["ai"].get("mode"))
    return 0


def cmd_daemon(cfg):
    """Scan forever every interval_seconds (heavy items every N rounds)."""
    state = load_state()
    if state is None:
        log("no baseline found, running implicit --init")
        cmd_init(cfg)
        state = load_state()
    interval = max(10, int(cfg.get("interval_seconds", 60)))
    heavy_every = max(1, int(cfg.get("heavy_interval_rounds", 5)))
    log("daemon started (interval=%ds, heavy every %d rounds, ai.mode=%s)"
        % (interval, heavy_every, cfg["ai"].get("mode")))
    print("TripFlare daemon running. interval=%ds, data=%s" % (interval, DATA_DIR))
    print("Press Ctrl+C to stop.")
    try:
        while True:
            state = load_state() or state
            heavy = (state.get("rounds", 0) % heavy_every == 0)
            try:
                run_round(state, cfg, heavy=heavy)
                save_state(state)
            except Exception:
                log("round failed:\n%s" % traceback.format_exc())
            time.sleep(interval)
    except KeyboardInterrupt:
        log("daemon stopped by user")
        print("\nTripFlare daemon stopped.")
        return 0


def cmd_digest(cfg):
    """Print unread alerts and mark them read (read_alerts.json)."""
    state = load_state()
    if state is None:
        print("No baseline yet. Run: tripflare.py --init")
        return 1
    alerts = unread_alerts(read_alerts())
    if not alerts:
        print("No unread alerts.")
        return 0
    order = {"high": 0, "warn": 1, "info": 2}
    alerts.sort(key=lambda a: (order.get(a.get("level"), 3),
                               a.get("epoch", 0)))
    counts = {"high": 0, "warn": 0, "info": 0}
    print("TripFlare digest - %d unread alert(s)\n" % len(alerts))
    for a in alerts:
        counts[a.get("level", "info")] = counts.get(a.get("level", "info"), 0) + 1
        print("[%s] score=%s %s %s" % (a.get("level", "?").upper(),
                                       a.get("score", "?"), a.get("ts", ""),
                                       a.get("path", "")))
        for reason in a.get("reasons", []):
            print("    - " + reason)
    print("\nTotals: high=%d warn=%d info=%d"
          % (counts["high"], counts["warn"], counts["info"]))
    mark_alerts_read([alert_id(a) for a in alerts])
    state["ai"]["last_digest"] = time.time()  # telemetry only
    save_state(state)
    return 0


def cmd_ai_review(cfg, max_alerts=None):
    """One-shot AI review of unread warn/high alerts (user-invoked)."""
    state = load_state()
    if state is None:
        print("No baseline yet. Run: tripflare.py --init")
        return 1
    cap = max_alerts or int(cfg["ai"].get("review_max_alerts", 20))
    alerts, total = pending_review_alerts(cap)
    if not alerts:
        print("No pending alerts to review (%d warn/high alert(s) in "
              "history, all reviewed)." % total)
        return 0
    print("Sending %d alert(s) to the AI backend...\n" % len(alerts))
    report, err = call_ai(cfg, build_review_prompt(alerts))
    if err:
        print("AI review failed: %s" % err)
        return 1
    header = ("# TripFlare AI review\n\n- time: %s\n- alerts supplied: %d\n\n"
              % (now_iso(), len(alerts)))
    path = save_review("review", header + report + "\n")
    mark_alerts_read([alert_id(a) for a in alerts])
    state["ai"]["last_review"] = time.time()
    state["ai"]["calls_today"] = state["ai"].get("calls_today", 0) + 1
    save_state(state)
    print(report)
    print("\n[review saved: %s]" % path)
    return 0


def cmd_patrol_tick(cfg):
    ran, reason = patrol_tick(cfg, trigger="scheduled")
    print("patrol-tick: %s" % reason)
    return 0


def cmd_allow(cfg, target):
    """Allowlist a path (or directory) or a signer substring."""
    looks_path = (os.sep in target or "/" in target or ":" in target
                  or os.path.exists(target)
                  or os.path.splitext(target)[1].lower() in WATCH_EXTS)
    path = writable_config_path(cfg)
    lst = cfg["allowlist"]["paths" if looks_path else "signers"]
    if target in lst:
        print("Already allowlisted: %s" % target)
    else:
        lst.append(target)
        try:
            save_config(cfg, path)
        except OSError as exc:
            print("Failed to save config: %s" % exc)
            return 1
    kind = "path" if looks_path else "signer"
    print("Allowlisted %s: %s" % (kind, target))
    print("Config saved to: %s" % path)
    return 0


def cmd_status(cfg):
    state = load_state()
    print("TripFlare %s" % VERSION)
    print("  data dir   : %s" % DATA_DIR)
    print("  config     : %s" % (cfg.get("_config_path") or "(built-in defaults)"))
    print("  ai.mode    : %s" % cfg["ai"].get("mode"))
    print("  ai.backend : %s" % (cfg["ai"].get("backend_path") or "auto"))
    if state is None:
        print("  baseline   : MISSING - run tripflare.py --init")
        return 1
    print("  baseline   : created %s" % state.get("created"))
    print("  rounds     : %d (last round %.2fs)" % (
        state.get("rounds", 0), state.get("last_round_seconds", 0)))
    print("  watched    : %d files, %d registry keys, %d tasks, %d services"
          % (len(state.get("files", {})), len(state.get("registry", {})),
             len(state.get("tasks", [])), len(state.get("services", {}))))
    ai = state.get("ai", {})
    print("  ai calls   : %d today (%s), cap %d/day" % (
        ai.get("calls_today", 0), ai.get("date", "?"),
        cfg["ai"].get("max_calls_per_day", 20)))
    counts = {"high": 0, "warn": 0, "info": 0}
    for a in read_alerts():
        counts[a.get("level", "info")] = counts.get(a.get("level", "info"), 0) + 1
    print("  alerts     : high=%d warn=%d info=%d (total in alerts.jsonl)"
          % (counts["high"], counts["warn"], counts["info"]))
    backend = detect_backend()
    print("  ai backend : %s" % (backend or "NOT FOUND"))
    return 0


def cmd_bench(cfg):
    """Run one full (heavy) round and print per-stage timings."""
    state = load_state()
    if state is None:
        print("No baseline yet. Run: tripflare.py --init")
        return 1
    timings = {}
    events = run_round(state, cfg, heavy=True, timings=timings)
    save_state(state)
    print("Bench round (heavy) completed: %d event(s)" % len(events))
    for name, secs in timings.items():
        print("  %-16s %7.3fs" % (name, secs))
    return 0


USAGE = __doc__ + """
Commands:
  --init        build baseline snapshot
  digest        show alerts since last digest
  ai-review     one-shot AI review [--max N]
  allow <x>     allowlist a path or signer substring
  status        show status
  patrol-tick   scheduled patrol entry point (patrol mode only)
  --bench       timed heavy round
"""


def main(argv):
    args = [a for a in argv[1:]]
    cfg = load_config()
    if "--init" in args:
        return cmd_init(cfg)
    if "--bench" in args:
        return cmd_bench(cfg)
    if args and args[0] == "digest":
        return cmd_digest(cfg)
    if args and args[0] == "ai-review":
        max_alerts = None
        if "--max" in args:
            idx = args.index("--max")
            try:
                max_alerts = int(args[idx + 1])
            except (IndexError, ValueError):
                max_alerts = None
        return cmd_ai_review(cfg, max_alerts=max_alerts)
    if args and args[0] == "allow":
        if len(args) < 2:
            print("usage: tripflare.py allow <path-or-signer>")
            return 2
        return cmd_allow(cfg, " ".join(args[1:]))
    if args and args[0] == "status":
        return cmd_status(cfg)
    if args and args[0] == "patrol-tick":
        return cmd_patrol_tick(cfg)
    if args and args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    if args:
        print("Unknown command: %s\n" % " ".join(args))
        print(USAGE)
        return 2
    return cmd_daemon(cfg)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
