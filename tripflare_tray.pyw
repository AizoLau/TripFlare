#!/usr/bin/env pythonw
# -*- coding: utf-8 -*-
"""TripFlare system tray agent - pure Win32 via ctypes (no dependencies).

Runs windowless under pythonw: registers a hidden message window, adds a
notification-area icon (Shell_NotifyIconW) with a right-click menu, watches
data\\alerts.jsonl for new high alerts and shows balloon tips, and keeps the
tooltip in sync with the daemon state.

Menu: open console / AI review now / start daemon / stop daemon /
      open data folder / quit tray. Double-click opens the console.
Balloon click opens the console on the alerts page.
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import tripflare as core  # noqa: E402  (paths + python resolvers reused)

DATA_DIR = core.DATA_DIR
TRAY_LOG = os.path.join(DATA_DIR, "tray.log")
ALERTS_PATH = core.ALERTS_PATH
ICON_PATH = os.path.join(SCRIPT_DIR, "tripflare.ico")
UI_SCRIPT = os.path.join(SCRIPT_DIR, "tripflare_ui.pyw")
CORE_SCRIPT = os.path.join(SCRIPT_DIR, "tripflare.py")
CREATE_NO_WINDOW = 0x08000000

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

def log(msg):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(TRAY_LOG) and os.path.getsize(TRAY_LOG) > 524288:
            try:
                os.replace(TRAY_LOG, TRAY_LOG + ".1")
            except OSError:
                pass
        with open(TRAY_LOG, "a", encoding="utf-8", errors="replace") as fh:
            fh.write("%s %s\n" % (datetime.now().isoformat(timespec="seconds"),
                                  msg))
    except OSError:
        pass


# --------------------------------------------------------------------------
# Actions (subprocess helpers; never block the message loop for long)
# --------------------------------------------------------------------------

def open_console(alerts=False, reports=False):
    args = [core.windowless_python(), UI_SCRIPT]
    if reports:
        args.append("--reports")
    elif alerts:
        args.append("--alerts")
    try:
        subprocess.Popen(args, creationflags=CREATE_NO_WINDOW)
        log("action: open console (alerts=%s reports=%s)" % (alerts, reports))
    except OSError as exc:
        log("open console failed: %s" % exc)


def daemon_task(action):
    """Start or stop the daemon through its scheduled task."""
    try:
        proc = subprocess.run(["schtasks", "/%s" % action, "/tn",
                               "TripFlareDaemon"],
                              capture_output=True, timeout=60,
                              creationflags=CREATE_NO_WINDOW)
        out = proc.stdout.decode("mbcs", "replace").strip()
        log("action: schtasks /%s TripFlareDaemon rc=%d %s"
            % (action, proc.returncode, out[:120]))
    except (OSError, subprocess.TimeoutExpired) as exc:
        log("action: schtasks /%s failed: %s" % (action, exc))


def open_data_dir():
    try:
        os.startfile(DATA_DIR)
        log("action: open data dir")
    except OSError as exc:
        log("open data dir failed: %s" % exc)


def daemon_running():
    """True when a python process command line contains tripflare.py."""
    script = ("Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" "
              "| Where-Object { $_.CommandLine -like '*tripflare.py*' "
              "-and $_.CommandLine -notlike '*--bench*' "
              "-and $_.CommandLine -notlike '*patrol-tick*' } "
              "| Measure-Object | Select-Object -ExpandProperty Count")
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             script], capture_output=True, timeout=60,
            creationflags=CREATE_NO_WINDOW)
        return int(proc.stdout.decode(
            "utf-8", "replace").strip().splitlines()[-1]) > 0
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return False


# --------------------------------------------------------------------------
# Win32 plumbing
# --------------------------------------------------------------------------

user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32
kernel32 = ctypes.windll.kernel32

WM_USER = 0x0400
WM_TRAYICON = WM_USER + 1
WM_TRAY_BALLOON = WM_USER + 2  # internal: show pending text balloon
WM_TIMER = 0x0113
WM_DESTROY = 0x0002
WM_NULL = 0x0000
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B
NIN_SELECT = 0x0400
NIN_BALLOONUSERCLICK = 0x0405

NIM_ADD, NIM_MODIFY, NIM_DELETE, NIM_SETVERSION = 0, 1, 2, 4
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x1, 0x2, 0x4, 0x10
NIIF_INFO = 0x1
NOTIFYICON_VERSION_4 = 4

TPM_RETURNCMD, TPM_RIGHTBUTTON = 0x0100, 0x0002
MF_STRING, MF_SEPARATOR, MF_GRAYED = 0x0000, 0x0800, 0x0001
IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x0010, 0x0040
IDI_APPLICATION = 32512

TIMER_ALERTS, TIMER_TOOLTIP = 1, 2

CMD_CONSOLE, CMD_REVIEW = 1001, 1002
CMD_START, CMD_STOP = 1003, 1004
CMD_DATADIR, CMD_QUIT = 1005, 1006


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong), ("hWnd", wt.HWND),
        ("uID", ctypes.c_uint), ("uFlags", ctypes.c_uint),
        ("uCallbackMessage", ctypes.c_uint), ("hIcon", wt.HICON),
        ("szTip", wt.WCHAR * 128),
        ("dwState", ctypes.c_ulong), ("dwStateMask", ctypes.c_ulong),
        ("szInfo", wt.WCHAR * 256),
        ("uTimeout", ctypes.c_uint),
        ("szInfoTitle", wt.WCHAR * 64),
        ("dwInfoFlags", ctypes.c_ulong),
        ("guidItem", GUID), ("hBalloonIcon", wt.HICON),
    ]


WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, wt.HWND, ctypes.c_uint,
                             wt.WPARAM, wt.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", ctypes.c_uint), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON),
                ("hCursor", wt.HANDLE), ("hbrBackground", wt.HBRUSH),
                ("lpszMenuName", wt.LPCWSTR), ("lpszClassName", wt.LPCWSTR)]


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class MENUITEMINFOW(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("fMask", ctypes.c_uint),
                ("fType", ctypes.c_uint), ("fState", ctypes.c_uint),
                ("wID", ctypes.c_uint), ("hSubMenu", wt.HANDLE),
                ("hbmpChecked", wt.HANDLE), ("hbmpUnchecked", wt.HANDLE),
                ("dwItemData", ctypes.c_void_p), ("dwTypeData", wt.LPCWSTR),
                ("cch", ctypes.c_uint), ("hbmpItem", wt.HANDLE)]


MIIM_STRING, MIIM_ID, MIIM_FTYPE, MIIM_STATE = 0x0040, 0x0002, 0x0100, 0x0001
MFT_STRING, MFT_SEPARATOR = 0x0000, 0x0800
MFS_GRAYED = 0x0003
MF_BYPOSITION = 0x0400

def menu_items(daemon_on, ai_on):
    """Menu layout; None = separator. State-aware labels/enablement."""
    return [
        (CMD_CONSOLE, "打开控制台", True),
        (CMD_REVIEW,
         "AI 研判（进行中…）" if ai_on else "立即AI研判", not ai_on),
        None,
        (CMD_START, "启动守护", not daemon_on),
        (CMD_STOP, "停止守护", daemon_on),
        None,
        (CMD_DATADIR, "打开数据目录", True),
        (CMD_QUIT, "退出托盘", True),
    ]


def build_menu(daemon_on=True, ai_on=False):
    """Create the tray popup menu via InsertMenuItemW/MENUITEMINFOW."""
    menu = user32.CreatePopupMenu()
    for pos, item in enumerate(menu_items(daemon_on, ai_on)):
        mii = MENUITEMINFOW()
        mii.cbSize = ctypes.sizeof(MENUITEMINFOW)
        if item is None:
            mii.fMask = MIIM_FTYPE
            mii.fType = MFT_SEPARATOR
        else:
            cmd, text, enabled = item
            mii.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STRING | MIIM_STATE
            mii.fType = MFT_STRING
            mii.wID = cmd
            mii.dwTypeData = text
            mii.fState = 0 if enabled else MFS_GRAYED
        if not user32.InsertMenuItemW(menu, pos, True, ctypes.byref(mii)):
            log("InsertMenuItemW failed at pos %d, err=%d"
                % (pos, kernel32.GetLastError()))
    return menu


def menutest():
    """Headless menu self-check: read entries back with GetMenuStringW."""
    for daemon_on, ai_on in ((True, False), (False, True)):
        print("menutest: scenario daemon_running=%s ai_running=%s"
              % (daemon_on, ai_on))
        menu = build_menu(daemon_on, ai_on)
        count = user32.GetMenuItemCount(menu)
        print("menutest: item count = %d (expect 8)" % count)
        for pos in range(count):
            mii = MENUITEMINFOW()
            mii.cbSize = ctypes.sizeof(MENUITEMINFOW)
            mii.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STATE
            user32.GetMenuItemInfoW(menu, pos, True, ctypes.byref(mii))
            buf = ctypes.create_unicode_buffer(128)
            user32.GetMenuStringW(menu, pos, buf, 128, MF_BYPOSITION)
            if mii.fType & MFT_SEPARATOR:
                print("menutest: [%d] <separator>" % pos)
            else:
                state = "DISABLED" if (mii.fState & MFS_GRAYED) else "enabled"
                print("menutest: [%d] id=%d %s text=%s"
                      % (pos, mii.wID, state, buf.value))
        user32.DestroyMenu(menu)
    print("menutest: OK")
    return 0
shell32.Shell_NotifyIconW.argtypes = [ctypes.c_ulong,
                                      ctypes.POINTER(NOTIFYICONDATAW)]
shell32.Shell_NotifyIconW.restype = wt.BOOL
user32.LoadImageW.restype = wt.HICON
user32.LoadImageW.argtypes = [wt.HINSTANCE, wt.LPCWSTR, ctypes.c_uint,
                              ctypes.c_int, ctypes.c_int, ctypes.c_uint]
user32.LoadIconW.restype = wt.HICON
user32.LoadIconW.argtypes = [wt.HINSTANCE, wt.LPCWSTR]
user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
user32.RegisterClassW.restype = wt.ATOM
user32.CreateWindowExW.restype = wt.HWND
user32.CreateWindowExW.argtypes = [ctypes.c_ulong, wt.LPCWSTR, wt.LPCWSTR,
                                   ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, wt.HWND,
                                   wt.HANDLE, wt.HINSTANCE, ctypes.c_void_p]
user32.DefWindowProcW.restype = ctypes.c_long
user32.DefWindowProcW.argtypes = [wt.HWND, ctypes.c_uint, wt.WPARAM,
                                  wt.LPARAM]
user32.DestroyWindow.argtypes = [wt.HWND]
user32.DestroyWindow.restype = wt.BOOL
user32.SetTimer.argtypes = [wt.HWND, ctypes.c_void_p, ctypes.c_uint,
                            ctypes.c_void_p]
user32.SetTimer.restype = ctypes.c_void_p
user32.KillTimer.argtypes = [wt.HWND, ctypes.c_void_p]
user32.KillTimer.restype = wt.BOOL
user32.PostQuitMessage.argtypes = [ctypes.c_int]
user32.PostMessageW.argtypes = [wt.HWND, ctypes.c_uint, wt.WPARAM, wt.LPARAM]
user32.PostMessageW.restype = wt.BOOL
user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND,
                               ctypes.c_uint, ctypes.c_uint]
user32.GetMessageW.restype = ctypes.c_int
user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
user32.TranslateMessage.restype = wt.BOOL
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
user32.DispatchMessageW.restype = ctypes.c_long
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.SetForegroundWindow.restype = wt.BOOL
user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
user32.GetCursorPos.restype = wt.BOOL
user32.CreatePopupMenu.restype = wt.HANDLE
user32.CreatePopupMenu.argtypes = []
user32.InsertMenuItemW.argtypes = [wt.HANDLE, ctypes.c_uint, wt.BOOL,
                                   ctypes.POINTER(MENUITEMINFOW)]
user32.InsertMenuItemW.restype = wt.BOOL
user32.GetMenuItemCount.argtypes = [wt.HANDLE]
user32.GetMenuItemCount.restype = ctypes.c_int
user32.GetMenuStringW.argtypes = [wt.HANDLE, ctypes.c_uint, wt.LPWSTR,
                                  ctypes.c_int, ctypes.c_uint]
user32.GetMenuStringW.restype = ctypes.c_int
user32.GetMenuItemInfoW.argtypes = [wt.HANDLE, ctypes.c_uint, wt.BOOL,
                                    ctypes.POINTER(MENUITEMINFOW)]
user32.GetMenuItemInfoW.restype = wt.BOOL
user32.TrackPopupMenu.argtypes = [wt.HANDLE, ctypes.c_uint, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_int, wt.HWND,
                                  ctypes.c_void_p]
user32.TrackPopupMenu.restype = ctypes.c_int
user32.DestroyMenu.argtypes = [wt.HANDLE]
user32.DestroyMenu.restype = wt.BOOL
user32.RegisterWindowMessageW.argtypes = [wt.LPCWSTR]
user32.RegisterWindowMessageW.restype = ctypes.c_uint
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.GetModuleHandleW.restype = wt.HINSTANCE
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]
kernel32.CreateMutexW.restype = wt.HANDLE
kernel32.GetLastError.restype = ctypes.c_ulong


class TrayApp:
    def __init__(self):
        self.hwnd = None
        self.hicon = None
        self.nid = None
        self.alerts_offset = 0
        self.ai_running = False
        self.daemon_state = None       # None = not probed yet
        self.pending_balloon = None    # (title, body, kind) for UI thread
        self.balloon_kind = "alert"    # what the visible balloon links to
        self.reviewtest = False
        self.taskbar_created = user32.RegisterWindowMessageW(
            "TaskbarCreated")
        self._wndproc = WNDPROC(self._on_message)  # keep a reference
        self.quitting = False

    # ---------------- window + icon setup ----------------

    def setup(self):
        instance = kernel32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = instance
        wc.lpszClassName = "TripFlareTrayWnd"
        if not user32.RegisterClassW(ctypes.byref(wc)):
            err = kernel32.GetLastError()
            if err != 1410:  # 1410 = class already registered
                raise OSError("RegisterClassW failed: %d" % err)
        self.hwnd = user32.CreateWindowExW(
            0, "TripFlareTrayWnd", "TripFlareTray", 0,
            0, 0, 0, 0, None, None, instance, None)
        if not self.hwnd:
            raise OSError("CreateWindowExW failed")
        self.hicon = user32.LoadImageW(None, ICON_PATH, IMAGE_ICON, 0, 0,
                                       LR_LOADFROMFILE | LR_DEFAULTSIZE)
        if self.hicon:
            log("icon loaded: %s" % ICON_PATH)
        else:
            self.hicon = user32.LoadIconW(None, IDI_APPLICATION)
            log("icon file not loadable, using fallback IDI_APPLICATION")
        self._add_icon()
        # Start the incremental tail at end-of-file: no historic balloons.
        try:
            self.alerts_offset = os.path.getsize(ALERTS_PATH)
        except OSError:
            self.alerts_offset = 0
        log("alerts tail offset=%d" % self.alerts_offset)
        user32.SetTimer(self.hwnd, TIMER_ALERTS, 10000, None)
        user32.SetTimer(self.hwnd, TIMER_TOOLTIP, 30000, None)
        self._refresh_tooltip()

    def _add_icon(self):
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = self.hicon
        nid.szTip = "TripFlare"
        ok = shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
        # Opt into the Vista+ callback behaviour (NIN_* messages).
        nid.uVersion = NOTIFYICON_VERSION_4
        shell32.Shell_NotifyIconW(NIM_SETVERSION, ctypes.byref(nid))
        self.nid = nid
        log("notify icon added: %s" % bool(ok))

    def _refresh_tooltip(self):
        self.daemon_state = daemon_running()
        tip = ("TripFlare - 守护运行中" if self.daemon_state
               else "TripFlare - 守护已停止")
        self.nid.uFlags = NIF_TIP
        self.nid.szTip = tip
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self.nid))

    # ---------------- balloon on new high alerts ----------------

    def _check_alerts(self):
        try:
            size = os.path.getsize(ALERTS_PATH)
        except OSError:
            return
        if size < self.alerts_offset:
            # File shrank (manual edit/rotation): resync without replay.
            self.alerts_offset = size
            log("alerts file shrank, resynced offset=%d" % size)
            return
        if size == self.alerts_offset:
            return
        try:
            with open(ALERTS_PATH, "r", encoding="utf-8",
                      errors="replace") as fh:
                fh.seek(self.alerts_offset)
                chunk = fh.read()
            self.alerts_offset = size
        except OSError as exc:
            log("alerts read failed: %s" % exc)
            return
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except ValueError:
                continue
            if alert.get("level") == "high":
                self._balloon(alert)

    def _balloon(self, alert):
        path = alert.get("path", "?")
        body = "%s\n评分 %s · %s" % (
            path, alert.get("score", "?"), alert.get("type", ""))
        self._show_text_balloon("TripFlare 高危异常", body, "alert")

    def _show_text_balloon(self, title, body, kind):
        """Show a NIF_INFO balloon (UI thread only) and remember its kind."""
        self.balloon_kind = kind
        self.nid.uFlags = NIF_INFO
        self.nid.szInfo = body[:255]
        self.nid.szInfoTitle = title[:63]
        self.nid.dwInfoFlags = NIIF_INFO
        self.nid.uTimeout = 10000
        ok = shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self.nid))
        log("balloon shown=%s kind=%s: %s | %s"
            % (bool(ok), kind, title, body.replace("\n", " | ")))
        if self.reviewtest and kind in ("review_done", "error", "info"):
            log("reviewtest: terminal balloon kind=%s, exiting" % kind)
            user32.DestroyWindow(self.hwnd)

    def _post_balloon(self, title, body, kind):
        """Thread-safe balloon request: the UI thread shows it."""
        self.pending_balloon = (title, body, kind)
        if self.hwnd:
            user32.PostMessageW(self.hwnd, WM_TRAY_BALLOON, 0, 0)

    # ---------------- AI review with three-state feedback ----------------

    def ai_review_start(self):
        if self.ai_running:
            return
        self.ai_running = True
        log("action: ai-review started")
        self._post_balloon("TripFlare", "AI 研判进行中…", "progress")
        threading.Thread(target=self._ai_worker, daemon=True).start()

    def _ai_worker(self):
        try:
            proc = subprocess.run(
                [core.console_python(), CORE_SCRIPT, "ai-review"],
                capture_output=True, timeout=900,
                creationflags=CREATE_NO_WINDOW)
            out = (proc.stdout + proc.stderr).decode("utf-8",
                                                   "replace").strip()
            last = out.splitlines()[-1] if out else "(no output)"
            log("action: ai-review finished rc=%d: %s"
                % (proc.returncode, last[:200]))
            if proc.returncode != 0:
                self._post_balloon("AI 研判失败", last[:200], "error")
            elif "No pending alerts" in out:
                self._post_balloon("TripFlare AI 研判",
                                   "没有未研判的告警", "info")
            else:
                self._post_balloon("TripFlare",
                                   "研判完成，点击查看报告", "review_done")
        except (OSError, subprocess.TimeoutExpired) as exc:
            log("action: ai-review failed: %s" % exc)
            self._post_balloon("AI 研判失败", str(exc)[:200], "error")
        finally:
            self.ai_running = False

    # ---------------- context menu ----------------

    def _show_menu(self):
        # Rebuild each time so enablement mirrors the live daemon state.
        self.daemon_state = daemon_running()
        menu = build_menu(self.daemon_state, self.ai_running)
        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)
        cmd = user32.TrackPopupMenu(
            menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0,
            self.hwnd, None)
        user32.PostMessageW(self.hwnd, WM_NULL, 0, 0)
        user32.DestroyMenu(menu)
        self._run_command(cmd)

    def _run_command(self, cmd):
        if cmd == CMD_CONSOLE:
            open_console()
        elif cmd == CMD_REVIEW:
            self.ai_review_start()
        elif cmd == CMD_START:
            daemon_task("run")
            self._refresh_tooltip()
        elif cmd == CMD_STOP:
            daemon_task("end")
            self._refresh_tooltip()
        elif cmd == CMD_DATADIR:
            open_data_dir()
        elif cmd == CMD_QUIT:
            log("tray quit requested")
            self.quitting = True
            user32.DestroyWindow(self.hwnd)

    # ---------------- window procedure ----------------

    def _on_message(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAYICON:
            if lparam in (NIN_BALLOONUSERCLICK,):
                if self.balloon_kind == "review_done":
                    open_console(reports=True)
                else:
                    open_console(alerts=True)
            elif lparam in (NIN_SELECT, WM_LBUTTONUP):
                open_console()
            elif lparam == WM_LBUTTONDBLCLK:
                open_console()
            elif lparam in (WM_RBUTTONUP, WM_CONTEXTMENU):
                self._show_menu()
            return 0
        if msg == WM_TRAY_BALLOON:
            if self.pending_balloon:
                title, body, kind = self.pending_balloon
                self.pending_balloon = None
                self._show_text_balloon(title, body, kind)
            return 0
        if msg == WM_TIMER:
            if wparam == TIMER_ALERTS:
                self._check_alerts()
            elif wparam == TIMER_TOOLTIP:
                self._refresh_tooltip()
            return 0
        if msg == WM_DESTROY:
            user32.KillTimer(hwnd, TIMER_ALERTS)
            user32.KillTimer(hwnd, TIMER_TOOLTIP)
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self.nid))
            log("tray icon removed, exiting")
            user32.PostQuitMessage(0)
            return 0
        if msg == self.taskbar_created:
            log("TaskbarCreated received, re-adding icon")
            self._add_icon()
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    # ---------------- main loop ----------------

    def run(self):
        self.setup()
        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))


def already_running():
    """Single-instance guard via a named mutex."""
    kernel32.CreateMutexW(None, False, "TripFlareTrayMutex")
    return kernel32.GetLastError() == 183  # ERROR_ALREADY_EXISTS


def reviewtest():
    """Test hook: run the tray, trigger one AI review, exit on its balloon."""
    os.makedirs(DATA_DIR, exist_ok=True)
    app = TrayApp()
    app.reviewtest = True
    app.setup()
    log("reviewtest: tray up, triggering ai-review")
    app.ai_review_start()
    msg = wt.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))
    return 0


def main():
    if "--menutest" in sys.argv:
        return menutest()
    if "--reviewtest" in sys.argv:
        return reviewtest()
    os.makedirs(DATA_DIR, exist_ok=True)
    if already_running():
        log("tray already running, second instance exits")
        return 0
    log("tray started (pid=%d)" % os.getpid())
    try:
        TrayApp().run()
    except Exception:
        log("tray crashed:\n%s" % traceback.format_exc())
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
