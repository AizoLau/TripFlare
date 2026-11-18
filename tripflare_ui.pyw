#!/usr/bin/env pythonw
# -*- coding: utf-8 -*-
"""TripFlare console UI - bilingual tkinter front-end for tripflare.py.

Pure standard library. Five tabs: alerts / reports / log / config / status.

    pythonw tripflare_ui.pyw            open the console
    pythonw tripflare_ui.pyw --alerts   open directly on the alerts tab
    pythonw tripflare_ui.pyw --reports  open directly on the reports tab
    python  tripflare_ui.pyw --selftest headless sanity check, then exit
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, ttk

SCRIPT_DIR = (os.path.dirname(os.path.abspath(sys.executable))
              if getattr(sys, "frozen", False)
              else os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SCRIPT_DIR)
import tripflare as core  # noqa: E402  (core constants/AI helpers reused)

DATA_DIR = core.DATA_DIR
ICON_PATH = core.resolve_resource_path("tripflare.ico")
FOCUS_REQ_PATH = os.path.join(DATA_DIR, "ui_focus.req")
WINDOW_TITLES = {
    "zh": "TripFlare 安全监控控制台",
    "en": "TripFlare Console",
}
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
_CONSOLE_MUTEX = None

LEVELS = ("high", "warn", "info")
LEVEL_ORDER = {"high": 3, "warn": 2, "info": 1}

LEVEL_I18N = {
    "zh": {"high": "高危", "warn": "中危", "info": "低危"},
    "en": {"high": "High", "warn": "Warn", "info": "Info"},
}
LEVEL_SHORT_I18N = {
    "zh": {"high": "高", "warn": "中", "info": "低"},
    "en": {"high": "HIGH", "warn": "WARN", "info": "INFO"},
}
TYPE_I18N = {
    "zh": {
        "file_new": "新增文件",
        "file_modified": "文件修改",
        "registry_new": "注册表新增",
        "registry_changed": "注册表修改",
        "registry_modified": "注册表修改",
        "process_new": "新进程",
        "task_new": "计划任务新增",
        "service_new": "服务新增",
        "service_changed": "服务修改",
        "ifeo_debugger": "IFEO 调试器",
    },
    "en": {
        "file_new": "New File",
        "file_modified": "File Modified",
        "registry_new": "Registry Added",
        "registry_changed": "Registry Modified",
        "registry_modified": "Registry Modified",
        "process_new": "New Process",
        "task_new": "Scheduled Task",
        "service_new": "New Service",
        "service_changed": "Service Modified",
        "ifeo_debugger": "IFEO Debugger",
    },
}
MODE_I18N = {
    "zh": {"recommend": "按需研判", "patrol": "自动巡逻", "off": "已关闭"},
    "en": {"recommend": "On-Demand", "patrol": "Auto Patrol", "off": "Off"},
}
MODE_CHOICES_I18N = {
    "zh": [
        ("按需手动研判", "recommend"),
        ("后台自动巡逻", "patrol"),
        ("关闭 AI 研判", "off"),
    ],
    "en": [
        ("On-Demand (Manual)", "recommend"),
        ("Auto Patrol", "patrol"),
        ("Off (Local Only)", "off"),
    ],
}
PROVIDER_CHOICES_I18N = {
    "zh": [
        ("自动选择", "auto"),
        ("本地 Ollama", "ollama"),
        ("OpenAI 兼容接口", "openai"),
        ("命令行工具", "cli"),
    ],
    "en": [
        ("Auto Detect", "auto"),
        ("Local Ollama", "ollama"),
        ("OpenAI-Compatible API", "openai"),
        ("Local CLI Tool", "cli"),
    ],
}
SIG_STATUS_I18N = {
    "zh": {
        "Valid": "有效签名",
        "NotSigned": "未签名",
        "UnknownError": "未知/不支持的签名格式",
        "HashMismatch": "哈希不匹配（签名已破坏）",
        "NotTrusted": "签名证书不受信任",
        "Error": "签名读取异常",
    },
    "en": {
        "Valid": "Valid Signature",
        "NotSigned": "Unsigned",
        "UnknownError": "Unknown / Unsupported Signature",
        "HashMismatch": "Hash Mismatch (Corrupted)",
        "NotTrusted": "Untrusted Certificate",
        "Error": "Signature Read Error",
    },
}

REASON_TAGS_I18N = {
    "zh": [
        ("renamed signed", "签名程序改名"),
        ("random-looking name", "随机名"),
        ("vowel-less", "随机名"),
        ("guid-named", "随机名"),
        ("high-risk drop zone", "高危目录"),
        ("hidden directory", "隐藏目录"),
        ("signer not in allowlist", "签名者未加白"),
        ("unsigned", "无有效签名"),
        ("not signed", "无有效签名"),
        ("masquerades", "伪装运行库名"),
        ("persistence", "持久化"),
        ("hidden file attribute", "隐藏属性"),
        ("critical autostart", "关键自启动"),
        ("ifeo", "IFEO 劫持"),
    ],
    "en": [
        ("renamed signed", "Renamed Signed"),
        ("random-looking name", "Random Name"),
        ("vowel-less", "Random Name"),
        ("guid-named", "GUID Dir"),
        ("high-risk drop zone", "Drop Zone"),
        ("hidden directory", "Hidden Dir"),
        ("signer not in allowlist", "Untrusted Signer"),
        ("unsigned", "Unsigned"),
        ("not signed", "Unsigned"),
        ("masquerades", "DLL Masquerade"),
        ("persistence", "Persistence"),
        ("hidden file attribute", "Hidden"),
        ("critical autostart", "Winlogon"),
        ("ifeo", "IFEO Hijack"),
    ],
}

I18N = {
    "zh": {
        "lang_toggle": "EN",
        "tab_alerts": " 告警中心 ",
        "tab_reports": " 研判报告 ",
        "tab_log": " 运行日志 ",
        "tab_config": " 系统配置 ",
        "tab_status": " 运行状态 ",
        "hdr_running": "● 守护运行中",
        "hdr_stopped": "● 守护已停止",
        "hdr_checking": "● 状态检测中",
        "hdr_mode": "AI 模式: %s",
        "hdr_alert": "最近告警: %s",
        "kpi_unread": "未读告警",
        "kpi_high": "高危异常",
        "kpi_warn": "中危提醒",
        "kpi_info": "低危记录",
        "search_lbl": "搜索:",
        "level_lbl": "级别:",
        "type_lbl": "类型:",
        "unread_chk": "仅看未读",
        "reset_btn": "重置筛选",
        "lv_all": "全部级别",
        "lv_wh": "高危 + 中危",
        "lv_high": "仅高危",
        "lv_warn": "仅中危",
        "lv_info": "仅低危",
        "tp_all": "全部类型",
        "tp_file": "文件",
        "tp_proc": "进程",
        "tp_reg": "注册表",
        "tp_svc": "系统服务",
        "tp_task": "计划任务",
        "tp_ifeo": "IFEO",
        "lv_opts": ("全部级别", "高危 + 中危", "仅高危", "仅中危", "仅低危"),
        "tp_opts": ("全部类型", "文件", "进程", "注册表",
                    "系统服务", "计划任务", "IFEO"),
        "count_fmt": "匹配 %d 条 / 总计 %d 条",
        "cap_fmt": "当前显示前 %d 条（共 %d 条）",
        "load_all": "加载全部记录",
        "btn_refresh": "↻ 刷新",
        "btn_open_dir": "📂 打开目录",
        "btn_allow_path": "✓ 加白路径",
        "btn_allow_signer": "🛡 信任签名者",
        "btn_mark_read": "标为已读",
        "btn_mark_unread": "标记为未读",
        "btn_prune": "🧹 清理误报",
        "btn_all_read": "全部已读",
        "btn_ai_sel": "✦ 研判选中项",
        "btn_ai_unread": "✦ AI 研判未读",
        "btn_ai_busy": "研判中…",
        "tip_ai_unread": "按单次上限抽取最新未读中/高危告警送交 AI 研判（低危不送审）",
        "tip_ai_sel": "将表格中选中的告警直接送交 AI 研判（支持多选，不限已读状态）",
        "col_time": "时间",
        "col_level": "级别",
        "col_type": "类型",
        "col_score": "风险分",
        "col_summary": "摘要与风险标签",
        "col_path": "对象路径",
        "insp_none": " 未选择 ",
        "insp_title": "告警详情",
        "insp_raw": "原始数据",
        "insp_copy": "复制路径",
        "insp_hint": "在上方列表中选择告警查看详情；按住 Ctrl 或 Shift 可多选批量处理。\n",
        "insp_score_badge": " %s · %s 分 ",
        "insp_sel_n": "  （已选中 %d 条）",
        "insp_path": "对象路径",
        "insp_target": "目标指令",
        "insp_sig": "数字签名",
        "insp_orig": "程序原始名称",
        "insp_size": "文件大小",
        "insp_size_suffix": "  （大小: %s）",
        "insp_reasons": "风险依据:\n",
        "ctx_ai_n": "✦ AI 研判选中项（%d 条）",
        "ctx_ai_1": "✦ AI 研判此项",
        "ctx_open_dir": "📂 打开所在目录",
        "ctx_copy": "📋 复制完整路径",
        "ctx_allow_path": "✓ 加白路径",
        "ctx_allow_signer": "🛡 信任签名者",
        "ctx_mark_read": "标记为已读",
        "ctx_mark_unread": "标记为未读",
        "ctx_raw": "查看原始数据",
        "copied": "已复制路径",
        "dlg_title": "告警完整详情",
        "dlg_copy_raw": "复制原始数据",
        "dlg_close": "关闭",
        "dlg_extra": "附加信息:",
        "dlg_raw": "原始记录:",
        "rep_list_title": "历史研判报告",
        "rep_kind": "类型",
        "rep_time": "生成时间",
        "rep_body_title": "报告正文",
        "rep_none": "暂无研判报告",
        "rep_open_ext": "用默认程序打开",
        "log_auto": "每 5 秒自动刷新",
        "log_filter": "筛选:",
        "log_all": "全部日志",
        "log_alerts": "仅告警",
        "log_errs": "仅错误/异常",
        "log_opts": ("全部日志", "仅告警", "仅错误/异常"),
        "log_open": "外部打开日志",
        "log_empty": "(暂无日志)\n",
        "cfg_left_title": "监控、AI 与降噪配置",
        "cfg_interval": "扫描间隔 (秒)",
        "cfg_thresh": "风险阈值 (中危 / 高危)",
        "cfg_realtime": "实时文件监控（秒级捕获落盘行为）",
        "cfg_noise": "过滤系统默认后台噪音（推荐开启）",
        "cfg_mode": "AI 研判模式",
        "cfg_provider": "AI 服务提供方",
        "cfg_api_base": "API 地址（可选）",
        "cfg_api_key": "API 密钥（可选）",
        "cfg_model": "模型名称（可选）",
        "cfg_cli": "命令行程序（CLI 模式）",
        "cfg_limits": "单次研判条数 / 每日上限",
        "cfg_patrol": "自动巡逻间隔 (分钟)",
        "cfg_save": "保存常用设置",
        "sub_allow": " 白名单管理 ",
        "sub_excl": " 排除扫描目录 ",
        "sub_adv": " 高级配置 ",
        "allow_signer_lbl": "受信任的数字签名者（填写厂商名称或证书关键字）",
        "allow_path_lbl": "白名单路径 / 文件名",
        "excl_hint": "跳过文件遍历的大体积或高频变动目录（如游戏目录、构建缓存、工程代码库）",
        "btn_add": "添加",
        "btn_del": "移除选中",
        "btn_browse": "选目录",
        "adv_hint": "直接编辑配置文件内容（保存前自动检查格式）。",
        "adv_save": "保存高级配置",
        "st_run": "TripFlare 后台守护正在运行",
        "st_stop": "TripFlare 后台守护未运行",
        "st_chk": "正在检测守护状态…",
        "st_sub": "AI 模式: %s  ·  实时监控: %s  ·  系统降噪: %s  ·  扫描间隔: %s 秒",
        "on": "已开启",
        "off": "已关闭",
        "st_cov": "基线监控覆盖面",
        "st_health": "运行健康与 AI 配额",
        "st_files": "监视文件数",
        "st_reg": "注册表键",
        "st_tasks": "计划任务",
        "st_svc": "系统服务",
        "st_proc": "已记录进程",
        "st_rounds": "已完成扫描轮数",
        "st_sec": "最近一轮耗时",
        "st_calls": "今日 AI 调用",
        "st_pending": "待研判中/高危告警",
        "btn_start": "▶ 启动守护",
        "btn_stop": "■ 停止守护",
        "btn_scan": "⟳ 立即扫描一轮",
        "btn_scanning": "扫描中…",
        "btn_init": "🔄 重建安全基线",
        "btn_initing": "重建中…",
        "btn_datadir": "📂 数据目录",
        "msg_scan_done": "全量扫描完成！\n\n• 扫描耗时: %.2f 秒\n• 本轮新增告警: %s 条",
        "msg_init_ok": "安全基线已重新建立，后续扫描将以当前系统状态作为基准。",
    },
    "en": {
        "lang_toggle": "中文",
        "tab_alerts": " Alerts ",
        "tab_reports": " Reports ",
        "tab_log": " Logs ",
        "tab_config": " Settings ",
        "tab_status": " Status ",
        "hdr_running": "● Monitor Running",
        "hdr_stopped": "● Monitor Stopped",
        "hdr_checking": "● Checking...",
        "hdr_mode": "AI: %s",
        "hdr_alert": "Last Alert: %s",
        "kpi_unread": "Unread",
        "kpi_high": "High Risk",
        "kpi_warn": "Warnings",
        "kpi_info": "Info",
        "search_lbl": "Search:",
        "level_lbl": "Level:",
        "type_lbl": "Type:",
        "unread_chk": "Unread Only",
        "reset_btn": "Reset",
        "lv_all": "All Levels",
        "lv_wh": "High + Warn",
        "lv_high": "High Only",
        "lv_warn": "Warn Only",
        "lv_info": "Info Only",
        "tp_all": "All Types",
        "tp_file": "Files",
        "tp_proc": "Processes",
        "tp_reg": "Registry",
        "tp_svc": "Services",
        "tp_task": "Tasks",
        "tp_ifeo": "IFEO",
        "lv_opts": ("All Levels", "High + Warn", "High Only",
                    "Warn Only", "Info Only"),
        "tp_opts": ("All Types", "Files", "Processes", "Registry",
                    "Services", "Tasks", "IFEO"),
        "count_fmt": "%d matched / %d total",
        "cap_fmt": "Showing top %d of %d alerts",
        "load_all": "Load All",
        "btn_refresh": "↻ Refresh",
        "btn_open_dir": "📂 Folder",
        "btn_allow_path": "✓ Allow Path",
        "btn_allow_signer": "🛡 Trust Signer",
        "btn_mark_read": "Mark Read",
        "btn_mark_unread": "Mark Unread",
        "btn_prune": "🧹 Prune Noise",
        "btn_all_read": "Read All",
        "btn_ai_sel": "✦ Triage Selected",
        "btn_ai_unread": "✦ AI Triage",
        "btn_ai_busy": "Triaging...",
        "tip_ai_unread": "Send newest unread Warn/High alerts to AI (Info is skipped)",
        "tip_ai_sel": "Send selected alerts directly to AI regardless of read status",
        "col_time": "Time",
        "col_level": "Level",
        "col_type": "Type",
        "col_score": "Score",
        "col_summary": "Summary & Risk Signals",
        "col_path": "Target Path",
        "insp_none": " None ",
        "insp_title": "Alert Inspector",
        "insp_raw": "Raw Data",
        "insp_copy": "Copy Path",
        "insp_hint": "Select any alert above to inspect details. Hold Ctrl/Shift to multi-select.\n",
        "insp_score_badge": " %s · Score %s ",
        "insp_sel_n": "  (%d selected)",
        "insp_path": "Target Path",
        "insp_target": "Command",
        "insp_sig": "Signature",
        "insp_orig": "OriginalFilename",
        "insp_size": "File Size",
        "insp_size_suffix": "  (Size: %s)",
        "insp_reasons": "Risk Signals:\n",
        "ctx_ai_n": "✦ AI Triage Selected (%d)",
        "ctx_ai_1": "✦ AI Triage This Alert",
        "ctx_open_dir": "📂 Open Containing Folder",
        "ctx_copy": "📋 Copy Full Path",
        "ctx_allow_path": "✓ Allowlist Path",
        "ctx_allow_signer": "🛡 Trust Signer",
        "ctx_mark_read": "Mark as Read",
        "ctx_mark_unread": "Mark as Unread",
        "ctx_raw": "View Raw Record",
        "copied": "Path copied",
        "dlg_title": "Alert Details",
        "dlg_copy_raw": "Copy Raw Data",
        "dlg_close": "Close",
        "dlg_extra": "Extra Metadata:",
        "dlg_raw": "Raw Record:",
        "rep_list_title": "AI Triage Reports",
        "rep_kind": "Type",
        "rep_time": "Created",
        "rep_body_title": "Report Content",
        "rep_none": "No reports yet",
        "rep_open_ext": "Open Externally",
        "log_auto": "Auto-refresh (5s)",
        "log_filter": "Filter:",
        "log_all": "All Logs",
        "log_alerts": "Alerts Only",
        "log_errs": "Errors Only",
        "log_opts": ("All Logs", "Alerts Only", "Errors Only"),
        "log_open": "Open Log File",
        "log_empty": "(No log entries yet)\n",
        "cfg_left_title": "Monitoring, AI & Noise Filter",
        "cfg_interval": "Scan Interval (sec)",
        "cfg_thresh": "Thresholds (Warn / High)",
        "cfg_realtime": "Real-time file watch (instant drop detection)",
        "cfg_noise": "Filter Windows background OS noise (recommended)",
        "cfg_mode": "AI Triage Mode",
        "cfg_provider": "AI Provider",
        "cfg_api_base": "API Base URL (optional)",
        "cfg_api_key": "API Key (optional)",
        "cfg_model": "Model Name (optional)",
        "cfg_cli": "CLI Tool (CLI mode)",
        "cfg_limits": "Batch Limit / Daily Cap",
        "cfg_patrol": "Patrol Interval (min)",
        "cfg_save": "Save Settings",
        "sub_allow": " Allowlist ",
        "sub_excl": " Excluded Dirs ",
        "sub_adv": " Advanced ",
        "allow_signer_lbl": "Trusted Authenticode Signers (vendor or subject keyword)",
        "allow_path_lbl": "Allowlisted Paths / Executables",
        "excl_hint": "Skip large or high-churn directories (games, build caches, repos)",
        "btn_add": "Add",
        "btn_del": "Remove",
        "btn_browse": "Browse",
        "adv_hint": "Edit JSON configuration directly (validated before saving).",
        "adv_save": "Save Advanced Config",
        "st_run": "TripFlare Background Monitor is Running",
        "st_stop": "TripFlare Background Monitor is Stopped",
        "st_chk": "Checking monitor status...",
        "st_sub": "AI: %s  ·  Real-time: %s  ·  Noise Filter: %s  ·  Interval: %ss",
        "on": "On",
        "off": "Off",
        "st_cov": "Baseline Coverage",
        "st_health": "Health & AI Quota",
        "st_files": "Watched Files",
        "st_reg": "Registry Keys",
        "st_tasks": "Scheduled Tasks",
        "st_svc": "Services",
        "st_proc": "Known Processes",
        "st_rounds": "Scan Rounds",
        "st_sec": "Last Round Time",
        "st_calls": "AI Calls Today",
        "st_pending": "Pending Warn/High",
        "btn_start": "▶ Start Monitor",
        "btn_stop": "■ Stop Monitor",
        "btn_scan": "⟳ Scan Now",
        "btn_scanning": "Scanning...",
        "btn_init": "🔄 Rebuild Baseline",
        "btn_initing": "Rebuilding...",
        "btn_datadir": "📂 Data Folder",
        "msg_scan_done": "Scan completed!\n\n• Duration: %.2f s\n• New events: %s",
        "msg_init_ok": "Security baseline rebuilt. Future scans will diff against this snapshot.",
    },
}

DISPLAY_CAP = 500

PALETTE = {
    "bg": "#F1F5F9",
    "surface": "#FFFFFF",
    "surface_alt": "#F8FAFC",
    "surface_hover": "#EFF6FF",
    "border": "#E2E8F0",
    "border_strong": "#CBD5E1",
    "header_bg": "#0F172A",
    "header_panel": "#1E293B",
    "header_text": "#F8FAFC",
    "header_sub": "#94A3B8",
    "accent": "#F97316",
    "accent_hover": "#EA580C",
    "primary": "#2563EB",
    "primary_hover": "#1D4ED8",
    "danger": "#DC2626",
    "danger_bg": "#FEF2F2",
    "danger_border": "#FECACA",
    "warn": "#D97706",
    "warn_text": "#B45309",
    "warn_bg": "#FFFBEB",
    "ok": "#10B981",
    "ok_dark": "#059669",
    "ok_bg": "#ECFDF5",
    "info": "#64748B",
    "text": "#0F172A",
    "text_sec": "#475569",
    "muted": "#64748B",
    "select_bg": "#DBEAFE",
    "select_fg": "#0F172A",
    "log_bg": "#0F172A",
    "log_fg": "#E2E8F0",
}


def enable_dpi_awareness():
    """Enable Windows DPI awareness so fonts and widgets stay crisp."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def focus_existing_console(start_tab=None):
    """Ensure only one console instance runs; restore existing window if active."""
    global _CONSOLE_MUTEX
    if os.name != "nt":
        return False
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]
    kernel32.CreateMutexW.restype = wt.HANDLE
    kernel32.GetLastError.restype = ctypes.c_ulong
    user32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
    user32.FindWindowW.restype = wt.HWND
    user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wt.BOOL
    user32.SetForegroundWindow.argtypes = [wt.HWND]
    user32.SetForegroundWindow.restype = wt.BOOL

    _CONSOLE_MUTEX = kernel32.CreateMutexW(
        None, False, "TripFlareConsoleMutex")
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        if start_tab is not None:
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                with open(FOCUS_REQ_PATH, "w", encoding="utf-8") as fh:
                    fh.write("reports" if start_tab == 1 else "alerts")
            except OSError:
                pass
        for title in WINDOW_TITLES.values():
            hwnd = user32.FindWindowW(None, title)
            if hwnd:
                user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                user32.SetForegroundWindow(hwnd)
                break
        return True
    return False


def _translate_reason_part(part):
    """Translate one scoring clause into natural Chinese."""
    m = re.match(r"^vowel-less random-looking name '(.+)'$", part)
    if m:
        return "无元音随机特征名 '%s'" % m.group(1)
    m = re.match(r"^random-looking name '(.+)'$", part)
    if m:
        return "随机特征文件名 '%s'" % m.group(1)
    m = re.match(r"^inside GUID-named directory '(.+)'$", part)
    if m:
        return "位于 GUID 随机命名目录 '%s' 内" % m.group(1)
    if part.startswith("masquerades as a runtime library name"):
        return "在 Windows 目录外伪装系统运行库名称"
    if part.startswith("located in a high-risk drop zone"):
        return "位于高危投递目录（Temp / 下载 / 桌面）"
    if part == "located inside a hidden directory":
        return "位于隐藏目录内"
    m = re.match(r"^unsigned or invalid signature \((.+)\)$", part)
    if m:
        st = SIG_STATUS_I18N["zh"].get(m.group(1), m.group(1))
        return "无签名或签名无效（%s）" % st
    m = re.match(r"^signer not in allowlist \('(.*)'\)$", part)
    if m:
        return "签名者未加入信任白名单（'%s'）" % m.group(1)
    m = re.match(r"^renamed signed system binary \(OriginalFilename: (.+)\)$",
                 part)
    if m:
        return "微软签名程序被改名伪装（原始文件名: %s）" % m.group(1)
    if part == "creates or modifies a persistence mechanism":
        return "创建或修改持久化自启动机制"
    if part == "hidden file attribute":
        return "文件带有隐藏属性"
    if part == "critical autostart value (Winlogon)":
        return "修改关键登录自启项（Winlogon）"
    if part == "IFEO debugger hijack primitive":
        return "存在 IFEO 映像劫持调试器"
    return part


def translate_reason(reason, lang="zh"):
    """Translate/format an alert scoring reason for the active language."""
    if lang == "en":
        return (reason or "").strip()
    s = (reason or "").strip()
    if not s:
        return s
    pts = ""
    m = re.search(r"\s*(\(\+\d+\))$", s)
    if m:
        pts = " " + m.group(1)
        s = s[:m.start()].strip()
    parts = [p.strip() for p in s.split("; ") if p.strip()]
    translated = [_translate_reason_part(p) for p in parts]
    return "；".join(translated) + pts


def translate_reason_zh(reason):
    """Backward-compatible helper returning Chinese scoring reason."""
    return translate_reason(reason, "zh")


def human_time(ts, lang="zh"):
    """Human-friendly timestamp."""
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        return ts or "-"
    today = datetime.now().date()
    if dt.date() == today:
        prefix = "Today" if lang == "en" else "今天"
        return "%s %02d:%02d" % (prefix, dt.hour, dt.minute)
    if dt.date() == today - timedelta(days=1):
        prefix = "Yesterday" if lang == "en" else "昨天"
        return "%s %02d:%02d" % (prefix, dt.hour, dt.minute)
    return "%02d-%02d %02d:%02d" % (dt.month, dt.day, dt.hour, dt.minute)


def format_size(size):
    """Format byte size cleanly for the inspector."""
    if size is None or size == "":
        return "-"
    try:
        n = int(size)
    except (TypeError, ValueError):
        return str(size)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return str(size)


def object_name(a):
    """Short object name: file name / key tail / task / service name."""
    extra = a.get("extra") or {}
    for key in ("value", "ifeo"):
        if extra.get(key):
            return extra[key]
    if extra.get("service"):
        svc = extra["service"]
        return svc.split("\\")[-1] if "\\" in svc else svc
    path = a.get("path", "")
    if path.startswith("schtasks:"):
        tail = extra.get("task") or path[len("schtasks:"):]
        return tail.rstrip("\\").split("\\")[-1]
    if path.startswith("service:"):
        svc = extra.get("service") or path[len("service:"):]
        return svc.split("\\")[-1] if "\\" in svc else svc
    return os.path.basename(path) or path


def risk_tags(a, lang="zh"):
    """Map the alert's reasons to at most two risk tag pills."""
    tags = []
    mapping = REASON_TAGS_I18N.get(lang, REASON_TAGS_I18N["zh"])
    for reason in a.get("reasons") or []:
        low = reason.lower()
        tag = None
        for key, label in mapping:
            if key in low:
                tag = label
                break
        if tag is None:
            tag = reason.split(" (+")[0][:20]
        if tag not in tags:
            tags.append(tag)
        if len(tags) >= 2:
            break
    fmt = "[%s]" if lang == "en" else "〔%s〕"
    return "".join(fmt % t for t in tags)


def alert_summary(a, lang="zh"):
    """Decluttered summary: object name + up to 2 risk tags."""
    return (object_name(a) + " " + risk_tags(a, lang=lang)).strip()


def resolve_open_target(path, lang="zh"):
    """Decide what 'open folder' should run for an alert path."""
    non_file = ("Not a filesystem path" if lang == "en"
                else "非文件路径，无目录可开")
    if not path:
        return None, non_file
    if path.startswith(("schtasks:", "service:", "ifeo:")):
        return None, non_file
    if re.match(r"^[A-Z_]+\\", path):
        return None, non_file
    if not re.match(r"^[A-Za-z]:\\", path):
        return None, non_file
    if os.path.exists(path):
        return ["explorer.exe", "/select," + path], ""
    parent = os.path.dirname(path)
    while parent and not os.path.isdir(parent):
        nxt = os.path.dirname(parent)
        if nxt == parent:
            break
        parent = nxt
    if parent and os.path.isdir(parent):
        note = ("File gone; opened parent folder" if lang == "en"
                else "文件已不存在，已打开上级目录")
        return ["explorer.exe", parent], note
    return None, ("Path no longer exists" if lang == "en" else "路径已不存在")


def run_hidden(args, timeout=120):
    """Run a console tool without flashing a window; return (rc, stdout)."""
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout,
                              creationflags=CREATE_NO_WINDOW)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)


def daemon_running():
    """True when TripFlare daemon (python or frozen exe) is running."""
    script = (
        "Get-CimInstance Win32_Process | Where-Object { "
        "($_.Name -like 'python*' -and $_.CommandLine -like '*tripflare.py*' "
        "-and $_.CommandLine -notlike '*--bench*' "
        "-and $_.CommandLine -notlike '*--init*' "
        "-and $_.CommandLine -notlike '*patrol-tick*') -or "
        "($_.Name -ieq 'TripFlareDaemon.exe' "
        "-and $_.CommandLine -notlike '*--bench*' "
        "-and $_.CommandLine -notlike '*--init*' "
        "-and $_.CommandLine -notlike '*patrol-tick*') "
        "} | Measure-Object | Select-Object -ExpandProperty Count"
    )
    rc, out = run_hidden(["powershell", "-NoProfile", "-NonInteractive",
                          "-Command", script], timeout=60)
    if rc != 0:
        return False
    try:
        return int(out.strip().splitlines()[-1]) > 0
    except (ValueError, IndexError):
        return False


def last_alert_ts():
    alerts = core.read_alerts(cap=1)
    return alerts[-1].get("ts", "-") if alerts else "-"


def parse_report_meta(filename, lang="zh"):
    """Return (kind_label, formatted_time) from a review/patrol filename."""
    if lang == "en":
        kind = "Patrol" if filename.startswith("patrol-") else "AI Triage"
    else:
        kind = "例行巡逻" if filename.startswith("patrol-") else "AI 研判"
    m = re.search(r"(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})", filename)
    ts = "%s-%s-%s %s:%s:%s" % m.groups() if m else filename
    return kind, ts


def selftest():
    """Headless check used by the build verification (--selftest)."""
    enable_dpi_awareness()
    cfg = core.load_config()
    alerts = core.read_alerts()
    counts = {lv: 0 for lv in LEVELS}
    for a in alerts:
        lv = a.get("level", "info")
        counts[lv] = counts.get(lv, 0) + 1
    reviews = []
    if os.path.isdir(core.REVIEWS_DIR):
        reviews = [f for f in os.listdir(core.REVIEWS_DIR)
                   if f.endswith(".md")]
    state = core.load_state() or {}
    read_ids = core.load_read_ids()
    unread = core.unread_alerts(alerts)
    pending, total_wh = core.pending_review_alerts(10 ** 9)
    print("selftest: alerts=%d (high=%d warn=%d info=%d)"
          % (len(alerts), counts["high"], counts["warn"], counts["info"]))
    print("selftest: read=%d unread=%d pending_review=%d/%d warn+high"
          % (len(read_ids), len(unread), len(pending), total_wh))
    print("selftest: config_mode=%s backend=%s"
          % (cfg["ai"].get("mode"), core.describe_ai_backend(cfg)))
    print("selftest: reviews=%d state_files=%d rounds=%d"
          % (len(reviews), len(state.get("files", {})),
             state.get("rounds", 0)))
    print("selftest: daemon_running=%s" % daemon_running())
    samples = []
    for want in ("high", "warn", "info"):
        for a in reversed(alerts):
            if a.get("level") == want:
                samples.append(a)
                break
    for a in samples:
        print("selftest: summary[%s] %s" % (a.get("level", "?"),
                                            alert_summary(a, "zh")))
    cases = [
        ("existing-file", os.path.join(SCRIPT_DIR, "tripflare.py")),
        ("missing-file",
         os.path.join(os.path.expanduser("~"), "Downloads",
                      "ZZ_NO_SUCH_FILE_9Q.exe")),
        ("schtasks-path", r"schtasks:\TripFlareTray"),
    ]
    for name, path in cases:
        cmd, note = resolve_open_target(path, "zh")
        print("selftest: open_target[%s] cmd=%s note=%s" % (name, cmd, note))
    app = TripFlareUI(withdraw_immediately=True)
    app.update_idletasks()
    other = "en" if app.lang == "zh" else "zh"
    app._apply_language(other, persist=False)
    app.update_idletasks()
    app._apply_language("zh" if other == "en" else "en", persist=False)
    app.update_idletasks()
    app.destroy()
    print("selftest: ui_build=OK")
    print("selftest: OK")
    return 0


class TripFlareUI(tk.Tk):
    def __init__(self, start_tab=None, withdraw_immediately=False):
        super().__init__()
        self._closing = False
        self._withdraw_mode = bool(withdraw_immediately)
        if self._withdraw_mode:
            self.withdraw()
        self.cfg = core.load_config()
        self.lang = core.resolve_language(self.cfg)
        self.title(WINDOW_TITLES.get(self.lang, WINDOW_TITLES["en"]))
        self._load_icon()
        self._setup_theme()
        self._configure_geometry()

        self._daemon_is_running = None
        self._probe_inflight = False
        self._hover_tip = None
        self._sort_col = "score"
        self._sort_desc = True
        self._display_limit = DISPLAY_CAP
        self._all_alerts = []
        self._filtered_alerts = []
        self._alerts_cache = []
        self._read_ids = set()
        self._report_paths = {}
        self._start_tab = start_tab

        self._hdr_frame = None
        self._body_frame = None
        self._build_all(start_tab=start_tab)

        if not self._withdraw_mode:
            self.protocol("WM_DELETE_WINDOW", self._on_close)
            self._schedule_header_refresh()
            self._schedule_focus_check()

    def _tr(self, key):
        return I18N[self.lang][key]

    def _build_all(self, start_tab=None):
        if self._hdr_frame is not None:
            self._hdr_frame.destroy()
        if self._body_frame is not None:
            self._body_frame.destroy()
        self.title(WINDOW_TITLES.get(self.lang, WINDOW_TITLES["en"]))
        self._build_header()
        self._body_frame = ttk.Frame(self, style="App.TFrame")
        self._body_frame.pack(fill="both", expand=True, padx=12, pady=(8, 12))
        self.nb = ttk.Notebook(self._body_frame)
        self.nb.pack(fill="both", expand=True)

        self._build_alerts_tab()
        self._build_reports_tab()
        self._build_log_tab()
        self._build_config_tab()
        self._build_status_tab()

        if start_tab is not None:
            self.nb.select(start_tab)

        self.refresh_alerts()
        self.refresh_reports()
        self.refresh_log()
        self.refresh_status()

    def _toggle_language(self):
        new_lang = "en" if self.lang == "zh" else "zh"
        self._apply_language(new_lang, persist=True)

    def _apply_language(self, new_lang, persist=True):
        if new_lang not in ("zh", "en") or new_lang == self.lang:
            return
        try:
            cur_tab = self.nb.index(self.nb.select())
        except Exception:
            cur_tab = 0
        self.lang = new_lang
        if persist:
            data = {k: v for k, v in self.cfg.items()
                    if not k.startswith("_")}
            data["language"] = new_lang
            try:
                core.save_config(data, core.writable_config_path(self.cfg))
                self.cfg = core.load_config()
            except OSError:
                pass
        self._build_all(start_tab=cur_tab)

    def _on_close(self):
        self._closing = True
        self._hover_hide()
        self.destroy()

    def _load_icon(self):
        if os.path.exists(ICON_PATH):
            try:
                self.iconbitmap(ICON_PATH)
            except tk.TclError:
                pass

    def _setup_theme(self):
        try:
            scale = max(1.0, self.winfo_fpixels("1i") / 96.0)
        except tk.TclError:
            scale = 1.0
        self._scale = scale
        ui_family = "Microsoft YaHei UI" if os.name == "nt" else "Segoe UI"
        self.ui_font = tkfont.Font(family=ui_family, size=10)
        self.ui_bold = tkfont.Font(family=ui_family, size=10, weight="bold")
        self.small_font = tkfont.Font(family=ui_family, size=9)
        self.small_bold = tkfont.Font(family=ui_family, size=9, weight="bold")
        self.kpi_num_font = tkfont.Font(family=ui_family, size=20, weight="bold")
        self.title_font = tkfont.Font(family=ui_family, size=14, weight="bold")
        self.mono_font = tkfont.Font(family="Consolas", size=10)
        self.mono_small = tkfont.Font(family="Consolas", size=9)

        self.configure(bg=PALETTE["bg"])
        self.option_add("*Font", self.ui_font)

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=PALETTE["bg"],
                        foreground=PALETTE["text"], font=self.ui_font)
        style.configure("App.TFrame", background=PALETTE["bg"])
        style.configure("Card.TFrame", background=PALETTE["surface"],
                        relief="flat")
        style.configure("Surface.TLabel", background=PALETTE["surface"],
                        foreground=PALETTE["text"])
        style.configure("Muted.TLabel", background=PALETTE["surface"],
                        foreground=PALETTE["muted"], font=self.small_font)
        style.configure("Surface.TCheckbutton",
                        background=PALETTE["surface"],
                        foreground=PALETTE["text"])

        style.configure("TNotebook", background=PALETTE["bg"],
                        borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", padding=(18, 8),
                        background=PALETTE["border"],
                        foreground=PALETTE["text_sec"],
                        font=self.ui_bold, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", PALETTE["surface"]),
                              ("active", "#E8EEF7")],
                  foreground=[("selected", PALETTE["primary"]),
                              ("active", PALETTE["text"])],
                  expand=[("selected", (0, 2, 0, 0))])

        style.configure("Toolbar.TButton", padding=(9, 4),
                        background=PALETTE["surface"],
                        foreground=PALETTE["text"],
                        bordercolor=PALETTE["border_strong"],
                        lightcolor=PALETTE["surface"],
                        darkcolor=PALETTE["border"],
                        relief="solid")
        style.map("Toolbar.TButton",
                  background=[("active", PALETTE["surface_hover"]),
                              ("disabled", PALETTE["bg"])],
                  foreground=[("disabled", "#94A3B8")])

        style.configure("Primary.TButton", padding=(11, 4),
                        background=PALETTE["primary"],
                        foreground="#FFFFFF",
                        bordercolor=PALETTE["primary"],
                        lightcolor=PALETTE["primary"],
                        darkcolor=PALETTE["primary_hover"],
                        font=self.ui_bold, relief="flat")
        style.map("Primary.TButton",
                  background=[("active", PALETTE["primary_hover"]),
                              ("disabled", "#93C5FD")])

        style.configure("Accent.TButton", padding=(12, 4),
                        background=PALETTE["accent"],
                        foreground="#FFFFFF",
                        bordercolor=PALETTE["accent"],
                        lightcolor=PALETTE["accent"],
                        darkcolor=PALETTE["accent_hover"],
                        font=self.ui_bold, relief="flat")
        style.map("Accent.TButton",
                  background=[("active", PALETTE["accent_hover"]),
                              ("disabled", "#FDBA74")])

        style.configure("TEntry", fieldbackground=PALETTE["surface"],
                        bordercolor=PALETTE["border_strong"], padding=4)
        style.configure("TCombobox", fieldbackground=PALETTE["surface"],
                        background=PALETTE["surface"],
                        bordercolor=PALETTE["border_strong"], padding=4)
        style.map("TCombobox",
                  fieldbackground=[("readonly", PALETTE["surface"])],
                  selectbackground=[("readonly", PALETTE["surface"])],
                  selectforeground=[("readonly", PALETTE["text"])])

        row_h = max(28, int(round(28 * min(scale, 1.35))))
        style.configure("Treeview", background=PALETTE["surface"],
                        fieldbackground=PALETTE["surface"],
                        foreground=PALETTE["text"],
                        rowheight=row_h, borderwidth=0, relief="flat",
                        font=self.ui_font)
        style.map("Treeview",
                  background=[("selected", PALETTE["select_bg"])],
                  foreground=[("selected", PALETTE["select_fg"])])
        style.configure("Treeview.Heading", background=PALETTE["surface_alt"],
                        foreground=PALETTE["text_sec"],
                        bordercolor=PALETTE["border"],
                        padding=(8, 6), font=self.small_bold, relief="flat")
        style.map("Treeview.Heading",
                  background=[("active", "#E2E8F0")])

        style.configure("Accent.Horizontal.TProgressbar",
                        troughcolor=PALETTE["border"],
                        background=PALETTE["accent"])

    def _configure_geometry(self):
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        s = min(self._scale, 1.2)
        w = min(int(round(1180 * s)), max(920, sw - 60))
        h = min(int(round(780 * s)), max(620, sh - 80))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2 - 16)
        self.geometry("%dx%d+%d+%d" % (w, h, x, y))
        self.minsize(920, 600)

    def _schedule_focus_check(self):
        if self._closing or self._withdraw_mode:
            return
        if os.path.exists(FOCUS_REQ_PATH):
            try:
                with open(FOCUS_REQ_PATH, "r", encoding="utf-8") as fh:
                    target = fh.read().strip().lower()
                os.remove(FOCUS_REQ_PATH)
            except OSError:
                target = ""
            self.deiconify()
            self.lift()
            if target == "reports":
                self.refresh_reports()
                self.nb.select(1)
            elif target == "alerts":
                self.refresh_alerts()
                self.nb.select(0)
        self.after(1000, self._schedule_focus_check)

    # ------------------------------------------------------------------
    # Header: dark command bar with live daemon & language switch
    # ------------------------------------------------------------------

    def _build_header(self):
        hdr = tk.Frame(self, bg=PALETTE["header_bg"], padx=16, pady=10)
        hdr.pack(fill="x")
        self._hdr_frame = hdr

        left = tk.Frame(hdr, bg=PALETTE["header_bg"])
        left.pack(side="left")

        brand_row = tk.Frame(left, bg=PALETTE["header_bg"])
        brand_row.pack(anchor="w")
        tk.Label(brand_row, text="●", bg=PALETTE["header_bg"],
                 fg=PALETTE["accent"], font=self.title_font).pack(
            side="left", padx=(0, 6))
        tk.Label(brand_row, text="TripFlare", bg=PALETTE["header_bg"],
                 fg=PALETTE["header_text"], font=self.title_font).pack(
            side="left")
        tk.Label(brand_row, text=" v%s " % core.VERSION,
                 bg=PALETTE["header_panel"], fg=PALETTE["header_sub"],
                 font=self.small_font, padx=6, pady=1).pack(
            side="left", padx=(8, 0))

        right = tk.Frame(hdr, bg=PALETTE["header_bg"])
        right.pack(side="right")

        lang_btn = tk.Label(
            right, text=self._tr("lang_toggle"),
            bg=PALETTE["header_panel"], fg=PALETTE["header_text"],
            font=self.small_bold, padx=10, pady=4, cursor="hand2",
            highlightbackground="#334155", highlightthickness=1)
        lang_btn.pack(side="right", padx=(8, 0))
        lang_btn.bind("<Button-1>", lambda _e: self._toggle_language())

        self.hdr_alert = tk.Label(
            right, text="", bg=PALETTE["header_panel"],
            fg=PALETTE["header_sub"], font=self.small_font, padx=10, pady=4)
        self.hdr_alert.pack(side="right", padx=(8, 0))

        self.hdr_mode = tk.Label(
            right, text="", bg=PALETTE["header_panel"],
            fg="#93C5FD", font=self.small_bold, padx=10, pady=4)
        self.hdr_mode.pack(side="right", padx=(8, 0))

        self.hdr_daemon = tk.Label(
            right, text=self._tr("hdr_checking"), bg=PALETTE["header_panel"],
            fg=PALETTE["header_sub"], font=self.small_bold, padx=10, pady=4)
        self.hdr_daemon.pack(side="right")
        self._render_header_badges()

    def _render_header_badges(self):
        if self._daemon_is_running is True:
            self.hdr_daemon.config(
                text=self._tr("hdr_running"), bg="#064E3B", fg="#6EE7B7")
        elif self._daemon_is_running is False:
            self.hdr_daemon.config(
                text=self._tr("hdr_stopped"), bg="#334155", fg="#CBD5E1")
        else:
            self.hdr_daemon.config(
                text=self._tr("hdr_checking"), bg=PALETTE["header_panel"],
                fg=PALETTE["header_sub"])
        mode = self.cfg.get("ai", {}).get("mode", "recommend")
        self.hdr_mode.config(
            text=self._tr("hdr_mode") % MODE_I18N[self.lang].get(mode, mode))
        self.hdr_alert.config(
            text=self._tr("hdr_alert") % human_time(
                last_alert_ts(), lang=self.lang))

    def _schedule_header_refresh(self):
        if self._closing:
            return
        self._render_header_badges()
        self._probe_daemon_async()
        self.after(5000, self._schedule_header_refresh)

    def _probe_daemon_async(self):
        if self._probe_inflight or self._withdraw_mode:
            return
        self._probe_inflight = True

        def worker():
            running = daemon_running()
            if not self._closing:
                self.after(0, lambda: self._on_daemon_probed(running))

        threading.Thread(target=worker, daemon=True).start()

    def _on_daemon_probed(self, running):
        self._probe_inflight = False
        if self._closing:
            return
        changed = (self._daemon_is_running != running)
        self._daemon_is_running = running
        self._render_header_badges()
        if changed:
            self._update_status_banner()

    # ------------------------------------------------------------------
    # Tab 1: Alerts Center
    # ------------------------------------------------------------------

    def _make_kpi_card(self, parent, title, accent, on_click):
        card = tk.Frame(parent, bg=PALETTE["surface"],
                        highlightbackground=PALETTE["border"],
                        highlightthickness=1, cursor="hand2")
        stripe = tk.Frame(card, bg=accent, height=3)
        stripe.pack(fill="x")
        inner = tk.Frame(card, bg=PALETTE["surface"], padx=14, pady=8,
                         cursor="hand2")
        inner.pack(fill="both", expand=True)
        val_lbl = tk.Label(inner, text="0", bg=PALETTE["surface"],
                           fg=accent, font=self.kpi_num_font, anchor="w",
                           cursor="hand2")
        val_lbl.pack(anchor="w")
        tit_lbl = tk.Label(inner, text=title, bg=PALETTE["surface"],
                           fg=PALETTE["muted"], font=self.small_font,
                           anchor="w", cursor="hand2")
        tit_lbl.pack(anchor="w")
        for w in (card, stripe, inner, val_lbl, tit_lbl):
            w.bind("<Button-1>", lambda _e, cb=on_click: cb())
        return card, val_lbl

    def _build_alerts_tab(self):
        tab = ttk.Frame(self.nb, style="App.TFrame")
        self.nb.add(tab, text=self._tr("tab_alerts"))

        kpi_row = tk.Frame(tab, bg=PALETTE["bg"])
        kpi_row.pack(fill="x", pady=(8, 8))
        for i in range(4):
            kpi_row.columnconfigure(i, weight=1, uniform="kpi")

        c0, self.kpi_unread = self._make_kpi_card(
            kpi_row, self._tr("kpi_unread"), PALETTE["primary"],
            lambda: self._quick_filter("unread"))
        c1, self.kpi_high = self._make_kpi_card(
            kpi_row, self._tr("kpi_high"), PALETTE["danger"],
            lambda: self._quick_filter("high"))
        c2, self.kpi_warn = self._make_kpi_card(
            kpi_row, self._tr("kpi_warn"), PALETTE["warn"],
            lambda: self._quick_filter("warn"))
        c3, self.kpi_info = self._make_kpi_card(
            kpi_row, self._tr("kpi_info"), PALETTE["info"],
            lambda: self._quick_filter("info"))
        c0.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        c1.grid(row=0, column=1, sticky="ew", padx=(0, 6))
        c2.grid(row=0, column=2, sticky="ew", padx=(0, 6))
        c3.grid(row=0, column=3, sticky="ew")
        self._kpi_cards = {
            "unread": (c0, PALETTE["primary"]),
            "high": (c1, PALETTE["danger"]),
            "warn": (c2, PALETTE["warn"]),
            "info": (c3, PALETTE["info"]),
        }

        toolbar_card = tk.Frame(tab, bg=PALETTE["surface"],
                                highlightbackground=PALETTE["border"],
                                highlightthickness=1, padx=10, pady=8)
        toolbar_card.pack(fill="x", pady=(0, 8))

        filter_row = tk.Frame(toolbar_card, bg=PALETTE["surface"])
        filter_row.pack(fill="x", pady=(0, 6))

        ttk.Label(filter_row, text=self._tr("search_lbl"),
                  style="Surface.TLabel").pack(side="left", padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(
            filter_row, textvariable=self.search_var, width=24)
        self.search_entry.pack(side="left", padx=(0, 3))
        self.search_entry.bind("<KeyRelease>", lambda _e: self._apply_filters())
        ttk.Button(filter_row, text="×", style="Toolbar.TButton", width=3,
                   command=self._clear_search_only).pack(
            side="left", padx=(0, 10))

        ttk.Label(filter_row, text=self._tr("level_lbl"),
                  style="Surface.TLabel").pack(side="left", padx=(0, 4))
        self.level_filter_var = tk.StringVar(value=self._tr("lv_all"))
        lv_cb = ttk.Combobox(
            filter_row, textvariable=self.level_filter_var, state="readonly",
            width=12, values=self._tr("lv_opts"))
        lv_cb.pack(side="left", padx=(0, 8))
        lv_cb.bind("<<ComboboxSelected>>", lambda _e: self._apply_filters())

        ttk.Label(filter_row, text=self._tr("type_lbl"),
                  style="Surface.TLabel").pack(side="left", padx=(0, 4))
        self.type_filter_var = tk.StringVar(value=self._tr("tp_all"))
        tp_cb = ttk.Combobox(
            filter_row, textvariable=self.type_filter_var, state="readonly",
            width=10, values=self._tr("tp_opts"))
        tp_cb.pack(side="left", padx=(0, 8))
        tp_cb.bind("<<ComboboxSelected>>", lambda _e: self._apply_filters())

        self.unread_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            filter_row, text=self._tr("unread_chk"),
            variable=self.unread_only, style="Surface.TCheckbutton",
            command=self._apply_filters).pack(side="left", padx=(0, 8))

        ttk.Button(filter_row, text=self._tr("reset_btn"),
                   style="Toolbar.TButton",
                   command=self._clear_filters).pack(side="left")

        self.count_label = ttk.Label(
            filter_row, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")

        action_row = tk.Frame(toolbar_card, bg=PALETTE["surface"])
        action_row.pack(fill="x")

        ttk.Button(action_row, text=self._tr("btn_refresh"),
                   style="Toolbar.TButton",
                   command=self.refresh_alerts).pack(side="left", padx=(0, 5))
        self.open_dir_btn = ttk.Button(
            action_row, text=self._tr("btn_open_dir"),
            style="Toolbar.TButton",
            command=self.open_selected_dir, state="disabled")
        self.open_dir_btn.pack(side="left", padx=(0, 5))
        self.allow_path_btn = ttk.Button(
            action_row, text=self._tr("btn_allow_path"),
            style="Toolbar.TButton",
            command=self.allow_selected, state="disabled")
        self.allow_path_btn.pack(side="left", padx=(0, 5))
        self.allow_signer_btn = ttk.Button(
            action_row, text=self._tr("btn_allow_signer"),
            style="Toolbar.TButton",
            command=self.allow_selected_signer, state="disabled")
        self.allow_signer_btn.pack(side="left", padx=(0, 5))
        self.mark_read_btn = ttk.Button(
            action_row, text=self._tr("btn_mark_read"),
            style="Toolbar.TButton",
            command=self._mark_selected_read, state="disabled")
        self.mark_read_btn.pack(side="left", padx=(0, 5))
        ttk.Button(action_row, text=self._tr("btn_prune"),
                   style="Toolbar.TButton",
                   command=self.prune_noise_ui).pack(side="left", padx=(0, 5))
        ttk.Button(action_row, text=self._tr("btn_all_read"),
                   style="Toolbar.TButton",
                   command=self.mark_all_read).pack(side="left", padx=(0, 5))

        self.ai_btn = ttk.Button(
            action_row, text=self._tr("btn_ai_unread"),
            style="Accent.TButton", command=self.start_ai_review)
        self.ai_btn.pack(side="right")
        self.ai_btn.bind(
            "<Enter>", lambda _e: self._hover_show(self._tr("tip_ai_unread")))
        self.ai_btn.bind("<Leave>", lambda _e: self._hover_hide())

        self.ai_sel_btn = ttk.Button(
            action_row, text=self._tr("btn_ai_sel"),
            style="Primary.TButton",
            command=self.start_ai_review_selected, state="disabled")
        self.ai_sel_btn.pack(side="right", padx=(0, 6))
        self.ai_sel_btn.bind(
            "<Enter>", lambda _e: self._hover_show(self._tr("tip_ai_sel")))
        self.ai_sel_btn.bind("<Leave>", lambda _e: self._hover_hide())

        self.ai_label = ttk.Label(action_row, text="", style="Muted.TLabel")
        self.ai_label.pack(side="right", padx=(0, 8))
        self.ai_busy = ttk.Progressbar(
            action_row, mode="indeterminate", length=90,
            style="Accent.Horizontal.TProgressbar")

        pane = ttk.PanedWindow(tab, orient="vertical")
        pane.pack(fill="both", expand=True)

        table_card = tk.Frame(pane, bg=PALETTE["surface"],
                              highlightbackground=PALETTE["border"],
                              highlightthickness=1)
        inspector_card = tk.Frame(pane, bg=PALETTE["surface"],
                                  highlightbackground=PALETTE["border"],
                                  highlightthickness=1)
        pane.add(table_card, weight=3)
        pane.add(inspector_card, weight=2)

        cols = ("time", "level", "type", "score", "summary", "path")
        self._col_heads = {
            "time": self._tr("col_time"),
            "level": self._tr("col_level"),
            "type": self._tr("col_type"),
            "score": self._tr("col_score"),
            "summary": self._tr("col_summary"),
            "path": self._tr("col_path"),
        }
        widths = (115, 64, 108, 72, 270, 380)
        tree_wrap = tk.Frame(table_card, bg=PALETTE["surface"])
        tree_wrap.pack(fill="both", expand=True)

        self.alert_tree = ttk.Treeview(
            tree_wrap, columns=cols, show="headings", selectmode="extended")
        for col, width in zip(cols, widths):
            self.alert_tree.heading(
                col, text=self._col_heads[col],
                command=lambda c=col: self._sort_by(c))
            self.alert_tree.column(
                col, width=width, minwidth=50, stretch=(col == "path"),
                anchor="center" if col in ("level", "score") else "w")
        self._update_heading_arrows()

        self.alert_tree.tag_configure("high", foreground=PALETTE["danger"])
        self.alert_tree.tag_configure("warn", foreground=PALETTE["warn_text"])
        self.alert_tree.tag_configure("info", foreground=PALETTE["info"])
        self.alert_tree.tag_configure("odd", background=PALETTE["surface_alt"])
        self.alert_tree.tag_configure("high_unread",
                                      foreground="#B91C1C",
                                      background=PALETTE["danger_bg"],
                                      font=self.ui_bold)
        self.alert_tree.tag_configure("unread", font=self.ui_bold)

        self.alert_tree.bind("<<TreeviewSelect>>", self._on_alert_select)
        self.alert_tree.bind("<Double-Button-1>", self._on_alert_double)
        self.alert_tree.bind("<Button-3>", self._on_alert_rightclick)

        vscroll = ttk.Scrollbar(tree_wrap, orient="vertical",
                                command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=vscroll.set)
        vscroll.pack(side="right", fill="y")
        self.alert_tree.pack(side="left", fill="both", expand=True)

        self.load_more_bar = tk.Frame(
            table_card, bg=PALETTE["surface_alt"], padx=10, pady=4)
        self.load_more_lbl = ttk.Label(
            self.load_more_bar, text="", style="Muted.TLabel")
        self.load_more_lbl.pack(side="left")
        ttk.Button(self.load_more_bar, text=self._tr("load_all"),
                   style="Toolbar.TButton",
                   command=self._load_all_alerts).pack(side="right")

        self._build_inspector(inspector_card)

    def _build_inspector(self, card):
        hdr = tk.Frame(card, bg=PALETTE["surface_alt"], padx=12, pady=6)
        hdr.pack(fill="x")
        self.insp_badge = tk.Label(
            hdr, text=self._tr("insp_none"), bg=PALETTE["border"],
            fg=PALETTE["text_sec"], font=self.small_bold, padx=8, pady=2)
        self.insp_badge.pack(side="left", padx=(0, 8))
        self.insp_title = tk.Label(
            hdr, text=self._tr("insp_title"), bg=PALETTE["surface_alt"],
            fg=PALETTE["text"], font=self.ui_bold, anchor="w")
        self.insp_title.pack(side="left", fill="x", expand=True)

        self.insp_json_btn = ttk.Button(
            hdr, text=self._tr("insp_raw"), style="Toolbar.TButton",
            command=self._open_selected_json, state="disabled")
        self.insp_json_btn.pack(side="right", padx=(6, 0))
        self.insp_copy_btn = ttk.Button(
            hdr, text=self._tr("insp_copy"), style="Toolbar.TButton",
            command=self._copy_selected_path, state="disabled")
        self.insp_copy_btn.pack(side="right")

        tk.Frame(card, bg=PALETTE["border"], height=1).pack(fill="x")

        txt_wrap = tk.Frame(card, bg=PALETTE["surface"])
        txt_wrap.pack(fill="both", expand=True)
        self.insp_text = tk.Text(
            txt_wrap, wrap="word", state="disabled", bd=0, padx=12, pady=8,
            bg=PALETTE["surface"], fg=PALETTE["text"], font=self.ui_font,
            height=6)
        iscroll = ttk.Scrollbar(txt_wrap, orient="vertical",
                                command=self.insp_text.yview)
        self.insp_text.configure(yscrollcommand=iscroll.set)
        iscroll.pack(side="right", fill="y")
        self.insp_text.pack(side="left", fill="both", expand=True)
        self.insp_text.tag_configure(
            "k", foreground=PALETTE["muted"], font=self.small_bold)
        self.insp_text.tag_configure(
            "v", foreground=PALETTE["text"], font=self.mono_font)
        self.insp_text.tag_configure(
            "reason", foreground=PALETTE["text"], font=self.ui_font)
        self.insp_text.tag_configure(
            "hint", foreground=PALETTE["muted"], font=self.ui_font)
        self._render_inspector(None)

    def _quick_filter(self, kind):
        if kind == "unread":
            active = (self.unread_only.get()
                      and self.level_filter_var.get() == self._tr("lv_all"))
            self.unread_only.set(not active)
            self.level_filter_var.set(self._tr("lv_all"))
        else:
            target_lv = {
                "high": self._tr("lv_high"),
                "warn": self._tr("lv_warn"),
                "info": self._tr("lv_info"),
            }[kind]
            active = (not self.unread_only.get()
                      and self.level_filter_var.get() == target_lv)
            self.unread_only.set(False)
            self.level_filter_var.set(
                self._tr("lv_all") if active else target_lv)
        self._display_limit = DISPLAY_CAP
        self._apply_filters()

    def _update_kpi_active(self):
        active_key = None
        lv = self.level_filter_var.get()
        if self.unread_only.get() and lv == self._tr("lv_all"):
            active_key = "unread"
        elif not self.unread_only.get():
            active_key = {
                self._tr("lv_high"): "high",
                self._tr("lv_warn"): "warn",
                self._tr("lv_info"): "info",
            }.get(lv)
        for key, (card, accent) in self._kpi_cards.items():
            if key == active_key:
                card.config(highlightthickness=2, highlightbackground=accent)
            else:
                card.config(highlightthickness=1,
                            highlightbackground=PALETTE["border"])

    def _clear_search_only(self):
        self.search_var.set("")
        self._apply_filters()

    def _clear_filters(self):
        self.search_var.set("")
        self.level_filter_var.set(self._tr("lv_all"))
        self.type_filter_var.set(self._tr("tp_all"))
        self.unread_only.set(False)
        self._display_limit = DISPLAY_CAP
        self._apply_filters()

    def _sort_by(self, col):
        if self._sort_col == col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = col
            self._sort_desc = col in ("time", "level", "score")
        self._update_heading_arrows()
        self._apply_filters()

    def _update_heading_arrows(self):
        for col, base in self._col_heads.items():
            arrow = ""
            if col == self._sort_col:
                arrow = " ▼" if self._sort_desc else " ▲"
            self.alert_tree.heading(col, text=base + arrow)

    def _load_all_alerts(self):
        self._display_limit = 10 ** 9
        self._render_alert_rows()

    def refresh_alerts(self):
        self._all_alerts = core.read_alerts()
        self._read_ids = core.load_read_ids()
        self._update_kpis()
        self._apply_filters()

    def _update_kpis(self):
        counts = {"high": 0, "warn": 0, "info": 0, "unread": 0}
        for a in self._all_alerts:
            lv = a.get("level", "info")
            counts[lv] = counts.get(lv, 0) + 1
            if core.alert_id(a) not in self._read_ids:
                counts["unread"] += 1
        self.kpi_unread.config(text=str(counts["unread"]))
        self.kpi_high.config(text=str(counts["high"]))
        self.kpi_warn.config(text=str(counts["warn"]))
        self.kpi_info.config(text=str(counts["info"]))

    def _matches_type_group(self, alert, group):
        if group == self._tr("tp_all"):
            return True
        tp = alert.get("type", "")
        if group == self._tr("tp_file"):
            return tp.startswith("file_")
        if group == self._tr("tp_proc"):
            return tp.startswith("process_")
        if group == self._tr("tp_reg"):
            return tp.startswith("registry_")
        if group == self._tr("tp_svc"):
            return tp.startswith("service_")
        if group == self._tr("tp_task"):
            return tp.startswith("task_")
        if group == self._tr("tp_ifeo"):
            return tp.startswith("ifeo_")
        return True

    def _apply_filters(self):
        self._update_kpi_active()
        q = self.search_var.get().strip().lower()
        lv_opt = self.level_filter_var.get()
        tp_opt = self.type_filter_var.get()
        unread_only = self.unread_only.get()

        filtered = []
        for a in self._all_alerts:
            if unread_only and core.alert_id(a) in self._read_ids:
                continue
            lv = a.get("level", "info")
            if lv_opt == self._tr("lv_wh") and lv not in ("high", "warn"):
                continue
            elif lv_opt == self._tr("lv_high") and lv != "high":
                continue
            elif lv_opt == self._tr("lv_warn") and lv != "warn":
                continue
            elif lv_opt == self._tr("lv_info") and lv != "info":
                continue
            if not self._matches_type_group(a, tp_opt):
                continue
            if q:
                hay = " ".join((
                    a.get("path", ""),
                    a.get("signer") or "",
                    a.get("orig_filename") or "",
                    alert_summary(a, self.lang),
                    " ".join(a.get("reasons") or []),
                    " ".join(translate_reason(r, "zh")
                             for r in (a.get("reasons") or [])),
                )).lower()
                if q not in hay:
                    continue
            filtered.append(a)

        self._sort_alert_list(filtered)
        self._filtered_alerts = filtered
        self._render_alert_rows()

    def _sort_alert_list(self, alerts):
        col = self._sort_col
        desc = self._sort_desc
        tp_map = TYPE_I18N[self.lang]

        def key_fn(a):
            if col == "time":
                return a.get("epoch", 0)
            if col == "level":
                return (LEVEL_ORDER.get(a.get("level", "info"), 0),
                        a.get("epoch", 0))
            if col == "type":
                return tp_map.get(a.get("type"), a.get("type", ""))
            if col == "score":
                return (a.get("score") or 0, a.get("epoch", 0))
            if col == "summary":
                return alert_summary(a, self.lang).lower()
            return a.get("path", "").lower()

        alerts.sort(key=key_fn, reverse=desc)

    def _render_alert_rows(self):
        self.alert_tree.delete(*self.alert_tree.get_children())
        total_match = len(self._filtered_alerts)
        shown = self._filtered_alerts[:self._display_limit]
        self._alerts_cache = shown

        lv_map = LEVEL_SHORT_I18N[self.lang]
        tp_map = TYPE_I18N[self.lang]

        for idx, a in enumerate(shown):
            lv = a.get("level", "info")
            unread = core.alert_id(a) not in self._read_ids
            when = human_time(a.get("ts"), lang=self.lang)
            if unread:
                when = "● " + when
            tags = [lv]
            if lv == "high" and unread:
                tags.append("high_unread")
            else:
                if idx % 2 == 1:
                    tags.append("odd")
                if unread:
                    tags.append("unread")
            self.alert_tree.insert(
                "", "end", iid=str(idx),
                values=(
                    when,
                    lv_map.get(lv, lv),
                    tp_map.get(a.get("type"), a.get("type", "")),
                    a.get("score", ""),
                    alert_summary(a, self.lang),
                    a.get("path", ""),
                ),
                tags=tags,
            )

        self.count_label.config(
            text=self._tr("count_fmt") % (total_match, len(self._all_alerts)))
        if total_match > len(shown):
            self.load_more_lbl.config(
                text=self._tr("cap_fmt") % (len(shown), total_match))
            self.load_more_bar.pack(fill="x", side="bottom")
        else:
            self.load_more_bar.pack_forget()
        self._update_action_states()
        self._render_inspector(None)

    def _render_inspector(self, alert, sel_count=0):
        self.insp_text.config(state="normal")
        self.insp_text.delete("1.0", "end")
        if alert is None:
            self.insp_badge.config(
                text=self._tr("insp_none"), bg=PALETTE["border"],
                fg=PALETTE["text_sec"])
            self.insp_title.config(text=self._tr("insp_title"))
            self.insp_copy_btn.config(state="disabled")
            self.insp_json_btn.config(state="disabled")
            self.insp_text.insert("end", self._tr("insp_hint"), "hint")
            self.insp_text.config(state="disabled")
            return

        lv = alert.get("level", "info")
        badge_colors = {
            "high": (PALETTE["danger"], "#FFFFFF"),
            "warn": (PALETTE["warn"], "#FFFFFF"),
            "info": ("#64748B", "#FFFFFF"),
        }
        bg, fg = badge_colors.get(lv, ("#64748B", "#FFFFFF"))
        lv_lbl = LEVEL_I18N[self.lang].get(lv, lv)
        self.insp_badge.config(
            text=self._tr("insp_score_badge") % (lv_lbl,
                                                 alert.get("score", "?")),
            bg=bg, fg=fg,
        )
        tp_label = TYPE_I18N[self.lang].get(
            alert.get("type"), alert.get("type", ""))
        extra_sel = (self._tr("insp_sel_n") % sel_count
                     if sel_count > 1 else "")
        self.insp_title.config(
            text="%s  |  %s  |  %s%s" % (
                object_name(alert), tp_label, alert.get("ts", "-"),
                extra_sel))
        self.insp_copy_btn.config(state="normal")
        self.insp_json_btn.config(state="normal")

        def add_kv(key, val):
            self.insp_text.insert("end", key + ": ", "k")
            self.insp_text.insert("end", str(val) + "\n", "v")

        add_kv(self._tr("insp_path"), alert.get("path", "-"))
        extra = alert.get("extra") or {}
        target = extra.get("target") or extra.get("image") or extra.get("data")
        if target and target != alert.get("path"):
            add_kv(self._tr("insp_target"), target)
        sig_status = alert.get("sig_status")
        signer = alert.get("signer")
        if sig_status or signer:
            sig_lbl = SIG_STATUS_I18N[self.lang].get(
                sig_status, sig_status or ("Unknown" if self.lang == "en"
                                           else "未知"))
            add_kv(self._tr("insp_sig"), "%s%s" % (
                sig_lbl, " — %s" % signer if signer else ""))
        if alert.get("orig_filename"):
            add_kv(self._tr("insp_orig"), alert.get("orig_filename"))
        if alert.get("sha1"):
            add_kv("SHA1", "%s%s" % (
                alert["sha1"],
                self._tr("insp_size_suffix") % format_size(extra.get("size"))))
        elif extra.get("size") is not None:
            add_kv(self._tr("insp_size"), format_size(extra.get("size")))
        reasons = alert.get("reasons") or []
        if reasons:
            self.insp_text.insert("end", self._tr("insp_reasons"), "k")
            for r in reasons:
                self.insp_text.insert(
                    "end",
                    "  • " + translate_reason(r, self.lang) + "\n",
                    "reason")
        self.insp_text.config(state="disabled")

    # ---------------- selection & read/unread handling ----------------

    def _selected_alerts(self):
        out = []
        for iid in self.alert_tree.selection():
            try:
                idx = int(iid)
            except ValueError:
                continue
            if 0 <= idx < len(self._alerts_cache):
                out.append(self._alerts_cache[idx])
        return out

    def _selected_alert(self):
        alerts = self._selected_alerts()
        return alerts[0] if alerts else None

    def _on_alert_select(self, _event=None):
        alerts = self._selected_alerts()
        self._update_action_states()
        self._render_inspector(
            alerts[0] if alerts else None, sel_count=len(alerts))

    def _update_action_states(self):
        alerts = self._selected_alerts()
        has_sel = bool(alerts)
        first = alerts[0] if alerts else None
        can_open = False
        if first is not None:
            path = ((first.get("extra") or {}).get("target")
                    or first.get("path") or "")
            cmd, _ = resolve_open_target(path, self.lang)
            can_open = cmd is not None
        can_signer = any(
            a.get("sig_status") == "Valid" and (a.get("signer") or "").strip()
            for a in alerts)
        has_unread = any(
            core.alert_id(a) not in self._read_ids for a in alerts)

        self.open_dir_btn.config(state="normal" if can_open else "disabled")
        self.allow_path_btn.config(state="normal" if has_sel else "disabled")
        self.allow_signer_btn.config(
            state="normal" if can_signer else "disabled")
        self.mark_read_btn.config(state="normal" if has_unread else "disabled")
        if str(self.ai_btn.cget("text")) == self._tr("btn_ai_unread"):
            self.ai_sel_btn.config(state="normal" if has_sel else "disabled")

    def _update_row_read_visuals(self, iids):
        for iid in iids:
            try:
                idx = int(iid)
                alert = self._alerts_cache[idx]
            except (ValueError, IndexError):
                continue
            aid = core.alert_id(alert)
            unread = aid not in self._read_ids
            values = list(self.alert_tree.item(iid, "values"))
            if values:
                when = str(values[0])
                clean_when = when[2:] if when.startswith("● ") else when
                values[0] = ("● " + clean_when) if unread else clean_when
            lv = alert.get("level", "info")
            tags = [lv]
            if lv == "high" and unread:
                tags.append("high_unread")
            else:
                if idx % 2 == 1:
                    tags.append("odd")
                if unread:
                    tags.append("unread")
            self.alert_tree.item(iid, values=values, tags=tags)

    def _mark_selected_read(self):
        alerts = self._selected_alerts()
        if not alerts:
            return
        ids = [core.alert_id(a) for a in alerts]
        core.mark_alerts_read(ids)
        self._read_ids.update(ids)
        self._update_kpis()
        if self.unread_only.get():
            self._apply_filters()
        else:
            self._update_row_read_visuals(self.alert_tree.selection())
            self._update_action_states()

    def _mark_selected_unread(self):
        alerts = self._selected_alerts()
        if not alerts:
            return
        ids = [core.alert_id(a) for a in alerts]
        core.unmark_alerts_read(ids)
        for i in ids:
            self._read_ids.discard(i)
        self._update_kpis()
        self._update_row_read_visuals(self.alert_tree.selection())
        self._update_action_states()

    def mark_all_read(self):
        core.mark_alerts_read([core.alert_id(a)
                               for a in core.read_alerts()])
        self.refresh_alerts()

    # ---------------- details / navigation ----------------

    def _on_alert_double(self, event):
        iid = self.alert_tree.identify_row(event.y)
        if not iid:
            return
        alert = self._alerts_cache[int(iid)]
        self.show_alert_details(alert)

    def _on_alert_rightclick(self, event):
        iid = self.alert_tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self.alert_tree.selection():
            self.alert_tree.selection_set(iid)
        alerts = self._selected_alerts()
        first = alerts[0]
        path = ((first.get("extra") or {}).get("target")
                or first.get("path") or "")
        cmd, _note = resolve_open_target(path, self.lang)
        can_signer = any(
            a.get("sig_status") == "Valid" and (a.get("signer") or "").strip()
            for a in alerts)
        has_unread = any(
            core.alert_id(a) not in self._read_ids for a in alerts)
        has_read = any(
            core.alert_id(a) in self._read_ids for a in alerts)

        menu = tk.Menu(self, tearoff=0)
        ai_lbl = (self._tr("ctx_ai_n") % len(alerts)
                  if len(alerts) > 1 else self._tr("ctx_ai_1"))
        menu.add_command(label=ai_lbl, command=self.start_ai_review_selected)
        menu.add_command(label=self._tr("ctx_open_dir"),
                         command=self.open_selected_dir,
                         state="normal" if cmd is not None else "disabled")
        menu.add_command(label=self._tr("ctx_copy"),
                         command=self._copy_selected_path)
        menu.add_separator()
        menu.add_command(label=self._tr("ctx_allow_path"),
                         command=self.allow_selected)
        menu.add_command(
            label=self._tr("ctx_allow_signer"),
            command=self.allow_selected_signer,
            state="normal" if can_signer else "disabled")
        menu.add_separator()
        menu.add_command(
            label=self._tr("ctx_mark_read"),
            command=self._mark_selected_read,
            state="normal" if has_unread else "disabled")
        menu.add_command(
            label=self._tr("ctx_mark_unread"),
            command=self._mark_selected_unread,
            state="normal" if has_read else "disabled")
        menu.add_command(label=self._tr("ctx_raw"),
                         command=self._open_selected_json)
        menu.post(event.x_root, event.y_root)

    def _show_tooltip(self, x, y, msg):
        tip = tk.Toplevel(self)
        tip.overrideredirect(True)
        tip.attributes("-topmost", True)
        tk.Label(tip, text=msg, background="#1E293B", foreground="#F8FAFC",
                 relief="solid", borderwidth=1, padx=8, pady=4,
                 font=self.small_font).pack()
        tip.geometry("+%d+%d" % (x + 10, y + 10))
        tip.after(1600, tip.destroy)
        return tip

    def _hover_show(self, msg):
        self._hover_hide()
        tip = tk.Toplevel(self)
        tip.overrideredirect(True)
        tip.attributes("-topmost", True)
        tk.Label(tip, text=msg, background="#1E293B", foreground="#F8FAFC",
                 relief="solid", borderwidth=1, padx=8, pady=4,
                 font=self.small_font).pack()
        tip.geometry("+%d+%d" % (self.winfo_pointerx() + 12,
                                 self.winfo_pointery() + 12))
        self._hover_tip = tip

    def _hover_hide(self):
        if self._hover_tip is not None:
            try:
                self._hover_tip.destroy()
            except tk.TclError:
                pass
            self._hover_tip = None

    def _copy_selected_path(self):
        alert = self._selected_alert()
        if alert is None:
            return
        path = ((alert.get("extra") or {}).get("target")
                or alert.get("path") or "")
        self.clipboard_clear()
        self.clipboard_append(path)
        self._show_tooltip(
            self.winfo_pointerx(), self.winfo_pointery(), self._tr("copied"))

    def _open_selected_json(self):
        alert = self._selected_alert()
        if alert is not None:
            self.show_alert_details(alert)

    def show_alert_details(self, alert):
        lv = alert.get("level", "info")
        lv_lbl = LEVEL_I18N[self.lang].get(lv, lv)
        tp_lbl = TYPE_I18N[self.lang].get(
            alert.get("type"), alert.get("type", ""))
        if self.lang == "en":
            lines = [
                "Time: %s" % alert.get("ts", "-"),
                "Level: %s    Score: %s" % (lv_lbl, alert.get("score", "?")),
                "Type: %s" % tp_lbl,
                "Path: %s" % alert.get("path", ""),
                "",
                "Risk Signals:",
            ]
        else:
            lines = [
                "时间: %s" % alert.get("ts", "-"),
                "级别: %s    风险分: %s" % (lv_lbl, alert.get("score", "?")),
                "类型: %s" % tp_lbl,
                "路径: %s" % alert.get("path", ""),
                "",
                "风险依据:",
            ]
        for reason in alert.get("reasons", []):
            lines.append("  - " + translate_reason(reason, self.lang))
        if alert.get("orig_filename"):
            lines.append("%s: %s" % (
                self._tr("insp_orig"), alert["orig_filename"]))
        if alert.get("sha1"):
            lines.append("SHA1: " + alert["sha1"])
        if alert.get("signer"):
            lines.append("%s: %s" % (
                "Signer" if self.lang == "en" else "签名者", alert["signer"]))
        if alert.get("sig_status"):
            sig_lbl = SIG_STATUS_I18N[self.lang].get(
                alert["sig_status"], alert["sig_status"])
            lines.append("%s: %s" % (
                self._tr("insp_sig"), sig_lbl))
        extra = alert.get("extra") or {}
        if extra:
            lines += ["", self._tr("dlg_extra"),
                      json.dumps(extra, ensure_ascii=False, indent=2)]
        raw = json.dumps(alert, ensure_ascii=False, indent=2)
        dlg = tk.Toplevel(self)
        dlg.title(self._tr("dlg_title"))
        dlg.geometry("720x540")
        dlg.configure(bg=PALETTE["bg"])
        text = tk.Text(dlg, wrap="word", font=self.mono_font,
                       bg=PALETTE["surface"], fg=PALETTE["text"],
                       padx=12, pady=10, bd=0)
        text.pack(fill="both", expand=True, padx=10, pady=(10, 6))
        text.insert("1.0", "\n".join(lines) + "\n\n%s\n%s" % (
            self._tr("dlg_raw"), raw))
        text.config(state="disabled")

        def copy_json():
            self.clipboard_clear()
            self.clipboard_append(raw)

        bar = ttk.Frame(dlg, style="App.TFrame")
        bar.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bar, text=self._tr("dlg_copy_raw"),
                   style="Primary.TButton",
                   command=copy_json).pack(side="left")
        ttk.Button(bar, text=self._tr("dlg_close"), style="Toolbar.TButton",
                   command=dlg.destroy).pack(side="right")

    def open_selected_dir(self):
        alert = self._selected_alert()
        if alert is None:
            return
        target = ((alert.get("extra") or {}).get("target")
                  or alert.get("path") or "")
        cmd, note = resolve_open_target(target, self.lang)
        if cmd is None:
            self._show_tooltip(
                self.winfo_pointerx(), self.winfo_pointery(), note)
            return
        subprocess.Popen(cmd)
        if note:
            self._show_tooltip(
                self.winfo_pointerx(), self.winfo_pointery(), note)

    def _post_allowlist_cleanup(self, added_label):
        matched = [a for a in self._all_alerts
                   if core.alert_matches_allowlist(a, self.cfg)]
        if not matched:
            msg = ("Added to allowlist:\n%s" if self.lang == "en"
                   else "已加入白名单:\n%s") % added_label
            messagebox.showinfo(self._tr("btn_allow_path"), msg)
            return
        if self.lang == "en":
            title = "Clean Matching History"
            body = ("Added to allowlist:\n%s\n\n"
                    "%d existing alert(s) match this rule:\n"
                    "• Yes: Remove matching historical alerts\n"
                    "• No: Keep records and mark them read\n"
                    "• Cancel: Keep allowlist only"
                    % (added_label, len(matched)))
        else:
            title = "联动处理历史告警"
            body = ("已加入白名单:\n%s\n\n"
                    "当前列表中共有 %d 条匹配该白名单规则的历史告警：\n"
                    "• 点击「是」：直接从告警列表中清理这些历史记录\n"
                    "• 点击「否」：保留记录并全部标为已读\n"
                    "• 点击「取消」：仅保存白名单，不改动历史记录"
                    % (added_label, len(matched)))
        ans = messagebox.askyesnocancel(title, body)
        if ans is True:
            core.cleanup_allowlisted_alerts(self.cfg, delete_records=True)
            self.refresh_alerts()
            self.refresh_status()
        elif ans is False:
            core.cleanup_allowlisted_alerts(self.cfg, delete_records=False)
            self.refresh_alerts()

    def allow_selected(self):
        alerts = self._selected_alerts()
        if not alerts:
            return
        targets = []
        for a in alerts:
            t = (a.get("extra") or {}).get("target") or a.get("path")
            if t and t not in targets:
                targets.append(t)
        if not targets:
            return
        preview = "\n".join(targets[:5])
        if len(targets) > 5:
            preview += ("\n... (%d items)" if self.lang == "en"
                        else "\n…等共 %d 项") % len(targets)
        prompt = ("Add these path(s) to allowlist?\n\n%s" if self.lang == "en"
                  else "将以下路径或目标加入白名单？\n\n%s") % preview
        if not messagebox.askyesno(self._tr("btn_allow_path"), prompt):
            return
        lst = self.cfg["allowlist"]["paths"]
        for t in targets:
            if t not in lst:
                lst.append(t)
        try:
            core.save_config(self.cfg, core.writable_config_path(self.cfg))
        except OSError as exc:
            messagebox.showerror(self._tr("btn_allow_path"), str(exc))
            return
        self.load_config_form()
        self._post_allowlist_cleanup(preview)

    def allow_selected_signer(self):
        alerts = self._selected_alerts()
        signers = []
        for a in alerts:
            if a.get("sig_status") == "Valid":
                s = (a.get("signer") or "").strip()
                if s and s not in signers:
                    signers.append(s)
        if not signers:
            return
        preview = "\n".join(signers[:5])
        prompt = ("Trust these verified signer(s)?\n\n%s" if self.lang == "en"
                  else "将以下已验证签名者加入白名单？\n\n%s") % preview
        if not messagebox.askyesno(self._tr("btn_allow_signer"), prompt):
            return
        lst = self.cfg["allowlist"]["signers"]
        for s in signers:
            if s not in lst:
                lst.append(s)
        try:
            core.save_config(self.cfg, core.writable_config_path(self.cfg))
        except OSError as exc:
            messagebox.showerror(self._tr("btn_allow_signer"), str(exc))
            return
        self.load_config_form()
        self._post_allowlist_cleanup(preview)

    def prune_noise_ui(self):
        if self.lang == "en":
            title = "Prune OS Background Noise"
            ask = ("Remove historical false alarms from Windows component "
                   "servicing, per-session system services, and browser updates "
                   "(backups are saved automatically).\n\nContinue?")
        else:
            title = "清理历史系统误报"
            ask = ("将清理历史记录中由系统组件维护、后台服务及浏览器更新产生的误报"
                   "（原文件会自动备份），个人文件与真实异常将完整保留。\n\n是否继续？")
        if not messagebox.askyesno(title, ask):
            return
        removed, kept, _removed_u = core.prune_historical_noise()
        self.refresh_alerts()
        self.refresh_status()
        if self.lang == "en":
            done = "Removed %d background noise alerts; %d alerts kept." % (
                removed, kept)
        else:
            done = "清理完成：已移除历史系统误报 %d 条，当前保留有效记录 %d 条。" % (
                removed, kept)
        messagebox.showinfo(title, done)

    # ------------------------------------------------------------------
    # AI review (background thread, unread-batch & selected items)
    # ------------------------------------------------------------------

    def start_ai_review(self):
        cap = int(self.cfg["ai"].get("review_max_alerts", 20))
        unread_wh, total_wh = core.unread_warn_high_alerts()
        if not unread_wh:
            msg = (
                "No unread Warn/High alerts (%d total reviewed).\n\n"
                "Tip: Select any row and click 'Triage Selected' to re-analyze."
                % total_wh
                if self.lang == "en" else
                "当前没有未读的中/高危告警（历史中/高危共 %d 条，均已处理）。\n\n"
                "提示：如需重新研判某条已读告警，请在列表中选中后点击「研判选中项」。"
                % total_wh)
            messagebox.showinfo(self._tr("btn_ai_unread"), msg)
            return
        batch = unread_wh[-cap:]
        if self.lang == "en":
            if len(unread_wh) > len(batch):
                msg = ("%d unread Warn/High alerts found. Send the newest %d "
                       "(batch cap) to %s and mark them read?"
                       % (len(unread_wh), len(batch),
                          core.describe_ai_backend(self.cfg)))
            else:
                msg = ("Send %d unread Warn/High alert(s) to %s and mark "
                       "them read?"
                       % (len(batch), core.describe_ai_backend(self.cfg)))
        else:
            if len(unread_wh) > len(batch):
                msg = ("当前共有 %d 条未读的中/高危告警，本次将按单次上限截取最新的 %d 条"
                       "送交 AI 研判（低危不送审，完成后自动标为已读）。\n\n是否继续？"
                       % (len(unread_wh), len(batch)))
            else:
                msg = ("当前共有 %d 条未读的中/高危告警，本次将全部送交 AI 研判"
                       "（低危不送审，完成后自动标为已读）。\n\n是否继续？"
                       % len(batch))
        if not messagebox.askyesno(self._tr("btn_ai_unread"), msg):
            return
        self._launch_ai_worker(batch)

    def start_ai_review_selected(self):
        alerts = self._selected_alerts()
        if not alerts:
            return
        cap = int(self.cfg["ai"].get("review_max_alerts", 20))
        batch = alerts[:cap]
        if self.lang == "en":
            msg = ("Send %d selected alert(s) to %s for AI triage?"
                   % (len(batch), core.describe_ai_backend(self.cfg)))
        else:
            if len(alerts) > cap:
                msg = ("已选中 %d 条告警（单次上限 %d 条），本次将送交其中前 %d 条"
                       "进行 AI 研判（不限已读状态，完成后自动标为已读）。是否继续？"
                       % (len(alerts), cap, len(batch)))
            else:
                msg = ("确定将选中的 %d 条告警送交 AI 研判？\n"
                       "（支持已读/未读，完成后将自动标为已读）" % len(batch))
        if not messagebox.askyesno(self._tr("btn_ai_sel"), msg):
            return
        self._launch_ai_worker(batch)

    def _launch_ai_worker(self, alerts):
        self.ai_btn.config(state="disabled", text=self._tr("btn_ai_busy"))
        self.ai_sel_btn.config(state="disabled")
        self.ai_label.config(
            text=("Triaging %d alert(s)..." if self.lang == "en"
                  else "AI 研判进行中（%d 条），请稍候…") % len(alerts))
        self.ai_busy.pack(side="right", padx=(0, 8))
        self.ai_busy.start(10)
        threading.Thread(target=self._ai_worker, args=(alerts, self.lang),
                         daemon=True).start()

    def _ai_worker(self, alerts, lang):
        cfg = core.load_config()
        state = core.load_state()
        err = path = None
        n = len(alerts)
        if state is None:
            err = ("No baseline yet. Rebuild baseline in the Status tab first."
                   if lang == "en"
                   else "尚未建立基线（请先在“运行状态”页重建安全基线）")
        elif not alerts:
            err = "No alerts"
        else:
            prompt = core.build_review_prompt(alerts, cfg=cfg, lang=lang)
            report, err = core.call_ai(cfg, prompt)
            if not err:
                if lang == "en":
                    header = ("# TripFlare AI Review Report\n\n- time: %s\n"
                              "- alerts supplied: %d\n\n"
                              % (core.now_iso(), n))
                else:
                    header = ("# TripFlare AI 研判报告\n\n- 生成时间: %s\n"
                              "- 送审告警数: %d\n\n" % (core.now_iso(), n))
                path = core.save_review("review", header + report + "\n")
                core.mark_alerts_read([core.alert_id(a) for a in alerts])
                state["ai"]["last_review"] = time.time()
                state["ai"]["calls_today"] = \
                    state["ai"].get("calls_today", 0) + 1
                core.save_state(state)
        if not self._closing:
            self.after(0, lambda: self._ai_done(err, path, n))

    def _ai_done(self, err, path, n):
        self.ai_busy.stop()
        self.ai_busy.pack_forget()
        self.ai_btn.config(state="normal", text=self._tr("btn_ai_unread"))
        self._update_action_states()
        if err:
            self.ai_label.config(text="")
            messagebox.showwarning(self._tr("btn_ai_unread"), err)
            return
        self.ai_label.config(
            text=("Done (%d alerts)" if self.lang == "en"
                  else "研判完成（%d 条告警）") % n)
        self.refresh_alerts()
        self.refresh_reports(select=os.path.basename(path))
        self.nb.select(1)

    # ------------------------------------------------------------------
    # Tab 2: Reports (Markdown-styled reader)
    # ------------------------------------------------------------------

    def _build_reports_tab(self):
        tab = ttk.Frame(self.nb, style="App.TFrame")
        self.nb.add(tab, text=self._tr("tab_reports"))

        pane = ttk.PanedWindow(tab, orient="horizontal")
        pane.pack(fill="both", expand=True, pady=(8, 0))

        left = tk.Frame(pane, bg=PALETTE["surface"],
                        highlightbackground=PALETTE["border"],
                        highlightthickness=1)
        right = tk.Frame(pane, bg=PALETTE["surface"],
                         highlightbackground=PALETTE["border"],
                         highlightthickness=1)
        pane.add(left, weight=1)
        pane.add(right, weight=3)

        l_bar = tk.Frame(left, bg=PALETTE["surface_alt"], padx=10, pady=8)
        l_bar.pack(fill="x")
        tk.Label(l_bar, text=self._tr("rep_list_title"),
                 bg=PALETTE["surface_alt"], fg=PALETTE["text"],
                 font=self.ui_bold).pack(side="left")
        ttk.Button(l_bar, text=self._tr("btn_refresh"),
                   style="Toolbar.TButton",
                   command=self.refresh_reports).pack(side="right")
        tk.Frame(left, bg=PALETTE["border"], height=1).pack(fill="x")

        self.report_tree = ttk.Treeview(
            left, columns=("kind", "time"), show="headings",
            selectmode="browse")
        self.report_tree.heading("kind", text=self._tr("rep_kind"))
        self.report_tree.heading("time", text=self._tr("rep_time"))
        self.report_tree.column("kind", width=85, anchor="center",
                                stretch=False)
        self.report_tree.column("time", width=165, anchor="w", stretch=True)
        rscroll = ttk.Scrollbar(left, orient="vertical",
                                command=self.report_tree.yview)
        self.report_tree.configure(yscrollcommand=rscroll.set)
        rscroll.pack(side="right", fill="y")
        self.report_tree.pack(fill="both", expand=True)
        self.report_tree.bind("<<TreeviewSelect>>", self.show_report)
        self.report_tree.bind("<Double-Button-1>", self.open_report_external)

        r_bar = tk.Frame(right, bg=PALETTE["surface_alt"], padx=12, pady=8)
        r_bar.pack(fill="x")
        self.report_title_lbl = tk.Label(
            r_bar, text=self._tr("rep_body_title"),
            bg=PALETTE["surface_alt"], fg=PALETTE["text"],
            font=self.ui_bold, anchor="w")
        self.report_title_lbl.pack(side="left", fill="x", expand=True)
        ttk.Button(r_bar, text=self._tr("rep_open_ext"),
                   style="Toolbar.TButton",
                   command=self.open_report_external).pack(side="right")
        tk.Frame(right, bg=PALETTE["border"], height=1).pack(fill="x")

        vwrap = tk.Frame(right, bg=PALETTE["surface"])
        vwrap.pack(fill="both", expand=True)
        self.report_view = tk.Text(
            vwrap, wrap="word", state="disabled", bd=0, padx=16, pady=12,
            bg=PALETTE["surface"], fg=PALETTE["text"], font=self.ui_font,
            spacing1=2, spacing3=3)
        rvscroll = ttk.Scrollbar(vwrap, orient="vertical",
                                 command=self.report_view.yview)
        self.report_view.configure(yscrollcommand=rvscroll.set)
        rvscroll.pack(side="right", fill="y")
        self.report_view.pack(side="left", fill="both", expand=True)

        self.report_view.tag_configure(
            "h1", font=(self.ui_font.cget("family"), 14, "bold"),
            foreground=PALETTE["primary"], spacing1=6, spacing3=6)
        self.report_view.tag_configure(
            "h2", font=(self.ui_font.cget("family"), 11, "bold"),
            foreground=PALETTE["text"], spacing1=8, spacing3=3)
        self.report_view.tag_configure(
            "bold", font=self.ui_bold, foreground=PALETTE["text"])
        self.report_view.tag_configure(
            "code", font=self.mono_small, background="#F1F5F9",
            foreground="#0F172A")
        self.report_view.tag_configure(
            "meta", foreground=PALETTE["muted"], font=self.small_font)
        self.report_view.tag_configure(
            "verdict_ok", foreground=PALETTE["ok_dark"],
            background=PALETTE["ok_bg"], font=self.ui_bold)
        self.report_view.tag_configure(
            "verdict_warn", foreground=PALETTE["warn_text"],
            background=PALETTE["warn_bg"], font=self.ui_bold)
        self.report_view.tag_configure(
            "verdict_high", foreground=PALETTE["danger"],
            background=PALETTE["danger_bg"], font=self.ui_bold)

    def refresh_reports(self, select=None):
        self.report_tree.delete(*self.report_tree.get_children())
        self._report_paths = {}
        names = []
        if os.path.isdir(core.REVIEWS_DIR):
            names = sorted((f for f in os.listdir(core.REVIEWS_DIR)
                            if f.endswith(".md")), reverse=True)
        for name in names:
            kind, ts = parse_report_meta(name, lang=self.lang)
            self._report_paths[name] = os.path.join(core.REVIEWS_DIR, name)
            self.report_tree.insert("", "end", iid=name, values=(kind, ts))
        target = select if (select and select in names) else (
            names[0] if names else None)
        if target:
            self.report_tree.selection_set(target)
            self.report_tree.see(target)
            self.show_report()
        else:
            self.report_title_lbl.config(text=self._tr("rep_none"))

    def _selected_report(self):
        sel = self.report_tree.selection()
        if not sel:
            return None
        return self._report_paths.get(sel[0])

    def show_report(self, _event=None):
        path = self._selected_report()
        if not path:
            return
        self.report_title_lbl.config(text=os.path.basename(path))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            text = "%s" % exc
        self.report_view.config(state="normal")
        self.report_view.delete("1.0", "end")
        in_code = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                self.report_view.insert("end", "  " + line + "\n", "code")
                continue
            if stripped.startswith("# "):
                self.report_view.insert("end", stripped[2:] + "\n", "h1")
                continue
            if re.match(r"^[•\-\s]*##+\s+", stripped):
                clean = re.sub(r"^[•\-\s]*##+\s+", "", stripped)
                self.report_view.insert("end", clean + "\n", "h2")
                continue
            if stripped.startswith(("- time:", "- alerts",
                                    "- 生成时间:", "- 送审告警数:")):
                self.report_view.insert("end", stripped + "\n", "meta")
                continue
            self._insert_md_line(line + "\n")
        self.report_view.config(state="disabled")

    def _insert_md_line(self, line):
        parts = re.split(r"(\*\*[^*]+\*\*)", line)
        low_line = line.lower()
        verdict_tag = None
        if "verdict" in low_line or "裁决" in line or "判定" in line:
            if ("high" in low_line or "critical" in low_line
                    or "高危" in line):
                verdict_tag = "verdict_high"
            elif "suspicious" in low_line or "可疑" in line:
                verdict_tag = "verdict_warn"
            elif "benign" in low_line or "正常" in line:
                verdict_tag = "verdict_ok"
        for p in parts:
            if p.startswith("**") and p.endswith("**") and len(p) > 4:
                self.report_view.insert("end", p[2:-2], "bold")
            elif verdict_tag and any(
                    w in p.lower() for w in (
                        "benign", "suspicious", "high", "critical",
                        "正常", "可疑", "高危")):
                self.report_view.insert("end", p, verdict_tag)
            else:
                self.report_view.insert("end", p)

    def open_report_external(self, _event=None):
        path = self._selected_report()
        if path and os.path.exists(path):
            os.startfile(path)

    # ------------------------------------------------------------------
    # Tab 3: Log Viewer
    # ------------------------------------------------------------------

    def _build_log_tab(self):
        tab = ttk.Frame(self.nb, style="App.TFrame")
        self.nb.add(tab, text=self._tr("tab_log"))

        bar_card = tk.Frame(tab, bg=PALETTE["surface"],
                            highlightbackground=PALETTE["border"],
                            highlightthickness=1, padx=10, pady=8)
        bar_card.pack(fill="x", pady=(8, 8))

        ttk.Button(bar_card, text=self._tr("btn_refresh"),
                   style="Toolbar.TButton",
                   command=self.refresh_log).pack(side="left", padx=(0, 8))
        self.log_auto = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            bar_card, text=self._tr("log_auto"), variable=self.log_auto,
            style="Surface.TCheckbutton",
            command=self._log_auto_tick).pack(side="left", padx=(0, 14))

        ttk.Label(bar_card, text=self._tr("log_filter"),
                  style="Surface.TLabel").pack(side="left", padx=(0, 4))
        self.log_filter_var = tk.StringVar()
        log_ent = ttk.Entry(
            bar_card, textvariable=self.log_filter_var, width=24)
        log_ent.pack(side="left", padx=(0, 8))
        log_ent.bind("<KeyRelease>", lambda _e: self.refresh_log())

        self.log_level_var = tk.StringVar(value=self._tr("log_all"))
        log_cb = ttk.Combobox(
            bar_card, textvariable=self.log_level_var, state="readonly",
            width=12, values=self._tr("log_opts"))
        log_cb.pack(side="left")
        log_cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh_log())

        ttk.Button(bar_card, text=self._tr("log_open"),
                   style="Toolbar.TButton",
                   command=self._open_log_file).pack(side="right")

        term_card = tk.Frame(tab, bg=PALETTE["log_bg"],
                             highlightbackground=PALETTE["border_strong"],
                             highlightthickness=1)
        term_card.pack(fill="both", expand=True)

        self.log_view = tk.Text(
            term_card, wrap="none", state="disabled", bd=0, padx=12, pady=10,
            bg=PALETTE["log_bg"], fg=PALETTE["log_fg"],
            insertbackground="#FFFFFF", font=self.mono_small)
        ly = ttk.Scrollbar(term_card, orient="vertical",
                           command=self.log_view.yview)
        lx = ttk.Scrollbar(term_card, orient="horizontal",
                           command=self.log_view.xview)
        self.log_view.configure(yscrollcommand=ly.set, xscrollcommand=lx.set)
        ly.pack(side="right", fill="y")
        lx.pack(side="bottom", fill="x")
        self.log_view.pack(side="left", fill="both", expand=True)

        self.log_view.tag_configure("ts", foreground="#94A3B8")
        self.log_view.tag_configure("high", foreground="#F87171")
        self.log_view.tag_configure("warn", foreground="#FBBF24")
        self.log_view.tag_configure("err", foreground="#FB7185")
        self.log_view.tag_configure("info", foreground="#CBD5E1")

    def refresh_log(self):
        try:
            with open(core.LOG_PATH, "r", encoding="utf-8",
                      errors="replace") as fh:
                lines = fh.readlines()[-500:]
        except OSError:
            lines = [self._tr("log_empty")]
        kw = self.log_filter_var.get().strip().lower()
        lv = self.log_level_var.get()
        shown = []
        for line in lines:
            low = line.lower()
            if lv == self._tr("log_alerts") and " alert " not in low:
                continue
            if lv == self._tr("log_errs") and not any(
                    k in low for k in ("fail", "error", "crash", "traceback")):
                continue
            if kw and kw not in low:
                continue
            shown.append(line)

        self.log_view.config(state="normal")
        self.log_view.delete("1.0", "end")
        for line in shown:
            low = line.lower()
            tag = "info"
            if any(k in low for k in ("fail", "error", "crash", "traceback")):
                tag = "err"
            elif " alert high " in low:
                tag = "high"
            elif " alert warn " in low:
                tag = "warn"
            if len(line) > 20 and line[4:5] == "-" and line[10:11] == "T":
                self.log_view.insert("end", line[:20], "ts")
                self.log_view.insert("end", line[20:], tag)
            else:
                self.log_view.insert("end", line, tag)
        self.log_view.see("end")
        self.log_view.config(state="disabled")

    def _log_auto_tick(self):
        if self._closing:
            return
        if self.log_auto.get():
            self.refresh_log()
            self.after(5000, self._log_auto_tick)

    def _open_log_file(self):
        if os.path.exists(core.LOG_PATH):
            os.startfile(core.LOG_PATH)

    # ------------------------------------------------------------------
    # Tab 4: Config, Allowlist & Exclusions Manager
    # ------------------------------------------------------------------

    def _build_config_tab(self):
        tab = ttk.Frame(self.nb, style="App.TFrame")
        self.nb.add(tab, text=self._tr("tab_config"))

        split = tk.Frame(tab, bg=PALETTE["bg"])
        split.pack(fill="both", expand=True, pady=(8, 0))
        split.columnconfigure(0, weight=2)
        split.columnconfigure(1, weight=3)
        split.rowconfigure(0, weight=1)

        left = tk.Frame(split, bg=PALETTE["surface"],
                        highlightbackground=PALETTE["border"],
                        highlightthickness=1, padx=16, pady=12)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        tk.Label(left, text=self._tr("cfg_left_title"), bg=PALETTE["surface"],
                 fg=PALETTE["text"], font=self.ui_bold).pack(
            anchor="w", pady=(0, 8))

        form = tk.Frame(left, bg=PALETTE["surface"])
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        self.var_interval = tk.StringVar()
        self.var_warn_th = tk.StringVar()
        self.var_high_th = tk.StringVar()
        self.var_realtime = tk.BooleanVar(value=True)
        self.var_noise_filter = tk.BooleanVar(value=True)
        self.var_mode = tk.StringVar()
        self.var_provider = tk.StringVar()
        self.var_api_base = tk.StringVar()
        self.var_api_key = tk.StringVar()
        self.var_model = tk.StringVar()
        self.var_backend = tk.StringVar()
        self.var_review_max = tk.StringVar()
        self.var_maxcalls = tk.StringVar()
        self.var_patrol = tk.StringVar()

        self._mode_d2k = dict(MODE_CHOICES_I18N[self.lang])
        self._mode_k2d = {k: d for d, k in MODE_CHOICES_I18N[self.lang]}
        self._prov_d2k = dict(PROVIDER_CHOICES_I18N[self.lang])
        self._prov_k2d = {k: d for d, k in PROVIDER_CHOICES_I18N[self.lang]}

        r = 0
        ttk.Label(form, text=self._tr("cfg_interval"),
                  style="Surface.TLabel").grid(
            row=r, column=0, sticky="w", pady=3, padx=(0, 10))
        ttk.Entry(form, textvariable=self.var_interval, width=22).grid(
            row=r, column=1, sticky="ew", pady=3)
        r += 1

        ttk.Label(form, text=self._tr("cfg_thresh"),
                  style="Surface.TLabel").grid(
            row=r, column=0, sticky="w", pady=3, padx=(0, 10))
        th_box = tk.Frame(form, bg=PALETTE["surface"])
        th_box.grid(row=r, column=1, sticky="ew", pady=3)
        th_box.columnconfigure(0, weight=1)
        th_box.columnconfigure(2, weight=1)
        ttk.Entry(th_box, textvariable=self.var_warn_th, width=8).grid(
            row=0, column=0, sticky="ew")
        ttk.Label(th_box, text=" / ", style="Surface.TLabel").grid(
            row=0, column=1)
        ttk.Entry(th_box, textvariable=self.var_high_th, width=8).grid(
            row=0, column=2, sticky="ew")
        r += 1

        simple_rows = [
            (self._tr("cfg_mode"), self.var_mode,
             [d for d, _ in MODE_CHOICES_I18N[self.lang]], None),
            (self._tr("cfg_provider"), self.var_provider,
             [d for d, _ in PROVIDER_CHOICES_I18N[self.lang]], None),
            (self._tr("cfg_api_base"), self.var_api_base, None, None),
            (self._tr("cfg_api_key"), self.var_api_key, None, "•"),
            (self._tr("cfg_model"), self.var_model, None, None),
            (self._tr("cfg_cli"), self.var_backend, None, None),
        ]
        for label, var, choices, mask in simple_rows:
            ttk.Label(form, text=label, style="Surface.TLabel").grid(
                row=r, column=0, sticky="w", pady=3, padx=(0, 10))
            if choices:
                ttk.Combobox(
                    form, textvariable=var, values=choices,
                    state="readonly", width=22).grid(
                    row=r, column=1, sticky="ew", pady=3)
            else:
                kw = {"show": mask} if mask else {}
                ttk.Entry(form, textvariable=var, width=24, **kw).grid(
                    row=r, column=1, sticky="ew", pady=3)
            r += 1

        ttk.Label(form, text=self._tr("cfg_limits"),
                  style="Surface.TLabel").grid(
            row=r, column=0, sticky="w", pady=3, padx=(0, 10))
        lim_box = tk.Frame(form, bg=PALETTE["surface"])
        lim_box.grid(row=r, column=1, sticky="ew", pady=3)
        lim_box.columnconfigure(0, weight=1)
        lim_box.columnconfigure(2, weight=1)
        ttk.Entry(lim_box, textvariable=self.var_review_max, width=8).grid(
            row=0, column=0, sticky="ew")
        ttk.Label(lim_box, text=" / ", style="Surface.TLabel").grid(
            row=0, column=1)
        ttk.Entry(lim_box, textvariable=self.var_maxcalls, width=8).grid(
            row=0, column=2, sticky="ew")
        r += 1

        ttk.Label(form, text=self._tr("cfg_patrol"),
                  style="Surface.TLabel").grid(
            row=r, column=0, sticky="w", pady=3, padx=(0, 10))
        ttk.Entry(form, textvariable=self.var_patrol, width=22).grid(
            row=r, column=1, sticky="ew", pady=3)

        ttk.Checkbutton(
            left, text=self._tr("cfg_realtime"),
            variable=self.var_realtime, style="Surface.TCheckbutton").pack(
            anchor="w", pady=(8, 2))
        ttk.Checkbutton(
            left, text=self._tr("cfg_noise"),
            variable=self.var_noise_filter, style="Surface.TCheckbutton").pack(
            anchor="w", pady=(2, 6))

        ttk.Button(left, text=self._tr("cfg_save"), style="Primary.TButton",
                   command=self.save_config_form).pack(
            anchor="w", pady=(8, 0))

        right = tk.Frame(split, bg=PALETTE["surface"],
                         highlightbackground=PALETTE["border"],
                         highlightthickness=1, padx=12, pady=12)
        right.grid(row=0, column=1, sticky="nsew")

        sub_nb = ttk.Notebook(right)
        sub_nb.pack(fill="both", expand=True)

        allow_tab = ttk.Frame(sub_nb, style="Card.TFrame")
        excl_tab = ttk.Frame(sub_nb, style="Card.TFrame")
        json_tab = ttk.Frame(sub_nb, style="Card.TFrame")
        sub_nb.add(allow_tab, text=self._tr("sub_allow"))
        sub_nb.add(excl_tab, text=self._tr("sub_excl"))
        sub_nb.add(json_tab, text=self._tr("sub_adv"))

        self._build_allowlist_subtab(allow_tab)
        self._build_exclusions_subtab(excl_tab)
        self._build_json_subtab(json_tab)
        self.load_config_form()

    def _build_allowlist_subtab(self, parent):
        tk.Label(parent, text=self._tr("allow_signer_lbl"),
                 bg=PALETTE["surface"], fg=PALETTE["text"],
                 font=self.small_bold).pack(anchor="w", padx=6, pady=(8, 4))
        s_add = tk.Frame(parent, bg=PALETTE["surface"])
        s_add.pack(fill="x", padx=6, pady=(0, 4))
        self.new_signer_var = tk.StringVar()
        ttk.Entry(s_add, textvariable=self.new_signer_var).pack(
            side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(s_add, text=self._tr("btn_add"), style="Toolbar.TButton",
                   command=self._add_allow_signer).pack(
            side="left", padx=(0, 4))
        ttk.Button(s_add, text=self._tr("btn_del"), style="Toolbar.TButton",
                   command=self._del_allow_signer).pack(side="left")

        self.allow_signer_list = tk.Listbox(
            parent, height=5, bd=1, relief="solid",
            highlightthickness=0, font=self.mono_small,
            selectbackground=PALETTE["select_bg"],
            selectforeground=PALETTE["select_fg"])
        self.allow_signer_list.pack(fill="both", expand=True, padx=6,
                                    pady=(0, 10))

        tk.Label(parent, text=self._tr("allow_path_lbl"),
                 bg=PALETTE["surface"], fg=PALETTE["text"],
                 font=self.small_bold).pack(anchor="w", padx=6, pady=(2, 4))
        p_add = tk.Frame(parent, bg=PALETTE["surface"])
        p_add.pack(fill="x", padx=6, pady=(0, 4))
        self.new_path_var = tk.StringVar()
        ttk.Entry(p_add, textvariable=self.new_path_var).pack(
            side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(p_add, text=self._tr("btn_browse"), style="Toolbar.TButton",
                   command=lambda: self._browse_dir_into(
                       self.new_path_var)).pack(side="left", padx=(0, 4))
        ttk.Button(p_add, text=self._tr("btn_add"), style="Toolbar.TButton",
                   command=self._add_allow_path).pack(side="left", padx=(0, 4))
        ttk.Button(p_add, text=self._tr("btn_del"), style="Toolbar.TButton",
                   command=self._del_allow_path).pack(side="left")

        self.allow_path_list = tk.Listbox(
            parent, height=6, bd=1, relief="solid",
            highlightthickness=0, font=self.mono_small,
            selectbackground=PALETTE["select_bg"],
            selectforeground=PALETTE["select_fg"])
        self.allow_path_list.pack(fill="both", expand=True, padx=6,
                                  pady=(0, 6))

    def _build_exclusions_subtab(self, parent):
        tk.Label(parent, text=self._tr("excl_hint"),
                 bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=self.small_font).pack(anchor="w", padx=6, pady=(8, 6))
        row = tk.Frame(parent, bg=PALETTE["surface"])
        row.pack(fill="x", padx=6, pady=(0, 6))
        self.new_excl_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.new_excl_var).pack(
            side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(row, text=self._tr("btn_browse"), style="Toolbar.TButton",
                   command=lambda: self._browse_dir_into(
                       self.new_excl_var)).pack(side="left", padx=(0, 4))
        ttk.Button(row, text=self._tr("btn_add"), style="Toolbar.TButton",
                   command=self._add_excl_dir).pack(side="left", padx=(0, 4))
        ttk.Button(row, text=self._tr("btn_del"), style="Toolbar.TButton",
                   command=self._del_excl_dir).pack(side="left")

        self.excl_dir_list = tk.Listbox(
            parent, bd=1, relief="solid", highlightthickness=0,
            font=self.mono_small,
            selectbackground=PALETTE["select_bg"],
            selectforeground=PALETTE["select_fg"])
        self.excl_dir_list.pack(fill="both", expand=True, padx=6, pady=(0, 6))

    def _build_json_subtab(self, parent):
        tk.Label(parent, text=self._tr("adv_hint"),
                 bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=self.small_font).pack(anchor="w", padx=6, pady=(8, 4))
        wrap = tk.Frame(parent, bg=PALETTE["surface"])
        wrap.pack(fill="both", expand=True, padx=6, pady=4)
        self.cfg_text = tk.Text(
            wrap, wrap="none", font=self.mono_small, bd=1, relief="solid")
        cy = ttk.Scrollbar(wrap, orient="vertical", command=self.cfg_text.yview)
        cx = ttk.Scrollbar(wrap, orient="horizontal",
                           command=self.cfg_text.xview)
        self.cfg_text.configure(yscrollcommand=cy.set, xscrollcommand=cx.set)
        cy.pack(side="right", fill="y")
        cx.pack(side="bottom", fill="x")
        self.cfg_text.pack(side="left", fill="both", expand=True)

        bar = tk.Frame(parent, bg=PALETTE["surface"])
        bar.pack(fill="x", padx=6, pady=(6, 4))
        ttk.Button(bar, text=self._tr("adv_save"), style="Primary.TButton",
                   command=self.save_config_json).pack(side="left")

    def _browse_dir_into(self, var):
        chosen = filedialog.askdirectory()
        if chosen:
            var.set(os.path.normpath(chosen))

    def _add_allow_signer(self):
        val = self.new_signer_var.get().strip()
        if not val:
            return
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        signers = data.setdefault("allowlist", {}).setdefault("signers", [])
        if val not in signers:
            signers.append(val)
            if self._save_config_dict(data):
                self.new_signer_var.set("")
                self.load_config_form()

    def _del_allow_signer(self):
        sel = self.allow_signer_list.curselection()
        if not sel:
            return
        target = self.allow_signer_list.get(sel[0])
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        signers = data.setdefault("allowlist", {}).setdefault("signers", [])
        if target in signers:
            signers.remove(target)
            if self._save_config_dict(data):
                self.load_config_form()

    def _add_allow_path(self):
        val = self.new_path_var.get().strip()
        if not val:
            return
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        paths = data.setdefault("allowlist", {}).setdefault("paths", [])
        if val not in paths:
            paths.append(val)
            if self._save_config_dict(data):
                self.new_path_var.set("")
                self.load_config_form()

    def _del_allow_path(self):
        sel = self.allow_path_list.curselection()
        if not sel:
            return
        target = self.allow_path_list.get(sel[0])
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        paths = data.setdefault("allowlist", {}).setdefault("paths", [])
        if target in paths:
            paths.remove(target)
            if self._save_config_dict(data):
                self.load_config_form()

    def _add_excl_dir(self):
        val = self.new_excl_var.get().strip()
        if not val:
            return
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        excls = data.setdefault("exclude_dirs", [])
        if val not in excls:
            excls.append(val)
            if self._save_config_dict(data):
                self.new_excl_var.set("")
                self.load_config_form()

    def _del_excl_dir(self):
        sel = self.excl_dir_list.curselection()
        if not sel:
            return
        target = self.excl_dir_list.get(sel[0])
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        excls = data.setdefault("exclude_dirs", [])
        if target in excls:
            excls.remove(target)
            if self._save_config_dict(data):
                self.load_config_form()

    def load_config_form(self):
        self.cfg = core.load_config()
        ai = self.cfg["ai"]
        th = self.cfg.get("score_thresholds", {})
        self.var_interval.set(str(self.cfg.get("interval_seconds", 60)))
        self.var_warn_th.set(str(th.get("warn", 3)))
        self.var_high_th.set(str(th.get("high", 7)))
        self.var_realtime.set(bool(self.cfg.get("realtime_watch", True)))
        self.var_noise_filter.set(
            bool(self.cfg.get("system_noise_filter", True)))

        mode_key = ai.get("mode", "recommend")
        self.var_mode.set(self._mode_k2d.get(
            mode_key, MODE_CHOICES_I18N[self.lang][0][0]))
        prov_key = ai.get("provider", "auto")
        self.var_provider.set(self._prov_k2d.get(
            prov_key, PROVIDER_CHOICES_I18N[self.lang][0][0]))
        self.var_api_base.set(str(ai.get("api_base", "")))
        self.var_api_key.set(str(ai.get("api_key", "")))
        self.var_model.set(str(ai.get("model", "")))
        self.var_backend.set(str(ai.get("backend_path", "auto")))
        self.var_review_max.set(str(ai.get("review_max_alerts", 20)))
        self.var_maxcalls.set(str(ai.get("max_calls_per_day", 20)))
        self.var_patrol.set(str(ai.get("patrol_interval_minutes", 30)))

        self.allow_signer_list.delete(0, "end")
        for s in self.cfg.get("allowlist", {}).get("signers", []):
            self.allow_signer_list.insert("end", s)
        self.allow_path_list.delete(0, "end")
        for p in self.cfg.get("allowlist", {}).get("paths", []):
            self.allow_path_list.insert("end", p)
        self.excl_dir_list.delete(0, "end")
        for d in self.cfg.get("exclude_dirs") or []:
            self.excl_dir_list.insert("end", d)

        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        self.cfg_text.delete("1.0", "end")
        self.cfg_text.insert("1.0", json.dumps(data, ensure_ascii=False,
                                               indent=2))
        self._render_header_badges()

    def _save_config_dict(self, data):
        path = core.writable_config_path(self.cfg)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
        except OSError as exc:
            messagebox.showerror(self._tr("tab_config").strip(), str(exc))
            return False
        self.cfg = core.load_config()
        self._render_header_badges()
        msg = ("Saved to:\n%s" if self.lang == "en" else "已保存到:\n%s") % path
        messagebox.showinfo(self._tr("tab_config").strip(), msg)
        return True

    def save_config_form(self):
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        try:
            data["interval_seconds"] = max(10, int(self.var_interval.get()))
            warn_t = int(self.var_warn_th.get())
            high_t = int(self.var_high_th.get())
            if warn_t >= high_t:
                messagebox.showerror(
                    self._tr("tab_config").strip(),
                    "Warn threshold must be < High threshold."
                    if self.lang == "en" else "中危阈值必须小于高危阈值。")
                return
            review_max = int(self.var_review_max.get())
            if not (1 <= review_max <= 200):
                messagebox.showerror(
                    self._tr("tab_config").strip(),
                    "Batch limit must be between 1 and 200."
                    if self.lang == "en" else "单次研判条数上限应在 1 到 200 之间。")
                return
            data["score_thresholds"] = {"warn": warn_t, "high": high_t}
            data["ai"]["review_max_alerts"] = review_max
            data["ai"]["max_calls_per_day"] = int(self.var_maxcalls.get())
            data["ai"]["patrol_interval_minutes"] = int(
                self.var_patrol.get())
        except ValueError:
            messagebox.showerror(
                self._tr("tab_config").strip(),
                "Interval / thresholds / limits must be integers."
                if self.lang == "en" else "间隔/阈值/上限必须是整数。")
            return
        data["realtime_watch"] = bool(self.var_realtime.get())
        data["system_noise_filter"] = bool(self.var_noise_filter.get())
        mode_raw = self.var_mode.get()
        prov_raw = self.var_provider.get()
        data["ai"]["mode"] = self._mode_d2k.get(mode_raw, mode_raw)
        data["ai"]["provider"] = self._prov_d2k.get(prov_raw, prov_raw)
        data["ai"]["api_base"] = self.var_api_base.get().strip()
        data["ai"]["api_key"] = self.var_api_key.get().strip()
        data["ai"]["model"] = self.var_model.get().strip()
        data["ai"]["backend_path"] = self.var_backend.get().strip() or "auto"
        if self._save_config_dict(data):
            self.load_config_form()
            self.refresh_status()

    def save_config_json(self):
        raw = self.cfg_text.get("1.0", "end").strip()
        try:
            data = json.loads(raw)
        except ValueError as exc:
            messagebox.showerror(
                self._tr("tab_config").strip(),
                ("Invalid JSON:\n%s" if self.lang == "en"
                 else "JSON 非法，未写入:\n%s") % exc)
            return
        if not isinstance(data, dict):
            messagebox.showerror(
                self._tr("tab_config").strip(),
                "Top level must be a JSON object."
                if self.lang == "en" else "顶层必须是 JSON 对象。")
            return
        if self._save_config_dict(data):
            self.load_config_form()
            self.refresh_status()

    # ------------------------------------------------------------------
    # Tab 5: Status Dashboard
    # ------------------------------------------------------------------

    def _make_stat_tile(self, parent, title, accent):
        tile = tk.Frame(parent, bg=PALETTE["surface"],
                        highlightbackground=PALETTE["border"],
                        highlightthickness=1, padx=14, pady=10)
        val = tk.Label(tile, text="-", bg=PALETTE["surface"], fg=accent,
                       font=self.kpi_num_font, anchor="w")
        val.pack(anchor="w")
        lbl = tk.Label(tile, text=title, bg=PALETTE["surface"],
                       fg=PALETTE["muted"], font=self.small_font, anchor="w")
        lbl.pack(anchor="w")
        return tile, val

    def _build_status_tab(self):
        tab = ttk.Frame(self.nb, style="App.TFrame")
        self.nb.add(tab, text=self._tr("tab_status"))

        banner = tk.Frame(tab, bg=PALETTE["surface"],
                          highlightbackground=PALETTE["border"],
                          highlightthickness=1, padx=16, pady=12)
        banner.pack(fill="x", pady=(8, 10))
        self.st_banner_dot = tk.Label(
            banner, text="●", bg=PALETTE["surface"], fg=PALETTE["muted"],
            font=self.title_font)
        self.st_banner_dot.pack(side="left", padx=(0, 8))
        info_col = tk.Frame(banner, bg=PALETTE["surface"])
        info_col.pack(side="left", fill="x", expand=True)
        self.st_banner_title = tk.Label(
            info_col, text=self._tr("st_chk"), bg=PALETTE["surface"],
            fg=PALETTE["text"], font=self.ui_bold, anchor="w")
        self.st_banner_title.pack(anchor="w")
        self.st_banner_sub = tk.Label(
            info_col, text="", bg=PALETTE["surface"], fg=PALETTE["muted"],
            font=self.small_font, anchor="w")
        self.st_banner_sub.pack(anchor="w", pady=(2, 0))

        tk.Label(tab, text=self._tr("st_cov"), bg=PALETTE["bg"],
                 fg=PALETTE["text_sec"], font=self.small_bold).pack(
            anchor="w", pady=(2, 6))
        grid1 = tk.Frame(tab, bg=PALETTE["bg"])
        grid1.pack(fill="x", pady=(0, 10))
        for i in range(5):
            grid1.columnconfigure(i, weight=1, uniform="st1")

        self._st_tiles = {}
        specs1 = [
            ("files", self._tr("st_files"), PALETTE["primary"]),
            ("registry", self._tr("st_reg"), PALETTE["primary"]),
            ("tasks", self._tr("st_tasks"), PALETTE["primary"]),
            ("services", self._tr("st_svc"), PALETTE["primary"]),
            ("processes", self._tr("st_proc"), PALETTE["primary"]),
        ]
        for idx, (key, title, col) in enumerate(specs1):
            t, v = self._make_stat_tile(grid1, title, col)
            t.grid(row=0, column=idx, sticky="ew",
                   padx=(0, 8 if idx < 4 else 0))
            self._st_tiles[key] = v

        tk.Label(tab, text=self._tr("st_health"), bg=PALETTE["bg"],
                 fg=PALETTE["text_sec"], font=self.small_bold).pack(
            anchor="w", pady=(2, 6))
        grid2 = tk.Frame(tab, bg=PALETTE["bg"])
        grid2.pack(fill="x", pady=(0, 12))
        for i in range(4):
            grid2.columnconfigure(i, weight=1, uniform="st2")

        specs2 = [
            ("rounds", self._tr("st_rounds"), PALETTE["text"]),
            ("round_sec", self._tr("st_sec"), PALETTE["ok_dark"]),
            ("ai_calls", self._tr("st_calls"), PALETTE["accent"]),
            ("pending_wh", self._tr("st_pending"), PALETTE["danger"]),
        ]
        for idx, (key, title, col) in enumerate(specs2):
            t, v = self._make_stat_tile(grid2, title, col)
            t.grid(row=0, column=idx, sticky="ew",
                   padx=(0, 8 if idx < 3 else 0))
            self._st_tiles[key] = v

        ctl_card = tk.Frame(tab, bg=PALETTE["surface"],
                            highlightbackground=PALETTE["border"],
                            highlightthickness=1, padx=16, pady=12)
        ctl_card.pack(fill="both", expand=True)

        self.st_meta_lbl = tk.Label(
            ctl_card, text="", bg=PALETTE["surface"], fg=PALETTE["text_sec"],
            font=self.mono_small, justify="left", anchor="nw")
        self.st_meta_lbl.pack(fill="x", pady=(0, 12))

        bar = tk.Frame(ctl_card, bg=PALETTE["surface"])
        bar.pack(fill="x", side="bottom")
        ttk.Button(bar, text=self._tr("btn_start"), style="Primary.TButton",
                   command=lambda: self._daemon_task("run")).pack(
            side="left", padx=(0, 6))
        ttk.Button(bar, text=self._tr("btn_stop"), style="Toolbar.TButton",
                   command=lambda: self._daemon_task("end")).pack(
            side="left", padx=(0, 6))
        self.scan_btn = ttk.Button(
            bar, text=self._tr("btn_scan"), style="Toolbar.TButton",
            command=self.start_scan_round)
        self.scan_btn.pack(side="left", padx=(0, 6))
        self.init_btn = ttk.Button(
            bar, text=self._tr("btn_init"), style="Toolbar.TButton",
            command=self.start_rebuild_baseline)
        self.init_btn.pack(side="left", padx=(0, 6))
        ttk.Button(bar, text=self._tr("btn_prune"), style="Toolbar.TButton",
                   command=self.prune_noise_ui).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text=self._tr("btn_datadir"), style="Toolbar.TButton",
                   command=lambda: os.startfile(DATA_DIR)).pack(
            side="left", padx=(0, 6))
        ttk.Button(bar, text=self._tr("btn_refresh"), style="Toolbar.TButton",
                   command=self.refresh_status).pack(side="right")

    def _update_status_banner(self):
        if not hasattr(self, "st_banner_title"):
            return
        if self._daemon_is_running is True:
            self.st_banner_dot.config(fg=PALETTE["ok"])
            self.st_banner_title.config(text=self._tr("st_run"))
        elif self._daemon_is_running is False:
            self.st_banner_dot.config(fg=PALETTE["muted"])
            self.st_banner_title.config(text=self._tr("st_stop"))
        else:
            self.st_banner_dot.config(fg=PALETTE["muted"])
            self.st_banner_title.config(text=self._tr("st_chk"))

    def refresh_status(self):
        self.cfg = core.load_config()
        state = core.load_state()
        self._update_status_banner()
        self._probe_daemon_async()

        mode = self.cfg["ai"].get("mode", "recommend")
        rt_on = self._tr("on") if self.cfg.get(
            "realtime_watch", True) else self._tr("off")
        noise_on = self._tr("on") if self.cfg.get(
            "system_noise_filter", True) else self._tr("off")
        self.st_banner_sub.config(
            text=self._tr("st_sub") % (
                MODE_I18N[self.lang].get(mode, mode), rt_on, noise_on,
                self.cfg.get("interval_seconds", 60)))

        if state:
            ai = state.get("ai", {})
            unread_wh, _total = core.unread_warn_high_alerts()
            self._st_tiles["files"].config(text=str(len(state.get("files", {}))))
            self._st_tiles["registry"].config(
                text=str(len(state.get("registry", {}))))
            self._st_tiles["tasks"].config(text=str(len(state.get("tasks", []))))
            self._st_tiles["services"].config(
                text=str(len(state.get("services", {}))))
            self._st_tiles["processes"].config(
                text=str(len(state.get("processes", {}))))
            self._st_tiles["rounds"].config(text=str(state.get("rounds", 0)))
            self._st_tiles["round_sec"].config(
                text="%.2fs" % state.get("last_round_seconds", 0))
            self._st_tiles["ai_calls"].config(
                text="%d / %d" % (ai.get("calls_today", 0),
                                  self.cfg["ai"].get("max_calls_per_day", 20)))
            self._st_tiles["pending_wh"].config(text=str(len(unread_wh)))
            if self.lang == "en":
                meta = [
                    "Data Dir : %s" % DATA_DIR,
                    "Config   : %s" % (self.cfg.get("_config_path") or "(default)"),
                    "Baseline : %s" % state.get("created", "?"),
                    "AI Engine: %s" % core.describe_ai_backend(self.cfg),
                ]
            else:
                meta = [
                    "数据目录: %s" % DATA_DIR,
                    "配置文件: %s" % (self.cfg.get("_config_path") or "(默认)"),
                    "基线创建时间: %s" % state.get("created", "?"),
                    "AI 引擎: %s" % core.describe_ai_backend(self.cfg),
                ]
        else:
            for k in self._st_tiles:
                self._st_tiles[k].config(text="-")
            meta = ([
                "Data Dir: %s" % DATA_DIR,
                "Status  : Baseline missing (click 'Rebuild Baseline' below)",
            ] if self.lang == "en" else [
                "数据目录: %s" % DATA_DIR,
                "状态: 尚未建立基线（请点击下方“重建安全基线”初始化）",
            ])
        self.st_meta_lbl.config(text="\n".join(meta))

    def _daemon_task(self, action):
        rc, out = run_hidden(["schtasks", "/%s" % action,
                              "/tn", "TripFlareDaemon"], timeout=60)
        if rc != 0 and action == "run" and core.FROZEN:
            exe = os.path.join(SCRIPT_DIR, "TripFlareDaemon.exe")
            if os.path.exists(exe):
                subprocess.Popen([exe], creationflags=CREATE_NO_WINDOW)
                self.after(1200, self.refresh_status)
                return
        if rc != 0:
            if self.lang == "en":
                lbl = "Start monitor" if action == "run" else "Stop monitor"
                messagebox.showerror(
                    self._tr("tab_status").strip(),
                    "%s failed:\n%s" % (lbl, out[:300]))
            else:
                act_zh = "启动守护" if action == "run" else "停止守护"
                messagebox.showerror(
                    "守护控制", "%s失败:\n%s" % (act_zh, out[:300]))
        self.after(1200, self.refresh_status)

    def start_scan_round(self):
        self.scan_btn.config(state="disabled", text=self._tr("btn_scanning"))
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        rc, out = run_hidden(core.daemon_cmd("--bench"), timeout=300)
        if not self._closing:
            self.after(0, lambda: self._scan_done(rc, out))

    def _scan_done(self, rc, out):
        self.scan_btn.config(state="normal", text=self._tr("btn_scan"))
        if rc != 0:
            messagebox.showerror(self._tr("btn_scan"), out[:400])
        else:
            m_ev = re.search(r"completed:\s*(\d+)\s*event", out)
            m_tot = re.search(r"total\s+([\d.]+)s", out)
            if m_ev and m_tot:
                msg = self._tr("msg_scan_done") % (
                    float(m_tot.group(1)), m_ev.group(1))
            else:
                msg = out.strip() or "OK"
            messagebox.showinfo(self._tr("btn_scan"), msg)
        self.refresh_status()
        self.refresh_alerts()

    def start_rebuild_baseline(self):
        if self.lang == "en":
            ask = ("Re-snapshot current files, autostart registry keys, tasks, "
                   "services, and processes as the clean baseline (no alerts "
                   "raised).\n\nConfirm this PC is clean and continue?")
        else:
            ask = ("将重新采集当前系统文件、注册表自启项、计划任务、系统服务与"
                   "运行中进程，作为新的安全基线（重建过程不会触发告警）。\n\n"
                   "请确认当前电脑处于安全状态，是否继续重建？")
        if not messagebox.askyesno(self._tr("btn_init"), ask):
            return
        self.init_btn.config(state="disabled", text=self._tr("btn_initing"))
        threading.Thread(target=self._init_worker, daemon=True).start()

    def _init_worker(self):
        rc, out = run_hidden(core.daemon_cmd("--init"), timeout=300)
        if not self._closing:
            self.after(0, lambda: self._init_done(rc, out))

    def _init_done(self, rc, out):
        self.init_btn.config(state="normal", text=self._tr("btn_init"))
        if rc != 0:
            messagebox.showerror(self._tr("btn_init"), out[:400])
        else:
            messagebox.showinfo(self._tr("btn_init"), self._tr("msg_init_ok"))
        self.refresh_status()


def main():
    if "--selftest" in sys.argv:
        return selftest()
    enable_dpi_awareness()
    start_tab = None
    if "--alerts" in sys.argv:
        start_tab = 0
    elif "--reports" in sys.argv:
        start_tab = 1
    if focus_existing_console(start_tab):
        return 0
    app = TripFlareUI(start_tab=start_tab)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
