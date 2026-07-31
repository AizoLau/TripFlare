#!/usr/bin/env pythonw
# -*- coding: utf-8 -*-
"""TripFlare console UI - tkinter front-end for tripflare.py.

Pure standard library. Five tabs: alerts / reports / log / config / status.

    pythonw tripflare_ui.pyw            open the console
    pythonw tripflare_ui.pyw --alerts   open directly on the alerts tab
    python  tripflare_ui.pyw --selftest headless sanity check, then exit
"""
import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import tripflare as core  # noqa: E402  (core constants/AI helpers reused)

DATA_DIR = core.DATA_DIR
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

LEVELS = ("high", "warn", "info")
LEVEL_ZH = {"high": "高危", "warn": "警告", "info": "信息"}
LEVEL_COLOR = {"high": "#c0392b", "warn": "#d68910", "info": "#7f8c8d"}


def run_hidden(args, timeout=120):
    """Run a console tool without flashing a window; return (rc, stdout)."""
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout,
                              creationflags=CREATE_NO_WINDOW)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)


def daemon_running():
    """True when a python process command line contains tripflare.py."""
    script = ("Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" "
              "| Where-Object { $_.CommandLine -like '*tripflare.py*' "
              "-and $_.CommandLine -notlike '*--bench*' "
              "-and $_.CommandLine -notlike '*patrol-tick*' } "
              "| Measure-Object | Select-Object -ExpandProperty Count")
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


def selftest():
    """Headless check used by the build verification (--selftest)."""
    cfg = core.load_config()
    alerts = core.read_alerts()
    counts = {lv: 0 for lv in LEVELS}
    for a in alerts:
        counts[a.get("level", "info")] = counts.get(a.get("level", "info"), 0) + 1
    reviews = []
    if os.path.isdir(core.REVIEWS_DIR):
        reviews = [f for f in os.listdir(core.REVIEWS_DIR)
                   if f.endswith(".md")]
    state = core.load_state() or {}
    print("selftest: alerts=%d (high=%d warn=%d info=%d)"
          % (len(alerts), counts["high"], counts["warn"], counts["info"]))
    print("selftest: config_mode=%s backend=%s"
          % (cfg["ai"].get("mode"), core.detect_backend() or "NOT FOUND"))
    print("selftest: reviews=%d state_files=%d rounds=%d"
          % (len(reviews), len(state.get("files", {})),
             state.get("rounds", 0)))
    print("selftest: daemon_running=%s" % daemon_running())
    print("selftest: OK")
    return 0


class TripFlareUI(tk.Tk):
    def __init__(self, start_tab=None):
        super().__init__()
        self.title("TripFlare 控制台")
        self.geometry("980x620")
        self.minsize(820, 480)
        self.cfg = core.load_config()
        self._build_header()
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self._build_alerts_tab()
        self._build_reports_tab()
        self._build_log_tab()
        self._build_config_tab()
        self._build_status_tab()
        if start_tab:
            self.nb.select(start_tab)
        self._refresh_header()
        self.refresh_alerts()
        self.refresh_reports()
        self.refresh_log()
        self.refresh_status()

    # ------------------------------------------------------------------
    # Header: daemon status dot + last alert time, always visible
    # ------------------------------------------------------------------

    def _build_header(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=(6, 2))
        ttk.Label(bar, text="TripFlare",
                  font=("Segoe UI", 12, "bold")).pack(side="left")
        self.hdr_alert = ttk.Label(bar, text="最近告警: -")
        self.hdr_alert.pack(side="right")
        self.hdr_daemon = ttk.Label(bar, text="● 守护未运行",
                                    foreground="#7f8c8d")
        self.hdr_daemon.pack(side="right", padx=(0, 16))

    def _refresh_header(self):
        running = daemon_running()
        if running:
            self.hdr_daemon.config(text="● 守护运行中", foreground="#27ae60")
        else:
            self.hdr_daemon.config(text="● 守护未运行", foreground="#7f8c8d")
        self.hdr_alert.config(text="最近告警: %s" % last_alert_ts())
        self.after(5000, self._refresh_header)

    # ------------------------------------------------------------------
    # Tab 1: alerts
    # ------------------------------------------------------------------

    def _build_alerts_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" 告警 ")
        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x", pady=4)
        self.unread_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar, text="仅看未读",
                        variable=self.unread_only,
                        command=self.refresh_alerts).pack(side="left", padx=4)
        ttk.Button(toolbar, text="刷新",
                   command=self.refresh_alerts).pack(side="left", padx=4)
        ttk.Button(toolbar, text="加白名单",
                   command=self.allow_selected).pack(side="left", padx=4)
        self.ai_btn = ttk.Button(toolbar, text="AI 研判",
                                 command=self.start_ai_review)
        self.ai_btn.pack(side="left", padx=4)
        self.ai_busy = ttk.Progressbar(toolbar, mode="indeterminate",
                                       length=120)
        self.ai_label = ttk.Label(toolbar, text="")
        cols = ("ts", "level", "type", "path", "score", "reasons")
        heads = ("时间", "级别", "类型", "路径", "评分", "理由")
        widths = (150, 60, 110, 320, 50, 320)
        self.alert_tree = ttk.Treeview(tab, columns=cols, show="headings")
        for col, head, width in zip(cols, heads, widths):
            self.alert_tree.heading(col, text=head)
            self.alert_tree.column(col, width=width,
                                   anchor="center" if col in ("level", "score")
                                   else "w")
        for lv, color in LEVEL_COLOR.items():
            self.alert_tree.tag_configure(lv, foreground=color)
        scroll = ttk.Scrollbar(tab, orient="vertical",
                               command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.alert_tree.pack(fill="both", expand=True)
        self._alerts_cache = []

    def refresh_alerts(self):
        self.alert_tree.delete(*self.alert_tree.get_children())
        alerts = core.read_alerts()
        if self.unread_only.get():
            state = core.load_state() or {}
            since = (state.get("ai") or {}).get("last_digest", 0)
            alerts = [a for a in alerts if a.get("epoch", 0) > since]
        self._alerts_cache = list(reversed(alerts))
        for idx, a in enumerate(self._alerts_cache):
            lv = a.get("level", "info")
            self.alert_tree.insert(
                "", "end", iid=str(idx),
                values=(a.get("ts", ""), LEVEL_ZH.get(lv, lv),
                        a.get("type", ""), a.get("path", ""),
                        a.get("score", ""),
                        "; ".join(a.get("reasons", []))[:160]),
                tags=(lv,))

    def allow_selected(self):
        sel = self.alert_tree.selection()
        if not sel:
            messagebox.showinfo("加白名单", "请先选中一条告警。")
            return
        alert = self._alerts_cache[int(sel[0])]
        target = (alert.get("extra") or {}).get("target") or alert.get("path")
        if not target:
            return
        if not messagebox.askyesno(
                "加白名单", "将以下内容加入白名单？\n\n%s" % target):
            return
        lst = self.cfg["allowlist"]["paths"]
        if target not in lst:
            lst.append(target)
            try:
                core.save_config(self.cfg, core.writable_config_path(self.cfg))
            except OSError as exc:
                messagebox.showerror("加白名单", "配置保存失败: %s" % exc)
                return
        messagebox.showinfo("加白名单", "已加入白名单:\n%s" % target)

    # ------------------------------------------------------------------
    # AI review (background thread, busy hint, auto-open the new report)
    # ------------------------------------------------------------------

    def start_ai_review(self):
        self.ai_btn.config(state="disabled")
        self.ai_label.config(text="")
        self.ai_busy.pack(side="left", padx=6)
        self.ai_busy.start(10)
        self.ai_label.config(text="AI 研判进行中，请稍候…")
        threading.Thread(target=self._ai_worker, daemon=True).start()

    def _ai_worker(self):
        cfg = core.load_config()
        state = core.load_state()
        err = report = path = None
        n = 0
        if state is None:
            err = "尚未建立基线（先运行 tripflare.py --init）"
        else:
            since = state["ai"].get("last_review", 0) or (time.time() - 86400)
            alerts = core.read_alerts(since_epoch=since,
                                      levels={"warn", "high"},
                                      cap=int(cfg["ai"].get(
                                          "review_max_alerts", 20)))
            if not alerts:
                err = "没有需要研判的 warn/high 告警。"
            else:
                n = len(alerts)
                report, err = core.call_ai(
                    cfg, core.build_review_prompt(alerts))
                if not err:
                    header = ("# TripFlare AI review\n\n- time: %s\n"
                              "- alerts supplied: %d\n\n"
                              % (core.now_iso(), n))
                    path = core.save_review("review", header + report + "\n")
                    state["ai"]["last_review"] = time.time()
                    state["ai"]["calls_today"] = \
                        state["ai"].get("calls_today", 0) + 1
                    core.save_state(state)
        self.after(0, lambda: self._ai_done(err, path, n))

    def _ai_done(self, err, path, n):
        self.ai_busy.stop()
        self.ai_busy.pack_forget()
        self.ai_btn.config(state="normal")
        if err:
            self.ai_label.config(text="")
            messagebox.showwarning("AI 研判", err)
            return
        self.ai_label.config(text="研判完成（%d 条告警）" % n)
        self.refresh_reports(select=os.path.basename(path))
        self.nb.select(1)  # jump to the reports tab

    # ------------------------------------------------------------------
    # Tab 2: reports
    # ------------------------------------------------------------------

    def _build_reports_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" 报告 ")
        pane = ttk.PanedWindow(tab, orient="horizontal")
        pane.pack(fill="both", expand=True)
        left = ttk.Frame(pane)
        right = ttk.Frame(pane)
        pane.add(left, weight=1)
        pane.add(right, weight=3)
        ttk.Button(left, text="刷新",
                   command=self.refresh_reports).pack(fill="x", pady=2)
        self.report_list = tk.Listbox(left, exportselection=False)
        self.report_list.pack(fill="both", expand=True)
        self.report_list.bind("<<ListboxSelect>>", self.show_report)
        self.report_list.bind("<Double-Button-1>", self.open_report_external)
        self.report_view = tk.Text(right, wrap="word", state="disabled",
                                   font=("Consolas", 10))
        self.report_view.pack(fill="both", expand=True)

    def refresh_reports(self, select=None):
        self.report_list.delete(0, "end")
        names = []
        if os.path.isdir(core.REVIEWS_DIR):
            names = sorted((f for f in os.listdir(core.REVIEWS_DIR)
                            if f.endswith(".md")), reverse=True)
        for name in names:
            self.report_list.insert("end", name)
        if select and select in names:
            idx = names.index(select)
            self.report_list.selection_set(idx)
            self.report_list.see(idx)
            self.show_report()
        elif names:
            self.report_list.selection_set(0)
            self.show_report()

    def _selected_report(self):
        sel = self.report_list.curselection()
        if not sel:
            return None
        return os.path.join(core.REVIEWS_DIR, self.report_list.get(sel[0]))

    def show_report(self, _event=None):
        path = self._selected_report()
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            text = "读取失败: %s" % exc
        self.report_view.config(state="normal")
        self.report_view.delete("1.0", "end")
        self.report_view.insert("1.0", text)
        self.report_view.config(state="disabled")

    def open_report_external(self, _event=None):
        path = self._selected_report()
        if path:
            os.startfile(path)

    # ------------------------------------------------------------------
    # Tab 3: log
    # ------------------------------------------------------------------

    def _build_log_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" 日志 ")
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=4)
        ttk.Button(bar, text="刷新",
                   command=self.refresh_log).pack(side="left", padx=4)
        self.log_auto = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="每 5 秒自动刷新",
                        variable=self.log_auto,
                        command=self._log_auto_tick).pack(side="left", padx=4)
        self.log_view = tk.Text(tab, wrap="none", state="disabled",
                                font=("Consolas", 9))
        self.log_view.pack(fill="both", expand=True)

    def refresh_log(self):
        lines = []
        try:
            with open(core.LOG_PATH, "r", encoding="utf-8",
                      errors="replace") as fh:
                lines = fh.readlines()[-300:]
        except OSError:
            lines = ["(暂无日志)\n"]
        self.log_view.config(state="normal")
        self.log_view.delete("1.0", "end")
        self.log_view.insert("1.0", "".join(lines))
        self.log_view.see("end")
        self.log_view.config(state="disabled")

    def _log_auto_tick(self):
        if self.log_auto.get():
            self.refresh_log()
            self.after(5000, self._log_auto_tick)

    # ------------------------------------------------------------------
    # Tab 4: config
    # ------------------------------------------------------------------

    def _build_config_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" 配置 ")
        form = ttk.LabelFrame(tab, text="常用项")
        form.pack(fill="x", padx=4, pady=4)
        self.var_interval = tk.StringVar()
        self.var_mode = tk.StringVar()
        self.var_backend = tk.StringVar()
        self.var_maxcalls = tk.StringVar()
        self.var_patrol = tk.StringVar()
        rows = [
            ("扫描间隔 (秒)", self.var_interval, None),
            ("AI 模式", self.var_mode, ("recommend", "patrol", "off")),
            ("AI 后端路径 (auto=自动探测)", self.var_backend, None),
            ("每日 AI 调用上限", self.var_maxcalls, None),
            ("巡逻间隔 (分钟)", self.var_patrol, None),
        ]
        for r, (label, var, choices) in enumerate(rows):
            ttk.Label(form, text=label).grid(row=r, column=0, sticky="w",
                                             padx=6, pady=3)
            if choices:
                ttk.Combobox(form, textvariable=var, values=choices,
                             state="readonly", width=28).grid(
                    row=r, column=1, sticky="w", padx=6)
            else:
                ttk.Entry(form, textvariable=var, width=32).grid(
                    row=r, column=1, sticky="w", padx=6)
        ttk.Button(form, text="保存常用项",
                   command=self.save_config_form).grid(
            row=len(rows), column=1, sticky="w", padx=6, pady=6)
        adv = ttk.LabelFrame(tab, text="高级 JSON（保存时校验，非法不写入）")
        adv.pack(fill="both", expand=True, padx=4, pady=4)
        self.cfg_text = tk.Text(adv, wrap="none", font=("Consolas", 9))
        self.cfg_text.pack(fill="both", expand=True)
        ttk.Button(adv, text="保存高级 JSON",
                   command=self.save_config_json).pack(anchor="w", padx=4,
                                                       pady=4)
        self.load_config_form()

    def load_config_form(self):
        self.cfg = core.load_config()
        ai = self.cfg["ai"]
        self.var_interval.set(str(self.cfg.get("interval_seconds", 60)))
        self.var_mode.set(ai.get("mode", "recommend"))
        self.var_backend.set(str(ai.get("backend_path", "auto")))
        self.var_maxcalls.set(str(ai.get("max_calls_per_day", 20)))
        self.var_patrol.set(str(ai.get("patrol_interval_minutes", 30)))
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        self.cfg_text.delete("1.0", "end")
        self.cfg_text.insert("1.0", json.dumps(data, ensure_ascii=False,
                                               indent=2))

    def _save_config_dict(self, data):
        path = core.writable_config_path(self.cfg)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
        except OSError as exc:
            messagebox.showerror("配置", "写入失败: %s" % exc)
            return False
        self.cfg = core.load_config()
        messagebox.showinfo("配置", "已保存到:\n%s" % path)
        return True

    def save_config_form(self):
        data = {k: v for k, v in self.cfg.items() if not k.startswith("_")}
        try:
            data["interval_seconds"] = max(10, int(self.var_interval.get()))
            data["ai"]["max_calls_per_day"] = int(self.var_maxcalls.get())
            data["ai"]["patrol_interval_minutes"] = int(
                self.var_patrol.get())
        except ValueError:
            messagebox.showerror("配置", "间隔/上限必须是整数。")
            return
        data["ai"]["mode"] = self.var_mode.get()
        data["ai"]["backend_path"] = self.var_backend.get().strip() or "auto"
        if self._save_config_dict(data):
            self.load_config_form()

    def save_config_json(self):
        raw = self.cfg_text.get("1.0", "end").strip()
        try:
            data = json.loads(raw)
        except ValueError as exc:
            messagebox.showerror("配置", "JSON 非法，未写入:\n%s" % exc)
            return
        if not isinstance(data, dict):
            messagebox.showerror("配置", "顶层必须是 JSON 对象。")
            return
        if self._save_config_dict(data):
            self.load_config_form()

    # ------------------------------------------------------------------
    # Tab 5: status
    # ------------------------------------------------------------------

    def _build_status_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" 状态 ")
        self.status_text = tk.Text(tab, height=12, state="disabled",
                                   font=("Consolas", 10))
        self.status_text.pack(fill="both", expand=True, padx=4, pady=4)
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=4)
        ttk.Button(bar, text="启动守护",
                   command=lambda: self._daemon_task("run")).pack(
            side="left", padx=4)
        ttk.Button(bar, text="停止守护",
                   command=lambda: self._daemon_task("end")).pack(
            side="left", padx=4)
        ttk.Button(bar, text="打开数据目录",
                   command=lambda: os.startfile(DATA_DIR)).pack(
            side="left", padx=4)
        self.scan_btn = ttk.Button(bar, text="立即扫描一轮",
                                   command=self.start_scan_round)
        self.scan_btn.pack(side="left", padx=4)
        ttk.Button(bar, text="刷新状态",
                   command=self.refresh_status).pack(side="left", padx=4)

    def refresh_status(self):
        state = core.load_state()
        running = daemon_running()
        lines = ["守护状态: %s" % ("运行中" if running else "未运行"),
                 "数据目录: %s" % DATA_DIR, ""]
        if state:
            ai = state.get("ai", {})
            lines += [
                "基线创建: %s" % state.get("created", "?"),
                "已跑轮数: %d" % state.get("rounds", 0),
                "最近一轮耗时: %.2f 秒" % state.get("last_round_seconds", 0),
                "监视文件: %d  注册表键: %d  任务: %d  服务: %d" % (
                    len(state.get("files", {})),
                    len(state.get("registry", {})),
                    len(state.get("tasks", [])),
                    len(state.get("services", {}))),
                "AI 模式: %s  今日 AI 调用: %d" % (
                    self.cfg["ai"].get("mode"), ai.get("calls_today", 0)),
            ]
        else:
            lines.append("尚未建立基线。")
        self.status_text.config(state="normal")
        self.status_text.delete("1.0", "end")
        self.status_text.insert("1.0", "\n".join(lines))
        self.status_text.config(state="disabled")

    def _daemon_task(self, action):
        rc, out = run_hidden(["schtasks", "/%s" % action,
                              "/tn", "TripFlareDaemon"], timeout=60)
        if rc != 0:
            messagebox.showerror(
                "守护控制", "schtasks /%s 失败:\n%s" % (action, out[:300]))
        self.after(1500, self.refresh_status)

    def start_scan_round(self):
        """Run one bench-equivalent round in a worker thread."""
        self.scan_btn.config(state="disabled", text="扫描中…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        py = core.console_python()
        rc, out = run_hidden([py, os.path.join(SCRIPT_DIR, "tripflare.py"),
                              "--bench"], timeout=300)
        self.after(0, lambda: self._scan_done(rc, out))

    def _scan_done(self, rc, out):
        self.scan_btn.config(state="normal", text="立即扫描一轮")
        if rc != 0:
            messagebox.showerror("扫描", "扫描失败:\n%s" % out[:400])
        else:
            messagebox.showinfo("扫描", out.strip() or "扫描完成。")
        self.refresh_status()
        self.refresh_alerts()


def main():
    if "--selftest" in sys.argv:
        return selftest()
    start_tab = 0 if "--alerts" in sys.argv else None
    app = TripFlareUI(start_tab=start_tab)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
