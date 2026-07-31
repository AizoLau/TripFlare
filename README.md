# TripFlare

Lightweight Windows anomaly monitor (tripwire) with three-tier AI review
and a tkinter console UI. Single-folder portable layout, standard library
only, zero tokens by default.

[中文说明见文末](#中文说明)

## What it does

TripFlare snapshots the places malware actually touches first — drop zones
(Downloads / Temp / Desktop / AppData / Startup folders), autostart registry
keys (`Run`, `RunOnce`, Winlogon, `StartupApproved`, IFEO debuggers,
services), scheduled tasks, and processes launched from risky locations —
then scores every change with local heuristics:

unsigned `+3` · unknown signer `+2` · random name `+3` · runtime-DLL
masquerade `+4` · risky location `+2` · hidden `+1` · persistence `+3`

`score >= 7` = **high**: appends `URGENT.txt` and notifies you through the
**system tray agent** (persistent icon, balloon, right-click menu). The old
desktop bat launcher is deprecated and disabled by default
(`notify.desktop_bat`). Full rule table and threat model:
[docs/DESIGN.md](docs/DESIGN.md).

## Layout (portable single folder)

```
TripFlare\
  TripFlare控制台.bat   # double-click: opens the GUI console (pythonw)
  tripflare.py          # daemon core - full CLI kept, no UI required
  tripflare_ui.pyw      # tkinter console (5 tabs, stdlib only)
  tripflare_tray.pyw    # system tray agent (ctypes Win32, stdlib only)
  tripflare.ico         # tray/console icon (scripts\make_icon.py rebuilds it)
  config.json           # live config (editable in the UI, git-ignored)
  config.default.json
  prompts\  docs\  scripts\  README.md  LICENSE  .gitignore
  data\                 # state.json / alerts.jsonl / reviews\ /
                        # URGENT.txt / tripflare.log / tray.log (git-ignored)
```

The data directory defaults to `<script dir>\data`; set the
`TRIPFLARE_DATA_DIR` environment variable to override it.

## System tray agent (tripflare_tray.pyw)

Pure Win32 via ctypes (Shell_NotifyIconW) — zero third-party packages:

- Persistent notification-area icon; double-click opens the console.
- Right-click menu: 打开控制台 / 立即AI研判 / 启动守护 / 停止守护 /
  打开数据目录 / 退出托盘.
- Tails `data\alerts.jsonl`: a new **high** alert pops a balloon
  ("TripFlare 高危异常"); clicking it opens the console alerts page.
  Balloon events are logged to `data\tray.log`.
- Tooltip mirrors daemon state (refreshed every 30 s).
- Re-adds its icon when Explorer restarts (TaskbarCreated).

`install.ps1` registers it as the `TripFlareTray` logon task
(restart-on-failure, no run-time limit) and starts it immediately.

## 30-second quickstart

GUI way: double-click **`TripFlare控制台.bat`**. The 状态 (status) tab
starts/stops the daemon, runs a scan round, and opens the data folder.

CLI way (everything works without the UI, for headless/GitHub users):

```bat
git clone <repo> TripFlare && cd TripFlare
python tripflare.py --init        :: build the baseline (no alerts)
python tripflare.py               :: run the daemon (Ctrl+C to stop)
```

Other commands: `digest` (unread alerts), `ai-review [--max N]` (one-shot
AI review), `allow <path-or-signer>` (allowlist), `status`, `--bench`
(timed round), `patrol-tick` (scheduler entry for patrol mode).

## Console UI (tripflare_ui.pyw)

Five tabs, Chinese interface, pure local tkinter (no ports opened):

- **告警 (Alerts)**: sortable table (time / level / type / path / score /
  reasons), high=red, warn=orange, info=gray; unread-only toggle, refresh,
  allowlist-selected, and an **AI 研判** button that runs the review in a
  background thread with a busy hint, then jumps to the new report.
- **报告 (Reports)**: list of `data\reviews\*.md` with a read-only viewer;
  double-click opens externally.
- **日志 (Log)**: tail of `tripflare.log`, optional 5-second auto-refresh.
- **配置 (Config)**: form for the common knobs (scan interval, ai.mode,
  AI backend path, daily AI cap, patrol interval) plus an advanced JSON
  editor validated before saving.
- **状态 (Status)**: daemon state (detected by process command line),
  last-round stats, and buttons: start/stop daemon (scheduled task),
  open data folder, run one scan round.

The header always shows a daemon status dot (green/gray) and the last
alert time. `--alerts` opens directly on the alerts tab (used by the
tray balloon click); `--selftest` runs a headless sanity check.

## Auto-start at logon (optional)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
# removes them again:
powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1
```

`install.ps1` registers three scheduled tasks: `TripFlareDaemon` (pythonw,
windowless, at logon), `TripFlarePatrol` (`patrol-tick` every 30 min — a
complete no-op unless `ai.mode` is `patrol`) and `TripFlareTray` (the tray
agent at logon, restarted on failure, started immediately).

## Three AI modes

| Mode | AI calls | Cost | For whom |
| --- | --- | --- | --- |
| `recommend` (default) | only when you click AI 研判 after a high alert | 0 by default | most users |
| `patrol` | immediate on high alerts (10-min cooldown) + routine every 30 min, hard cap 20/day | ~5-15k tokens per patrol, you pay | high-security users |
| `off` | never (manual `ai-review` still possible) | 0 | air-gapped / paranoid |

Set `"ai": {"mode": "..."}` in `config.json` (or the UI config tab). The
AI backend is any CLI that maps `-p "<prompt>"` to text on stdout —
kimi.exe is auto-detected; point `ai.backend_path` at anything else.

Reviews are incremental: only unread warn/high alerts are sent (info-level
never goes to the AI), and reviewed alerts are marked read in
`data\read_alerts.json` — the same read state the console UI shows, so an
alert is never reviewed twice.

In patrol mode the AI investigates read-only (signatures, file headers,
hash lookups, registry cross-checks) and writes `data\reviews\patrol-*.md`;
`high` verdicts escalate to `URGENT.txt` + notification. Auto-quarantine
exists (`ai.patrol.allow_auto_quarantine`) but is **off by default** and
documented as dangerous. Guardrails live in
[prompts/patrol_prompt.md](prompts/patrol_prompt.md).

## Measured performance

Test host: Windows 11, ~2 400 watched files, 189 scheduled tasks, 678
services, 60 s interval.

| Metric | Light round (4 of 5) | Heavy round (every 5th) |
| --- | --- | --- |
| Wall time | ~0.9-1.1 s | ~1.8 s (measured 1.805 / 1.790 / 1.796 s) |
| Daemon memory | 24 MB working set | same |

Average CPU is well under 1 % of one core; steady-state disk I/O is
directory metadata only (NTFS cache), plus one PowerShell process snapshot
per round and a handful of `reg query` calls.

## Blind spots (read before trusting it)

TripFlare is a tripwire, **not antivirus**: no rootkit, fileless, or
in-memory detection; a baseline taken after compromise blesses the malware;
process watching is path-first-seen, not behavioral. It complements
periodic full scans (e.g. Emsisoft Emergency Kit) and a real AV. Patrol
mode costs real AI quota (circuit breaker included). The AI is read-only
unless you explicitly enable quarantine. TripFlare never alerts on itself:
`pythonw.exe`, the AI backend, and everything under the install/data
directories are whitelisted.

## License

MIT — see [LICENSE](LICENSE).

---

## 中文说明

TripFlare 是一个轻量级 Windows 异常监控（绊线式）工具：对首次入侵最常
触碰的位置建立基线（下载/临时/桌面/AppData/启动目录、Run 键、
Winlogon、StartupApproved、IFEO、服务、计划任务、高危位置新进程），
用本地启发式规则打分（无签名 +3、未知签名者 +2、随机名 +3、伪装运
行库 +4、高危目录 +2、隐藏属性 +1、持久化 +3），≥7 分为高危：写
`URGENT.txt`，并由**系统托盘代理**弹气球通知（旧版桌面 bat 方案已废
弃，默认关闭）。

**便携单文件夹**：代码、配置、数据（`data\`）全部在一个目录里。
双击 `TripFlare控制台.bat` 打开图形控制台（告警/报告/日志/配置/状态
五个页签）；任务栏右下角常驻托盘图标，双击开控制台、右键有快捷菜单
（打开控制台 / 立即AI研判 / 启动·停止守护 / 打开数据目录 / 退出），
出现高危告警时托盘弹气球、点击直达告警页；命令行用法全部保留，不用
UI 也能完整使用。

三档 AI 模式：`recommend`（默认，不点研判不花 token）、`patrol`
（高危立即巡逻 10 分钟冷却 + 每 30 分钟例行巡逻，每日上限 20 次熔
断，AI 默认只读）、`off`（纯本地）。AI 后端默认自动探测 kimi.exe，
可换任何"收 prompt 出文本"的命令行工具。研判为增量口径：只发送上
次以来未读的中/高级告警（信息级不送 AI），研判处自动标记已读，与
控制台告警页的已读状态同源，同一告警绝不重复送审。

上手：双击 `TripFlare控制台.bat`，在"状态"页启动守护；或命令行
`python tripflare.py --init` 建基线 → `python tripflare.py` 跑守护。
`scripts\install.ps1` 可注册登录自启、定时巡逻、系统托盘三个计划任务
（TripFlareDaemon / TripFlarePatrol / TripFlareTray，托盘装完立即启动），
`uninstall.ps1` 回滚。实测每轮约 0.9–1.8 秒、内存约 24MB，平均
CPU 远低于 1%。

它是绊线而非杀软：防不住 rootkit / 无文件 / 内存攻击，与定期全盘扫
描互补；patrol 模式烧的是你自己的配额（有熔断）；AI 默认只读，自动
隔离需显式开启。
