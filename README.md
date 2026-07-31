# SecMon

Lightweight Windows anomaly monitor (tripwire) with three-tier AI review.
Single-file Python, standard library only, zero tokens by default.

[中文说明见文末](#中文说明)

## What it does

SecMon snapshots the places malware actually touches first — drop zones
(Downloads / Temp / Desktop / AppData / Startup folders), autostart registry
keys (`Run`, `RunOnce`, Winlogon, `StartupApproved`, IFEO debuggers,
services), scheduled tasks, and processes launched from risky locations —
then scores every change with local heuristics:

unsigned `+3` · unknown signer `+2` · random name `+3` · runtime-DLL
masquerade `+4` · risky location `+2` · hidden `+1` · persistence `+3`

`score >= 7` = **high**: appends `URGENT.txt`, pops a Windows notification,
and drops a one-click AI-review launcher on your desktop. Full rule table
and threat model: [docs/DESIGN.md](docs/DESIGN.md).

## 30-second quickstart

```bat
git clone <repo> secmon && cd secmon
python secmon.py --init        :: build the baseline (no alerts)
python secmon.py               :: run the daemon (Ctrl+C to stop)
```

Other commands: `digest` (unread alerts), `ai-review [--max N]` (one-shot
AI review), `allow <path-or-signer>` (allowlist), `status`, `--bench`
(timed round), `patrol-tick` (scheduler entry for patrol mode).

Auto-start at logon (optional):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
# removes them again:
powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1
```

`install.ps1` registers two scheduled tasks: `SecMonDaemon` (pythonw,
windowless, at logon) and `SecMonPatrol` (`patrol-tick` every 30 min — a
complete no-op unless `ai.mode` is `patrol`).

## Three AI modes

| Mode | AI calls | Cost | For whom |
| --- | --- | --- | --- |
| `recommend` (default) | only when you double-click the desktop bat after a high alert | 0 by default | most users |
| `patrol` | immediate on high alerts (10-min cooldown) + routine every 30 min, hard cap 20/day | ~5-15k tokens per patrol, you pay | high-security users |
| `off` | never (manual `ai-review` still possible) | 0 | air-gapped / paranoid |

Set `"ai": {"mode": "..."}` in `config.json`. The AI backend is any CLI
that maps `-p "<prompt>"` to text on stdout — kimi.exe is auto-detected;
point `ai.backend_path` at anything else.

In patrol mode the AI investigates read-only (signatures, file headers,
hash lookups, registry cross-checks) and writes `reviews\patrol-*.md`;
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

## Runtime data

`%LOCALAPPDATA%\SecMon\` — `state.json` (baseline), `alerts.jsonl`,
`reviews\` (AI reports), `URGENT.txt` (high alerts), `secmon.log`.
Config: `config.json` next to `secmon.py` (seeded from
`config.default.json` on `--init`).

## Blind spots (read before trusting it)

SecMon is a tripwire, **not antivirus**: no rootkit, fileless, or in-memory
detection; a baseline taken after compromise blesses the malware; process
watching is path-first-seen, not behavioral. It complements periodic full
scans (e.g. Emsisoft Emergency Kit) and a real AV. Patrol mode costs real
AI quota (circuit breaker included). The AI is read-only unless you
explicitly enable quarantine. SecMon never alerts on itself: `pythonw.exe`,
the AI backend, and everything under the install/data directories are
whitelisted.

## License

MIT — see [LICENSE](LICENSE).

---

## 中文说明

SecMon 是一个轻量级 Windows 异常监控（绊线式）工具：对首次入侵最常
触碰的位置建立基线（下载/临时/桌面/AppData/启动目录、Run 键、
Winlogon、StartupApproved、IFEO、服务、计划任务、高危位置新进程），
用本地启发式规则打分（无签名 +3、未知签名者 +2、随机名 +3、伪装运
行库 +4、高危目录 +2、隐藏属性 +1、持久化 +3），≥7 分为高危：写
`URGENT.txt`、弹 Windows 通知，并在桌面生成一键 AI 研判 bat。

三档 AI 模式：`recommend`（默认，不点 bat 不花 token）、`patrol`
（高危立即巡逻 10 分钟冷却 + 每 30 分钟例行巡逻，每日上限 20 次熔
断，AI 默认只读）、`off`（纯本地）。AI 后端默认自动探测 kimi.exe，
可换任何"收 prompt 出文本"的命令行工具。

上手：`python secmon.py --init` 建基线 → `python secmon.py` 跑守护；
`scripts\install.ps1` 可注册登录自启与定时巡逻两个计划任务，
`uninstall.ps1` 回滚。实测每轮约 0.9–1.8 秒、内存约 24MB，平均
CPU 远低于 1%。

它是绊线而非杀软：防不住 rootkit / 无文件 / 内存攻击，与定期全盘扫
描互补；patrol 模式烧的是你自己的配额（有熔断）；AI 默认只读，自动
隔离需显式开启。
