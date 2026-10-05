# Fine-clash 仓库 & 路由器安全审计报告 — 2026-10-03

> 范围：本地仓库 `d:/repo-tasks/Fine-clash` + 路由器 `192.168.0.1` (ShellCrash/mihomo)
> 原则：只读审计 + 已授权清洗；路由器运行态**未做任何修改**（仅收集证据）。
> 证据均来自本机命令 / paramiko 只读 SSH，可复验。

---

## 一、仓库审计

### 1.1 散落文件清理（已执行，move 非 rm，留底可恢复）
- 归档 **103** 个未跟踪文件/目录 → `D:/Temp/Fine-clash_archive_20261003/`
- 其中 **8 个 `_bitz_*.py` 含 Bitz 真实订阅 token** `23a7ad64b83f7b867eb75da3738184c6`（`cont.bbkcdpub.com/api/v1/client/BitzNet.conf?token=...`）
- 这些文件此前**未被 `.gitignore` 覆盖**，一旦 `git add -A` 即泄露到公开 GitHub —— 已消除该风险
- 归档后 `git status --short` 为空（干净）

### 1.2 密钥面扫描（git tracked + history）
| 检查项 | 结果 |
|---|---|
| `.env`（含路由器 SSH 密码）是否进库 | **从未提交** ✅ |
| 完整 Bitz token 是否进 git 历史 (`-S 23a7ad64b83f7b867eb75da3738184c6`) | **空（无）** ✅ |
| 路由器密码 `9eeb78d4` 是否进 git 历史 | ⚠️ **仅出现在 `.gitignore` 注释文字**（commit 48c77c0），非密码本体。本次已修注释 |
| tracked 文件残留 `token=`/`23a7ad64`/`ROUTER_SSH_PASSWORD` | 仅 `fine_clash.py:252` 是代码 `os.getenv(token_name)` 引用，非明文 ✅ |

### 1.3 `.gitignore` 加固（已执行）
- 新增模式：`_bitz_*` `_dual_*` `_build_*` `_deploy_*` `_recover*` `_revert*` `_diag*` `_verify_*` `ab_run.log` `btest*.yaml` `dual_final*.yaml` `bitz_*.yaml` `router_fine_template.yaml` 等
- 修复 `.gitignore` 第 7 行注释：把真实密码前缀 `9eeb78d4` 改为占位说明，不再强化泄露

### 1.4 交付物与 CI 核查
- `build_uni.py` / `.github/workflows/update.yml`：CI 每 4h 抓 clashfree 兜底池 + 重建 uni 链 + `mihomo -t` 闸才提交 ✅
- `mobile_dual_uni.yaml`：独立复核脚本 18 项 ALL PASS；本地与远端副本均过 `mihomo -t`；`raw@main` 与本地 md5 一致（`ee12a94f0c51`）
- 结构：Fine=24(21专线+3兜底) / Bitz=20(live_clash最新池) / Fine∩Bitz=空 / rules=108 / allow-lan=true / 无 external-controller

---

## 二、路由器审计（只读，未修改）

### 2.1 运行态健康 ✅
| 项 | 实测 |
|---|---|
| 核心进程 | CrashCore **pid 28644**，`-d /data/clash -f /tmp/ShellCrash/config.yaml` |
| 端口 | `:::7890`(Mixed) / `:::9999`(API) 在听；1080/9090 属设备其它进程，无冲突 |
| 守护 | `crontab` 仅 1 条 `* * * * * /bin/ash /data/clash/dual_start.sh`；`/dev/watchdog` 在看 |
| iptables | nat 129 行 / mangle 104 行（透明代理规则完好） |
| 日志 | CrashCore 日志最后一条 10-01 09:55 正常启动，无崩溃/error 级运行报错 |
| 磁盘/内存 | `/data` 36% 用（128M 可用）；内存 254M 总/79M 空闲，充裕 |
| 双组 | 运行态 config 含 `♻️ Fine自动` + `♻️ Bitz自动` 两组；Fine 组含 youtube/play/google 等大流量分流规则 ✅ |
| 明文 token | 运行态 config **不含** `cont.bbkcdpub.com` URL 或 `token=` 明文（provider 模式，订阅在别处）✅ |

### 2.2 发现项（观察，未擅改）
- ⚠️ **两份 config 不一致**：运行态 `/tmp/ShellCrash/config.yaml` = **27227B**（=回滚原样 unipre/RollbackNow），正确；`/data/clash/yamls/config.yaml` = **23974B** 旧/异副本，**未被运行使用**，属冗余。
- 备份中间产物较多（`/tmp/ShellCrash/` + `/data/clash/yamls/` 下 ~15 个 `config.yaml.bak_*` / `bak_pre_onelink_*`），空间不紧迫，但建议保留关键回滚点、清理中间产物。

---

## 三、长期安全改进项（待用户决策，未擅自动）

| 项 | 内容 | 风险 | 建议 |
|---|---|---|---|
| **B** | 改路由器 SSH 密码 + 同步 `.env` 的 `ROUTER_SSH_PASSWORD` | 前缀 `9eeb78d4` 已进公开历史，暴力空间被压缩 | 登录路由器改密 → 同步 `.env`；改后确保本机脚本仍能连 |
| **C** | 轮换 Bitz 订阅 token | 本地归档 `_bitz_*.py` 含明文旧 token（虽未进库，但本地散落） | Bitz 后台重置订阅 → 更新路由器 provider URL |
| **D** | 清理路由器中间备份（`bak_pre_onelink_*` 等） | 不可逆删除 | 授权后保留 `bak_unipre`/`bak_RollbackNow`，其余移除 |
| A | 修 `.gitignore` 注释暴露密码前缀 | 已在本报告执行 ✅ | — |

> 执行 B/C/D 前需用户明确授权；本机已具备 paramiko 只读通道，改动类操作默认先备份再实施。
