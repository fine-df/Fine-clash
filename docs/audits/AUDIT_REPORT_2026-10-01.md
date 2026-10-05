# Fine-clash 代码审计报告（GIT 仓库 + 路由器部署）

**审计时间**：2026-10-01 16:44　**审计对象**：`d:/repo-tasks/Fine-clash` 仓库 + 小米路由器 ShellCrash/mihomo v1.19.28
**结论先行**：核心功能链路（两层策略组自动切换）**健康且与 git 一致**；致命问题是**仓库卫生与凭据管理**（已现场修复）；CI 缺少审计门禁、README 已严重过时。

---

## 风险等级汇总

| 等级 | 数量 | 项 |
|---|---|---|
| 🔴 P0（必须处理） | 2 | ① 明文路由器密码未忽略 ② 生产 sync 脚本 `_fine_sync.sh` 未纳入版本控制 |
| 🟠 P1（应尽快） | 2 | ③ CI 未挂 `audit_final.py` 门禁 ④ CI 用「最新 mihomo」校验，路由器跑 v1.19.28（版本错位） |
| 🟡 P2（建议） | 6 | ⑤ README 文档漂移 ⑥ build_final.py docstring/代码 tolerance 不一致 ⑦ build_final.py 死代码 guard ⑧ `_fine_sync.sh` 冗余判据 ⑨ 冗余 `20 */12` cron ⑩ 安全暴露（external-controller 0.0.0.0 无密码，用户选 C 维持） |

---

## 一、GIT 仓库审计

### 1.1 仓库卫生（P0-② + 已修）
- 仓库根目录有 **~140 个未提交文件**：`diag2~diag11.py`、`probe2~probe8.py`、`*_backup.yaml`、`router_config_*.yaml`（30KB×4）、`_remote_cfg.yaml`（50KB）、`ca-bundle.crt`（74KB）等大量一次性调试/备份产物。
- **修复**：已扩充 `.gitignore`，把实验脚本、备份、证书、本地样本全部忽略；保留生产文件（`_fine_sync.sh` / `deploy_local.py` / `deploy_sync.py` / `build_final.py` / `audit_final.py` / `monitor_pick.py` / `play_test.py`）可见待提交。
- 剩余未跟踪仅：`deploy_sync.py`（生产，应提交）、`data/*.json`（CI 产物，应提交）、`.gitignore`（本次修改）。

### 1.2 凭据暴露（P0-① + 已修）
- `_router_ssh.py` 第 15 行硬编码路由器 SSH 密码 `PASSWORD = "9eeb78d4"`，且**原 `.gitignore` 未覆盖它** → 一旦 `git add -A` 即把密码推到公开 GitHub。
- **修复**：`.gitignore` 已加入 `_router_ssh.py`、`ca-bundle.crt`、`make_ca_bundle.ps1`，实测 `git check-ignore` 命中。
- **后续建议**（未做，避免改动正在工作的部署代码）：把密码迁到已忽略的 `.env`（`ROUTER_PASS=...`），`_router_ssh.py` 改为 `os.environ.get("ROUTER_PASS")` 读取——这样即便误提交也不泄密。

### 1.3 可复现性（PASS）
- `git show HEAD:fine_final.yaml` == 当前工作树重跑 `build_final.py` 产物（归一化 CRLF 后逐字节一致）。
- 提交文件为 **LF**（0 个 `\r`），无 CRLF 隐患。生成器幂等，产物可信。

### 1.4 CI 流水线 `update.yml`（P1-③④）
- **P1-③ 缺审计门禁**：CI 只跑 `pytest`（针对 `fine_clash.py`），**完全没跑 `audit_final.py`**。提交前仅有 `mihomo -t` 做 YAML 语法校验，**不校验语义**（GLOBAL/节点选择/自动选择三层结构、探针 URL、组引用）。`build_final.py` 一旦回归结构，CI 不会拦截。
  - **建议**：在 `Validate generated Clash config` 步增加 `python audit_final.py`。
- **P1-④ mihomo 版本错位**：CI 第 31–44 行下载 **latest** mihomo 做 `-t` 校验，路由器实际跑 **v1.19.28**。新版本能过的配置旧版本可能拒绝（或反之）。
  - **建议**：把校验用的 mihomo 固定到 `v1.19.28`（与路由器一致）。
- 其余健康：cron 每 4h（UTC `0 0,4,8,12,16,20`）、`permissions: contents: write`、watchdog 兜底（距上次成功 >22h 自触发 `workflow_dispatch`）、`requirements.txt` 含 PyYAML/requests/pytest。
- `pytest --co` 离线集合 **26 个用例全部可加载**（无 import/语法错误）。

### 1.5 文档漂移（P2-⑤，README.md）
README 与代码严重不符：

| README 原文 | 实际 |
|---|---|
| 第 5 行「runs once per day」 | CI 每 4h 跑一次（6×/天） |
| 第 36 行 cron `0 2,8,14,20` | 实际 `0 0,4,8,12,16,20` |
| 第 38/47 行「探测 gemini.google.com」 | 探针早已改为 `play.google.com/store`（commit 4ac802b） |
| 第 48 行「>20 小时」 | watchdog 阈值实际 22h |
| 全文只描述单 `PROXY` 组 | 实际已是两层结构（节点选择→自动选择），且未提「手动点节点会钉死 url-test」的坑 |

**建议**：重写 README「自动更新链路」段，标注两层组结构 + 探针 + 不点自动选择组的告诫。

---

## 二、核心代码审计

### 2.1 `build_final.py`（生成器，当前版本 v3）
- **P2-⑥ docstring 与代码不一致**：第 15 行注释写「tolerance=100ms」，代码第 25 行 `TOLERANCE = 50`。读代码人会被注释误导。
- **P2-⑦ 死代码 guard**：第 40–42 行 `if not any(g.get("name")=="PROXY" ...)` 检查源是否有 PROXY 组，但第 85 行直接 `base["proxy-groups"] = [global_group, pick, auto]` 整体覆盖——该检查对生成结果**毫无影响**（真正依赖的是第 34–37 行对 `proxies` 的存在性检查）。应删掉或改为检查 `proxies`。
- 规则改写（第 89–99 行）：仅把 `MATCH`/`FINAL` 和显式 `,PROXY` 规则改道到 `🚀 节点选择`，其余规则原样保留。经 `audit_final.py` P0-9 验证 15 条规则目标全部存在，无悬空组引用——**逻辑正确**。
- 顶层键清理（tun/redir-port 等 pop）、`find-process-mode: off`、`unified-delay: False` 处理正确。

### 2.2 `_fine_sync.sh`（路由器同步，当前版本）
- **P2-⑧ 冗余判据**：第 62–63 行 `grep -q "tolerance:"` 与 `grep -q "name: GLOBAL"` 在第 21 行边缘轮询时已判过，属重复且不增加信息，建议删除以利维护。
- **关键护栏正确**：第 42–46 行「本地 fine-override 标记优先」护栏（防止 CDN 旧参数覆盖本地调参）实测有效；第 70 行 `CrashCore -t` 自检门禁到位；多边缘兜底（cdn/gcore/testingcf）实测路由器全通。
- **小改进点**：第 80–82 行重启 ShellCrash 后无健康检查——若 `start.sh` 异常，脚本仍打印 `sync_restarted`。建议重启后 `curl /version` 探活。

---

## 三、路由器部署审计

### 3.1 运行态与 git 一致性（PASS）
实测路由器（`192.168.0.1:9999`）：
- 核心版本 `v1.19.28`；模板参数 `interval:90 / timeout:10000 / tolerance:50 / lazy:false / unified-delay:false / log-level:warning`，**与 git 的 build_final.py 完全一致**。
- override 标记 `# fine-override: v3` 一致。
- **三组结构完整**：`GLOBAL(select)→🚀 节点选择(select,22成员)→♻️ 自动选择(url-test,20节点)`；API 实测 `fixed` 在三个组上**全为 `None`/空** → 自动切换已恢复，无手动钉死。
- 模板 10955B vs git 11382B（差 427B）：经拉取模板 proxy-groups 段核对，结构/节点名/override **完全齐全**，差异系 mihomo 载入时重写缩进所致，**无字段丢失**。

### 3.2 安全暴露（P2-⑩，用户选 C 维持）
- `external-controller: 0.0.0.0:9999` + `allow-lan: True` + `authentication: []`：同局域网任意设备可改/读代理。用户已于上一轮明确选 **C（维持现状）**，此处仅记录，不改动。

### 3.3 冗余 cron（P2-⑨）
- crontab 含两条：**`*/15`** 跑 `fine_sync.sh`（jsDelivr 拉取+护栏+重启，主链路）；**`20 */12`** `cp /tmp/ShellCrash/fine_final.yaml /data/clash/yamls/config.yaml`（#同步Fine模板）。
- 后者来源定位为历史 `fix_cron.py:16`，与 `fine_sync.sh` 的 `cp $TMP $TPL` **完全重复**，且**不重启核心**——纯冗余死配置。
- **建议**：`crontab -l` 中删掉 `20 */12` 那一行（由 `deploy_sync.py` 重写 crontab 时一并清理，或在路由器上手动 `crontab -e` 删除）。

---

## 四、已现场落地修复
1. ✅ `.gitignore` 扩充：忽略 `_router_ssh.py`（明文密码）、`ca-bundle.crt`、全部实验/备份脚本与本地样本。凭据泄露路径已切断，实测 `git check-ignore` 命中。
2. ✅ 生产文件（`_fine_sync.sh` 等）保留可见、未误伤。

## 五、建议行动清单（按优先级）

| 优先级 | 动作 | 风险/收益 |
|---|---|---|
| **P0** | `git add` 并提交 `_fine_sync.sh`、`deploy_local.py`、`deploy_sync.py`、`monitor_pick.py`、`play_test.py`、`audit_final.py`、`.gitignore`、`data/*.json` | 让路由器在跑的 sync 脚本、部署脚本有源码归属；否则仓库克隆即丢失生产逻辑 |
| **P0** | 密码迁 `.env`（`ROUTER_PASS`），`_router_ssh.py` 改读环境变量 | 双保险，即便误提交也不泄密 |
| **P1** | CI 增加 `python audit_final.py` 步骤 | 把 19 项结构审计变成提交门禁，防 build_final 回归 |
| **P1** | CI 校验 mihomo 固定 `v1.19.28` | 消除版本错位导致的「CI 过、路由器挂」 |
| **P2** | 重写 README 链路段（两层结构+探针+不点自动选择告诫） | 文档与实现对齐 |
| **P2** | 修 build_final.py：删死 guard、docstring/代码 tolerance 统一 | 可读性 |
| **P2** | 删 `_fine_sync.sh` 冗余 grep；重启后加探活 | 健壮性 |
| **P2** | 清理路由器 `20 */12` 冗余 cron | 消除潜在覆盖护栏的死配置 |

---
*审计脚本：`audit_final.py`（19/19 PASS）；本次未修改任何运行配置，仅扩充 `.gitignore`。*
