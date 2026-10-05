# Fine-clash 链路代码审计（2026-10-04）

> 方法：不带历史结论、从零独立读码（`fine_clash.py` 780 行 / `build_final.py` / `_find_live.py` /
> `_deploy_cfg.py` / `_router_ssh.py` / `_fine_sync.sh` / `config.yaml` / `discover_broad.py`）。
> 每条结论给出 **文件:行号:证据**。审计产出 + 修复已 commit `fde45b0` 推 `@main`。

## 一、活动链路（审计范围）

```
GitHub 搜索 / data/sources.json
   └─ fine_clash.py run()        发现+实测+rank → live_clash.yaml(裸池,带PROXY组) + live_probes.json
        └─ build_final.py         裸池 → 四端分流(live_clash.yaml 原地重写成 Bitz/Fine 互斥 + 规则)
             └─ cp → fine_final.yaml   (CI: update.yml)
                  └─ 路由器 _fine_sync.sh  每15min 从 jsDelivr@main 拉取(版本单调护栏) → 生效
手动扩池：_find_live.py (经路由器 delay API 测活) → 同链路
```

## 二、确认真实 BUG（已修复）

### B1 — `build_final.py:85-90` 无探针兜底丢节点
**证据**：无 `live_probes.json` 时 `fine_names=[]`→兜底取 `names[:len//2]`；随后
`bitz_names=[n for n in names if n not in fine_names and _ok(n)]` 因 `_ok` 全 False 为空
→安全兜底 `bitz_names=fine_names`。结果：后半节点整体被丢弃、两组重复前半。
**修复**：无探针时确定性对半切 `fine=names[:(n+1)//2]`, `bitz=names[(n+1)//2:]`，互补零重叠、不丢节点。

### B2 — `build_final.py:61-63` 非幂等脚枪
**证据**：脚本**原地重写**同一 `live_clash.yaml`。输入无 `PROXY` 组即 `sys.exit(1)`。
对已生成的成品再次 `build_final.py live_clash.yaml` 必 FATAL。
**修复**：检测产物已含 `Bitz/Fine` 组 → 打印 `skip: already built` 并 `exit 0`（幂等）。

### B3 — `_fine_sync.sh:59` `NPROXY -ge 3` 枯水期冻结路由
**证据**：实测当前合法池仅 2 节点（`awk` 同公式=2，见 `fine_final.yaml`）。护栏要求 ≥3
才接受 CDN 更新；免费节点市场常态仅 1~2 活节点，导致自动同步静默冻结在陈旧配置。
真实有效性由下方 `CrashCore -t` 把关。
**修复**：`NPROXY -ge 1`（非空即可，≥1 工作节点优于陈旧 0）。

### B4 — `_find_live.py:64` 分类探针与 FINE_PROBE 不一致
**证据**：`_find_live` 用 `play.google.com/store` 判定 `play` 写 `live_probes.json`，
但 `build_final.py:40` 的 `FINE_PROBE=https://www.youtube.com`。错位导致「能开 play 但开不了
youtube」的节点被错放进 Fine 组。
**修复**：分类探针统一为 `youtube.com`（与 FINE_PROBE 一致）。

### B5 — `fine_clash.py:691` 死代码
**证据**：`candidate=(item["gemini"] and item["google_play"] and score>=...)` 在 691 行算一次，
699-706 行被 `candidate_gate` 逻辑整体覆盖，691 行永不生效。
**修复**：删除 691 行。

## 三、低危 / 观察（未强改，记录）

- `fine_clash.py:640` curated base64 解码兜底：明文订阅被当 base64 解码可能产生假节点，
  但被 try/except 兜住，`decoded if decoded else raw` 在非 base64 明文时拿乱码当 text。低危。
- `discover_broad.py:84-85` `fc.load_rules()` 重复调用两次（每次重读 config.yaml）。微效瑕疵。
- `build_final.py` 把 `dns` 整体覆盖为 `fine_merged.yaml` 的公网版；`build_outputs` 内部的
  `dns` 配置（含 `redir-host`）会被覆盖，属无效配置（死配置），因被覆盖无副作用，未动。

## 四、清洗（已执行）

引用扫描（`re` 全仓文本匹配，排除 `.git/__pycache__/archive/data/.github`）确认 **64 个 `.py`
无任何文件引用**，全部为调试期一次性脚本（`diag*`/`probe*`/`check*`/`verify*`/`upload_cfg*`/
`push*`/`start*`/`restart*`/`gh_*` 等）。
加 `extra_pool.yaml`（CI `update.yml:66` 已标注 "build_final.py 不消费它（死代码）"），
一并移入 `archive/`（可恢复，非删除）。

结果：根目录 `.py` 由 ~90 个收敛为 **24 个活动链路文件**。

## 五、验证

- `py_compile` 全部活动 `.py` 通过；`import fine_clash` 通过。
- `build_final.py` 三路径回归全过：
  - 探针分类：A(play)/B(ok-not-play)/C(dead) → `Bitz=[B] Fine=[A]` ✅
  - 无探针 5 节点 → `Fine=[N0,N1,N2] Bitz=[N3,N4]`，零重叠、全集覆盖 ✅
  - 已构建成品再跑 → `skip: already built` exit 0 ✅
- `_fine_sync.sh` `bash -n` 语法通过。

## 六、待办（需人工/运维确认）

- **B3 需重推 `_fine_sync.sh` 到路由器**才生效：该脚本运行态在路由器上，不在标准路径
  （`/tmp/ShellCrash/`、`/data/clash/` 均未命中，crontab 无 sync 条目，疑由 ShellCrash 自身
  定时机制托管）。当前路由器跑 v7 正常，不受代码改动影响；重推到实际位置后枯水期冻结即解。
- 夜间（23:00 后，按 Token 刷新窗口）跑 `_find_live.py` 扩池，B1/B4 修复将在多节点时显现
  （油管可达节点进 Fine、其余进 Bitz，面板真正互斥分离）。
