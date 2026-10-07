# Fine-Clash

唯一对外订阅地址：

https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml

备用原始地址：

https://raw.githubusercontent.com/fine-df/Fine-clash/refs/heads/main/live_clash.yaml

## 默认分流与手动控制

默认运行模式是 Mihomo `rule`：

| 流量 | 出口 |
|---|---|
| 中国大陆网站 / 中国内网 | DIRECT |
| 视频站点（YouTube / Netflix / Twitch / Vimeo 等） | Fine |
| 应用商店与下载（Google Play / Microsoft / Steam 等） | Fine |
| 其他需要代理的海外流量 | Bitz（Bitz 未配置时为 Fine） |

`Fine` 与 `Bitz` 是两组对称、随时可手动切换的代理组：

- `Fine`：已验证过的免费节点池，专门承载视频 / 商店 / 下载等大流量。
- `Fine-Auto`：Fine 内部隐藏的自动测速子组，选择 `Fine -> Fine-Auto` 时自动选优。
- `Bitz`：付费上游节点组，兜底除大流量之外的其余代理流量（`MATCH` 落到这里）。
- `Bitz-Auto`：Bitz 内部隐藏的自动测速子组，选择 `Bitz -> Bitz-Auto` 时自动选优。
- 每组各自带有 `DIRECT`：选择 `Fine -> DIRECT` / `Bitz -> DIRECT` 可对该组强制直连。
- 两组内的具体节点也都能人工点选固定。
- 定期更新时，上一版完整优质节点池会进入连续性保留位，仍需通过当轮完整验证；合格的旧节点优先保留，不会因源刷新直接消失；新节点只在旧节点失效退出后补入。

Bitz 的接入方式：

- Bitz 订阅 URL 只从环境变量 `FINE_BITZ_SUBSCRIPTION_URL` 读取，**不写进代码、不进 git 历史**。
- 该变量未设置时，产物自动退化为 Fine-only，`MATCH` 回到 `Fine`，公开订阅不含任何付费凭证。
- 该上游只认官方客户端的 User-Agent；mihomo 会忽略 provider 级的自定义请求头，因此必须用全局 `global-ua` 伪装 UA 才能取到订阅。
- 主机名必须同时在 `FINE_BITZ_ALLOWED_HOSTS` 里获批，且 URL 不能带凭证；否则 `build_final.py` 直接构建失败（fail-closed）。

另有独立的 `GLOBAL` 手动接管模式：

- 正常情况下不参与默认规则分流。
- 明确切换 Mihomo 到 `global` 模式后，可在 `GLOBAL` 中手动选择任意节点，使全部流量走该节点。
- 切回 `rule` 模式后，恢复上述自动分流。

核心原则：

- Fine 是免费已验证节点池，承载视频 / 商店 / 下载等大流量。
- Bitz 是付费上游节点组，承接其余代理流量并作为 `MATCH` 兜底；未配置时该职责回到 Fine。
- Fine 节点来自 GitHub 公开源发现与验证链。
- 不再维护第二个最终订阅文件；旧 `fine_final.yaml` 已退出生产链路。
- 订阅按 Mihomo / Clash.Meta 兼容语法设计，避免平台专用网卡名、固定 routing-mark 等设置。
- 公开订阅的红线：`live_clash.yaml` 经 jsDelivr 公开分发，**不得包含付费上游域名或任何凭证**。
  防线是三层：
  1. `build_final.py` 源头拦截 —— provider 主机名必须在 `FINE_BITZ_ALLOWED_HOSTS` 白名单内，
     且 URL 不得携带凭证（查询串 `token=/key=`、路径式 token、UUID 形态都会识别），否则构建失败。
  2. CI 与 `_fine_sync.sh` 的第二道 grep 闸门 —— 拦已知付费上游域名与 `token=` 等形态。
  3. 单测 `test_repository_contains_no_credential_bearing_url` 扫描仓库内所有 URL。
- 因此要在公开订阅里启用 Bitz，`FINE_BITZ_SUBSCRIPTION_URL` 必须指向**不含凭证的自建中继地址**，
  由中继侧补 User-Agent 并代理上游；不要直接填原始带 token 的机场 URL。
- 注意：grep 闸门是黑名单，只覆盖已知形态。真正的保证来自第 1 层的白名单，请不要绕过它。

## 自动更新

GitHub Actions 每 4 小时重新发现、验证 Fine 节点并生成 `live_clash.yaml`。只有最终配置通过结构校验和 Mihomo 配置测试后才发布；失败时保留上一份可用订阅。

路由器同步也只认同一个 `live_clash.yaml` 地址。
