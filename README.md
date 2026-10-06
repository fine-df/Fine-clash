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
| Ozon | DIRECT |
| Amazon / Seller Central | Fine |
| 其他需要代理的海外流量 | Fine |

- `Fine`：唯一主操作组。
- `AUTO`：Fine 内部隐藏的自动测速子组，选择 `Fine -> AUTO` 时自动测速选优。
- `DIRECT`：直接加入 Fine，选择 `Fine -> DIRECT` 时强制直连。
- Fine 内的具体节点：需要时可人工固定某个节点。
- 定期更新时，上一版完整优质节点池会进入连续性保留位，仍需通过当轮完整验证；合格的旧节点优先保留，不会因源刷新直接消失；新节点只在旧节点失效退出后补入。

另有独立的 `GLOBAL` 手动接管模式：

- 正常情况下不参与默认规则分流。
- 明确切换 Mihomo 到 `global` 模式后，可在 `GLOBAL` 中手动选择任意节点，使全部流量走该节点。
- 切回 `rule` 模式后，恢复上述自动分流。

核心原则：

- Fine 是唯一代理节点池，也是全部海外代理流量的默认出口。
- 视频、商店下载和其他大流量海外网站进入 Fine；`MATCH` 也落到 Fine。
- Fine 节点来自 GitHub 公开源发现与验证链。
- 不再维护第二个最终订阅文件；旧 `fine_final.yaml` 已退出生产链路。
- 订阅按 Mihomo / Clash.Meta 兼容语法设计，避免平台专用网卡名、固定 routing-mark 等设置。

## 自动更新

GitHub Actions 每 4 小时重新发现、验证 Fine 节点并生成 `live_clash.yaml`。只有最终配置通过结构校验和 Mihomo 配置测试后才发布；失败时保留上一份可用订阅。

路由器同步也只认同一个 `live_clash.yaml` 地址。
