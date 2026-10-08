# Fine-Clash

个人设备使用配置。

请勿公开传播订阅文件或节点内容。

## 默认分流与手动控制

默认运行模式是 Mihomo `rule`。

| 流量 | 出口 |
|---|---|
| 中国大陆网站 / 中国内网 | DIRECT |
| 视频站点（YouTube / Netflix / Twitch / Vimeo 等） | Fine |
| 应用商店与下载（Google Play / Microsoft / Steam 等） | Fine |
| 其他需要代理的海外流量 | Bitz（Bitz 未配置时为 Fine） |

`Fine` 为已验证免费节点池，支持自动测速和手动选择。

如果配置了 Bitz 上游，其他代理流量由 Bitz 兜底；未配置时全部回落到 Fine。

- `Fine-Auto`：Fine 内部自动测速子组。
- 节点更新时，上一版有效节点会参与连续性保留，并重新验证。
- 配置兼容 Mihomo / Clash.Meta / Shadowrocket / Clash for Android / v2rayN。

## 构建与更新

GitHub Actions 定期重新发现、验证节点并生成最新配置。

只有通过结构校验和 Mihomo 配置测试后才发布；失败时保留上一版可用配置。

## 安全说明

- 订阅入口不在 README 中公开。
- 不提交私人凭证和敏感订阅地址。
- 节点池来自公开源发现与自动验证流程。
