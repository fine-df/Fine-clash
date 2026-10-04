# Fine-Clash

唯一对外订阅地址：

https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml

备用原始地址：

https://raw.githubusercontent.com/fine-df/Fine-clash/refs/heads/main/live_clash.yaml

## 固定分流逻辑

| 流量 | 出口 |
|---|---|
| 中国大陆网站 / 中国内网 | DIRECT |
| Ozon | Bitz |
| Amazon / Seller Central | Bitz |
| 其他全部海外流量 | Fine |

核心原则：

- Bitz 是严格白名单，不承担 MATCH。
- Fine 是海外默认出口。
- YouTube、Netflix、TikTok、下载和其他大流量海外网站不会进入 Bitz，因为 MATCH 永远落到 Fine。
- Bitz 节点来自独立订阅源；Fine 节点来自独立的公开节点发现与验证链，两个池不再互相拆借。
- 不再维护第二个最终订阅文件；fine_final.yaml 已退出生产链路。
- 订阅按 Mihomo / Clash.Meta 兼容语法设计，避免平台专用网卡名、固定 routing-mark 等设置。

## 自动更新

GitHub Actions 每 4 小时重新发现、验证 Fine 节点并生成 live_clash.yaml。只有最终配置通过结构校验和 Mihomo 配置测试后才发布；失败时保留上一份可用订阅。

路由器同步也只认同一个 live_clash.yaml 地址。
