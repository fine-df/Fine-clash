# Fine-Clash 全链路审计 R3（2026-10-04）

状态：**主线已重建为“4K 已验证基线 + 后续已确认修复”的显式节点架构。**

## 当前生产架构

`GitHub 源发现 → 订阅解析 → 节点安全过滤 → Mihomo 批量验证 → Gemini/Play/Google/IPInfo → 深圳 TCP 探测 → 历史/评分 → Fine 池 → build_final → live_clash.yaml → GitHub Actions → _fine_sync.sh → 路由器 Mihomo`

最终订阅现在明确包含两套真实 outbound：

- Bitz：构建时从独立 Bitz 订阅抓取、解析并直接写入 `proxies`
- Fine：来自 Fine 验证池

不再依赖 Mihomo 运行时 `proxy-providers` 聚合 Bitz 节点。

## 关键行为

默认 `mode: rule`：

- Ozon / Amazon → Bitz
- 中国大陆 / 局域网 / 微信 / Xiaomi → DIRECT
- 其他需要代理的海外流量 → Fine

Bitz / Fine 组均为：

`select → Auto + 具体节点`

因此：

- 默认使用 Auto
- 需要时可手动固定组内具体节点
- Bitz 节点会直接显示在客户端策略组中

GLOBAL 为显式手动模式：

- 正常 rule 模式不引用 GLOBAL
- 切换 Mihomo `global` 后，可在 GLOBAL 中直接选择任意具体节点
- 切回 `rule` 恢复自动分流

## 继承的已确认修复

保留之前已经验证有效的修复：

- Ozon / Amazon 规则置于 `GEOIP,CN,DIRECT` 之前
- 移除 `GEOSITE` 依赖
- Xiaomi / WeChat / 局域网 DIRECT
- 节点 fingerprint 包含传输与安全参数
- 深圳延迟 >400ms 或丢包 >25% 的硬闸
- 节点 REALITY 参数预检
- Mihomo 批量解析错误隔离
- 公网订阅源 DNS→私网 SSRF 防护
- source version 排序修复
- main 发布护栏
- Mihomo CI 固定为当前路由器兼容基线 v1.19.28

## 为什么放弃 Provider 聚合

之前虽然离线验证了 v1.19.28 / v1.19.31 的 Provider 聚合行为，但实际目标是“客户端 Bitz 组必须直接看到可手动选择的具体 Bitz 节点”。

Provider 方案增加了一个没有必要的中间层，并且使最终输出对客户端/provider 展开行为产生额外依赖。

因此本轮明确退回更简单、更可观察的架构：

`Bitz subscription → build-time parse → top-level proxies → Bitz-Auto / Bitz select`

这是本轮的核心架构决策。

## 当前验证状态

最近一次 GitHub Actions 已证明新主线的测试主体可以启动；第一次失败仅发生在两个旧测试仍按旧 `build_final.main()` 源码文本断言。

这两个测试已经改为验证实际生成配置的行为。

**当前新的完整 CI 尚未获得结果。**

原因不是代码测试失败，而是本次 GitHub API 提交没有再次产生对应的 push workflow run。

因此当前仓库代码已经切换到新架构，但 `live_clash.yaml` 仍需要下一次成功的主工作流重新生成后，才会成为新的生产输出。

## 单独遗留问题

- `BITZ_SUB_URL` 当前仍有源码 fallback token；这属于后续凭据治理问题，不应与本次架构修复混在一起。
- 路由器本地 `_fine_sync.sh` 已同步修改为要求显式 Bitz 节点。
