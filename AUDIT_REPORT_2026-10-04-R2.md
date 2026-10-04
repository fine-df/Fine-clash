# Fine-Clash 全链路代码审计（2026-10-04）

## 当前生产链路

GitHub 高星仓发现 → 订阅源文件发现 → 订阅解析 → SSRF/节点安全过滤 → Mihomo 批量验证 → Gemini / Google Play / Google / IPInfo → 深圳 TCP 硬质量闸 → 历史与评分 → Fine 池 → Fine-only 最终 Clash/Mihomo 配置 → GitHub Actions 校验/发布 → 路由器同步脚本 → Mihomo。

Bitz 已从生产链路彻底移除。当前不读取 Bitz Secret、不使用 Provider、不生成 Bitz 节点、不使用 Bitz 分流。

## 当前分流契约

- 中国大陆、局域网、微信/腾讯、小米/小米路由 → DIRECT
- 视频类、应用商店、下载类域名 → Fine
- 其他需要代理的海外流量 → Fine
- Fine-Auto：自动测速选择节点
- GLOBAL：切换 Mihomo global 模式后手动选择具体 Fine 节点，全部代理流量走所选节点
- 默认 mode: rule

## 源收集闸门

生产 fine_clash.py：
- GitHub repository search 按配置查询词搜索
- 当前 min_stars=30
- 当前每 query 最多 20 个仓
- 合并去重后最多 80 个仓进入生产发现
- 每仓最多 6 个候选源文件
- 单源最大 8 MB
- 至少解析出 2 个节点才成为源
- 缓存源也必须携带并满足当前 min_stars
- 当前 data/sources.json 已刷新为 15 个源，最低星数 303，无缺失星数元数据

discover_broad.py 是补充性的宽口径源挖掘脚本，不属于每次生产构建的必经步骤；其结果通过 data/sources.json 进入生产缓存。

## 节点质量链

节点必须同时通过：
- 支持类型：vmess / vless / trojan / ss
- server / port 基础校验
- DNS 解析后必须全部为公网地址
- REALITY 参数预检
- 非 tcp/ws/grpc 网络过滤
- Mihomo 启动/解析隔离
- Gemini 或 Google Play + clean score 门槛
- 深圳 TCP 探测：延迟 <= 400ms、丢包 <= 25%
- fail_closed=true：深圳探测失败不进入最终池
- 最终按评分、深圳延迟、丢包、稳定性、寿命，并按 server / org 多样性限制排序

## 最终配置与发布护栏

build_final.py 只接受 data/fine_pool.yaml，生成显式 Fine 节点：
- 无 proxy-providers
- 无 Bitz
- 无 GEOSITE
- 无第二最终配置文件
- MATCH,Fine
- 视频/商店规则在 MATCH 之前
- 国内 DIRECT 规则在 GEOIP 之前
- GLOBAL 和 Fine-Auto 均为显式节点策略组

GitHub Actions：
- pytest
- router sync script 执行 sh -n 语法检查
- Mihomo 配置测试
- 公开配置禁止出现 Provider、Bitz、token-bearing URL、GEOSITE
- 只有完整校验通过才 Publish

路由器同步：
- 只读取一个公开 live_clash.yaml
- 版本号单调递增保护
- 新配置先 Mihomo 自检，成功才替换
- 失败保留当前本地配置
- 脚本当前为 Fine-only 单一版本

## 本轮审计发现与处理

P1：Bitz 端点持续 HTTP 403。
处理：停止继续增加第三方访问链路，彻底移除 Bitz。

P1：router sync script 在连续补丁过程中出现重复残段。
处理：完整重建脚本，并加入 CI sh -n 闸门。

P1：Fine-only 迁移后测试仍残留 Bitz fixture。
处理：测试改为直接验证 Fine-only 配置与 GLOBAL 合约。

P1：缓存 data/sources.json 原先存在缺失星数元数据，理论上可能绕过当前高星闸门。
处理：刷新现有缓存源星数并在生产代码中对缓存源重新执行 min_stars 闸门。

P2：build_final.py 曾残留 Bitz 访问相关 imports / 常量。
处理：清理为 Fine-only 构建代码。

P2：旧审计报告与当前生产架构不一致。
处理：本报告改为当前 Fine-only 生产基线。

## 未进入本轮生产链的项目

- discover_broad.py 不在每次生产构建中运行，避免每轮执行大量 raw 路径扫描；它作为扩源工具使用，结果进入缓存后再由生产链验证。
- Bitz 历史 Git 提交中的旧凭据仍属于历史泄漏问题；当前生产文件不再使用该凭据，但历史 commit 不会因本轮代码删除而自动消失。后续应单独完成凭据轮换和历史清理。

## 审计结论

当前 Fine-only 代码链路的核心架构已经统一；本轮新增的主要风险不是 Fine 逻辑本身，而是快速迁移产生的旧架构残片。这些残片已逐项清理，并增加了缓存星数闸门和路由同步脚本语法闸门。

下一次主工作流需要作为最终验收：pytest → sh -n → Build Fine pool → Build profile → Mihomo validate → Publish 全部成功后，才视为本轮正式收口。
