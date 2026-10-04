# Fine-Clash 全链路审计 R2（2026-10-04）

状态：**暂停生产合并，等待 Mihomo Provider→策略组兼容性实测。**

## 已审链路

`GitHub 源发现 → 订阅解析 → 节点安全过滤 → Mihomo 批量验证 → Gemini/Play/Google/IPInfo → 深圳 TCP 探测 → 历史/评分 → Fine 池 → build_final → live_clash.yaml → GitHub Actions 校验/发布 → _fine_sync.sh → 路由器 Mihomo`

另审查了新增的：
- Bitz / Fine 的 Auto + 手动节点结构
- Mihomo `GLOBAL` 全局手动接管
- provider 节点进入策略组的兼容性
- 공개订阅源带来的 SSRF 风险
- CI / 路由器 Mihomo 版本一致性

## 已确认并修复

### 1. Ozon/Amazon 规则优先级
原顺序中 `GEOIP,CN,DIRECT` 在 Ozon/Amazon 前。

现改为：

`DIRECT 特殊流量 → Ozon/Amazon → GEOIP,CN → MATCH,Fine`

避免显式业务域名因解析到中国 IP 而被 GEOIP 规则截走。

### 2. 发现源版本号排序正则
`discover_broad.py` 的版本号匹配存在转义错误，导致 `v2` / `version-2` 类路径无法按版本排序。

已修正。

### 3. 候选门槛注释漂移
实际 `candidate_gate=gemini_or_play` 是“Gemini 或 Google Play + clean score”进入深圳测试；`score_threshold` 只用于历史通过天数统计，不是当前候选硬门槛。

已统一代码注释。

### 4. 域名型代理地址 SSRF
原代码只拦截字面上的私网/回环 IP，恶意订阅可用公网域名解析到私网地址。

已增加：
- DNS 解析
- 任一解析地址非 global 即拒绝
- DNS 失败即拒绝
- 4096 条解析缓存
- 覆盖 GitHub、curated、direct URL 三条节点输入通道

### 5. 默认/全局路由结构
默认保持：

`mode: rule`

自动规则：
- Ozon/Amazon → Bitz
- 其他代理流量 → Fine
- 中国/局域网/Xiaomi/微信 → DIRECT

组内：
- Bitz-Auto / Fine-Auto 默认
- 可人工固定具体节点

特殊情况：
- 切换 Mihomo `global`
- `GLOBAL` 使用 `include-all: true`
- 手动指定单节点
- 全部流量走该节点
- 切回 `rule` 恢复自动分流

## 当前唯一阻断项：Mihomo Provider 聚合

已核实当前路由器版本为 v1.19.28（此前路由器审计证据）。

Mihomo 官方 Issue #2970 明确记录：
- v1.19.27：provider 节点正常进入 select/url-test 组
- v1.19.28：provider 可以下载并显示，但节点没有加入引用该 provider 的代理组
- 相同配置回退 v1.19.27 即恢复

该问题对应当前 Bitz 设计的关键路径：
- `Bitz` → `use: [BitzPool]`
- `Bitz-Auto` → `include-all-providers: true`
- `GLOBAL` → `include-all: true`

因此不能仅靠 `mihomo -t` 判定新结构可以在当前路由器上正常显示和选择。

## 已加入离线兼容性测试

新增：

`tools/provider_group_smoke.py`

测试完全使用本地 HTTP provider fixture，不使用真实 Bitz URL、不暴露真实节点。

它检查：
- Bitz select 是否包含 provider 节点
- Bitz-Auto url-test 是否包含 provider 节点
- GLOBAL 是否包含 provider 节点

后续应分别使用 Mihomo v1.19.28 与当前稳定版本执行。

## 当前版本事实

截至本次审计，Mihomo 官方稳定版为 v1.19.31；此前 CI 使用 latest，和路由器 v1.19.28 存在版本漂移。

因此后续版本策略应先实测：
1. v1.19.28：当前路由器兼容基线
2. v1.19.31：候选升级版本

在未完成该测试前，不升级路由器、不合并生产配置。

## 其他观察项

- `build_final.py` 中 Bitz subscription token 仍为源码明文，尚未处理；属于凭据管理风险。
- CI 仍下载 Mihomo latest，尚未改成固定版本；应在兼容性测试完成后决定固定到当前路由器版本还是升级后的版本。
- `GLOBAL` 的 `include-all` 不包含其他 proxy groups，只包含 outbound proxies 与 proxy sets，符合“全节点手动选择”的目标。

## 结论

**代码逻辑层面：新增 GLOBAL 需求已形成正确的双模式设计。**

**安全层面：发现到运行前的代理地址 SSRF 风险已补强。**

**业务路由层面：Ozon/Amazon 优先级已修正。**

**生产发布层面：暂不通过。唯一需要实际 Mihomo 运行验证的阻断项是 Provider 节点能否在当前/候选 Mihomo 版本中进入 Bitz、Bitz-Auto、GLOBAL。**
