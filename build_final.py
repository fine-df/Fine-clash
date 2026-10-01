# -*- coding: utf-8 -*-
"""由 live_clash.yaml（CI 产物）生成路由器专用 fine_final.yaml。

PROXY 组 = url-test，探测 https://play.google.com/store（用户实际诉求是 PLAY 商店），
在能开 PLAY 的节点中自动选延迟最小的那个（掉线即剔除）。

⚠️ 探针选型（2026-10-01 实测 19 节点）：
  play.google.com/store   通过 11/19   ← 直接代表 PLAY 可用性
  gemini.google.com/      通过 10/19
  gstatic.com/generate_204 通过  9/19
三者通过集合**互不包含**，所以探针必须选 PLAY 本体；
用 gstatic/204 会选中「204 通但 PLAY 打不开」的节点（实测 Turkey 即此情况）。

mihomo 对 3xx 判定为成功（不 follow 重定向），store 返回 302 即为可达。
tolerance=100ms 抑制快慢交替造成的横跳（切一次就是一次断流）。
"""
import io, os, sys, yaml

# ---- 参数唯一真源：构建产物和产物顶部的 fine-override 标记都从这里取值 ----
AUTO_NAME = "♻️ 自动选择"   # url-test 组：只放节点，永远选最快
PICK_NAME = "🚀 节点选择"   # select  组：手动入口，第一项=自动选择（=默认自动挡）
PROBE_URL = "https://play.google.com/store"
INTERVAL = 90        # 比速间隔（秒）。原 180 太钝：掉线后要 2 轮才恢复（实测 245s 才跳一次）
TIMEOUT = 10000      # 单节点探针超时（毫秒）。原 6000 会误杀首字节波动大的边缘节点
TOLERANCE = 50       # 与参考配置一致：50ms 内视为等价，避免两个节点反复横跳（切一次=一次断流）
UNIFIED_DELAY = False  # 上层是纯 select，没有自动父组，统一延迟量纲没有收益
LOG_LEVEL = "warning"
OVERRIDE_TAG = "v3"  # 本地参数版本标记，bump 它＝主动允许 sync 发布新参数

SRC = sys.argv[1] if len(sys.argv) > 1 else ("fine_only.yaml" if os.path.exists("fine_only.yaml") else "live_clash.yaml")
OUT = "fine_final.yaml"

base = yaml.safe_load(io.open(SRC, encoding="utf-8"))
names = [p["name"] for p in base.get("proxies", [])]
if not names:
    print("FATAL: no proxies in", SRC, file=sys.stderr)
    sys.exit(1)
print("source:", SRC, "nodes:", len(names))

if not any(g.get("name") == "PROXY" for g in base.get("proxy-groups", [])):
    print("FATAL: PROXY group not found in", SRC, file=sys.stderr)
    sys.exit(1)

# ============================ 两组结构（对齐参考配置 c.yaml）============================
# 为什么必须两层，而不是把节点直接平铺进一个组：
#
#   mihomo URLTest 源码（v1.19.28 adapter/outboundgroup/urltest.go）:
#       func (u *URLTest) fast(touch bool) C.Proxy {
#           ... if u.selected != "" {                     // 只要被「手动选过点」
#                   for _, proxy := range proxies {
#                       if proxy.Name() == u.selected { return proxy }  // 直接返回，跳过比速
#           ...
#           // 只有 selected == "" 时，才走「遍历全部成员取最小延迟」＋ tolerance 判定
#       }
#   → 在 url-test 组里点任何一个节点（Dashboard / Verge / API PUT）都会写 u.selected，
#     该组就此**被钉死在那台节点上**，比速形同虚设，直到重启核心或节点被判死。
#     实测：fixed=🇵🇱 Poland 而当时最快的 🇫🇷 只有 220ms（波兰 315ms）却永不切换。
#
#   解法就是参考配置的做法：
#     ♻️ 自动选择(url-test)  ← 只放节点，任何人不要去点它
#     🚀 节点选择(select)    ← 手动入口：第一项=自动选择（默认=自动挡），后面才是 DIRECT + 各节点
#   想锁某台节点，只在「节点选择」里选，永远不污染「自动选择」组。
# =============================================================================

auto = {
    "name": AUTO_NAME,
    "type": "url-test",
    "url": PROBE_URL,
    "interval": INTERVAL,
    "timeout": TIMEOUT,
    "tolerance": TOLERANCE,
    "lazy": False,
    "proxies": list(names),
}
# 第一项必须是自动选择：mihomo Select 组未指定 default 时取成员列表首项为初始选中项，
# 这样「开箱即自动挡」，用户不必先手动选一次。
pick = {
    "name": PICK_NAME,
    "type": "select",
    "proxies": [AUTO_NAME, "DIRECT"] + list(names),
}
# GLOBAL 只做外壳：不写它时 Clash Verge 会自行造一个 selector 并把全部节点平铺，
# 界面上的 GLOBAL 就变成「手动锁一个点、掉线不切」。
global_group = {"name": "GLOBAL", "type": "select", "proxies": [PICK_NAME]}
base["proxy-groups"] = [global_group, pick, auto]

# 规则出口改指向「节点选择」：所有原指向 PROXY 的规则、以及 MATCH 兜底，全部改道。
# （改道后默认链路 = 节点选择 → 自动选择 → 全场最快节点）
rules = base.get("rules", [])
new_rules = []
for r in rules:
    parts = r.split(",")
    kind = parts[0].strip().upper()
    if kind in ("MATCH", "FINAL"):
        parts[-1] = PICK_NAME
    elif parts[-1].strip() == "PROXY":
        parts[-1] = PICK_NAME
    new_rules.append(",".join(parts))
base["rules"] = new_rules

# 路由器是 mihomo v1.19.28，去掉 tun / 重定向模式相关字段，避免启动冲突
for k in ("tun", "redir-port", "tproxy-port", "routing-mark"):
    base.pop(k, None)
base["find-process-mode"] = "off"
base["log-level"] = LOG_LEVEL
base["external-controller"] = "0.0.0.0:9999"
base["external-ui"] = "ui"
base["external-ui-url"] = ""
base["authentication"] = []
base["allow-lan"] = True
base["mode"] = "rule"
base["ipv6"] = False
# unified-delay 只在「父组也是自动策略」时才需要（让父组拿到与节点同量纲的延迟）。
# 这里 GLOBAL 是纯 select 外壳，没有自动父组，统一延迟量纲买不到任何好处，
# 反而多一个不确定变量 —— 关掉，让 url-test 的选点判定回到最原始的最小值比较。
base["unified-delay"] = UNIFIED_DELAY

# 产物顶部写一行 fine-override 标记（yaml.safe_dump 会丢注释，所以自己写在 dump 之前）：
# 告诉路由器的 _fine_sync.sh「这份文件带本地调过的参数，CDN 旧参数版本不许盖回来」。
# 想主动发布新参数时，把 OVERRIDE_TAG 的序号 +1 即可（老 CDN 版本带 v(N-1) 标记 → 触发正常比对）。
dumped = yaml.safe_dump(base, allow_unicode=True, sort_keys=False, default_flow_style=False)
with io.open(OUT, "w", encoding="utf-8") as f:
    f.write("# fine-override: %s | %s(select)->%s(url-test) url=%s interval=%s timeout=%s tolerance=%s unified-delay=%s log=%s\n"
            % (OVERRIDE_TAG, PICK_NAME, AUTO_NAME, PROBE_URL, INTERVAL, TIMEOUT, TOLERANCE,
               UNIFIED_DELAY, LOG_LEVEL))
    f.write(dumped)
print("written", OUT, os.path.getsize(OUT), "bytes; %s -> %s over %d nodes"
      % (PICK_NAME, AUTO_NAME, len(names)))
