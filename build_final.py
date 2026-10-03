# -*- coding: utf-8 -*-
"""由 live_clash.yaml（CI 裸节点池产物）原地重写成四端统一分流订阅 live_clash.yaml。

四端（Win / 安卓 / iOS / 路由器）统一订阅这一个链接，且按用户给定层级分流：
  DIRECT（微信/QQ/腾讯直连）
  ↓ 中国大陆网站 → DIRECT
  ↓ Bitz：OZON / AMAZON / 低流量网站
  ↓ Fine：其他所有海外流量（MATCH）


分组结构（用户给定路由层级）：
  DIRECT（微信/QQ/腾讯直连）
  ↓ 中国大陆网站 → DIRECT
  ↓ Bitz：OZON / AMAZON / 低流量网站
  ↓ Fine：其他所有海外流量（MATCH）

实现：Bitz / Fine 两个 url-test 组各持全部节点，但探针不同
      （Bitz=RU 电商可达性 ozon.ru，Fine=综合海外 Web play.google.com/store 探针），
      规则按层级把流量引到对应组；手动入口 节点选择 可强制某条链路。

⚠️ 探针选型（2026-10-01 实测 19 节点）：
  play.google.com/store   通过 11/19   ← 直接代表 PLAY 可用性
  gemini.google.com/      通过 10/19
  gstatic.com/generate_204 通过  9/19
三者通过集合**互不包含**，所以探针必须选 PLAY 本体；
用 gstatic/204 会选中「204 通但 PLAY 打不开」的节点（实测 Turkey 即此情况）。

mihomo 对 3xx 判定为成功（不 follow 重定向），store 返回 302 即为可达。
tolerance=50ms 抑制快慢交替造成的横跳（切一次就是一次断流）。
"""
import io, os, sys, re, yaml

# ---- 参数唯一真源：构建产物和产物顶部的 fine-override 标记都从这里取值 ----
BITZ_NAME = "Bitz"    # url-test 组：OZON/AMAZON/低流量网站走这里（RU 电商可达性探针）
FINE_NAME = "Fine"    # url-test 组：其他所有海外流量走这里（综合 Web 探针）
PICK_NAME = "🚀 节点选择"   # select 组：手动入口，第一项=Fine（=默认海外出口）
BITZ_PROBE = "https://www.ozon.ru"             # Bitz 探针：代表 RU 电商可达性
FINE_PROBE = "https://play.google.com/store"   # Fine 探针：代表综合海外 Web 可用性；按 2026-10-01 实测 PLAY 通过率最高、最代表通用可达性（优于 gemini/gstatic）
INTERVAL = 90        # 比速间隔（秒）。
TIMEOUT = 10000      # 单节点探针超时（毫秒）。
TOLERANCE = 50       # 与参考配置一致：50ms 内视为等价，避免两个节点反复横跳（切一次=一次断流）
UNIFIED_DELAY = False
LOG_LEVEL = "warning"
OVERRIDE_TAG = "v5"  # 本地参数版本标记，bump 它＝主动允许 sync 发布新结构（Bitz/Fine 双组）

SRC = sys.argv[1] if len(sys.argv) > 1 else ("fine_only.yaml" if os.path.exists("fine_only.yaml") else "live_clash.yaml")
# 用户要求：四端（Win/安卓/iOS/路由器）统一订阅 live_clash.yaml 且按规则分流。
# 因此本脚本把「裸节点池(live_clash)」原地重写成「最终分流配置(live_clash)」，
# 让 live_clash.yaml 这一个链接既是生成产物也是四端共用的分流订阅。
OUT = "live_clash.yaml"

base = yaml.safe_load(io.open(SRC, encoding="utf-8"))
names = [p["name"] for p in base.get("proxies", [])]
if not names:
    print("FATAL: no proxies in", SRC, file=sys.stderr)
    sys.exit(1)
print("source:", SRC, "nodes:", len(names))

if not any(g.get("name") == "PROXY" for g in base.get("proxy-groups", [])):
    print("FATAL: PROXY group not found in", SRC, file=sys.stderr)
    sys.exit(1)

# ============================ 双 url-test 分组（Bitz / Fine）============================
# 用户给定路由层级：
#   DIRECT（微信/QQ/腾讯直连）
#   ↓ 中国大陆网站 → DIRECT
#   ↓ Bitz：OZON / AMAZON / 低流量网站
#   ↓ Fine：其他所有海外流量
# 实现：两个 url-test 组各持全部节点，但探针不同（Bitz=RU 电商可达性，Fine=综合 Web），
#      规则按层级把流量引到对应组；手动入口 节点选择 可强制某条链路。
# =============================================================================

bitz = {
    "name": BITZ_NAME,
    "type": "url-test",
    "url": BITZ_PROBE,
    "interval": INTERVAL,
    "timeout": TIMEOUT,
    "tolerance": TOLERANCE,
    "lazy": False,
    "proxies": list(names),
}
fine = {
    "name": FINE_NAME,
    "type": "url-test",
    "url": FINE_PROBE,
    "interval": INTERVAL,
    "timeout": TIMEOUT,
    "tolerance": TOLERANCE,
    "lazy": False,
    "proxies": list(names),
}
# 节点选择：手动入口。第一项=Fine（与 MATCH→Fine 默认一致）；
# 后面挂 Bitz / DIRECT / 各节点，方便手动强制某条链路。
pick = {
    "name": PICK_NAME,
    "type": "select",
    "proxies": [FINE_NAME, BITZ_NAME, "DIRECT"] + list(names),
}
# GLOBAL 只做外壳：不写它时 Clash Verge 会自行造一个 selector 并把全部节点平铺，
# 界面上的 GLOBAL 就变成「手动锁一个点、掉线不切」。
global_group = {"name": "GLOBAL", "type": "select", "proxies": [PICK_NAME]}
base["proxy-groups"] = [global_group, pick, bitz, fine]

# ===================== 规则：按用户给定层级重组 =====================
# 优先级 = 数组顺序（越靠前越高）：
#   ① DIRECT（微信/QQ/腾讯，来自 SRC）
#   ② 中国大陆网站 → DIRECT（GEOSITE,CN / GEOIP,CN）
#   ③ Bitz：OZON / AMAZON / 低流量网站
#   ④ Fine：其他所有海外流量（MATCH）
SRC_RULES = base.get("rules", [])
kept = [r for r in SRC_RULES if not re.match(r"^\s*(MATCH|FINAL)\b", r, re.I)]
# OZON / AMAZON / 低流量站点 → Bitz（如要扩「低流量网站」类别，在此追加 DOMAIN 规则即可）
BITZ_RULES = [
    "DOMAIN-SUFFIX,ozon.ru,Bitz",
    "DOMAIN-SUFFIX,ozon.com,Bitz",
    "DOMAIN-SUFFIX,ozon.kz,Bitz",
    "DOMAIN-SUFFIX,ozon.by,Bitz",
    "DOMAIN-SUFFIX,amazon.com,Bitz",
    "DOMAIN-SUFFIX,amazon.co.uk,Bitz",
    "DOMAIN-SUFFIX,amazon.de,Bitz",
    "DOMAIN-SUFFIX,amazon.fr,Bitz",
    "DOMAIN-SUFFIX,amazon.es,Bitz",
    "DOMAIN-SUFFIX,amazon.it,Bitz",
    "DOMAIN-SUFFIX,amazon.nl,Bitz",
    "DOMAIN-SUFFIX,amazon.pl,Bitz",
    "DOMAIN-SUFFIX,amazon.se,Bitz",
    "DOMAIN-SUFFIX,amazon.ca,Bitz",
    "DOMAIN-SUFFIX,amazon.com.au,Bitz",
    "DOMAIN-SUFFIX,amazon.co.jp,Bitz",
    "DOMAIN-SUFFIX,amazon.in,Bitz",
    "DOMAIN-SUFFIX,amazon.com.br,Bitz",
    "DOMAIN-SUFFIX,sellercentral.amazon.com,Bitz",
]
new_rules = kept + BITZ_RULES + ["MATCH,Fine"]
base["rules"] = new_rules

# 路由器是 mihomo v1.19.28 —— 保留 tun / routing-mark。
# 实测运行态（fine_merged，含 tun）工作正常，且订阅此 CDN 链接重启后也需保持透明代理，故不再剥离。
base["find-process-mode"] = "off"
base["log-level"] = LOG_LEVEL
base["external-controller"] = ":9999"
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

# 复用已验证的路由器壳（fine_merged.yaml）：tun / experimental / routing-mark / secret
# 原样保留（路由器实测可用），确保四端统一链接在路由器上稳定分流、透明代理不丢。
# dns 必须改为跨平台公网版：原 fine_merged 用 localhost / 127.0.0.1 作 nameserver，
# 仅路由器成立，手机/PC 订阅会断 DNS。这里只把 nameserver / default-nameserver 改公网，
# 其余（listen: :1053 / fake-ip / fake-ip-filter）保持与路由器一致。
_SHELL_SRC = "fine_merged.yaml"
if os.path.exists(_SHELL_SRC):
    _shell = yaml.safe_load(io.open(_SHELL_SRC, encoding="utf-8")) or {}
    for _k in ("tun", "experimental", "routing-mark", "secret"):
        if _k in _shell:
            base[_k] = _shell[_k]
    if "dns" in _shell:
        _dns = dict(_shell["dns"])
        _dns["nameserver"] = ["223.5.5.5", "119.29.29.29"]
        _dns["default-nameserver"] = ["223.5.5.5", "119.29.29.29"]
        base["dns"] = _dns
else:
    base.setdefault("tun", {"enable": True, "stack": "system", "device": "utun",
                            "auto-route": True, "auto-detect-interface": True})
    base.setdefault("experimental", {"ignore-resolve-fail": True})
    base.setdefault("routing-mark", 7894)
    base.setdefault("dns", {
        "enable": True, "listen": ":1053", "use-hosts": True, "ipv6": False,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"], "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16", "fake-ip-filter": ["*.lan", "*.local", "localhost", "127.0.0.1", "::1"],
        "nameserver": ["223.5.5.5", "119.29.29.29"],
    })

# 产物顶部写一行 fine-override 标记（yaml.safe_dump 会丢注释，所以自己写在 dump 之前）：
# 告诉路由器的 _fine_sync.sh「这份文件带本地调过的参数，CDN 旧参数版本不许盖回来」。
# 想主动发布新参数时，把 OVERRIDE_TAG 的序号 +1 即可（老 CDN 版本带 v(N-1) 标记 → 触发正常比对）。
dumped = yaml.safe_dump(base, allow_unicode=True, sort_keys=False, default_flow_style=False)
with io.open(OUT, "w", encoding="utf-8") as f:
    f.write("# fine-override: %s | Bitz(url-test)=%s Fine(url-test)=%s 节点选择(select)->[Fine,Bitz,DIRECT] url Bitz=%s Fine=%s interval=%s timeout=%s tolerance=%s unified-delay=%s log=%s\n"
            % (OVERRIDE_TAG, BITZ_NAME, FINE_NAME, BITZ_PROBE, FINE_PROBE, INTERVAL, TIMEOUT,
               TOLERANCE, UNIFIED_DELAY, LOG_LEVEL))
    f.write(dumped)
print("written", OUT, os.path.getsize(OUT), "bytes; %s=[%s,Fine] over %d nodes; rules=%d (Bitz=%d)"
      % (PICK_NAME, BITZ_NAME, len(names), len(new_rules), len(BITZ_RULES)))
