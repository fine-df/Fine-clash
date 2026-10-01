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

SRC = sys.argv[1] if len(sys.argv) > 1 else ("fine_only.yaml" if os.path.exists("fine_only.yaml") else "live_clash.yaml")
OUT = "fine_final.yaml"

base = yaml.safe_load(io.open(SRC, encoding="utf-8"))
names = [p["name"] for p in base.get("proxies", [])]
if not names:
    print("FATAL: no proxies in", SRC, file=sys.stderr)
    sys.exit(1)
print("source:", SRC, "nodes:", len(names))

replaced = 0
for g in base.get("proxy-groups", []):
    if g.get("name") != "PROXY":
        continue
    g.clear()
    g.update({
        "name": "PROXY",
        "type": "url-test",
        "url": "https://play.google.com/store",
        "interval": 180,
        "timeout": 6000,
        "tolerance": 100,
        "lazy": False,
        "proxies": list(names),
    })
    replaced += 1
if not replaced:
    print("FATAL: PROXY group not found in", SRC, file=sys.stderr)
    sys.exit(1)

# 路由器是 mihomo v1.19.28，去掉 tun / 重定向模式相关字段，避免启动冲突
for k in ("tun", "redir-port", "tproxy-port", "routing-mark"):
    base.pop(k, None)
base["find-process-mode"] = "off"
base["log-level"] = "info"
base["external-controller"] = "0.0.0.0:9999"
base["external-ui"] = "ui"
base["external-ui-url"] = ""
base["authentication"] = []
base["allow-lan"] = True
base["mode"] = "rule"
base["ipv6"] = False
base["unified-delay"] = True

with io.open(OUT, "w", encoding="utf-8") as f:
    yaml.safe_dump(base, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
print("written", OUT, os.path.getsize(OUT), "bytes; PROXY url-test over", len(names), "nodes")
