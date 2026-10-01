# -*- coding: utf-8 -*-
"""由 live_clash.yaml（CI 产物）生成路由器专用 fine_final.yaml。

PROXY 组 = url-test，探测 https://gemini.google.com/ ，
仅在能连上 GEMINI 的节点中自动选延迟最小的那个（掉线即剔除）。
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
        "url": "https://gemini.google.com/",
        "interval": 120,
        "timeout": 8000,
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
