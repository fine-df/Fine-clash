# -*- coding: utf-8 -*-
"""用路由器 mihomo API 对每节点实测 play/ozon 延迟，统计真正可用节点。"""
import json, sys, time, urllib.request, urllib.error

BASE = "http://192.168.0.1:9999"


def get(path):
    for _ in range(3):
        try:
            with urllib.request.urlopen(BASE + path, timeout=12) as r:
                return json.load(r)
        except Exception as e:
            time.sleep(1)
    return None


def delay(name, url):
    q = "/proxies/%s/delay?url=%s&timeout=9000" % (urllib.parse.quote(name), urllib.parse.quote(url, safe=""))
    try:
        with urllib.request.urlopen(BASE + q, timeout=12) as r:
            d = json.load(r)
            return d.get("delay")
    except urllib.error.HTTPError as e:
        return None
    except Exception:
        return None


import urllib.parse

d = get("/proxies")
if not d:
    print("API fail"); sys.exit(1)
proxies = d["proxies"]
nodes = [k for k, v in proxies.items() if v["type"] in ("Shadowsocks", "Vless", "Vmess", "Trojan", "SSR")]
print("total node-type entries:", len(nodes))

play_ok, ozon_ok = [], []
rows = []
for n in nodes:
    dp = delay(n, "https://play.google.com/store")
    do = delay(n, "https://www.ozon.ru")
    alive_p = isinstance(dp, int) and dp > 0
    alive_o = isinstance(do, int) and do > 0
    rows.append((n, dp, do, alive_p, alive_o))
    if alive_p:
        play_ok.append(n)
    if alive_o:
        ozon_ok.append(n)
    print("%-46s play=%-6s ozon=%-6s" % (n[:44], dp, do))

print("\n=== SUMMARY ===")
print("play(google store) reachable :", len(play_ok), "/", len(nodes))
print("ozon reachable              :", len(ozon_ok), "/", len(nodes))
print("\nplay-OK nodes:")
for n in play_ok:
    print("  ", n)
