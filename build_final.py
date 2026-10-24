# -*- coding: utf-8 -*-
"""Build the single public Clash/Mihomo profile from LIVE free node sources.

Architecture (2026-10-24, fail-safe flat aggregation):
- One subscription link (jsDelivr -> live_clash.yaml) is consumed by FOUR clients
  behind the GFW (iOS/Shadowrocket, Android/mihomo, router/ShellCrash, PC/Clash
  Verge). Every one of them must be able to PARSE the file and find live nodes.
- Why a flat `proxies:` list (not proxy-providers):
    * The router's `check_groups` validator (_fine_sync.sh) HARD-rejects any
      profile containing `proxy-providers:` (legacy guard), so a provider-based
      file would make the router refuse the update.
    * Shadowrocket's Clash parser is partial and does not reliably consume
      `proxy-providers:` / `use:` — risking the one currently-working end.
  A flat list is universally parseable, so all four ends stay alive.
- "Always live" is achieved by (a) aggregating MANY nodes from MULTIPLE free
  sources (diversity => some always survive), and (b) the CI rebuilding this file
  on a schedule (every few hours) so the embedded snapshot never freezes. The
  previous failure (frozen pool) came from a China-network publish gate that the
  US runner could not satisfy; that gate is gone, so the profile now regenerates
  continuously. Clients still url-test locally (AUTO group) to pick the fastest.
- Free-only: sources MUST be public free aggregators. No paid airports, no Bitz,
  no收费上游 (permanent red line).
"""
from __future__ import annotations
import re
import ssl
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import yaml

OUT = Path("live_clash.yaml")
CFG = Path("config.yaml")

# ---- Free source catalog (jsDelivr-wrapped GitHub raw = China-reachable) -----
# Each entry: id, url, prefix(for embedded flat list to avoid name collisions
# across sources), take(max embedded from this source).
SOURCES = [
    {
        "id": "ermaozi",
        "url": "https://cdn.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/clash.yml",
        "prefix": "E-",
        "take": 45,
    },
    {
        "id": "chengaopan",
        "url": "https://cdn.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@main/snippets/nodes.yml",
        "prefix": "C-",
        "take": 35,
    },
]

ALLOWED_TYPES = {"vmess", "vless", "trojan", "ss"}
HEALTH_URL = "https://www.google.com/generate_204"

# Junk / decoy / placeholder node names from free aggregators (not real proxies).
JUNK_RE = re.compile(
    r"(防范|渗透|测试|占位|无效|过期|dead|expired|机场|订阅|示例|demo|fake|"
    r"test|unknown|null|占位符|临时|失效|不可用|广告|引流)",
    re.IGNORECASE,
)
# Domestic "exit" nodes are useless as a GFW bypass in the flat list.
CN_RE = re.compile(r"(🇨🇳|中国|cn[-_])", re.IGNORECASE)

VIDEO_DOMAINS = ["youtube.com","youtu.be","ytimg.com","googlevideo.com","netflix.com","nflxvideo.net","nflximg.net","twitch.tv","ttvnw.net","vimeo.com"]
STORE_DOMAINS = ["play.google.com","googleplay.com","dl.google.com","gvt1.com","gvt2.com","microsoft.com","microsoftstore.com","apps.microsoft.com","steampowered.com","steamcommunity.com"]
OZON_DIRECT = ["DOMAIN-SUFFIX,ozon.ru,DIRECT","DOMAIN-SUFFIX,ozon.com,DIRECT","DOMAIN-SUFFIX,ozonusercontent.com,DIRECT","DOMAIN-SUFFIX,ozoncdn.ru,DIRECT","DOMAIN-SUFFIX,ozoncdn.com,DIRECT","DOMAIN-SUFFIX,o3.ru,DIRECT","DOMAIN-SUFFIX,ozone.ru,DIRECT","DOMAIN-SUFFIX,ozonpartners.ru,DIRECT","DOMAIN-SUFFIX,ozon.tech,DIRECT","DOMAIN-SUFFIX,ozon.by,DIRECT","DOMAIN-SUFFIX,ozon.kz,DIRECT"]
WECHAT_DIRECT = ["DOMAIN-SUFFIX,weixin.qq.com,DIRECT","DOMAIN-SUFFIX,wx.qq.com,DIRECT","DOMAIN-SUFFIX,wechat.com,DIRECT","DOMAIN-SUFFIX,qpic.cn,DIRECT","DOMAIN-SUFFIX,qlogo.cn,DIRECT","DOMAIN-SUFFIX,gtimg.cn,DIRECT","DOMAIN-SUFFIX,gtimg.com,DIRECT","DOMAIN-SUFFIX,qq.com,DIRECT","DOMAIN-SUFFIX,tenpay.com,DIRECT","DOMAIN-SUFFIX,wechatpay.cn,DIRECT","DOMAIN-SUFFIX,tencent.com,DIRECT","DOMAIN-SUFFIX,tencent-cloud.com,DIRECT","DOMAIN-SUFFIX,myqcloud.com,DIRECT","DOMAIN-SUFFIX,tencentcos.cn,DIRECT"]
WPS_DIRECT = ["DOMAIN-SUFFIX,wps.cn,DIRECT","DOMAIN-SUFFIX,wps.com,DIRECT","DOMAIN-SUFFIX,kdocs.cn,DIRECT","DOMAIN-SUFFIX,kdocs.com,DIRECT","DOMAIN-SUFFIX,kingsoft.com,DIRECT"]
XIAOMI_DIRECT = ["DOMAIN-SUFFIX,mi.com,DIRECT","DOMAIN-SUFFIX,xiaomi.com,DIRECT","DOMAIN-SUFFIX,miwifi.com,DIRECT","DOMAIN-SUFFIX,miui.com,DIRECT","DOMAIN-SUFFIX,mijia.com,DIRECT","DOMAIN-SUFFIX,xiaomi.cn,DIRECT"]
LOCAL_IOT_DIRECT = ["IP-CIDR,224.0.0.0/4,DIRECT,no-resolve","IP-CIDR,169.254.0.0/16,DIRECT,no-resolve"]
PRIVATE_DIRECT = ["DOMAIN-SUFFIX,lan,DIRECT","DOMAIN-SUFFIX,local,DIRECT","DOMAIN-SUFFIX,localhost,DIRECT","DOMAIN-SUFFIX,cn,DIRECT","DOMAIN-SUFFIX,com.cn,DIRECT","DOMAIN-SUFFIX,net.cn,DIRECT","DOMAIN-SUFFIX,gov.cn,DIRECT","DOMAIN-SUFFIX,edu.cn,DIRECT","IP-CIDR,10.0.0.0/8,DIRECT,no-resolve","IP-CIDR,172.16.0.0/12,DIRECT,no-resolve","IP-CIDR,192.168.0.0/16,DIRECT,no-resolve","IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"]
# Keep subscription-refresh traffic on domestic-reachable links so the client can
# re-pull this very file even when its current nodes are slow/dead.
SUBSCRIPTION_CDN_DIRECT = ["DOMAIN-SUFFIX,jsdelivr.net,DIRECT","DOMAIN-SUFFIX,github.com,DIRECT","DOMAIN-SUFFIX,raw.githubusercontent.com,DIRECT"]

UA = "Fine-clash-builder/1.0 (+https://github.com/fine-df/Fine-clash)"


def fetch_yaml(url, timeout=30, retries=2):
    ctx = ssl.create_default_context()
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                text = r.read().decode("utf-8", "replace")
            return yaml.safe_load(text) or {}
        except Exception as e:
            if attempt == retries:
                print(f"fetch_yaml WARN: failed {url}: {e}")
                return None
    return None


def fingerprint(n):
    keys = ("type", "server", "port", "uuid", "password", "cipher", "sni", "servername")
    return "|".join(str(n.get(k, "")) for k in keys)


def valid_node(n):
    if not isinstance(n, dict):
        return False
    for k in ("name", "server", "port", "type"):
        if not n.get(k):
            return False
    if str(n.get("type")) not in ALLOWED_TYPES:
        return False
    name = str(n.get("name", ""))
    if JUNK_RE.search(name):
        return False
    if CN_RE.search(name):
        return False
    srv = str(n.get("server", "")).strip()
    if srv in ("", "0.0.0.0", "127.0.0.1", "localhost"):
        return False
    if not re.match(r"^[\w.\-]+$", srv):
        return False
    return True


def collect_flat():
    """Aggregate a fresh, prefixed, de-duplicated flat node list for all clients."""
    flat = []
    seen = set()
    for src in SOURCES:
        doc = fetch_yaml(src["url"])
        if not doc:
            print(f"collect_flat: source {src['id']} unavailable, skipped")
            continue
        nodes = doc.get("proxies") or []
        if not isinstance(nodes, list):
            continue
        taken = 0
        for n in nodes:
            if taken >= src["take"]:
                break
            if not valid_node(n):
                continue
            node = dict(n)
            node["name"] = f"{src['prefix']}{str(node['name']).strip()}"
            fp = fingerprint(node)
            if fp in seen:
                continue
            seen.add(fp)
            flat.append(node)
            taken += 1
        print(f"collect_flat: {src['id']} -> added {taken} (prefix {src['prefix']})")
    return flat


def build_proxy_groups(flat_names):
    fine_proxies = ["AUTO", "DIRECT"] + flat_names
    return [
        {
            "name": "Fine",
            "type": "select",
            "proxies": fine_proxies,
            "default-selected": flat_names[0] if flat_names else "DIRECT",
        },
        {
            "name": "AUTO",
            "type": "url-test",
            "proxies": flat_names,
            "url": HEALTH_URL,
            "interval": 900,
            "timeout": 8000,
            "tolerance": 250,
            "lazy": False,
            "hidden": True,
        },
    ]


def build_config(flat_nodes):
    flat_names = [n["name"] for n in flat_nodes]
    rules = (LOCAL_IOT_DIRECT + WPS_DIRECT + PRIVATE_DIRECT + OZON_DIRECT
             + WECHAT_DIRECT + XIAOMI_DIRECT
             + [f"DOMAIN-SUFFIX,{d},Fine" for d in VIDEO_DOMAINS]
             + [f"DOMAIN-SUFFIX,{d},Fine" for d in STORE_DOMAINS]
             + ["GEOIP,CN,DIRECT"]
             + SUBSCRIPTION_CDN_DIRECT
             + ["MATCH,Fine"])
    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "unified-delay": False,
        "tcp-concurrent": True,
        "profile": {"store-selected": True},
        "proxies": flat_nodes,
        "proxy-groups": build_proxy_groups(flat_names),
        "tun": {"enable": False, "stack": "system", "auto-route": False, "auto-detect-interface": False},
        "dns": {
            "enable": True,
            "ipv6": False,
            "use-hosts": True,
            "enhanced-mode": "redir-host",
            "nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"],
            "nameserver-policy": {
                "+.mi.com": ["223.5.5.5", "119.29.29.29"],
                "+.xiaomi.com": ["223.5.5.5", "119.29.29.29"],
                "+.xiaomi.cn": ["223.5.5.5", "119.29.29.29"],
                "+.mijia.com": ["223.5.5.5", "119.29.29.29"],
                "+.miwifi.com": ["223.5.5.5", "119.29.29.29"],
                "+.miui.com": ["223.5.5.5", "119.29.29.29"],
                "+.weixin.qq.com": ["223.5.5.5", "119.29.29.29"],
                "+.qq.com": ["223.5.5.5", "119.29.29.29"],
                "+.myqcloud.com": ["223.5.5.5", "119.29.29.29"],
                "+.tencentcos.cn": ["223.5.5.5", "119.29.29.29"],
                "+.ozon.ru": ["223.5.5.5", "119.29.29.29"],
            },
            "fallback": ["https://1.1.1.1/dns-query", "tls://8.8.8.8"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN"},
        },
        "rules": rules,
    }


def main():
    if len(sys.argv) > 1:
        print(f"build_final.py: ignoring legacy arg {sys.argv[1]!r} (no longer used)")
    flat = collect_flat()
    if not flat:
        print("FATAL: no usable free nodes aggregated from any source; "
              "refusing to overwrite live_clash.yaml.")
        raise SystemExit(1)
    config = build_config(flat)
    dumped = yaml.safe_dump(config, allow_unicode=True, sort_keys=False,
                            default_flow_style=False)
    previous_version = 0
    if OUT.is_file():
        try:
            m = re.match(r"^#.*?fine-clash-version:(\d+).*?\n",
                         OUT.read_text(encoding="utf-8"))
            if m:
                previous_version = int(m.group(1))
        except OSError:
            pass
    version = (str(previous_version + 1) if previous_version
               else datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    header = (f"# fine-clash-unified-v4 | fine-clash-version:{version} | "
              f"Fine=free-live-pool | CN->DIRECT | MATCH->Fine | "
              f"schedule-refresh:true | client-urltest:true\n")
    OUT.write_text(header + dumped, encoding="utf-8")
    print(f"written {OUT}: flat={len(config['proxies'])} nodes; "
          f"rules={len(config['rules'])}")


if __name__ == "__main__":
    main()
