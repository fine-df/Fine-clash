# -*- coding: utf-8 -*-
"""Build the single public Clash/Mihomo profile with Bitz + Fine dual routing."""
from __future__ import annotations
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

from fine_clash import (
    fingerprint,
    mihomo_node_is_testable,
    parse_subscription,
    resolved_server_is_safe,
    unique_node_names,
)

OUT = Path("live_clash.yaml")
SRC = Path("data/fine_pool.yaml")
PREMIUM_SRC = Path("data/premium_us_pool.yaml")

BITZ_SUB_ENV = "BITZ_SUB_URL"
BITZ_UA = "Fine-Clash/2.0"

AMAZON_DOMAINS = [
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.es",
    "amazon.it", "amazon.nl", "amazon.pl", "amazon.se", "amazon.ca",
    "amazon.com.au", "amazon.co.jp", "amazon.in", "amazon.com.br",
    "amazon.com.mx", "amazon.sg", "amazon.ae", "amazon.sa", "amazon.tr",
    "sellercentral.amazon.com", "amazon-adsystem.com", "ssl-images-amazon.com",
    "media-amazon.com",
]
OZON_DOMAINS = ["ozon.ru", "ozon.com", "ozon.kz", "ozon.by", "ozonusercontent.com"]
MUSE_DOMAINS = ["muse.ai"]

VIDEO_DOMAINS = [
    "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
    "netflix.com", "nflxvideo.net", "nflximg.net",
    "twitch.tv", "ttvnw.net", "vimeo.com",
]
STORE_DOMAINS = [
    "play.google.com", "googleplay.com", "dl.google.com", "gvt1.com", "gvt2.com",
    "microsoft.com", "microsoftstore.com", "apps.microsoft.com",
    "steampowered.com", "steamcommunity.com",
]

WECHAT_DIRECT = [
    "DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
    "DOMAIN-SUFFIX,wx.qq.com,DIRECT",
    "DOMAIN-SUFFIX,wechat.com,DIRECT",
    "DOMAIN-SUFFIX,qpic.cn,DIRECT",
    "DOMAIN-SUFFIX,qlogo.cn,DIRECT",
    "DOMAIN-SUFFIX,gtimg.cn,DIRECT",
    "DOMAIN-SUFFIX,gtimg.com,DIRECT",
    "DOMAIN-SUFFIX,qq.com,DIRECT",
    "DOMAIN-SUFFIX,tenpay.com,DIRECT",
    "DOMAIN-SUFFIX,wechatpay.cn,DIRECT",
    "DOMAIN-SUFFIX,tencent.com,DIRECT",
    "DOMAIN-SUFFIX,tencent-cloud.com,DIRECT",
]
XIAOMI_DIRECT = [
    "DOMAIN-SUFFIX,mi.com,DIRECT",
    "DOMAIN-SUFFIX,xiaomi.com,DIRECT",
    "DOMAIN-SUFFIX,miwifi.com,DIRECT",
    "DOMAIN-SUFFIX,miui.com,DIRECT",
]
LOCAL_IOT_DIRECT = [
    "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
]
PRIVATE_DIRECT = [
    "DOMAIN-SUFFIX,lan,DIRECT",
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,localhost,DIRECT",
    "DOMAIN-SUFFIX,cn,DIRECT",
    "DOMAIN-SUFFIX,com.cn,DIRECT",
    "DOMAIN-SUFFIX,net.cn,DIRECT",
    "DOMAIN-SUFFIX,gov.cn,DIRECT",
    "DOMAIN-SUFFIX,edu.cn,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
]


def _dedupe_nodes(nodes, prefix):
    out = []
    seen = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node = dict(node)
        if not node.get("name") or not node.get("server") or not node.get("port") or not node.get("type"):
            continue
        if not mihomo_node_is_testable(node):
            continue
        node["name"] = f"{prefix}{str(node['name']).strip()}"
        fp = fingerprint(node)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(node)
    return unique_node_names(out)


def load_fine_nodes():
    if not SRC.is_file():
        raise SystemExit(f"FATAL: missing Fine pool: {SRC}")
    raw = yaml.safe_load(SRC.read_text(encoding="utf-8")) or {}
    parsed = raw.get("proxies") or []
    nodes = _dedupe_nodes(
        [
            node
            for node in parsed
            if isinstance(node, dict) and resolved_server_is_safe(node.get("server", ""))
        ],
        "",
    )
    if not nodes:
        raise SystemExit("FATAL: Fine pool is empty or has no testable nodes.")
    return nodes


def load_premium_us_nodes():
    if not PREMIUM_SRC.is_file():
        return []
    raw = yaml.safe_load(PREMIUM_SRC.read_text(encoding="utf-8")) or {}
    parsed = raw.get("proxies") or []
    return _dedupe_nodes(
        [
            node
            for node in parsed
            if isinstance(node, dict) and resolved_server_is_safe(node.get("server", ""))
        ],
        "",
    )


def fetch_bitz_nodes():
    url = os.environ.get(BITZ_SUB_ENV, "").strip()
    if not url:
        raise SystemExit(f"FATAL: missing {BITZ_SUB_ENV} environment secret.")

    try:
        response = requests.get(
            url,
            timeout=30,
            headers={
                "User-Agent": BITZ_UA,
                "Accept": "text/plain,application/yaml,*/*",
            },
        )
        response.raise_for_status()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        body = exc.response.text[:160].replace("\\n", " ") if exc.response is not None else ""
        raise SystemExit(f"FATAL: Bitz subscription fetch failed: HTTP {status}; body={body!r}") from exc
    except requests.RequestException as exc:
        raise SystemExit(f"FATAL: Bitz subscription fetch failed: {type(exc).__name__}") from exc

    parsed = parse_subscription(response.text)
    nodes = _dedupe_nodes(
        [
            node
            for node in parsed
            if isinstance(node, dict)
            and resolved_server_is_safe(node.get("server", ""))
        ],
        "Bitz | ",
    )
    if not nodes:
        raise SystemExit("FATAL: Bitz subscription returned no supported testable nodes.")
    return nodes


def suffix_rules(domains, group):
    return [f"DOMAIN-SUFFIX,{domain},{group}" for domain in domains]


def build_proxy_groups(fine_names, bitz_names, premium_names=None):
    premium_names = premium_names or []
    all_names = bitz_names + fine_names + premium_names
    groups = [
        {
            "name": "GLOBAL",
            "type": "select",
            "proxies": ["DIRECT"] + all_names,
            "default-selected": "DIRECT",
        },
        {
            "name": "Bitz",
            "type": "select",
            "proxies": ["Bitz-Auto"] + bitz_names,
            "default-selected": "Bitz-Auto",
        },
        {
            "name": "Bitz-Auto",
            "type": "url-test",
            "proxies": bitz_names,
            "url": "https://www.ozon.ru/",
            "interval": 900,
            "timeout": 8000,
            "tolerance": 100,
            "lazy": False,
        },
        {
            "name": "Fine",
            "type": "select",
            "proxies": ["Fine-Auto"] + fine_names,
            "default-selected": "Fine-Auto",
        },
        {
            "name": "Fine-Auto",
            "type": "url-test",
            "proxies": fine_names,
            "url": "https://play.google.com/store",
            "interval": 900,
            "timeout": 8000,
            "tolerance": 50,
            "lazy": False,
        },
    ]
    if premium_names:
        groups.extend(
            [
                {
                    "name": "Premium-US",
                    "type": "select",
                    "proxies": ["Premium-US-Auto"] + premium_names,
                    "default-selected": "Premium-US-Auto",
                },
                {
                    "name": "Premium-US-Auto",
                    "type": "url-test",
                    "proxies": premium_names,
                    "url": "https://www.google.com/generate_204",
                    "interval": 900,
                    "timeout": 8000,
                    "tolerance": 50,
                    "lazy": False,
                },
            ]
        )
    return groups


def build_config(fine_nodes, bitz_nodes, premium_nodes=None):
    if not fine_nodes:
        raise ValueError("Fine pool must be non-empty")
    if not bitz_nodes:
        raise ValueError("Bitz pool must be non-empty")

    premium_nodes = premium_nodes or []
    fine_fps = {fingerprint(node) for node in fine_nodes}
    bitz_fps = {fingerprint(node) for node in bitz_nodes}
    premium_fps = {fingerprint(node) for node in premium_nodes}

    combined = {}
    for node in list(bitz_nodes) + list(fine_nodes) + list(premium_nodes):
        combined[fingerprint(node)] = dict(node)

    combined_nodes = unique_node_names(list(combined.values()))
    bitz_names = [node["name"] for node in combined_nodes if fingerprint(node) in bitz_fps]
    fine_names = [node["name"] for node in combined_nodes if fingerprint(node) in fine_fps]
    premium_names = [node["name"] for node in combined_nodes if fingerprint(node) in premium_fps]

    rules = (
        LOCAL_IOT_DIRECT
        + PRIVATE_DIRECT
        + WECHAT_DIRECT
        + XIAOMI_DIRECT
        + suffix_rules(OZON_DOMAINS, "Bitz")
        + suffix_rules(AMAZON_DOMAINS, "Bitz")
        + suffix_rules(MUSE_DOMAINS, "Bitz")
        + suffix_rules(VIDEO_DOMAINS, "Fine")
        + suffix_rules(STORE_DOMAINS, "Fine")
        + ["GEOIP,CN,DIRECT", "MATCH,Fine"]
    )

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
        "proxies": combined_nodes,
        "proxy-groups": build_proxy_groups(fine_names, bitz_names, premium_names),
        "tun": {
            "enable": True,
            "stack": "system",
            "auto-route": True,
            "auto-detect-interface": True,
        },
        "dns": {
            "enable": True,
            "ipv6": False,
            "use-hosts": True,
            "enhanced-mode": "redir-host",
            "nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"],
            "nameserver-policy": {
                "+.mi.com": ["223.5.5.5", "119.29.29.29"],
                "+.xiaomi.com": ["223.5.5.5", "119.29.29.29"],
                "+.miwifi.com": ["223.5.5.5", "119.29.29.29"],
                "+.miui.com": ["223.5.5.5", "119.29.29.29"],
                "+.weixin.qq.com": ["223.5.5.5", "119.29.29.29"],
                "+.qq.com": ["223.5.5.5", "119.29.29.29"],
            },
            "fallback": ["https://1.1.1.1/dns-query", "tls://8.8.8.8"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN"},
        },
        "rules": rules,
    }


def main():
    fine_nodes = load_fine_nodes()
    bitz_nodes = fetch_bitz_nodes()
    premium_nodes = load_premium_us_nodes()
    config = build_config(fine_nodes, bitz_nodes, premium_nodes)

    dumped = yaml.safe_dump(
        config,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )

    previous_version = 0
    if OUT.is_file():
        try:
            match = re.match(
                r"^#.*?fine-clash-version:(\d+).*?\n",
                OUT.read_text(encoding="utf-8"),
            )
            if match:
                previous_version = int(match.group(1))
        except OSError:
            pass

    version = (
        str(previous_version + 1)
        if previous_version
        else datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    )
    premium_flag = (
        "Premium-US=optional"
        if any(group.get("name") == "Premium-US" for group in config.get("proxy-groups", []))
        else "Premium-US=empty"
    )
    header = (
        f"# fine-clash-unified-v4 | fine-clash-version:{version} | "
        f"Bitz=subscription | Fine=validated-pool | "
        f"Ozon/Amazon/Muse->Bitz | Video/Store/Downloads->Fine | "
        f"{premium_flag} | CN->DIRECT | MATCH->Fine\n"
    )
    OUT.write_text(header + dumped, encoding="utf-8")
    print(
        f"written {OUT}: Bitz={len(bitz_nodes)}; Fine={len(fine_nodes)}; "
        f"Premium-US={'yes' if premium_nodes else 'empty'}; "
        f"total proxies={len(config['proxies'])}; rules={len(config['rules'])}"
    )


if __name__ == "__main__":
    main()
