# -*- coding: utf-8 -*-
"""Build the only public subscription: live_clash.yaml."""
from __future__ import annotations
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
import yaml

OUT = Path("live_clash.yaml")
SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "data/fine_pool.yaml")

BITZ_SUB_URL = "https://cont.bbkcdpub.com/api/v1/client/BitzNet.conf?token=23a7ad64b83f7b867eb75da3738184c6"

AMAZON_DOMAINS = [
    "amazon.com","amazon.co.uk","amazon.de","amazon.fr","amazon.es","amazon.it",
    "amazon.nl","amazon.pl","amazon.se","amazon.ca","amazon.com.au","amazon.co.jp",
    "amazon.in","amazon.com.br","amazon.com.mx","amazon.sg","amazon.ae","amazon.sa",
    "amazon.tr","sellercentral.amazon.com","amazon-adsystem.com",
    "ssl-images-amazon.com","media-amazon.com",
]
OZON_DOMAINS = ["ozon.ru","ozon.com","ozon.kz","ozon.by","ozonusercontent.com"]
WECHAT_DIRECT = [
    "DOMAIN-SUFFIX,weixin.qq.com,DIRECT","DOMAIN-SUFFIX,wx.qq.com,DIRECT",
    "DOMAIN-SUFFIX,wechat.com,DIRECT","DOMAIN-SUFFIX,qpic.cn,DIRECT",
    "DOMAIN-SUFFIX,qlogo.cn,DIRECT","DOMAIN-SUFFIX,gtimg.cn,DIRECT",
    "DOMAIN-SUFFIX,gtimg.com,DIRECT","DOMAIN-SUFFIX,qq.com,DIRECT",
    "DOMAIN-SUFFIX,tenpay.com,DIRECT","DOMAIN-SUFFIX,wechatpay.cn,DIRECT",
    "DOMAIN-SUFFIX,tencent.com,DIRECT","DOMAIN-SUFFIX,tencent-cloud.com,DIRECT",
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
    "DOMAIN-SUFFIX,lan,DIRECT","DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,localhost,DIRECT","DOMAIN-SUFFIX,cn,DIRECT",
    "DOMAIN-SUFFIX,com.cn,DIRECT","DOMAIN-SUFFIX,net.cn,DIRECT",
    "DOMAIN-SUFFIX,gov.cn,DIRECT","DOMAIN-SUFFIX,edu.cn,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve","IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve","IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
]

def load_fine_nodes():
    if not SRC.is_file():
        raise SystemExit(f"FATAL: missing Fine pool: {SRC}")
    raw = yaml.safe_load(SRC.read_text(encoding="utf-8")) or {}
    valid, names = [], set()
    for node in raw.get("proxies") or []:
        if not isinstance(node, dict):
            continue
        name = str(node.get("name") or "").strip()
        if not name or name in names:
            continue
        if not node.get("server") or not node.get("port") or not node.get("type"):
            continue
        valid.append(node)
        names.add(name)
    if not valid:
        raise SystemExit("FATAL: Fine pool is empty; previous live_clash.yaml must be preserved by CI.")
    return valid

def suffix_rules(domains, group):
    return [f"DOMAIN-SUFFIX,{d},{group}" for d in domains]


def build_proxy_groups(fine_names):
    """Build automatic groups plus explicit manual-control layers.

    Normal operation stays in mode=rule: route rules choose Bitz/Fine/DIRECT,
    and Bitz/Fine groups choose Auto or a specific node. GLOBAL is reserved
    for explicit Mihomo global-mode override and exposes all nodes so one
    manually selected node can carry all traffic.
    """
    return [
        {"name": "GLOBAL", "type": "select", "proxies": ["DIRECT"], "include-all": True},
        {"name": "Bitz", "type": "select",
         "proxies": ["Bitz-Auto"], "use": ["BitzPool"],
         "default-selected": "Bitz-Auto"},
        {"name": "Bitz-Auto", "type": "url-test",
         "include-all-providers": True,
         "url": "https://www.ozon.ru/",
         "interval": 900, "timeout": 8000, "tolerance": 100, "lazy": False},
        {"name": "Fine", "type": "select",
         "proxies": ["Fine-Auto"] + fine_names,
         "default-selected": "Fine-Auto"},
        {"name": "Fine-Auto", "type": "url-test",
         "proxies": fine_names,
         "url": "https://www.gstatic.com/generate_204",
         "interval": 900, "timeout": 8000, "tolerance": 100, "lazy": False},
    ]

def main():
    fine_nodes = load_fine_nodes()
    fine_names = [n["name"] for n in fine_nodes]
    rules = (
        LOCAL_IOT_DIRECT + PRIVATE_DIRECT + WECHAT_DIRECT + XIAOMI_DIRECT + ["GEOIP,CN,DIRECT"]
        + suffix_rules(OZON_DOMAINS, "Bitz")
        + suffix_rules(AMAZON_DOMAINS, "Bitz")
        + ["MATCH,Fine"]
    )
    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "bind-address": "*",
        "mode": "rule",  # default: automatic rule-based routing; GLOBAL is explicit override
        "log-level": "warning",
        "ipv6": False,
        "unified-delay": False,
        "tcp-concurrent": True,
        "profile": {"store-selected": True},
        "proxy-providers": {
            "BitzPool": {
                "type": "http",
                "url": BITZ_SUB_URL,
                "interval": 21600,
            }
        },
        "proxies": fine_nodes,
        "proxy-groups": build_proxy_groups(fine_names),
        "tun": {"enable": True, "stack": "system", "auto-route": True, "auto-detect-interface": True},
        "dns": {
            "enable": True, "ipv6": False, "use-hosts": True, "enhanced-mode": "redir-host",
            "nameserver": ["223.5.5.5","119.29.29.29","1.1.1.1"],
            "nameserver-policy": {
                "+.mi.com": ["223.5.5.5","119.29.29.29"],
                "+.xiaomi.com": ["223.5.5.5","119.29.29.29"],
                "+.miwifi.com": ["223.5.5.5","119.29.29.29"],
                "+.miui.com": ["223.5.5.5","119.29.29.29"],
                "+.weixin.qq.com": ["223.5.5.5","119.29.29.29"],
                "+.qq.com": ["223.5.5.5","119.29.29.29"],
            },
            "fallback": ["https://1.1.1.1/dns-query","tls://8.8.8.8"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN"},
        },
        "rules": rules,
    }
    dumped = yaml.safe_dump(config, allow_unicode=True, sort_keys=False, default_flow_style=False)
    previous_version = 0
    previous_body = None
    if OUT.is_file():
        try:
            previous = OUT.read_text(encoding="utf-8")
            m = re.match(r"^#.*?fine-clash-version:(\d+).*?\n", previous)
            if m:
                previous_version = int(m.group(1))
                previous_body = previous[m.end():]
        except OSError:
            pass
    if previous_body == dumped and previous_version:
        version = str(previous_version)
    else:
        version = str(previous_version + 1) if previous_version else datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    header = f"# fine-clash-unified-v1 | fine-clash-version:{version} | Bitz=remote-provider | Fine=validated-pool | Ozon/Amazon->Bitz | CN->DIRECT | MATCH->Fine\n"
    OUT.write_text(header + dumped, encoding="utf-8")
    print(f"written {OUT} with Fine={len(fine_nodes)} nodes; Bitz=remote-provider; rules={len(rules)}")

if __name__ == "__main__":
    main()
