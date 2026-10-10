# -*- coding: utf-8 -*-
"""Build the single public Clash/Mihomo profile from the validated Fine pool."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from pathlib import Path
import yaml
from fine_clash import WPS_DIRECT_RULES, fingerprint, mihomo_node_is_testable, resolved_server_is_safe, unique_node_names

OUT = Path("live_clash.yaml")
SRC = Path("data/fine_pool.yaml")

VIDEO_DOMAINS=["youtube.com","youtu.be","ytimg.com","googlevideo.com","netflix.com","nflxvideo.net","nflximg.net","twitch.tv","ttvnw.net","vimeo.com"]
STORE_DOMAINS=["play.google.com","googleplay.com","dl.google.com","gvt1.com","gvt2.com","microsoft.com","microsoftstore.com","apps.microsoft.com","steampowered.com","steamcommunity.com"]
WECHAT_DIRECT=["DOMAIN-SUFFIX,weixin.qq.com,DIRECT","DOMAIN-SUFFIX,wx.qq.com,DIRECT","DOMAIN-SUFFIX,wechat.com,DIRECT","DOMAIN-SUFFIX,qpic.cn,DIRECT","DOMAIN-SUFFIX,qlogo.cn,DIRECT","DOMAIN-SUFFIX,gtimg.cn,DIRECT","DOMAIN-SUFFIX,gtimg.com,DIRECT","DOMAIN-SUFFIX,qq.com,DIRECT","DOMAIN-SUFFIX,tenpay.com,DIRECT","DOMAIN-SUFFIX,wechatpay.cn,DIRECT","DOMAIN-SUFFIX,tencent.com,DIRECT","DOMAIN-SUFFIX,tencent-cloud.com,DIRECT","DOMAIN-SUFFIX,myqcloud.com,DIRECT","DOMAIN-SUFFIX,tencentcos.cn,DIRECT"]
XIAOMI_DIRECT=["DOMAIN-SUFFIX,mi.com,DIRECT","DOMAIN-SUFFIX,xiaomi.com,DIRECT","DOMAIN-SUFFIX,miwifi.com,DIRECT","DOMAIN-SUFFIX,miui.com,DIRECT","DOMAIN-SUFFIX,mijia.com,DIRECT","DOMAIN-SUFFIX,xiaomi.cn,DIRECT"]
LOCAL_IOT_DIRECT=["IP-CIDR,224.0.0.0/4,DIRECT,no-resolve","IP-CIDR,169.254.0.0/16,DIRECT,no-resolve"]
PRIVATE_DIRECT=["DOMAIN-SUFFIX,lan,DIRECT","DOMAIN-SUFFIX,local,DIRECT","DOMAIN-SUFFIX,localhost,DIRECT","DOMAIN-SUFFIX,cn,DIRECT","DOMAIN-SUFFIX,com.cn,DIRECT","DOMAIN-SUFFIX,net.cn,DIRECT","DOMAIN-SUFFIX,gov.cn,DIRECT","DOMAIN-SUFFIX,edu.cn,DIRECT","IP-CIDR,10.0.0.0/8,DIRECT,no-resolve","IP-CIDR,172.16.0.0/12,DIRECT,no-resolve","IP-CIDR,192.168.0.0/16,DIRECT,no-resolve","IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"]

def _dedupe_nodes(nodes,prefix):
    out=[]; seen=set()
    for node in nodes:
        if not isinstance(node,dict): continue
        node=dict(node)
        if not node.get("name") or not node.get("server") or not node.get("port") or not node.get("type"): continue
        if not mihomo_node_is_testable(node): continue
        node["name"]=f"{prefix}{str(node['name']).strip()}"
        fp=fingerprint(node)
        if fp in seen: continue
        seen.add(fp); out.append(node)
    return unique_node_names(out)

def load_fine_nodes():
    if not SRC.is_file(): raise SystemExit(f"FATAL: missing Fine pool: {SRC}")
    raw=yaml.safe_load(SRC.read_text(encoding="utf-8")) or {}
    parsed=raw.get("proxies") or []
    nodes=_dedupe_nodes([node for node in parsed if isinstance(node,dict) and resolved_server_is_safe(node.get("server",""))],"")
    if not nodes: raise SystemExit("FATAL: Fine pool is empty or has no testable nodes.")
    return nodes

def suffix_rules(domains,group):
    return [f"DOMAIN-SUFFIX,{d},{group}" for d in domains]

def build_proxy_groups(fine_names):
    """Build the only supported public proxy groups."""
    if not fine_names:
        raise ValueError("Fine pool must be non-empty")
    primary=fine_names[0]
    return [
        {"name":"Fine","type":"select","proxies":["Fine-Auto","DIRECT"]+fine_names,"default-selected":primary},
        {"name":"Fine-Auto","type":"url-test","proxies":fine_names,"url":"https://play.google.com/store","interval":900,"timeout":8000,"tolerance":250,"lazy":False,"hidden":True},
    ]


def build_config(fine_nodes):
    if not fine_nodes: raise ValueError("Fine pool must be non-empty")
    fine_nodes=unique_node_names(fine_nodes)
    fine_names=[n["name"] for n in fine_nodes]
    # The single public profile uses only the validated Fine node pool.
    # Bulk traffic and all other proxy-bound traffic use Fine.
    rules=LOCAL_IOT_DIRECT+WPS_DIRECT_RULES+PRIVATE_DIRECT+WECHAT_DIRECT+XIAOMI_DIRECT+suffix_rules(VIDEO_DOMAINS,"Fine")+suffix_rules(STORE_DOMAINS,"Fine")+["GEOIP,CN,DIRECT"]
    rules.append("MATCH,Fine")
    config={
        "mixed-port":7890,"allow-lan":True,"bind-address":"*","mode":"rule","log-level":"warning","ipv6":False,"unified-delay":False,"tcp-concurrent":True,
        "profile":{"store-selected":True},
    }
    config["proxies"]=fine_nodes
    config["proxy-groups"]=build_proxy_groups(fine_names)
    config["tun"]={"enable":True,"stack":"system","auto-route":True,"auto-detect-interface":True}
    config["dns"]={"enable":True,"ipv6":False,"use-hosts":True,"enhanced-mode":"redir-host","nameserver":["223.5.5.5","119.29.29.29","1.1.1.1"],
               "nameserver-policy":{"+.wps.cn":["223.5.5.5","119.29.29.29"],"+.wps.com":["223.5.5.5","119.29.29.29"],"+.wps365.com":["223.5.5.5","119.29.29.29"],"+.kdocs.cn":["223.5.5.5","119.29.29.29"],"+.wpscdn.cn":["223.5.5.5","119.29.29.29"],"+.wpscdn.com":["223.5.5.5","119.29.29.29"],"+.mi.com":["223.5.5.5","119.29.29.29"],"+.xiaomi.com":["223.5.5.5","119.29.29.29"],"+.xiaomi.cn":["223.5.5.5","119.29.29.29"],"+.mijia.com":["223.5.5.5","119.29.29.29"],"+.miwifi.com":["223.5.5.5","119.29.29.29"],"+.miui.com":["223.5.5.5","119.29.29.29"],"+.weixin.qq.com":["223.5.5.5","119.29.29.29"],"+.qq.com":["223.5.5.5","119.29.29.29"],"+.myqcloud.com":["223.5.5.5","119.29.29.29"],"+.tencentcos.cn":["223.5.5.5","119.29.29.29"]},
               "fallback":["https://1.1.1.1/dns-query","tls://8.8.8.8"],"fallback-filter":{"geoip":True,"geoip-code":"CN"}}
    config["rules"]=rules
    return config

def main():
    config=build_config(load_fine_nodes())
    dumped=yaml.safe_dump(config,allow_unicode=True,sort_keys=False,default_flow_style=False)
    previous_version=0
    if OUT.is_file():
        try:
            m=re.match(r"^#.*?fine-clash-version:(\d+).*?\n",OUT.read_text(encoding="utf-8"))
            if m: previous_version=int(m.group(1))
        except OSError: pass
    version=str(previous_version+1) if previous_version else datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    header=(f"# fine-clash-unified-v4 | fine-clash-version:{version} | "
            "Fine=validated-pool | bulk->Fine | CN->DIRECT | MATCH->Fine\n")
    OUT.write_text(header+dumped,encoding="utf-8")
    print(f"written {OUT}: Fine={len(config['proxies'])} validated nodes; MATCH->Fine")

if __name__=="__main__": main()
