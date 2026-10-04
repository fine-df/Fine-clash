# -*- coding: utf-8 -*-
"""Build the single public Clash/Mihomo profile with explicit Bitz nodes."""
from __future__ import annotations
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import requests
import yaml
from fine_clash import fingerprint, mihomo_node_is_testable, parse_subscription

OUT = Path("live_clash.yaml")
SRC = Path("data/fine_pool.yaml")
BITZ_SUB_URL = os.environ.get("BITZ_SUB_URL", "https://cont.bbkcdpub.com/api/v1/client/BitzNet.conf?token=23a7ad64b83f7b867eb75da3738184c6")

AMAZON_DOMAINS=["amazon.com","amazon.co.uk","amazon.de","amazon.fr","amazon.es","amazon.it","amazon.nl","amazon.pl","amazon.se","amazon.ca","amazon.com.au","amazon.co.jp","amazon.in","amazon.com.br","amazon.com.mx","amazon.sg","amazon.ae","amazon.sa","amazon.tr","sellercentral.amazon.com","amazon-adsystem.com","ssl-images-amazon.com","media-amazon.com"]
OZON_DOMAINS=["ozon.ru","ozon.com","ozon.kz","ozon.by","ozonusercontent.com"]
WECHAT_DIRECT=["DOMAIN-SUFFIX,weixin.qq.com,DIRECT","DOMAIN-SUFFIX,wx.qq.com,DIRECT","DOMAIN-SUFFIX,wechat.com,DIRECT","DOMAIN-SUFFIX,qpic.cn,DIRECT","DOMAIN-SUFFIX,qlogo.cn,DIRECT","DOMAIN-SUFFIX,gtimg.cn,DIRECT","DOMAIN-SUFFIX,gtimg.com,DIRECT","DOMAIN-SUFFIX,qq.com,DIRECT","DOMAIN-SUFFIX,tenpay.com,DIRECT","DOMAIN-SUFFIX,wechatpay.cn,DIRECT","DOMAIN-SUFFIX,tencent.com,DIRECT","DOMAIN-SUFFIX,tencent-cloud.com,DIRECT"]
XIAOMI_DIRECT=["DOMAIN-SUFFIX,mi.com,DIRECT","DOMAIN-SUFFIX,xiaomi.com,DIRECT","DOMAIN-SUFFIX,miwifi.com,DIRECT","DOMAIN-SUFFIX,miui.com,DIRECT"]
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
    return out

def load_fine_nodes():
    if not SRC.is_file(): raise SystemExit(f"FATAL: missing Fine pool: {SRC}")
    raw=yaml.safe_load(SRC.read_text(encoding="utf-8")) or {}
    nodes=_dedupe_nodes(raw.get("proxies") or [],"")
    if not nodes: raise SystemExit("FATAL: Fine pool is empty or has no testable nodes.")
    return nodes

def fetch_bitz_nodes():
    try:
        r=requests.get(BITZ_SUB_URL,timeout=30,headers={"User-Agent":"Fine-Clash/2.0","Accept":"text/plain,application/yaml,*/*"})
        r.raise_for_status()
    except requests.RequestException as exc:
        raise SystemExit(f"FATAL: Bitz subscription fetch failed: {exc}") from exc
    nodes=_dedupe_nodes(parse_subscription(r.text),"Bitz | ")
    if not nodes: raise SystemExit("FATAL: Bitz subscription returned no supported testable nodes.")
    return nodes

def suffix_rules(domains,group):
    return [f"DOMAIN-SUFFIX,{d},{group}" for d in domains]

def build_proxy_groups(bitz_names,fine_names):
    all_names=bitz_names+fine_names
    return [
        {"name":"GLOBAL","type":"select","proxies":["DIRECT"]+all_names,"default-selected":"DIRECT"},
        {"name":"Bitz","type":"select","proxies":["Bitz-Auto"]+bitz_names,"default-selected":"Bitz-Auto"},
        {"name":"Bitz-Auto","type":"url-test","proxies":bitz_names,"url":"https://www.ozon.ru/","interval":900,"timeout":8000,"tolerance":100,"lazy":False},
        {"name":"Fine","type":"select","proxies":["Fine-Auto"]+fine_names,"default-selected":"Fine-Auto"},
        {"name":"Fine-Auto","type":"url-test","proxies":fine_names,"url":"https://play.google.com/store","interval":900,"timeout":8000,"tolerance":50,"lazy":False},
    ]

def build_config(fine_nodes,bitz_nodes):
    fine_names=[n["name"] for n in fine_nodes]; bitz_names=[n["name"] for n in bitz_nodes]
    if not fine_names or not bitz_names: raise ValueError("Fine and Bitz pools must both be non-empty")
    rules=LOCAL_IOT_DIRECT+PRIVATE_DIRECT+WECHAT_DIRECT+XIAOMI_DIRECT+suffix_rules(OZON_DOMAINS,"Bitz")+suffix_rules(AMAZON_DOMAINS,"Bitz")+["GEOIP,CN,DIRECT","MATCH,Fine"]
    return {
        "mixed-port":7890,"allow-lan":True,"bind-address":"*","mode":"rule","log-level":"warning","ipv6":False,"unified-delay":False,"tcp-concurrent":True,
        "profile":{"store-selected":True},
        "proxies":bitz_nodes+fine_nodes,
        "proxy-groups":build_proxy_groups(bitz_names,fine_names),
        "tun":{"enable":True,"stack":"system","auto-route":True,"auto-detect-interface":True},
        "dns":{"enable":True,"ipv6":False,"use-hosts":True,"enhanced-mode":"redir-host","nameserver":["223.5.5.5","119.29.29.29","1.1.1.1"],
               "nameserver-policy":{"+.mi.com":["223.5.5.5","119.29.29.29"],"+.xiaomi.com":["223.5.5.5","119.29.29.29"],"+.miwifi.com":["223.5.5.5","119.29.29.29"],"+.miui.com":["223.5.5.5","119.29.29.29"],"+.weixin.qq.com":["223.5.5.5","119.29.29.29"],"+.qq.com":["223.5.5.5","119.29.29.29"]},
               "fallback":["https://1.1.1.1/dns-query","tls://8.8.8.8"],"fallback-filter":{"geoip":True,"geoip-code":"CN"}},
        "rules":rules,
    }

def main():
    config=build_config(load_fine_nodes(),fetch_bitz_nodes())
    dumped=yaml.safe_dump(config,allow_unicode=True,sort_keys=False,default_flow_style=False)
    previous_version=0
    if OUT.is_file():
        try:
            m=re.match(r"^#.*?fine-clash-version:(\d+).*?\n",OUT.read_text(encoding="utf-8"))
            if m: previous_version=int(m.group(1))
        except OSError: pass
    version=str(previous_version+1) if previous_version else datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    header=f"# fine-clash-unified-v2 | fine-clash-version:{version} | Bitz=embedded-pool | Fine=validated-pool | Ozon/Amazon->Bitz | CN->DIRECT | MATCH->Fine\n"
    OUT.write_text(header+dumped,encoding="utf-8")
    print(f"written {OUT}: Bitz={len(config['proxy-groups'][1]['proxies'])-1} explicit nodes; Fine={len(config['proxy-groups'][3]['proxies'])-1} validated nodes; rules={len(config['rules'])}")

if __name__=="__main__":
    main()
