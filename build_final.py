# -*- coding: utf-8 -*-
"""Build the single public Clash/Mihomo profile from the validated Fine pool."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from pathlib import Path
import json
import yaml
from fine_clash import fingerprint, load_rules, mihomo_node_is_testable, resolved_server_is_safe, unique_node_names

OUT = Path("live_clash.yaml")
SRC = Path("data/fine_pool.yaml")

VALIDATION_REPORT=Path("data/last_run.json")

VIDEO_DOMAINS=["youtube.com","youtu.be","ytimg.com","googlevideo.com","netflix.com","nflxvideo.net","nflximg.net","twitch.tv","ttvnw.net","vimeo.com"]
STORE_DOMAINS=["play.google.com","googleplay.com","dl.google.com","gvt1.com","gvt2.com","microsoft.com","microsoftstore.com","apps.microsoft.com","steampowered.com","steamcommunity.com"]
OZON_DIRECT=["DOMAIN-SUFFIX,ozon.ru,DIRECT"]
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
    return unique_node_names(out)

def load_fine_nodes():
    if not SRC.is_file(): raise SystemExit(f"FATAL: missing Fine pool: {SRC}")
    if not VALIDATION_REPORT.is_file(): raise SystemExit(f"FATAL: missing validation report: {VALIDATION_REPORT}")
    raw=yaml.safe_load(SRC.read_text(encoding="utf-8")) or {}
    parsed=raw.get("proxies") or []
    nodes=_dedupe_nodes([node for node in parsed if isinstance(node,dict) and resolved_server_is_safe(node.get("server",""))],"")
    if not nodes: raise SystemExit("FATAL: Fine pool is empty or has no testable nodes.")
    try:
        report=json.loads(VALIDATION_REPORT.read_text(encoding="utf-8"))
        by_fp={row.get("fingerprint"):row for row in report.get("results",[]) if isinstance(row,dict) and row.get("fingerprint")}
    except Exception as exc:
        raise SystemExit(f"FATAL: unreadable validation report: {exc}")
    shenzhen=load_rules().get("shenzhen_probe",{}) or {}
    reject_ms=float(shenzhen.get("reject_above_ms",350))
    reject_loss=float(shenzhen.get("reject_loss_pct",10))
    validated=[]
    for node in nodes:
        row=by_fp.get(fingerprint(node))
        if not row or not row.get("gemini") or not row.get("google_play"):
            continue
        if str(row.get("shenzhen_status")) not in {"cached","ok"}:
            continue
        ping=row.get("shenzhen_ping_ms")
        loss=row.get("shenzhen_loss_pct")
        if ping is None or loss is None:
            continue
        try:
            if float(ping)>reject_ms or float(loss)>reject_loss:
                continue
        except (TypeError,ValueError):
            continue
        validated.append(node)
    if not validated: raise SystemExit("FATAL: no nodes passed final Gemini/Play/Quality validation.")
    return validated

def suffix_rules(domains,group):
    return [f"DOMAIN-SUFFIX,{d},{group}" for d in domains]

def build_proxy_groups(fine_names):
    return [
        {"name":"GLOBAL","type":"select","proxies":["DIRECT","Fine"],"default-selected":"Fine"},
        {"name":"Fine","type":"url-test","proxies":fine_names,"url":"https://gemini.google.com/","interval":900,"timeout":8000,"tolerance":250,"lazy":False},
    ]

def build_config(fine_nodes):
    if not fine_nodes: raise ValueError("Fine pool must be non-empty")
    fine_nodes=unique_node_names(fine_nodes)
    fine_names=[n["name"] for n in fine_nodes]
    rules=OZON_DIRECT+LOCAL_IOT_DIRECT+PRIVATE_DIRECT+WECHAT_DIRECT+XIAOMI_DIRECT+suffix_rules(VIDEO_DOMAINS,"Fine")+suffix_rules(STORE_DOMAINS,"Fine")+["GEOIP,CN,DIRECT","MATCH,Fine"]
    return {
        "mixed-port":7890,"allow-lan":True,"bind-address":"*","mode":"rule","log-level":"warning","ipv6":False,"unified-delay":False,"tcp-concurrent":True,
        "profile":{"store-selected":True},
        "proxies":fine_nodes,
        "proxy-groups":build_proxy_groups(fine_names),
        "tun":{"enable":True,"stack":"system","auto-route":True,"auto-detect-interface":True},
        "dns":{"enable":True,"ipv6":False,"use-hosts":True,"enhanced-mode":"redir-host","nameserver":["223.5.5.5","119.29.29.29","1.1.1.1"],
               "nameserver-policy":{"+.mi.com":["223.5.5.5","119.29.29.29"],"+.xiaomi.com":["223.5.5.5","119.29.29.29"],"+.miwifi.com":["223.5.5.5","119.29.29.29"],"+.miui.com":["223.5.5.5","119.29.29.29"],"+.weixin.qq.com":["223.5.5.5","119.29.29.29"],"+.qq.com":["223.5.5.5","119.29.29.29"]},
               "fallback":["https://1.1.1.1/dns-query","tls://8.8.8.8"],"fallback-filter":{"geoip":True,"geoip-code":"CN"}},
        "rules":rules,
    }

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
    header=f"# fine-clash-unified-v3 | fine-clash-version:{version} | Fine=validated-pool | Ozon->DIRECT | CN->DIRECT | MATCH->Fine\n"
    OUT.write_text(header+dumped,encoding="utf-8")
    print(f"written {OUT}: Fine={len(config['proxies'])} validated nodes; rules={len(config['rules'])}")

if __name__=="__main__": main()
