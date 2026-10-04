# -*- coding: utf-8 -*-
"""Build the single public Clash/Mihomo profile with explicit Bitz nodes."""
from __future__ import annotations
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
import requests
import yaml
from urllib.parse import urlsplit, urlunsplit
from fine_clash import fingerprint, mihomo_node_is_testable, parse_subscription, resolved_server_is_safe, unique_node_names

OUT = Path("live_clash.yaml")
SRC = Path("data/fine_pool.yaml")
BITZ_SUB_URL = os.environ.get("BITZ_SUB_URL", "").strip()
GLOBALPING_HTTP_URL = "https://api.globalping.io/v1/measurements"

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
    return unique_node_names(out)

def load_fine_nodes():
    if not SRC.is_file(): raise SystemExit(f"FATAL: missing Fine pool: {SRC}")
    raw=yaml.safe_load(SRC.read_text(encoding="utf-8")) or {}
    parsed=raw.get("proxies") or []
    nodes=_dedupe_nodes([node for node in parsed if isinstance(node,dict) and resolved_server_is_safe(node.get("server",""))],"")
    if not nodes: raise SystemExit("FATAL: Fine pool is empty or has no testable nodes.")
    return nodes

def _redact_url(url):
    try:
        parts=urlsplit(url)
        if not parts.scheme or not parts.netloc:
            return "<invalid-url>"
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except Exception:
        return "<invalid-url>"

def _globalping_fetch_text(url):
    parts=urlsplit(url)
    if not parts.hostname:
        raise RuntimeError("invalid Bitz subscription host")
    target=parts.hostname
    if parts.port:
        target=f"{target}:{parts.port}"
    path=parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    payload={
        "type":"http",
        "target":target,
        "locations":[{"city":"Shenzhen","limit":1}],
        "measurementOptions":{
            "protocol":"HTTPS" if parts.scheme.lower()=="https" else "HTTP",
            "request":{"method":"GET","path":path},
        },
    }
    headers={"User-Agent":"Fine-Clash/2.1 (+Globalping fallback)","Content-Type":"application/json"}
    created=requests.post(GLOBALPING_HTTP_URL,json=payload,headers=headers,timeout=20)
    created.raise_for_status()
    body=created.json()
    measurement_id=body.get("id")
    if not measurement_id:
        raise RuntimeError("Globalping returned no measurement id")
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        time.sleep(0.6)
        response=requests.get(f"{GLOBALPING_HTTP_URL}/{measurement_id}",headers={"User-Agent":"Fine-Clash/2.1 (+Globalping fallback)"},timeout=15)
        response.raise_for_status()
        result=response.json()
        if result.get("status")=="in-progress":
            continue
        results=result.get("results") or []
        if not results:
            raise RuntimeError("Globalping returned no probe result")
        remote=results[0].get("result") or {}
        status=int(remote.get("statusCode") or 0)
        if status>=400:
            raise RuntimeError(f"Bitz returned HTTP {status} from Shenzhen Globalping probe")
        text=remote.get("rawBody")
        if not isinstance(text,str) or not text.strip():
            raise RuntimeError("Globalping returned an empty HTTP response body")
        return text
    raise RuntimeError("Globalping Bitz fetch timed out")

def fetch_bitz_nodes():
    if not BITZ_SUB_URL:
        raise SystemExit("FATAL: BITZ_SUB_URL is not configured. Store the complete Bitz subscription URL in the BITZ_SUB_URL environment variable / GitHub Actions secret.")
    safe_url=_redact_url(BITZ_SUB_URL)
    response_text=None
    direct_error=None
    try:
        r=requests.get(
            BITZ_SUB_URL,
            timeout=30,
            headers={"User-Agent":"Fine-Clash/2.1","Accept":"text/plain,application/yaml,*/*"},
        )
        r.raise_for_status()
        response_text=r.text
    except requests.HTTPError as exc:
        status=exc.response.status_code if exc.response is not None else "unknown"
        direct_error=f"HTTP {status}"
        if status not in (401,403):
            raise SystemExit(f"FATAL: Bitz subscription fetch failed with HTTP {status} at {safe_url}.") from exc
    except requests.RequestException as exc:
        direct_error=f"network error: {type(exc).__name__}"
    if response_text is None:
        try:
            print(f"Bitz direct fetch failed ({direct_error}); retrying once through a Shenzhen Globalping HTTP probe.")
            response_text=_globalping_fetch_text(BITZ_SUB_URL)
            print("Bitz subscription fetched successfully through Shenzhen Globalping.")
        except Exception as exc:
            raise SystemExit(
                f"FATAL: Bitz subscription unavailable at {safe_url}. Direct runner fetch failed ({direct_error}); "
                f"Shenzhen Globalping fallback also failed ({type(exc).__name__}: {str(exc)[:160]}). "
                "The Bitz endpoint is reachable only from a network path not currently available to the build runner."
            ) from exc
    parsed=parse_subscription(response_text)
    nodes=_dedupe_nodes([node for node in parsed if resolved_server_is_safe(node.get("server",""))],"Bitz | ")
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
    if not fine_nodes or not bitz_nodes: raise ValueError("Fine and Bitz pools must both be non-empty")
    combined=unique_node_names([*bitz_nodes,*fine_nodes])
    bitz_count=len(bitz_nodes)
    bitz_nodes=combined[:bitz_count]
    fine_nodes=combined[bitz_count:]
    fine_names=[n["name"] for n in fine_nodes]; bitz_names=[n["name"] for n in bitz_nodes]
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
