# -*- coding: utf-8 -*-
"""Build the single public Clash/Mihomo profile from the validated Fine pool."""
from __future__ import annotations
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import yaml
from fine_clash import fingerprint, mihomo_node_is_testable, resolved_server_is_safe, unique_node_names

OUT = Path("live_clash.yaml")
SRC = Path("data/fine_pool.yaml")

# Bitz is the paid upstream subscription. Its URL embeds a private token, so it
# is NEVER stored in this repository: it is read from the environment instead.
# When unset, the profile degrades to the Fine-only layout, which keeps every
# public build (CI -> jsDelivr -> router) free of that token.
BITZ_URL_ENV = "FINE_BITZ_SUBSCRIPTION_URL"
# Every host that may appear as a proxy-provider URL has to be approved here.
# The published profile is world-readable, so an unapproved host is rejected
# instead of published: this is what stops the 2026-10-04 leak from recurring
# through a URL that happens not to contain the literal string "token=".
BITZ_ALLOWED_HOSTS_ENV = "FINE_BITZ_ALLOWED_HOSTS"
# The upstream answers HTTP 403 to every non-official client. Mihomo ignores a
# provider-level `http-opts.headers.User-Agent` and always sends its own
# `clash.meta/<version>` instead (verified locally with mihomo v1.19.32 against
# a probe server), so the UA must be set globally via `global-ua`.
# NOTE: `global-ua` applies to every outbound request Mihomo makes from this
# profile, including the url-test / health-check probes issued by Fine-Auto and
# Bitz-Auto. Bitz tolerates that UA, and no other upstream is contacted here,
# so it is safe today; revisit if another upstream ever starts caring.
BITZ_USER_AGENT = "BBGen2UA"
BITZ_HEALTH_CHECK_URL = "https://www.gstatic.com/generate_204"


# Query keys that carry a credential when present with a value.
BITZ_CREDENTIAL_QUERY_KEYS={"token","key","secret","passwd","password","auth","access_token","apikey","api_key","apikey2","code","uuid","sid","pwd","t","tk"}
# Path/value shapes that look like a secret rather than a stable endpoint name.
BITZ_CREDENTIAL_VALUE=re.compile(r"^(?:[0-9a-fA-F]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
BITZ_CREDENTIAL_SEGMENT=re.compile(r"/(?:[0-9a-fA-F]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?![0-9a-fA-F-])")


def bitz_allowed_hosts():
    """Hosts explicitly approved to appear in the published profile."""
    raw=os.environ.get(BITZ_ALLOWED_HOSTS_ENV) or ""
    return {host.strip().lower() for host in raw.split(",") if host.strip()}


def bitz_url_carries_credential(url):
    """True when the URL itself transports a secret (query key or opaque path segment)."""
    parsed=urlparse(url)
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        if name.lower() in BITZ_CREDENTIAL_QUERY_KEYS and values and any(values):
            return True
        if any(BITZ_CREDENTIAL_VALUE.match(value or "") for value in values):
            return True
    return bool(BITZ_CREDENTIAL_SEGMENT.search(parsed.path or ""))


def bitz_subscription_url():
    """Return the approved Bitz provider URL, or "" when Bitz is disabled.

    Fails closed on purpose. The profile built here is published to a public
    repository and served through jsDelivr, so a provider URL may only ever
    point at a host that was explicitly approved AND must not embed a
    credential. Rather than relying on grep-based gates downstream, the build
    refuses to produce anything when either condition is violated.
    """
    url=(os.environ.get(BITZ_URL_ENV) or "").strip()
    if not url:
        return ""
    if urlparse(url).scheme not in ("http","https"):
        raise SystemExit(f"FATAL: {BITZ_URL_ENV} must be an http(s) URL.")
    host=(urlparse(url).hostname or "").lower()
    allowed=bitz_allowed_hosts()
    if host not in allowed:
        raise SystemExit(
            f"FATAL: refusing to publish a Bitz provider on host {host!r}. "
            f"Only add it to {BITZ_ALLOWED_HOSTS_ENV} once you have confirmed the "
            f"URL contains no credential, because everything here is public."
        )
    if bitz_url_carries_credential(url):
        raise SystemExit(
            f"FATAL: {BITZ_URL_ENV} looks like it embeds a credential; the "
            f"published profile must never carry one."
        )
    return url

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

def build_proxy_groups(fine_names, bitz_enabled=False):
    """Build symmetric Fine / Bitz groups, each usable manually and via Auto.

    2026-10-07 调整：
      - 恢复 Bitz 组（付费上游），其节点来自 proxy-provider `BitzPool`。
      - 两组结构对称：`<组>-Auto`(url-test 自动测速选优) + DIRECT(强制直连)
        + 组内具体节点，全部可手动点选。
      - Fine 保持不变，仍是 validated-free-pool；大流量规则仍指向 Fine。
      - Bitz 只在设置了订阅 URL 的环境变量时出现；未设置时不产出任何 Bitz
        结构，公开订阅退化为 Fine-only，避免付费 token 泄露。
    """
    # `fine_names[0]` is the sticky-quality primary chosen by fine_clash.py's
    # sticky ordering (previous node if still Shenzhen-quality, else freshest
    # quality node). Pinning it as the default-selected keeps the connection
    # stable across subscription updates.
    primary=fine_names[0]
    groups=[
        {"name":"Fine","type":"select","proxies":["Fine-Auto","DIRECT"]+fine_names,"default-selected":primary},
        {"name":"Fine-Auto","type":"url-test","proxies":fine_names,"url":"https://play.google.com/store","interval":900,"timeout":8000,"tolerance":250,"lazy":False,"hidden":True},
    ]
    if bitz_enabled:
        # `Fine` is listed inside Bitz on purpose: if the upstream provider ever
        # fails to load (expired credential, dead relay, upstream outage) the
        # Bitz group would otherwise be empty and every MATCH-bound connection
        # would blackhole. Keeping Fine selectable gives the panel a working
        # exit instead. `DIRECT` and `Bitz-Auto` stay ahead so nothing changes
        # during normal operation.
        groups += [
            {"name":"Bitz","type":"select","proxies":["Bitz-Auto","DIRECT","Fine"],"use":["BitzPool"],"default-selected":"Bitz-Auto"},
            {"name":"Bitz-Auto","type":"url-test","include-all-providers":True,"url":BITZ_HEALTH_CHECK_URL,"interval":900,"timeout":8000,"tolerance":250,"lazy":False,"hidden":True},
        ]
    return groups

def build_config(fine_nodes):
    if not fine_nodes: raise ValueError("Fine pool must be non-empty")
    fine_nodes=unique_node_names(fine_nodes)
    fine_names=[n["name"] for n in fine_nodes]
    bitz_url=bitz_subscription_url()
    bitz_enabled=bool(bitz_url)
    # Bulk traffic (video / app stores) stays on Fine, the validated free pool.
    # Every other proxy-bound destination falls through to Bitz. When Bitz is
    # not configured the profile must never lose its fallback, so MATCH stays
    # on Fine instead of pointing at a group that does not exist.
    rules=LOCAL_IOT_DIRECT+PRIVATE_DIRECT+WECHAT_DIRECT+XIAOMI_DIRECT+suffix_rules(VIDEO_DOMAINS,"Fine")+suffix_rules(STORE_DOMAINS,"Fine")+["GEOIP,CN,DIRECT"]
    rules.append("MATCH,Bitz" if bitz_enabled else "MATCH,Fine")
    config={
        "mixed-port":7890,"allow-lan":True,"bind-address":"*","mode":"rule","log-level":"warning","ipv6":False,"unified-delay":False,"tcp-concurrent":True,
        "profile":{"store-selected":True},
    }
    if bitz_enabled:
        # Must sit next to the provider fetch, not inside `http-opts`: mihomo
        # silently ignores per-provider headers (see BITZ_USER_AGENT note).
        config["global-ua"]=BITZ_USER_AGENT
        config["proxy-providers"]={"BitzPool":{
            "type":"http",
            "url":bitz_url,
            "interval":21600,
            "health-check":{"enable":True,"url":BITZ_HEALTH_CHECK_URL,"interval":300},
        }}
    config["proxies"]=fine_nodes
    config["proxy-groups"]=build_proxy_groups(fine_names,bitz_enabled)
    config["tun"]={"enable":True,"stack":"system","auto-route":True,"auto-detect-interface":True}
    config["dns"]={"enable":True,"ipv6":False,"use-hosts":True,"enhanced-mode":"redir-host","nameserver":["223.5.5.5","119.29.29.29","1.1.1.1"],
               "nameserver-policy":{"+.mi.com":["223.5.5.5","119.29.29.29"],"+.xiaomi.com":["223.5.5.5","119.29.29.29"],"+.xiaomi.cn":["223.5.5.5","119.29.29.29"],"+.mijia.com":["223.5.5.5","119.29.29.29"],"+.miwifi.com":["223.5.5.5","119.29.29.29"],"+.miui.com":["223.5.5.5","119.29.29.29"],"+.weixin.qq.com":["223.5.5.5","119.29.29.29"],"+.qq.com":["223.5.5.5","119.29.29.29"],"+.myqcloud.com":["223.5.5.5","119.29.29.29"],"+.tencentcos.cn":["223.5.5.5","119.29.29.29"]},
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
    bitz_enabled="BitzPool" in (config.get("proxy-providers") or {})
    fallback="Bitz" if bitz_enabled else "Fine"
    bitz_note=f"Bitz=remote-provider(UA={BITZ_USER_AGENT}) | " if bitz_enabled else "Bitz=disabled(no-subscription-url) | "
    header=(f"# fine-clash-unified-v4 | fine-clash-version:{version} | "
            f"{bitz_note}Fine=validated-pool | bulk->Fine | CN->DIRECT | MATCH->{fallback}\n")
    OUT.write_text(header+dumped,encoding="utf-8")
    print(f"written {OUT}: Fine={len(config['proxies'])} validated nodes; "
          f"Bitz={'remote-provider' if bitz_enabled else 'disabled'}; rules={len(config['rules'])}")

if __name__=="__main__": main()
