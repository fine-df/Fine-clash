from __future__ import annotations
import base64, hashlib, ipaddress, json, os, re, shutil, socket, subprocess, tempfile, time
from concurrent.futures import ThreadPoolExecutor
import functools
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse
import requests, yaml

SUPPORTED = {"vmess","vless","trojan","ss"}
ALLOWED_FIELDS = {
    "vmess":{"type","name","server","port","uuid","alterId","cipher","tls","servername","network","ws-opts","udp"},
    "vless":{"type","name","server","port","uuid","tls","servername","flow","network","ws-opts","grpc-opts","reality-opts","client-fingerprint","encryption","udp"},
    "trojan":{"type","name","server","port","password","tls","servername","network","ws-opts","udp"},
    "ss":{"type","name","server","port","cipher","password","udp"},
}
URI_RE = re.compile(r"(?:(?:vmess|vless|trojan|ss)://[^\s\"'<>]+)")
UA="Fine-Clash/1.0"
# Candidate file selection (2026-10-20 fix).
#
# Root cause of the 28/28 wrong files (audit Fine-clash-diagnosis-2026-10-20):
# the old rule selected a file when a keyword (sub/subscribe/clash/v2ray/proxy/
# nodes/free/...) appeared ANYWHERE in the full path as a substring. Client-
# software repos (clash-verge, v2rayN, FlClash, Shadowrocket, mitmproxy, sub2api,
# ...) and unrelated projects contain those tokens in directory/package names, so
# their source-tree files (i18n translations, docker-compose, k8s configmap,
# github workflows, LICENSE, test fixtures, adblock .conf rules, fonts, cmake/
# pubspec) were pulled in as if they were subscriptions.
#
# Fix: decide on the FILE BASENAME only, matching a keyword as a *whole word*
# (not a substring), then reject paths that belong to a CONFIRMED non-subscription
# category. Whole-word basename matching alone excludes 25 of the 28 audited
# files; the remaining 3 (proxy-configmap, sandbox-network-proxy-image,
# sr_proxy_banad) are caught by the targeted blacklist below.

# Keyword candidates, matched as whole words against the basename only.
CANDIDATE_TOKENS = ("sub", "subscribe", "subscription", "clash", "v2ray",
                    "proxy", "nodes", "node", "free")
CANDIDATE_TOKENS_SET = set(CANDIDATE_TOKENS)

# Extension allow-list -- unchanged from the pre-fix EXTENSIONS.
SUBSCRIPTION_EXT = (".yaml", ".yml", ".txt", ".conf", ".base64")

# Confirmed non-subscription path/basename signals, each traced to >=1 of the 28
# audited mis-matches. They are never legitimate subscription locations, so
# rejecting them cannot hide a real node source. Subscription keywords
# (sub/subscribe/subscription/clash/v2ray/proxy/nodes/node/free) are deliberately
# absent so a real `nodes/...` or `clash/...` source is never dropped.
_PATH_BLACKLIST = re.compile(
    r"(?<![a-z0-9])("
    r"i18n|locale|locales|lang|languages|"
    r"docker|compose|configmap|"
    r"\.github|workflows|issue[_-]?template|"
    r"submission|submodule|submodules|subset|freeze|"
    r"test|tests|example|examples|sample|samples|fixture|fixtures|spec|benchmarks|"
    r"cmake|pubspec|flutter|"
    r"license|licence|readme|"
    r"adblock|fonts|font|assets|renderers|"
    r"mitm|mitmproxy|reverse[_-]?proxy|banad"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)


def _basename_tokens(path):
    base = path.rsplit("/", 1)[-1].lower()
    name, _ext = os.path.splitext(base)
    return {t for t in re.split(r"[^a-z0-9]+", name) if t}


def _is_subscription_path(path):
    """True only for file paths that plausibly hold a real subscription.

    Selection is based on the file BASENAME (whole-word keyword match) plus a
    targeted blacklist of confirmed non-subscription categories. This stops
    client-software repos from being selected merely because a directory in
    their tree contains a keyword.
    """
    low = path.lower()
    if not low.endswith(SUBSCRIPTION_EXT):
        return False
    if _PATH_BLACKLIST.search(low):
        return False
    return bool(CANDIDATE_TOKENS_SET & _basename_tokens(path))
ROOT=Path(__file__).resolve().parent

# High-priority direct routes for WeChat/Tencent infrastructure. These sit above
# generic CN matching because some router environments resolve or route these
# domains before country rules can reliably classify them.
WECHAT_DIRECT_RULES = [
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

# Xiaomi/Mi Home direct rules. Explicit domain rules take precedence over GEOIP so
# Xiaomi IoT control/cloud traffic is not accidentally sent through the overseas proxy.
XIAOMI_DIRECT_RULES = [
    "DOMAIN-SUFFIX,mi.com,DIRECT",
    "DOMAIN-SUFFIX,xiaomi.com,DIRECT",
    "DOMAIN-SUFFIX,miwifi.com,DIRECT",
    "DOMAIN-SUFFIX,miui.com,DIRECT",
]
LOCAL_IOT_DIRECT_RULES = [
    "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
]

def load_rules():
    return yaml.safe_load((ROOT/"config.yaml").read_text(encoding="utf-8"))

def _safe_int(value, default=0):
    try: return int(str(value).strip())
    except (TypeError,ValueError): return default

def _safe_float(value, default=0.0):
    try:
        if value is None: return default
        return float(value)
    except (TypeError,ValueError): return default

def _clean_name(value, fallback):
    value=unquote(str(value or "")).strip()
    return value[:100] or fallback

def _decode_b64(value):
    value=re.sub(r"\s+","",value).strip()
    value += "=" * (-len(value) % 4)
    for decoder in (base64.urlsafe_b64decode,base64.b64decode):
        try: return decoder(value.encode())
        except Exception: pass
    return None

def is_safe_server(server):
    if not isinstance(server, (str, int)):
        return False
    value=str(server or "").strip().lower().rstrip(".")
    blocked={"localhost","ip6-localhost","ip6-loopback","0.0.0.0","::","ip6-allnodes","ip6-allrouters"}
    if value in blocked or value.endswith((".localhost",".local",".internal")): return False
    try: return ipaddress.ip_address(value).is_global
    except ValueError: return True

@functools.lru_cache(maxsize=4096)
def resolved_server_is_safe(server):
    """Fail closed when a proxy hostname resolves to any non-global address.

    Public subscription sources are untrusted input. Blocking only literal private
    IPs is insufficient because an attacker-controlled hostname can resolve to loopback,
    link-local, RFC1918, or other non-public addresses on the runner.
    """
    if not is_safe_server(server):
        return False
    value=str(server or "").strip().strip("[]")
    try:
        infos=socket.getaddrinfo(value,None,socket.AF_UNSPEC,socket.SOCK_STREAM)
    except (socket.gaierror,UnicodeError):
        return False
    addresses=set()
    for info in infos:
        raw=str(info[4][0]).split("%",1)[0]
        try:
            addresses.add(ipaddress.ip_address(raw))
        except ValueError:
            return False
    return bool(addresses) and all(addr.is_global for addr in addresses)


def _parse_vmess(uri):
    payload=_decode_b64(uri[8:])
    if not payload: return None
    try: obj=json.loads(payload.decode("utf-8","ignore"))
    except json.JSONDecodeError: return None
    server,port,uuid=str(obj.get("add") or "").strip(),_safe_int(obj.get("port")),str(obj.get("id") or "").strip()
    if not server or not port or not uuid or not is_safe_server(server): return None
    node={"type":"vmess","name":_clean_name(obj.get("ps"),f"vmess-{server}:{port}"),"server":server,"port":port,"uuid":uuid,"alterId":_safe_int(obj.get("aid")),"cipher":str(obj.get("scy") or "auto"),"udp":True}
    net=str(obj.get("net") or "tcp").lower()
    if net!="tcp": node["network"]=net
    if obj.get("tls") not in (None,"",False,0,"none"): node["tls"]=True
    if obj.get("sni"): node["servername"]=obj["sni"]
    if net=="ws":
        ws={}
        if obj.get("host"): ws["headers"]={"Host":obj["host"]}
        if obj.get("path"): ws["path"]=obj["path"]
        if ws: node["ws-opts"]=ws
    return node

def _parse_standard(uri):
    parsed=urlparse(uri); scheme=parsed.scheme.lower()
    if scheme not in {"vless","trojan","ss"}: return None
    server,port=parsed.hostname,parsed.port
    if not isinstance(server, str) or not server or not port or not is_safe_server(server): return None
    name=_clean_name(parsed.fragment,f"{scheme}-{server}:{port}")
    if scheme=="ss":
        user,password=parsed.username or "",parsed.password or ""
        if not password and "@" not in parsed.netloc:
            decoded=_decode_b64(parsed.netloc.split("#",1)[0])
            if decoded:
                try:
                    alt=urlparse("ss://"+decoded.decode())
                    user,password=alt.username or "",alt.password or ""
                    server,port=alt.hostname or server,alt.port or port
                except ValueError: pass
        if not user or not password: return None
        return {"type":"ss","name":name,"server":server,"port":port,"cipher":unquote(user),"password":unquote(password),"udp":True}
    secret=unquote(parsed.username or "")
    if not secret: return None
    node={"type":scheme,"name":name,"server":server,"port":port,"udp":True,("uuid" if scheme=="vless" else "password"):secret}
    query=parse_qs(parsed.query,keep_blank_values=True); security=query.get("security",[""])[0].lower()
    if scheme=="vless":
        node["encryption"]=unquote(query.get("encryption",["none"])[0] or "none")
    if security in {"tls","reality"} or scheme=="trojan": node["tls"]=True
    for src,dst in (("sni","servername"),("flow","flow"),("fp","client-fingerprint")):
        value=query.get(src,[""])[0]
        if value: node[dst]=unquote(value)
    if security=="reality":
        pbk=unquote(query.get("pbk",[""])[0]); sid=unquote(query.get("sid",[""])[0])
        reality={}
        if pbk: reality["public-key"]=pbk
        if sid: reality["short-id"]=sid
        if reality: node["reality-opts"]=reality
    network=query.get("type",[""])[0]
    if network: node["network"]=network
    if network=="ws":
        ws={}
        if query.get("path",[""])[0]: ws["path"]=unquote(query["path"][0])
        if query.get("host",[""])[0]: ws["headers"]={"Host":unquote(query["host"][0])}
        if ws: node["ws-opts"]=ws
    elif network=="grpc" and query.get("serviceName",[""])[0]:
        node["grpc-opts"]={"grpc-service-name":unquote(query["serviceName"][0])}
    elif network=="xhttp":
        xhttp={}
        if query.get("path",[""])[0]: xhttp["path"]=unquote(query["path"][0])
        if query.get("host",[""])[0]: xhttp["host"]=unquote(query["host"][0])
        if query.get("mode",[""])[0]: xhttp["mode"]=unquote(query["mode"][0])
        if xhttp: node["xhttp-opts"]=xhttp
    return node

TESTABLE_NETWORKS = {"tcp","ws","grpc"}

def mihomo_node_reject_reason(node):
    network=str(node.get("network") or "tcp").strip().lower()
    if network not in TESTABLE_NETWORKS:
        return f"unsupported network: {network}"
    reality=node.get("reality-opts")
    if reality is None:
        return None
    if not isinstance(reality,dict):
        return "invalid reality-opts"
    pbk=str(reality.get("public-key") or "").strip()
    if not pbk:
        return "missing REALITY public key"
    try:
        padded=pbk + "=" * (-len(pbk) % 4)
        decoded=base64.b64decode(padded.encode(),altchars=b"-_",validate=True)
    except Exception:
        return "invalid REALITY public key encoding"
    if len(decoded) != 32:
        return "invalid REALITY public key length"
    sid=reality.get("short-id")
    if sid is not None and str(sid).strip():
        sid=str(sid).strip()
        if sid.lower()=="null" or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,8}",sid):
            return "invalid REALITY short ID"
    return None

def mihomo_node_is_testable(node):
    return mihomo_node_reject_reason(node) is None


def parse_uri(uri):
    uri=uri.strip()
    try:
        return _parse_vmess(uri) if uri.lower().startswith("vmess://") else _parse_standard(uri)
    except (ValueError, TypeError):
        # A malformed URI (e.g. a non-integer port 'ADzlhA3ndouUCY3JbLddR' found in a
        # real discovered source) must be skipped, never crash the whole discovery run.
        # One bad node must not zero out all sources.
        return None

def parse_subscription(text):
    if not text: return []
    try:
        obj=yaml.safe_load(text); proxies=obj.get("proxies") if isinstance(obj,dict) else None
        if isinstance(proxies,list):
            out=[]
            for proxy in proxies:
                if not isinstance(proxy,dict): continue
                kind=str(proxy.get("type","")).lower()
                if kind not in SUPPORTED or not isinstance(proxy.get("server"), str) or not proxy.get("server") or not _safe_int(proxy.get("port")): continue
                if not is_safe_server(proxy.get("server")): continue
                node={k:proxy[k] for k in ALLOWED_FIELDS[kind] if k in proxy}
                node["type"]=kind; node["port"]=_safe_int(proxy["port"]); node["name"]=_clean_name(node.get("name"),f"{kind}-{node['server']}:{node['port']}")
                out.append(node)
            if out: return out
    except yaml.YAMLError: pass
    nodes=[node for uri in URI_RE.findall(text) if (node:=parse_uri(uri))]
    if nodes: return nodes
    decoded=_decode_b64(text)
    if decoded: return [node for uri in URI_RE.findall(decoded.decode("utf-8","ignore")) if (node:=parse_uri(uri))]
    return []

def fingerprint(node):
    # Include transport/security parameters. server+port+credential alone is too coarse:
    # two nodes can share the same endpoint while differing by SNI/WS/gRPC/Reality.
    identity = {
        "type": node.get("type"),
        "server": node.get("server"),
        "port": node.get("port"),
        "uuid": node.get("uuid"),
        "password": node.get("password"),
        "cipher": node.get("cipher"),
        "tls": node.get("tls"),
        "servername": node.get("servername"),
        "flow": node.get("flow"),
        "client-fingerprint": node.get("client-fingerprint"),
        "encryption": node.get("encryption"),
        "network": node.get("network"),
        "ws-opts": node.get("ws-opts"),
        "grpc-opts": node.get("grpc-opts"),
        "reality-opts": node.get("reality-opts"),
    }
    data=json.dumps(identity,ensure_ascii=False,sort_keys=True,separators=(",",":"))
    return hashlib.sha256(data.encode()).hexdigest()[:20]

def load_history(path):
    if not path.exists(): return {}
    try:
        data=json.loads(path.read_text(encoding="utf-8")); return data if isinstance(data,dict) else {}
    except (OSError,json.JSONDecodeError): return {}

def update_history(db,fp,result,score_threshold=70):
    today=date.today().isoformat()
    row=db.setdefault(fp,{"first_seen":today,"last_seen":today,"seen_count":0,"pass_count":0,"gemini_pass_count":0,"play_pass_count":0})
    if row["last_seen"]!=today:
        row["last_seen"]=today; row["seen_count"]+=1
    elif row["seen_count"]==0:
        row["seen_count"]=1
    else:
        # 同一自然日内重复访问：pass_count/gemini/play 计数已在当天首次访问时累加，
        # 此处不再累加，保持 pass_count 与 seen_count 同为「天数」口径，避免同天多次运行虚高。
        return row
    if result.get("score",0)>=float(score_threshold): row["pass_count"]+=1
    if result.get("gemini"): row["gemini_pass_count"]+=1
    if result.get("google_play"): row["play_pass_count"]+=1
    return row

def lifespan_days(row):
    try: return max(0,(date.today()-date.fromisoformat(row["first_seen"])).days)
    except Exception: return 0


def load_previous_published_nodes(path, max_nodes=5):
    """Load a small continuity reserve from the previous published profile."""
    try: limit=max(0,int(max_nodes))
    except (TypeError,ValueError): limit=5
    if limit<=0 or not path.is_file(): return []
    try: nodes=parse_subscription(path.read_text(encoding="utf-8"))
    except OSError: return []
    out=[]; seen=set()
    for node in nodes:
        fp=fingerprint(node)
        if fp in seen or node.get("type") not in SUPPORTED: continue
        server=node.get("server")
        if not server or not resolved_server_is_safe(server) or not mihomo_node_is_testable(node): continue
        seen.add(fp); out.append(node)
        if len(out)>=limit: break
    return out

class GlobalpingShenzhenProbe:
    def __init__(self, cfg):
        self.cfg=cfg
        self.session=requests.Session()
        self.session.headers.update({"User-Agent":UA,"Content-Type":"application/json"})
        token_name=str(self.cfg.get("api_token_env","GLOBALPING_API_TOKEN"))
        token=os.getenv(token_name,"").strip()
        if token:
            self.session.headers["Authorization"]=f"Bearer {token}"
        self.base_url="https://api.globalping.io/v1/measurements"

    def measure(self, node):
        city=str(self.cfg.get("city","Shenzhen"))
        port=_safe_int(node.get("port"))
        target=str(node.get("server") or "").strip()
        if not target or not port:
            return {"ok":False,"status":"invalid-target"}
        payload={
            "target":target,
            "type":"ping",
            "locations":[{"city":city,"limit":1}],
            "measurementOptions":{
                "protocol":str(self.cfg.get("protocol","TCP")).upper(),
                "port":port,
                "packets":int(self.cfg.get("packets",3)),
            },
        }
        try:
            created=self.session.post(self.base_url,json=payload,timeout=15)
            created.raise_for_status(); body=created.json(); measurement_id=body.get("id")
            if not measurement_id:
                return {"ok":False,"status":"no-measurement-id"}
            deadline=time.monotonic()+float(self.cfg.get("max_wait_seconds",30))
            poll=float(self.cfg.get("poll_interval_seconds",2))
            result=None
            while time.monotonic()<deadline:
                time.sleep(poll)
                response=self.session.get(f"{self.base_url}/{measurement_id}",timeout=15)
                response.raise_for_status(); result=response.json()
                if result.get("status") != "in-progress": break
            if not result or result.get("status")=="in-progress":
                return {"ok":False,"status":"timeout","measurement_id":measurement_id}
            for entry in result.get("results",[]):
                data=entry.get("result") or {}
                stats=data.get("stats") or {}
                avg=stats.get("avg")
                if avg is None: avg=stats.get("average")
                loss=stats.get("loss")
                if avg is not None:
                    return {
                        "ok":True,
                        "status":"ok",
                        "avg_ms":float(avg),
                        "loss_pct":float(loss) if loss is not None else None,
                        "probe_city":(entry.get("probe") or {}).get("city"),
                        "measurement_id":measurement_id,
                    }
            return {"ok":False,"status":"no-stats","measurement_id":measurement_id}
        except (requests.RequestException,ValueError,TypeError) as exc:
            return {"ok":False,"status":"error","error":str(exc)[:180]}


def cached_shenzhen_result(row, cfg):
    checked=row.get("shenzhen_checked_at")
    avg=row.get("shenzhen_ping_ms")
    if not checked or avg is None: return None
    try:
        checked_at=datetime.fromisoformat(checked)
        if datetime.now(timezone.utc)-checked_at <= timedelta(days=float(cfg.get("cache_days",1))):
            return {"ok":True,"status":"cached","avg_ms":float(avg),"loss_pct":row.get("shenzhen_loss_pct"),"probe_city":row.get("shenzhen_probe_city")}
    except (ValueError,TypeError):
        pass
    return None


def shenzhen_passes(result, cfg):
    if result.get("ok"):
        try:
            avg=float(result["avg_ms"])
            loss=result.get("loss_pct")
            max_loss=float(cfg.get("reject_loss_pct",100))
            if loss is None:
                return False
            return avg <= float(cfg.get("reject_above_ms",400)) and float(loss) <= max_loss
        except (TypeError,ValueError):
            return False
    return not bool(cfg.get("fail_closed",False))


def save_shenzhen_history(row, result):
    row["shenzhen_checked_at"]=datetime.now(timezone.utc).isoformat()
    row["shenzhen_ping_ms"]=result.get("avg_ms") if result.get("ok") else None
    row["shenzhen_loss_pct"]=result.get("loss_pct") if result.get("ok") else None
    row["shenzhen_status"]=result.get("status","unknown")
    row["shenzhen_probe_city"]=result.get("probe_city")

CLOUD_MARKERS=("amazon","aws","google","azure","microsoft","digitalocean","vultr","linode","hetzner","contabo","oracle","cloudflare")
HIGH_RISK_MARKERS=("m247","layer7","bluevps","alfahost")

def clean_score(ipinfo,google_result):
    if not ipinfo: return 60
    score=80; org=str(ipinfo.get("org","")).lower()
    if any(x in org for x in CLOUD_MARKERS+HIGH_RISK_MARKERS): score-=20
    privacy=ipinfo.get("privacy") or {}
    if isinstance(privacy,dict):
        if privacy.get("vpn"): score-=15
        if privacy.get("proxy"): score-=15
        if privacy.get("tor"): score-=20
        if privacy.get("hosting"): score-=15
    if google_result.get("challenge"): score-=30
    if not google_result.get("ok"): score-=20
    return max(0,min(100,score))

def total_score(*,gemini,google_play,google,clean,lifespan,stability):
    points=(20 if google.get("ok") else 0)+(25 if gemini else 0)+(20 if google_play else 0)+round(clean*0.20)
    points += 10 if lifespan>=30 else 7 if lifespan>=14 else 4 if lifespan>=7 else 2 if lifespan>=3 else 0
    points += round(5*max(0,min(1,stability)))
    return min(100,points)

def source_path_sort_key(path):
    low=str(path).lower()
    dates=[int(x) for x in re.findall(r"(20\d{6})", low)]
    versions=[int(x) for x in re.findall(r"(?:v|version)[-_]?(\d+)", low)]
    date_score=max(dates) if dates else -1
    version_score=max(versions) if versions else -1
    is_readme=1 if "readme" in low else 0
    return (date_score,version_score,-is_readme,-len(low),low)

class GitHubDiscovery:
    def __init__(self,token,cfg):
        self.cfg=cfg; self.session=requests.Session(); self.session.headers.update({"User-Agent":UA,"Accept":"application/vnd.github+json"})
        if token: self.session.headers["Authorization"]=f"Bearer {token}"
        # Auditable discovery metadata. Lets the run report distinguish a genuine
        # "no matching repositories" result from a silent network/API failure, so a
        # temporary GitHub outage is never misreported as a clean empty run.
        self.meta={
            "search_succeeded":False,"search_error":None,"rate_limited":False,
            "queries":0,"repos_found":0,"repos_filtered":0,"repos_excluded":0,"candidate_files":0,
            "candidate_files_failed":0,"fetched":0,"fetched_failed":0,
            "parsed":0,"parse_failed":0,"failure_type":None,
        }
    def _get_json(self,url,params=None):
        try:
            response=self.session.get(url,params=params,timeout=20); response.raise_for_status(); return response.json()
        except requests.RequestException as exc:
            status=getattr(getattr(exc,"response",None),"status_code",None)
            if status in (403,429): self.meta["rate_limited"]=True
            raise
    def search_repositories(self):
        cutoff=(datetime.now(timezone.utc)-timedelta(days=int(self.cfg["recent_days"]))).date().isoformat(); repos={}
        push_suffix=f" pushed:>={cutoff}" if self.cfg.get("require_recent_push",False) else ""
        self.meta["queries"]=len(self.cfg["queries"])
        exclude=set(self.cfg.get("exclude_repos", []) or [])
        for base_query in self.cfg["queries"]:
            try:
                data=self._get_json("https://api.github.com/search/repositories",{"q":f"{base_query}{push_suffix}","sort":"stars","order":"desc","per_page":self.cfg["repositories_per_query"]})
                self.meta["search_succeeded"]=True
            except requests.RequestException as exc:
                self.meta["failure_type"]="search_error"; self.meta["search_error"]=f"{type(exc).__name__}: {str(exc)[:160]}"
                continue
            for item in data.get("items",[]):
                self.meta["repos_found"]+=1
                fn=item["full_name"]
                if fn in exclude:
                    # Confirmed client-software / panel repos (audit §1.2) — never
                    # subscription sources; drop post-search to cut dilution without
                    # bloating the 256-char query with inline `-repo:` qualifiers.
                    self.meta["repos_excluded"]+=1; continue
                if int(item.get("stargazers_count", 0)) >= int(self.cfg.get("min_stars", 30)):
                    repos[fn]=item
                else:
                    self.meta["repos_filtered"]+=1
        return sorted(repos.values(),key=lambda x:(x.get("stargazers_count",0),x.get("pushed_at","")),reverse=True)[:int(self.cfg["max_repositories"])]
    def candidate_files(self,repo):
        owner,name=repo["full_name"].split("/",1)
        try: tree=self._get_json(f"https://api.github.com/repos/{owner}/{name}/git/trees/{repo['default_branch']}",{"recursive":"1"})
        except requests.RequestException as exc:
            self.meta["candidate_files_failed"]+=1
            status=getattr(getattr(exc,"response",None),"status_code",None)
            if status in (403,429): self.meta["rate_limited"]=True
            return []
        self.meta["candidate_files"]+=1
        paths=[]
        for item in tree.get("tree",[]):
            if item.get("type")!="blob": continue
            path=item.get("path","")
            if _is_subscription_path(path): paths.append(path)
        paths.sort(key=lambda p: source_path_sort_key(p), reverse=True)
        return paths[:int(self.cfg["max_candidate_files_per_repo"])]
    def fetch_and_validate(self,repo,path):
        owner,name=repo["full_name"].split("/",1); raw=f"https://raw.githubusercontent.com/{owner}/{name}/{quote(repo['default_branch'],safe='')}/{quote(path,safe='/')}"
        try:
            response=self.session.get(raw,timeout=20,allow_redirects=True); response.raise_for_status()
            if len(response.content)>int(self.cfg["max_source_bytes"]): self.meta["parse_failed"]+=1; return None
        except requests.RequestException:
            self.meta["fetched_failed"]+=1; return None
        self.meta["fetched"]+=1
        nodes=parse_subscription(response.text)
        if len(nodes)<int(self.cfg["min_nodes_per_source"]):
            self.meta["parse_failed"]+=1; return None
        self.meta["parsed"]+=1
        return {"url":raw,"repo":repo["full_name"],"path":path,"stars":repo.get("stargazers_count",0),"forks":repo.get("forks_count",0),"pushed_at":repo.get("pushed_at"),"nodes":len(nodes)}
    def discover(self):
        out=[]; seen=set()
        repos=self.search_repositories()
        for repo in repos:
            for path in self.candidate_files(repo):
                source=self.fetch_and_validate(repo,path)
                if source and source["url"] not in seen:
                    seen.add(source["url"]); out.append(source)
        # Distinguish a successful search with zero matches from a failed search.
        if not out and not self.meta["search_succeeded"]:
            self.meta["failure_type"]=self.meta["failure_type"] or "no_fresh_sources_discovered"
        elif out:
            self.meta["search_succeeded"]=True
        return out, dict(self.meta)

MIHOMO_GEO_FILES = ("GeoSite.dat","Country.mmdb","geoip.metadb","geosite.dat","geoip.dat")

def prepare_mihomo_geodata(work_dir, geo_dir):
    work_dir=Path(work_dir)
    geo_dir=Path(geo_dir)
    copied=[]
    for filename in MIHOMO_GEO_FILES:
        src=geo_dir/filename
        if src.is_file():
            shutil.copyfile(src, work_dir/filename)
            copied.append(filename)
    return copied


class MihomoTester:
    def __init__(self,binary,cfg,port_offset=0):
        self.binary=binary; self.cfg=cfg; self.proc=None; self.tmp=None; self.log_handle=None; self.session=requests.Session()
        self.port_offset=int(port_offset)
        # 端口改由 start() 运行时经 OS 分配空闲端口（见 _alloc_port），
        # 避免 test_nodes_parallel 多 worker 固定 idx*10 端口与机器上残留/其它 mihomo 冲突。
        self.proxy_port=None
        self.controller_port=None
    @staticmethod
    def _alloc_port():
        """让 OS 分配一个当前空闲的临时端口并返回。关闭探测 socket 后立刻交还内核，
        由 mihomo 在微小时窗后绑定——冲突概率极低，且远优于固定 idx*10 端口。"""
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
        finally:
            s.close()
    def start(self,nodes):
        names=[]; proxies=[]
        for idx,node in enumerate(nodes):
            name=f"N{idx:03d}"; names.append(name); proxy=dict(node); proxy["name"]=name; proxies.append(proxy)
        # 运行时分配独立空闲端口，杜绝并行 worker 间及与机器残留 mihomo 的端口冲突
        self.controller_port=self._alloc_port()
        self.proxy_port=self._alloc_port()
        config={"mixed-port":self.proxy_port,"allow-lan":False,"mode":"rule","log-level":"error","external-controller":f"127.0.0.1:{self.controller_port}","proxies":proxies,"proxy-groups":[{"name":"TEST","type":"select","proxies":names}],"rules":["GEOIP,CN,DIRECT","MATCH,TEST"]}
        self.tmp=Path(tempfile.mkdtemp(prefix="fine-clash-")); (self.tmp/"config.yaml").write_text(yaml.safe_dump(config,allow_unicode=True,sort_keys=False),encoding="utf-8")
        # Preload local Mihomo geodata into the exact filenames Mihomo expects.
        # This keeps CI startup independent of runtime GeoIP/GeoSite downloads.
        geo_dir=Path(os.environ.get("MIHOMO_GEO_DIR",str(ROOT)))
        prepare_mihomo_geodata(self.tmp, geo_dir)
        self.log_path=self.tmp/"mihomo.log"
        self.log_handle=self.log_path.open("w",encoding="utf-8")
        self.proc=subprocess.Popen([self.binary,"-d",str(self.tmp)],stdout=self.log_handle,stderr=subprocess.STDOUT)
        deadline=time.time()+max(5.0,float(self.cfg.get("controller_startup_seconds",1.5))*4)
        last_error=None
        while time.time()<deadline:
            if self.proc.poll() is not None:
                self.log_handle.flush()
                detail=self.log_path.read_text(encoding="utf-8",errors="replace")[-4000:]
                self.log_handle.close(); self.log_handle=None
                raise RuntimeError(f"Mihomo exited during startup (rc={self.proc.returncode}): {detail}")
            try:
                response=self.session.get(f"http://127.0.0.1:{self.controller_port}/proxies",timeout=1)
                response.raise_for_status()
            except requests.RequestException as exc:
                last_error=exc
                time.sleep(0.2)
                continue
            # 校验本实例确实加载了 TEST 组：防连到错误/残留实例，或临时 config 未被加载。
            # 这是此前 404 /proxies/TEST 的根因自检点——命中会带 mihomo.log 明确报错，而非静默 404。
            try:
                test_resp=self.session.get(f"http://127.0.0.1:{self.controller_port}/proxies/TEST",timeout=2)
                test_resp.raise_for_status()
            except requests.RequestException as exc:
                detail=""
                try:
                    detail=self.log_path.read_text(encoding="utf-8",errors="replace")[-4000:]
                except Exception:
                    pass
                raise RuntimeError(f"mihomo@{self.controller_port} responded but /proxies/TEST missing (wrong instance or config not loaded): {exc}; log={detail}")
            return names
        detail=""
        try:
            self.log_handle.flush()
            detail=self.log_path.read_text(encoding="utf-8",errors="replace")[-4000:]
        except Exception:
            pass
        raise RuntimeError(f"Mihomo controller did not become ready on {self.controller_port}: {last_error}; log={detail}")
    def choose(self,name):
        response=self.session.put(f"http://127.0.0.1:{self.controller_port}/proxies/TEST",json={"name":name},timeout=5); response.raise_for_status(); time.sleep(float(self.cfg["switch_wait_seconds"]))
    def request(self,url,parse_json=False):
        started=time.perf_counter(); proxy={"http":f"http://127.0.0.1:{self.proxy_port}","https":f"http://127.0.0.1:{self.proxy_port}"}
        try:
            session=requests.Session()
            response=session.get(url,headers={"User-Agent":UA},proxies=proxy,timeout=float(self.cfg["test_timeout_seconds"]),allow_redirects=True)
            text=response.text[:50000].lower(); challenge=any(marker.lower() in text for marker in self.cfg.get("challenge_markers",[])); ok=response.status_code in self.cfg.get("success_statuses",[200,204,301,302]) and not challenge
            data=None
            if parse_json and ok:
                try: data=response.json()
                except ValueError: pass
            return {"ok":ok,"status":response.status_code,"latency_ms":round((time.perf_counter()-started)*1000),"challenge":challenge,"data":data}
        except requests.RequestException as exc:
            return {"ok":False,"status":0,"latency_ms":round((time.perf_counter()-started)*1000),"error":str(exc)[:160],"challenge":False,"data":None}
    def test_nodes(self,nodes,checks):
        if not nodes:
            return []
        endpoint_workers=max(1,min(int(self.cfg.get("endpoint_workers",4)),4))
        endpoints=[
            ("gemini",checks["gemini_url"],False),
            ("google_play",checks["google_play_url"],False),
            ("google",checks["google_204_url"],False),
            ("ipinfo",checks["ipinfo_url"],True),
        ]
        try:
            names=self.start(nodes)
        except RuntimeError as exc:
            # Only Mihomo's explicit config-parse failure is treated as a node-data
            # problem. Other startup failures are systemic and must still fail loudly.
            error=str(exc)
            if "Parse config error:" not in error:
                self.stop()
                raise
            # A single malformed proxy can make Mihomo reject the entire batch.
            # Isolate the bad node(s) by splitting the batch instead of aborting the run.
            self.stop()
            if len(nodes)==1:
                error=str(exc)[-1000:]
                return [{
                    "node":nodes[0],
                    "gemini":False,
                    "google_play":False,
                    "google":{"ok":False,"status":0,"challenge":False,"error":error,"data":None},
                    "ipinfo":None,
                    "startup_error":error,
                }]
            mid=len(nodes)//2
            return self.test_nodes(nodes[:mid],checks)+self.test_nodes(nodes[mid:],checks)
        try:
            results=[]
            for idx,node in enumerate(nodes):
                self.choose(names[idx])
                with ThreadPoolExecutor(max_workers=endpoint_workers) as executor:
                    futures=[executor.submit(self.request,url,parse_json) for _,url,parse_json in endpoints]
                    checks_out=[future.result() for future in futures]
                item=dict(zip((name for name,_,_ in endpoints),checks_out))
                results.append({
                    "node":node,
                    "gemini":item["gemini"]["ok"],
                    "google_play":item["google_play"]["ok"],
                    "google":item["google"],
                    "ipinfo":item["ipinfo"].get("data") if item["ipinfo"]["ok"] else None,
                })
            return results
        finally:
            self.stop()
    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try: self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired: self.proc.kill()
            self.proc=None
        if self.log_handle is not None:
            try: self.log_handle.close()
            except Exception: pass
            self.log_handle=None

def test_nodes_parallel(binary,nodes,cfg,checks):
    workers=max(1,min(int(cfg.get("validation_workers",1)),len(nodes)))
    if workers<=1:
        return MihomoTester(binary,cfg).test_nodes(nodes,checks)
    batches=[nodes[i::workers] for i in range(workers) if nodes[i::workers]]
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures=[executor.submit(MihomoTester(binary,cfg,port_offset=idx*10).test_nodes,batch,checks) for idx,batch in enumerate(batches)]
        results=[]
        for future in futures:
            results.extend(future.result())
    return results

def probe_shenzhen_parallel(tasks,cfg):
    if not tasks:
        return {}
    workers=max(1,min(int(cfg.get("workers",1)),len(tasks)))
    def worker(item):
        fp,node=item
        return fp,GlobalpingShenzhenProbe(cfg).measure(node)
    if workers<=1:
        return dict(worker(task) for task in tasks)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return dict(executor.map(worker,tasks))

def unique_node_names(nodes):
    """Return copied nodes with deterministic unique Clash proxy names."""
    bases=[_clean_name(node.get("name"),f"{node.get('type','node')}-{node.get('server','')}") for node in nodes]
    counts={}
    for base in bases: counts[base]=counts.get(base,0)+1
    used=set(); out=[]
    for node,base in zip(nodes,bases):
        candidate=base
        if counts[base]>1:
            suffix=f" [{fingerprint(node)[:8]}]"
            candidate=f"{base[:100-len(suffix)]}{suffix}"
        if candidate in used:
            suffix=f" [{fingerprint(node)[:12]}]"
            candidate=f"{base[:100-len(suffix)]}{suffix}"
        counter=2
        while candidate in used:
            suffix=f" [{fingerprint(node)[:8]}-{counter}]"
            candidate=f"{base[:100-len(suffix)]}{suffix}"
            counter+=1
        copy=dict(node); copy["name"]=candidate
        used.add(candidate); out.append(copy)
    return out

COMPATIBLE_NETWORKS = {"tcp", "ws", "grpc"}

def build_outputs(nodes, output_rules):
    nodes=[dict(node) for node in nodes if node.get("network","tcp") in COMPATIBLE_NETWORKS]
    nodes=unique_node_names(nodes)
    names=[node["name"] for node in nodes]
    route_rules=LOCAL_IOT_DIRECT_RULES+WECHAT_DIRECT_RULES+XIAOMI_DIRECT_RULES+["GEOIP,CN,DIRECT","MATCH,PROXY"]
    dns_config={
        "enable":True,
        "ipv6":False,
        "use-hosts":True,
        "use-system-hosts":True,
        "enhanced-mode":"redir-host",
        "default-nameserver":["223.5.5.5","119.29.29.29"],
        "nameserver-policy":{
            "+.qq.com":["223.5.5.5","119.29.29.29"],
            "+.weixin.qq.com":["223.5.5.5","119.29.29.29"],
            "+.mi.com":["223.5.5.5","119.29.29.29"],
            "+.xiaomi.com":["223.5.5.5","119.29.29.29"],
            "+.miwifi.com":["223.5.5.5","119.29.29.29"],
            "+.miui.com":["223.5.5.5","119.29.29.29"],
            "+.wx.qq.com":["223.5.5.5","119.29.29.29"],
            "+.qpic.cn":["223.5.5.5","119.29.29.29"],
            "+.qlogo.cn":["223.5.5.5","119.29.29.29"],
            "+.gtimg.cn":["223.5.5.5","119.29.29.29"],
            "+.gtimg.com":["223.5.5.5","119.29.29.29"],
            "+.wechat.com":["223.5.5.5","119.29.29.29"],
            "+.tenpay.com":["223.5.5.5","119.29.29.29"],
            "+.wechatpay.cn":["223.5.5.5","119.29.29.29"],
            "+.tencent.com":["223.5.5.5","119.29.29.29"],
        },
        "nameserver":["223.5.5.5","119.29.29.29"],
        "fallback":["https://1.1.1.1/dns-query","tls://8.8.8.8"],
        "fallback-filter":{"geoip":True,"geoip-code":"CN"},
        "direct-nameserver":["223.5.5.5","119.29.29.29"],
        "direct-nameserver-follow-policy":True,
    }
    config={"mixed-port":7890,"allow-lan":True,"mode":"rule","dns":dns_config,"proxies":nodes,"proxy-groups":[{"name":"PROXY","type":"select","proxies":names+["DIRECT"]}],"rules":route_rules}
    clash_path=ROOT/output_rules["output"]["clash_file"]; clash_path.parent.mkdir(parents=True,exist_ok=True); clash_path.write_text(yaml.safe_dump(config,allow_unicode=True,sort_keys=False),encoding="utf-8")

def node_is_quality(meta, sticky_cfg):
    """Return True only if a node's Shenzhen probe metrics meet the 'keep' quality bar.

    The bar is intentionally tighter than the publish gate (shenzhen_probe.reject_*):
    a node may be publishable yet not 'excellent' enough to stay pinned as the primary.
    """
    if not isinstance(meta, dict): return False
    try:
        keep_ping=float(sticky_cfg.get("keep_ping_ms", 300))
        keep_loss=float(sticky_cfg.get("keep_loss_pct", 5.0))
    except (TypeError, ValueError):
        keep_ping, keep_loss = 300.0, 5.0
    ping=meta.get("shenzhen_ping_ms"); loss=meta.get("shenzhen_loss_pct")
    if ping is None or loss is None: return False
    return float(ping) < keep_ping and float(loss) <= keep_loss

def choose_sticky_primary(ranked, previous_profile_nodes, ranking_meta, sticky_cfg):
    """Decide which node should be the sticky primary for the published pool.

    Rule (per user requirement 2026-10-06):
      - If the currently-connected node (previous profile's first node) is still
        Shenzhen-quality, keep it as primary (stable connection across updates).
      - Else, pick the highest-ranked quality node from the pool.
      - If no node meets the quality bar, return None (caller keeps current
        ordering as best-effort rather than forcing a degraded pick).
    """
    prev0 = previous_profile_nodes[0] if previous_profile_nodes else None
    if prev0 is not None:
        fp0=fingerprint(prev0)
        if any(fingerprint(n)==fp0 for n in ranked) and node_is_quality(ranking_meta.get(fp0), sticky_cfg):
            return prev0
    for n in ranked:
        if node_is_quality(ranking_meta.get(fingerprint(n)), sticky_cfg):
            return n
    return None

# US datacenter/cloud org markers (substring match, lowercased org/asn).
# Used to exclude known hosting/cloud ASN when prioritizing US residential/ISP nodes.
US_DATACENTER_ORG_MARKERS = (
    "datacenter", "hosting", "cloud", "server", "colocation", " vps", "leaseweb",
    "ovh", "amazon", "google ", "microsoft", "linode", "vultr", "hetzner", "contabo",
    "digitalocean", "oracle", "alibaba", "tencent", "azure", "scaleway", "ionos",
    "m247", "datacamp", "nova ", "choopa", "as-hosting", "proxyprovider", "digital",
)

def _us_non_datacenter_bonus(meta):
    """1 if node is a US residential/ISP (non-datacenter) node, else 0.

    Top sorting priority so US优质非机房 nodes are preferred in the final pool
    (2026-10-06 专项加强美国优质节点). Relies on meta['country']=='US' and
    meta['org']/meta['asn'] not matching known datacenter/cloud markers.
    Missing country falls back to 0 (treated as non-prioritized).
    """
    country = str(meta.get("country") or "").upper()
    if country != "US":
        return 0
    org = str(meta.get("org") or meta.get("asn") or "").lower()
    if any(k in org for k in US_DATACENTER_ORG_MARKERS):
        return 0
    return 1


def rank_candidates(nodes, limit=20, metadata=None, max_per_server=2, max_per_org=3, min_final_score=0):
    """Rank verified nodes by US-residential priority, score, and diversity.

    Sorting priority (higher first unless noted):
      1. us_non_datacenter (1 if US residential/ISP, else 0)   # 2026-10-06
      2. above_min_final_score (1 if score >= min_final_score) # 2026-10-06 软地板
      3. total_score (desc)
      4. shenzhen_ping_ms (asc)
      5. shenzhen_loss_pct (asc)
      6. stability (desc)
      7. lifespan (desc)
      8. fingerprint (asc, deterministic tiebreak)

    Diversity caps applied greedily in sorted order:
      - duplicate fingerprint -> keep only the highest-scored node
      - same server -> keep at most `max_per_server`
      - same org/ASN -> keep at most `max_per_org`

    `metadata` is a fingerprint -> dict lookup (score, shenzhen_ping_ms,
    shenzhen_loss_pct, stability, lifespan, org, asn, country). Missing fields
    fall back safely, so ranking never raises. `min_final_score` (from
    config nodes.min_final_score) is a soft floor: nodes below it sort after
    nodes at/above it, so the final pool prefers high-score nodes.
    """
    metadata=metadata or {}
    try: limit=max(1,int(limit))
    except (TypeError,ValueError): limit=20
    try: max_per_server=max(1,int(max_per_server))
    except (TypeError,ValueError): max_per_server=2
    try: max_per_org=max(1,int(max_per_org))
    except (TypeError,ValueError): max_per_org=3
    try: min_final_score=max(0,float(min_final_score))
    except (TypeError,ValueError): min_final_score=0.0
    enriched=[]
    for node in nodes:
        fp=fingerprint(node); meta=metadata.get(fp,{})
        score=_safe_float(meta.get("score"),0.0)
        enriched.append({
            "node":node,"fp":fp,
            "score":score,
            "ping":_safe_float(meta.get("shenzhen_ping_ms"),float("inf")),
            "loss":_safe_float(meta.get("shenzhen_loss_pct"),float("inf")),
            "stability":_safe_float(meta.get("stability"),0.0),
            "lifespan":_safe_float(meta.get("lifespan"),0.0),
            "us_nd":_us_non_datacenter_bonus(meta),
            "above_floor":1 if score>=min_final_score else 0,
            "server":str(node.get("server") or "").strip().lower(),
            "org":str(meta.get("org") or meta.get("asn") or "").strip().lower(),
        })
    enriched.sort(key=lambda e:(-e["us_nd"],-e["above_floor"],-e["score"],e["ping"],e["loss"],-e["stability"],-e["lifespan"],e["fp"]))
    seen_fp=set(); server_count={}; org_count={}; picked=[]
    for e in enriched:
        if e["fp"] in seen_fp: continue
        if e["server"] and server_count.get(e["server"],0)>=max_per_server: continue
        if e["org"] and org_count.get(e["org"],0)>=max_per_org: continue
        seen_fp.add(e["fp"])
        if e["server"]: server_count[e["server"]]=server_count.get(e["server"],0)+1
        if e["org"]: org_count[e["org"]]=org_count.get(e["org"],0)+1
        picked.append(e["node"])
        if len(picked)>=limit: break
    return picked

def candidate_gate_passes(item, gate, clean, min_clean):
    """Evaluate the configured candidate gate against endpoint reachability and cleanliness."""
    gemini=bool(item.get("gemini"))
    google_play=bool(item.get("google_play"))
    google=item.get("google") or {}
    google_ok=bool(google.get("ok"))
    clean_ok=float(clean) >= float(min_clean)
    gate=str(gate or "gemini_or_play").lower()
    if gate=="reachable":
        return bool((gemini or google_play or google_ok) and clean_ok)
    if gate=="gemini_or_play":
        return bool((gemini or google_play) and clean_ok)
    if gate=="gemini_and_play":
        return bool(gemini and google_play and clean_ok)
    return False

def cache_fresh(source, min_stars, cutoff_date):
    """Return True if a cached source record may enter this run's candidate pool.

    Freshness requires a known star count at/above the floor AND a pushed_at
    timestamp on/after the configured recency cutoff. Sources missing pushed_at
    cannot prove freshness and are treated as stale (never auto-qualified). This is
    the single source of truth for the F3 expiry gate and is unit-tested.
    """
    if not isinstance(source, dict) or not source.get("url"):
        return False
    try:
        if int(source.get("stars", 0) or 0) < min_stars:
            return False
    except (TypeError, ValueError):
        return False
    pa = source.get("pushed_at")
    if not pa:
        return False
    try:
        pa_dt = datetime.fromisoformat(pa.replace("Z", "+00:00"))
    except ValueError:
        return False
    return pa_dt.date() >= cutoff_date

def load_source_history(path):
    """Load the persistent historical source audit record (url -> metadata)."""
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def write_source_history(path, history):
    """Persist the historical source audit record. Never truncates to empty on a
    failed run — only merges; expired entries stay recorded but do NOT grant usage."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(history, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

def admission_reason(item, rules, clean):
    """Return (admitted, reason) using every independent hard gate.

    A node reaches the final pool only if it clears, in order:
      1. candidate gate  — endpoint reachability + cleanliness
      2. real_proxy_ok   — mihomo actually forwarded live traffic
      3. latency gate    — proxy_latency_ms present AND <= max_proxy_latency_ms
      4. compatibility   — supported transport network
    Shenzhen TCP ping is intentionally NOT here: it only proved a probe-host port
    was open, never that user traffic forwards. Missing/invalid latency is rejected
    (never coerced to 0 ms).
    """
    node = item["node"]
    gate = str(rules["nodes"].get("candidate_gate", "gemini_or_play")).lower()
    min_clean = float(rules["nodes"].get("min_clean_score", 0))
    if not candidate_gate_passes(item, gate, clean, min_clean):
        return False, "candidate_gate_fail"
    if not (item["gemini"] or item["google_play"] or (item.get("google") or {}).get("ok")):
        return False, "real_proxy_fail"
    max_lat = int(rules["nodes"].get("max_proxy_latency_ms", 0) or 0)
    lat = (item.get("google") or {}).get("latency_ms")
    if lat is None:
        return False, "latency_missing"
    if max_lat and lat > max_lat:
        return False, "latency_exceed_%dms" % max_lat
    if node.get("network", "tcp") not in COMPATIBLE_NETWORKS:
        return False, "incompatible_network"
    return True, "ok"

def decide_publish(selected_len, nodes_rules):
    """True only when the qualified pool meets the minimum publish floor.

    Below the floor the last published profile must be preserved — never an empty
    pool, a sub-floor pool, or a failed build result."""
    return selected_len >= int(nodes_rules.get("min_final_nodes", 1))

def run():
    rules=load_rules()
    source_path=ROOT/rules["output"]["source_file"]
    history_path=ROOT/rules["output"]["history_file"]
    report_path=ROOT/rules["output"]["report_file"]
    source_history_path=ROOT/rules["output"].get("source_history_file","data/source_history.json")
    # GitHubDiscovery now returns (sources, discovery_meta) so a temporary API
    # failure can be told apart from a genuine zero-result search.
    live, discovery_meta = GitHubDiscovery(os.getenv("GITHUB_TOKEN"), rules["sources"]).discover()
    cached=[]
    if source_path.is_file():
        try:
            cached=json.loads(source_path.read_text(encoding="utf-8"))
            if not isinstance(cached,list): cached=[]
        except Exception: cached=[]
    # Freshness gate (F3, 2026-10-20): cached sources must prove recency via
    # pushed_at >= recent_days cutoff; expired sources are NEVER re-admitted just
    # because live search came back empty. cache_fresh() is the single source of
    # truth and is unit-tested.
    seen={s.get("url") for s in live if isinstance(s,dict)}
    sources=list(live)
    min_stars=int(rules["sources"].get("min_stars",30))
    recent_days=int(rules["sources"].get("recent_days",14))
    cutoff_date=(datetime.now(timezone.utc)-timedelta(days=recent_days)).date()
    for s in cached:
        if s.get("url") in seen:
            continue
        if not cache_fresh(s, min_stars, cutoff_date):
            continue
        seen.add(s["url"]); sources.append(s)
    # Bound the persistent source pool by quality, not live-vs-cached ordering.
    max_sources=int(rules["sources"].get("max_sources",120))
    if len(sources)>max_sources:
        def source_quality(row):
            return (
                int(row.get("stars", 0) or 0),
                int(row.get("nodes", 0) or 0),
                str(row.get("pushed_at") or ""),
                str(row.get("url") or ""),
            )
        sources=sorted(sources,key=source_quality,reverse=True)[:max_sources]
    # Persistent historical source record (audit trail). Never overwritten to empty
    # by a failed/empty run — only merged. Expired entries stay recorded but do NOT
    # grant usage; only cache_fresh() decides what enters the candidate pool.
    history_sources=load_source_history(source_history_path)
    for s in sources:
        url=s.get("url")
        if not url: continue
        prev=history_sources.get(url,{})
        history_sources[url]={
            "url":url,"repo":s.get("repo"),"stars":s.get("stars"),"nodes":s.get("nodes"),
            "pushed_at":s.get("pushed_at"),
            "last_seen":datetime.now(timezone.utc).isoformat(),
            "last_error":prev.get("last_error"),
        }
    # Mark discovery failures in the historical record without destroying prior data.
    if not discovery_meta.get("search_succeeded"):
        err=discovery_meta.get("search_error") or discovery_meta.get("failure_type")
        for s in history_sources.values():
            s["last_error"]=err
    write_source_history(source_history_path, history_sources)
    source_path.parent.mkdir(parents=True,exist_ok=True)
    if discovery_meta.get("search_succeeded"):
        # Definitive fresh result (may legitimately be empty); refresh the fresh cache.
        source_path.write_text(json.dumps(sources,ensure_ascii=False,indent=2),encoding="utf-8")
    else:
        # A failed search must NOT blank the only usable source list. The audit
        # trail is safe in source_history.json; keep the previous fresh cache.
        print("source_discovery: search failed (%s); preserving previous %s" % (discovery_meta.get("failure_type"), source_path))
    nodes_by_fp={}; session=requests.Session()
    for source in sources:
        try:
            response=session.get(source["url"],timeout=20,headers={"User-Agent":UA}); response.raise_for_status()
            for node in parse_subscription(response.text):
                if node.get("type") in rules["nodes"]["allowed_types"] and node.get("server") and node.get("port") and resolved_server_is_safe(node["server"]) and mihomo_node_is_testable(node): nodes_by_fp[fingerprint(node)]=node
        except requests.RequestException: continue
    # ★ 并入手维护优质节点源（2026-10-04 接入）：sub_local.txt 是用户精选的 [BL] 节点池，
    #   之前完全不在发现管线里，导致「唯一活节点不是 git 收集的」。这里把它解码后并入候选池，
    #   走和免费源完全相同的 gemini/play/深圳 实测闸门——活的才发布，过期的一样被筛掉。
    curated_file=rules.get("curated_nodes_file")
    curated_fps=set()
    if curated_file:
        cf=ROOT/curated_file
        if cf.is_file():
            try:
                raw=cf.read_text(encoding="utf-8").strip()
                # base64（允许换行）或明文订阅文本都兼容
                decoded=None
                try: decoded=base64.b64decode(raw.replace("\n","").strip()+"="*(-len(raw.replace("\n","").strip())%4)).decode("utf-8","ignore")
                except Exception: decoded=None
                text=decoded if decoded else raw
                cnt=0
                for node in parse_subscription(text):
                    if node.get("type") in rules["nodes"]["allowed_types"] and node.get("server") and node.get("port") and resolved_server_is_safe(node["server"]):
                        if not mihomo_node_is_testable(node):
                            continue
                        fp=fingerprint(node); nodes_by_fp.setdefault(fp,node); curated_fps.add(fp); cnt+=1
                print("curated_source: loaded %d nodes from %s" % (cnt, curated_file))
            except Exception as e:
                print("curated_source: skip %s (%s)" % (curated_file, type(e).__name__))
    # ★ 直接订阅 URL 通道（2026-10-04 新增）：绕过 GitHub 搜索，直接拉取已知
    #   免费订阅端点（clash/v2ray base64 / yaml），并入同一候选池走相同实测闸门。
    direct_urls=rules.get("direct_urls") or []
    if isinstance(direct_urls,list) and direct_urls:
        try:
            dsession=requests.Session()
            for url in direct_urls:
                try:
                    resp=dsession.get(url,timeout=20,headers={"User-Agent":UA}); resp.raise_for_status()
                    cnt=0
                    for node in parse_subscription(resp.text):
                        if node.get("type") in rules["nodes"]["allowed_types"] and node.get("server") and node.get("port") and resolved_server_is_safe(node["server"]):
                            if not mihomo_node_is_testable(node):
                                continue
                            nodes_by_fp.setdefault(fingerprint(node),node); cnt+=1
                    print("direct_url: loaded %d nodes from %s" % (cnt, url))
                except requests.RequestException as e:
                    print("direct_url: skip %s (%s)" % (url, type(e).__name__))
        except Exception as e:
            print("direct_url: fatal %s" % type(e).__name__)

    # ★ curated 优质节点优先（2026-10-04 修复回退）：用户手维护的 [BL] 节点是能通 Gemini 的
    #   核心资产，必须始终排在测试集最前、绝不被 max_test_nodes 截断丢弃。否则会出现
    #   「免费 204 节点挤掉唯一通 Gemini 的 [BL] 节点」的净亏（实测发生过：Gemini 从 200 掉到 000）。
    #   排序：curated 优先，其余按发现顺序；再截断到上限。
    retention_cfg=rules.get("retention",{}) or {}
    previous_profile_nodes=load_previous_published_nodes(ROOT / "live_clash.yaml", retention_cfg.get("max_previous_nodes",5) if retention_cfg.get("enabled",True) else 0)
    previous_fps={fingerprint(n) for n in previous_profile_nodes}
    # Previously published nodes are re-tested first, but never bypass current gates.
    cap=int(rules["nodes"]["max_test_nodes"])
    ordered=previous_profile_nodes[:]
    ordered.extend([n for fp,n in nodes_by_fp.items() if fp in curated_fps and fingerprint(n) not in previous_fps])
    ordered.extend([n for fp,n in nodes_by_fp.items() if fp not in curated_fps and fingerprint(n) not in previous_fps])
    dedup_ordered=[]; ordered_seen=set()
    for node in ordered:
        fp=fingerprint(node)
        if fp in ordered_seen: continue
        ordered_seen.add(fp); dedup_ordered.append(node)
    nodes=dedup_ordered[:cap]
    binary=shutil.which("mihomo") or shutil.which("clash")
    if not nodes: raise RuntimeError("No valid nodes discovered; published outputs were preserved.")
    if not binary: raise RuntimeError("mihomo binary not found")
    checks=rules["checks"]; tester_cfg={**rules["nodes"],"challenge_markers":checks["challenge_markers"],"success_statuses":checks["success_statuses"]}; history=load_history(history_path); selected=[]
    report={"generated_at":datetime.now(timezone.utc).isoformat(),"sources":len(sources),"nodes_discovered":len(nodes),"previous_profile_candidates":len(previous_profile_nodes),"results":[],"source_discovery":discovery_meta,"source_history_total":len(history_sources),"max_proxy_latency_ms":int(rules["nodes"].get("max_proxy_latency_ms",0) or 0)}
    report_lookup={}
    candidate_records=[]

    for item in test_nodes_parallel(binary,nodes,tester_cfg,checks):
        node,fp=item["node"],fingerprint(item["node"])
        row=history.get(fp,{"first_seen":date.today().isoformat(),"last_seen":date.today().isoformat(),"seen_count":0,"pass_count":0,"gemini_pass_count":0,"play_pass_count":0})
        life=lifespan_days(row); ipinfo_data=item.get("ipinfo") or {}; clean=clean_score(item.get("ipinfo"),item["google"]); stability=min(1.0,row.get("pass_count",0)/max(1,row.get("seen_count",1)))
        score=total_score(gemini=item["gemini"],google_play=item["google_play"],google=item["google"],clean=clean,lifespan=life,stability=stability)
        row=update_history(history,fp,{"score":score,"gemini":item["gemini"],"google_play":item["google_play"]},score_threshold=rules["nodes"].get("score_threshold",70))
        # ★ 2026-10-04 策略放宽（池子做大的核心）：
        #   candidate_gate 控制「候选」门槛，分数(score)只用于排序/多样性，不再卡入选。
        #   - reachable（推荐）：代理能通外网即可（google204/gemini/play 任一可达）。
        #     新挖到的免费节点无历史(lifespan/stability=0)，硬卡 70 分会把仅过单探针的活节点全刷掉，
        #     导致 selected=0 永远不发布。改「通外网即候选」才能保证池子真正长大。
        #   - gemini_or_play：gemini 或 play 任一通过（仍卡 70 分，留作保守档）。
        #   - gemini_and_play：原双过严格档（保留向后兼容）。
        asn_obj=ipinfo_data.get("asn"); asn_value=asn_obj.get("asn") if isinstance(asn_obj,dict) else asn_obj
        # ★ L2 (2026-10-18) + 延迟硬门槛 (2026-10-20):
        #   最终入选 = 候选门槛 AND 真实代理转发(real_proxy_ok) AND 延迟上限(max_proxy_latency_ms)
        #   AND 网络兼容。四者独立，缺一不可。Shenzhen TCP ping 仅作展示/粘性参考，
        #   不再是入选路径（它只证明探针主机到端口通，证不了用户侧真实转发）。
        #   延迟缺失/无效按失败处理，不得当 0ms 自动通过（见 admission_reason）。
        real_proxy_ok=bool(item["gemini"] or item["google_play"] or (item.get("google") or {}).get("ok"))
        proxy_latency_ms=(item.get("google") or {}).get("latency_ms")
        admitted, reject_reason = admission_reason(item, rules, clean)
        entry={"fingerprint":fp,"name":node["name"],"score":score,"gemini":item["gemini"],"google_play":item["google_play"],"clean":clean,"lifespan_days":lifespan_days(row),"shenzhen_ping_ms":None,"shenzhen_loss_pct":None,"shenzhen_status":"not-tested","real_proxy_ok":real_proxy_ok,"proxy_latency_ms":proxy_latency_ms,"admitted":admitted,"reject_reason":(None if admitted else reject_reason),"org":ipinfo_data.get("org"),"asn":asn_value,"country":ipinfo_data.get("country")}
        report["results"].append(entry); report_lookup[fp]=entry

        shenzhen_cfg=rules.get("shenzhen_probe",{})
        cached=cached_shenzhen_result(row,shenzhen_cfg) if shenzhen_cfg.get("enabled",False) else None
        candidate_records.append({"fp":fp,"node":node,"result":cached})
        if admitted:
            selected.append(node)

    shenzhen_cfg=rules.get("shenzhen_probe",{})
    pending=[(rec["fp"],rec["node"]) for rec in candidate_records if rec["result"] is None]
    measured=probe_shenzhen_parallel(pending,shenzhen_cfg) if shenzhen_cfg.get("enabled",False) else {}
    for rec in candidate_records:
        fp,node,cached=rec["fp"],rec["node"],rec["result"]
        row=history.get(fp,{})
        result=cached if cached is not None else measured.get(fp,{"ok":False,"status":"not-measured"})
        if cached is None:
            save_shenzhen_history(row,result)
        entry=report_lookup[fp]
        entry["shenzhen_ping_ms"]=result.get("avg_ms") if result.get("ok") else None
        entry["shenzhen_loss_pct"]=result.get("loss_pct") if result.get("ok") else None
        entry["shenzhen_status"]=result.get("status","unknown")

    # Shenzhen is a hard quality gate. Never backfill rejected/unmeasured nodes into the final pool.
    history_path.write_text(json.dumps(history,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
    before=len(selected); selected=[node for node in selected if node.get("network","tcp") in COMPATIBLE_NETWORKS]; report["incompatible_filtered"]=before-len(selected)
    if not decide_publish(len(selected), rules["nodes"]):
        report["published"]=False; report["selected"]=len(selected); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); print(f"publish_guard: only {len(selected)} qualified nodes (< min_final_nodes {rules['nodes'].get('min_final_nodes')}); last published config preserved."); return
    ranking_meta={}
    for node in selected:
        fp=fingerprint(node); entry=report_lookup.get(fp,{}); row=history.get(fp,{})
        # Keep real-proxy latency and Shenzhen latency as distinct fields so the
        # report never conflates the two (previously eff_ping was mislabelled as
        # shenzhen_ping_ms in this dict).
        ranking_meta[fp]={
            "score":entry.get("score",0),
            "shenzhen_ping_ms":entry.get("shenzhen_ping_ms"),
            "proxy_latency_ms":entry.get("proxy_latency_ms"),
            "real_proxy_ok":entry.get("real_proxy_ok",False),
            "shenzhen_loss_pct":entry.get("shenzhen_loss_pct"),
            "stability":min(1.0,row.get("pass_count",0)/max(1,row.get("seen_count",1))),
            "lifespan":lifespan_days(row),"org":entry.get("org"),"asn":entry.get("asn"),"country":entry.get("country"),
        }
    max_final=int(rules["nodes"].get("max_final_nodes",20))
    # Reserve slots for previously published nodes that still pass all current gates.
    selected_fps={fingerprint(x) for x in selected}
    # ★ L4 (2026-10-18): 保留节点必须在本轮真实代理判活中通过，不得沿用旧快照。
    #   上一轮已发布的节点若本轮 real_proxy_ok=False（协议已死），一律不保留，
    #   避免死亡螺旋：同一批濒死节点被反复重发、永远等不到新鲜替补。
    retained_previous=[n for n in previous_profile_nodes
                       if fingerprint(n) in selected_fps
                       and report_lookup.get(fingerprint(n), {}).get("real_proxy_ok", False)][:min(len(previous_profile_nodes),max_final)]
    retained_fps={fingerprint(n) for n in retained_previous}
    fresh_selected=[n for n in selected if fingerprint(n) not in retained_fps]
    retained_previous_ranked=retained_previous[:max_final]
    fresh_ranked=rank_candidates(fresh_selected,limit=max(0,max_final-len(retained_previous_ranked)),metadata=ranking_meta,max_per_server=int(rules["nodes"].get("max_per_server",2)),max_per_org=int(rules["nodes"].get("max_per_org",3)),min_final_score=int(rules["nodes"].get("min_final_score",0)))
    ranked=retained_previous_ranked+fresh_ranked
    # ★ 粘性优质节点（2026-10-06）：订阅更新时保持当前优秀节点为首选，
    #   仅当其深圳 PING>=keep_ping_ms 或掉包率>keep_loss_pct 时才让位给新优质节点。
    sticky_cfg=rules.get("sticky", {}) or {}
    if sticky_cfg.get("enabled", True):
        kept=choose_sticky_primary(ranked, previous_profile_nodes, ranking_meta, sticky_cfg)
        if kept is not None:
            fp_kept=fingerprint(kept)
            ranked=[kept]+[n for n in ranked if fingerprint(n)!=fp_kept]
            print("sticky: kept primary node %r (Shenzhen-quality)" % kept.get("name"))
        else:
            print("sticky: no Shenzhen-quality node available; keeping current pool order")
    report["ranking"]=[]
    for i,node in enumerate(ranked,1):
        entry=report_lookup.get(fingerprint(node),{})
        report["ranking"].append({
            "rank":i,"score":entry.get("score"),
            "shenzhen_ping_ms":entry.get("shenzhen_ping_ms"),
            "proxy_latency_ms":entry.get("proxy_latency_ms"),
            "real_proxy_ok":entry.get("real_proxy_ok",False),
            "reject_reason":entry.get("reject_reason"),
            "shenzhen_loss_pct":entry.get("shenzhen_loss_pct"),
            "server":node.get("server"),"type":node.get("type"),
        })
    print("Top20 Ranking:"); print("Rank | Score | ShenzhenPing | ProxyLatency | RealProxy | RejectReason | Server | Type")
    for r in report["ranking"]:
        sp=r["shenzhen_ping_ms"] if r["shenzhen_ping_ms"] is not None else "-"
        pl=r["proxy_latency_ms"] if r["proxy_latency_ms"] is not None else "-"
        print(f"{r['rank']:>4} | {r['score']:>5} | {str(sp):>12} | {str(pl):>13} | {str(r['real_proxy_ok']):>9} | {str(r['reject_reason']):>14} | {r['server']} | {r['type']}")
    if not decide_publish(len(ranked), rules["nodes"]):
        report["published"]=False; report["selected"]=len(ranked); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); print(f"publish_guard: only {len(ranked)} nodes after diversity ranking (< min_final_nodes {rules['nodes'].get('min_final_nodes')}); last published config preserved."); return
    build_outputs(ranked,rules); report["published"]=True; report["selected"]=len(ranked); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")

if __name__=="__main__": run()
