from __future__ import annotations
import base64, hashlib, ipaddress, json, os, re, shutil, socket, subprocess, tempfile, time
from concurrent.futures import ThreadPoolExecutor
import functools
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse
import requests, yaml, statistics

SUPPORTED = {"vmess","vless","trojan","ss"}
ALLOWED_FIELDS = {
    "vmess":{"type","name","server","port","uuid","alterId","cipher","tls","servername","network","ws-opts","udp"},
    "vless":{"type","name","server","port","uuid","tls","servername","flow","network","ws-opts","grpc-opts","reality-opts","client-fingerprint","encryption","udp"},
    "trojan":{"type","name","server","port","password","tls","servername","network","ws-opts","udp"},
    "ss":{"type","name","server","port","cipher","password","udp"},
}
URI_RE = re.compile(r"(?:(?:vmess|vless|trojan|ss)://[^\s\"'<>]+)")
UA="Fine-Clash/1.0"
CANDIDATE_NAMES=("sub","subscribe","subscription","clash","v2ray","proxy","nodes","node","free","config","export","pool","link","links","readme")
CANDIDATE_BASENAMES={"sub","subscribe","subscription","clash","v2ray","nodes","node","free"}
EXTENSIONS=(".yaml",".yml",".txt",".conf",".base64",".list",".lst",".json",".json5",".md")

def is_candidate_source_path(path):
    """Reject cached paths that are ordinary project files, not subscription feeds."""
    low=str(path or "").split("?",1)[0].lower()
    basename=low.rsplit("/",1)[-1]
    if not basename:
        return False
    if basename in CANDIDATE_BASENAMES:
        return True
    return basename.endswith(EXTENSIONS) and any(key in basename for key in CANDIDATE_NAMES)

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

# WPS Office / Kingsoft Docs direct routes. Explicitly cover service and CDN domains.
WPS_DIRECT_RULES = [
    "DOMAIN-SUFFIX,wps.cn,DIRECT",
    "DOMAIN-SUFFIX,wps.com,DIRECT",
    "DOMAIN-SUFFIX,wps365.com,DIRECT",
    "DOMAIN-SUFFIX,kdocs.cn,DIRECT",
    "DOMAIN-SUFFIX,wpscdn.cn,DIRECT",
    "DOMAIN-SUFFIX,wpscdn.com,DIRECT",
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
    try:
        uri=uri.strip()
        return _parse_vmess(uri) if uri.lower().startswith("vmess://") else _parse_standard(uri)
    except (ValueError,TypeError,UnicodeError):
        # One malformed public URI must not abort discovery of every source.
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
    """Load only proxies explicitly referenced by the previous Fine group for re-testing."""
    try:
        limit=max(0,int(max_nodes))
    except (TypeError,ValueError):
        limit=5
    if limit<=0 or not path.is_file():
        return []
    try:
        text=path.read_text(encoding="utf-8")
        parsed=parse_subscription(text)
        raw=yaml.safe_load(text) or {}
    except (OSError,yaml.YAMLError):
        return []
    fine_names=[]
    for group in raw.get("proxy-groups",[]) if isinstance(raw,dict) else []:
        if isinstance(group,dict) and group.get("name")=="Fine":
            fine_names=[name for name in (group.get("proxies") or []) if isinstance(name,str)]
            break
    if fine_names:
        by_name={node.get("name"):node for node in parsed if isinstance(node,dict)}
        nodes=[by_name[name] for name in fine_names if name in by_name]
    else:
        return []
    out=[]; seen=set()
    for node in nodes:
        fp=fingerprint(node)
        if fp in seen or node.get("type") not in SUPPORTED:
            continue
        server=node.get("server")
        if not server or not resolved_server_is_safe(server) or not mihomo_node_is_testable(node):
            continue
        seen.add(fp)
        out.append(node)
        if len(out)>=limit:
            break
    return out


def load_stable_pool_nodes(path, max_nodes=20):
    """Load the last successfully published Fine pool as continuity candidates."""
    try:
        limit=max(0,int(max_nodes))
        if limit==0 or not path.is_file():
            return []
        raw=yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw,dict) or not isinstance(raw.get("proxies"),list):
            return []
        out=[]; seen=set()
        for node in raw["proxies"]:
            if not isinstance(node,dict) or node.get("type") not in SUPPORTED:
                continue
            if not node.get("server") or not node.get("port"):
                continue
            if not resolved_server_is_safe(node["server"]) or not mihomo_node_is_testable(node):
                continue
            fp=fingerprint(node)
            if fp in seen:
                continue
            seen.add(fp); out.append(node)
            if len(out)>=limit:
                break
        return out
    except (OSError,ValueError,TypeError,yaml.YAMLError):
        return []


def save_stable_pool(path, nodes, max_nodes=20):
    """Update the stable reserve only after the full candidate pool passes every gate."""
    try:
        limit=max(1,int(max_nodes))
    except (TypeError,ValueError):
        limit=20
    clean=unique_node_names([dict(node) for node in (nodes or []) if isinstance(node,dict)])[:limit]
    if not clean:
        raise ValueError("refusing to overwrite the stable pool with an empty list")
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(yaml.safe_dump({"proxies":clean},allow_unicode=True,sort_keys=False),encoding="utf-8")
    return len(clean)


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
        """Retry transient probe-service errors; never convert unknown results to success."""
        retries=max(0,_safe_int(self.cfg.get("retries",1),1))
        retryable={"probe-unavailable","timeout","no-stats","no-measurement-id","error","invalid-response"}
        result={"ok":False,"status":"not-measured"}
        for attempt in range(retries+1):
            result=self._measure_once(node)
            result["attempts"]=attempt+1
            if result.get("ok") or result.get("status") not in retryable or attempt>=retries:
                return result
            time.sleep(min(2.0,0.5*(attempt+1)))
        return result

    def _measure_once(self, node):
        city=str(self.cfg.get("city","Shenzhen"))
        port=_safe_int(node.get("port"))
        target=str(node.get("server") or "").strip()
        if not target or not port:
            return {"ok":False,"status":"invalid-target"}
        probe_count=max(1,_safe_int(self.cfg.get("probe_count",2),2))
        payload={
            "target":target,
            "type":"ping",
            "locations":[{"city":city,"limit":probe_count}],
            "measurementOptions":{
                "protocol":str(self.cfg.get("protocol","TCP")).upper(),
                "port":port,
                "packets":int(self.cfg.get("packets",4)),
            },
        }
        try:
            created=self.session.post(self.base_url,json=payload,timeout=15)
            created.raise_for_status()
            body=created.json()
            measurement_id=body.get("id")
            if not measurement_id:
                return {"ok":False,"status":"no-measurement-id"}
            deadline=time.monotonic()+float(self.cfg.get("max_wait_seconds",20))
            poll=max(0.25,float(self.cfg.get("poll_interval_seconds",1)))
            result=None
            while time.monotonic()<deadline:
                time.sleep(poll)
                response=self.session.get(f"{self.base_url}/{measurement_id}",timeout=15)
                response.raise_for_status()
                result=response.json()
                if result.get("status")!="in-progress":
                    break
            if not result or result.get("status")=="in-progress":
                return {"ok":False,"status":"timeout","measurement_id":measurement_id}

            observations=[]; cities=[]
            for entry in result.get("results",[]):
                data=entry.get("result") or {}
                stats=data.get("stats") or {}
                avg=stats.get("avg")
                if avg is None:
                    avg=stats.get("average")
                loss=stats.get("loss")
                if avg is None or loss is None:
                    continue
                try:
                    avg=float(avg); loss=float(loss)
                except (TypeError,ValueError):
                    continue
                if avg<0 or not 0<=loss<=100:
                    continue
                observations.append((avg,loss))
                probe_city=(entry.get("probe") or {}).get("city")
                if probe_city:
                    cities.append(str(probe_city))
            minimum=max(1,_safe_int(self.cfg.get("min_successful_probes",1),1))
            if len(observations)<minimum:
                return {"ok":False,"status":"no-stats","measurement_id":measurement_id,
                        "probe_observations":len(observations)}
            return {
                "ok":True,
                "status":"ok" if len(observations)>=probe_count else "partial-ok",
                "avg_ms":round(statistics.median(value[0] for value in observations),1),
                "loss_pct":max(value[1] for value in observations),
                "probe_city":",".join(sorted(set(cities))) or city,
                "probe_observations":len(observations),
                "measurement_id":measurement_id,
            }
        except requests.RequestException as exc:
            response=getattr(exc,"response",None)
            code=getattr(response,"status_code",None)
            status="probe-unavailable" if code==429 or code is None or code>=500 else "request-rejected"
            return {"ok":False,"status":status,"http_status":code,"error":str(exc)[:180]}
        except (ValueError,TypeError,KeyError) as exc:
            return {"ok":False,"status":"invalid-response","error":str(exc)[:180]}


def cached_shenzhen_result(row, cfg):
    checked=row.get("shenzhen_checked_at")
    avg=row.get("shenzhen_ping_ms")
    loss=row.get("shenzhen_loss_pct")
    if not checked or avg is None or loss is None: return None
    try:
        checked_at=datetime.fromisoformat(checked)
        if checked_at.tzinfo is None:
            checked_at=checked_at.replace(tzinfo=timezone.utc)
        age=datetime.now(timezone.utc)-checked_at
        if timedelta(0)<=age<=timedelta(days=float(cfg.get("cache_days",1))):
            return {"ok":True,"status":"cached","avg_ms":float(avg),"loss_pct":float(loss),
                    "probe_city":row.get("shenzhen_probe_city"),
                    "probe_observations":_safe_int(row.get("shenzhen_probe_observations"),1)}
    except (ValueError,TypeError):
        pass
    return None


def shenzhen_passes(result, cfg):
    """An unknown probe result is never equivalent to a passing measurement."""
    if not result.get("ok"):
        return False
    try:
        avg=float(result["avg_ms"])
        loss=float(result["loss_pct"])
        observations=_safe_int(result.get("probe_observations"),1)
        minimum=max(1,_safe_int(cfg.get("min_successful_probes",1),1))
        return observations>=minimum and avg<=float(cfg.get("reject_above_ms",400)) and loss<=float(cfg.get("reject_loss_pct",100))
    except (KeyError,TypeError,ValueError):
        return False


def record_shenzhen_source_metrics(source_stats, result, cfg, *, cached=False):
    """Track fresh Shenzhen measurements separately from cached quality evidence.

    Reusing a cached passing measurement may keep a node eligible during its cache
    window, but it is not a new independent probe observation and must not inflate
    cumulative source-quality success counts.
    """
    if source_stats is None:
        return
    if cached:
        source_stats["shenzhen_cache_hits"] = _safe_int(source_stats.get("shenzhen_cache_hits"), 0) + 1
        return
    if result.get("ok"):
        source_stats["shenzhen_decided"] += 1
        if shenzhen_passes(result, cfg):
            source_stats["shenzhen_passed"] += 1
        else:
            source_stats["shenzhen_failed"] += 1
    else:
        source_stats["probe_unknown"] += 1


def save_shenzhen_history(row, result):
    """Record failures without deleting the last successful Shenzhen measurement."""
    now=datetime.now(timezone.utc).isoformat()
    row["shenzhen_last_attempt_at"]=now
    row["shenzhen_last_attempt_status"]=result.get("status","unknown")
    row["shenzhen_last_attempts"]=_safe_int(result.get("attempts"),1)
    if result.get("ok") and result.get("avg_ms") is not None and result.get("loss_pct") is not None:
        row["shenzhen_checked_at"]=now
        row["shenzhen_ping_ms"]=float(result["avg_ms"])
        row["shenzhen_loss_pct"]=float(result["loss_pct"])
        row["shenzhen_status"]=result.get("status","ok")
        row["shenzhen_probe_city"]=result.get("probe_city")
        row["shenzhen_probe_observations"]=_safe_int(result.get("probe_observations"),1)
        row.pop("shenzhen_last_error",None)
    else:
        row["shenzhen_last_error"]=str(result.get("error") or result.get("status") or "unknown")[:180]


def recent_shenzhen_good_result(row, max_age_hours=24):
    """Use last successful measurement as temporary continuity during probe outages."""
    checked=row.get("shenzhen_checked_at")
    avg=row.get("shenzhen_ping_ms")
    loss=row.get("shenzhen_loss_pct")
    if not checked or avg is None or loss is None:
        return None
    try:
        stamp=datetime.fromisoformat(checked)
        if stamp.tzinfo is None:
            stamp=stamp.replace(tzinfo=timezone.utc)
        age=(datetime.now(timezone.utc)-stamp.astimezone(timezone.utc)).total_seconds()/3600
        if age<0 or age>float(max_age_hours):
            return None
        return {"ok":True,"status":"last-good","avg_ms":float(avg),"loss_pct":float(loss),
                "probe_city":row.get("shenzhen_probe_city"),
                "probe_observations":_safe_int(row.get("shenzhen_probe_observations"),1)}
    except (ValueError,TypeError):
        return None


PROBE_UNKNOWN_STATUSES={"probe-unavailable","timeout","no-stats","no-measurement-id","invalid-response","request-rejected","error"}

CLOUD_MARKERS=("amazon","aws","google","azure","microsoft","digitalocean","vultr","linode","hetzner","contabo","oracle","cloudflare")
HIGH_RISK_MARKERS=("m247","layer7","bluevps","alfahost")

def clean_score(ipinfo,google_result):
    # A missing IP-intelligence response is unknown, not evidence of a bad node.
    # Cloudflare often appears as a reverse-proxy edge, so its ASN alone also
    # does not identify the origin or prove low quality. Both receive a neutral
    # score that still must pass endpoint and Shenzhen measurements.
    if not ipinfo:
        score=65
        org=""
        privacy={}
    else:
        score=80
        org=str(ipinfo.get("org","")).lower()
        # Exclude Cloudflare alone from the hosting penalty; retain all other
        # cloud/high-risk markers and any explicit privacy flags.
        markers=tuple(x for x in CLOUD_MARKERS if x!="cloudflare")+HIGH_RISK_MARKERS
        if any(x in org for x in markers): score-=20
        if "cloudflare" in org and not any(x in org for x in markers):
            score=min(score,65)
        privacy=ipinfo.get("privacy") or {}
    if isinstance(privacy,dict):
        if privacy.get("vpn"): score-=15
        if privacy.get("proxy"): score-=15
        if privacy.get("tor"): score-=20
        if privacy.get("hosting"): score-=15
    if google_result.get("challenge"): score-=30
    if not google_result.get("ok"): score-=20
    return max(0,min(100,score))

def worst_endpoint_latency_ms(item):
    """Worst observed end-to-end proxy response time among tested Google services."""
    values=[]
    for value in (item.get("endpoint_latency_ms") or {}).values():
        try:
            number=float(value)
            if number>=0:
                values.append(number)
        except (TypeError,ValueError):
            continue
    return round(max(values)) if values else None


def total_score(*,gemini,google_play,google,clean,lifespan,stability,endpoint_latency_ms=None):
    points=(20 if google.get("ok") else 0)+(25 if gemini else 0)+(20 if google_play else 0)+round(clean*0.20)
    points += 10 if lifespan>=30 else 7 if lifespan>=14 else 4 if lifespan>=7 else 2 if lifespan>=3 else 0
    points += round(5*max(0,min(1,stability)))
    if endpoint_latency_ms is not None:
        try:
            latency=max(0.0,float(endpoint_latency_ms))
            points -= min(30,max(0,int((latency-500.0)//250.0)))
        except (TypeError,ValueError):
            pass
    return max(0,min(100,points))

def source_path_sort_key(path):
    low=str(path).lower()
    dates=[int(x) for x in re.findall(r"(20\d{6})", low)]
    versions=[int(x) for x in re.findall(r"(?:v|version)[-_]?(\d+)", low)]
    date_score=max(dates) if dates else -1
    version_score=max(versions) if versions else -1
    is_readme=1 if "readme" in low else 0
    return (date_score,version_score,-is_readme,-len(low),low)

def source_timestamp(source):
    """Prefer a date-coded snapshot filename; otherwise use repository push time."""
    if not isinstance(source,dict):
        return None
    path=str(source.get("path") or source.get("url") or "")
    dates=re.findall(r"(20\d{6})",path)
    if dates:
        try:
            return datetime.strptime(max(dates),"%Y%m%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    raw=source.get("pushed_at")
    if not raw:
        return None
    try:
        stamp=datetime.fromisoformat(str(raw).replace("Z","+00:00"))
    except (TypeError,ValueError):
        return None
    if stamp.tzinfo is None:
        stamp=stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def source_is_fresh(source,max_age_days,now=None):
    """Reject undated and stale sources, even if they remain in the source cache."""
    try:
        limit=timedelta(days=float(max_age_days))
    except (TypeError,ValueError):
        return False
    if limit.total_seconds()<0:
        return False
    stamp=source_timestamp(source)
    if stamp is None:
        return False
    current=now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current=current.replace(tzinfo=timezone.utc)
    age=current.astimezone(timezone.utc)-stamp
    return -timedelta(hours=24)<=age<=limit




def load_source_quality(path):
    try:
        value=json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value,dict) and isinstance(value.get("sources"),dict):
            return {"version":1,"updated_at":value.get("updated_at"),"sources":value["sources"]}
    except (OSError,json.JSONDecodeError):
        pass
    return {"version":1,"updated_at":None,"sources":{}}


def source_quality_score(row):
    """0-100 smoothed score; unavailable probes are excluded from node-failure counts."""
    def rate(success,total):
        return (float(success)+1.0)/(float(total)+2.0)
    parsed=max(0,_safe_int(row.get("parsed_nodes_total"),0))
    unique=max(0,_safe_int(row.get("unique_nodes_total"),0))
    tested=max(0,_safe_int(row.get("endpoint_tested_total"),0))
    passed=max(0,_safe_int(row.get("endpoint_passed_total"),0))
    decided=max(0,_safe_int(row.get("shenzhen_decided_total"),0))
    shenzhen=max(0,_safe_int(row.get("shenzhen_passed_total"),0))
    diversity=rate(min(unique,parsed),parsed) if parsed else 0.5
    endpoint=rate(min(passed,tested),tested) if tested else 0.5
    local=rate(min(shenzhen,decided),decided) if decided else 0.5
    return round(20*diversity+35*endpoint+45*local,1)


def rank_source_list(sources, quality_rows, max_sources, exploration_fraction=0.2):
    """Keep a high-yield majority while reserving slots for under-tested feeds."""
    if not sources:
        return []
    try:
        limit=max(1,int(max_sources))
    except (TypeError,ValueError):
        limit=len(sources)
    def url_of(source):
        return str(source.get("url") or "")
    def sample_counts(source):
        row=quality_rows.get(url_of(source),{})
        return _safe_int(row.get("endpoint_tested_total"),0),_safe_int(row.get("shenzhen_decided_total"),0)
    def stamp(source):
        return source_timestamp(source) or datetime.min.replace(tzinfo=timezone.utc)
    ordered=sorted(sources,key=lambda s:(source_quality_score(quality_rows.get(url_of(s),{})),
                                          stamp(s),_safe_int(s.get("stars"),0),url_of(s)),reverse=True)
    if len(ordered)<=limit:
        return ordered
    proven=[s for s in ordered if sample_counts(s)[0]>=10 and sample_counts(s)[1]>=3]
    explore=[s for s in ordered if s not in proven]
    try:
        fraction=max(0.0,min(0.5,float(exploration_fraction)))
    except (TypeError,ValueError):
        fraction=0.2
    slots=min(len(explore),limit,max(1,int(round(limit*fraction)))) if explore else 0
    selected=proven[:limit-slots]+explore[:slots]
    chosen={url_of(s) for s in selected}
    for source in ordered:
        if len(selected)>=limit:
            break
        if url_of(source) not in chosen:
            selected.append(source); chosen.add(url_of(source))
    return selected[:limit]


SOURCE_RUN_METRICS=("parsed_nodes","structurally_valid_nodes","unique_nodes","duplicate_nodes",
                    "tested_nodes","endpoint_passed","shenzhen_decided","shenzhen_passed",
                    "shenzhen_failed","probe_unknown","shenzhen_cache_hits")
SOURCE_TOTAL_METRICS={
    "parsed_nodes":"parsed_nodes_total",
    "structurally_valid_nodes":"structurally_valid_nodes_total",
    "unique_nodes":"unique_nodes_total",
    "duplicate_nodes":"duplicate_nodes_total",
    "tested_nodes":"endpoint_tested_total",
    "endpoint_passed":"endpoint_passed_total",
    "shenzhen_decided":"shenzhen_decided_total",
    "shenzhen_passed":"shenzhen_passed_total",
    "shenzhen_failed":"shenzhen_failed_total",
    "probe_unknown":"probe_unknown_total",
}


def update_source_quality(db, current, now=None):
    stamp=(now or datetime.now(timezone.utc)).isoformat()
    rows=db.setdefault("sources",{})
    for url,metrics in current.items():
        if not url:
            continue
        row=rows.setdefault(url,{"repo":metrics.get("repo"),"runs_seen":0})
        row["repo"]=metrics.get("repo") or row.get("repo")
        for key,total_key in SOURCE_TOTAL_METRICS.items():
            row[total_key]=_safe_int(row.get(total_key),0)+_safe_int(metrics.get(key),0)
        row["runs_seen"]=_safe_int(row.get("runs_seen"),0)+1
        row["last_seen_at"]=stamp
        row["last_run"]={key:_safe_int(metrics.get(key),0) for key in SOURCE_RUN_METRICS}
        row["quality_score"]=source_quality_score(row)
    db["version"]=1
    db["updated_at"]=stamp
    if len(rows)>500:
        db["sources"]=dict(sorted(rows.items(),key=lambda item:str(item[1].get("last_seen_at") or ""),reverse=True)[:500])
    return db


class GitHubDiscovery:
    def __init__(self,token,cfg):
        self.cfg=cfg
        self.session=requests.Session()
        self.session.headers.update({"User-Agent":UA,"Accept":"application/vnd.github+json"})
        if token:
            self.session.headers["Authorization"]=f"Bearer {token}"
        self.stats={"queries":0,"query_failures":0,"repos_found":0,"tree_failures":0,"source_fetch_failures":0,"sources_found":0}

    def _get_json(self,url,params=None):
        headers=dict(self.session.headers)
        response=requests.get(url,params=params,headers=headers,timeout=15)
        response.raise_for_status()
        return response.json()

    def search_repositories(self):
        cutoff=(datetime.now(timezone.utc)-timedelta(days=int(self.cfg["recent_days"]))).date().isoformat()
        repos={}
        push_suffix=f" pushed:>={cutoff}" if self.cfg.get("require_recent_push",False) else ""
        for base_query in self.cfg["queries"]:
            self.stats["queries"]+=1
            try:
                data=self._get_json(
                    "https://api.github.com/search/repositories",
                    {"q":f"{base_query}{push_suffix}","sort":"updated","order":"desc","per_page":int(self.cfg["repositories_per_query"])}
                )
            except requests.RequestException as exc:
                self.stats["query_failures"]+=1
                print(f"source_search_skip: {type(exc).__name__}: {str(exc)[:180]}")
                continue
            for item in data.get("items",[]):
                if int(item.get("stargazers_count",0) or 0) >= int(self.cfg.get("min_stars",30)):
                    repos[item["full_name"]]=item
        self.stats["repos_found"]=len(repos)
        return sorted(
            repos.values(),
            key=lambda x:(x.get("pushed_at",""),x.get("stargazers_count",0),x.get("forks_count",0)),
            reverse=True
        )[:int(self.cfg["max_repositories"])]

    def candidate_files(self,repo):
        owner,name=repo["full_name"].split("/",1)
        try:
            tree=self._get_json(
                f"https://api.github.com/repos/{owner}/{name}/git/trees/{repo['default_branch']}",
                {"recursive":"1"}
            )
        except requests.RequestException as exc:
            self.stats["tree_failures"]+=1
            print(f"source_tree_skip: {repo['full_name']}: {type(exc).__name__}")
            return []
        paths=[]
        for item in tree.get("tree",[]):
            if item.get("type")!="blob":
                continue
            path=item.get("path","")
            low=path.lower()
            basename=low.rsplit("/",1)[-1]
            if is_candidate_source_path(path):
                paths.append(path)
        paths.sort(key=lambda p: source_path_sort_key(p), reverse=True)
        return paths[:int(self.cfg["max_candidate_files_per_repo"])]

    def fetch_and_validate(self,repo,path):
        owner,name=repo["full_name"].split("/",1)
        raw=f"https://raw.githubusercontent.com/{owner}/{name}/{quote(repo['default_branch'],safe='')}/{quote(path,safe='/')}"
        try:
            response=requests.get(raw,headers={"User-Agent":UA},timeout=12,allow_redirects=True)
            response.raise_for_status()
            if len(response.content)>int(self.cfg["max_source_bytes"]):
                return None
        except requests.RequestException:
            self.stats["source_fetch_failures"]+=1
            return None
        nodes=parse_subscription(response.text)
        if len(nodes)<int(self.cfg["min_nodes_per_source"]):
            return None
        return {
            "url":raw,
            "repo":repo["full_name"],
            "path":path,
            "stars":repo.get("stargazers_count",0),
            "forks":repo.get("forks_count",0),
            "pushed_at":repo.get("pushed_at"),
            "nodes":len(nodes)
        }

    def discover(self):
        out=[]
        seen=set()
        repos=self.search_repositories()
        workers=max(1,min(int(self.cfg.get("source_workers",12)),16))
        candidate_cap=max(1,int(self.cfg.get("max_source_fetches",180)))
        repo_paths=[]
        # Bound concurrent API tree lookups to avoid serial discovery or an API burst.
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures=[executor.submit(self.candidate_files,repo) for repo in repos]
            for repo,future in zip(repos,futures):
                try:
                    paths=future.result()
                except Exception as exc:
                    self.stats["tree_failures"]+=1
                    print(f"source_tree_skip: {repo.get('full_name','unknown')}: {type(exc).__name__}")
                    paths=[]
                repo_paths.extend((repo,path) for path in paths)
        candidates_discovered=len(repo_paths)
        # Hard cap the number of feed downloads. Otherwise 120 repositories × 8
        # files can create ~1,000 sequentially queued requests and exceed the CI timeout.
        repo_paths=repo_paths[:candidate_cap]
        self.stats["candidate_paths_discovered"]=candidates_discovered
        self.stats["candidate_paths_scheduled"]=len(repo_paths)
        print("source_candidates: discovered=%d scheduled=%d workers=%d" % (candidates_discovered,len(repo_paths),workers))
        # Fetch subscription content concurrently while preserving repo/path priority.
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures=[executor.submit(self.fetch_and_validate,repo,path) for repo,path in repo_paths]
            for (repo,path),future in zip(repo_paths,futures):
                try:
                    source=future.result()
                except Exception as exc:
                    self.stats["source_fetch_failures"]+=1
                    print(f"source_parse_skip: {repo.get('full_name','unknown')}/{path}: {type(exc).__name__}")
                    continue
                if source and source["url"] not in seen:
                    seen.add(source["url"])
                    out.append(source)
        self.stats["sources_found"]=len(out)
        print(
            "source_discovery: queries=%d query_failures=%d repos=%d tree_failures=%d "
            "source_fetch_failures=%d sources=%d"
            % (
                self.stats["queries"],self.stats["query_failures"],self.stats["repos_found"],
                self.stats["tree_failures"],self.stats["source_fetch_failures"],self.stats["sources_found"]
            )
        )
        return out
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
    def __init__(self,binary,cfg):
        self.binary=binary; self.cfg=cfg; self.proc=None; self.tmp=None; self.log_handle=None; self.session=requests.Session()
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
        config={"mixed-port":self.proxy_port,"allow-lan":False,"mode":"rule","log-level":"warning","external-controller":f"127.0.0.1:{self.controller_port}","proxies":proxies,"proxy-groups":[{"name":"TEST","type":"select","proxies":names}],"rules":["GEOIP,CN,DIRECT","MATCH,TEST"]}
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
                present=None
                try:
                    present=sorted((self.session.get(f"http://127.0.0.1:{self.controller_port}/proxies",timeout=2).json().get("proxies") or {}).keys())
                except Exception:
                    pass
                detail=""
                try:
                    detail=self.log_path.read_text(encoding="utf-8",errors="replace")[-4000:]
                except Exception:
                    pass
                # `present` tells the two failure modes apart: seeing only DIRECT/REJECT/GLOBAL
                # means every node in this batch was rejected (a node-data problem), while a
                # foreign set of groups means we hit someone else's controller (port collision).
                raise RuntimeError(f"mihomo@{self.controller_port} /proxies/TEST missing: nodes={len(nodes)} present={present}; {exc}; log={detail}")
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
            error=str(exc)
            # A single malformed node can make Mihomo drop the whole TEST group, which
            # surfaces as `Parse config error:` or as `/proxies/TEST missing`. Both are
            # node-data problems: isolate them by splitting instead of aborting the run.
            # Anything else is systemic ("Mihomo exited", ports, etc.) and fails loudly.
            if "Parse config error:" not in error and "/proxies/TEST missing" not in error:
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
                    "endpoint_latency_ms":{
                        "gemini":item["gemini"].get("latency_ms"),
                        "google_play":item["google_play"].get("latency_ms"),
                        "google":item["google"].get("latency_ms"),
                    },
                })
                print("node_test_progress: completed=%d/%d name=%r" % (idx+1,len(nodes),node.get("name","")))
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
        futures=[executor.submit(MihomoTester(binary,cfg).test_nodes,batch,checks) for idx,batch in enumerate(batches)]
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
    route_rules=LOCAL_IOT_DIRECT_RULES+WPS_DIRECT_RULES+WECHAT_DIRECT_RULES+XIAOMI_DIRECT_RULES+["GEOIP,CN,DIRECT","MATCH,PROXY"]
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
            "+.wps.cn":["223.5.5.5","119.29.29.29"],
            "+.wps.com":["223.5.5.5","119.29.29.29"],
            "+.wps365.com":["223.5.5.5","119.29.29.29"],
            "+.kdocs.cn":["223.5.5.5","119.29.29.29"],
            "+.wpscdn.cn":["223.5.5.5","119.29.29.29"],
            "+.wpscdn.com":["223.5.5.5","119.29.29.29"],
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
    """Pin a node only when its endpoint score and Shenzhen quality both remain acceptable."""
    if not isinstance(meta, dict): return False
    try:
        keep_ping=float(sticky_cfg.get("keep_ping_ms", 300))
        keep_loss=float(sticky_cfg.get("keep_loss_pct", 5.0))
        keep_endpoint=float(sticky_cfg.get("keep_endpoint_latency_ms", 2000))
        keep_score=float(sticky_cfg.get("keep_min_score", 70))
        score=float(meta.get("score", 0))
        app_latency=float(meta.get("app_latency_ms"))
    except (TypeError,ValueError):
        return False
    ping=meta.get("shenzhen_ping_ms"); loss=meta.get("shenzhen_loss_pct")
    if ping is None or loss is None or app_latency>keep_endpoint or score<keep_score: return False
    return float(ping)<keep_ping and float(loss)<=keep_loss

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
            "app_latency":_safe_float(meta.get("app_latency_ms"),float("inf")),
            "ping":_safe_float(meta.get("shenzhen_ping_ms"),float("inf")),
            "loss":_safe_float(meta.get("shenzhen_loss_pct"),float("inf")),
            "stability":_safe_float(meta.get("stability"),0.0),
            "lifespan":_safe_float(meta.get("lifespan"),0.0),
            "us_nd":_us_non_datacenter_bonus(meta),
            "above_floor":1 if score>=min_final_score else 0,
            "server":str(node.get("server") or "").strip().lower(),
            "org":str(meta.get("org") or meta.get("asn") or "").strip().lower(),
        })
    enriched.sort(key=lambda e:(-e["above_floor"],-e["score"],e["app_latency"],e["ping"],e["loss"],-e["stability"],-e["lifespan"],-e["us_nd"],e["fp"]))
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


def rank_final_nodes(candidates, metadata, cfg):
    """Rank all passing candidates; previous-pool membership never bypasses caps."""
    return rank_candidates(
        candidates,
        limit=int(cfg.get("max_final_nodes", 20)),
        metadata=metadata,
        max_per_server=int(cfg.get("max_per_server", 2)),
        max_per_org=int(cfg.get("max_per_org", 3)),
        min_final_score=int(cfg.get("min_final_score", 0)),
    )


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

def round_robin_fingerprints(source_buckets, weights=None):
    """Give every non-empty feed a first sample, then allocate extra slots by quality weight."""
    supplied=list(weights) if weights is not None else []
    buckets=[]; bucket_weights=[]
    for original_index,raw_bucket in enumerate(source_buckets):
        bucket=list(dict.fromkeys(raw_bucket or []))
        if not bucket:
            continue
        buckets.append(bucket)
        weight=_safe_float(supplied[original_index],1.0) if original_index<len(supplied) else 1.0
        bucket_weights.append(max(0.1,weight))
    if not buckets:
        return []
    offsets=[0 for _ in buckets]
    if weights is None:
        seen=set(); out=[]
        while True:
            progressed=False
            for index,bucket in enumerate(buckets):
                offset=offsets[index]
                while offset<len(bucket) and bucket[offset] in seen:
                    offset+=1
                if offset<len(bucket):
                    fp=bucket[offset]; out.append(fp); seen.add(fp)
                    offset+=1; progressed=True
                offsets[index]=offset
            if not progressed:
                break
        return out
    current=[0.0 for _ in buckets]; seen=set(); out=[]
    for i,bucket in enumerate(buckets):
        while offsets[i]<len(bucket) and bucket[offsets[i]] in seen:
            offsets[i]+=1
        if offsets[i]<len(bucket):
            fp=bucket[offsets[i]]; offsets[i]+=1
            if fp not in seen:
                out.append(fp); seen.add(fp)
    while True:
        active=[i for i,bucket in enumerate(buckets) if offsets[i]<len(bucket)]
        if not active:
            break
        total=sum(bucket_weights[i] for i in active)
        for i in active:
            current[i]+=bucket_weights[i]
        chosen=max(active,key=lambda i:(current[i],-i))
        current[chosen]-=total
        while offsets[chosen]<len(buckets[chosen]) and buckets[chosen][offsets[chosen]] in seen:
            offsets[chosen]+=1
        if offsets[chosen]>=len(buckets[chosen]):
            continue
        fp=buckets[chosen][offsets[chosen]]
        offsets[chosen]+=1
        if fp not in seen:
            out.append(fp); seen.add(fp)
    return out


def select_dns_safe_candidates(nodes, limit, workers=16):
    """DNS-validate only prioritized candidates needed for a bounded test run.

    Subscription sources can contain tens of thousands of proxy records. Resolving
    every host before applying max_test_nodes makes a small validation run perform
    thousands of DNS lookups. Process a bounded window concurrently and stop as
    soon as the requested number of safe candidates has been selected.
    """
    try:
        limit=max(0,int(limit))
        worker_count=max(1,min(int(workers),32))
    except (TypeError,ValueError):
        limit=0
        worker_count=1
    if limit == 0 or not nodes:
        return [],0,0

    selected=[]
    checked=0
    rejected=0
    chunk_size=worker_count*4

    def check_server(server):
        try:
            return resolved_server_is_safe(server)
        except Exception:
            # A resolver error must fail closed, never make the node testable.
            return False

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        for offset in range(0,len(nodes),chunk_size):
            batch=nodes[offset:offset+chunk_size]
            safe_flags=list(executor.map(check_server,(node.get("server") for node in batch)))
            checked += len(batch)
            rejected += sum(1 for ok in safe_flags if not ok)
            for node,ok in zip(batch,safe_flags):
                if ok:
                    selected.append(node)
                    if len(selected) >= limit:
                        break
            if len(selected) >= limit:
                break
    return selected,checked,rejected


def run():
    rules=load_rules()
    source_path=ROOT/rules["output"]["source_file"]
    history_path=ROOT/rules["output"]["history_file"]
    report_path=ROOT/rules["output"]["report_file"]
    quality_path=ROOT/rules["output"].get("source_quality_file","data/source_quality.json")
    quality_db=load_source_quality(quality_path)
    quality_rows=quality_db.get("sources",{})
    discovery=GitHubDiscovery(os.getenv("GITHUB_TOKEN"),rules["sources"])
    live_discovered=discovery.discover()
    source_now=datetime.now(timezone.utc)
    max_source_age_days=float(rules["sources"].get("max_source_age_days",3))
    live=[s for s in live_discovered if source_is_fresh(s,max_source_age_days,source_now)]
    source_pool_stats={
        "live_discovered":len(live_discovered),
        "live_fresh":len(live),
        "live_stale_dropped":len(live_discovered)-len(live),
        "cache_seen":0,
        "cache_fresh":0,
        "cache_stale_or_undated_dropped":0,
        "cache_non_candidate_dropped":0,
        "cache_low_star_dropped":0,
        "accepted_sources":0,
        "max_source_age_days":max_source_age_days,
    }
    cached=[]
    if source_path.is_file():
        try:
            cached=json.loads(source_path.read_text(encoding="utf-8"))
            if not isinstance(cached,list): cached=[]
        except Exception: cached=[]
    # Cache is continuity only; its entries must pass the same freshness rule as live sources.
    source_pool_stats["cache_seen"]=len(cached)
    seen={s.get("url") for s in live if isinstance(s,dict)}
    sources=list(live)
    min_stars=int(rules["sources"].get("min_stars",30))
    for s in cached:
        if not isinstance(s,dict) or not s.get("url") or s["url"] in seen:
            continue
        if not is_candidate_source_path(s.get("path") or s.get("url")):
            source_pool_stats["cache_non_candidate_dropped"]+=1
            continue
        if not source_is_fresh(s,max_source_age_days,source_now):
            source_pool_stats["cache_stale_or_undated_dropped"]+=1
            continue
        try:
            if int(s.get("stars")) < min_stars:
                source_pool_stats["cache_low_star_dropped"]+=1
                continue
        except (TypeError,ValueError):
            source_pool_stats["cache_low_star_dropped"]+=1
            continue
        seen.add(s["url"])
        sources.append(s)
        source_pool_stats["cache_fresh"]+=1
    max_sources=int(rules["sources"].get("max_sources",120))
    sources=rank_source_list(sources,quality_rows,max_sources,rules["sources"].get("exploration_fraction",0.2))
    source_pool_stats["accepted_sources"]=len(sources)
    print(
        "source_freshness: live=%d/%d stale_live=%d cached_fresh=%d cached_non_candidate=%d cached_stale_or_undated=%d accepted=%d max_age_days=%s"
        % (source_pool_stats["live_fresh"],source_pool_stats["live_discovered"],
           source_pool_stats["live_stale_dropped"],source_pool_stats["cache_fresh"],
           source_pool_stats["cache_non_candidate_dropped"],source_pool_stats["cache_stale_or_undated_dropped"],
           source_pool_stats["accepted_sources"],source_pool_stats["max_source_age_days"])
    )
    if not sources:
        source_pool_stats["no_fresh_sources"]=True
        print("source_warning: no fresh subscription sources; validating the saved stable Fine pool")
    if sources:
        source_path.parent.mkdir(parents=True,exist_ok=True)
        source_path.write_text(json.dumps(sources,ensure_ascii=False,indent=2),encoding="utf-8")
    nodes_by_fp={}; node_source_by_fp={}; source_fingerprints_by_url={}; source_run_stats={}; session=requests.Session()
    source_lookup={str(source.get("url") or ""):source for source in sources}
    def ensure_source_stats(url, source=None):
        if not url:
            return None
        source=source or source_lookup.get(str(url),{}) or {}
        return source_run_stats.setdefault(str(url),{"repo":source.get("repo"),**{key:0 for key in SOURCE_RUN_METRICS}})
    for source_index, source in enumerate(sources,1):
        source_url=str(source.get("url") or "")
        print("source_load: %d/%d %s" % (source_index,len(sources),source_url))
        stats=ensure_source_stats(source_url,source)
        try:
            response=session.get(source_url,timeout=20,headers={"User-Agent":UA}); response.raise_for_status()
            parsed=parse_subscription(response.text)
            stats["parsed_nodes"]+=len(parsed)
            print("source_load_done: %d/%d parsed_nodes=%d" % (source_index,len(sources),len(parsed)))
            source_bucket=source_fingerprints_by_url.setdefault(source_url,[])
            for node in parsed:
                if node.get("type") not in rules["nodes"]["allowed_types"] or not node.get("server") or not node.get("port"):
                    continue
                # parse_subscription already rejects literal private/invalid servers.
                # Defer DNS resolution until after the bounded candidate list is ranked.
                if not is_safe_server(node["server"]) or not mihomo_node_is_testable(node):
                    continue
                stats["structurally_valid_nodes"]+=1
                fp=fingerprint(node)
                if fp not in nodes_by_fp:
                    nodes_by_fp[fp]=node
                    node_source_by_fp[fp]=source_url
                    source_bucket.append(fp)
                    stats["unique_nodes"]+=1
                else:
                    stats["duplicate_nodes"]+=1
        except requests.RequestException as exc:
            print("source_content_skip: %s (%s)" % (source_url,type(exc).__name__))
            continue
    # Re-test the saved stable Fine candidates alongside current source discovery.
    stable_file=ROOT/rules["nodes"].get("stable_pool_file","data/stable_pool.yaml")
    stable_fps=set()
    stable_nodes=load_stable_pool_nodes(stable_file,rules["nodes"].get("max_stable_nodes",20))
    for node in stable_nodes:
        fp=fingerprint(node)
        nodes_by_fp.setdefault(fp,node)
        stable_fps.add(fp)
    print("stable_pool: loaded %d previously validated candidates" % len(stable_nodes))
    # Preserve previously published Fine nodes and stable-pool candidates first; allocate
    # the remaining test budget across source feeds using the measured quality weights.
    retention_cfg=rules.get("retention",{}) or {}
    previous_profile_nodes=load_previous_published_nodes(ROOT / "live_clash.yaml", retention_cfg.get("max_previous_nodes",5) if retention_cfg.get("enabled",True) else 0)
    previous_fps={fingerprint(n) for n in previous_profile_nodes}
    cap=int(rules["nodes"]["max_test_nodes"])
    ordered=previous_profile_nodes[:]
    ordered.extend([n for fp,n in nodes_by_fp.items() if fp in stable_fps and fingerprint(n) not in previous_fps])
    source_urls=list(source_fingerprints_by_url)
    source_weights=[max(0.5,min(1.5,0.5+source_quality_score(quality_rows.get(url,{}))/100.0)) for url in source_urls]
    source_order=round_robin_fingerprints([source_fingerprints_by_url[url] for url in source_urls],source_weights)
    ordered.extend([nodes_by_fp[fp] for fp in source_order if fp not in stable_fps and fp not in previous_fps])
    dedup_ordered=[]; ordered_seen=set()
    for node in ordered:
        fp=fingerprint(node)
        if fp in ordered_seen: continue
        ordered_seen.add(fp); dedup_ordered.append(node)
    nodes,dns_checked,dns_rejected=select_dns_safe_candidates(
        dedup_ordered,
        cap,
        rules["nodes"].get("dns_validation_workers",16),
    )
    print("node_dns_validation: candidates=%d checked=%d rejected=%d selected=%d cap=%d" % (
        len(dedup_ordered),dns_checked,dns_rejected,len(nodes),cap
    ))
    binary=shutil.which("mihomo") or shutil.which("clash")
    if not nodes: raise RuntimeError("No valid nodes discovered; published outputs were preserved.")
    if not binary: raise RuntimeError("mihomo binary not found")
    checks=rules["checks"]; tester_cfg={**rules["nodes"],"challenge_markers":checks["challenge_markers"],"success_statuses":checks["success_statuses"]}; history=load_history(history_path); selected=[]
    report={
        "generated_at":datetime.now(timezone.utc).isoformat(),
        "sources":len(sources),
        "source_discovery":discovery.stats,
        "source_pool":source_pool_stats,
        "dns_validation":{"prioritized_candidates":len(dedup_ordered),"checked":dns_checked,"rejected":dns_rejected,"workers":int(rules["nodes"].get("dns_validation_workers",16))},
        "nodes_discovered":len(nodes),
        "previous_profile_candidates":len(previous_profile_nodes),
        "stable_candidates":sum(1 for node in nodes if fingerprint(node) in (stable_fps|previous_fps)),
        "exploration_candidates":sum(1 for node in nodes if fingerprint(node) not in (stable_fps|previous_fps)),
        "results":[]
    }
    report_lookup={}
    candidate_records=[]
    clean_floor_passed=0
    candidate_gate_passed=0
    endpoint_latency_passed=0

    for item in test_nodes_parallel(binary,nodes,tester_cfg,checks):
        node,fp=item["node"],fingerprint(item["node"])
        row=history.get(fp,{"first_seen":date.today().isoformat(),"last_seen":date.today().isoformat(),"seen_count":0,"pass_count":0,"gemini_pass_count":0,"play_pass_count":0})
        source_url=node_source_by_fp.get(fp) or row.get("source_url")
        source_info=source_lookup.get(str(source_url or ""),{})
        if not source_info and row.get("source_repo"):
            source_info={"repo":row.get("source_repo")}
        source_stats=ensure_source_stats(source_url,source_info) if source_url else None
        if source_stats is not None:
            source_stats["tested_nodes"]+=1
            row["source_url"]=source_url
            if source_info.get("repo"):
                row["source_repo"]=source_info["repo"]
        life=lifespan_days(row); ipinfo_data=item.get("ipinfo") or {}; clean=clean_score(item.get("ipinfo"),item["google"]); stability=min(1.0,row.get("pass_count",0)/max(1,row.get("seen_count",1)))
        app_latency_ms=worst_endpoint_latency_ms(item)
        score=total_score(gemini=item["gemini"],google_play=item["google_play"],google=item["google"],clean=clean,lifespan=life,stability=stability,endpoint_latency_ms=app_latency_ms)
        row=update_history(history,fp,{"score":score,"gemini":item["gemini"],"google_play":item["google_play"]},score_threshold=rules["nodes"].get("score_threshold",70))
        # candidate_gate 控制「候选」门槛；score_threshold 仅用于历史稳定性统计，
        # 不再作为候选硬门槛。
        #   - reachable：Google 204 / Gemini / Play 任一可达，并满足洁净度下限。
        #   - gemini_or_play：Gemini 或 Play 任一通过，并满足洁净度下限。
        #   - gemini_and_play：Gemini 与 Play 均通过，并满足洁净度下限。
        gate=str(rules["nodes"].get("candidate_gate","reachable")).lower()
        min_clean=float(rules["nodes"].get("min_clean_score",0))
        if clean >= min_clean:
            clean_floor_passed += 1
        if app_latency_ms is not None and app_latency_ms<=float(rules["nodes"].get("max_endpoint_latency_ms",2500)):
            endpoint_latency_passed += 1
        # score_threshold is used for history/pass-day statistics, not as a hard
        # candidate gate. The candidate gate itself is explicit and testable.
        max_endpoint_latency_ms=float(rules["nodes"].get("max_endpoint_latency_ms",2500))
        latency_ok=app_latency_ms is not None and app_latency_ms<=max_endpoint_latency_ms
        candidate=candidate_gate_passes(item,gate,clean,min_clean) and latency_ok
        if source_stats is not None:
            source_stats["endpoint_passed"]+=int(candidate)

        asn_obj=ipinfo_data.get("asn"); asn_value=asn_obj.get("asn") if isinstance(asn_obj,dict) else asn_obj
        entry={"fingerprint":fp,"name":node["name"],"score":score,"gemini":item["gemini"],"google_play":item["google_play"],"clean":clean,"lifespan_days":lifespan_days(row),"app_latency_ms":app_latency_ms,"endpoint_latency_ms":item.get("endpoint_latency_ms"),"shenzhen_ping_ms":None,"shenzhen_loss_pct":None,"shenzhen_status":"not-tested","org":ipinfo_data.get("org"),"asn":asn_value,"country":ipinfo_data.get("country")}
        report["results"].append(entry); report_lookup[fp]=entry

        shenzhen_cfg=rules.get("shenzhen_probe",{})
        if candidate:
            candidate_gate_passed += 1
            if shenzhen_cfg.get("enabled",False):
                cached=cached_shenzhen_result(row,shenzhen_cfg)
                candidate_records.append({"fp":fp,"node":node,"result":cached,"source_url":source_url})
            else:
                selected.append(node)

    report["clean_floor_passed"]=clean_floor_passed
    report["candidate_gate_passed"]=candidate_gate_passed
    report["endpoint_latency_passed"]=endpoint_latency_passed
    report["max_endpoint_latency_ms"]=float(rules["nodes"].get("max_endpoint_latency_ms",2500))
    report["candidate_gate"]=gate
    report["candidate_clean_floor"]=min_clean
    shenzhen_cfg=rules.get("shenzhen_probe",{})
    pending=[(rec["fp"],rec["node"]) for rec in candidate_records if rec["result"] is None]
    measured=probe_shenzhen_parallel(pending,shenzhen_cfg) if shenzhen_cfg.get("enabled",False) else {}
    retained_fps=set(previous_fps)|set(stable_fps)
    for rec in candidate_records:
        fp,node,cached=rec["fp"],rec["node"],rec["result"]
        row=history[fp]
        result=cached if cached is not None else measured.get(fp,{"ok":False,"status":"not-measured"})
        source_url=rec.get("source_url") or node_source_by_fp.get(fp) or row.get("source_url")
        source_info=source_lookup.get(str(source_url or ""),{})
        if not source_info and row.get("source_repo"):
            source_info={"repo":row.get("source_repo")}
        source_stats=ensure_source_stats(source_url,source_info) if source_url else None
        if cached is None:
            save_shenzhen_history(row,result)
        record_shenzhen_source_metrics(
            source_stats,
            result,
            shenzhen_cfg,
            cached=(cached is not None),
        )
        effective=result
        if (not result.get("ok") and fp in retained_fps
                and result.get("status") in PROBE_UNKNOWN_STATUSES):
            grace_hours=float(shenzhen_cfg.get("stable_probe_grace_hours",24))
            last_good=recent_shenzhen_good_result(row,grace_hours)
            if last_good is not None and shenzhen_passes(last_good,shenzhen_cfg):
                effective=last_good
        entry=report_lookup[fp]
        entry["shenzhen_probe_status"]=result.get("status","unknown")
        entry["shenzhen_ping_ms"]=effective.get("avg_ms") if effective.get("ok") else None
        entry["shenzhen_loss_pct"]=effective.get("loss_pct") if effective.get("ok") else None
        entry["shenzhen_status"]="probe-unavailable-retained" if effective is not result else result.get("status","unknown")
        if shenzhen_passes(effective,shenzhen_cfg):
            selected.append(node)

    report["shenzhen_passed"]=len(selected)
    report["shenzhen_status_counts"]={}
    for result in report["results"]:
        status=result.get("shenzhen_status","unknown")
        report["shenzhen_status_counts"][status]=report["shenzhen_status_counts"].get(status,0)+1
    # Unknown probe outcomes are separate from measured node failures.
    quality_db=update_source_quality(quality_db,source_run_stats)
    quality_path.parent.mkdir(parents=True,exist_ok=True)
    quality_path.write_text(json.dumps(quality_db,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
    report["source_quality_top"]=[
        {"source_url":url,"repo":quality_db["sources"].get(url,{}).get("repo") or stats.get("repo"),
         "score":source_quality_score(quality_db["sources"].get(url,{})),
         "tested_nodes":stats.get("tested_nodes",0),"endpoint_passed":stats.get("endpoint_passed",0),
         "shenzhen_passed":stats.get("shenzhen_passed",0),"shenzhen_failed":stats.get("shenzhen_failed",0),
         "probe_unknown":stats.get("probe_unknown",0),"shenzhen_cache_hits":stats.get("shenzhen_cache_hits",0)}
        for url,stats in sorted(source_run_stats.items(),
            key=lambda item:source_quality_score(quality_db["sources"].get(item[0],{})),reverse=True)[:20]
    ]
    # Shenzhen is a hard quality gate. Never backfill rejected/unmeasured nodes into the final pool.
    history_path.write_text(json.dumps(history,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
    before=len(selected); selected=[node for node in selected if node.get("network","tcp") in COMPATIBLE_NETWORKS]; report["incompatible_filtered"]=before-len(selected)
    if len(selected)<int(rules["nodes"]["min_final_nodes"]):
        report["published"]=False; report["selected"]=len(selected); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); raise RuntimeError(f"Only {len(selected)} nodes passed final threshold; refusing to publish the previous Fine pool.")
    ranking_meta={}
    for node in selected:
        fp=fingerprint(node); entry=report_lookup.get(fp,{}); row=history.get(fp,{})
        ranking_meta[fp]={"score":entry.get("score",0),"app_latency_ms":entry.get("app_latency_ms"),"shenzhen_ping_ms":entry.get("shenzhen_ping_ms"),"shenzhen_loss_pct":entry.get("shenzhen_loss_pct"),"stability":min(1.0,row.get("pass_count",0)/max(1,row.get("seen_count",1))),"lifespan":lifespan_days(row),"org":entry.get("org"),"asn":entry.get("asn"),"country":entry.get("country")}
    # Rank the entire currently passing pool. Previous nodes were already prioritized
    # for re-testing above; they must not reserve final slots or bypass diversity caps.
    ranked=rank_final_nodes(selected, ranking_meta, rules["nodes"])
    report["ranking_input"]=len(selected)
    report["ranking_output"]=len(ranked)
    report["ranking_dropped"]=max(0,len(selected)-len(ranked))
    # ★ 粘性优质节点（2026-10-06）：订阅更新时保持当前优秀节点为首选，
    #   只有分数、端到端延迟、深圳 PING/掉包率均达标才保持首选；低分旧节点必须让位。
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
        report["ranking"].append({"rank":i,"score":entry.get("score"),"app_latency_ms":entry.get("app_latency_ms"),"shenzhen_ping_ms":entry.get("shenzhen_ping_ms"),"shenzhen_loss_pct":entry.get("shenzhen_loss_pct"),"server":node.get("server"),"type":node.get("type")})
    print("Top20 Ranking:"); print("Rank | Score | App ms | Ping | Loss | Server | Type")
    for r in report["ranking"]:
        app_ms=r["app_latency_ms"] if r["app_latency_ms"] is not None else "-"; ping=r["shenzhen_ping_ms"] if r["shenzhen_ping_ms"] is not None else "-"; loss=r["shenzhen_loss_pct"] if r["shenzhen_loss_pct"] is not None else "-"
        print(f"{r['rank']:>4} | {r['score']:>5} | {str(app_ms):>6} | {str(ping):>5} | {str(loss):>5} | {r['server']} | {r['type']}")
    if len(ranked)<int(rules["nodes"]["min_final_nodes"]):
        report["published"]=False; report["selected"]=len(ranked); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); raise RuntimeError(f"Only {len(ranked)} nodes remained after diversity ranking; refusing to publish the previous Fine pool.")
    build_outputs(ranked,rules)
    report["stable_pool_written"]=save_stable_pool(stable_file,ranked,rules["nodes"].get("max_stable_nodes",20))
    report["published"]=True
    report["selected"]=len(ranked)
    report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")

if __name__=="__main__": run()
