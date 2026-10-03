from __future__ import annotations
import base64, hashlib, ipaddress, json, os, re, shutil, subprocess, tempfile, time
from concurrent.futures import ThreadPoolExecutor
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
CANDIDATE_NAMES=("sub","subscribe","subscription","clash","v2ray","proxy","nodes","free")
EXTENSIONS=(".yaml",".yml",".txt",".conf",".base64")
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

def parse_uri(uri):
    uri=uri.strip()
    return _parse_vmess(uri) if uri.lower().startswith("vmess://") else _parse_standard(uri)

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
    data="|".join(str(node.get(k,"")) for k in ("type","server","port","uuid","password"))
    return hashlib.sha256(data.encode()).hexdigest()[:20]

def node_to_uri(node):
    kind,server,port=node.get("type"),node.get("server"),node.get("port")
    if not server or not port: return None
    name=quote(str(node.get("name") or "node"),safe="")
    host=f"[{server}]" if ":" in str(server) and not str(server).startswith("[") else str(server)
    if kind=="vless":
        q=[]
        reality=node.get("reality-opts")
        if reality: q.append("security=reality")
        elif node.get("tls"): q.append("security=tls")
        if node.get("encryption"): q.append("encryption="+quote(str(node["encryption"]),safe=""))
        if node.get("servername"): q.append("sni="+quote(str(node["servername"]),safe=""))
        if node.get("flow"): q.append("flow="+quote(str(node["flow"]),safe=""))
        if node.get("client-fingerprint"): q.append("fp="+quote(str(node["client-fingerprint"]),safe=""))
        if reality and reality.get("public-key"): q.append("pbk="+quote(str(reality["public-key"]),safe=""))
        if reality and reality.get("short-id"): q.append("sid="+quote(str(reality["short-id"]),safe=""))
        if node.get("network"): q.append("type="+quote(str(node["network"]),safe=""))
        if node.get("network")=="ws" and node.get("ws-opts",{}).get("path"): q.append("path="+quote(str(node["ws-opts"]["path"]),safe=""))
        if node.get("network")=="ws" and node.get("ws-opts",{}).get("headers",{}).get("Host"): q.append("host="+quote(str(node["ws-opts"]["headers"]["Host"]),safe=""))
        if node.get("network")=="grpc" and node.get("grpc-opts",{}).get("grpc-service-name"): q.append("serviceName="+quote(str(node["grpc-opts"]["grpc-service-name"]),safe=""))
        return f"vless://{quote(str(node.get('uuid','')),safe='')}@{host}:{port}?{'&'.join(q)}#{name}"
    if kind=="trojan":
        q=["security=tls"]
        if node.get("servername"): q.append("sni="+quote(str(node["servername"]),safe=""))
        if node.get("network"): q.append("type="+quote(str(node["network"]),safe=""))
        if node.get("network")=="ws":
            ws=node.get("ws-opts",{})
            if ws.get("path"): q.append("path="+quote(str(ws["path"]),safe=""))
            if ws.get("headers",{}).get("Host"): q.append("host="+quote(str(ws["headers"]["Host"]),safe=""))
        elif node.get("network")=="grpc":
            service=node.get("grpc-opts",{}).get("grpc-service-name")
            if service: q.append("serviceName="+quote(str(service),safe=""))
        return f"trojan://{quote(str(node.get('password','')),safe='')}@{host}:{port}?{'&'.join(q)}#{name}"
    if kind=="ss":
        raw=f"{node.get('cipher','chacha20-ietf-poly1305')}:{node.get('password','')}@{host}:{port}"
        return f"ss://{base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')}#{name}"
    if kind=="vmess":
        ws=node.get("ws-opts",{})
        network=node.get("network","tcp")
        payload={"v":"2","ps":node.get("name","vmess"),"add":server,"port":str(port),"id":node.get("uuid",""),"aid":str(node.get("alterId",0)),"scy":node.get("cipher","auto"),"net":network,"type":"none","host":ws.get("headers",{}).get("Host",""),"path":ws.get("path",""),"tls":"tls" if node.get("tls") else ""}
        if network=="grpc" and node.get("grpc-opts",{}).get("grpc-service-name"):
            payload["path"]=node["grpc-opts"]["grpc-service-name"]
        if node.get("servername"): payload["sni"]=node["servername"]
        return "vmess://"+base64.b64encode(json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode()).decode()
    return None

def load_history(path):
    if not path.exists(): return {}
    try:
        data=json.loads(path.read_text(encoding="utf-8")); return data if isinstance(data,dict) else {}
    except (OSError,json.JSONDecodeError): return {}

def update_history(db,fp,result):
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
    if result.get("score",0)>=70: row["pass_count"]+=1
    if result.get("gemini"): row["gemini_pass_count"]+=1
    if result.get("google_play"): row["play_pass_count"]+=1
    return row

def lifespan_days(row):
    try: return max(0,(date.today()-date.fromisoformat(row["first_seen"])).days)
    except Exception: return 0

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
        return float(result["avg_ms"]) <= float(cfg.get("reject_above_ms",400))
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

class GitHubDiscovery:
    def __init__(self,token,cfg):
        self.cfg=cfg; self.session=requests.Session(); self.session.headers.update({"User-Agent":UA,"Accept":"application/vnd.github+json"})
        if token: self.session.headers["Authorization"]=f"Bearer {token}"
    def _get_json(self,url,params=None):
        response=self.session.get(url,params=params,timeout=20); response.raise_for_status(); return response.json()
    def search_repositories(self):
        cutoff=(datetime.now(timezone.utc)-timedelta(days=int(self.cfg["recent_days"]))).date().isoformat(); repos={}
        for base_query in self.cfg["queries"]:
            try: data=self._get_json("https://api.github.com/search/repositories",{"q":f"{base_query} pushed:>={cutoff}","sort":"stars","order":"desc","per_page":self.cfg["repositories_per_query"]})
            except requests.RequestException: continue
            for item in data.get("items",[]): repos[item["full_name"]]=item
        return sorted(repos.values(),key=lambda x:(x.get("stargazers_count",0),x.get("pushed_at","")),reverse=True)[:int(self.cfg["max_repositories"])]
    def candidate_files(self,repo):
        owner,name=repo["full_name"].split("/",1)
        try: tree=self._get_json(f"https://api.github.com/repos/{owner}/{name}/git/trees/{repo['default_branch']}",{"recursive":"1"})
        except requests.RequestException: return []
        paths=[]
        for item in tree.get("tree",[]):
            if item.get("type")!="blob": continue
            path=item.get("path",""); low=path.lower()
            if low.endswith(EXTENSIONS) and any(key in low for key in CANDIDATE_NAMES): paths.append(path)
        paths.sort(key=lambda p:("readme" in p.lower(),len(p),p.lower()))
        return paths[:int(self.cfg["max_candidate_files_per_repo"])]
    def fetch_and_validate(self,repo,path):
        owner,name=repo["full_name"].split("/",1); raw=f"https://raw.githubusercontent.com/{owner}/{name}/{quote(repo['default_branch'],safe='')}/{quote(path,safe='/')}"
        try:
            response=self.session.get(raw,timeout=20,allow_redirects=True); response.raise_for_status()
            if len(response.content)>int(self.cfg["max_source_bytes"]): return None
        except requests.RequestException: return None
        nodes=parse_subscription(response.text)
        if len(nodes)<int(self.cfg["min_nodes_per_source"]): return None
        return {"url":raw,"repo":repo["full_name"],"path":path,"stars":repo.get("stargazers_count",0),"forks":repo.get("forks_count",0),"pushed_at":repo.get("pushed_at"),"nodes":len(nodes)}
    def discover(self):
        out=[]; seen=set()
        for repo in self.search_repositories():
            for path in self.candidate_files(repo):
                source=self.fetch_and_validate(repo,path)
                if source and source["url"] not in seen: seen.add(source["url"]); out.append(source)
        return out

class MihomoTester:
    def __init__(self,binary,cfg,port_offset=0):
        self.binary=binary; self.cfg=cfg; self.proc=None; self.tmp=None; self.session=requests.Session()
        self.proxy_port=17890+int(port_offset)
        self.controller_port=19090+int(port_offset)
    def start(self,nodes):
        names=[]; proxies=[]
        for idx,node in enumerate(nodes):
            name=f"N{idx:03d}"; names.append(name); proxy=dict(node); proxy["name"]=name; proxies.append(proxy)
        config={"mixed-port":self.proxy_port,"allow-lan":False,"mode":"rule","log-level":"error","external-controller":f"127.0.0.1:{self.controller_port}","proxies":proxies,"proxy-groups":[{"name":"TEST","type":"select","proxies":names}],"rules":["GEOSITE,CN,DIRECT","GEOIP,CN,DIRECT","MATCH,TEST"]}
        self.tmp=Path(tempfile.mkdtemp(prefix="fine-clash-")); (self.tmp/"config.yaml").write_text(yaml.safe_dump(config,allow_unicode=True,sort_keys=False),encoding="utf-8")
        # geo 预置(2026-10-03)：mihomo 首启会在线下载 GeoSite.dat，2.5s 启动窗口内下载不完导致控口拒绝连接；
        # 从 MIHOMO_GEO_DIR 本地缓存预拷，跳过在线下载。缺文件时退回 mihomo 自带下载行为，不影响 CI。
        for geo in ("GeoSite.dat","Country.mmdb","geoip.metadb","geosite.dat","geoip.dat"):
            src=Path(os.environ.get("MIHOMO_GEO_DIR",""))/geo
            if src.is_file(): shutil.copyfile(src,self.tmp/geo)
        self.proc=subprocess.Popen([self.binary,"-d",str(self.tmp)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(float(self.cfg["controller_startup_seconds"])); return names
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
        names=self.start(nodes); results=[]
        endpoint_workers=max(1,min(int(self.cfg.get("endpoint_workers",4)),4))
        endpoints=[
            ("gemini",checks["gemini_url"],False),
            ("google_play",checks["google_play_url"],False),
            ("google",checks["google_204_url"],False),
            ("ipinfo",checks["ipinfo_url"],True),
        ]
        try:
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
        finally:
            self.stop()
        return results
    def stop(self):
        if self.proc is None: return
        self.proc.terminate()
        try: self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired: self.proc.kill()
        self.proc=None

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
    route_rules=WECHAT_DIRECT_RULES+["GEOSITE,CN,DIRECT","GEOIP,CN,DIRECT","MATCH,PROXY"]
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
    uris=[uri for node in nodes if (uri:=node_to_uri(node))]
    v2ray_path=ROOT/output_rules["output"]["v2ray_file"]; v2ray_path.parent.mkdir(parents=True,exist_ok=True); v2ray_path.write_text(base64.b64encode("\n".join(uris).encode()).decode()+"\n",encoding="utf-8")

def rank_candidates(nodes, limit=20, metadata=None, max_per_server=2, max_per_org=3):
    """Rank verified nodes by score and diversity, returning the top `limit`.

    Sorting priority (higher first unless noted):
      1. total_score (desc)
      2. shenzhen_ping_ms (asc)
      3. shenzhen_loss_pct (asc)
      4. stability (desc)
      5. lifespan (desc)
      6. fingerprint (asc, deterministic tiebreak)

    Diversity caps applied greedily in sorted order:
      - duplicate fingerprint -> keep only the highest-scored node
      - same server -> keep at most `max_per_server`
      - same org/ASN -> keep at most `max_per_org`

    `metadata` is a fingerprint -> dict lookup (score, shenzhen_ping_ms,
    shenzhen_loss_pct, stability, lifespan, org, asn). Missing fields fall back
    safely, so ranking never raises.
    """
    metadata=metadata or {}
    try: limit=max(1,int(limit))
    except (TypeError,ValueError): limit=20
    try: max_per_server=max(1,int(max_per_server))
    except (TypeError,ValueError): max_per_server=2
    try: max_per_org=max(1,int(max_per_org))
    except (TypeError,ValueError): max_per_org=3
    enriched=[]
    for node in nodes:
        fp=fingerprint(node); meta=metadata.get(fp,{})
        enriched.append({
            "node":node,"fp":fp,
            "score":_safe_float(meta.get("score"),0.0),
            "ping":_safe_float(meta.get("shenzhen_ping_ms"),float("inf")),
            "loss":_safe_float(meta.get("shenzhen_loss_pct"),float("inf")),
            "stability":_safe_float(meta.get("stability"),0.0),
            "lifespan":_safe_float(meta.get("lifespan"),0.0),
            "server":str(node.get("server") or "").strip().lower(),
            "org":str(meta.get("org") or meta.get("asn") or "").strip().lower(),
        })
    enriched.sort(key=lambda e:(-e["score"],e["ping"],e["loss"],-e["stability"],-e["lifespan"],e["fp"]))
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

def run():
    rules=load_rules(); source_path=ROOT/rules["output"]["source_file"]; history_path=ROOT/rules["output"]["history_file"]; report_path=ROOT/rules["output"]["report_file"]
    live=GitHubDiscovery(os.getenv("GITHUB_TOKEN"),rules["sources"]).discover()
    cached=[]
    if source_path.is_file():
        try:
            cached=json.loads(source_path.read_text(encoding="utf-8"))
            if not isinstance(cached,list): cached=[]
        except Exception: cached=[]
    # ★ 2026-10-04：始终合并缓存源（data/sources.json）。匿名 GitHub API 限额时 live 可能很少，
    #   而 data/sources.json 由 discover_broad.py 预先用 raw 路径绕过 tree 限流挖出大量含订阅的仓库。
    #   合并策略：live 优先，cached 中 url 不重复的追加，确保扩源成果一定进候选池。
    seen={s.get("url") for s in live if isinstance(s,dict)}
    sources=list(live)
    for s in cached:
        if isinstance(s,dict) and s.get("url") and s["url"] not in seen:
            seen.add(s["url"]); sources.append(s)
    if not sources and cached:
        sources=cached
    source_path.parent.mkdir(parents=True,exist_ok=True); source_path.write_text(json.dumps(sources,ensure_ascii=False,indent=2),encoding="utf-8")
    nodes_by_fp={}; session=requests.Session()
    for source in sources:
        try:
            response=session.get(source["url"],timeout=20,headers={"User-Agent":UA}); response.raise_for_status()
            for node in parse_subscription(response.text):
                if node.get("type") in rules["nodes"]["allowed_types"] and node.get("server") and node.get("port") and is_safe_server(node["server"]): nodes_by_fp[fingerprint(node)]=node
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
                    if node.get("type") in rules["nodes"]["allowed_types"] and node.get("server") and node.get("port") and is_safe_server(node["server"]):
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
                        if node.get("type") in rules["nodes"]["allowed_types"] and node.get("server") and node.get("port") and is_safe_server(node["server"]):
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
    cap=int(rules["nodes"]["max_test_nodes"])
    ordered=[n for fp,n in nodes_by_fp.items() if fp in curated_fps]+[n for fp,n in nodes_by_fp.items() if fp not in curated_fps]
    nodes=ordered[:cap]
    binary=shutil.which("mihomo") or shutil.which("clash")
    if not nodes: raise RuntimeError("No valid nodes discovered; published outputs were preserved.")
    if not binary: raise RuntimeError("mihomo binary not found")
    checks=rules["checks"]; tester_cfg={**rules["nodes"],"challenge_markers":checks["challenge_markers"],"success_statuses":checks["success_statuses"]}; history=load_history(history_path); selected=[]
    report={"generated_at":datetime.now(timezone.utc).isoformat(),"sources":len(sources),"nodes_discovered":len(nodes),"results":[]}
    report_lookup={}
    candidate_records=[]
    all_candidate_fps=[]

    for item in test_nodes_parallel(binary,nodes,tester_cfg,checks):
        node,fp=item["node"],fingerprint(item["node"])
        row=history.get(fp,{"first_seen":date.today().isoformat(),"last_seen":date.today().isoformat(),"seen_count":0,"pass_count":0,"gemini_pass_count":0,"play_pass_count":0})
        life=lifespan_days(row); ipinfo_data=item.get("ipinfo") or {}; clean=clean_score(item.get("ipinfo"),item["google"]); stability=min(1.0,row.get("pass_count",0)/max(1,row.get("seen_count",1)))
        score=total_score(gemini=item["gemini"],google_play=item["google_play"],google=item["google"],clean=clean,lifespan=life,stability=stability)
        row=update_history(history,fp,{"score":score,"gemini":item["gemini"],"google_play":item["google_play"]})
        candidate=(item["gemini"] and item["google_play"] and score>=int(rules["nodes"]["score_threshold"]))
        # ★ 2026-10-04 策略放宽（池子做大的核心）：
        #   candidate_gate 控制「候选」门槛，分数(score)只用于排序/多样性，不再卡入选。
        #   - reachable（推荐）：代理能通外网即可（google204/gemini/play 任一可达）。
        #     新挖到的免费节点无历史(lifespan/stability=0)，硬卡 70 分会把仅过单探针的活节点全刷掉，
        #     导致 selected=0 永远不发布。改「通外网即候选」才能保证池子真正长大。
        #   - gemini_or_play：gemini 或 play 任一通过（仍卡 70 分，留作保守档）。
        #   - gemini_and_play：原双过严格档（保留向后兼容）。
        gate=str(rules["nodes"].get("candidate_gate","reachable")).lower()
        google_ok=bool((item.get("google") or {}).get("ok"))
        if gate=="reachable":
            candidate=bool(google_ok or item["gemini"] or item["google_play"])
        elif gate=="gemini_or_play":
            candidate=((item["gemini"] or item["google_play"]) and score>=int(rules["nodes"]["score_threshold"]))
        else:
            candidate=(item["gemini"] and item["google_play"] and score>=int(rules["nodes"]["score_threshold"]))
        asn_obj=ipinfo_data.get("asn"); asn_value=asn_obj.get("asn") if isinstance(asn_obj,dict) else asn_obj
        entry={"fingerprint":fp,"name":node["name"],"score":score,"gemini":item["gemini"],"google_play":item["google_play"],"clean":clean,"lifespan_days":lifespan_days(row),"shenzhen_ping_ms":None,"shenzhen_loss_pct":None,"shenzhen_status":"not-tested","org":ipinfo_data.get("org"),"asn":asn_value}
        report["results"].append(entry); report_lookup[fp]=entry

        shenzhen_cfg=rules.get("shenzhen_probe",{})
        if candidate:
            all_candidate_fps.append(fp)
            if shenzhen_cfg.get("enabled",False):
                cached=cached_shenzhen_result(row,shenzhen_cfg)
                candidate_records.append({"fp":fp,"node":node,"result":cached})
            else:
                selected.append(node)

    shenzhen_cfg=rules.get("shenzhen_probe",{})
    pending=[(rec["fp"],rec["node"]) for rec in candidate_records if rec["result"] is None]
    measured=probe_shenzhen_parallel(pending,shenzhen_cfg) if shenzhen_cfg.get("enabled",False) else {}
    fp_node={}
    for rec in candidate_records:
        fp,node,cached=rec["fp"],rec["node"],rec["result"]
        fp_node[fp]=node
        row=history[fp]
        result=cached if cached is not None else measured.get(fp,{"ok":False,"status":"not-measured"})
        if cached is None:
            save_shenzhen_history(row,result)
        entry=report_lookup[fp]
        entry["shenzhen_ping_ms"]=result.get("avg_ms") if result.get("ok") else None
        entry["shenzhen_loss_pct"]=result.get("loss_pct") if result.get("ok") else None
        entry["shenzhen_status"]=result.get("status","unknown")
        if shenzhen_passes(result,shenzhen_cfg):
            selected.append(node)

    # ★ 深圳闸软化（2026-10-04 修复）：过 gemini+play+score 的候选经深圳延迟闸后仍不足
    #   min_final_nodes 时，用「未过深圳闸」的候选按深圳延迟升序补足，避免整轮 0 发布、
    #   旧（腐烂）的手维护配置被永久保留。深圳延迟仅作「优选」不再作「硬拒」。
    min_final=int(rules["nodes"]["min_final_nodes"])
    if len(selected) < min_final:
        sel_names={n.get("name") for n in selected}
        rest=[fp for fp in all_candidate_fps if fp_node.get(fp) and fp_node[fp].get("name") not in sel_names]
        rest.sort(key=lambda fp: (report_lookup.get(fp,{}).get("shenzhen_ping_ms") or 9e9))
        for fp in rest:
            if len(selected) >= min_final: break
            selected.append(fp_node[fp])
        if rest:
            print("shenzhen_topup: selected %d -> %d (min=%d)" % (len(selected)-len(rest), len(selected), min_final))

    history_path.write_text(json.dumps(history,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
    before=len(selected); selected=[node for node in selected if node.get("network","tcp") in COMPATIBLE_NETWORKS]; report["incompatible_filtered"]=before-len(selected)
    if len(selected)<int(rules["nodes"]["min_final_nodes"]):
        report["published"]=False; report["selected"]=len(selected); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); print(f"Only {len(selected)} nodes passed final threshold; published outputs were preserved."); return
    ranking_meta={}
    for node in selected:
        fp=fingerprint(node); entry=report_lookup.get(fp,{}); row=history.get(fp,{})
        ranking_meta[fp]={"score":entry.get("score",0),"shenzhen_ping_ms":entry.get("shenzhen_ping_ms"),"shenzhen_loss_pct":entry.get("shenzhen_loss_pct"),"stability":min(1.0,row.get("pass_count",0)/max(1,row.get("seen_count",1))),"lifespan":lifespan_days(row),"org":entry.get("org"),"asn":entry.get("asn")}
    ranked=rank_candidates(selected,limit=int(rules["nodes"].get("max_final_nodes",20)),metadata=ranking_meta,max_per_server=int(rules["nodes"].get("max_per_server",2)),max_per_org=int(rules["nodes"].get("max_per_org",3)))
    report["ranking"]=[]
    for i,node in enumerate(ranked,1):
        entry=report_lookup.get(fingerprint(node),{})
        report["ranking"].append({"rank":i,"score":entry.get("score"),"shenzhen_ping_ms":entry.get("shenzhen_ping_ms"),"shenzhen_loss_pct":entry.get("shenzhen_loss_pct"),"server":node.get("server"),"type":node.get("type")})
    print("Top20 Ranking:"); print("Rank | Score | Ping | Loss | Server | Type")
    for r in report["ranking"]:
        ping=r["shenzhen_ping_ms"] if r["shenzhen_ping_ms"] is not None else "-"; loss=r["shenzhen_loss_pct"] if r["shenzhen_loss_pct"] is not None else "-"
        print(f"{r['rank']:>4} | {r['score']:>5} | {str(ping):>5} | {str(loss):>5} | {r['server']} | {r['type']}")
    if len(ranked)<int(rules["nodes"]["min_final_nodes"]):
        report["published"]=False; report["selected"]=len(ranked); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); print(f"Only {len(ranked)} nodes remained after diversity ranking; published outputs were preserved."); return
    build_outputs(ranked,rules); report["published"]=True; report["selected"]=len(ranked); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")

if __name__=="__main__": run()
