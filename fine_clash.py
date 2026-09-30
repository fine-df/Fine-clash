from __future__ import annotations
import base64, hashlib, ipaddress, json, os, re, shutil, subprocess, tempfile, time
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
]

def load_rules():
    return yaml.safe_load((ROOT/"config.yaml").read_text(encoding="utf-8"))

def _safe_int(value, default=0):
    try: return int(str(value).strip())
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
        return f"trojan://{quote(str(node.get('password','')),safe='')}@{host}:{port}?{'&'.join(q)}#{name}"
    if kind=="ss":
        raw=f"{node.get('cipher','chacha20-ietf-poly1305')}:{node.get('password','')}@{host}:{port}"
        return f"ss://{base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')}#{name}"
    if kind=="vmess":
        ws=node.get("ws-opts",{})
        payload={"v":"2","ps":node.get("name","vmess"),"add":server,"port":str(port),"id":node.get("uuid",""),"aid":str(node.get("alterId",0)),"scy":node.get("cipher","auto"),"net":node.get("network","tcp"),"type":"none","host":ws.get("headers",{}).get("Host",""),"path":ws.get("path",""),"tls":"tls" if node.get("tls") else ""}
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
    if result.get("score",0)>=70: row["pass_count"]+=1
    if result.get("gemini"): row["gemini_pass_count"]+=1
    if result.get("google_play"): row["play_pass_count"]+=1
    return row

def lifespan_days(row):
    try: return max(0,(date.today()-date.fromisoformat(row["first_seen"])).days)
    except Exception: return 0

def clean_score(ipinfo,google_result):
    if not ipinfo: return 60
    score=80; org=str(ipinfo.get("org","")).lower()
    markers=("amazon","aws","google cloud","azure","microsoft","digitalocean","vultr","linode","hetzner","contabo","oracle cloud")
    if any(x in org for x in markers): score-=20
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
    def __init__(self,binary,cfg):
        self.binary=binary; self.cfg=cfg; self.proc=None; self.tmp=None; self.session=requests.Session()
    def start(self,nodes):
        names=[]; proxies=[]
        for idx,node in enumerate(nodes):
            name=f"N{idx:03d}"; names.append(name); proxy=dict(node); proxy["name"]=name; proxies.append(proxy)
        config={"mixed-port":17890,"allow-lan":False,"mode":"rule","log-level":"error","external-controller":"127.0.0.1:19090","proxies":proxies,"proxy-groups":[{"name":"TEST","type":"select","proxies":names}],"rules":["GEOSITE,CN,DIRECT","GEOIP,CN,DIRECT","MATCH,TEST"]}
        self.tmp=Path(tempfile.mkdtemp(prefix="fine-clash-")); (self.tmp/"config.yaml").write_text(yaml.safe_dump(config,allow_unicode=True,sort_keys=False),encoding="utf-8")
        self.proc=subprocess.Popen([self.binary,"-d",str(self.tmp)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(float(self.cfg["controller_startup_seconds"])); return names
    def choose(self,name):
        response=self.session.put("http://127.0.0.1:19090/proxies/TEST",json={"name":name},timeout=5); response.raise_for_status(); time.sleep(float(self.cfg["switch_wait_seconds"]))
    def request(self,url,parse_json=False):
        started=time.perf_counter(); proxy={"http":"http://127.0.0.1:17890","https":"http://127.0.0.1:17890"}
        try:
            response=self.session.get(url,headers={"User-Agent":UA},proxies=proxy,timeout=float(self.cfg["test_timeout_seconds"]),allow_redirects=True)
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
        try:
            for idx,node in enumerate(nodes):
                self.choose(names[idx]); gemini=self.request(checks["gemini_url"]); play=self.request(checks["google_play_url"]); google=self.request(checks["google_204_url"]); ip=self.request(checks["ipinfo_url"],True)
                results.append({"node":node,"gemini":gemini["ok"],"google_play":play["ok"],"google":google,"ipinfo":ip.get("data") if ip["ok"] else None})
        finally: self.stop()
        return results
    def stop(self):
        if self.proc is None: return
        self.proc.terminate()
        try: self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired: self.proc.kill()
        self.proc=None

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
    config={"mixed-port":7890,"allow-lan":True,"mode":"rule","proxies":nodes,"proxy-groups":[{"name":"PROXY","type":"select","proxies":names+["DIRECT"]}],"rules":route_rules}
    clash_path=ROOT/output_rules["output"]["clash_file"]; clash_path.parent.mkdir(parents=True,exist_ok=True); clash_path.write_text(yaml.safe_dump(config,allow_unicode=True,sort_keys=False),encoding="utf-8")
    uris=[uri for node in nodes if (uri:=node_to_uri(node))]
    v2ray_path=ROOT/output_rules["output"]["v2ray_file"]; v2ray_path.parent.mkdir(parents=True,exist_ok=True); v2ray_path.write_text(base64.b64encode("\n".join(uris).encode()).decode()+"\n",encoding="utf-8")

def run():
    rules=load_rules(); source_path=ROOT/rules["output"]["source_file"]; history_path=ROOT/rules["output"]["history_file"]; report_path=ROOT/rules["output"]["report_file"]
    sources=GitHubDiscovery(os.getenv("GITHUB_TOKEN"),rules["sources"]).discover(); source_path.parent.mkdir(parents=True,exist_ok=True); source_path.write_text(json.dumps(sources,ensure_ascii=False,indent=2),encoding="utf-8")
    nodes_by_fp={}; session=requests.Session()
    for source in sources:
        try:
            response=session.get(source["url"],timeout=20,headers={"User-Agent":UA}); response.raise_for_status()
            for node in parse_subscription(response.text):
                if node.get("type") in rules["nodes"]["allowed_types"] and node.get("server") and node.get("port") and is_safe_server(node["server"]): nodes_by_fp[fingerprint(node)]=node
        except requests.RequestException: continue
    nodes=list(nodes_by_fp.values())[:int(rules["nodes"]["max_test_nodes"])]
    binary=shutil.which("mihomo") or shutil.which("clash")
    if not nodes: raise RuntimeError("No valid nodes discovered; published outputs were preserved.")
    if not binary: raise RuntimeError("mihomo binary not found")
    checks=rules["checks"]; tester_cfg={**rules["nodes"],"challenge_markers":checks["challenge_markers"],"success_statuses":checks["success_statuses"]}; history=load_history(history_path); selected=[]
    report={"generated_at":datetime.now(timezone.utc).isoformat(),"sources":len(sources),"nodes_discovered":len(nodes),"results":[]}
    for item in MihomoTester(binary,tester_cfg).test_nodes(nodes,checks):
        node,fp=item["node"],fingerprint(item["node"]); row=history.get(fp,{"first_seen":date.today().isoformat()}); life=lifespan_days(row); clean=clean_score(item.get("ipinfo"),item["google"]); stability=min(1.0,row.get("pass_count",0)/max(1,row.get("seen_count",1)))
        score=total_score(gemini=item["gemini"],google_play=item["google_play"],google=item["google"],clean=clean,lifespan=life,stability=stability); row=update_history(history,fp,{"score":score,"gemini":item["gemini"],"google_play":item["google_play"]})
        report["results"].append({"fingerprint":fp,"name":node["name"],"score":score,"gemini":item["gemini"],"google_play":item["google_play"],"clean":clean,"lifespan_days":lifespan_days(row)})
        if item["gemini"] and item["google_play"] and score>=int(rules["nodes"]["score_threshold"]): selected.append(node)
    history_path.write_text(json.dumps(history,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
    if len(selected)<int(rules["nodes"]["min_final_nodes"]):
        report["published"]=False; report["selected"]=len(selected); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); print(f"Only {len(selected)} nodes passed final threshold; published outputs were preserved."); return
    selected.sort(key=lambda node:node["name"]); build_outputs(selected,rules); report["published"]=True; report["selected"]=len(selected); report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")

if __name__=="__main__": run()
