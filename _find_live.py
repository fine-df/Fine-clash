# -*- coding: utf-8 -*-
"""经路由器 mihomo delay API 批量实测免费源候选节点的真实可用性（绕过本机直连被墙）。
流程：拉源 -> 解析去重 -> 临时部署(含罗马尼亚保底) -> delay API 并发测活 -> 收集活节点 -> 组新池部署。"""
import sys, io, json, subprocess, time, warnings, concurrent.futures, urllib.request, urllib.parse, yaml
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
import fine_clash as fc

PY = sys.executable
ROUTER = "http://192.168.0.1:9999"

# ---------- 1. 拉源（经代理）----------
import requests
sess = requests.Session()
sess.proxies.update({"http": "http://192.168.0.1:7890", "https": "http://192.168.0.1:7890"})
src = json.load(open("data/sources.json", encoding="utf-8"))
cands = {}
for s in src:
    url = s.get("url")
    if not url:
        continue
    try:
        r = sess.get(url, timeout=25)
        nodes = fc.parse_subscription(r.text) if r.status_code == 200 else []
        _code = r.status_code
    except Exception:
        nodes = []
        _code = "ERR"
    for n in nodes:
        key = (n.get("type"), n.get("server"), n.get("port"))
        if key not in cands:
            cands[key] = n
    print("source %-40s http=%s nodes=%d total=%d" % (s.get("repo", "")[:40], _code, len(nodes), len(cands)), flush=True)
    if len(cands) >= 400:
        break
print("TOTAL unique candidates: %d" % len(cands), flush=True)

# ---------- 2. 保底罗马尼亚 + 候选前 150 ----------
be = subprocess.check_output(["git", "show", "be1fffc:fine_final.yaml"], text=True)
beb = yaml.safe_load(be)
roma = [p for p in beb["proxies"] if "Romania" in p.get("name", "")]
cand_list = list(cands.values())[:150]
all_nodes = roma + cand_list
names = [n["name"] for n in all_nodes]
print("test config: %d nodes (roma=%d + cand=%d)" % (len(all_nodes), len(roma), len(cand_list)), flush=True)

def build_bare_write(nodes, fname="live_clash.yaml"):
    nn = [n["name"] for n in nodes]
    bare = {"proxies": nodes, "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": nn + ["DIRECT"]}]}
    yaml.safe_dump(bare, open(fname, "w", encoding="utf-8"), allow_unicode=True, sort_keys=False)

def deploy():
    subprocess.run([PY, "build_final.py", "live_clash.yaml"], check=True)
    import shutil
    shutil.copy("live_clash.yaml", "fine_final.yaml")
    subprocess.run([PY, "_deploy_cfg.py"], check=True)

# ---------- 3. 临时部署测试配置 ----------
build_bare_write(all_nodes)
deploy()
time.sleep(5)

# ---------- 4. delay API 并发测活 ----------
def probe(name):
    n = urllib.parse.quote(name)
    # ★ 2026-10-04 修正（B4）：分类探针必须与 build_final.FINE_PROBE 一致。
    #   原用 play.google.com/store，但 Fine 组实际探针是 youtube.com，
    #   错位会导致「能开 play 但开不了 youtube」的节点被错放进 Fine。
    url = "%s/proxies/%s/delay?url=https://www.youtube.com&timeout=8000" % (ROUTER, n)
    try:
        r = json.load(urllib.request.urlopen(url, timeout=12))
        return name, r.get("delay")
    except Exception:
        return name, None

live = []
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    for nm, dly in ex.map(probe, names):
        if dly is not None:
            live.append((nm, dly))
live.sort(key=lambda x: x[1])
print("LIVE nodes (youtube reachable): %d" % len(live), flush=True)
for nm, dly in live[:40]:
    print("  %5d  %s" % (dly, nm[:48]), flush=True)

# ---------- 5. 组最终池：活节点(前35) + 罗马尼亚保底 ----------
final_names = set(nm for nm, _ in live[:35])
final_nodes = [n for n in all_nodes if n["name"] in final_names or "Romania" in n.get("name", "")]
seen = set(); fnodes = []
for n in final_nodes:
    if n["name"] in seen:
        continue
    seen.add(n["name"]); fnodes.append(n)
print("FINAL pool: %d nodes (live=%d + roma=%d)" % (len(fnodes), len(final_names), len(roma)), flush=True)
# 写分类（油管/youtube 可达性 + 总体可达）→ build_final.py 据其把池子切成互斥/安全 Bitz/Fine
_final_play = set(nm for nm, _ in live[:35])
_probes = {n["name"]: {"play": n["name"] in _final_play, "ok": n["name"] in _final_play} for n in fnodes}
json.dump(_probes, io.open("live_probes.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print("probes: %d nodes, youtube=%d ok=%d" % (len(_probes), sum(1 for v in _probes.values() if v["play"]), sum(1 for v in _probes.values() if v["ok"])), flush=True)
build_bare_write(fnodes)
deploy()
print("DONE. final nodes=%d" % len(fnodes), flush=True)
