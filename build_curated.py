# -*- coding: utf-8 -*-
"""用 sub_local.txt 优质节点池 + 当前路由器活节点，重建 live_clash.yaml。
不自动部署，只生成；部署由 _deploy_cfg.py 单独触发。"""
import base64, os, sys, socket, json, yaml
sys.path.insert(0, os.path.dirname(__file__))
from fine_clash import parse_subscription, fingerprint

ROOT = os.path.dirname(os.path.abspath(__file__))

# 1) 解码 sub_local.txt
raw = open(os.path.join(ROOT, "sub_local.txt"), encoding="utf-8").read().strip()
decoded = base64.b64decode(raw.replace("\n", "").strip() + "=" * (-len(raw.replace("\n", "").strip()) % 4)).decode("utf-8", "ignore")
curated = parse_subscription(decoded)
print("curated parsed:", len(curated))

# 2) 合并当前 live_clash.yaml 的节点（保底：含当前活着的 Romania [BL]）
cur_live = []
live_path = os.path.join(ROOT, "live_clash.yaml")
if os.path.exists(live_path):
    try:
        cur = yaml.safe_load(open(live_path, encoding="utf-8")) or {}
        cur_live = cur.get("proxies", []) or []
    except Exception as e:
        print("read live_clash err", e)
print("current live_clash proxies:", len(cur_live))

# 3) 合并去重（按 fingerprint）
seen = {}
for n in list(curated) + list(cur_live):
    fp = fingerprint(n)
    seen.setdefault(fp, n)
merged = list(seen.values())
print("merged unique:", len(merged))

# 4) TCP 预筛（server:port 可达性）
def tcp_up(node, timeout=4):
    srv = str(node.get("server") or "").strip()
    try:
        port = int(node.get("port"))
    except Exception:
        return False
    try:
        with socket.create_connection((srv, port), timeout=timeout):
            return True
    except Exception:
        return False

up = [n for n in merged if tcp_up(n)]
down = [n for n in merged if not tcp_up(n)]
print("TCP up:", len(up), " down:", len(down))
for n in up:
    print("  UP  ", n.get("type"), n.get("name", "")[:40])
for n in down:
    print("  DN  ", n.get("type"), n.get("name", "")[:40])

# 5) 写出节点池（含 PROXY 组，满足 build_final 输入要求）
pool = {"proxies": up, "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [n["name"] for n in up] + ["DIRECT"]}]}
pool_path = os.path.join(ROOT, "curated_pool.yaml")
yaml.safe_dump(pool, open(pool_path, "w", encoding="utf-8"), allow_unicode=True, sort_keys=False)
print("wrote", pool_path, len(up), "nodes")

# 6) 跑 build_final.py 生成 live_clash.yaml
import subprocess
r = subprocess.run([sys.executable, "build_final.py", "curated_pool.yaml"], cwd=ROOT, capture_output=True, text=True)
print("build_final rc", r.returncode)
print(r.stdout[-600:])
if r.stderr:
    print("ERR", r.stderr[-400:])

# 7) 结果概览
final = yaml.safe_load(open(live_path, encoding="utf-8"))
print("FINAL live_clash: proxies=%d groups=%s" % (
    len(final.get("proxies", [])), [g["name"] for g in final.get("proxy-groups", [])]))
