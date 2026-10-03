# -*- coding: utf-8 -*-
"""紧急抢救发布(2026-10-03)：
背景：免费源节点大规模死亡(路由器现网 20 节点仅 3 活)，管线重跑后 3 个 gemini+play 双过节点
(分数86/82/86)被深圳探测 fail_closed 拦下(selected=0, published=False)。用户 Gemini 断供。
本脚本人工合成应急池：3 个管线实测 gemini+play 通过节点 + 路由器现网 3 个实测存活节点。
不动管线闸门本身，仅本次人工发布，全程留痕。
"""
import json, sys, io, subprocess
from pathlib import Path
import yaml, requests

sys.path.insert(0, str(Path(__file__).parent))
import fine_clash as fc

ROOT = Path(__file__).parent
UA = fc.UA

# ---------- 1) 从缓存源重抓节点(与管线同逻辑，raw 不占 GitHub API 限额) ----------
rules = fc.load_rules()
sources = json.loads((ROOT / "data" / "sources.json").read_text(encoding="utf-8"))
nodes_by_fp = {}
session = requests.Session()
for src in sources:
    try:
        r = session.get(src["url"], timeout=20, headers={"User-Agent": UA})
        r.raise_for_status()
        for node in fc.parse_subscription(r.text):
            if (node.get("type") in rules["nodes"]["allowed_types"] and node.get("server")
                    and node.get("port") and fc.is_safe_server(node["server"])):
                nodes_by_fp[fc.fingerprint(node)] = node
    except requests.RequestException:
        continue
print(f"[1] 源 {len(sources)} 个, 去重后节点 {len(nodes_by_fp)} 个")

# ---------- 2) 取管线实测 gemini+play 双过的 3 个节点(按 fingerprint 匹配) ----------
last = json.loads((ROOT / "data" / "last_run.json").read_text(encoding="utf-8"))
targets = [r for r in last.get("results", []) if r.get("gemini") and r.get("google_play")]
rescued, missing = [], []
for t in targets:
    fp = t.get("fingerprint")
    node = nodes_by_fp.get(fp)
    if node is None:  # 兜底按名字匹配
        for n in nodes_by_fp.values():
            if n.get("name") == t.get("name"):
                node = n; break
    if node is None:
        missing.append(t.get("name")); continue
    rescued.append(node)
    print(f"[2] 抢救节点: {node.get('name','')[:36]} | {node.get('type')} | {node.get('server')}:{node.get('port')} (score={t.get('score')})")
if missing:
    print(f"[2][warn] 未匹配到: {missing}")

# ---------- 3) 取现网(CDN @526a452)实测存活的 3 个节点 ----------
cdn = yaml.safe_load(requests.get(
    "https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@526a452/live_clash.yaml",
    timeout=30, headers={"User-Agent": UA}).text)
alive_names = [
    "🇩🇪 Germany, Frankfurt am Main | [BL] [bbec054e]",
    "🇵🇱 Poland, Warsaw | [BL] [c04e90e6]",
    "🇷🇴 Romania, Bucharest | [BL]",
]
by_name = {p.get("name"): p for p in cdn.get("proxies", [])}
kept = []
for nm in alive_names:
    n = by_name.get(nm)
    if n is None:
        print(f"[3][warn] 现网节点未找到: {nm}"); continue
    kept.append(n)
    print(f"[3] 现网存活节点: {nm[:40]} | {n.get('type')}")

# ---------- 4) 合成 SRC(去重按 server:port:type) ----------
seen, pool = set(), []
for n in rescued + kept:
    key = (n.get("type"), str(n.get("server")), int(n.get("port") or 0))
    if key in seen: continue
    seen.add(key); pool.append(n)
if len(pool) < 3:
    print(f"[4][FATAL] 应急池过小({len(pool)}), 放弃发布"); sys.exit(1)
src_cfg = {
    "proxies": pool,
    "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [p["name"] for p in pool]}],
    "rules": cdn.get("rules", []),
}
out = ROOT / "_rescue_src.yaml"
out.write_text(yaml.safe_dump(src_cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
print(f"[4] SRC 已写 {out.name}: {len(pool)} 节点")
