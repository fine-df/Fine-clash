"""
discover_broad.py — 宽口径 GitHub 订阅源发现（2026-10-04）
-----------------------------------------------------------------
策略：
  1. 复用既有 data/candidate_repos.json（141 个高星仓）+ 新宽查询 GitHub 搜索，
     汇总候选仓库全集（去重）。
  2. 对每个仓库，直接打 raw.githubusercontent.com 试一组常见订阅文件路径，
     绕过 tree API（core API 60/hr 限额），raw CDN 不限流。
  3. 解析出 ≥ min_nodes_per_source 个节点的文件即记为有效源，写回 data/sources.json。
  4. GitHub search 部分按 ~7s 间隔限速（匿名 10/min）。

仅产出 sources.json，节点实测/发布由 fine_clash.py run() 接管。
"""
from __future__ import annotations
import json, os, sys, time, requests
from pathlib import Path
from datetime import datetime, timedelta, timezone
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fine_clash as fc

ROOT = Path(__file__).resolve().parent
UA = fc.UA
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA})

# 常见订阅文件路径（相对仓库根），按可能性排序；分支先试 main 再 master
CANDIDATE_PATHS = [
    "sub", "sub.yaml", "sub.yml", "sub.txt", "sub.conf", "sub.base64",
    "subscribe", "subscribe.yaml", "subscribe.yml", "subscribe.txt",
    "subscription", "subscription.yaml",
    "clash", "clash.yaml", "clash.yml", "clash.config.yaml", "clashconfig.yaml",
    "v2ray", "v2ray.yaml", "v2ray.yml", "v2ray.txt",
    "nodes", "nodes.txt", "nodes.yaml",
    "node", "node.txt",
    "free", "free.yaml", "free.txt",
    "config.yaml", "config.yml", "proxies.yaml", "proxy.yaml", "proxy.txt",
    "list.txt", "list.yaml", "raw.txt", "out/clash.yaml", "out/config.yaml",
    "api", "README.md", "readme.md",
]
BRANCHES = ["main", "master"]


def collect_repo_names():
    names = {}
    # 1) 既有 candidate_repos.json
    cr = ROOT / "data" / "candidate_repos.json"
    if cr.is_file():
        try:
            for r in json.loads(cr.read_text(encoding="utf-8")):
                fn = r.get("full_name") or r.get("name")
                if fn and "/" in fn:
                    names[fn.lower()] = fn
        except Exception as e:
            print("candidate_repos read err:", e)
    # 2) 新宽查询 GitHub 搜索（限速）
    rules = fc.load_rules()
    queries = rules["sources"].get("queries", [])
    print("broad search: %d queries (paced 7s)" % len(queries))
    for q in queries:
        try:
            suffix = f" pushed:>={recent_cutoff(rules)}" if rules["sources"].get("require_recent_push", False) else ""
            params = {"q": f"{q}{suffix}", "sort": "stars", "order": "desc", "per_page": rules["sources"].get("repositories_per_query", 20)}
            r = SESSION.get("https://api.github.com/search/repositories", params=params, timeout=20)
            if r.status_code == 403:
                print("  rate-limited on query, stopping search"); break
            data = r.json()
            items = data.get("items", [])
            for it in items:
                if int(it.get("stargazers_count", 0)) < int(rules["sources"].get("min_stars", 30)):
                    continue
                fn = it.get("full_name")
                if fn: names[fn.lower()] = fn
            print("  q=%-70s -> +%d (total %d)" % (q[:70], len(items), len(names)))
        except Exception as e:
            print("  query err:", e)
        time.sleep(7)
    return list(names.values())


def recent_cutoff(rules):
    from datetime import datetime, timedelta, timezone
    d = int(rules["sources"].get("recent_days", 30))
    return (datetime.now(timezone.utc) - timedelta(days=d)).date().isoformat()


def dated_candidate_paths(days=7):
    today = datetime.now(timezone.utc).date()
    out = []
    for i in range(days):
        day = today - timedelta(days=i)
        stamp = day.strftime("%Y%m%d")
        out.extend([
            f"clash{stamp}.yml", f"clash{stamp}.yaml",
            f"sub{stamp}.txt", f"sub{stamp}.yaml",
            f"v2ray{stamp}.txt", f"v2ray{stamp}.yaml",
        ])
    return out

def try_repo(full_name):
    owner, name = full_name.split("/", 1)
    rules = fc.load_rules()
    min_nodes = int(rules["sources"].get("min_nodes_per_source", 2))
    max_bytes = int(rules["sources"].get("max_source_bytes", 8000000))
    paths = list(dict.fromkeys(dated_candidate_paths() + CANDIDATE_PATHS))
    # 最近日期型订阅优先，再试固定入口；避免长期抓旧日文件。
    for branch in BRANCHES:
        for path in paths:
            url = f"https://raw.githubusercontent.com/{owner}/{name}/{branch}/{path}"
            try:
                r = SESSION.get(url, timeout=12, allow_redirects=True)
                if r.status_code != 200 or len(r.content) > max_bytes:
                    continue
                nodes = fc.parse_subscription(r.text)
                if len(nodes) >= min_nodes:
                    return {"url": url, "repo": full_name, "path": path, "branch": branch, "nodes": len(nodes)}
            except requests.RequestException:
                continue
    return None

def main():
    repos = collect_repo_names()
    MAX_REPOS = 220
    if len(repos) > MAX_REPOS:
        repos = repos[:MAX_REPOS]
    print("total candidate repos: %d (capped %d)" % (len(repos), MAX_REPOS))
    # 读已有 sources.json 作为起点（保留之前已验证的）
    src_path = ROOT / "data" / "sources.json"
    existing = []
    if src_path.is_file():
        try: existing = json.loads(src_path.read_text(encoding="utf-8"))
        except Exception: existing = []
    existing_urls = {s.get("url") for s in existing if isinstance(s, dict)}
    found = list(existing)
    checked = 0
    for fn in repos:
        if fn.lower() in {s.get("repo", "").lower() for s in existing if isinstance(s, dict)}:
            continue  # 已验证过的仓跳过
        res = try_repo(fn)
        checked += 1
        if res:
            if res["url"] not in existing_urls:
                found.append(res); existing_urls.add(res["url"])
                print("  + %s/%s (%d nodes) %s" % (res["repo"], res["path"], res["nodes"], res["branch"]))
        if checked % 20 == 0:
            print("  ...checked %d, found %d valid sources" % (checked, len(found) - len(existing)))
    src_path.parent.mkdir(parents=True, exist_ok=True)
    src_path.write_text(json.dumps(found, ensure_ascii=False, indent=2), encoding="utf-8")
    print("DONE: %d repos checked, %d valid subscription sources written to data/sources.json" % (checked, len(found)))


if __name__ == "__main__":
    main()
