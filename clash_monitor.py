import os
import json
import time
import hashlib
import base64
import subprocess
import re
from urllib.parse import urlparse

import requests
import yaml


# =========================
# 基础配置
# =========================

HISTORY_FILE = "node_history.json"
SOURCE_CACHE_FILE = "subscription_sources.json"   # 缓存自动发现的订阅源

MIHOMO_BIN = "clash"
MIXED_PORT = 9050
CONTROLLER_PORT = 9090
CONTROLLER_URL = f"http://127.0.0.1:{CONTROLLER_PORT}"

MAX_CANDIDATES = 100
MAX_PER_SOURCE = 30
MAX_OUTPUT_NODES = 40

SWITCH_WAIT_SECONDS = 1.0
REQUEST_TIMEOUT = 8

# 长寿命相关
STABLE_PASS_COUNT = 2
HISTORY_RESET_HOURS = 48
MIN_SURVIVAL_HOURS = 6

# ========== 地区与清洁度要求 ==========
TW_MAX_LATENCY_MS = 100
TW_REQUIRE_CLEAN = True

US_MAX_LATENCY_MS = 250
US_REQUIRE_CLEAN = True

REQUIRE_GOOGLE = True
REQUIRE_GEMINI_WEB = True
REQUIRE_GEMINI_API = False
GLOBAL_MAX_LATENCY_MS = 400

# GitHub 搜索配置
GITHUB_SEARCH_ENABLED = True
GITHUB_MAX_REPOS = 20                 # 最多搜索多少个仓库
GITHUB_MIN_STARS = 30                 # 最低 Star 数
GITHUB_MAX_DAYS = 45                  # 最近多少天有更新
GITHUB_SEARCH_QUERIES = [
    "free clash stars:>30",
    "free v2ray clash stars:>30",
    "clash 免费 订阅 stars:>20",
    "free nodes clash yaml",
]

# 检测目标
IP_CHECK_URL = (
    "http://ip-api.com/json/"
    "?fields=status,country,countryCode,regionName,city,hosting,proxy,org,isp,query"
)
GOOGLE_TEST_URL = "https://www.google.com/generate_204"
GEMINI_TEST_URL = "https://gemini.google.com/"
GEMINI_API_TEST_URL = "https://generativelanguage.googleapis.com/v1beta/models"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}

GITHUB_TOKEN = os.getenv("GH_TOKEN", "")
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"


# =========================
# 固定兜底订阅源（防止搜索失败）
# =========================

FALLBACK_SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/freefq/free/master/clash",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.yaml",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/yudou66.yaml",
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/free18/v2ray/main/c.yaml",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
]


# =========================
# 历史记录
# =========================

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception as e:
        print(f"⚠️ 历史记录读取失败: {e}")
    return {}


def save_history(history):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"⚠️ 历史记录保存失败: {e}")


# =========================
# 订阅源自动发现
# =========================

def load_source_cache():
    if not os.path.exists(SOURCE_CACHE_FILE):
        return []
    try:
        with open(SOURCE_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def save_source_cache(urls):
    try:
        with open(SOURCE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(urls, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"⚠️ 订阅源缓存保存失败: {e}")


def extract_subscription_urls_from_text(text):
    """从 README 文本中提取可能的 Clash 订阅链接"""
    if not text:
        return []

    # 常见 raw / githubusercontent / jsdelivr 订阅链接
    patterns = [
        r'https?://raw\.githubusercontent\.com/[^\s\'"<>]+?(?:clash|yaml|yml|sub|node|v2ray)[^\s\'"<>]*',
        r'https?://cdn\.jsdelivr\.net/gh/[^\s\'"<>]+?(?:clash|yaml|yml|sub|node)[^\s\'"<>]*',
        r'https?://[^\s\'"<>]+?\.(?:yaml|yml)(?:\?[^\s\'"<>]*)?',
        r'https?://[^\s\'"<>]+?/sub[^\s\'"<>]*',
        r'https?://[^\s\'"<>]+?/clash[^\s\'"<>]*',
    ]

    found = set()
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches:
            m = m.rstrip(").,;\"'")
            if len(m) > 20 and ("http" in m):
                found.add(m)

    return list(found)


def search_github_repos():
    """搜索高 Star 近期更新的免费 Clash 仓库"""
    if not GITHUB_SEARCH_ENABLED:
        return []

    print("\n🔍 开始从 GitHub 自动搜索优质订阅源...")

    repos = []
    headers = HEADERS.copy()
    headers["Accept"] = "application/vnd.github.v3+json"

    for query in GITHUB_SEARCH_QUERIES:
        try:
            url = "https://api.github.com/search/repositories"
            params = {
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": 10,
            }
            resp = requests.get(url, headers=headers, params=params, timeout=15)
            if resp.status_code != 200:
                print(f"  ⚠️ 搜索失败: {query} -> HTTP {resp.status_code}")
                continue

            items = resp.json().get("items", [])
            for item in items:
                stars = item.get("stargazers_count", 0)
                if stars < GITHUB_MIN_STARS:
                    continue
                repos.append({
                    "full_name": item.get("full_name"),
                    "stars": stars,
                    "url": item.get("html_url"),
                    "default_branch": item.get("default_branch", "main"),
                })
            time.sleep(1)  # 避免触发限流
        except Exception as e:
            print(f"  ⚠️ 搜索异常: {e}")

    # 去重
    seen = set()
    unique_repos = []
    for r in repos:
        if r["full_name"] not in seen:
            seen.add(r["full_name"])
            unique_repos.append(r)

    # 按 Star 排序，取前 N 个
    unique_repos.sort(key=lambda x: -x["stars"])
    unique_repos = unique_repos[:GITHUB_MAX_REPOS]

    print(f"  └─ 找到 {len(unique_repos)} 个优质仓库")
    return unique_repos


def fetch_readme_urls(repo):
    """获取仓库 README 并提取订阅链接"""
    full_name = repo["full_name"]
    branch = repo.get("default_branch", "main")

    readme_urls = [
        f"https://raw.githubusercontent.com/{full_name}/{branch}/README.md",
        f"https://raw.githubusercontent.com/{full_name}/{branch}/readme.md",
        f"https://api.github.com/repos/{full_name}/readme",
    ]

    for url in readme_urls:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=12)
            if resp.status_code != 200:
                continue

            # GitHub API 返回的是 base64
            if "api.github.com" in url:
                content = resp.json().get("content", "")
                if content:
                    import base64 as b64
                    text = b64.b64decode(content).decode("utf-8", errors="ignore")
                else:
                    continue
            else:
                text = resp.text

            urls = extract_subscription_urls_from_text(text)
            if urls:
                print(f"  ✅ {full_name} 提取到 {len(urls)} 个链接")
                return urls
        except Exception:
            continue

    return []


def discover_subscription_sources():
    """自动发现 + 合并订阅源"""
    discovered = []

    # 1. 从缓存加载
    cached = load_source_cache()
    if cached:
        print(f"📦 从缓存加载 {len(cached)} 个历史订阅源")
        discovered.extend(cached)

    # 2. GitHub 搜索
    if GITHUB_SEARCH_ENABLED:
        repos = search_github_repos()
        for repo in repos:
            urls = fetch_readme_urls(repo)
            discovered.extend(urls)
            time.sleep(0.8)

    # 3. 加入兜底源
    discovered.extend(FALLBACK_SUBSCRIPTION_URLS)

    # 去重并过滤明显无效链接
    unique = []
    seen = set()
    for u in discovered:
        u = u.strip()
        if not u or u in seen:
            continue
        if "github.com" in u and "/blob/" in u:
            # 把 blob 转成 raw
            u = u.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        seen.add(u)
        unique.append(u)

    print(f"\n📊 最终可用订阅源数量: {len(unique)}")

    # 保存缓存（下次加速）
    save_source_cache(unique)

    return unique


# =========================
# 节点标准化 / 去重
# =========================

def normalize_proxy(proxy):
    if not isinstance(proxy, dict):
        return None

    result = {k: v for k, v in proxy.items() if v is not None}

    server = result.get("server")
    port = result.get("port")
    if not server or not port:
        return None

    try:
        result["port"] = int(port)
    except Exception:
        return None

    if not result.get("name"):
        result["name"] = f"{result.get('type', 'proxy')}-{server}:{port}"

    return result


def proxy_fingerprint(proxy):
    identity = {
        "type": proxy.get("type"),
        "server": proxy.get("server"),
        "port": proxy.get("port"),
        "uuid": proxy.get("uuid"),
        "password": proxy.get("password"),
        "username": proxy.get("username"),
        "cipher": proxy.get("cipher"),
        "tls": proxy.get("tls"),
        "servername": proxy.get("servername"),
        "sni": proxy.get("sni"),
        "network": proxy.get("network"),
        "ws-opts": proxy.get("ws-opts"),
        "grpc-opts": proxy.get("grpc-opts"),
        "reality-opts": proxy.get("reality-opts"),
        "http-opts": proxy.get("http-opts"),
        "h2-opts": proxy.get("h2-opts"),
    }
    raw = json.dumps(identity, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


# =========================
# 订阅解析
# =========================

def try_yaml_parse(text):
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            proxies = data.get("proxies")
            if isinstance(proxies, list):
                return proxies
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def try_base64_yaml_parse(text):
    try:
        compact = "".join(text.split())
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
        decoded_text = decoded.decode("utf-8", errors="ignore")
        return try_yaml_parse(decoded_text)
    except Exception:
        return []


def fetch_proxies_from_url(url):
    print(f"\n📥 获取订阅: {url}")
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        if response.status_code != 200:
            print(f"⚠️ HTTP {response.status_code}")
            return []

        text = response.text.strip()

        proxies = try_yaml_parse(text)
        if proxies:
            print(f"  └─ YAML 解析成功 ({len(proxies)} 个)")
            return proxies

        proxies = try_base64_yaml_parse(text)
        if proxies:
            print(f"  └─ Base64 YAML 解析成功 ({len(proxies)} 个)")
            return proxies

        print("⚠️ 无法解析为 Clash YAML")
    except Exception as e:
        print(f"⚠️ 订阅获取失败: {e}")
    return []


# =========================
# 候选节点收集
# =========================

def collect_candidates(subscription_urls):
    source_lists = []

    for source_url in subscription_urls:
        raw = fetch_proxies_from_url(source_url)
        normalized = []
        for proxy in raw:
            p = normalize_proxy(proxy)
            if p:
                normalized.append(p)
        normalized = normalized[:MAX_PER_SOURCE]
        print(f"  └─ 有效候选: {len(normalized)}")
        if normalized:
            source_lists.append(normalized)

    candidates = []
    seen = set()
    index = 0

    while len(candidates) < MAX_CANDIDATES:
        added_this_round = False
        for source_list in source_lists:
            if index >= len(source_list):
                continue
            proxy = source_list[index]
            key = proxy_fingerprint(proxy)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(proxy)
            added_this_round = True
            if len(candidates) >= MAX_CANDIDATES:
                break
        if not added_this_round:
            break
        index += 1

    print(f"\n📊 最终进入深度测试的候选节点: {len(candidates)}")
    return candidates


# =========================
# Mihomo 配置
# =========================

def build_mihomo_config(candidates):
    internal_proxies = []
    metadata = {}

    for index, proxy in enumerate(candidates, start=1):
        internal_name = f"TEST-{index:03d}"
        item = dict(proxy)
        item["name"] = internal_name
        internal_proxies.append(item)
        metadata[internal_name] = {
            "proxy": proxy,
            "fingerprint": proxy_fingerprint(proxy),
        }

    names = [item["name"] for item in internal_proxies]

    config = {
        "mixed-port": MIXED_PORT,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
        "proxies": internal_proxies,
        "proxy-groups": [
            {
                "name": "TEST",
                "type": "select",
                "proxies": names,
            }
        ],
        "rules": ["MATCH,TEST"],
    }
    return config, metadata


def write_temp_config(config):
    path = "temp_mihomo.yaml"
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
    return path


# =========================
# 启动 / 停止 Mihomo
# =========================

def start_mihomo(config_path):
    print("\n🚀 启动 Mihomo...")
    proc = subprocess.Popen(
        [MIHOMO_BIN, "-f", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            response = requests.get(f"{CONTROLLER_URL}/version", timeout=1)
            if response.status_code == 200:
                print("✅ Mihomo Controller 已启动")
                return proc
        except Exception:
            pass
        time.sleep(0.5)

    print("❌ Mihomo Controller 启动失败")
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        proc.kill()
    return None


def stop_mihomo(proc):
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def select_proxy(proxy_name):
    try:
        response = requests.put(
            f"{CONTROLLER_URL}/proxies/TEST",
            json={"name": proxy_name},
            timeout=3,
        )
        if response.status_code not in (200, 204):
            return False
        time.sleep(SWITCH_WAIT_SECONDS)
        return True
    except Exception:
        return False


# =========================
# 实际测试
# =========================

def test_current_proxy():
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    session.proxies.update({
        "http": f"http://127.0.0.1:{MIXED_PORT}",
        "https": f"http://127.0.0.1:{MIXED_PORT}",
    })

    result = {
        "passed": False,
        "exit_ip": "",
        "country": "",
        "countryCode": "",
        "city": "",
        "org": "",
        "isp": "",
        "hosting": False,
        "proxy": False,
        "google_access": False,
        "gemini_access": False,
        "gemini_api_reachable": False,
        "latency_ms": None,
        "is_clean": False,
        "reason": "",
    }

    try:
        start = time.time()
        response = session.get(IP_CHECK_URL, timeout=REQUEST_TIMEOUT)
        result["latency_ms"] = int((time.time() - start) * 1000)

        if response.status_code != 200:
            result["reason"] = f"IP API HTTP {response.status_code}"
            return result

        data = response.json()
        if data.get("status") != "success":
            result["reason"] = "IP API 返回失败"
            return result

        result["exit_ip"] = data.get("query", "")
        result["country"] = data.get("country", "")
        result["countryCode"] = data.get("countryCode", "")
        result["city"] = data.get("city", "")
        result["org"] = data.get("org", "")
        result["isp"] = data.get("isp", "")
        result["hosting"] = bool(data.get("hosting", False))
        result["proxy"] = bool(data.get("proxy", False))
        result["is_clean"] = (not result["hosting"]) and (not result["proxy"])

        latency = result["latency_ms"]
        cc = result["countryCode"]

        if latency > GLOBAL_MAX_LATENCY_MS:
            result["reason"] = f"延迟过高: {latency}ms"
            return result

        if cc == "TW":
            if latency > TW_MAX_LATENCY_MS:
                result["reason"] = f"台湾节点延迟过高: {latency}ms > {TW_MAX_LATENCY_MS}ms"
                return result
            if TW_REQUIRE_CLEAN and not result["is_clean"]:
                result["reason"] = "台湾节点清洁度不足（机房或代理IP）"
                return result

        if cc == "US":
            if latency > US_MAX_LATENCY_MS:
                result["reason"] = f"美国节点延迟过高: {latency}ms > {US_MAX_LATENCY_MS}ms"
                return result
            if US_REQUIRE_CLEAN and not result["is_clean"]:
                result["reason"] = "美国节点清洁度不足（机房或代理IP）"
                return result

    except Exception as e:
        result["reason"] = f"出口 IP 检测失败: {e}"
        return result

    if REQUIRE_GOOGLE:
        try:
            response = session.get(GOOGLE_TEST_URL, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            if response.status_code in (200, 204):
                result["google_access"] = True
            else:
                result["reason"] = f"Google 连通失败 HTTP {response.status_code}"
                return result
        except Exception as e:
            result["reason"] = f"Google 请求失败: {e}"
            return result

    if REQUIRE_GEMINI_WEB:
        try:
            response = session.get(GEMINI_TEST_URL, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            final_host = urlparse(response.url).hostname or ""
            google_domain = final_host == "google.com" or final_host.endswith(".google.com")
            if response.status_code in range(200, 400) and google_domain:
                result["gemini_access"] = True
            else:
                result["reason"] = f"Gemini Web 不满足条件: HTTP {response.status_code}, host={final_host}"
                return result
        except Exception as e:
            result["reason"] = f"Gemini Web 请求失败: {e}"
            return result

    if REQUIRE_GEMINI_API:
        try:
            response = session.get(GEMINI_API_TEST_URL, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            if response.status_code in (200, 400, 401, 403, 404):
                result["gemini_api_reachable"] = True
            else:
                result["reason"] = f"Gemini API 网络层异常: HTTP {response.status_code}"
                return result
        except Exception as e:
            result["reason"] = f"Gemini API 网络层失败: {e}"
            return result

    result["passed"] = True
    return result


# =========================
# 历史状态更新
# =========================

def update_history(history, fingerprint, current_time, test_result, original_name):
    old = history.get(fingerprint, {})
    last_seen = old.get("last_seen", 0)

    if last_seen and current_time - last_seen > HISTORY_RESET_HOURS * 3600:
        first_seen = current_time
        pass_count = 1
    else:
        first_seen = old.get("first_seen", current_time)
        pass_count = int(old.get("pass_count", 0)) + 1

    history[fingerprint] = {
        "first_seen": first_seen,
        "last_seen": current_time,
        "pass_count": pass_count,
        "last_latency_ms": test_result["latency_ms"],
        "last_exit_ip": test_result["exit_ip"],
        "country": test_result["country"],
        "city": test_result["city"],
        "org": test_result["org"],
        "isp": test_result["isp"],
        "hosting": test_result["hosting"],
        "proxy": test_result["proxy"],
        "name": original_name,
    }
    return history[fingerprint]


# =========================
# 输出最终配置
# =========================

def build_final_config(passed_nodes):
    proxies = []
    for node in passed_nodes:
        proxy = dict(node["proxy"])
        proxy["name"] = node["display_name"]
        proxies.append(proxy)

    proxy_names = [p["name"] for p in proxies]

    tw_names = [n for n in proxy_names if "🇹🇼" in n]
    us_names = [n for n in proxy_names if "🇺🇸" in n]

    final_config = {
        "mixed-port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": proxy_names + ["DIRECT"],
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names,
            },
            {
                "name": "🇹🇼 台湾",
                "type": "select",
                "proxies": tw_names if tw_names else ["DIRECT"],
            },
            {
                "name": "🇺🇸 美国",
                "type": "select",
                "proxies": us_names if us_names else ["DIRECT"],
            },
            {
                "name": "🤖 Gemini",
                "type": "select",
                "proxies": ["♻️ 自动选择", "🚀 节点选择", "🇹🇼 台湾", "🇺🇸 美国"],
            },
        ],
        "rules": [
            # 国内直连
            "GEOIP,CN,DIRECT",
            "DOMAIN-SUFFIX,cn,DIRECT",
            "DOMAIN-KEYWORD,baidu,DIRECT",
            "DOMAIN-KEYWORD,alibaba,DIRECT",
            "DOMAIN-KEYWORD,tencent,DIRECT",
            "DOMAIN-KEYWORD,bilibili,DIRECT",
            "DOMAIN-KEYWORD,qq.com,DIRECT",
            "DOMAIN-KEYWORD,163.com,DIRECT",
            "DOMAIN-KEYWORD,taobao,DIRECT",
            "DOMAIN-KEYWORD,jd.com,DIRECT",
            "DOMAIN-KEYWORD,weixin,DIRECT",
            "DOMAIN-KEYWORD,wechat,DIRECT",

            # Gemini / Google
            "DOMAIN-SUFFIX,gemini.google.com,🤖 Gemini",
            "DOMAIN-SUFFIX,googleapis.com,🤖 Gemini",
            "DOMAIN-SUFFIX,generativelanguage.googleapis.com,🤖 Gemini",
            "DOMAIN-SUFFIX,google.com,🤖 Gemini",

            # 兜底
            "MATCH,🚀 节点选择",
        ],
    }
    return final_config


# =========================
# 主流程
# =========================

def run_agent():
    current_time = int(time.time())
    history = load_history()

    # ========== 自动更新订阅源 ==========
    subscription_urls = discover_subscription_sources()

    candidates = collect_candidates(subscription_urls)

    if not candidates:
        print("\n❌ 没有获得有效候选节点")
        save_history(history)
        empty_config = {
            "mixed-port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "proxies": [],
        }
        with open("live_clash.yaml", "w", encoding="utf-8") as f:
            yaml.safe_dump(empty_config, f, allow_unicode=True, sort_keys=False)
        return

    config, metadata = build_mihomo_config(candidates)
    config_path = write_temp_config(config)
    proc = None
    passed_nodes = []

    try:
        proc = start_mihomo(config_path)
        if proc is None:
            return

        print(f"\n🔎 开始逐节点实际测试，共 {len(metadata)} 个\n")

        for internal_name, meta in metadata.items():
            proxy = meta["proxy"]
            fingerprint = meta["fingerprint"]
            original_name = proxy.get("name", internal_name)

            print(f"▶ {internal_name} | {original_name}")

            if not select_proxy(internal_name):
                print("  ❌ Mihomo 节点切换失败")
                continue

            test_result = test_current_proxy()

            if not test_result["passed"]:
                print(f"  ❌ 淘汰: {test_result['reason']}")
                continue

            history_item = update_history(
                history, fingerprint, current_time, test_result, original_name
            )

            pass_count = history_item["pass_count"]
            survival_hours = int((current_time - history_item["first_seen"]) / 3600)
            latency = test_result["latency_ms"]

            if pass_count < STABLE_PASS_COUNT:
                print(f"  ⏳ 通过但次数不足 ({pass_count}/{STABLE_PASS_COUNT})，暂不输出")
                continue

            cc = test_result["countryCode"]
            if cc == "TW":
                flag = "🇹🇼"
            elif cc == "US":
                flag = "🇺🇸"
            else:
                flag = "🌐"

            clean_tag = "洁" if test_result["is_clean"] else "机"

            display_name = (
                f"{flag}{clean_tag} [{latency}ms|{survival_hours}h|{pass_count}次] {original_name}"
            )

            passed_nodes.append({
                "proxy": proxy,
                "display_name": display_name,
                "fingerprint": fingerprint,
                "test": test_result,
                "pass_count": pass_count,
                "survival_hours": survival_hours,
                "latency": latency,
                "countryCode": cc,
                "is_clean": test_result["is_clean"],
            })

            print(
                f"  ✅ 通过 | {cc} | IP={test_result['exit_ip']} | "
                f"{test_result['city']} | {latency}ms | 存活{survival_hours}h | 通过{pass_count}次"
            )

    finally:
        save_history(history)
        stop_mihomo(proc)
        if os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception:
                pass

    def sort_key(x):
        cc = x["countryCode"]
        is_tw = 0 if cc == "TW" else 1
        is_us_clean = 0 if (cc == "US" and x["is_clean"]) else 1
        long_life = 0 if x["survival_hours"] >= MIN_SURVIVAL_HOURS else 1

        return (
            is_tw,
            is_us_clean,
            long_life,
            -x["survival_hours"],
            -x["pass_count"],
            x["latency"] or 999999,
        )

    passed_nodes.sort(key=sort_key)
    passed_nodes = passed_nodes[:MAX_OUTPUT_NODES]

    final_config = build_final_config(passed_nodes)

    with open("live_clash.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(final_config, f, allow_unicode=True, sort_keys=False)

    print("\n" + "=" * 60)
    print(f"✅ 最终输出节点: {len(passed_nodes)} 个")
    print("=" * 60)
    for node in passed_nodes:
        t = node["test"]
        print(f"{node['display_name']} | {t['exit_ip']} | {t.get('org', '')}")


if __name__ == "__main__":
    run_agent()
