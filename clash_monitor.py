import os
import re
import json
import time
import base64
import hashlib
import subprocess
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

import requests
import yaml


# =========================================================
# 基础配置
# =========================================================

HISTORY_FILE = "node_history.json"
SOURCE_REGISTRY_FILE = "source_registry.json"

MIHOMO_BIN = "clash"

MIXED_PORT = 9050
CONTROLLER_PORT = 9090
CONTROLLER_URL = f"http://127.0.0.1:{CONTROLLER_PORT}"

MAX_CANDIDATES = 80
MAX_PER_SOURCE = 20

REQUEST_TIMEOUT = 8
SWITCH_WAIT_SECONDS = 1.0

HISTORY_RESET_HOURS = 48

# ---------------------------------------------------------
# GitHub 动态发现
# ---------------------------------------------------------

GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"

RECENT_DAYS = 180
MIN_REPO_STARS = 100
FALLBACK_MIN_REPO_STARS = 20

TOP_REPOS_PER_QUERY = 5
MAX_DISCOVERED_REPOS = 15
MAX_DISCOVERED_URLS = 30

GITHUB_SEARCH_QUERIES = [
    "clash proxy subscription",
    "clash free nodes",
    "mihomo subscription",
    "clash yaml nodes",
    "free proxy clash",
]

# 固定保底源
PINNED_SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/er26/free/main/clash.yaml",
    "https://raw.githubusercontent.com/nodefree/nodefree.github.io/main/clash/clash.yaml",
    "https://raw.githubusercontent.com/Pawroid/Free-Node/main/clash.yaml",
]

# ---------------------------------------------------------
# 网络检测
# ---------------------------------------------------------

IP_CHECK_URL = (
    "http://ip-api.com/json/"
    "?fields=status,country,countryCode,regionName,city,"
    "hosting,proxy,org,isp,query"
)

GOOGLE_TEST_URL = "https://www.google.com/generate_204"
GEMINI_TEST_URL = "https://gemini.google.com/"
GEMINI_API_TEST_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models"
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/154.0.0.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}

GITHUB_TOKEN = os.getenv("GH_TOKEN", "")

if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": GITHUB_API_VERSION,
    "User-Agent": USER_AGENT,
}

if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"


# =========================================================
# 通用工具
# =========================================================

def now_ts():
    return int(time.time())


def safe_json_load(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return data

    except Exception as e:
        print(f"⚠️ JSON 读取失败 {path}: {e}")
        return default


def safe_json_save(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                ensure_ascii=False,
                indent=2,
            )
    except Exception as e:
        print(f"⚠️ JSON 保存失败 {path}: {e}")


def sha1_text(text):
    return hashlib.sha1(
        text.encode("utf-8")
    ).hexdigest()[:20]


# =========================================================
# GitHub 动态仓库发现
# =========================================================

def github_get(path, params=None):
    url = f"{GITHUB_API}{path}"

    try:
        response = requests.get(
            url,
            headers=GITHUB_HEADERS,
            params=params,
            timeout=15,
        )

        if response.status_code != 200:
            print(
                f"⚠️ GitHub API {response.status_code}: "
                f"{path}"
            )
            return None

        return response.json()

    except Exception as e:
        print(f"⚠️ GitHub API 请求失败: {e}")
        return None


def discover_github_repositories():
    """
    自动发现：
    - 高 Star
    - 最近持续更新
    - 与 Clash / Mihomo / Proxy / Subscription 有关

    不是一次性抓固定仓库。
    每次运行都会重新搜索。
    """

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(days=RECENT_DAYS)
    ).strftime("%Y-%m-%d")

    repositories = {}

    print("\n🔎 开始扫描 GitHub 高质量候选仓库...")

    for keyword in GITHUB_SEARCH_QUERIES:
        query = (
            f"{keyword} "
            f"stars:>={MIN_REPO_STARS} "
            f"pushed:>={cutoff}"
        )

        data = github_get(
            "/search/repositories",
            params={
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": TOP_REPOS_PER_QUERY,
            },
        )

        items = []

        if data:
            items = data.get("items", [])

        # 如果严格条件没有结果，降低 Star 门槛
        if not items:
            query = (
                f"{keyword} "
                f"stars:>={FALLBACK_MIN_REPO_STARS} "
                f"pushed:>={cutoff}"
            )

            data = github_get(
                "/search/repositories",
                params={
                    "q": query,
                    "sort": "stars",
                    "order": "desc",
                    "per_page": TOP_REPOS_PER_QUERY,
                },
            )

            if data:
                items = data.get("items", [])

        print(
            f"  └─ {keyword}: "
            f"{len(items)} 个候选仓库"
        )

        for repo in items:
            full_name = repo.get("full_name")

            if not full_name:
                continue

            repositories[full_name] = {
                "full_name": full_name,
                "html_url": repo.get("html_url"),
                "default_branch": (
                    repo.get("default_branch")
                    or "main"
                ),
                "stars": int(
                    repo.get("stargazers_count") or 0
                ),
                "forks": int(
                    repo.get("forks_count") or 0
                ),
                "pushed_at": repo.get("pushed_at"),
                "description": (
                    repo.get("description") or ""
                ),
            }

    # 高 Star + 最近更新时间
    repo_list = list(repositories.values())

    repo_list.sort(
        key=lambda r: (
            -r["stars"],
            r["pushed_at"] or "",
        )
    )

    repo_list = repo_list[:MAX_DISCOVERED_REPOS]

    print(
        f"\n✅ 最终纳入 GitHub 监控仓库: "
        f"{len(repo_list)}"
    )

    for repo in repo_list:
        print(
            f"  ⭐ {repo['stars']:>6} "
            f"{repo['full_name']} "
            f"| {repo['pushed_at']}"
        )

    return repo_list


def score_subscription_path(path):
    """
    对仓库文件路径进行订阅候选评分。
    """

    lower = path.lower()

    # 明显不是节点文件
    bad_words = [
        ".github/",
        "workflow",
        "test/",
        "tests/",
        "docs/",
        "example/",
        "examples/",
        "readme",
        "license",
    ]

    for word in bad_words:
        if word in lower:
            return -999

    ext_score = 0

    if lower.endswith(".yaml"):
        ext_score = 10
    elif lower.endswith(".yml"):
        ext_score = 10
    elif lower.endswith(".txt"):
        ext_score = 6
    elif lower.endswith(".conf"):
        ext_score = 3
    else:
        return -999

    score = ext_score

    keywords = [
        ("clash", 12),
        ("mihomo", 12),
        ("subscribe", 10),
        ("subscription", 10),
        ("sub", 5),
        ("proxy", 8),
        ("proxies", 8),
        ("node", 7),
        ("nodes", 7),
        ("free", 5),
        ("merge", 4),
        ("all", 2),
    ]

    for word, weight in keywords:
        if word in lower:
            score += weight

    return score


def repo_tree(repo):
    full_name = repo["full_name"]
    branch = repo["default_branch"]

    encoded_branch = quote(
        branch,
        safe=""
    )

    path = (
        f"/repos/{full_name}/git/trees/"
        f"{encoded_branch}"
    )

    return github_get(
        path,
        params={"recursive": "1"},
    )


def discover_subscription_urls(repo):
    """
    从仓库 Git Tree 自动寻找：
    Clash / Mihomo / proxy / subscription 文件。
    """

    tree_data = repo_tree(repo)

    if not tree_data:
        return []

    tree = tree_data.get("tree", [])

    candidates = []

    for item in tree:
        if item.get("type") != "blob":
            continue

        path = item.get("path", "")
        size = item.get("size")

        if size is not None and size > 3_000_000:
            continue

        score = score_subscription_path(path)

        if score < 15:
            continue

        candidates.append(
            {
                "path": path,
                "score": score,
                "size": size,
            }
        )

    candidates.sort(
        key=lambda x: (
            -x["score"],
            x["path"],
        )
    )

    urls = []

    for item in candidates[:8]:
        raw_url = (
            "https://raw.githubusercontent.com/"
            f"{repo['full_name']}/"
            f"{quote(repo['default_branch'], safe='')}/"
            f"{quote(item['path'], safe='/')}"
        )

        urls.append(
            {
                "url": raw_url,
                "repo": repo["full_name"],
                "stars": repo["stars"],
                "path": item["path"],
                "score": item["score"],
            }
        )

    return urls


def discover_sources():
    """
    动态发现 + 固定保底源。
    """

    repos = discover_github_repositories()

    discovered = []

    for repo in repos:
        urls = discover_subscription_urls(repo)

        if urls:
            print(
                f"  📂 {repo['full_name']} "
                f"发现 {len(urls)} 个订阅文件"
            )

        discovered.extend(urls)

    # 按仓库 Star + 文件评分排序
    discovered.sort(
        key=lambda x: (
            -x["stars"],
            -x["score"],
        )
    )

    discovered = discovered[
        :MAX_DISCOVERED_URLS
    ]

    # 固定保底源
    final_sources = []

    for url in PINNED_SUBSCRIPTION_URLS:
        final_sources.append(
            {
                "url": url,
                "repo": "PINNED",
                "stars": 0,
                "path": "",
                "score": 0,
            }
        )

    # 动态源在前
    for item in discovered:
        final_sources.insert(
            0,
            item,
        )

    # URL 去重
    seen = set()
    unique_sources = []

    for source in final_sources:
        url = source["url"]

        if url in seen:
            continue

        seen.add(url)
        unique_sources.append(source)

    registry = {
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "repositories": repos,
        "sources": unique_sources,
    }

    safe_json_save(
        SOURCE_REGISTRY_FILE,
        registry,
    )

    print(
        f"\n🌐 最终监控订阅源: "
        f"{len(unique_sources)}"
    )

    return unique_sources


# =========================================================
# 订阅解析
# =========================================================

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
        compact = "".join(
            text.split()
        )

        decoded = base64.b64decode(
            compact + "=" * (
                -len(compact) % 4
            ),
            validate=False,
        )

        decoded_text = decoded.decode(
            "utf-8",
            errors="ignore",
        )

        return try_yaml_parse(
            decoded_text
        )

    except Exception:
        return []


def fetch_proxies_from_url(url):
    print(f"\n📥 获取: {url}")

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=15,
        )

        if response.status_code != 200:
            print(
                f"⚠️ HTTP {response.status_code}"
            )
            return []

        text = response.text.strip()

        # 标准 YAML
        proxies = try_yaml_parse(text)

        if proxies:
            return proxies

        # Base64 YAML
        proxies = try_base64_yaml_parse(text)

        if proxies:
            return proxies

        print(
            "⚠️ 无法识别为 Clash/Mihomo YAML"
        )

    except Exception as e:
        print(
            f"⚠️ 订阅获取失败: {e}"
        )

    return []


# =========================================================
# 节点标准化 / 去重
# =========================================================

def normalize_proxy(proxy):
    if not isinstance(proxy, dict):
        return None

    result = {}

    for key, value in proxy.items():
        if value is not None:
            result[key] = value

    server = result.get("server")
    port = result.get("port")

    if not server or not port:
        return None

    try:
        result["port"] = int(port)
    except Exception:
        return None

    if not result.get("name"):
        result["name"] = (
            f"{result.get('type', 'proxy')}-"
            f"{server}:{result['port']}"
        )

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

    raw = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )

    return sha1_text(raw)


# =========================================================
# 候选节点池
# =========================================================

def collect_candidates(sources):
    source_lists = []

    for source in sources:
        raw = fetch_proxies_from_url(
            source["url"]
        )

        normalized = []

        for proxy in raw:
            proxy = normalize_proxy(proxy)

            if proxy:
                normalized.append(proxy)

        # 单源限额
        normalized = normalized[
            :MAX_PER_SOURCE
        ]

        print(
            f"  └─ 候选节点: "
            f"{len(normalized)}"
        )

        source_lists.append(
            normalized
        )

    # 轮询多个来源
    candidates = []
    seen = set()

    index = 0

    while len(candidates) < MAX_CANDIDATES:
        added = False

        for source_list in source_lists:
            if index >= len(source_list):
                continue

            proxy = source_list[index]

            fingerprint = proxy_fingerprint(
                proxy
            )

            if fingerprint in seen:
                continue

            seen.add(fingerprint)

            candidates.append(proxy)

            added = True

            if len(candidates) >= MAX_CANDIDATES:
                break

        if not added:
            break

        index += 1

    print(
        f"\n📊 进入深度测试: "
        f"{len(candidates)} 个"
    )

    return candidates


# =========================================================
# Mihomo
# =========================================================

def build_mihomo_config(candidates):
    internal_proxies = []
    metadata = {}

    for index, proxy in enumerate(
        candidates,
        start=1,
    ):
        internal_name = (
            f"TEST-{index:03d}"
        )

        item = dict(proxy)
        item["name"] = internal_name

        internal_proxies.append(item)

        metadata[internal_name] = {
            "proxy": proxy,
            "fingerprint": proxy_fingerprint(
                proxy
            ),
        }

    names = [
        x["name"]
        for x in internal_proxies
    ]

    config = {
        "mixed-port": MIXED_PORT,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",

        "external-controller":
            f"127.0.0.1:{CONTROLLER_PORT}",

        "proxies":
            internal_proxies,

        "proxy-groups": [
            {
                "name": "TEST",
                "type": "select",
                "proxies": names,
            }
        ],

        "rules": [
            "MATCH,TEST",
        ],
    }

    return config, metadata


def write_temp_config(config):
    path = "temp_mihomo.yaml"

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
        yaml.safe_dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False,
        )

    return path


def start_mihomo(config_path):
    print(
        "\n🚀 启动 Mihomo..."
    )

    proc = subprocess.Popen(
        [
            MIHOMO_BIN,
            "-f",
            config_path,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + 12

    while time.time() < deadline:
        try:
            response = requests.get(
                f"{CONTROLLER_URL}/version",
                timeout=1,
            )

            if response.status_code == 200:
                print(
                    "✅ Mihomo Controller 已启动"
                )
                return proc

        except Exception:
            pass

        time.sleep(0.5)

    print(
        "❌ Mihomo Controller 启动失败"
    )

    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

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
            json={
                "name": proxy_name
            },
            timeout=3,
        )

        if response.status_code not in (
            200,
            204,
        ):
            return False

        time.sleep(
            SWITCH_WAIT_SECONDS
        )

        return True

    except Exception:
        return False


# =========================================================
# 节点深度验证
# =========================================================

def test_current_proxy():
    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        }
    )

    proxy_url = (
        f"http://127.0.0.1:"
        f"{MIXED_PORT}"
    )

    session.proxies.update(
        {
            "http": proxy_url,
            "https": proxy_url,
        }
    )

    result = {
        "passed": False,

        "exit_ip": "",
        "country": "",
        "city": "",
        "org": "",
        "isp": "",

        "hosting": False,
        "proxy": False,

        "google_access": False,
        "gemini_access": False,
        "gemini_api_reachable": False,

        "ip_latency_ms": None,
        "gemini_latency_ms": None,

        "reason": "",
    }

    # -----------------------------------------------------
    # 1. 实际出口 IP
    # -----------------------------------------------------

    try:
        start = time.time()

        response = session.get(
            IP_CHECK_URL,
            timeout=REQUEST_TIMEOUT,
        )

        result["ip_latency_ms"] = int(
            (time.time() - start) * 1000
        )

        if response.status_code != 200:
            result["reason"] = (
                "IP API HTTP "
                f"{response.status_code}"
            )
            return result

        data = response.json()

        if data.get("status") != "success":
            result["reason"] = (
                "IP API 返回失败"
            )
            return result

        result["exit_ip"] = (
            data.get("query", "")
        )

        result["country"] = (
            data.get("country", "")
        )

        result["city"] = (
            data.get("city", "")
        )

        result["org"] = (
            data.get("org", "")
        )

        result["isp"] = (
            data.get("isp", "")
        )

        result["hosting"] = bool(
            data.get("hosting", False)
        )

        result["proxy"] = bool(
            data.get("proxy", False)
        )

        if data.get(
            "countryCode"
        ) != "US":
            result["reason"] = (
                "出口不是美国: "
                f"{data.get('countryCode')}"
            )
            return result

        if result["proxy"]:
            result["reason"] = (
                "IP API 判定 proxy=true"
            )
            return result

        if not result["hosting"]:
            result["reason"] = (
                "不是 hosting/datacenter IP"
            )
            return result

    except Exception as e:
        result["reason"] = (
            f"出口 IP 检测失败: {e}"
        )
        return result

    # -----------------------------------------------------
    # 2. Google
    # -----------------------------------------------------

    try:
        response = session.get(
            GOOGLE_TEST_URL,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        if response.status_code in (
            200,
            204,
        ):
            result["google_access"] = True
        else:
            result["reason"] = (
                "Google HTTP "
                f"{response.status_code}"
            )
            return result

    except Exception as e:
        result["reason"] = (
            f"Google 请求失败: {e}"
        )
        return result

    # -----------------------------------------------------
    # 3. Gemini Web
    # -----------------------------------------------------

    try:
        start = time.time()

        response = session.get(
            GEMINI_TEST_URL,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        result["gemini_latency_ms"] = int(
            (time.time() - start) * 1000
        )

        final_host = (
            urlparse(response.url).hostname
            or ""
        )

        google_domain = (
            final_host == "google.com"
            or final_host.endswith(
                ".google.com"
            )
        )

        if (
            response.status_code in range(
                200,
                400,
            )
            and google_domain
        ):
            result["gemini_access"] = True

        else:
            result["reason"] = (
                "Gemini Web 不满足条件: "
                f"HTTP {response.status_code}, "
                f"host={final_host}"
            )
            return result

    except Exception as e:
        result["reason"] = (
            f"Gemini Web 请求失败: {e}"
        )
        return result

    # -----------------------------------------------------
    # 4. Gemini API 网络层
    # -----------------------------------------------------

    try:
        response = session.get(
            GEMINI_API_TEST_URL,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        # 重点：
        # 这里不是把 401 当作“API 可调用”
        # 而是只判断 Google Gemini API
        # 的 HTTPS 网络层是否可达。
        if response.status_code in (
            200,
            400,
            401,
            403,
            404,
        ):
            result[
                "gemini_api_reachable"
            ] = True
        else:
            result["reason"] = (
                "Gemini API 网络层失败: "
                f"HTTP {response.status_code}"
            )
            return result

    except Exception as e:
        result["reason"] = (
            f"Gemini API 请求失败: {e}"
        )
        return result

    result["passed"] = True

    return result


# =========================================================
# 历史记录
# =========================================================

def update_history(
    history,
    fingerprint,
    current_time,
    test_result,
    original_name,
):
    old = history.get(
        fingerprint,
        {}
    )

    last_seen = int(
        old.get("last_seen", 0)
    )

    old_success_streak = int(
        old.get(
            "success_streak",
            0,
        )
    )

    old_pass_count = int(
        old.get(
            "pass_count",
            0,
        )
    )

    old_fail_count = int(
        old.get(
            "fail_count",
            0,
        )
    )

    if (
        last_seen
        and current_time - last_seen
        > HISTORY_RESET_HOURS * 3600
    ):
        first_seen = current_time
        pass_count = 1
        success_streak = 1

    else:
        first_seen = old.get(
            "first_seen",
            current_time,
        )

        pass_count = old_pass_count + 1
        success_streak = (
            old_success_streak + 1
        )

    item = {
        "first_seen": first_seen,
        "last_seen": current_time,
        "last_success": current_time,

        "pass_count": pass_count,
        "fail_count": old_fail_count,
        "success_streak": success_streak,

        "last_ip_latency_ms":
            test_result[
                "ip_latency_ms"
            ],

        "last_gemini_latency_ms":
            test_result[
                "gemini_latency_ms"
            ],

        "last_exit_ip":
            test_result["exit_ip"],

        "country":
            test_result["country"],

        "city":
            test_result["city"],

        "org":
            test_result["org"],

        "isp":
            test_result["isp"],

        "hosting":
            test_result["hosting"],

        "proxy":
            test_result["proxy"],

        "name":
            original_name,
    }

    history[fingerprint] = item

    return item


def record_failure(
    history,
    fingerprint,
    current_time,
    original_name,
):
    old = history.get(
        fingerprint,
        {}
    )

    old["last_seen"] = current_time

    old["fail_count"] = (
        int(
            old.get(
                "fail_count",
                0,
            )
        )
        + 1
    )

    old["success_streak"] = 0
    old["name"] = original_name

    history[fingerprint] = old


# =========================================================
# 最终配置
# =========================================================

def build_final_config(
    passed_nodes
):
    proxies = []

    for node in passed_nodes:
        proxy = dict(
            node["proxy"]
        )

        proxy["name"] = (
            node["display_name"]
        )

        proxies.append(proxy)

    proxy_names = [
        proxy["name"]
        for proxy in proxies
    ]

    return {
        "mixed-port": 7890,
        "socks-port": 7891,
        "allow-lan": True,

        "mode": "rule",
        "log-level": "info",

        "proxies": proxies,

        "proxy-groups": [
            {
                "name": "GEMINI-US",
                "type": "select",
                "proxies": proxy_names,
            }
        ],

        "rules": [
            "DOMAIN-SUFFIX,gemini.google.com,GEMINI-US",
            "DOMAIN-SUFFIX,google.com,GEMINI-US",
            "DOMAIN-SUFFIX,googleapis.com,GEMINI-US",
            "DOMAIN-SUFFIX,generativelanguage.googleapis.com,GEMINI-US",
            "MATCH,GEMINI-US",
        ],
    }


def write_final_config(
    config
):
    with open(
        "live_clash.yaml",
        "w",
        encoding="utf-8",
    ) as f:
        yaml.safe_dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False,
        )


# =========================================================
# 主流程
# =========================================================

def run_agent():
    current_time = now_ts()

    history = safe_json_load(
        HISTORY_FILE,
        {},
    )

    # -----------------------------------------------------
    # A. 动态发现 GitHub 高质量仓库
    # -----------------------------------------------------

    sources = discover_sources()

    # -----------------------------------------------------
    # B. 拉取候选节点
    # -----------------------------------------------------

    candidates = collect_candidates(
        sources
    )

    if not candidates:
        print(
            "\n❌ 没有获得候选节点"
        )

        write_final_config(
            {
                "mixed-port": 7890,
                "socks-port": 7891,
                "allow-lan": True,
                "mode": "rule",
                "log-level": "info",
                "proxies": [],
            }
        )

        safe_json_save(
            HISTORY_FILE,
            history,
        )

        return

    # -----------------------------------------------------
    # C. 启动 Mihomo
    # -----------------------------------------------------

    config, metadata = (
        build_mihomo_config(
            candidates
        )
    )

    config_path = write_temp_config(
        config
    )

    proc = None
    passed_nodes = []

    try:
        proc = start_mihomo(
            config_path
        )

        if proc is None:
            return

        print(
            "\n🔎 开始逐节点深度测试\n"
        )

        for (
            internal_name,
            meta,
        ) in metadata.items():

            proxy = meta["proxy"]
            fingerprint = meta[
                "fingerprint"
            ]

            original_name = proxy.get(
                "name",
                internal_name,
            )

            print(
                f"\n▶ {internal_name} | "
                f"{original_name}"
            )

            if not select_proxy(
                internal_name
            ):
                print(
                    "  ❌ Mihomo 切换失败"
                )

                record_failure(
                    history,
                    fingerprint,
                    current_time,
                    original_name,
                )

                continue

            result = test_current_proxy()

            if not result["passed"]:
                print(
                    f"  ❌ 淘汰: "
                    f"{result['reason']}"
                )

                record_failure(
                    history,
                    fingerprint,
                    current_time,
                    original_name,
                )

                continue

            history_item = (
                update_history(
                    history,
                    fingerprint,
                    current_time,
                    result,
                    original_name,
                )
            )

            first_seen = history_item[
                "first_seen"
            ]

            survival_hours = int(
                (
                    current_time
                    - first_seen
                )
                / 3600
            )

            streak = history_item[
                "success_streak"
            ]

            pass_count = history_item[
                "pass_count"
            ]

            gemini_latency = result[
                "gemini_latency_ms"
            ]

            display_name = (
                f"🇺🇸 "
                f"[S{streak}|"
                f"{pass_count}次|"
                f"{gemini_latency}ms|"
                f"{survival_hours}h] "
                f"{original_name}"
            )

            passed_nodes.append(
                {
                    "proxy": proxy,
                    "display_name":
                        display_name,

                    "fingerprint":
                        fingerprint,

                    "test":
                        result,

                    "success_streak":
                        streak,

                    "pass_count":
                        pass_count,
                }
            )

            print(
                f"  ✅ 通过 | "
                f"IP={result['exit_ip']} | "
                f"{result['city']} | "
                f"{result['org']} | "
                f"Gemini={gemini_latency}ms | "
                f"连续={streak} | "
                f"累计={pass_count}"
            )

    finally:
        safe_json_save(
            HISTORY_FILE,
            history,
        )

        stop_mihomo(proc)

        if os.path.exists(
            config_path
        ):
            try:
                os.remove(
                    config_path
                )
            except Exception:
                pass

    # -----------------------------------------------------
    # D. 正确排序
    #
    # 第一优先：连续稳定次数
    # 第二优先：历史累计通过次数
    # 第三优先：Gemini 实测延迟
    # -----------------------------------------------------

    passed_nodes.sort(
        key=lambda x: (
            -x["success_streak"],
            -x["pass_count"],
            (
                x["test"]
                ["gemini_latency_ms"]
                if x["test"]
                ["gemini_latency_ms"]
                is not None
                else 999999
            ),
        )
    )

    # -----------------------------------------------------
    # E. 输出
    # -----------------------------------------------------

    final_config = (
        build_final_config(
            passed_nodes
        )
    )

    write_final_config(
        final_config
    )

    safe_json_save(
        HISTORY_FILE,
        history,
    )

    print(
        "\n"
        + "=" * 65
    )

    print(
        "✅ 最终通过节点: "
        f"{len(passed_nodes)}"
    )

    print(
        "🌐 动态订阅源: "
        f"{len(sources)}"
    )

    print(
        "📦 候选节点: "
        f"{len(candidates)}"
    )

    print(
        "=" * 65
    )

    for index, node in enumerate(
        passed_nodes,
        start=1,
    ):
        result = node["test"]

        print(
            f"{index:02d}. "
            f"{node['display_name']} | "
            f"{result['exit_ip']} | "
            f"{result['org']}"
        )


if __name__ == "__main__":
    run_agent()
