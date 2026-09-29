import os
import json
import time
import hashlib
import base64
import subprocess
import re
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import requests
import yaml


# ============================================================
# 基础配置
# ============================================================

HISTORY_FILE = "node_history.json"
SOURCE_CACHE_FILE = "subscription_sources.json"
SOURCE_REGISTRY_FILE = "source_registry.json"

MIHOMO_BIN = "clash"
TEST_PORT = 9050
CONTROLLER_PORT = 9090
CONTROLLER_URL = f"http://127.0.0.1:{CONTROLLER_PORT}"

MAX_CANDIDATES = 100
MAX_PER_SOURCE = 30
MAX_OUTPUT_NODES = 40
MAX_SUBSCRIPTION_SOURCES = 60

REQUEST_TIMEOUT = 8
SWITCH_WAIT_SECONDS = 1.0

# 节点稳定性
STABLE_PASS_COUNT = 2
HISTORY_RESET_HOURS = 48
MIN_SURVIVAL_HOURS = 6

# 台湾 / 美国节点要求
TW_MAX_LATENCY_MS = 100
US_MAX_LATENCY_MS = 250
GLOBAL_MAX_LATENCY_MS = 400

TW_REQUIRE_CLEAN = True
US_REQUIRE_CLEAN = True

# 连通性要求
REQUIRE_GOOGLE = True
REQUIRE_GEMINI_WEB = True
REQUIRE_GEMINI_API = False


# ============================================================
# GitHub 自动发现配置
# ============================================================

GITHUB_SEARCH_ENABLED = True
GITHUB_MAX_REPOS = 20
GITHUB_MIN_STARS = 30
GITHUB_MAX_DAYS = 45

GITHUB_SEARCH_QUERIES = [
    "free clash",
    "clash subscription",
    "mihomo subscription",
    "free nodes clash",
    "clash 免费 订阅",
]


# ============================================================
# 测试地址
# ============================================================

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
    "Chrome/128.0.0.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}

GITHUB_TOKEN = os.getenv("GH_TOKEN", "")

if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"


# ============================================================
# 兜底订阅源
# ============================================================

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


# ============================================================
# JSON 工具
# ============================================================

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = json.load(f)
        return value
    except Exception:
        return default


def save_json(path, value):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            value,
            f,
            ensure_ascii=False,
            indent=2,
        )


# ============================================================
# 历史记录
# ============================================================

def load_history():
    value = load_json(HISTORY_FILE, {})
    return value if isinstance(value, dict) else {}


def save_history(history):
    try:
        save_json(HISTORY_FILE, history)
    except Exception as e:
        print(f"history save failed: {e}")


# ============================================================
# URL 处理
# ============================================================

def normalize_url(url):
    if not url:
        return ""

    url = url.strip().rstrip(").,;'\"")

    if "github.com" in url and "/blob/" in url:
        url = url.replace(
            "https://github.com/",
            "https://raw.githubusercontent.com/",
        )
        url = url.replace("/blob/", "/")

    return url


def extract_subscription_urls(text):
    if not text:
        return []

    patterns = [
        r'https?://raw\.githubusercontent\.com/[^\s\'"<>]+',
        r'https?://cdn\.jsdelivr\.net/gh/[^\s\'"<>]+',
        r'https?://[^\s\'"<>]+\.(?:yaml|yml)(?:\?[^\s\'"<>]*)?',
        r'https?://[^\s\'"<>]+/(?:sub|subscribe|clash|mihomo)[^\s\'"<>]*',
    ]

    out = set()

    for pattern in patterns:
        for item in re.findall(pattern, text, re.I):
            item = normalize_url(item)

            if len(item) > 20 and item.startswith("http"):
                out.add(item)

    return sorted(out)


# ============================================================
# GitHub 自动搜索
# ============================================================

def search_github_repos():
    if not GITHUB_SEARCH_ENABLED:
        return []

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(days=GITHUB_MAX_DAYS)
    ).date().isoformat()

    repos = {}

    headers = dict(HEADERS)
    headers["Accept"] = "application/vnd.github+json"

    for base_query in GITHUB_SEARCH_QUERIES:

        query = (
            f"{base_query} "
            f"stars:>={GITHUB_MIN_STARS} "
            f"pushed:>={cutoff}"
        )

        try:
            response = requests.get(
                "https://api.github.com/search/repositories",
                headers=headers,
                params={
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": 10,
                },
                timeout=15,
            )

            if response.status_code != 200:
                print(
                    f"GitHub search HTTP "
                    f"{response.status_code}: {base_query}"
                )
                continue

            for item in response.json().get("items", []):

                full_name = item.get("full_name")
                stars = int(
                    item.get("stargazers_count", 0)
                )
                updated_at = item.get("updated_at", "")

                if not full_name:
                    continue

                if stars < GITHUB_MIN_STARS:
                    continue

                try:
                    updated_dt = datetime.fromisoformat(
                        updated_at.replace("Z", "+00:00")
                    )

                    if updated_dt < (
                        datetime.now(timezone.utc)
                        - timedelta(days=GITHUB_MAX_DAYS)
                    ):
                        continue

                except Exception:
                    continue

                repos[full_name] = {
                    "full_name": full_name,
                    "stars": stars,
                    "default_branch": item.get(
                        "default_branch",
                        "main",
                    ),
                    "updated_at": updated_at,
                }

            time.sleep(0.7)

        except Exception as e:
            print(f"GitHub search error: {e}")

    result = sorted(
        repos.values(),
        key=lambda x: (
            -x["stars"],
            x["updated_at"],
        ),
    )

    result = result[:GITHUB_MAX_REPOS]

    print(
        f"GitHub dynamic repositories: "
        f"{len(result)}"
    )

    return result


def fetch_text(url, timeout=12):
    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=timeout,
        )

        if response.status_code == 200:
            return response.text

    except Exception:
        pass

    return ""


def fetch_repo_texts(repo):
    full_name = repo["full_name"]
    branch = repo.get(
        "default_branch",
        "main",
    )

    texts = []

    # README
    for path in (
        "README.md",
        "readme.md",
    ):
        text = fetch_text(
            f"https://raw.githubusercontent.com/"
            f"{full_name}/{branch}/{path}"
        )

        if text:
            texts.append(text)
            break

    # 根目录候选文件
    try:
        response = requests.get(
            f"https://api.github.com/repos/"
            f"{full_name}/contents/",
            headers=HEADERS,
            timeout=12,
        )

        if response.status_code == 200:

            for item in response.json():

                if item.get("type") != "file":
                    continue

                name = item.get(
                    "name",
                    "",
                ).lower()

                if not any(
                    keyword in name
                    for keyword in (
                        "clash",
                        "mihomo",
                        "sub",
                        "subscribe",
                        "node",
                        "free",
                    )
                ):
                    continue

                if not name.endswith(
                    (
                        ".yaml",
                        ".yml",
                        ".txt",
                        ".json",
                        ".conf",
                    )
                ):
                    continue

                download_url = item.get(
                    "download_url"
                )

                if not download_url:
                    continue

                text = fetch_text(
                    download_url
                )

                if text:
                    texts.append(text)

    except Exception:
        pass

    return texts


# ============================================================
# 订阅源注册表
# ============================================================

def ensure_source_entry(
    registry,
    url,
    repo="",
    stars=0,
):
    now = int(time.time())

    entry = registry.setdefault(
        url,
        {
            "url": url,
            "repo": repo,
            "stars": stars,
            "first_seen": now,
            "last_seen": now,
            "success_count": 0,
            "failure_count": 0,
            "last_status": "",
            "last_nodes": 0,
        },
    )

    entry["last_seen"] = now

    if repo:
        entry["repo"] = repo

    if stars:
        entry["stars"] = stars

    return entry


def discover_subscription_sources():

    cache = load_json(
        SOURCE_CACHE_FILE,
        [],
    )

    if not isinstance(cache, list):
        cache = []

    registry = load_json(
        SOURCE_REGISTRY_FILE,
        {},
    )

    if not isinstance(registry, dict):
        registry = {}

    discovered = []

    # 历史源
    for url in cache:

        url = normalize_url(url)

        if url:
            discovered.append(url)

            ensure_source_entry(
                registry,
                url,
            )

    # GitHub 动态搜索
    repos = search_github_repos()

    for repo in repos:

        urls = set()

        for text in fetch_repo_texts(repo):
            urls.update(
                extract_subscription_urls(text)
            )

        if urls:
            print(
                f"{repo['full_name']} "
                f"Star={repo['stars']} "
                f"new sources={len(urls)}"
            )

        for url in urls:

            discovered.append(url)

            ensure_source_entry(
                registry,
                url,
                repo["full_name"],
                repo["stars"],
            )

        time.sleep(0.4)

    # 兜底源
    for url in FALLBACK_SUBSCRIPTION_URLS:

        discovered.append(url)

        ensure_source_entry(
            registry,
            url,
            "fallback",
            0,
        )

    # 去重
    unique = []
    seen = set()

    for url in discovered:

        url = normalize_url(url)

        if not url:
            continue

        if url in seen:
            continue

        seen.add(url)
        unique.append(url)

    # 历史成功源优先
    unique.sort(
        key=lambda u: (
            -int(
                registry.get(
                    u,
                    {},
                ).get(
                    "success_count",
                    0,
                )
            ),
            -int(
                registry.get(
                    u,
                    {},
                ).get(
                    "stars",
                    0,
                )
            ),
        )
    )

    unique = unique[
        :MAX_SUBSCRIPTION_SOURCES
    ]

    save_json(
        SOURCE_CACHE_FILE,
        unique,
    )

    save_json(
        SOURCE_REGISTRY_FILE,
        registry,
    )

    print(
        f"Subscription sources: "
        f"{len(unique)}"
    )

    return unique


# ============================================================
# 节点标准化
# ============================================================

def normalize_proxy(proxy):

    if not isinstance(proxy, dict):
        return None

    result = {
        key: value
        for key, value in proxy.items()
        if value is not None
    }

    if not result.get("server"):
        return None

    if not result.get("port"):
        return None

    try:
        result["port"] = int(
            result["port"]
        )
    except Exception:
        return None

    result.setdefault(
        "name",
        (
            f"{result.get('type', 'proxy')}-"
            f"{result['server']}:"
            f"{result['port']}"
        ),
    )

    return result


def proxy_fingerprint(proxy):

    identity = {
        key: proxy.get(key)
        for key in (
            "type",
            "server",
            "port",
            "uuid",
            "password",
            "username",
            "cipher",
            "tls",
            "servername",
            "sni",
            "network",
            "ws-opts",
            "grpc-opts",
            "reality-opts",
            "http-opts",
            "h2-opts",
        )
    }

    raw = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )

    return hashlib.sha256(
        raw.encode()
    ).hexdigest()[:20]


# ============================================================
# 订阅解析
# ============================================================

def parse_yaml(text):

    try:
        data = yaml.safe_load(text)

        if (
            isinstance(data, dict)
            and isinstance(
                data.get("proxies"),
                list,
            )
        ):
            return data["proxies"]

        if isinstance(data, list):
            return data

    except Exception:
        pass

    return []


def parse_base64_yaml(text):

    try:

        compact = "".join(
            text.split()
        )

        decoded = base64.b64decode(
            compact
            + "="
            * (-len(compact) % 4),
            validate=False,
        )

        decoded_text = decoded.decode(
            "utf-8",
            errors="ignore",
        )

        return parse_yaml(
            decoded_text
        )

    except Exception:
        return []


def fetch_source(url):

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=15,
        )

        if response.status_code != 200:
            return (
                [],
                f"HTTP {response.status_code}",
            )

        text = response.text.strip()

        nodes = parse_yaml(text)

        if nodes:
            return nodes, "YAML"

        nodes = parse_base64_yaml(
            text
        )

        if nodes:
            return (
                nodes,
                "Base64 YAML",
            )

        return [], "unparsed"

    except Exception as e:
        return [], str(e)


# ============================================================
# 候选节点
# ============================================================

def collect_candidates(
    source_urls
):

    registry = load_json(
        SOURCE_REGISTRY_FILE,
        {},
    )

    if not isinstance(registry, dict):
        registry = {}

    source_lists = []

    for url in source_urls:

        raw, status = fetch_source(
            url
        )

        entry = ensure_source_entry(
            registry,
            url,
        )

        entry["last_status"] = status
        entry["last_nodes"] = len(raw)

        if raw:
            entry["success_count"] += 1
        else:
            entry["failure_count"] += 1

        normalized = []

        for node in raw:

            item = normalize_proxy(
                node
            )

            if item:
                normalized.append(item)

        if normalized:
            source_lists.append(
                normalized[
                    :MAX_PER_SOURCE
                ]
            )

    save_json(
        SOURCE_REGISTRY_FILE,
        registry,
    )

    candidates = []
    seen = set()
    index = 0

    while len(candidates) < MAX_CANDIDATES:

        added = False

        for source_list in source_lists:

            if index >= len(
                source_list
            ):
                continue

            node = source_list[index]

            fingerprint = (
                proxy_fingerprint(node)
            )

            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            candidates.append(node)
            added = True

            if (
                len(candidates)
                >= MAX_CANDIDATES
            ):
                break

        if not added:
            break

        index += 1

    print(
        f"Candidates for deep test: "
        f"{len(candidates)}"
    )

    return candidates


# ============================================================
# Mihomo 测试配置
# ============================================================

def build_test_config(
    candidates
):

    proxies = []
    metadata = {}

    for index, proxy in enumerate(
        candidates,
        1,
    ):

        name = (
            f"TEST-{index:03d}"
        )

        item = dict(proxy)
        item["name"] = name

        proxies.append(item)

        metadata[name] = {
            "proxy": proxy,
            "fingerprint":
                proxy_fingerprint(
                    proxy
                ),
        }

    config = {
        "mixed-port": TEST_PORT,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller":
            f"127.0.0.1:"
            f"{CONTROLLER_PORT}",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "TEST",
                "type": "select",
                "proxies": [
                    p["name"]
                    for p in proxies
                ],
            }
        ],
        "rules": [
            "MATCH,TEST"
        ],
    }

    return config, metadata


def write_yaml(
    path,
    data,
):

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:

        yaml.safe_dump(
            data,
            f,
            allow_unicode=True,
            sort_keys=False,
        )


# ============================================================
# Mihomo 启停
# ============================================================

def start_mihomo(
    config_path
):

    proc = subprocess.Popen(
        [
            MIHOMO_BIN,
            "-f",
            config_path,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = (
        time.time() + 12
    )

    while time.time() < deadline:

        try:

            response = requests.get(
                f"{CONTROLLER_URL}/version",
                timeout=1,
            )

            if response.status_code == 200:
                return proc

        except Exception:
            pass

        time.sleep(0.5)

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


def select_proxy(name):

    try:

        response = requests.put(
            f"{CONTROLLER_URL}/proxies/TEST",
            json={
                "name": name
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


# ============================================================
# 节点实际检测
# ============================================================

def test_current_proxy():

    session = requests.Session()

    session.headers.update({
        "User-Agent":
            USER_AGENT,
        "Accept":
            "*/*",
    })

    session.proxies.update({
        "http":
            f"http://127.0.0.1:"
            f"{TEST_PORT}",
        "https":
            f"http://127.0.0.1:"
            f"{TEST_PORT}",
    })

    result = {
        "passed":
            False,
        "exit_ip":
            "",
        "country":
            "",
        "countryCode":
            "",
        "city":
            "",
        "org":
            "",
        "isp":
            "",
        "hosting":
            False,
        "proxy":
            False,
        "google_access":
            False,
        "gemini_access":
            False,
        "gemini_api_reachable":
            False,
        "latency_ms":
            None,
        "is_clean":
            False,
        "reason":
            "",
    }

    # --------------------------------------------------------
    # 1. 出口 IP
    # --------------------------------------------------------

    try:

        start = time.time()

        response = session.get(
            IP_CHECK_URL,
            timeout=REQUEST_TIMEOUT,
        )

        result["latency_ms"] = int(
            (
                time.time()
                - start
            )
            * 1000
        )

        if response.status_code != 200:
            result["reason"] = (
                f"IP API HTTP "
                f"{response.status_code}"
            )
            return result

        data = response.json()

        if data.get("status") != "success":
            result["reason"] = (
                "IP API failed"
            )
            return result

        result["exit_ip"] = (
            data.get(
                "query",
                "",
            )
        )

        result["country"] = (
            data.get(
                "country",
                "",
            )
        )

        result["countryCode"] = (
            data.get(
                "countryCode",
                "",
            )
        )

        result["city"] = (
            data.get(
                "city",
                "",
            )
        )

        result["org"] = (
            data.get(
                "org",
                "",
            )
        )

        result["isp"] = (
            data.get(
                "isp",
                "",
            )
        )

        result["hosting"] = bool(
            data.get(
                "hosting",
                False,
            )
        )

        result["proxy"] = bool(
            data.get(
                "proxy",
                False,
            )
        )

        result["is_clean"] = (
            not result["hosting"]
            and not result["proxy"]
        )

        # 总延迟闸门
        if (
            result["latency_ms"]
            > GLOBAL_MAX_LATENCY_MS
        ):

            result["reason"] = (
                f"latency "
                f"{result['latency_ms']}ms "
                f"> "
                f"{GLOBAL_MAX_LATENCY_MS}ms"
            )

            return result

        cc = result["countryCode"]

        # 台湾
        if cc == "TW":

            if (
                result["latency_ms"]
                > TW_MAX_LATENCY_MS
            ):
                result["reason"] = (
                    "TW latency too high"
                )
                return result

            if (
                TW_REQUIRE_CLEAN
                and not result["is_clean"]
            ):
                result["reason"] = (
                    "TW IP not clean"
                )
                return result

        # 美国
        if cc == "US":

            if (
                result["latency_ms"]
                > US_MAX_LATENCY_MS
            ):
                result["reason"] = (
                    "US latency too high"
                )
                return result

            if (
                US_REQUIRE_CLEAN
                and not result["is_clean"]
            ):
                result["reason"] = (
                    "US IP not clean"
                )
                return result

    except Exception as e:

        result["reason"] = (
            f"IP test failed: {e}"
        )

        return result

    # --------------------------------------------------------
    # 2. Google
    # --------------------------------------------------------

    if REQUIRE_GOOGLE:

        try:

            response = session.get(
                GOOGLE_TEST_URL,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            if response.status_code not in (
                200,
                204,
            ):

                result["reason"] = (
                    f"Google HTTP "
                    f"{response.status_code}"
                )

                return result

            result["google_access"] = True

        except Exception as e:

            result["reason"] = (
                f"Google failed: {e}"
            )

            return result

    # --------------------------------------------------------
    # 3. Gemini Web
    # --------------------------------------------------------

    if REQUIRE_GEMINI_WEB:

        try:

            response = session.get(
                GEMINI_TEST_URL,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            final_host = (
                urlparse(
                    response.url
                ).hostname
                or ""
            )

            google_domain = (
                final_host == "google.com"
                or final_host.endswith(
                    ".google.com"
                )
            )

            if (
                response.status_code
                not in range(200, 400)
                or not google_domain
            ):

                result["reason"] = (
                    f"Gemini HTTP "
                    f"{response.status_code}, "
                    f"host={final_host}"
                )

                return result

            result["gemini_access"] = True

        except Exception as e:

            result["reason"] = (
                f"Gemini failed: {e}"
            )

            return result

    # --------------------------------------------------------
    # 4. Gemini API（可选）
    # --------------------------------------------------------

    if REQUIRE_GEMINI_API:

        try:

            response = session.get(
                GEMINI_API_TEST_URL,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            if response.status_code not in (
                200,
                400,
                401,
                403,
                404,
            ):

                result["reason"] = (
                    f"Gemini API HTTP "
                    f"{response.status_code}"
                )

                return result

            result[
                "gemini_api_reachable"
            ] = True

        except Exception as e:

            result["reason"] = (
                f"Gemini API failed: {e}"
            )

            return result

    result["passed"] = True

    return result


# ============================================================
# 历史状态
# ============================================================

def update_history(
    history,
    fingerprint,
    now,
    test,
    original_name,
):

    old = history.get(
        fingerprint,
        {},
    )

    last_seen = old.get(
        "last_seen"
    )

    if (
        last_seen
        and now - last_seen
        > HISTORY_RESET_HOURS * 3600
    ):

        first_seen = now
        pass_count = 1

    else:

        first_seen = old.get(
            "first_seen",
            now,
        )

        pass_count = int(
            old.get(
                "pass_count",
                0,
            )
        ) + 1

    history[fingerprint] = {

        "first_seen":
            first_seen,

        "last_seen":
            now,

        "pass_count":
            pass_count,

        "last_latency_ms":
            test["latency_ms"],

        "last_exit_ip":
            test["exit_ip"],

        "country":
            test["country"],

        "city":
            test["city"],

        "org":
            test["org"],

        "isp":
            test["isp"],

        "hosting":
            test["hosting"],

        "proxy":
            test["proxy"],

        "name":
            original_name,
    }

    return history[fingerprint]


# ============================================================
# 最终 Clash 配置
# ============================================================

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

    names = [
        p["name"]
        for p in proxies
    ]

    tw_names = [
        n
        for n in names
        if "🇹🇼" in n
    ]

    us_names = [
        n
        for n in names
        if "🇺🇸" in n
    ]

    # 自动选择：
    # 只有通过初始 Gemini 测试的节点
    # 才能进入该组。
    #
    # 0 节点时使用 REJECT，
    # 防止 Gemini 自动组意外回落 DIRECT。
    auto_candidates = (
        names
        if names
        else ["REJECT"]
    )

    manual_candidates = (
        names
        if names
        else ["DIRECT"]
    )

    final_config = {

        "mixed-port":
            7890,

        "socks-port":
            7891,

        "allow-lan":
            True,

        "mode":
            "rule",

        "log-level":
            "info",

        "proxies":
            proxies,

        "proxy-groups": [

            # 主节点选择
            {
                "name":
                    "🚀 节点选择",

                "type":
                    "select",

                "proxies": [
                    "♻️ 自动选择",
                    "🌐 手动选择",
                    "🇹🇼 台湾",
                    "🇺🇸 美国",
                    "DIRECT",
                ],
            },

            # Gemini 健康检查自动选择
            {
                "name":
                    "♻️ 自动选择",

                "type":
                    "url-test",

                "url":
                    GEMINI_TEST_URL,

                # Gemini 当前允许正常成功响应
                # 与跳转响应
                "expected-status":
                    "200-399",

                # 每 180 秒重新验证
                "interval":
                    180,

                "tolerance":
                    50,

                # 不等第一次实际请求才检测
                "lazy":
                    False,

                "proxies":
                    auto_candidates,
            },

            # 人工节点选择
            {
                "name":
                    "🌐 手动选择",

                "type":
                    "select",

                "proxies":
                    manual_candidates,
            },

            # 台湾节点
            {
                "name":
                    "🇹🇼 台湾",

                "type":
                    "select",

                "proxies":
                    (
                        tw_names
                        if tw_names
                        else ["DIRECT"]
                    ),
            },

            # 美国节点
            {
                "name":
                    "🇺🇸 美国",

                "type":
                    "select",

                "proxies":
                    (
                        us_names
                        if us_names
                        else ["DIRECT"]
                    ),
            },
        ],

        "rules": [

            # =================================================
            # 中国大陆目的地：直连
            # =================================================

            "GEOSITE,CN,DIRECT",
            "GEOIP,CN,DIRECT",

            # 私有地址直连
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",

            # 中国域名
            "DOMAIN-SUFFIX,cn,DIRECT",
            "DOMAIN-SUFFIX,com.cn,DIRECT",
            "DOMAIN-SUFFIX,org.cn,DIRECT",
            "DOMAIN-SUFFIX,net.cn,DIRECT",
            "DOMAIN-SUFFIX,gov.cn,DIRECT",

            # 常用国内服务
            "DOMAIN-SUFFIX,qq.com,DIRECT",
            "DOMAIN-SUFFIX,baidu.com,DIRECT",
            "DOMAIN-SUFFIX,taobao.com,DIRECT",
            "DOMAIN-SUFFIX,tmall.com,DIRECT",
            "DOMAIN-SUFFIX,jd.com,DIRECT",
            "DOMAIN-SUFFIX,bilibili.com,DIRECT",
            "DOMAIN-SUFFIX,wechat.com,DIRECT",
            "DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
            "DOMAIN-SUFFIX,163.com,DIRECT",
            "DOMAIN-SUFFIX,alibaba.com,DIRECT",

            # =================================================
            # Google / Gemini
            # 必须走 Gemini 自动检测节点
            # =================================================

            "DOMAIN-SUFFIX,gemini.google.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,googleapis.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,generativelanguage.googleapis.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,google.com,♻️ 自动选择",

            # =================================================
            # 其他海外流量
            # =================================================

            "MATCH,🚀 节点选择",
        ],
    }

    return final_config


# ============================================================
# 主流程
# ============================================================

def run_agent():

    now = int(time.time())

    history = load_history()

    # 1. 动态发现订阅源
    source_urls = (
        discover_subscription_sources()
    )

    # 2. 获取节点
    candidates = (
        collect_candidates(
            source_urls
        )
    )

    # 没有候选
    if not candidates:

        print(
            "No candidates"
        )

        write_yaml(
            "live_clash.yaml",
            build_final_config([]),
        )

        save_history(
            history
        )

        return

    # 3. 构造测试配置
    test_config, metadata = (
        build_test_config(
            candidates
        )
    )

    config_path = (
        "temp_mihomo.yaml"
    )

    write_yaml(
        config_path,
        test_config,
    )

    proc = None
    passed = []

    try:

        # 4. 启动 Mihomo
        proc = start_mihomo(
            config_path
        )

        if not proc:
            raise RuntimeError(
                "Mihomo failed to start"
            )

        # 5. 逐节点检测
        for (
            internal_name,
            meta
        ) in metadata.items():

            # 切换测试节点
            if not select_proxy(
                internal_name
            ):
                continue

            # 实际检测
            result = (
                test_current_proxy()
            )

            # 任何一项失败直接淘汰
            if not result["passed"]:

                print(
                    f"REJECT "
                    f"{internal_name}: "
                    f"{result['reason']}"
                )

                continue

            # 6. 更新历史
            history_item = (
                update_history(
                    history,
                    meta["fingerprint"],
                    now,
                    result,
                    meta["proxy"].get(
                        "name",
                        internal_name,
                    ),
                )
            )

            survival_hours = int(
                (
                    now
                    - history_item[
                        "first_seen"
                    ]
                )
                / 3600
            )

            # 7. 稳定次数闸门
            if (
                history_item[
                    "pass_count"
                ]
                < STABLE_PASS_COUNT
            ):
                continue

            country_code = (
                result["countryCode"]
            )

            if country_code == "TW":
                flag = "🇹🇼"

            elif country_code == "US":
                flag = "🇺🇸"

            else:
                flag = "🌐"

            clean_tag = (
                "洁"
                if result["is_clean"]
                else "机"
            )

            display_name = (
                f"{flag}{clean_tag} "
                f"[{result['latency_ms']}ms|"
                f"{survival_hours}h|"
                f"{history_item['pass_count']}次] "
                f"{meta['proxy'].get('name', internal_name)}"
            )

            passed.append({

                "proxy":
                    meta["proxy"],

                "display_name":
                    display_name,

                "fingerprint":
                    meta["fingerprint"],

                "test":
                    result,

                "pass_count":
                    history_item[
                        "pass_count"
                    ],

                "survival_hours":
                    survival_hours,

                "latency":
                    result[
                        "latency_ms"
                    ],

                "countryCode":
                    country_code,

                "is_clean":
                    result[
                        "is_clean"
                    ],
            })

    finally:

        save_history(
            history
        )

        stop_mihomo(
            proc
        )

        try:
            os.remove(
                config_path
            )
        except OSError:
            pass

    # 8. 最终排序
    passed.sort(
        key=lambda x: (

            # 台湾优先
            (
                0
                if x["countryCode"]
                == "TW"
                else 1
            ),

            # 美国清洁优先
            (
                0
                if (
                    x["countryCode"]
                    == "US"
                    and x["is_clean"]
                )
                else 1
            ),

            # 存活时间优先
            (
                0
                if x["survival_hours"]
                >= MIN_SURVIVAL_HOURS
                else 1
            ),

            -x["survival_hours"],
            -x["pass_count"],
            x["latency"]
            or 999999,
        )
    )

    passed = passed[
        :MAX_OUTPUT_NODES
    ]

    # 9. 生成最终配置
    final_config = (
        build_final_config(
            passed
        )
    )

    write_yaml(
        "live_clash.yaml",
        final_config,
    )

    print(
        f"Output nodes: "
        f"{len(passed)}"
    )


if __name__ == "__main__":
    run_agent()
