import os
import json
import time
import hashlib
import base64
import subprocess
import re
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests
import yaml


# ============================================================
# 核心规则
# ============================================================
# 1. 自动寻找近期活跃的新订阅源
# 2. 台湾 / 美国优先
# 3. 清洁 IP 优先
# 4. 实际代理 HTTP 延迟必须 < 250ms
# 5. Google 必须可用
# 6. Gemini 必须可用
# 7. Google Play 必须可用
# 8. Gemini Android 关键 Google 主机必须大部分可达
# 9. 记录节点寿命，长期稳定节点优先
# 10. 记录订阅源稳定性，长期有效源优先
# 11. 中国大陆流量 DIRECT
# 12. 国内 DNS 优先国内解析
# 13. Gemini 自动选择持续健康检查
# 14. Google Play 自动选择持续健康检查
# ============================================================


HISTORY_FILE = "node_history.json"
SOURCE_CACHE_FILE = "subscription_sources.json"
SOURCE_REGISTRY_FILE = "source_registry.json"

MIHOMO_BIN = "clash"

TEST_PORT = 9050
CONTROLLER_PORT = 9090
CONTROLLER_URL = (
    f"http://127.0.0.1:{CONTROLLER_PORT}"
)

MAX_CANDIDATES = 100
MAX_PER_SOURCE = 30
MAX_OUTPUT_NODES = 40
MAX_SUBSCRIPTION_SOURCES = 60

REQUEST_TIMEOUT = 6
DELAY_TIMEOUT_MS = 5000
SWITCH_WAIT_SECONDS = 0.8

# 最终真实代理延迟硬门槛
MAX_PROXY_DELAY_MS = 250

# 节点历史
STABLE_PASS_COUNT = 2
HISTORY_RESET_HOURS = 48
MIN_SURVIVAL_HOURS = 6

# IP 清洁度
REQUIRE_CLEAN_IP = True


# ============================================================
# GitHub 自动发现
# ============================================================

GITHUB_SEARCH_ENABLED = True
GITHUB_MAX_REPOS = 20
GITHUB_MIN_STARS = 10
GITHUB_MAX_DAYS = 30

GITHUB_SEARCH_QUERIES = [
    "free clash",
    "clash subscription",
    "mihomo subscription",
    "free nodes clash",
    "clash 免费 订阅",
]


# ============================================================
# 测试目标
# ============================================================

IP_CHECK_URL = (
    "http://ip-api.com/json/"
    "?fields=status,country,countryCode,regionName,city,"
    "hosting,proxy,org,isp,query"
)

GOOGLE_DELAY_URL = (
    "https://www.google.com/generate_204"
)

GEMINI_DELAY_URL = (
    "https://gemini.google.com/"
)

PLAY_DELAY_URL = (
    "https://play.google.com/store/apps/"
)


# Gemini Android / Google 关键服务
GEMINI_MOBILE_PROBES = [
    "https://www.googleapis.com/",
    "https://apis.google.com/",
    "https://jnn-pa.googleapis.com/",
    "https://waa-pa.clients6.google.com/",
    "https://www.gstatic.com/",
    "https://ssl.gstatic.com/",
    "https://optimizationguide-pa.googleapis.com/",
    "https://play.googleapis.com/",
]


USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 14) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Mobile Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}


GITHUB_TOKEN = os.getenv(
    "GH_TOKEN",
    ""
)

if GITHUB_TOKEN:
    HEADERS["Authorization"] = (
        f"Bearer {GITHUB_TOKEN}"
    )


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
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/free18/v2ray/main/c.yaml",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
]


# ============================================================
# JSON
# ============================================================

def load_json(path, default):
    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2,
        )


# ============================================================
# 节点历史
# ============================================================

def load_history():
    data = load_json(
        HISTORY_FILE,
        {},
    )

    return (
        data
        if isinstance(data, dict)
        else {}
    )


def save_history(history):
    try:
        save_json(
            HISTORY_FILE,
            history,
        )
    except Exception as exc:
        print(
            f"history save failed: {exc}"
        )


# ============================================================
# URL
# ============================================================

def normalize_url(url):
    if not url:
        return ""

    url = url.strip().rstrip(
        ").,;'\""
    )

    if (
        "github.com" in url
        and "/blob/" in url
    ):
        url = url.replace(
            "https://github.com/",
            "https://raw.githubusercontent.com/",
        )

        url = url.replace(
            "/blob/",
            "/",
        )

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

    urls = set()

    for pattern in patterns:
        for item in re.findall(
            pattern,
            text,
            re.I,
        ):
            item = normalize_url(item)

            if (
                len(item) > 20
                and item.startswith("http")
            ):
                urls.add(item)

    return sorted(urls)


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
            "stars": int(stars or 0),
            "first_seen": now,
            "last_seen": now,
            "success_count": 0,
            "failure_count": 0,
            "qualified_runs": 0,
            "qualified_nodes_total": 0,
            "last_status": "",
            "last_nodes": 0,
            "last_qualified_nodes": 0,
            "last_qualified_at": 0,
        },
    )

    entry["last_seen"] = now

    if repo:
        entry["repo"] = repo

    if stars:
        entry["stars"] = int(stars)

    return entry


# ============================================================
# GitHub 自动搜索
# ============================================================

def search_github_repos():

    if not GITHUB_SEARCH_ENABLED:
        return []

    repos = {}

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(
            days=GITHUB_MAX_DAYS
        )
    )

    headers = dict(HEADERS)

    headers["Accept"] = (
        "application/vnd.github+json"
    )

    for base_query in GITHUB_SEARCH_QUERIES:

        query = (
            f"{base_query} "
            f"stars:>={GITHUB_MIN_STARS} "
            f"pushed:>="
            f"{cutoff.date().isoformat()}"
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
                timeout=12,
            )

            if response.status_code != 200:
                print(
                    f"GitHub search HTTP "
                    f"{response.status_code}: "
                    f"{base_query}"
                )
                continue

            for item in response.json().get(
                "items",
                [],
            ):

                full_name = item.get(
                    "full_name"
                )

                stars = int(
                    item.get(
                        "stargazers_count",
                        0,
                    )
                )

                updated_at = item.get(
                    "updated_at",
                    "",
                )

                if not full_name:
                    continue

                if (
                    stars
                    < GITHUB_MIN_STARS
                ):
                    continue

                try:
                    updated_dt = (
                        datetime.fromisoformat(
                            updated_at.replace(
                                "Z",
                                "+00:00",
                            )
                        )
                    )

                    if updated_dt < cutoff:
                        continue

                except Exception:
                    continue

                repos[full_name] = {
                    "full_name": full_name,
                    "stars": stars,
                    "default_branch":
                        item.get(
                            "default_branch",
                            "main",
                        ),
                    "updated_at":
                        updated_at,
                }

            time.sleep(0.6)

        except Exception as exc:
            print(
                f"GitHub search error: {exc}"
            )

    result = sorted(
        repos.values(),
        key=lambda x: (
            -x["stars"],
            x["updated_at"],
        ),
    )

    result = result[
        :GITHUB_MAX_REPOS
    ]

    print(
        f"GitHub dynamic repositories: "
        f"{len(result)}"
    )

    return result


def fetch_text(
    url,
    timeout=10,
):

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

    full_name = repo[
        "full_name"
    ]

    branch = repo.get(
        "default_branch",
        "main",
    )

    texts = []

    for filename in (
        "README.md",
        "readme.md",
    ):

        text = fetch_text(
            f"https://raw.githubusercontent.com/"
            f"{full_name}/"
            f"{branch}/"
            f"{filename}"
        )

        if text:
            texts.append(text)
            break

    try:

        response = requests.get(
            f"https://api.github.com/repos/"
            f"{full_name}/contents/",
            headers=HEADERS,
            timeout=10,
        )

        if response.status_code == 200:

            for item in response.json():

                if item.get(
                    "type"
                ) != "file":
                    continue

                name = item.get(
                    "name",
                    "",
                ).lower()

                if not any(
                    key in name
                    for key in (
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


def discover_subscription_sources():

    cache = load_json(
        SOURCE_CACHE_FILE,
        [],
    )

    if not isinstance(
        cache,
        list,
    ):
        cache = []

    registry = load_json(
        SOURCE_REGISTRY_FILE,
        {},
    )

    if not isinstance(
        registry,
        dict,
    ):
        registry = {}

    discovered = []

    for url in cache:

        url = normalize_url(url)

        if url:
            discovered.append(url)

            ensure_source_entry(
                registry,
                url,
            )

    for repo in search_github_repos():

        repo_urls = set()

        for text in fetch_repo_texts(
            repo
        ):
            repo_urls.update(
                extract_subscription_urls(
                    text
                )
            )

        if repo_urls:
            print(
                f"{repo['full_name']} "
                f"Star={repo['stars']} "
                f"sources={len(repo_urls)}"
            )

        for url in repo_urls:

            discovered.append(url)

            ensure_source_entry(
                registry,
                url,
                repo["full_name"],
                repo["stars"],
            )

    for url in FALLBACK_SUBSCRIPTION_URLS:

        discovered.append(url)

        ensure_source_entry(
            registry,
            url,
            "fallback",
            0,
        )

    unique = []
    seen = set()

    for url in discovered:

        url = normalize_url(url)

        if (
            not url
            or url in seen
        ):
            continue

        seen.add(url)
        unique.append(url)

    def source_priority(url):

        entry = registry.get(
            url,
            {},
        )

        qualified_runs = int(
            entry.get(
                "qualified_runs",
                0,
            )
        )

        success_count = int(
            entry.get(
                "success_count",
                0,
            )
        )

        stars = int(
            entry.get(
                "stars",
                0,
            )
        )

        last_qualified = int(
            entry.get(
                "last_qualified_at",
                0,
            )
        )

        return (
            -qualified_runs,
            -success_count,
            -stars,
            -last_qualified,
        )

    unique.sort(
        key=source_priority
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
        f"Subscription sources selected: "
        f"{len(unique)}"
    )

    return unique


# ============================================================
# 节点解析
# ============================================================

def normalize_proxy(proxy):

    if not isinstance(
        proxy,
        dict,
    ):
        return None

    result = {
        key: value
        for key, value in proxy.items()
        if value is not None
    }

    if not result.get(
        "server"
    ):
        return None

    if not result.get(
        "port"
    ):
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
        raw.encode("utf-8")
    ).hexdigest()[:20]


# ============================================================
# 订阅获取
# ============================================================

def parse_yaml(text):

    try:

        data = yaml.safe_load(
            text
        )

        if (
            isinstance(
                data,
                dict,
            )
            and isinstance(
                data.get("proxies"),
                list,
            )
        ):
            return data[
                "proxies"
            ]

        if isinstance(
            data,
            list,
        ):
            return data

    except Exception:
        pass

    return []


def parse_base64_yaml(text):

    try:

        compact = "".join(
            text.split()
        )

        decoded = (
            base64.b64decode(
                compact
                + "="
                * (
                    -len(compact)
                    % 4
                ),
                validate=False,
            )
        )

        return parse_yaml(
            decoded.decode(
                "utf-8",
                errors="ignore",
            )
        )

    except Exception:
        return []


def fetch_source(url):

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=12,
        )

        if response.status_code != 200:

            return (
                [],
                f"HTTP "
                f"{response.status_code}",
            )

        text = (
            response.text.strip()
        )

        nodes = parse_yaml(
            text
        )

        if nodes:
            return (
                nodes,
                "YAML",
            )

        nodes = parse_base64_yaml(
            text
        )

        if nodes:
            return (
                nodes,
                "Base64 YAML",
            )

        return (
            [],
            "unparsed",
        )

    except Exception as exc:

        return (
            [],
            str(exc),
        )


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

    if not isinstance(
        registry,
        dict,
    ):
        registry = {}

    source_lists = []

    for source_url in source_urls:

        raw, status = fetch_source(
            source_url
        )

        entry = ensure_source_entry(
            registry,
            source_url,
        )

        entry[
            "last_status"
        ] = status

        entry[
            "last_nodes"
        ] = len(raw)

        if raw:

            entry[
                "success_count"
            ] += 1

        else:

            entry[
                "failure_count"
            ] += 1

        normalized = []

        for node in raw:

            item = normalize_proxy(
                node
            )

            if item:
                normalized.append(
                    item
                )

        if normalized:

            source_lists.append(
                {
                    "source_url":
                        source_url,
                    "nodes":
                        normalized[
                            :MAX_PER_SOURCE
                        ],
                }
            )

    save_json(
        SOURCE_REGISTRY_FILE,
        registry,
    )

    candidates = []
    seen = set()
    index = 0

    while (
        len(candidates)
        < MAX_CANDIDATES
    ):

        added = False

        for source in source_lists:

            nodes = source[
                "nodes"
            ]

            if (
                index
                >= len(nodes)
            ):
                continue

            node = nodes[
                index
            ]

            fingerprint = (
                proxy_fingerprint(
                    node
                )
            )

            if (
                fingerprint
                in seen
            ):
                continue

            seen.add(
                fingerprint
            )

            candidates.append(
                {
                    "proxy":
                        node,

                    "fingerprint":
                        fingerprint,

                    "source_url":
                        source[
                            "source_url"
                        ],
                }
            )

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

    for index, candidate in enumerate(
        candidates,
        start=1,
    ):

        name = (
            f"TEST-{index:03d}"
        )

        proxy = dict(
            candidate["proxy"]
        )

        proxy["name"] = name

        proxies.append(proxy)

        metadata[name] = {
            "proxy":
                candidate["proxy"],

            "fingerprint":
                candidate["fingerprint"],

            "source_url":
                candidate["source_url"],
        }

    config = {

        "mixed-port":
            TEST_PORT,

        "allow-lan":
            False,

        "mode":
            "rule",

        "log-level":
            "silent",

        "external-controller":
            (
                f"127.0.0.1:"
                f"{CONTROLLER_PORT}"
            ),

        "proxies":
            proxies,

        "proxy-groups": [
            {
                "name":
                    "TEST",

                "type":
                    "select",

                "proxies":
                    [
                        p["name"]
                        for p in proxies
                    ],
            }
        ],

        "rules":
            [
                "MATCH,TEST"
            ],
    }

    return (
        config,
        metadata,
    )


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
# Mihomo 启动
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
        time.time()
        + 12
    )

    while (
        time.time()
        < deadline
    ):

        try:

            response = requests.get(
                (
                    f"{CONTROLLER_URL}"
                    f"/version"
                ),
                timeout=1,
            )

            if response.status_code == 200:
                return proc

        except Exception:
            pass

        time.sleep(
            0.5
        )

    try:

        proc.terminate()

        proc.wait(
            timeout=3
        )

    except Exception:

        try:
            proc.kill()
        except Exception:
            pass

    return None


def stop_mihomo(proc):

    if not proc:
        return

    try:

        proc.terminate()

        proc.wait(
            timeout=5
        )

    except Exception:

        try:
            proc.kill()
        except Exception:
            pass


def select_proxy(
    name
):

    try:

        response = requests.put(
            (
                f"{CONTROLLER_URL}"
                f"/proxies/TEST"
            ),
            json={
                "name": name
            },
            timeout=3,
        )

        if (
            response.status_code
            not in (
                200,
                204,
            )
        ):
            return False

        time.sleep(
            SWITCH_WAIT_SECONDS
        )

        return True

    except Exception:
        return False


# ============================================================
# Mihomo 原生真实延迟
# ============================================================

def proxy_delay(
    proxy_name,
    url,
    expected=None,
):

    encoded_name = quote(
        proxy_name,
        safe="",
    )

    params = {
        "url":
            url,

        "timeout":
            DELAY_TIMEOUT_MS,
    }

    if expected:
        params[
            "expected"
        ] = expected

    try:

        response = requests.get(
            (
                f"{CONTROLLER_URL}"
                f"/proxies/"
                f"{encoded_name}"
                f"/delay"
            ),
            params=params,
            timeout=(
                DELAY_TIMEOUT_MS
                / 1000
                + 2
            ),
        )

        if response.status_code != 200:
            return None

        data = response.json()

        delay = data.get(
            "delay"
        )

        if delay is None:
            return None

        return int(delay)

    except Exception:
        return None


# ============================================================
# 代理 Session
# ============================================================

def build_proxy_session():

    session = requests.Session()

    session.headers.update(
        HEADERS
    )

    session.proxies.update(
        {
            "http":
                (
                    f"http://127.0.0.1:"
                    f"{TEST_PORT}"
                ),

            "https":
                (
                    f"http://127.0.0.1:"
                    f"{TEST_PORT}"
                ),
        }
    )

    return session


# ============================================================
# URL 实际连通
# ============================================================

def probe_url(
    session,
    url,
    timeout=4,
):

    try:

        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
        )

        if (
            200
            <= response.status_code
            < 400
        ):
            return (
                True,
                response.status_code,
            )

        if response.status_code in (
            400,
            404,
            405,
            408,
            409,
            429,
        ):
            return (
                True,
                response.status_code,
            )

        return (
            False,
            response.status_code,
        )

    except Exception as exc:

        return (
            False,
            str(exc),
        )


def get_exit_ip_info(
    session
):

    try:

        response = session.get(
            IP_CHECK_URL,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            return None

        data = response.json()

        if data.get(
            "status"
        ) != "success":
            return None

        return data

    except Exception:
        return None


# ============================================================
# 单节点深度测试
# ============================================================

def test_node(
    proxy_name
):

    result = {

        "passed":
            False,

        "google_delay_ms":
            None,

        "gemini_delay_ms":
            None,

        "play_delay_ms":
            None,

        "max_delay_ms":
            None,

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

        "is_clean":
            False,

        "google_access":
            False,

        "gemini_access":
            False,

        "play_access":
            False,

        "mobile_probe_passed":
            0,

        "mobile_probe_total":
            len(
                GEMINI_MOBILE_PROBES
            ),

        "reason":
            "",
    }

    # 1. Google
    google_delay = proxy_delay(
        proxy_name,
        GOOGLE_DELAY_URL,
        "204",
    )

    result[
        "google_delay_ms"
    ] = google_delay

    if google_delay is None:
        result[
            "reason"
        ] = "Google delay failed"
        return result

    if (
        google_delay
        >= MAX_PROXY_DELAY_MS
    ):
        result[
            "reason"
        ] = (
            f"Google proxy delay "
            f"{google_delay}ms >= "
            f"{MAX_PROXY_DELAY_MS}ms"
        )
        return result

    # 2. Gemini
    gemini_delay = proxy_delay(
        proxy_name,
        GEMINI_DELAY_URL,
        "200-399",
    )

    result[
        "gemini_delay_ms"
    ] = gemini_delay

    if gemini_delay is None:
        result[
            "reason"
        ] = (
            "Gemini delay/HTTP "
            "check failed"
        )
        return result

    if (
        gemini_delay
        >= MAX_PROXY_DELAY_MS
    ):
        result[
            "reason"
        ] = (
            f"Gemini delay "
            f"{gemini_delay}ms >= "
            f"{MAX_PROXY_DELAY_MS}ms"
        )
        return result

    # 3. Google Play
    play_delay = proxy_delay(
        proxy_name,
        PLAY_DELAY_URL,
        "200-399",
    )

    result[
        "play_delay_ms"
    ] = play_delay

    if play_delay is None:
        result[
            "reason"
        ] = (
            "Google Play delay/"
            "HTTP check failed"
        )
        return result

    if (
        play_delay
        >= MAX_PROXY_DELAY_MS
    ):
        result[
            "reason"
        ] = (
            f"Google Play delay "
            f"{play_delay}ms >= "
            f"{MAX_PROXY_DELAY_MS}ms"
        )
        return result

    result[
        "max_delay_ms"
    ] = max(
        google_delay,
        gemini_delay,
        play_delay,
    )

    # 4. IP 清洁度
    session = build_proxy_session()

    ip_info = get_exit_ip_info(
        session
    )

    if not ip_info:
        result[
            "reason"
        ] = "Exit IP information failed"
        return result

    result[
        "exit_ip"
    ] = ip_info.get(
        "query",
        "",
    )

    result[
        "country"
    ] = ip_info.get(
        "country",
        "",
    )

    result[
        "countryCode"
    ] = ip_info.get(
        "countryCode",
        "",
    )

    result[
        "city"
    ] = ip_info.get(
        "city",
        "",
    )

    result[
        "org"
    ] = ip_info.get(
        "org",
        "",
    )

    result[
        "isp"
    ] = ip_info.get(
        "isp",
        "",
    )

    result[
        "hosting"
    ] = bool(
        ip_info.get(
            "hosting",
            False,
        )
    )

    result[
        "proxy"
    ] = bool(
        ip_info.get(
            "proxy",
            False,
        )
    )

    result[
        "is_clean"
    ] = (
        not result["hosting"]
        and not result["proxy"]
    )

    if (
        REQUIRE_CLEAN_IP
        and not result["is_clean"]
    ):
        result[
            "reason"
        ] = (
            "IP marked as hosting/proxy"
        )
        return result

    # 5. 实际 GET
    ok, _ = probe_url(
        session,
        GEMINI_DELAY_URL,
        5,
    )

    if not ok:
        result[
            "reason"
        ] = "Gemini GET probe failed"
        return result

    result[
        "gemini_access"
    ] = True

    ok, _ = probe_url(
        session,
        PLAY_DELAY_URL,
        5,
    )

    if not ok:
        result[
            "reason"
        ] = (
            "Google Play GET "
            "probe failed"
        )
        return result

    result[
        "play_access"
    ] = True

    ok, _ = probe_url(
        session,
        "https://www.google.com/",
        5,
    )

    if not ok:
        result[
            "reason"
        ] = "Google GET probe failed"
        return result

    result[
        "google_access"
    ] = True

    # 6. Gemini Android / Google 关键主机
    passed = 0

    for url in GEMINI_MOBILE_PROBES:

        ok, _ = probe_url(
            session,
            url,
            4,
        )

        if ok:
            passed += 1

    result[
        "mobile_probe_passed"
    ] = passed

    required_mobile = max(
        5,
        int(
            len(
                GEMINI_MOBILE_PROBES
            ) * 0.75
            + 0.999
        ),
    )

    if (
        passed
        < required_mobile
    ):
        result[
            "reason"
        ] = (
            f"Gemini mobile host probes "
            f"{passed}/"
            f"{len(GEMINI_MOBILE_PROBES)}"
        )
        return result

    result[
        "passed"
    ] = True

    return result


# ============================================================
# 节点历史
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
        "last_seen",
        0,
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

        pass_count = (
            int(
                old.get(
                    "pass_count",
                    0,
                )
            )
            + 1
        )

    history[
        fingerprint
    ] = {

        "first_seen":
            first_seen,

        "last_seen":
            now,

        "pass_count":
            pass_count,

        "last_max_delay_ms":
            test[
                "max_delay_ms"
            ],

        "last_google_delay_ms":
            test[
                "google_delay_ms"
            ],

        "last_gemini_delay_ms":
            test[
                "gemini_delay_ms"
            ],

        "last_play_delay_ms":
            test[
                "play_delay_ms"
            ],

        "last_exit_ip":
            test[
                "exit_ip"
            ],

        "country":
            test[
                "country"
            ],

        "countryCode":
            test[
                "countryCode"
            ],

        "city":
            test[
                "city"
            ],

        "org":
            test[
                "org"
            ],

        "isp":
            test[
                "isp"
            ],

        "hosting":
            test[
                "hosting"
            ],

        "proxy":
            test[
                "proxy"
            ],

        "mobile_probe_passed":
            test[
                "mobile_probe_passed"
            ],

        "name":
            original_name,
    }

    return history[
        fingerprint
    ]


# ============================================================
# 来源历史
# ============================================================

def finalize_source_registry(
    registry,
    qualified_by_source,
):

    for (
        url,
        count
    ) in qualified_by_source.items():

        entry = ensure_source_entry(
            registry,
            url,
        )

        if count <= 0:
            continue

        entry[
            "last_qualified_at"
        ] = int(time.time())

        entry[
            "last_qualified_nodes"
        ] = count

        entry[
            "qualified_runs"
        ] = (
            int(
                entry.get(
                    "qualified_runs",
                    0,
                )
            )
            + 1
        )

        entry[
            "qualified_nodes_total"
        ] = (
            int(
                entry.get(
                    "qualified_nodes_total",
                    0,
                )
            )
            + count
        )


# ============================================================
# 最终 Clash 配置
# ============================================================

def build_final_config(
    passed_nodes
):

    proxies = []

    for node in passed_nodes:

        proxy = dict(
            node[
                "proxy"
            ]
        )

        proxy[
            "name"
        ] = node[
            "display_name"
        ]

        proxies.append(
            proxy
        )

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

    auto_nodes = (
        names
        if names
        else ["REJECT"]
    )

    manual_nodes = (
        names
        if names
        else ["DIRECT"]
    )

    return {

        # ====================================================
        # 基础
        # ====================================================

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

        "unified-delay":
            True,

        "tcp-concurrent":
            True,

        "proxies":
            proxies,

        # ====================================================
        # DNS
        # ====================================================
        # 国内：
        #   国内域名优先走国内 DoH
        #   DIRECT 再由系统 DNS 解析
        #
        # 海外：
        #   使用默认 nameserver
        #
        # IPv6 DNS 关闭，避免部分国内网络
        # 因 AAAA 路径异常产生额外等待。
        # ====================================================

        "dns": {

            "enable":
                True,

            "cache-algorithm":
                "arc",

            "prefer-h3":
                False,

            "use-hosts":
                True,

            "use-system-hosts":
                True,

            "respect-rules":
                False,

            "listen":
                "0.0.0.0:1053",

            "ipv6":
                False,

            "enhanced-mode":
                "fake-ip",

            "fake-ip-range":
                "198.18.0.1/16",

            "fake-ip-filter-mode":
                "blacklist",

            "fake-ip-filter": [
                "*.lan",
                "*.local",
                "+.local",
                "+.localhost",
            ],

            "default-nameserver": [
                "223.5.5.5",
                "223.6.6.6",
            ],

            # 国内域名优先国内 DoH
            "nameserver-policy": {

                "geosite:cn": [
                    "https://doh.pub/dns-query",
                    "https://dns.alidns.com/dns-query",
                ],

                "+.cn": [
                    "https://doh.pub/dns-query",
                    "https://dns.alidns.com/dns-query",
                ],

                "+.com.cn": [
                    "https://doh.pub/dns-query",
                    "https://dns.alidns.com/dns-query",
                ],

                "+.org.cn": [
                    "https://doh.pub/dns-query",
                    "https://dns.alidns.com/dns-query",
                ],

                "+.net.cn": [
                    "https://doh.pub/dns-query",
                    "https://dns.alidns.com/dns-query",
                ],
            },

            # 默认 DNS
            "nameserver": [
                "https://doh.pub/dns-query",
                "https://dns.alidns.com/dns-query",
            ],

            # DIRECT 出口重新使用系统 DNS
            "direct-nameserver": [
                "system",
            ],

            "direct-nameserver-follow-policy":
                False,

        },

        # ====================================================
        # Proxy Groups
        # ====================================================

        "proxy-groups": [

            {
                "name":
                    "🚀 节点选择",

                "type":
                    "select",

                "proxies": [
                    "♻️ 自动选择",
                    "🛍 Play自动选择",
                    "🌐 手动选择",
                    "🇹🇼 台湾",
                    "🇺🇸 美国",
                    "DIRECT",
                ],
            },

            # Gemini 自动选择
            {
                "name":
                    "♻️ 自动选择",

                "type":
                    "url-test",

                "url":
                    GEMINI_DELAY_URL,

                "expected-status":
                    "200-399",

                "interval":
                    180,

                "tolerance":
                    30,

                "lazy":
                    False,

                "proxies":
                    auto_nodes,
            },

            # Google Play 自动选择
            {
                "name":
                    "🛍 Play自动选择",

                "type":
                    "url-test",

                "url":
                    PLAY_DELAY_URL,

                "expected-status":
                    "200-399",

                "interval":
                    180,

                "tolerance":
                    30,

                "lazy":
                    False,

                "proxies":
                    auto_nodes,
            },

            {
                "name":
                    "🌐 手动选择",

                "type":
                    "select",

                "proxies":
                    manual_nodes,
            },

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

        # ====================================================
        # Rules
        # ====================================================

        "rules": [

            # 私有网络
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",

            # 中国大陆
            "GEOSITE,CN,DIRECT",
            "GEOIP,CN,DIRECT",

            "DOMAIN-SUFFIX,cn,DIRECT",
            "DOMAIN-SUFFIX,com.cn,DIRECT",
            "DOMAIN-SUFFIX,org.cn,DIRECT",
            "DOMAIN-SUFFIX,net.cn,DIRECT",
            "DOMAIN-SUFFIX,gov.cn,DIRECT",

            # 常用国内站点
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

            # Google Play
            "DOMAIN-SUFFIX,play.google.com,🛍 Play自动选择",
            "DOMAIN-SUFFIX,play.googleapis.com,🛍 Play自动选择",

            # Gemini / Google
            "DOMAIN-SUFFIX,gemini.google.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,jnn-pa.googleapis.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,waa-pa.clients6.google.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,apis.google.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,googleapis.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,gstatic.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,googleusercontent.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,ggpht.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,gvt1.com,♻️ 自动选择",
            "DOMAIN-SUFFIX,google.com,♻️ 自动选择",

            # YouTube
            "DOMAIN-SUFFIX,youtube.com,🚀 节点选择",
            "DOMAIN-SUFFIX,youtubei.googleapis.com,🚀 节点选择",
            "DOMAIN-SUFFIX,googlevideo.com,🚀 节点选择",

            # 其他海外
            "MATCH,🚀 节点选择",
        ],
    }


# ============================================================
# 主流程
# ============================================================

def run_agent():

    now = int(
        time.time()
    )

    history = load_history()

    registry = load_json(
        SOURCE_REGISTRY_FILE,
        {},
    )

    if not isinstance(
        registry,
        dict,
    ):
        registry = {}

    # --------------------------------------------------------
    # 1. 自动发现订阅源
    # --------------------------------------------------------

    source_urls = (
        discover_subscription_sources()
    )

    # --------------------------------------------------------
    # 2. 获取候选节点
    # --------------------------------------------------------

    candidates = (
        collect_candidates(
            source_urls
        )
    )

    if not candidates:

        write_yaml(
            "live_clash.yaml",
            build_final_config(
                []
            ),
        )

        save_history(
            history
        )

        return

    # --------------------------------------------------------
    # 3. 启动 Mihomo 测试实例
    # --------------------------------------------------------

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

    qualified_by_source = {}

    try:

        proc = start_mihomo(
            config_path
        )

        if not proc:
            raise RuntimeError(
                "Mihomo failed to start"
            )

        # ----------------------------------------------------
        # 4. 逐节点深度测试
        # ----------------------------------------------------

        for (
            internal_name,
            meta
        ) in metadata.items():

            if not select_proxy(
                internal_name
            ):
                continue

            test = test_node(
                internal_name
            )

            if not test[
                "passed"
            ]:

                print(
                    f"REJECT "
                    f"{internal_name}: "
                    f"{test['reason']}"
                )

                continue

            fingerprint = (
                meta[
                    "fingerprint"
                ]
            )

            proxy = meta[
                "proxy"
            ]

            source_url = meta[
                "source_url"
            ]

            original_name = (
                proxy.get(
                    "name",
                    internal_name,
                )
            )

            # ------------------------------------------------
            # 5. 节点历史
            # ------------------------------------------------

            history_item = (
                update_history(
                    history,
                    fingerprint,
                    now,
                    test,
                    original_name,
                )
            )

            pass_count = (
                history_item[
                    "pass_count"
                ]
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

            if (
                pass_count
                < STABLE_PASS_COUNT
            ):
                continue

            country_code = (
                test[
                    "countryCode"
                ]
            )

            if country_code == "TW":
                flag = "🇹🇼"

            elif country_code == "US":
                flag = "🇺🇸"

            else:
                flag = "🌐"

            clean_tag = (
                "洁"
                if test[
                    "is_clean"
                ]
                else "机"
            )

            display_name = (
                f"{flag}{clean_tag} "
                f"[{test['max_delay_ms']}ms|"
                f"{survival_hours}h|"
                f"{pass_count}次] "
                f"{original_name}"
            )

            passed.append(
                {
                    "proxy":
                        proxy,

                    "display_name":
                        display_name,

                    "fingerprint":
                        fingerprint,

                    "source_url":
                        source_url,

                    "test":
                        test,

                    "pass_count":
                        pass_count,

                    "survival_hours":
                        survival_hours,

                    "latency":
                        test[
                            "max_delay_ms"
                        ],

                    "countryCode":
                        country_code,

                    "is_clean":
                        test[
                            "is_clean"
                        ],
                }
            )

            qualified_by_source[
                source_url
            ] = (
                qualified_by_source.get(
                    source_url,
                    0,
                )
                + 1
            )

            print(
                f"PASS "
                f"{internal_name} | "
                f"{country_code} | "
                f"max={test['max_delay_ms']}ms | "
                f"Google={test['google_delay_ms']} | "
                f"Gemini={test['gemini_delay_ms']} | "
                f"Play={test['play_delay_ms']} | "
                f"Mobile={test['mobile_probe_passed']}/"
                f"{test['mobile_probe_total']} | "
                f"life={survival_hours}h"
            )

    finally:

        save_history(
            history
        )

        finalize_source_registry(
            registry,
            qualified_by_source,
        )

        save_json(
            SOURCE_REGISTRY_FILE,
            registry,
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

    # --------------------------------------------------------
    # 6. 最终排序
    # --------------------------------------------------------

    def sort_key(node):

        country_code = (
            node[
                "countryCode"
            ]
        )

        # 台湾 > 美国 > 其他
        region_rank = (
            0
            if country_code == "TW"
            else (
                1
                if country_code == "US"
                else 2
            )
        )

        # 清洁优先
        clean_rank = (
            0
            if node[
                "is_clean"
            ]
            else 1
        )

        # 长寿命优先
        long_life_rank = (
            0
            if (
                node[
                    "survival_hours"
                ]
                >= MIN_SURVIVAL_HOURS
            )
            else 1
        )

        return (
            region_rank,
            clean_rank,
            long_life_rank,
            -node[
                "survival_hours"
            ],
            -node[
                "pass_count"
            ],
            node[
                "latency"
            ] or 999999,
        )

    passed.sort(
        key=sort_key
    )

    passed = passed[
        :MAX_OUTPUT_NODES
    ]

    # --------------------------------------------------------
    # 7. 输出
    # --------------------------------------------------------

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
        "=" * 70
    )

    print(
        f"Final qualified nodes: "
        f"{len(passed)}"
    )

    print(
        "=" * 70
    )

    for node in passed:

        print(
            f"{node['display_name']} | "
            f"{node['countryCode']} | "
            f"{node['test']['exit_ip']} | "
            f"{node['source_url']}"
        )


if __name__ == "__main__":
    run_agent()
