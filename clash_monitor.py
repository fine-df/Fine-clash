import os
import json
import time
import hashlib
import base64
import subprocess
from urllib.parse import urlparse

import requests
import yaml


# =========================
# 基础配置
# =========================

HISTORY_FILE = "node_history.json"

MIHOMO_BIN = "clash"
MIXED_PORT = 9050
CONTROLLER_PORT = 9090
CONTROLLER_URL = f"http://127.0.0.1:{CONTROLLER_PORT}"

MAX_CANDIDATES = 60
MAX_PER_SOURCE = 20

SWITCH_WAIT_SECONDS = 1.0
REQUEST_TIMEOUT = 8

# 连续多少次成功后认为稳定
STABLE_PASS_COUNT = 3

# 如果节点超过这个时间没有成功，再次出现时重新计算 first_seen
HISTORY_RESET_HOURS = 48

# 实际检测目标
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
    "Chrome/154.0.0.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}

GITHUB_TOKEN = os.getenv("GH_TOKEN", "")
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"


# =========================
# 订阅源
# =========================

PRESET_SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/freefq/free/master/clash.m3u",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/er26/free/main/clash.yaml",
    "https://raw.githubusercontent.com/nodefree/nodefree.github.io/main/clash/clash.yaml",
    "https://raw.githubusercontent.com/Pawroid/Free-Node/main/clash.yaml",
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
            json.dump(
                history,
                f,
                ensure_ascii=False,
                indent=2,
            )
    except Exception as e:
        print(f"⚠️ 历史记录保存失败: {e}")


# =========================
# 节点标准化 / 去重
# =========================

def normalize_proxy(proxy):
    if not isinstance(proxy, dict):
        return None

    result = {}

    for key, value in proxy.items():
        if value is None:
            continue

        result[key] = value

    server = result.get("server")
    port = result.get("port")

    if not server or not port:
        return None

    try:
        port = int(port)
    except Exception:
        return None

    result["port"] = port

    # Mihomo 必须有 name
    if not result.get("name"):
        result["name"] = f"{result.get('type', 'proxy')}-{server}:{port}"

    return result


def proxy_fingerprint(proxy):
    """
    不只使用 server:port。
    同一 IP:port 可能存在不同 UUID / password / TLS / transport。
    """
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

        decoded = base64.b64decode(
            compact + "=" * (-len(compact) % 4),
            validate=False,
        )

        decoded_text = decoded.decode("utf-8", errors="ignore")

        return try_yaml_parse(decoded_text)

    except Exception:
        return []


def fetch_proxies_from_url(url):
    print(f"\n📥 获取订阅: {url}")

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=15,
        )

        if response.status_code != 200:
            print(f"⚠️ HTTP {response.status_code}")
            return []

        text = response.text.strip()

        # 第一优先：标准 Clash YAML
        proxies = try_yaml_parse(text)

        if proxies:
            return proxies

        # 第二优先：Base64 编码的 Clash YAML
        proxies = try_base64_yaml_parse(text)

        if proxies:
            return proxies

        print("⚠️ 无法解析为 Clash YAML/Base64 Clash YAML")

    except Exception as e:
        print(f"⚠️ 订阅获取失败: {e}")

    return []


# =========================
# 候选节点收集
# =========================

def collect_candidates():
    source_lists = []

    for source_url in PRESET_SUBSCRIPTION_URLS:
        raw = fetch_proxies_from_url(source_url)

        normalized = []

        for proxy in raw:
            proxy = normalize_proxy(proxy)

            if proxy:
                normalized.append(proxy)

        # 单源限额，避免某一个源垄断候选池
        normalized = normalized[:MAX_PER_SOURCE]

        print(f"  └─ 有效候选: {len(normalized)}")

        source_lists.append(normalized)

    # 轮流从各源取节点，避免第一个源垄断
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

    print(
        f"\n📊 最终进入深度测试的候选节点: "
        f"{len(candidates)}"
    )

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

        "rules": [
            "MATCH,TEST",
        ],
    }

    return config, metadata


def write_temp_config(config):
    path = "temp_mihomo.yaml"

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False,
        )

    return path


# =========================
# 启动 Mihomo
# =========================

def start_mihomo(config_path):
    print("\n🚀 启动 Mihomo...")

    proc = subprocess.Popen(
        [
            MIHOMO_BIN,
            "-f",
            config_path,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 等待 controller 出现
    deadline = time.time() + 12

    while time.time() < deadline:
        try:
            response = requests.get(
                f"{CONTROLLER_URL}/version",
                timeout=1,
            )

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


# =========================
# 切换节点
# =========================

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
# 通过当前代理测试
# =========================

def test_current_proxy():
    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        }
    )

    proxies = {
        "http": f"http://127.0.0.1:{MIXED_PORT}",
        "https": f"http://127.0.0.1:{MIXED_PORT}",
    }

    session.proxies.update(proxies)

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
        "latency_ms": None,
        "reason": "",
    }

    # -------------------------
    # 1. 出口 IP
    # -------------------------

    try:
        start = time.time()

        response = session.get(
            IP_CHECK_URL,
            timeout=REQUEST_TIMEOUT,
        )

        result["latency_ms"] = int(
            (time.time() - start) * 1000
        )

        if response.status_code != 200:
            result["reason"] = (
                f"IP API HTTP {response.status_code}"
            )
            return result

        data = response.json()

        if data.get("status") != "success":
            result["reason"] = "IP API 返回失败"
            return result

        result["exit_ip"] = data.get("query", "")
        result["country"] = data.get("country", "")
        result["city"] = data.get("city", "")
        result["org"] = data.get("org", "")
        result["isp"] = data.get("isp", "")
        result["hosting"] = bool(data.get("hosting", False))
        result["proxy"] = bool(data.get("proxy", False))

        # 必须美国出口
        if data.get("countryCode") != "US":
            result["reason"] = (
                f"出口国家不是 US: "
                f"{data.get('countryCode')}"
            )
            return result

        # proxy=true 直接淘汰
        if result["proxy"]:
            result["reason"] = "IP API 判定为 proxy"
            return result

        # 需要机房 IP
        if not result["hosting"]:
            result["reason"] = "不是 hosting/datacenter IP"
            return result

    except Exception as e:
        result["reason"] = f"出口 IP 检测失败: {e}"
        return result

    # -------------------------
    # 2. Google 基础连通性
    # -------------------------

    try:
        response = session.get(
            GOOGLE_TEST_URL,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        if response.status_code in (200, 204):
            result["google_access"] = True
        else:
            result["reason"] = (
                f"Google 连通失败 HTTP {response.status_code}"
            )
            return result

    except Exception as e:
        result["reason"] = f"Google 请求失败: {e}"
        return result

    # -------------------------
    # 3. Gemini Web
    # -------------------------

    try:
        response = session.get(
            GEMINI_TEST_URL,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        final_host = urlparse(
            response.url
        ).hostname or ""

        # 允许：
        # gemini.google.com
        # accounts.google.com
        # www.google.com
        google_domain = (
            final_host == "google.com"
            or final_host.endswith(".google.com")
        )

        if response.status_code in range(200, 400) and google_domain:
            result["gemini_access"] = True
        else:
            result["reason"] = (
                f"Gemini Web 不满足条件: "
                f"HTTP {response.status_code}, "
                f"host={final_host}"
            )
            return result

    except Exception as e:
        result["reason"] = f"Gemini Web 请求失败: {e}"
        return result

    # -------------------------
    # 4. Gemini API 网络层
    #
    # 这里不需要 API Key。
    # 目标是判断：
    # generativelanguage.googleapis.com
    # 是否能通过该节点建立 HTTPS/HTTP。
    #
    # 401/403 本身不能代表 API 可调用，
    # 但可以证明 Google API 服务端已收到请求。
    # -------------------------

    try:
        response = session.get(
            GEMINI_API_TEST_URL,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        if response.status_code in (
            200,
            400,
            401,
            403,
            404,
        ):
            result["gemini_api_reachable"] = True

        else:
            result["reason"] = (
                "Gemini API 网络层异常: "
                f"HTTP {response.status_code}"
            )
            return result

    except Exception as e:
        result["reason"] = (
            f"Gemini API 网络层失败: {e}"
        )
        return result

    # 全部通过
    result["passed"] = True
    return result


# =========================
# 历史状态
# =========================

def update_history(
    history,
    fingerprint,
    current_time,
    test_result,
    original_name,
):
    old = history.get(fingerprint, {})

    last_seen = old.get("last_seen", 0)

    # 太久没有通过，视为重新出现
    if (
        last_seen
        and current_time - last_seen
        > HISTORY_RESET_HOURS * 3600
    ):
        first_seen = current_time
        pass_count = 1
    else:
        first_seen = old.get(
            "first_seen",
            current_time,
        )

        pass_count = int(
            old.get("pass_count", 0)
        ) + 1

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
# 输出最终 Clash 配置
# =========================

def build_final_config(passed_nodes):
    proxies = []

    for node in passed_nodes:
        proxy = dict(node["proxy"])

        display_name = node["display_name"]

        proxy["name"] = display_name

        proxies.append(proxy)

    proxy_names = [
        proxy["name"]
        for proxy in proxies
    ]

    final_config = {
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

    return final_config


# =========================
# 主流程
# =========================

def run_agent():
    current_time = int(time.time())

    history = load_history()

    candidates = collect_candidates()

    if not candidates:
        print("\n❌ 没有获得有效候选节点")

        save_history(history)

        final_config = {
            "mixed-port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "proxies": [],
        }

        with open(
            "live_clash.yaml",
            "w",
            encoding="utf-8",
        ) as f:
            yaml.safe_dump(
                final_config,
                f,
                allow_unicode=True,
                sort_keys=False,
            )

        return

    config, metadata = build_mihomo_config(
        candidates
    )

    config_path = write_temp_config(config)

    proc = None

    passed_nodes = []

    try:
        proc = start_mihomo(config_path)

        if proc is None:
            return

        print(
            f"\n🔎 开始逐节点实际测试，共 "
            f"{len(metadata)} 个\n"
        )

        for internal_name, meta in metadata.items():
            proxy = meta["proxy"]
            fingerprint = meta["fingerprint"]

            original_name = proxy.get(
                "name",
                internal_name,
            )

            print(
                f"▶ {internal_name} | "
                f"{original_name}"
            )

            if not select_proxy(internal_name):
                print("  ❌ Mihomo 节点切换失败")
                continue

            test_result = test_current_proxy()

            if not test_result["passed"]:
                print(
                    f"  ❌ 淘汰: "
                    f"{test_result['reason']}"
                )
                continue

            history_item = update_history(
                history,
                fingerprint,
                current_time,
                test_result,
                original_name,
            )

            first_seen = history_item[
                "first_seen"
            ]

            survival_hours = int(
                (current_time - first_seen) / 3600
            )

            pass_count = history_item[
                "pass_count"
            ]

            latency = test_result[
                "latency_ms"
            ]

            display_name = (
                f"🇺🇸 "
                f"[{latency}ms|"
                f"{survival_hours}h|"
                f"{pass_count}次] "
                f"{original_name}"
            )

            passed_nodes.append(
                {
                    "proxy": proxy,
                    "display_name": display_name,
                    "fingerprint": fingerprint,
                    "test": test_result,
                }
            )

            print(
                f"  ✅ 通过 | "
                f"IP={test_result['exit_ip']} | "
                f"{test_result['city']} | "
                f"{latency}ms | "
                f"累计通过 {pass_count} 次"
            )

    finally:
        save_history(history)

        stop_mihomo(proc)

        if os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception:
                pass

    # =========================
    # 排序
    # =========================

    passed_nodes.sort(
        key=lambda x: (
            -x["history"]["pass_count"]
            if "history" in x
            else 0,
            x["test"]["latency_ms"]
            if x["test"]["latency_ms"] is not None
            else 999999,
        )
    )

    # =========================
    # 输出
    # =========================

    final_config = build_final_config(
        passed_nodes
    )

    with open(
        "live_clash.yaml",
        "w",
        encoding="utf-8",
    ) as f:
        yaml.safe_dump(
            final_config,
            f,
            allow_unicode=True,
            sort_keys=False,
        )

    print("\n" + "=" * 60)
    print(
        f"✅ 最终通过 Gemini 检测: "
        f"{len(passed_nodes)} 个"
    )
    print("=" * 60)

    for node in passed_nodes:
        test = node["test"]

        print(
            f"🇺🇸 {node['display_name']} | "
            f"{test['exit_ip']} | "
            f"{test['org']}"
        )


if __name__ == "__main__":
    run_agent()
