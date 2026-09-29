import os
import re
import socket
import subprocess
import time
import json
import requests
import yaml

GITHUB_TOKEN = os.getenv("GH_TOKEN", "")
SEARCH_QUERY = "clash subscription stars:>200 pushed:>2026-03-01"
SUBCONVERTER_API = "https://api.v1.mk/sub?target=clash&url="

# 优化后的筛选条件
MAX_PING_MS = 250  # 适当放宽延迟上限至 250ms，确保公网优质节点顺利入选
GEMINI_TEST_URL = "https://alkalinetransit-pa.googleapis.com/v1beta/models"
HISTORY_FILE = "node_history.json"

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"


def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)


def fetch_high_star_repos():
    print("🔍 正在检索 GitHub 上高星且活跃的 Clash 仓库...")
    url = f"https://api.github.com/search/repositories?q={SEARCH_QUERY}&sort=stars&order=desc"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            repos = resp.json().get("items", [])
            print(f"✅ 找到 {len(repos)} 个优质仓库")
            return [repo["full_name"] for repo in repos[:10]]
        return []
    except Exception as e:
        print(f"❌ 检索仓库失败: {e}")
        return []


def find_subscription_urls(repo_full_name):
    common_files = ["clash.yaml", "clash.yml", "sub", "output/clash.yaml"]
    found_urls = []
    proxy_prefix = "https://gh-proxy.com/"

    for file in common_files:
        raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/main/{file}"
        test_url = f"{proxy_prefix}{raw_url}"
        try:
            r = requests.head(test_url, timeout=5)
            if r.status_code == 200:
                found_urls.append(test_url)
        except Exception:
            continue
    return found_urls


def test_tcp_ping(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        result = sock.connect_ex((host, int(port)))
        latency = int((time.time() - start_time) * 1000)
        sock.close()
        if result == 0:
            return True, latency
    except Exception:
        pass
    return False, -1


def check_node_quality_and_gemini(proxy_config):
    """深度测试：美国出口 IP + 清洁度 + 机房固定 IP + Gemini 可用性"""
    temp_clash_config = {
        "mixed-port": 9050,
        "mode": "rule",
        "log-level": "silent",
        "proxies": [proxy_config],
        "rules": ["MATCH,GLOBAL"],
    }

    with open("temp_config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_clash_config, f)

    proc = subprocess.Popen(
        ["clash", "-f", "temp_config.yaml"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    proxies_http = {
        "http": "http://127.0.0.1:9050",
        "https": "http://127.0.0.1:9050",
    }

    is_us_ip = False
    is_clean_ip = False
    is_stable_datacenter = False
    can_access_gemini = False

    try:
        ip_res = requests.get(
            "http://ip-api.com/json/?fields=status,countryCode,hosting,proxy,org,isp,query",
            proxies=proxies_http,
            timeout=6,
        )
        if ip_res.status_code == 200:
            ip_data = ip_res.json()
            if ip_data.get("countryCode") == "US":
                is_us_ip = True
            if not ip_data.get("proxy", False):
                is_clean_ip = True
            # 标记数据中心 IP
            if ip_data.get("hosting", False):
                is_stable_datacenter = True

        gemini_res = requests.get(
            GEMINI_TEST_URL, proxies=proxies_http, timeout=6, verify=True
        )
        if gemini_res.status_code in [200, 400, 401]:
            can_access_gemini = True

    except Exception:
        pass
    finally:
        proc.terminate()
        proc.wait()
        if os.path.exists("temp_config.yaml"):
            os.remove("temp_config.yaml")

    return is_us_ip and is_clean_ip and can_access_gemini and is_stable_datacenter


def verify_and_filter_sub(yaml_url):
    print(f"🧪 解析并筛选订阅: {yaml_url}")
    target_url = (
        yaml_url
        if (yaml_url.endswith(".yaml") or yaml_url.endswith(".yml"))
        else f"{SUBCONVERTER_API}{yaml_url}"
    )

    try:
        resp = requests.get(target_url, timeout=10)
        if resp.status_code != 200:
            return []

        config = yaml.safe_load(resp.text)
        proxies = config.get("proxies", [])
        if not proxies:
            return []

        filtered_proxies = []

        for proxy in proxies[:30]:
            name = proxy.get("name", "")
            server = proxy.get("server")
            port = proxy.get("port")

            if not (server and port):
                continue

            # 过滤美国地名标识
            if not re.search(
                r"(US|United States|美国|美|洛杉矶|圣何塞|西雅图|芝加哥)",
                name,
                re.IGNORECASE,
            ):
                continue

            # PING 延迟测试
            is_alive, ping_ms = test_tcp_ping(server, port)
            if not is_alive or ping_ms > MAX_PING_MS:
                continue

            # 深度清洁度与 Gemini 连通性测试
            if check_node_quality_and_gemini(proxy):
                proxy["_ping_ms"] = ping_ms
                filtered_proxies.append(proxy)
                print(f"  ✅ 发现优质美国节点: {name} (Ping: {ping_ms}ms)")

        return filtered_proxies

    except Exception as e:
        print(f"⚠️ 解析失败: {e}")
        return []


def run_agent():
    history = load_history()
    current_time = int(time.time())
    new_history = {}

    repos = fetch_high_star_repos()
    candidate_proxies = []

    for repo in repos:
        urls = find_subscription_urls(repo)
        for url in urls:
            nodes = verify_and_filter_sub(url)
            candidate_proxies.extend(nodes)

    matched_proxies = []

    for proxy in candidate_proxies:
        server_key = f"{proxy.get('server')}:{proxy.get('port')}"

        first_seen = history.get(server_key, {}).get("first_seen", current_time)
        new_history[server_key] = {
            "first_seen": first_seen,
            "last_seen": current_time,
        }

        survival_hours = int((current_time - first_seen) / 3600)
        ping_ms = proxy.pop("_ping_ms", 0)

        # 节点重命名（标注存活时间与延迟）
        proxy["name"] = f"🇺🇸 [存活{survival_hours}h|{ping_ms}ms] {proxy.get('name')}"
        matched_proxies.append(proxy)

    save_history(new_history)

    final_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": matched_proxies,
    }

    with open("live_clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(final_config, f, allow_unicode=True)

    print(f"\n✨ 筛选完成！共保留 {len(matched_proxies)} 个高品质美国节点。")


if __name__ == "__main__":
    run_agent()
