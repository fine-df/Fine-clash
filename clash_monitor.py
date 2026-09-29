import os
import re
import socket
import subprocess
import time
import requests
import yaml

# 1. 基础配置
GITHUB_TOKEN = os.getenv("GH_TOKEN", "")
SEARCH_QUERY = "clash subscription stars:>200 pushed:>2026-03-01"
SUBCONVERTER_API = "https://api.v1.mk/sub?target=clash&url="

# 筛选条件
MAX_PING_MS = 180  # 最大响应延迟 180ms
GEMINI_TEST_URL = "https://alkalinetransit-pa.googleapis.com/v1beta/models"

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"


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
        print(f"❌ 请求失败: {e}")
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
        except:
            continue
    return found_urls


def test_tcp_ping(host, port, timeout=2):
    """测量 TCP 握手延迟 (PING <= 180ms)"""
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
    """验证：美国出口 IP + 高清洁度(非高风险代理段) + Gemini 通畅度"""
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
    can_access_gemini = False

    try:
        # 1. IP 属性与清洁度分析
        ip_res = requests.get(
            "http://ip-api.com/json/?fields=status,countryCode,hosting,proxy,query",
            proxies=proxies_http,
            timeout=6,
        )
        if ip_res.status_code == 200:
            ip_data = ip_res.json()
            if ip_data.get("countryCode") == "US":
                is_us_ip = True
            if not ip_data.get("proxy", False):
                is_clean_ip = True

        # 2. Gemini 可用性测试
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

    return is_us_ip and is_clean_ip and can_access_gemini


def verify_and_filter_sub(yaml_url):
    print(f"🧪 下载并严格筛选订阅: {yaml_url}")
    target_url = (
        yaml_url
        if (yaml_url.endswith(".yaml") or yaml_url.endswith(".yml"))
        else f"{SUBCONVERTER_API}{yaml_url}"
    )

    try:
        resp = requests.get(target_url, timeout=10)
        if resp.status_code != 200:
            return None

        config = yaml.safe_load(resp.text)
        proxies = config.get("proxies", [])
        if not proxies:
            return None

        filtered_proxies = []

        for proxy in proxies[:40]:
            name = proxy.get("name", "")
            server = proxy.get("server")
            port = proxy.get("port")

            if not (server and port):
                continue

            # 筛选美国关键词
            if not re.search(
                r"(US|United States|美国|美|洛杉矶|圣何塞|西雅图|芝加哥)",
                name,
                re.IGNORECASE,
            ):
                continue

            # PING 测速测试 (<= 180ms)
            is_alive, ping_ms = test_tcp_ping(server, port)
            if not is_alive or ping_ms > MAX_PING_MS:
                continue

            # 深度清洁度与 Gemini 测试
            if check_node_quality_and_gemini(proxy):
                proxy["name"] = f"🇺🇸 [US-{ping_ms}ms] {name}"
                filtered_proxies.append(proxy)
                print(f"  ✅ 保留节点: [{proxy['name']}]")

        if filtered_proxies:
            config["proxies"] = filtered_proxies
            return config

    except Exception as e:
        print(f"⚠️ 校验失败: {e}")

    return None


def run_agent():
    repos = fetch_high_star_repos()
    matched_proxies = []

    for repo in repos:
        urls = find_subscription_urls(repo)
        for url in urls:
            cfg = verify_and_filter_sub(url)
            if cfg and cfg.get("proxies"):
                matched_proxies.extend(cfg["proxies"])

    # 生成最终可用的 Clash 配置文件
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

    print(
        f"\n✨ 完成！提取到 {len(matched_proxies)} 个符合条件的【高清洁度美国低PING节点】"
    )


if __name__ == "__main__":
    run_agent()
