import os
import re
import socket
import subprocess
import time
import json
import requests
import yaml

GITHUB_TOKEN = os.getenv("GH_TOKEN", "")
MAX_PING_MS = 250
GEMINI_TEST_URL = "https://alkalinetransit-pa.googleapis.com/v1beta/models"
HISTORY_FILE = "node_history.json"

# 1. 静态保底订阅源（确保绝不空手而归）
PRESET_SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/freefq/free/master/clash.m3u",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/er26/free/main/clash.yaml",
    "https://raw.githubusercontent.com/nodefree/nodefree.github.io/main/clash/clash.yaml",
    "https://raw.githubusercontent.com/Pawroid/Free-Node/main/clash.yaml",
]

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

def fetch_proxies_from_url(url):
    print(f"📥 正在获取订阅: {url}")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            config = yaml.safe_load(resp.text)
            if isinstance(config, dict):
                return config.get("proxies", [])
    except Exception as e:
        print(f"⚠️ 获取订阅失败: {url} -> {e}")
    return []

def run_agent():
    history = load_history()
    current_time = int(time.time())
    new_history = {}

    all_raw_proxies = []
    
    # 从内置静态源获取
    for sub_url in PRESET_SUBSCRIPTION_URLS:
        proxies = fetch_proxies_from_url(sub_url)
        all_raw_proxies.extend(proxies)
        print(f"  └─ 提取到 {len(proxies)} 个候选节点")

    print(f"\n📊 汇总获得 {len(all_raw_proxies)} 个候选节点，准备筛选...")

    matched_proxies = []

    for proxy in all_raw_proxies[:100]:  # 筛选前 100 个
        if not isinstance(proxy, dict):
            continue

        name = proxy.get("name", "")
        server = proxy.get("server")
        port = proxy.get("port")

        if not (server and port):
            continue

        # 1. 校验美国关键词
        if not re.search(r"(US|United States|美国|美|洛杉矶|圣何塞|西雅图|芝加哥)", name, re.IGNORECASE):
            continue

        # 2. PING 延迟测试
        is_alive, ping_ms = test_tcp_ping(server, port)
        if not is_alive or ping_ms > MAX_PING_MS:
            continue

        # 3. 深度测试（美国出口 + 清洁度 + Gemini + 机房固定 IP）
        if check_node_quality_and_gemini(proxy):
            server_key = f"{server}:{port}"
            first_seen = history.get(server_key, {}).get("first_seen", current_time)
            new_history[server_key] = {"first_seen": first_seen, "last_seen": current_time}
            
            survival_hours = int((current_time - first_seen) / 3600)
            proxy["name"] = f"🇺🇸 [存活{survival_hours}h|{ping_ms}ms] {name}"
            matched_proxies.append(proxy)
            print(f"  ✅ 完美通关节点: {proxy['name']}")

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

    print(f"\n✨ 最终筛选出 {len(matched_proxies)} 个满足所有条件的高品质美国节点。")

if __name__ == "__main__":
    run_agent()
