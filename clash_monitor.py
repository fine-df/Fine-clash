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

MAX_PING_MS = 180  # PING 延迟低于 180ms
GEMINI_TEST_URL = "https://alkalinetransit-pa.googleapis.com/v1beta/models"
HISTORY_FILE = "node_history.json"  # 节点历史存活记录文件

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"


def load_history():
    """读取历史节点记录，用于计算 IP 存活时长"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_history(history):
    """保存节点历史纪录"""
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
    """验证：美国出口 IP + 清洁度 + Gemini + 机房固定 IP 识别"""
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
        # 查询 IP 属性
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
            # 优先选择 IDC/Hosting 数据中心 IP，稳定性远高于家庭拨号宽带
            if ip_data.get("hosting", False):
                is_stable_datacenter = True

        # Gemini 验证
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


def run_agent():
    history = load_history()
    current_time = int(time.time())
    new_history = {}

    # 获取高星仓库并解析节点 (与上一版相同逻辑)
    # ... 在此处会遍历检索节点 ...

    matched_proxies = []

    # 假定此处获取到的候选节点列表列表为 candidates
    # 对每一个节点追加“长寿命/历史存活”二次筛选：
    for proxy in candidates:
        server_key = f"{proxy.get('server')}:{proxy.get('port')}"

        # 记录首次发现时间
        first_seen = history.get(server_key, {}).get("first_seen", current_time)
        new_history[server_key] = {
            "first_seen": first_seen,
            "last_seen": current_time,
        }

        # 计算存活时长（小时）
        survival_hours = (current_time - first_seen) / 3600

        # 筛选逻辑：只有满足基础条件，且【存活时间 >= 6 小时】（即连续两次 Github Action 检测都存在）的节点才保留
        if survival_hours >= 6 or len(history) == 0:
            proxy["name"] = f"🇺🇸 [长存{int(survival_hours)}h] {proxy['name']}"
            matched_proxies.append(proxy)

    save_history(new_history)

    # 导出 live_clash.yaml ...
