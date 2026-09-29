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

MAX_CANDIDATES = 100
MAX_PER_SOURCE = 30
MAX_OUTPUT_NODES = 40

SWITCH_WAIT_SECONDS = 1.0
REQUEST_TIMEOUT = 8

# 长寿命相关
STABLE_PASS_COUNT = 2          # 至少连续通过 2 次才输出（过滤一天内就挂的）
HISTORY_RESET_HOURS = 48       # 超过 48 小时没出现则重新计算
MIN_SURVIVAL_HOURS = 6         # 历史存活不足 6 小时的节点降权（但不直接丢弃）

# ========== 地区与清洁度要求 ==========
# 台湾专属
TW_MAX_LATENCY_MS = 100        # 台湾 Ping 必须 < 100ms
TW_REQUIRE_CLEAN = True        # 台湾必须高清洁度

# 美国专属
US_MAX_LATENCY_MS = 250        # 美国 Ping 必须 < 250ms
US_REQUIRE_CLEAN = True        # 美国必须高清洁度

# 通用
REQUIRE_GOOGLE = True
REQUIRE_GEMINI_WEB = True
REQUIRE_GEMINI_API = False
GLOBAL_MAX_LATENCY_MS = 400    # 所有节点通用延迟上限

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
# 订阅源
# =========================

PRESET_SUBSCRIPTION_URLS = [
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
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml",
    "https://cdn.jsdelivr.net/gh/skywolf626/ProxyNode@main/nodes/clash.yaml",
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
