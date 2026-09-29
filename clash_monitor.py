import base64
import json
import os
import socket
import subprocess
import time
import requests
import yaml

# 1. 配置参数
GITHUB_TOKEN = os.getenv("GH_TOKEN", "")  # 可在 Actions 中配置 Secret
SEARCH_QUERY = "clash subscription stars:>200 pushed:>2026-03-01"
SUBCONVERTER_API = "https://api.v1.mk/sub?target=clash&url="

# Gemini 验证目标 URL
GEMINI_TEST_URL = "https://alkalinetransit-pa.googleapis.com/v1beta/models"  # 或 "https://gemini.google.com"

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"


def fetch_high_star_repos():
    """Step 1: 检索 GitHub 上高星且近半年的仓库"""
    print("🔍 正在检索 GitHub 上高星且近半年的 Clash 仓库...")
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
    """Step 2: 嗅探仓库中的订阅文件"""
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


def test_tcp_connectivity(host, port, timeout=2):
    """Step 3: 基础 TCP 连通性快速预筛选"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except:
        return False


def test_gemini_accessibility(proxy_config):
    """Step 4: 深度探针 - 在本地启动临时 Clash 节点并验证 Gemini 解锁状态"""
    # 构建单节点临时 Clash 配置文件
    temp_clash_config = {
        "mixed-port": 9050,
        "mode": "rule",
        "log-level": "silent",
        "proxies": [proxy_config],
        "rules": ["MATCH,GLOBAL"],
    }

    with open("temp_config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_clash_config, f)

    # 启动后台 clash 进程（需 runner 已安装 clash 核心）
    proc = subprocess.Popen(
        ["clash", "-f", "temp_config.yaml"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)  # 等待代理端口就绪

    is_gemini_ok = False
    proxies_http = {
        "http": "http://127.0.0.1:9050",
        "https": "http://127.0.0.1:9050",
    }

    try:
        # 发起 HTTP 请求验证是否能连通 Google API / Gemini 服务
        resp = requests.get(
            GEMINI_TEST_URL, proxies=proxies_http, timeout=5, verify=True
        )
        # 只要不是 403 / 451 (区域限制) 且 HTTP code < 500，即证明可访问 Gemini
        if resp.status_code in [200, 400, 401]:  # 400/401 说明连通了 Google 鉴权服务
            is_gemini_ok = True
    except Exception:
        is_gemini_ok = False
    finally:
        proc.terminate()  # 测试完毕及时关闭后台代理
        proc.wait()
        if os.path.exists("temp_config.yaml"):
            os.remove("temp_config.yaml")

    return is_gemini_ok


def verify_and_filter_sub(yaml_url):
    """Step 5: 下载、解析并进行双层过滤 (TCP + Gemini)"""
    print(f"🧪 正在下载并验证订阅: {yaml_url}")
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

        print(f"📋 共 {len(proxies)} 个节点，开始双重测试...")

        gemini_ready_proxies = []
        for proxy in proxies[:30]:  # 控制单次测试节点上限，防止 GitHub Action 超时
            server = proxy.get("server")
            port = proxy.get("port")

            # 1. 快速 TCP 筛选
            if server and port and test_tcp_connectivity(server, port):
                # 2. 深度 Gemini 可用性测试
                if test_gemini_accessibility(proxy):
                    proxy["name"] = (
                        f"⚡[Gemini] {proxy.get('name', 'Node')}"  # 打上 Gemini 专属标识
                    )
                    gemini_ready_proxies.append(proxy)
                    print(
                        f"  ✅ 节点 [{proxy.get('name')}] 通过验证，可正常访问 Gemini！"
                    )

        if gemini_ready_proxies:
            config["proxies"] = gemini_ready_proxies
            return config
    except Exception as e:
        print(f"⚠️ 解析失败: {e}")

    return None


def run_agent():
    repos = fetch_high_star_repos()
    all_gemini_proxies = []

    for repo in repos:
        urls = find_subscription_urls(repo)
        for url in urls:
            cfg = verify_and_filter_sub(url)
            if cfg and cfg.get("proxies"):
                all_gemini_proxies.extend(cfg["proxies"])

    if all_gemini_proxies:
        final_config = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "proxies": all_gemini_proxies,
        }

        with open("live_clash.yaml", "w", encoding="utf-8") as f:
            yaml.dump(final_config, f, allow_unicode=True)
        print(
            f"\n✨ 成功提取 {len(all_gemini_proxies)} 个通过 Gemini 验证的节点，已写入 live_clash.yaml！"
        )


if __name__ == "__main__":
    run_agent()
