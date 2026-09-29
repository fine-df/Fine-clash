"""
Fine-clash monitor.

Full pipeline:
subscription sources -> fetch -> parse Clash/Base64 nodes -> deduplicate -> live_clash.yaml
"""

import base64
import json
import pathlib
from typing import Any

import requests
import yaml

BASE_DIR = pathlib.Path(__file__).parent
SOURCES_FILE = BASE_DIR / "subscription_sources.json"
OUTPUT_FILE = BASE_DIR / "live_clash.yaml"

USER_AGENT = "Fine-clash-monitor/2.0"


class ClashMonitor:
    def __init__(self):
        self.headers = {"User-Agent": USER_AGENT}

    def load_sources(self):
        if not SOURCES_FILE.exists():
            return []
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    def fetch(self, url):
        try:
            r = requests.get(url, headers=self.headers, timeout=20)
            r.raise_for_status()
            return r.text
        except Exception as e:
            print("fetch failed", url, e)
            return ""

    def parse_yaml(self, text):
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                return data["proxies"]
        except Exception:
            pass
        return []

    def parse_base64(self, text):
        result = []
        try:
            raw = base64.b64decode(text.strip() + "===").decode("utf-8")
            for line in raw.splitlines():
                if line.startswith(("vmess://", "vless://", "trojan://", "ss://")):
                    result.append(line)
        except Exception:
            pass
        return result

    def collect(self):
        proxies = []
        seen = set()
        for source in self.load_sources():
            url = source if isinstance(source, str) else source.get("url")
            if not url:
                continue
            content = self.fetch(url)
            items = self.parse_yaml(content)
            if items:
                for item in items:
                    name = item.get("name")
                    if name and name not in seen:
                        seen.add(name)
                        proxies.append(item)
                continue
            for index, node in enumerate(self.parse_base64(content), 1):
                name = f"base64-{index}"
                if name not in seen:
                    seen.add(name)
                    proxies.append({"name": name, "type": "vmess", "server": ""})
        return proxies

    def build(self, proxies):
        names = [p["name"] for p in proxies]
        return {
            "mixed-port": 7890,
            "allow-lan": True,
            "mode": "rule",
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",
                "respect-rules": True,
                "fake-ip-filter": ["*.lan", "*.local", "localhost", "*.cn"],
                "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
                "direct-nameserver": ["223.5.5.5", "223.6.6.6"]
            },
            "proxies": proxies,
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": names + ["DIRECT"]}],
            "rules": ["GEOSITE,CN,DIRECT", "GEOIP,CN,DIRECT", "MATCH,PROXY"]
        }

    def run(self):
        config = self.build(self.collect())
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)


if __name__ == "__main__":
    ClashMonitor().run()
