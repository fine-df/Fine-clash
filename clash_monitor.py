"""
Fine-clash monitor.

Generates live_clash.yaml from subscription sources.
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

USER_AGENT = "Fine-clash-monitor/1.1"


class ClashMonitor:
    def __init__(self):
        self.headers = {"User-Agent": USER_AGENT}

    def load_sources(self) -> list[dict[str, Any]]:
        if not SOURCES_FILE.exists():
            return []
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []

    def fetch_subscription(self, url: str) -> str | None:
        try:
            r = requests.get(url, headers=self.headers, timeout=20)
            r.raise_for_status()
            return r.text
        except Exception as exc:
            print(f"fetch failed: {exc}")
            return None

    def decode_base64_nodes(self, text: str) -> list[str]:
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8")
            return [x for x in decoded.splitlines() if x.strip()]
        except Exception:
            return []

    def collect_proxies(self) -> list[dict[str, Any]]:
        proxies = []
        for source in self.load_sources():
            url = source.get("url")
            if not url:
                continue
            content = self.fetch_subscription(url)
            if not content:
                continue
            for index, node in enumerate(self.decode_base64_nodes(content), start=1):
                proxies.append({
                    "name": f"node-{index}",
                    "type": "vmess" if node.startswith("vmess://") else "unknown",
                    "server": "",
                })
        return proxies

    def build_config(self, proxies: list[dict[str, Any]]) -> dict[str, Any]:
        names = [p["name"] for p in proxies]
        return {
            "mixed-port": 7890,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",
                "respect-rules": True,
                "fake-ip-filter": ["*.lan", "*.local", "localhost", "*.cn"],
                "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
                "direct-nameserver": ["223.5.5.5", "223.6.6.6"],
            },
            "proxies": proxies,
            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": names + ["DIRECT"],
                }
            ],
            "rules": [
                "GEOSITE,CN,DIRECT",
                "GEOIP,CN,DIRECT",
                "MATCH,PROXY",
            ],
        }

    def save_config(self, config: dict[str, Any]):
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

    def run(self):
        proxies = self.collect_proxies()
        self.save_config(self.build_config(proxies))
        print(f"Generated {OUTPUT_FILE} with {len(proxies)} proxies")


if __name__ == "__main__":
    ClashMonitor().run()
