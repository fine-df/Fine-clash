"""
Fine-clash monitor base framework.

Responsibilities:
- Load subscription sources
- Fetch subscription content
- Generate Clash configuration
- Prepare future node testing pipeline
"""

import json
import pathlib
import time
from typing import Any

import requests
import yaml

BASE_DIR = pathlib.Path(__file__).parent
SOURCES_FILE = BASE_DIR / "subscription_sources.json"
OUTPUT_FILE = BASE_DIR / "live_clash.yaml"

USER_AGENT = "Fine-clash-monitor/1.0"


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
            response = requests.get(
                url,
                headers=self.headers,
                timeout=15,
            )
            response.raise_for_status()
            return response.text
        except Exception as exc:
            print(f"subscription fetch failed: {exc}")
            return None

    def build_config(self, proxies: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "mixed-port": 7890,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",
                "respect-rules": True,
            },
            "proxies": proxies,
            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": ["DIRECT"],
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
        print("Fine-clash monitor started")
        self.save_config(self.build_config([]))
        print("Generated live_clash.yaml")


if __name__ == "__main__":
    ClashMonitor().run()
