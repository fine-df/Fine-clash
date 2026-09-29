"""
Fine-clash monitor.

Pipeline:
subscription sources -> fetch -> parser -> health filter -> live_clash.yaml
"""

import json
import logging
import pathlib

import requests
import yaml

from node_health import filter_alive_nodes
from node_parser import merge_proxies, parse_clash_yaml, parse_uri_nodes

BASE_DIR = pathlib.Path(__file__).parent
SOURCES_FILE = BASE_DIR / "subscription_sources.json"
OUTPUT_FILE = BASE_DIR / "live_clash.yaml"
USER_AGENT = "Fine-clash-monitor/4.0"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fine-clash")


class ClashMonitor:
    def __init__(self):
        self.headers = {"User-Agent": USER_AGENT}

    def load_sources(self):
        if not SOURCES_FILE.exists():
            return []
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []

    def fetch(self, url):
        try:
            response = requests.get(url, headers=self.headers, timeout=20)
            response.raise_for_status()
            return response.text
        except Exception as exc:
            logger.warning("fetch failed %s: %s", url, exc)
            return ""

    def collect(self):
        groups = []
        for source in self.load_sources():
            url = source if isinstance(source, str) else source.get("url")
            if not url:
                continue
            content = self.fetch(url)
            nodes = parse_clash_yaml(content)
            if not nodes:
                nodes = parse_uri_nodes(content)
            groups.append(nodes)
        return filter_alive_nodes(merge_proxies(groups))

    def build(self, proxies):
        names = [proxy["name"] for proxy in proxies]
        return {
            "mixed-port": 7890,
            "allow-lan": True,
            "mode": "rule",
            "proxies": proxies,
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": names + ["DIRECT"]}
            ],
            "rules": ["GEOSITE,CN,DIRECT", "GEOIP,CN,DIRECT", "MATCH,PROXY"],
        }

    def run(self):
        proxies = self.collect()
        logger.info("generated %s alive nodes", len(proxies))
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.build(proxies), f, allow_unicode=True, sort_keys=False)


if __name__ == "__main__":
    ClashMonitor().run()
