"""
Fine-clash node parser.
Supports Clash YAML and common URI based proxy formats.
"""

import base64
from typing import Any
from urllib.parse import urlparse

import yaml


def parse_clash_yaml(text: str) -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(text) or {}
    except Exception:
        return []
    proxies = data.get("proxies", [])
    return proxies if isinstance(proxies, list) else []


def parse_uri_nodes(text: str) -> list[dict[str, Any]]:
    result = []
    try:
        raw = base64.b64decode(text.strip() + "===").decode("utf-8")
    except Exception:
        raw = text

    for index, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        scheme = urlparse(line).scheme
        if scheme in {"vmess", "vless", "trojan", "ss"}:
            result.append({"name": f"node-{index}", "type": scheme, "uri": line})
    return result


def merge_proxies(items: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for group in items:
        for proxy in group:
            name = proxy.get("name")
            if not name or name in seen:
                continue
            seen.add(name)
            result.append(proxy)
    return result
