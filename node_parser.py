"""
Fine-clash node parser.
Supports basic Clash YAML extraction and keeps extension points
for vmess/vless/trojan/ss decoders.
"""

from typing import Any

import yaml


def parse_clash_yaml(text: str) -> list[dict[str, Any]]:
    """Extract proxies from Clash compatible YAML."""
    try:
        data = yaml.safe_load(text) or {}
    except Exception:
        return []

    proxies = data.get("proxies", [])
    return proxies if isinstance(proxies, list) else []


def merge_proxies(items: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Merge and deduplicate proxy definitions."""
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
