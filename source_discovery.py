"""GitHub subscription source discovery.

Collect candidate Clash/Mihomo/V2Ray subscription sources.
"""

import re
import requests

KEYWORDS = [
    "clash subscription",
    "mihomo subscription",
    "v2ray subscription",
    "proxy provider",
]

RAW_PATTERN = r"https://raw\.githubusercontent\.com/[\w./_-]+"


def discover_sources_from_text(text):
    return list(set(re.findall(RAW_PATTERN, text)))


def discover_sources():
    """Reserved for GitHub API search integration."""
    return []


def validate_source(url):
    try:
        response = requests.get(url, timeout=10)
        return bool(response.text.strip())
    except Exception:
        return False


def score_source(source):
    score = 0
    if source.get("url"):
        score += 20
    if source.get("format") in ["yaml", "base64", "clash"]:
        score += 30
    if source.get("updated_recently"):
        score += 30
    if source.get("node_count", 0) > 0:
        score += 20
    return score
