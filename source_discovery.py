"""GitHub subscription source discovery module.

Collect candidate Clash/Mihomo/V2Ray subscription sources for later filtering.
"""

import requests

KEYWORDS = [
    "clash subscription",
    "mihomo subscription",
    "v2ray subscription",
    "proxy provider",
]


def discover_sources():
    """Placeholder for GitHub search integration.

    The returned structure is designed for scoring and filtering.
    """
    return []


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
