"""Rank discovered subscription sources."""

from datetime import datetime, timezone


def score_source(source: dict) -> int:
    score = 0
    if source.get("url"):
        score += 20
    if source.get("format") in {"clash", "yaml", "uri"}:
        score += 20
    if source.get("updated_recently"):
        score += 30
    if source.get("node_count", 0) > 0:
        score += 30
    return score


def filter_sources(sources, minimum=60):
    return [s for s in sources if score_source(s) >= minimum]
