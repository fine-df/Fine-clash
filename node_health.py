"""
Node health checker for Fine-clash.
"""

import logging
import socket
from typing import Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fine-clash-health")


def check_server(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception as exc:
        logger.debug("health check failed %s:%s %s", host, port, exc)
        return False


def filter_alive_nodes(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alive = []
    for proxy in proxies:
        host = proxy.get("server")
        port = proxy.get("port")
        if not host or not port:
            continue
        if check_server(host, int(port)):
            alive.append(proxy)
    logger.info("health check: %s/%s nodes alive", len(alive), len(proxies))
    return alive
