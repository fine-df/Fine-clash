"""
Node health checker for Fine-clash.

Checks proxy candidates before publishing generated configuration.
"""

import socket
from typing import Any


def check_server(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def filter_alive_nodes(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alive = []
    for proxy in proxies:
        host = proxy.get("server")
        port = proxy.get("port")
        if host and port and check_server(host, int(port)):
            alive.append(proxy)
    return alive
