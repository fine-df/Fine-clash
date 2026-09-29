"""Filter nodes according to user rules."""

SUPPORTED = {"vmess", "vless", "trojan", "ss"}


def filter_nodes(nodes):
    result = []
    seen = set()
    for node in nodes:
        if node.get("type") not in SUPPORTED:
            continue
        if not node.get("server") or not node.get("port"):
            continue
        key = (node.get("type"), node.get("server"), node.get("port"))
        if key in seen:
            continue
        seen.add(key)
        result.append(node)
    return result
