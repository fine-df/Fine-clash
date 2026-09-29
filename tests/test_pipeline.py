from node_parser import parse_clash_yaml, merge_proxies
from node_health import filter_alive_nodes


def test_parse_clash_yaml():
    data = """
proxies:
  - name: test-node
    type: ss
    server: example.com
    port: 443
"""
    result = parse_clash_yaml(data)
    assert len(result) == 1
    assert result[0]["name"] == "test-node"


def test_merge_proxies():
    result = merge_proxies([
        [{"name": "a"}],
        [{"name": "a"}, {"name": "b"}],
    ])
    assert len(result) == 2


def test_health_empty():
    assert filter_alive_nodes([]) == []
