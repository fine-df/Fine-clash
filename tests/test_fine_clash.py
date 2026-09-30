import base64
from pathlib import Path

import fine_clash as fc


def test_parse_yaml_and_strip_untrusted_fields():
    text = """proxies:
  - name: demo
    type: trojan
    server: example.com
    port: 443
    password: secret
    dialer-proxy: DIRECT
"""
    node = fc.parse_subscription(text)[0]
    assert node["type"] == "trojan"
    assert "dialer-proxy" not in node


def test_parse_vless_and_vmess_uri():
    vless = fc.parse_subscription("vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fchat#demo")[0]
    assert vless["tls"] and vless["ws-opts"]["path"] == "/chat"
    vmess_payload = base64.b64encode(b'{"v":"2","ps":"vm","add":"example.com","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","aid":"0","scy":"auto","net":"tcp","tls":"tls"}').decode()
    vmess = fc.parse_subscription("vmess://" + vmess_payload)[0]
    assert vmess["type"] == "vmess"


def test_local_targets_rejected():
    assert not fc.is_safe_server("127.0.0.1")
    assert not fc.is_safe_server("localhost")
    assert fc.is_safe_server("example.com")


def test_score_and_history():
    assert fc.clean_score({"org": "Amazon Web Services"}, {"ok": True, "challenge": False}) < 80
    score = fc.total_score(gemini=True, google_play=True, google={"ok": True}, clean=90, lifespan=30, stability=1)
    assert score >= 90
    db = {}
    row = fc.update_history(db, "abc", {"score": score, "gemini": True, "google_play": True})
    assert row["seen_count"] == 1 and row["pass_count"] == 1


def test_output_builder(tmp_path: Path):
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml"), "v2ray_file": str(tmp_path / "v2ray.txt")}}
    nodes = [{"name":"demo","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True,"servername":"example.com"}]
    fc.build_outputs(nodes, rules)
    assert "GEOSITE,CN,DIRECT" in (tmp_path / "clash.yaml").read_text()
    assert base64.b64decode((tmp_path / "v2ray.txt").read_text()).decode().startswith("trojan://")


def test_output_builder_deduplicates_proxy_names(tmp_path: Path):
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml"), "v2ray_file": str(tmp_path / "v2ray.txt")}}
    nodes = [
        {"name":"same","type":"trojan","server":"one.example","port":443,"password":"one","tls":True},
        {"name":"same","type":"trojan","server":"two.example","port":443,"password":"two","tls":True},
    ]
    fc.build_outputs(nodes, rules)
    text = (tmp_path / "clash.yaml").read_text()
    assert text.count("  name: same") == 0
    assert "  - same\n" not in text
    assert text.count("[") >= 2
    built = fc.yaml.safe_load(text)
    proxy_names = [node["name"] for node in built["proxies"]]
    group_names = built["proxy-groups"][0]["proxies"][:-1]
    assert len(proxy_names) == len(set(proxy_names)) == 2
    assert group_names == proxy_names


def test_output_builder_has_wechat_direct_rules(tmp_path: Path):
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml"), "v2ray_file": str(tmp_path / "v2ray.txt")}}
    nodes = [{"name":"demo","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True,"servername":"example.com"}]
    fc.build_outputs(nodes, rules)
    built = fc.yaml.safe_load((tmp_path / "clash.yaml").read_text())
    routes = built["rules"]
    assert routes[:3] == fc.WECHAT_DIRECT_RULES[:3]
    assert "DOMAIN-SUFFIX,qpic.cn,DIRECT" in routes
    assert "DOMAIN-SUFFIX,qq.com,DIRECT" in routes
    assert "GEOSITE,CN,DIRECT" in routes
    assert routes[-1] == "MATCH,PROXY"


def test_vless_reality_is_normalized_for_mihomo():
    uri = "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality&sni=example.com&fp=chrome&pbk=PUBLICKEY&sid=SHORTID&type=tcp#reality"
    node = fc.parse_subscription(uri)[0]
    assert node["reality-opts"] == {"public-key": "PUBLICKEY", "short-id": "SHORTID"}
    assert "public-key" not in node and "short-id" not in node
    assert fc.node_to_uri(node).startswith("vless://")
    assert "security=reality" in fc.node_to_uri(node)
    assert "pbk=PUBLICKEY" in fc.node_to_uri(node)
    assert "sid=SHORTID" in fc.node_to_uri(node)


def test_output_builder_filters_xhttp_for_compatibility(tmp_path: Path):
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml"), "v2ray_file": str(tmp_path / "v2ray.txt")}}
    nodes = [
        {"name":"xhttp","type":"vless","server":"x.example","port":443,"uuid":"u","tls":True,"network":"xhttp","xhttp-opts":{"path":"/x"}},
        {"name":"ws","type":"vless","server":"w.example","port":443,"uuid":"u2","tls":True,"network":"ws"},
    ]
    fc.build_outputs(nodes, rules)
    built = fc.yaml.safe_load((tmp_path / "clash.yaml").read_text())
    assert [n["name"] for n in built["proxies"]] == ["ws"]


def test_shenzhen_latency_filter():
    cfg = {"reject_above_ms": 400, "fail_closed": False}
    assert fc.shenzhen_passes({"ok": True, "avg_ms": 399.9}, cfg)
    assert fc.shenzhen_passes({"ok": True, "avg_ms": 400}, cfg)
    assert not fc.shenzhen_passes({"ok": True, "avg_ms": 400.1}, cfg)
    assert fc.shenzhen_passes({"ok": False, "status": "timeout"}, cfg)
    assert not fc.shenzhen_passes({"ok": False, "status": "timeout"}, {**cfg, "fail_closed": True})


def test_cached_shenzhen_result(tmp_path: Path):
    row = {
        "shenzhen_checked_at": fc.datetime.now(fc.timezone.utc).isoformat(),
        "shenzhen_ping_ms": 210.5,
        "shenzhen_loss_pct": 0,
        "shenzhen_probe_city": "Shenzhen",
    }
    cached = fc.cached_shenzhen_result(row, {"cache_days": 1})
    assert cached and cached["avg_ms"] == 210.5 and cached["status"] == "cached"


def test_output_builder_configures_wechat_friendly_dns(tmp_path: Path):
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml"), "v2ray_file": str(tmp_path / "v2ray.txt")}}
    nodes = [{"name":"demo","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True,"servername":"example.com"}]
    fc.build_outputs(nodes, rules)
    built = fc.yaml.safe_load((tmp_path / "clash.yaml").read_text())
    assert built["dns"]["enhanced-mode"] == "redir-host"
    assert built["dns"]["nameserver-policy"]["+.qq.com"] == ["223.5.5.5", "119.29.29.29"]
    assert built["dns"]["direct-nameserver-follow-policy"] is True


def test_trojan_grpc_v2ray_uri_preserves_transport_options():
    node = {
        "name":"grpc",
        "type":"trojan",
        "server":"example.com",
        "port":443,
        "password":"secret",
        "tls":True,
        "servername":"example.com",
        "network":"grpc",
        "grpc-opts":{"grpc-service-name":"edge"},
    }
    uri = fc.node_to_uri(node)
    assert "type=grpc" in uri
    assert "serviceName=edge" in uri


def test_vmess_grpc_v2ray_uri_preserves_service_name():
    node = {
        "name":"vmess-grpc",
        "type":"vmess",
        "server":"example.com",
        "port":443,
        "uuid":"123e4567-e89b-12d3-a456-426614174000",
        "tls":True,
        "network":"grpc",
        "grpc-opts":{"grpc-service-name":"edge"},
    }
    uri = fc.node_to_uri(node)
    payload = fc.base64.b64decode(uri[len("vmess://"):]).decode()
    assert '"net":"grpc"' in payload
    assert '"path":"edge"' in payload


def test_globalping_token_is_applied(monkeypatch):
    monkeypatch.setenv("GLOBALPING_API_TOKEN", "test-token")
    probe = fc.GlobalpingShenzhenProbe({"api_token_env":"GLOBALPING_API_TOKEN"})
    assert probe.session.headers["Authorization"] == "Bearer test-token"
