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
