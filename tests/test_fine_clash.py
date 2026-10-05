import base64
import inspect
import pytest
from pathlib import Path

import fine_clash as fc
import build_final as bf


def test_final_proxy_groups_expose_explicit_fine_and_global_nodes():
    groups = bf.build_proxy_groups(["Fine-1", "Fine-2"])
    by_name = {g["name"]: g for g in groups}
    assert by_name["GLOBAL"]["proxies"] == ["DIRECT", "Fine-1", "Fine-2"]
    assert by_name["Fine"]["default-selected"] == "Fine-Auto"
    assert by_name["Fine"]["proxies"] == ["Fine-Auto", "Fine-1", "Fine-2"]
    assert by_name["Fine-Auto"]["proxies"] == ["Fine-1", "Fine-2"]

def test_final_config_is_fine_only():
    cfg = bf.build_config([{"name":"Fine-1","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True}])
    assert cfg["mode"] == "rule"
    assert [n["name"] for n in cfg["proxies"]] == ["Fine-1"]
    assert "DOMAIN-SUFFIX,ozon.ru,DIRECT" in cfg["rules"]
    assert cfg["rules"].index("DOMAIN-SUFFIX,ozon.ru,DIRECT") < cfg["rules"].index("MATCH,Fine")
    assert "MATCH,Fine" in cfg["rules"]

def test_candidate_gate_modes_are_explicit():
    item = {"gemini": False, "google_play": False, "google": {"ok": True}}
    assert fc.candidate_gate_passes(item, "reachable", 80, 65)
    assert not fc.candidate_gate_passes(item, "gemini_or_play", 80, 65)
    item["google_play"] = True
    assert fc.candidate_gate_passes(item, "gemini_or_play", 80, 65)
    item["gemini"] = True
    assert fc.candidate_gate_passes(item, "gemini_and_play", 80, 65)
    assert not fc.candidate_gate_passes(item, "unknown", 80, 65)


def test_resolved_server_safety_fails_closed_for_private_dns(monkeypatch):
    monkeypatch.setattr(
        fc.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(fc.socket.AF_INET, 0, 0, "", ("192.168.1.10", 0))],
    )
    fc.resolved_server_is_safe.cache_clear()
    assert not fc.resolved_server_is_safe("attacker.example")


def test_source_path_sort_key_parses_version_numbers():
    assert fc.source_path_sort_key("clash-v2.yaml")[1] == 2
    assert fc.source_path_sort_key("version-12.yaml")[1] == 12


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
    row = fc.update_history(db, "abc", {"score": score, "gemini": True, "google_play": True}, score_threshold=70)
    assert row["seen_count"] == 1 and row["pass_count"] == 1


def test_prepare_mihomo_geodata_preserves_expected_filenames(tmp_path: Path):
    source_dir = tmp_path / "source"
    work_dir = tmp_path / "work"
    source_dir.mkdir()
    work_dir.mkdir()
    (source_dir / "geoip.dat").write_bytes(b"geoip")
    (source_dir / "Country.mmdb").write_bytes(b"mmdb")
    copied = fc.prepare_mihomo_geodata(work_dir, source_dir)
    assert copied == ["Country.mmdb", "geoip.dat"]
    assert (work_dir / "geoip.dat").read_bytes() == b"geoip"
    assert (work_dir / "Country.mmdb").read_bytes() == b"mmdb"


def test_mihomo_startup_failure_isolated_to_bad_nodes():
    class FakeTester(fc.MihomoTester):
        def __init__(self):
            self.cfg = {"endpoint_workers": 2}
            self.binary = "fake"
            self.proc = None
            self.tmp = None
            self.log_handle = None
            self.session = None
            self.port_offset = 0
            self.proxy_port = 17890
            self.controller_port = 19090

        def start(self, nodes):
            if any(node.get("bad") for node in nodes):
                raise RuntimeError("Mihomo exited during startup (rc=1): Parse config error: proxy 1: invalid REALITY public key")
            return [f"N{i:03d}" for i in range(len(nodes))]

        def choose(self, name):
            return None

        def request(self, url, parse_json=False):
            return {"ok": True, "status": 200, "challenge": False, "data": {} if parse_json else None}

        def stop(self):
            return None

    nodes = [
        {"name":"good-a", "bad":False},
        {"name":"bad", "bad":True},
        {"name":"good-b", "bad":False},
    ]
    checks = {
        "gemini_url":"gemini", "google_play_url":"play",
        "google_204_url":"google", "ipinfo_url":"ipinfo",
    }
    results = FakeTester().test_nodes(nodes, checks)
    assert [row["node"]["name"] for row in results] == ["good-a", "bad", "good-b"]
    bad = next(row for row in results if row["node"]["name"] == "bad")
    assert bad["gemini"] is False
    assert "invalid REALITY public key" in bad["startup_error"]
    assert next(row for row in results if row["node"]["name"] == "good-a")["gemini"] is True


def test_mihomo_rejects_invalid_reality_configuration():
    good_key = fc.base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
    base = {
        "type": "vless", "server": "example.com", "port": 443,
        "uuid": "123e4567-e89b-12d3-a456-426614174000", "tls": True,
        "network": "tcp",
    }
    assert fc.mihomo_node_is_testable(dict(base, **{"reality-opts": {"public-key": good_key, "short-id": "0123456789abcdef"}}))
    assert not fc.mihomo_node_is_testable(dict(base, **{"reality-opts": {"public-key": "bad", "short-id": "0123"}}))
    assert not fc.mihomo_node_is_testable(dict(base, **{"reality-opts": {"public-key": good_key, "short-id": "null"}}))
    assert not fc.mihomo_node_is_testable(dict(base, network="xhttp"))


def test_mihomo_systemic_startup_failure_is_not_silenced():
    class BrokenTester(fc.MihomoTester):
        def __init__(self):
            self.cfg = {"endpoint_workers": 1}
            self.binary = "fake"
            self.proc = None
            self.tmp = None
            self.log_handle = None
            self.session = None
            self.port_offset = 0
            self.proxy_port = 17890
            self.controller_port = 19090

        def start(self, nodes):
            raise RuntimeError("Mihomo binary failed to initialize")

        def stop(self):
            return None

    checks = {
        "gemini_url":"gemini", "google_play_url":"play",
        "google_204_url":"google", "ipinfo_url":"ipinfo",
    }
    with pytest.raises(RuntimeError, match="failed to initialize"):
        BrokenTester().test_nodes([{"name":"demo"}], checks)


def test_mihomo_tester_uses_no_geosite_rule():
    source = inspect.getsource(fc.MihomoTester.start)
    assert "GEOSITE,CN,DIRECT" not in source


def test_output_builder(tmp_path: Path):
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml")}}
    nodes = [{"name":"demo","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True,"servername":"example.com"}]
    fc.build_outputs(nodes, rules)
    assert "GEOSITE,CN,DIRECT" not in (tmp_path / "clash.yaml").read_text()


def test_output_builder_deduplicates_proxy_names(tmp_path: Path):
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml")}}
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
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml")}}
    nodes = [{"name":"demo","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True,"servername":"example.com"}]
    fc.build_outputs(nodes, rules)
    built = fc.yaml.safe_load((tmp_path / "clash.yaml").read_text())
    routes = built["rules"]
    # Local LAN/direct rules intentionally come before application-specific
    # WeChat/Xiaomi rules so multicast/link-local traffic is not intercepted.
    assert routes[:len(fc.LOCAL_IOT_DIRECT_RULES)] == fc.LOCAL_IOT_DIRECT_RULES
    for rule in fc.WECHAT_DIRECT_RULES:
        assert rule in routes
    assert "DOMAIN-SUFFIX,qpic.cn,DIRECT" in routes
    assert "DOMAIN-SUFFIX,qq.com,DIRECT" in routes
    assert "GEOSITE,CN,DIRECT" not in routes
    assert "DOMAIN-SUFFIX,mi.com,DIRECT" in routes
    assert "DOMAIN-SUFFIX,xiaomi.com,DIRECT" in routes
    assert routes[-1] == "MATCH,PROXY"


def test_vless_reality_is_normalized_for_mihomo():
    uri = "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality&sni=example.com&fp=chrome&pbk=PUBLICKEY&sid=SHORTID&type=tcp#reality"
    node = fc.parse_subscription(uri)[0]
    assert node["reality-opts"] == {"public-key": "PUBLICKEY", "short-id": "SHORTID"}
    assert "public-key" not in node and "short-id" not in node


def test_output_builder_filters_xhttp_for_compatibility(tmp_path: Path):
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml")}}
    nodes = [
        {"name":"xhttp","type":"vless","server":"x.example","port":443,"uuid":"u","tls":True,"network":"xhttp","xhttp-opts":{"path":"/x"}},
        {"name":"ws","type":"vless","server":"w.example","port":443,"uuid":"u2","tls":True,"network":"ws"},
    ]
    fc.build_outputs(nodes, rules)
    built = fc.yaml.safe_load((tmp_path / "clash.yaml").read_text())
    assert [n["name"] for n in built["proxies"]] == ["ws"]


def test_shenzhen_latency_filter():
    cfg = {"reject_above_ms": 400, "reject_loss_pct": 25, "fail_closed": False}
    assert fc.shenzhen_passes({"ok": True, "avg_ms": 399.9, "loss_pct": 0}, cfg)
    assert fc.shenzhen_passes({"ok": True, "avg_ms": 400, "loss_pct": 25}, cfg)
    assert not fc.shenzhen_passes({"ok": True, "avg_ms": 400.1, "loss_pct": 0}, cfg)
    assert not fc.shenzhen_passes({"ok": True, "avg_ms": 100, "loss_pct": 26}, cfg)
    assert not fc.shenzhen_passes({"ok": True, "avg_ms": 100}, cfg)
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
    rules = {"output": {"clash_file": str(tmp_path / "clash.yaml")}}
    nodes = [{"name":"demo","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True,"servername":"example.com"}]
    fc.build_outputs(nodes, rules)
    built = fc.yaml.safe_load((tmp_path / "clash.yaml").read_text())
    assert built["dns"]["enhanced-mode"] == "redir-host"
    assert built["dns"]["nameserver-policy"]["+.qq.com"] == ["223.5.5.5", "119.29.29.29"]
    assert built["dns"]["direct-nameserver-follow-policy"] is True


def test_globalping_token_is_applied(monkeypatch):
    monkeypatch.setenv("GLOBALPING_API_TOKEN", "test-token")
    probe = fc.GlobalpingShenzhenProbe({"api_token_env":"GLOBALPING_API_TOKEN"})
    assert probe.session.headers["Authorization"] == "Bearer test-token"


def _rank_node(name, server, password="p"):
    return {"name": name, "type": "trojan", "server": server, "port": 443, "password": password, "tls": True}


def _rank_meta(node, score=80, ping=100, loss=0, stability=1, lifespan=10, org=None):
    return {
        "score": score,
        "shenzhen_ping_ms": ping,
        "shenzhen_loss_pct": loss,
        "stability": stability,
        "lifespan": lifespan,
        "org": org,
    }



def test_fingerprint_includes_transport_identity():
    base = _rank_node("n1", "same.example")
    a = dict(base, **{"servername":"a.example","network":"ws","ws-opts":{"path":"/a"}})
    b = dict(base, **{"servername":"b.example","network":"ws","ws-opts":{"path":"/b"}})
    assert fc.fingerprint(a) != fc.fingerprint(b)

def test_rank_candidates_sorts_and_limits():
    nodes = [
        _rank_node("low", "a.example"),
        _rank_node("high", "b.example"),
        _rank_node("mid", "c.example"),
    ]
    meta = {
        fc.fingerprint(nodes[0]): _rank_meta(nodes[0], score=70, ping=100),
        fc.fingerprint(nodes[1]): _rank_meta(nodes[1], score=90, ping=50),
        fc.fingerprint(nodes[2]): _rank_meta(nodes[2], score=80, ping=75),
    }
    ranked = fc.rank_candidates(nodes, limit=2, metadata=meta)
    assert [n["name"] for n in ranked] == ["high", "mid"]


def test_rank_candidates_orders_by_score_then_ping():
    tie = _rank_node("tie-a", "t1.example")
    faster = _rank_node("tie-b", "t2.example")
    slower = _rank_node("tie-c", "t3.example")
    nodes = [tie, slower, faster]
    meta = {
        fc.fingerprint(tie): _rank_meta(tie, score=80, ping=100),
        fc.fingerprint(slower): _rank_meta(slower, score=80, ping=300),
        fc.fingerprint(faster): _rank_meta(faster, score=80, ping=50),
    }
    ranked = fc.rank_candidates(nodes, metadata=meta)
    assert [n["name"] for n in ranked] == ["tie-b", "tie-a", "tie-c"]


def test_rank_candidates_dedups_fingerprint():
    node = _rank_node("dup", "9.9.9.9")
    nodes = [dict(node), dict(node)]
    meta = {fc.fingerprint(node): _rank_meta(node, score=88)}
    ranked = fc.rank_candidates(nodes, metadata=meta)
    assert len(ranked) == 1


def test_rank_candidates_caps_same_server():
    nodes = [
        _rank_node("a1", "1.2.3.4", password="p1"),
        _rank_node("a2", "1.2.3.4", password="p2"),
        _rank_node("a3", "1.2.3.4", password="p3"),
        _rank_node("b1", "5.6.7.8"),
    ]
    meta = {
        fc.fingerprint(nodes[0]): _rank_meta(nodes[0], score=90),
        fc.fingerprint(nodes[1]): _rank_meta(nodes[1], score=89),
        fc.fingerprint(nodes[2]): _rank_meta(nodes[2], score=88),
        fc.fingerprint(nodes[3]): _rank_meta(nodes[3], score=87),
    }
    ranked = fc.rank_candidates(nodes, limit=20, metadata=meta)
    servers = [n["server"] for n in ranked]
    assert servers.count("1.2.3.4") <= 2
    assert "5.6.7.8" in servers


def test_rank_candidates_caps_same_org():
    nodes = [
        _rank_node("n1", "1.1.1.1"),
        _rank_node("n2", "2.2.2.2"),
        _rank_node("n3", "3.3.3.3"),
        _rank_node("n4", "4.4.4.4"),
    ]
    meta = {
        fc.fingerprint(nodes[i]): _rank_meta(nodes[i], score=90 - i, org="Cloudflare, Inc.")
        for i in range(len(nodes))
    }
    ranked = fc.rank_candidates(nodes, limit=20, metadata=meta)
    assert len(ranked) == 3


def test_rank_candidates_missing_metadata_is_safe():
    nodes = [_rank_node("a", "10.0.0.1"), _rank_node("b", "10.0.0.2")]
    ranked = fc.rank_candidates(nodes, limit=20, metadata=None)
    assert len(ranked) == 2


def test_rank_candidates_max_per_server_is_configurable():
    nodes = [_rank_node(f"s{i}", "20.20.20.20", password=f"pw{i}") for i in range(5)]
    meta = {fc.fingerprint(n): _rank_meta(n, score=90 - i) for i, n in enumerate(nodes)}
    ranked = fc.rank_candidates(nodes, limit=20, metadata=meta, max_per_server=3)
    assert len(ranked) == 3


def test_rank_candidates_max_per_org_is_configurable():
    nodes = [_rank_node(f"o{i}", f"30.0.{i}.1") for i in range(6)]
    meta = {fc.fingerprint(n): _rank_meta(n, score=90 - i, org="SameOrg, Inc.") for i, n in enumerate(nodes)}
    ranked = fc.rank_candidates(nodes, limit=20, metadata=meta, max_per_org=5)
    assert len(ranked) == 5


def test_clean_score_catches_google_and_oracle():
    g_ok = {"ok": True, "challenge": False}
    assert fc.clean_score({"org": "AS396982 Google LLC"}, g_ok) < 80
    assert fc.clean_score({"org": "AS31898 Oracle Corporation"}, g_ok) < 80


def test_clean_score_catches_high_risk_hosting():
    g_ok = {"ok": True, "challenge": False}
    assert fc.clean_score({"org": "AS9009 M247 Europe SRL"}, g_ok) < 80
    assert fc.clean_score({"org": "AS199912 Layer7 Networks GmbH"}, g_ok) < 80
    assert fc.clean_score({"org": "AS62005 BlueVPS OU"}, g_ok) < 80


def test_update_history_dedups_within_same_day():
    db = {}
    result = {"score": 80, "gemini": True, "google_play": True}
    fc.update_history(db, "fp", result)
    row = fc.update_history(db, "fp", result)  # 同一自然日第二次访问
    assert row["pass_count"] == 1 and row["seen_count"] == 1
