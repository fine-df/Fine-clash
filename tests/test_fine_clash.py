import base64
import inspect
import json
import subprocess
import requests
import pytest
from pathlib import Path

import fine_clash as fc
import build_final as bf


def test_final_proxy_groups_single_fine_with_direct():
    fine_names = ["Fine-1", "Fine-2"]
    groups = bf.build_proxy_groups(fine_names)
    by_name = {g["name"]: g for g in groups}
    # Only the Fine group is user-visible; AUTO is a hidden url-test subgroup
    # embedded in Fine for one-tap latency auto-selection (only Fine and AUTO are generated).
    assert set(by_name) == {"Fine", "AUTO"}
    # Sticky-first: the first (quality-ranked) node is pinned as default-selected.
    assert by_name["Fine"]["default-selected"] == fine_names[0]
    # AUTO (auto-select) and DIRECT are selectable alongside every node.
    assert by_name["Fine"]["proxies"] == ["AUTO", "DIRECT"] + fine_names
    # AUTO itself is a hidden url-test group so it stays out of the UI list.
    assert by_name["AUTO"]["type"] == "url-test"
    assert by_name["AUTO"]["hidden"] is True
    assert by_name["AUTO"]["proxies"] == fine_names

def test_sticky_primary_is_pinned_as_default_selected():
    # The pool is intentionally ordered quality-first by fine_clash.py's sticky
    # ordering (previous connected node if still Shenzhen-quality, else freshest
    # quality node). build_proxy_groups must pin that first node as the default
    # so the user's active connection survives a subscription refresh.
    fine_names = ["Fine-KEPT", "Fine-B", "Fine-C"]
    groups = bf.build_proxy_groups(fine_names)
    by_name = {g["name"]: g for g in groups}
    assert by_name["Fine"]["default-selected"] == "Fine-KEPT"
    # AUTO url-test subgroup is embedded in Fine for auto-selection, but the
    # sticky primary (not AUTO) remains the default so the connection persists.
    assert "AUTO" in by_name
    assert by_name["Fine"]["default-selected"] != "AUTO"


def test_load_previous_published_nodes_uses_safe_continuity_reserve(tmp_path: Path, monkeypatch):
    profile = tmp_path / "live_clash.yaml"
    profile.write_text(
        "# fine-clash-version:1\n"
        "proxies:\n"
        "  - name: old-1\n"
        "    type: trojan\n"
        "    server: example.com\n"
        "    port: 443\n"
        "    password: secret\n"
        "    tls: true\n"
        "  - name: old-2\n"
        "    type: vless\n"
        "    server: example.org\n"
        "    port: 443\n"
        "    uuid: 123e4567-e89b-12d3-a456-426614174000\n"
        "    tls: true\n"
        "  - name: old-3\n"
        "    type: trojan\n"
        "    server: old.example\n"
        "    port: 443\n"
        "    password: secret\n"
        "    tls: true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(fc, "resolved_server_is_safe", lambda server: True)
    nodes = fc.load_previous_published_nodes(profile, max_nodes=2)
    assert [node["name"] for node in nodes] == ["old-1", "old-2"]


def test_shenzhen_quality_gates_are_tightened():
    cfg = fc.load_rules()
    assert cfg["shenzhen_probe"]["reject_above_ms"] == 350
    assert cfg["shenzhen_probe"]["reject_loss_pct"] == 10
    assert cfg["retention"]["enabled"] is True
    assert cfg["retention"]["max_previous_nodes"] == 20

def test_final_config_is_fine_only():
    cfg = bf.build_config([{"name":"Fine-1","type":"trojan","server":"example.com","port":443,"password":"secret","tls":True}])
    assert cfg["mode"] == "rule"
    assert [n["name"] for n in cfg["proxies"]] == ["Fine-1"]
    rules = cfg["rules"]
    groups = {group["name"]: group for group in cfg["proxy-groups"]}
    assert set(groups) == {"Fine", "AUTO"}
    assert "DOMAIN-SUFFIX,ozon.ru,DIRECT" in rules
    geoip_cn = rules.index("GEOIP,CN,DIRECT")
    for rule in bf.OZON_DIRECT:
        assert rule in rules
        assert rules.index(rule) < geoip_cn  # Ozon must proxy even if its IP geolocates to China
    for rule in bf.WPS_DIRECT:
        assert rule in rules
        assert rules.index(rule) < geoip_cn
    for rule in bf.WECHAT_DIRECT + bf.XIAOMI_DIRECT:
        assert rule in rules
        assert rules.index(rule) < geoip_cn
    assert "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve" in rules
    assert "MATCH,Fine" in rules
    assert rules[-1] == "MATCH,Fine"

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


def test_us_non_datacenter_bonus():
    assert fc._us_non_datacenter_bonus({"country": "US", "org": "Comcast Cable Communications"}) == 1
    assert fc._us_non_datacenter_bonus({"country": "US", "org": "Amazon Web Services"}) == 0
    assert fc._us_non_datacenter_bonus({"country": "US", "org": "Google LLC"}) == 0
    assert fc._us_non_datacenter_bonus({"country": "DE", "org": "Deutsche Telekom"}) == 0
    assert fc._us_non_datacenter_bonus({"country": None, "org": "x"}) == 0


def test_rank_candidates_prefers_us_residential_over_us_dc_and_foreign():
    us_home = _rank_node("us-home", "1.1.1.1")
    us_dc = _rank_node("us-dc", "2.2.2.2")
    foreign = _rank_node("foreign", "3.3.3.3")
    nodes = [foreign, us_dc, us_home]
    meta = {
        fc.fingerprint(us_home): {**_rank_meta(us_home, score=80, ping=200), "country": "US", "org": "Comcast Cable Communications"},
        fc.fingerprint(us_dc): {**_rank_meta(us_dc, score=80, ping=50), "country": "US", "org": "Amazon Web Services"},
        fc.fingerprint(foreign): {**_rank_meta(foreign, score=80, ping=50), "country": "DE", "org": "Deutsche Telekom"},
    }
    ranked = fc.rank_candidates(nodes, metadata=meta)
    names = [n["name"] for n in ranked]
    # US residential leads unconditionally (us_nd=1 beats both us_nd=0 buckets).
    assert names[0] == "us-home"
    # US-datacenter (US but a known cloud ASN) and foreign both have us_nd=0,
    # so they tie on the priority key; only the leading US-residential node is
    # guaranteed. Assert the trailing set, not a fixed order.
    assert set(names[1:]) == {"us-dc", "foreign"}


def test_rank_candidates_min_final_score_floor():
    high = _rank_node("high", "1.1.1.1")
    low = _rank_node("low", "2.2.2.2")
    nodes = [low, high]
    meta = {
        fc.fingerprint(high): _rank_meta(high, score=90, ping=100),
        fc.fingerprint(low): _rank_meta(low, score=40, ping=50),
    }
    # Without a floor the lower-ping (low-score) node would win; with floor=55
    # the high-score node is preferred into the final pool.
    ranked = fc.rank_candidates(nodes, metadata=meta, min_final_score=55)
    assert [n["name"] for n in ranked] == ["high", "low"]


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


# ============================================================================
# 2026-10-20 regression suite: data-source resilience, quality gates, and the
# router sync contract. Every test walks the REAL code paths (GitHubDiscovery,
# admission_reason, decide_publish, run()'s cache-write guard, and the live
# _fine_sync.sh check_groups/vercmp functions) — no reimplementations.
# ============================================================================

def _make_item(gemini=False, google_play=False, google_ok=False, latency_ms=100, network="tcp"):
    return {
        "node": {"network": network},
        "gemini": gemini,
        "google_play": google_play,
        "google": {"ok": google_ok, "latency_ms": latency_ms},
    }


def _node_rules(**over):
    base = {"candidate_gate": "gemini_or_play", "min_clean_score": 65,
            "max_proxy_latency_ms": 2500}
    base.update(over)
    return {"nodes": base}


def test_cache_fresh_rejects_expired_and_incomplete():
    cutoff = (fc.datetime.now(fc.timezone.utc) - fc.timedelta(days=14)).date()
    now_iso = fc.datetime.now(fc.timezone.utc).isoformat()
    fresh = {"url": "https://x/fresh.yaml", "stars": 150, "pushed_at": now_iso}
    assert fc.cache_fresh(fresh, 100, cutoff) is True
    # pushed_at older than the recency window -> stale, never auto-qualified.
    stale = {"url": "https://x/stale.yaml", "stars": 150,
             "pushed_at": (fc.datetime.now(fc.timezone.utc) - fc.timedelta(days=30)).isoformat()}
    assert fc.cache_fresh(stale, 100, cutoff) is False
    # below the star floor
    low = {"url": "https://x/low.yaml", "stars": 10, "pushed_at": now_iso}
    assert fc.cache_fresh(low, 100, cutoff) is False
    # missing pushed_at -> cannot prove freshness, never coerced to fresh
    nopush = {"url": "https://x/nopush.yaml", "stars": 150}
    assert fc.cache_fresh(nopush, 100, cutoff) is False
    # not a dict / no url
    assert fc.cache_fresh(None, 100, cutoff) is False
    assert fc.cache_fresh({"stars": 150, "pushed_at": now_iso}, 100, cutoff) is False


def test_discover_distinguishes_failure_from_empty(monkeypatch):
    cfg = {"recent_days": 14, "require_recent_push": True, "queries": ["x"],
           "repositories_per_query": 20, "max_repositories": 80, "min_stars": 100,
           "max_candidate_files_per_repo": 6, "max_source_bytes": 8000000, "min_nodes_per_source": 2}
    # Case A: every search query fails (network/API outage).
    disc = fc.GitHubDiscovery("tok", cfg)
    def boom(*a, **k):
        raise requests.RequestException("Connection reset by peer")
    monkeypatch.setattr(disc, "_get_json", boom)
    out, meta = disc.discover()
    assert out == []
    assert meta["search_succeeded"] is False
    assert meta["failure_type"] == "search_error"
    # Case B: search returns HTTP 200 but genuinely matches nothing.
    disc2 = fc.GitHubDiscovery("tok", cfg)
    def ok_empty(*a, **k):
        return {"items": []}
    monkeypatch.setattr(disc2, "_get_json", ok_empty)
    out2, meta2 = disc2.discover()
    assert out2 == []
    assert meta2["search_succeeded"] is True
    assert meta2["failure_type"] is None


def test_admission_reason_rejects_without_real_proxy():
    rules = _node_rules()
    # All three reachability signals false -> rejected (candidate gate fails first).
    ok, reason = fc.admission_reason(_make_item(), rules, 90)
    assert ok is False
    # gemini true passes candidate gate, but a missing latency must still be
    # rejected (never coerced to 0 ms to sneak through).
    ok, reason = fc.admission_reason(_make_item(gemini=True, latency_ms=None), rules, 90)
    assert ok is False and reason == "latency_missing"
    # real proxy ok but latency over the configured ceiling
    ok, reason = fc.admission_reason(_make_item(gemini=True, google_ok=True, latency_ms=3000), rules, 90)
    assert ok is False and reason == "latency_exceed_2500ms"
    # unsupported transport
    ok, reason = fc.admission_reason(_make_item(gemini=True, google_ok=True, network="xhttp"), rules, 90)
    assert ok is False and reason == "incompatible_network"


def test_admission_reason_accepts_qualified_node():
    rules = _node_rules()
    ok, reason = fc.admission_reason(_make_item(gemini=True, google_ok=True, latency_ms=500), rules, 90)
    assert ok is True and reason == "ok"


def test_decide_publish_respects_min_final_nodes():
    assert fc.decide_publish(2, {"min_final_nodes": 3}) is False
    assert fc.decide_publish(3, {"min_final_nodes": 3}) is True
    assert fc.decide_publish(4, {"min_final_nodes": 3}) is True
    # 0 nodes never publishes even with the old floor of 1
    assert fc.decide_publish(0, {"min_final_nodes": 1}) is False
    assert fc.decide_publish(1, {"min_final_nodes": 1}) is True


# --- run()'s source-cache write guard: a failed discovery must not blank the cache ---

def _patch_run(monkeypatch, tmp_path, discover_return):
    """Isolate run() down to the cache-write decision without mihomo/network."""
    cfg = {
        "sources": {"recent_days": 14, "min_stars": 100, "require_recent_push": True,
                    "queries": [], "repositories_per_query": 20, "max_repositories": 80,
                    "max_sources": 120, "max_candidate_files_per_repo": 6,
                    "max_source_bytes": 8000000, "min_nodes_per_source": 2},
        "nodes": {"candidate_gate": "gemini_or_play", "min_clean_score": 65,
                  "max_proxy_latency_ms": 2500, "min_final_nodes": 3, "max_final_nodes": 20,
                  "max_per_server": 2, "max_per_org": 3, "min_final_score": 0,
                  "max_test_nodes": 200},
        "output": {"source_file": "data/sources.json", "history_file": "data/history.json",
                   "source_history_file": "data/source_history.json",
                   "report_file": "data/last_run.json", "clash_file": "data/fine_pool.yaml"},
        "checks": {"challenge_markers": [], "success_statuses": [200, 204, 301, 302]},
        "shenzhen_probe": {"enabled": False},
        "retention": {"enabled": True, "max_previous_nodes": 5},
        "sticky": {"enabled": False},
    }
    monkeypatch.setattr(fc, "ROOT", tmp_path)
    monkeypatch.setattr(fc, "load_rules", lambda: cfg)
    monkeypatch.setattr(fc, "load_previous_published_nodes", lambda *a, **k: [])
    monkeypatch.setattr(fc.GitHubDiscovery, "discover", lambda self: discover_return)
    # Guard against any node-fetch network call during the merge path.
    def _offline(self, *a, **k):
        raise requests.RequestException("offline")
    monkeypatch.setattr(requests.Session, "get", _offline)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    return tmp_path / "data" / "sources.json"


def test_failed_discovery_preserves_existing_source_cache(monkeypatch, tmp_path):
    source_path = _patch_run(monkeypatch, tmp_path,
                             ([], {"search_succeeded": False, "failure_type": "search_error"}))
    prior = [{"url": "https://old.example/c.yaml", "stars": 150}]  # no pushed_at -> stale
    source_path.write_text(json.dumps(prior, indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError):
        fc.run()
    # A failed search must never blank the only usable source list.
    assert json.loads(source_path.read_text(encoding="utf-8")) == prior


def test_successful_discovery_refreshes_source_cache(monkeypatch, tmp_path):
    fresh = [{"url": "https://new.example/a.yaml", "stars": 200,
              "pushed_at": fc.datetime.now(fc.timezone.utc).isoformat(),
              "nodes": 3, "repo": "new/repo", "path": "a.yaml"}]
    source_path = _patch_run(monkeypatch, tmp_path,
                             (fresh, {"search_succeeded": True, "failure_type": None}))
    source_path.write_text(json.dumps([], indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError):
        fc.run()
    # A definitive successful search refreshes the fresh cache with the live list.
    assert json.loads(source_path.read_text(encoding="utf-8")) == fresh


# --- router sync contract (real _fine_sync.sh sourced, not reimplemented) ---

FINE_SYNC = Path(__file__).resolve().parent.parent / "_fine_sync.sh"


def _bash(expr):
    return subprocess.run(
        ["bash", "-c", 'source "%s"; %s' % (str(FINE_SYNC).replace("\\", "/"), expr)],
        capture_output=True, text=True,
    )


def _sync_check_groups(cfg_path):
    proc = _bash('check_groups "%s"; echo RC=$?' % str(cfg_path).replace("\\", "/"))
    for line in proc.stdout.splitlines():
        if line.startswith("RC="):
            return int(line[3:].strip())
    return -1


def _write_published_config(path, nodes):
    cfg = bf.build_config(nodes)
    import yaml
    header = "# fine-clash-unified-v3 | fine-clash-version:20261020120000 | Fine=validated-pool | CN->DIRECT | MATCH->Fine\n"
    path.write_text(header + yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")


def test_sync_check_groups_passes_published_config(tmp_path):
    cfg_file = tmp_path / "live_clash.yaml"
    _write_published_config(cfg_file, [{"name": "Fine-1", "type": "trojan",
                                        "server": "example.com", "port": 443,
                                        "password": "secret", "tls": True}])
    assert _sync_check_groups(cfg_file) == 0


def test_sync_check_groups_rejects_missing_fine_group(tmp_path):
    cfg_file = tmp_path / "bad.yaml"
    cfg_file.write_text(
        "mode: rule\n"
        "proxy-groups:\n"
        "  - name: PROXY\n    type: select\n    proxies: [DIRECT]\n"
        "rules:\n  - MATCH,PROXY\n",
        encoding="utf-8",
    )
    assert _sync_check_groups(cfg_file) == 1


def test_sync_check_groups_rejects_geosite_dependency(tmp_path):
    cfg_file = tmp_path / "geo.yaml"
    _write_published_config(cfg_file, [{"name": "Fine-1", "type": "trojan",
                                        "server": "example.com", "port": 443,
                                        "password": "secret", "tls": True}])
    # Inject a GEOSITE rule the generator would never emit -> guard must catch it.
    text = cfg_file.read_text(encoding="utf-8") + "  - GEOSITE,google@ads,Fine\n"
    cfg_file.write_text(text, encoding="utf-8")
    assert _sync_check_groups(cfg_file) == 1


def _vercmp(remote, local):
    proc = _bash('vercmp "%s" "%s"; echo RC=$?' % (remote, local))
    for line in proc.stdout.splitlines():
        if line.startswith("RC="):
            return int(line[3:].strip())
    return -1


def test_sync_vercmp_handles_14_digit_without_overflow():
    # 14-digit timestamps exceed the 32-bit signed int range (> 2**31-1); vercmp
    # must compare them as numbers via awk, not as 32-bit ints.
    assert _vercmp("20261020120000", "20261020110000") == 0  # remote newer
    assert _vercmp("20261020110000", "20261020120000") == 1  # remote older
    assert _vercmp("20261020120000", "20261020120000") == 1  # equal -> not newer
    assert _vercmp("", "20261020120000") == 1                # no remote -> keep local
    assert _vercmp("20261020120000", "") == 0                # no local -> remote newer
    # Far-future timestamps (overflow 32-bit) still compare correctly.
    assert _vercmp("20991231235959", "19990101000000") == 0
    assert _vercmp("19990101000000", "20991231235959") == 1
