import base64
import inspect
import pytest
from pathlib import Path

import fine_clash as fc
import build_final as bf


def _fine_node(name="Fine-1"):
    return {"name": name, "type": "trojan", "server": "example.com", "port": 443, "password": "secret", "tls": True}


def test_final_proxy_groups_single_fine_with_direct():
    fine_names = ["Fine-1", "Fine-2"]
    groups = bf.build_proxy_groups(fine_names)
    by_name = {g["name"]: g for g in groups}
    assert set(by_name) == {"Fine", "Fine-Auto"}
    # Sticky-first: the first (quality-ranked) node is pinned as default-selected.
    assert by_name["Fine"]["default-selected"] == fine_names[0]
    # Fine-Auto (auto-select) and DIRECT are selectable alongside every node.
    assert by_name["Fine"]["proxies"] == ["Fine-Auto", "DIRECT"] + fine_names
    # Fine-Auto itself is a hidden url-test group so it stays out of the UI list.
    assert by_name["Fine-Auto"]["type"] == "url-test"
    assert by_name["Fine-Auto"]["hidden"] is True
    assert by_name["Fine-Auto"]["proxies"] == fine_names

def test_sticky_primary_is_pinned_as_default_selected():
    # The pool is intentionally ordered quality-first by fine_clash.py's sticky
    # ordering (previous connected node if still Shenzhen-quality, else freshest
    # quality node). build_proxy_groups must pin that first node as the default
    # so the user's active connection survives a subscription refresh.
    fine_names = ["Fine-KEPT", "Fine-B", "Fine-C"]
    groups = bf.build_proxy_groups(fine_names)
    by_name = {g["name"]: g for g in groups}
    assert by_name["Fine"]["default-selected"] == "Fine-KEPT"
    # Fine-Auto url-test subgroup is embedded in Fine for auto-selection, but the
    # sticky primary (not Fine-Auto) remains the default so the connection persists.
    assert "Fine-Auto" in by_name
    assert by_name["Fine"]["default-selected"] != "Fine-Auto"


def test_final_config_is_fine_only():
    cfg = bf.build_config([_fine_node()])
    assert cfg["mode"] == "rule"
    assert [n["name"] for n in cfg["proxies"]] == ["Fine-1"]
    assert "proxy-providers" not in cfg
    assert "global-ua" not in cfg
    assert cfg["rules"][-1] == "MATCH,Fine"
    assert {g["name"] for g in cfg["proxy-groups"]} == {"Fine", "Fine-Auto"}
    for rule in bf.WPS_DIRECT_RULES:
        assert rule in cfg["rules"]
    assert cfg["rules"].index("DOMAIN-SUFFIX,wps.cn,DIRECT") < cfg["rules"].index("DOMAIN-SUFFIX,cn,DIRECT")
    for domain in ("+.wps.cn", "+.wps.com", "+.wps365.com", "+.kdocs.cn", "+.wpscdn.cn", "+.wpscdn.com"):
        assert domain in cfg["dns"]["nameserver-policy"]


def test_public_profile_is_self_contained_fine_only():
    config = bf.build_config([_fine_node()])
    assert "proxy-providers" not in config
    assert "global-ua" not in config
    assert config["rules"][-1] == "MATCH,Fine"
    assert {group["name"] for group in config["proxy-groups"]} == {"Fine", "Fine-Auto"}


def test_load_previous_published_nodes_only_keeps_members_of_fine_group(tmp_path, monkeypatch):
    profile = tmp_path / "live_clash.yaml"
    profile.write_text(
        "proxies:\n"
        "  - name: fine-1\n"
        "    type: trojan\n"
        "    server: fine.example\n"
        "    port: 443\n"
        "    password: fine\n"
        "    tls: true\n"
        "  - name: unrelated-1\n"
        "    type: trojan\n"
        "    server: unrelated.example\n"
        "    port: 443\n"
        "    password: unrelated\n"
        "    tls: true\n"
        "proxy-groups:\n"
        "  - name: Fine\n"
        "    type: select\n"
        "    proxies: [Fine-Auto, DIRECT, fine-1]\n"
        "  - name: Other\n"
        "    type: select\n"
        "    proxies: [unrelated-1]\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(fc, "resolved_server_is_safe", lambda server: True)
    nodes = fc.load_previous_published_nodes(profile, max_nodes=5)
    assert [node["name"] for node in nodes] == ["fine-1"]


def test_source_discovery_accepts_extensionless_subscription_files(monkeypatch):
    discovery = fc.GitHubDiscovery(None, {
        "queries": [], "recent_days": 30, "require_recent_push": True,
        "repositories_per_query": 20, "max_repositories": 20,
        "max_candidate_files_per_repo": 8,
    })
    monkeypatch.setattr(
        discovery,
        "_get_json",
        lambda url, params=None: {"tree": [
            {"type": "blob", "path": "sub"},
            {"type": "blob", "path": "README.md"},
            {"type": "blob", "path": "notes.log"},
            {"type": "blob", "path": "luci-app-openclash/root/usr/share/openclash/res/default.yaml"},
            {"type": "blob", "path": "clash20261010.yml"},
        ]},
    )
    files = discovery.candidate_files({"full_name":"x/y","default_branch":"main"})
    assert "sub" in files
    assert "README.md" in files
    assert "clash20261010.yml" in files
    assert "luci-app-openclash/root/usr/share/openclash/res/default.yaml" not in files
    assert "notes.log" not in files

def test_cached_source_candidate_path_rejects_project_defaults():
    assert fc.is_candidate_source_path("Subscriptions/Sub9.txt")
    assert fc.is_candidate_source_path("api/allConfigs.json")
    assert fc.is_candidate_source_path("README.md")
    assert not fc.is_candidate_source_path("luci-app-openclash/root/usr/share/openclash/res/default.yaml")
    assert not fc.is_candidate_source_path("docs/defaults.yaml")

def test_round_robin_fingerprints_balances_large_repositories():
    first = [f"a-{i}" for i in range(100)]
    second = ["b-0", "b-1"]
    third = [f"c-{i}" for i in range(100)]
    picked = fc.round_robin_fingerprints([first, second, third])
    assert picked[:9] == ["a-0", "b-0", "c-0", "a-1", "b-1", "c-1", "a-2", "c-2", "a-3"]
    assert len(picked) == 202
    assert len(set(picked)) == len(picked)


def test_discovery_fetches_sources_concurrently_and_preserves_priority_order(monkeypatch):
    discovery = fc.GitHubDiscovery(None, {"source_workers": 2})
    repos = [
        {"full_name": "x/first", "default_branch": "main"},
        {"full_name": "x/second", "default_branch": "main"},
    ]
    monkeypatch.setattr(discovery, "search_repositories", lambda: repos)
    monkeypatch.setattr(discovery, "candidate_files", lambda repo: [f"{repo['full_name']}.yaml"])
    monkeypatch.setattr(
        discovery,
        "fetch_and_validate",
        lambda repo, path: {"url": path, "repo": repo["full_name"]},
    )
    result = discovery.discover()
    assert [source["repo"] for source in result] == ["x/first", "x/second"]
    assert discovery.stats["sources_found"] == 2


def test_discovery_caps_total_feed_downloads(monkeypatch):
    discovery = fc.GitHubDiscovery(None, {"source_workers": 2, "max_source_fetches": 1})
    repos = [
        {"full_name": "x/first", "default_branch": "main"},
        {"full_name": "x/second", "default_branch": "main"},
    ]
    monkeypatch.setattr(discovery, "search_repositories", lambda: repos)
    monkeypatch.setattr(discovery, "candidate_files", lambda repo: [f"{repo['full_name']}.yaml"])
    fetched = []
    def fetch(repo, path):
        fetched.append(path)
        return {"url": path, "repo": repo["full_name"]}
    monkeypatch.setattr(discovery, "fetch_and_validate", fetch)
    result = discovery.discover()
    assert [source["repo"] for source in result] == ["x/first"]
    assert fetched == ["x/first.yaml"]
    assert discovery.stats["candidate_paths_discovered"] == 2
    assert discovery.stats["candidate_paths_scheduled"] == 1


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
        "    tls: true\n"
        "proxy-groups:\n"
        "  - name: Fine\n"
        "    type: select\n"
        "    proxies: [Fine-Auto, DIRECT, old-1, old-2, old-3]\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(fc, "resolved_server_is_safe", lambda server: True)
    nodes = fc.load_previous_published_nodes(profile, max_nodes=2)
    assert [node["name"] for node in nodes] == ["old-1", "old-2"]




def test_stable_pool_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(fc, "resolved_server_is_safe", lambda server: True)
    path = tmp_path / "stable_pool.yaml"
    nodes = [
        {"name":"Stable-A","type":"trojan","server":"a.example","port":443,"password":"a","tls":True},
        {"name":"Stable-B","type":"trojan","server":"b.example","port":443,"password":"b","tls":True},
    ]
    assert fc.save_stable_pool(path,nodes,max_nodes=5)==2
    loaded=fc.load_stable_pool_nodes(path,max_nodes=5)
    assert [node["name"] for node in loaded]==["Stable-A","Stable-B"]


def test_pool_build_uses_fresh_sources_and_end_to_end_quality_gates():
    cfg = fc.load_rules()
    assert cfg["sources"]["recent_days"] == 7
    assert cfg["sources"]["source_workers"] == 12
    assert cfg["sources"]["max_source_fetches"] == 180
    assert cfg["sources"]["max_repositories"] == 60
    assert cfg["sources"]["max_candidate_files_per_repo"] == 4
    assert cfg["sources"]["max_source_age_days"] == 3
    assert cfg["sources"]["exploration_fraction"] == 0.2
    assert cfg["output"]["source_quality_file"] == "data/source_quality.json"
    assert cfg["nodes"]["stable_pool_file"] == "data/stable_pool.yaml"
    assert cfg["nodes"]["max_stable_nodes"] == 20
    assert cfg["nodes"]["candidate_gate"] == "gemini_or_play"
    assert cfg["nodes"]["min_clean_score"] == 65
    assert cfg["nodes"]["min_final_nodes"] == 3
    assert cfg["nodes"]["max_per_server"] == 2
    assert cfg["nodes"]["max_per_org"] == 3
    assert cfg["nodes"]["max_endpoint_latency_ms"] == 2500
    assert cfg["shenzhen_probe"]["reject_above_ms"] == 250
    assert cfg["shenzhen_probe"]["reject_loss_pct"] == 0
    assert cfg["shenzhen_probe"]["cache_days"] == 0.25
    assert cfg["retention"]["enabled"] is True
    assert cfg["retention"]["max_previous_nodes"] == 5

def test_total_score_penalizes_slow_end_to_end_requests():
    common = {
        "gemini": True, "google_play": True, "google": {"ok": True},
        "clean": 80, "lifespan": 3, "stability": 1,
    }
    fast = fc.total_score(**common, endpoint_latency_ms=400)
    slow = fc.total_score(**common, endpoint_latency_ms=5000)
    assert slow <= fast - 15


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


def test_source_is_fresh_rejects_stale_snapshot_even_if_repo_was_pushed_later():
    now = fc.datetime(2026, 10, 10, 12, 0, tzinfo=fc.timezone.utc)
    stale_snapshot = {"path": "clash20261004.yml", "pushed_at": "2026-10-09T10:00:00Z"}
    fresh_feed = {"path": "sub.yaml", "pushed_at": "2026-10-09T10:00:00Z"}
    assert not fc.source_is_fresh(stale_snapshot, 3, now)
    assert fc.source_is_fresh(fresh_feed, 3, now)
    assert not fc.source_is_fresh({"path": "sub.yaml"}, 3, now)


def test_source_path_sort_key_parses_version_numbers():
    assert fc.source_path_sort_key("clash-v2.yaml")[1] == 2
    assert fc.source_path_sort_key("version-12.yaml")[1] == 12


def test_parse_uri_skips_malformed_port_instead_of_aborting_source_scan():
    assert fc.parse_uri("vless://some-uuid@example.com:not-a-port?security=tls") is None


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
    for rule in fc.WPS_DIRECT_RULES:
        assert rule in routes
    for rule in fc.WECHAT_DIRECT_RULES:
        assert rule in routes
    assert "DOMAIN-SUFFIX,qpic.cn,DIRECT" in routes
    assert "DOMAIN-SUFFIX,qq.com,DIRECT" in routes
    assert "GEOSITE,CN,DIRECT" not in routes
    assert "DOMAIN-SUFFIX,mi.com,DIRECT" in routes
    assert "DOMAIN-SUFFIX,xiaomi.com,DIRECT" in routes
    for domain in ("+.wps.cn", "+.wps.com", "+.kdocs.cn", "+.wpscdn.cn", "+.wpscdn.com"):
        assert domain in built["dns"]["nameserver-policy"]
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
    cfg = {"reject_above_ms": 400, "reject_loss_pct": 25}
    assert fc.shenzhen_passes({"ok": True, "avg_ms": 399.9, "loss_pct": 0}, cfg)
    assert fc.shenzhen_passes({"ok": True, "avg_ms": 400, "loss_pct": 25}, cfg)
    assert not fc.shenzhen_passes({"ok": True, "avg_ms": 400.1, "loss_pct": 0}, cfg)
    assert not fc.shenzhen_passes({"ok": True, "avg_ms": 100, "loss_pct": 26}, cfg)
    assert not fc.shenzhen_passes({"ok": True, "avg_ms": 100}, cfg)
    assert not fc.shenzhen_passes({"ok": False, "status": "timeout"}, cfg)


def test_probe_outage_preserves_last_good_shenzhen_measurement():
    row = {
        "shenzhen_checked_at": fc.datetime.now(fc.timezone.utc).isoformat(),
        "shenzhen_ping_ms": 120.0,
        "shenzhen_loss_pct": 0.0,
        "shenzhen_probe_city": "Shenzhen",
        "shenzhen_probe_observations": 2,
    }
    fc.save_shenzhen_history(row, {"ok": False, "status": "probe-unavailable", "attempts": 2})
    assert row["shenzhen_ping_ms"] == 120.0
    assert row["shenzhen_loss_pct"] == 0.0
    assert row["shenzhen_last_attempt_status"] == "probe-unavailable"
    last_good = fc.recent_shenzhen_good_result(row, 24)
    assert last_good and last_good["avg_ms"] == 120.0


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


def test_rank_final_nodes_applies_diversity_to_previous_and_new_candidates():
    # Formerly retained previous nodes filled final slots before rank_candidates
    # ran, so same-server duplicates bypassed the diversity cap.
    old_nodes = [
        _rank_node(f"old-{i}", "old.example", password=f"old-{i}")
        for i in range(5)
    ]
    fresh_nodes = [
        _rank_node("fresh-a", "fresh-a.example"),
        _rank_node("fresh-b", "fresh-b.example"),
        _rank_node("fresh-c", "fresh-c.example"),
    ]
    candidates = old_nodes + fresh_nodes
    metadata = {
        fc.fingerprint(node): _rank_meta(node, score=96 - i, ping=80 + i)
        for i, node in enumerate(old_nodes)
    }
    metadata.update({
        fc.fingerprint(node): _rank_meta(node, score=90 - i, ping=60 + i)
        for i, node in enumerate(fresh_nodes)
    })

    ranked = fc.rank_final_nodes(
        candidates,
        metadata,
        {
            "max_final_nodes": 4,
            "max_per_server": 2,
            "max_per_org": 10,
            "min_final_score": 55,
        },
    )

    servers = [node["server"] for node in ranked]
    assert len(ranked) == 4
    assert servers.count("old.example") == 2
    assert "fresh-a.example" in servers
    assert "fresh-b.example" in servers


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


def test_rank_candidates_uses_us_residential_only_as_quality_tiebreaker():
    us_home = _rank_node("us-home", "1.1.1.1")
    us_dc = _rank_node("us-dc", "2.2.2.2")
    foreign = _rank_node("foreign", "3.3.3.3")
    nodes = [foreign, us_dc, us_home]
    meta = {
        fc.fingerprint(us_home): {**_rank_meta(us_home, score=80, ping=50), "app_latency_ms": 500, "country": "US", "org": "Comcast Cable Communications"},
        fc.fingerprint(us_dc): {**_rank_meta(us_dc, score=80, ping=50), "app_latency_ms": 500, "country": "US", "org": "Amazon Web Services"},
        fc.fingerprint(foreign): {**_rank_meta(foreign, score=80, ping=50), "app_latency_ms": 500, "country": "DE", "org": "Deutsche Telekom"},
    }
    ranked = fc.rank_candidates(nodes, metadata=meta)
    names = [n["name"] for n in ranked]
    assert names[0] == "us-home"
    assert set(names[1:]) == {"us-dc", "foreign"}


def test_rank_candidates_does_not_let_us_bonus_override_endpoint_speed():
    us_home = _rank_node("us-home", "1.1.1.1")
    fast_foreign = _rank_node("fast-foreign", "3.3.3.3")
    nodes = [us_home, fast_foreign]
    meta = {
        fc.fingerprint(us_home): {**_rank_meta(us_home, score=80, ping=200), "app_latency_ms": 2000, "country": "US", "org": "Comcast Cable Communications"},
        fc.fingerprint(fast_foreign): {**_rank_meta(fast_foreign, score=80, ping=50), "app_latency_ms": 500, "country": "DE", "org": "Deutsche Telekom"},
    }
    ranked = fc.rank_candidates(nodes, metadata=meta)
    assert [n["name"] for n in ranked] == ["fast-foreign", "us-home"]


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


def test_sticky_quality_requires_fast_end_to_end_latency():
    base = {"shenzhen_ping_ms": 120, "shenzhen_loss_pct": 0, "app_latency_ms": 1500}
    cfg = {"keep_ping_ms": 300, "keep_loss_pct": 5, "keep_endpoint_latency_ms": 2000}
    assert fc.node_is_quality(base, cfg)
    assert not fc.node_is_quality({**base, "app_latency_ms": 2500}, cfg)
    assert not fc.node_is_quality({"shenzhen_ping_ms": 120, "shenzhen_loss_pct": 0}, cfg)


def test_missing_ipinfo_and_cloudflare_edge_are_neutral_not_hard_rejected():
    google_ok = {"ok": True, "challenge": False}
    item = {"gemini": True, "google_play": True, "google": google_ok}
    assert fc.clean_score(None, google_ok) == 65
    assert fc.clean_score({"org": "AS13335 Cloudflare, Inc."}, google_ok) == 65
    assert fc.clean_score({"org": "AS9009 M247 Europe SRL"}, google_ok) < 65
    assert fc.candidate_gate_passes(item, "gemini_or_play", 65, 65)
    assert not fc.candidate_gate_passes(item, "gemini_or_play", 60, 65)


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

def test_previous_profile_without_fine_group_is_not_trusted(tmp_path, monkeypatch):
    profile = tmp_path / "live_clash.yaml"
    profile.write_text("proxies:\\n- name: orphan\\n  type: trojan\\n  server: orphan.example\\n  port: 443\\n  password: x\\n",
                       encoding="utf-8")
    monkeypatch.setattr(fc, "resolved_server_is_safe", lambda server: True)
    assert fc.load_previous_published_nodes(profile, max_nodes=5) == []

def test_source_quality_score_rewards_real_quality():
    good={"parsed_nodes_total":100,"unique_nodes_total":80,
          "endpoint_tested_total":50,"endpoint_passed_total":40,
          "shenzhen_decided_total":20,"shenzhen_passed_total":17}
    bad={"parsed_nodes_total":100,"unique_nodes_total":10,
         "endpoint_tested_total":50,"endpoint_passed_total":4,
         "shenzhen_decided_total":20,"shenzhen_passed_total":2}
    assert fc.source_quality_score(good)>fc.source_quality_score(bad)


def test_source_selection_reserves_exploration_slots():
    sources=[
        {"url":f"https://raw.example/proven-{i}.yaml","repo":f"x/proven-{i}",
         "pushed_at":"2026-10-10T01:00:00Z","stars":100}
        for i in range(4)
    ]+[{"url":"https://raw.example/new.yaml","repo":"x/new",
        "pushed_at":"2026-10-10T05:00:00Z","stars":40}]
    quality={
        s["url"]:{"parsed_nodes_total":50,"unique_nodes_total":40,
                  "endpoint_tested_total":30,"endpoint_passed_total":24,
                  "shenzhen_decided_total":10,"shenzhen_passed_total":8}
        for s in sources[:-1]
    }
    picked=fc.rank_source_list(sources,quality,max_sources=3,exploration_fraction=0.34)
    assert len(picked)==3
    assert "https://raw.example/new.yaml" in {s["url"] for s in picked}


def test_weighted_round_robin_gives_each_feed_a_seed_and_favors_good_sources():
    high=[f"h-{i}" for i in range(12)]
    low=[f"l-{i}" for i in range(12)]
    picked=fc.round_robin_fingerprints([high,low],weights=[1.5,0.5])
    assert picked[:2]==["h-0","l-0"]
    # Compare the actual test window, not the complete schedule that contains every node.
    window=picked[:12]
    assert sum(x.startswith("h-") for x in window)>sum(x.startswith("l-") for x in window)

def test_globalping_measure_retries_a_transient_unknown_result(monkeypatch):
    probe=fc.GlobalpingShenzhenProbe({"retries":1})
    attempts=[]
    def measure_once(node):
        attempts.append(node["name"])
        if len(attempts)==1:
            return {"ok":False,"status":"probe-unavailable"}
        return {"ok":True,"status":"ok","avg_ms":120.0,"loss_pct":0.0,"probe_observations":2}
    monkeypatch.setattr(probe,"_measure_once",measure_once)
    monkeypatch.setattr(fc.time,"sleep",lambda *_:None)
    result=probe.measure({"name":"demo"})
    assert result["ok"] is True
    assert result["attempts"]==2
    assert len(attempts)==2


def test_globalping_aggregates_multiple_probe_results(monkeypatch):
    probe=fc.GlobalpingShenzhenProbe({
        "city":"Shenzhen","protocol":"TCP","probe_count":2,
        "min_successful_probes":1,"max_wait_seconds":1,"poll_interval_seconds":0.25,
        "packets":4,
    })
    class FakeResponse:
        def __init__(self,payload): self.payload=payload
        def raise_for_status(self): return None
        def json(self): return self.payload
    posted=[]
    def fake_post(url,json,timeout):
        posted.append(json)
        return FakeResponse({"id":"measurement-1"})
    def fake_get(url,timeout):
        return FakeResponse({
            "status":"finished",
            "results":[
                {"probe":{"city":"Shenzhen"},"result":{"stats":{"avg":100,"loss":0}}},
                {"probe":{"city":"Shenzhen"},"result":{"stats":{"avg":140,"loss":5}}},
            ],
        })
    monkeypatch.setattr(probe.session,"post",fake_post)
    monkeypatch.setattr(probe.session,"get",fake_get)
    result=probe._measure_once({"name":"demo","server":"example.com","port":443})
    assert posted[0]["locations"][0]["limit"]==2
    assert result["ok"] is True
    assert result["probe_observations"]==2
    assert result["avg_ms"]==120.0
    assert result["loss_pct"]==5.0

