import base64
import inspect
import re
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
    # Bitz stays absent unless its subscription URL is supplied by the
    # environment; the public profile must stay Fine-only by default.
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


def test_final_config_is_fine_only(monkeypatch):
    # A public build has no Bitz credential available, so it must degrade to a
    # fully self-contained Fine-only profile rather than referencing a group
    # that would never be populated.
    monkeypatch.delenv(bf.BITZ_URL_ENV, raising=False)
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
    for domain in ("+.wps.cn", "+.wps.com", "+.kdocs.cn", "+.wpscdn.cn", "+.wpscdn.com"):
        assert domain in cfg["dns"]["nameserver-policy"]


def test_final_config_leaves_mihomo_default_ua_untouched_without_bitz(monkeypatch):
    # Without Bitz there is no reason to spoof anything, so mihomo keeps its own UA.
    monkeypatch.delenv(bf.BITZ_URL_ENV, raising=False)
    cfg = bf.build_config([_fine_node()])
    assert "global-ua" not in cfg


def _bitz_node():
    return {"name": "Bitz-1", "type": "trojan", "server": "bitz.example", "port": 443,
            "password": "pw", "udp": True}


def test_final_config_enables_bitz_from_environment(monkeypatch):
    monkeypatch.setenv(bf.BITZ_ALLOWED_HOSTS_ENV, "upstream.example")
    monkeypatch.setenv(bf.BITZ_URL_ENV, "https://upstream.example/api/v1/client/sub.conf")
    monkeypatch.setattr(bf, "fetch_bitz_nodes", lambda url, timeout=30: [_bitz_node()])
    cfg = bf.build_config([_fine_node()])
    # Nodes are embedded rather than referenced through `proxy-providers`, because
    # only mihomo understands that extension while this profile must also load in
    # Shadowrocket / Clash for Android / v2rayN.
    assert "proxy-providers" not in cfg
    assert [n["name"] for n in cfg["proxies"]] == ["Fine-1", "Bitz-1"]
    # Bulk video/store traffic keeps using the validated Fine pool...
    assert "DOMAIN-SUFFIX,youtube.com,Fine" in cfg["rules"]
    assert "DOMAIN-SUFFIX,play.google.com,Fine" in cfg["rules"]
    # ...everything else falls through to Bitz.
    assert cfg["rules"][-1] == "MATCH,Bitz"
    # Domestic direct rules must survive the Bitz rollout untouched.
    assert "DOMAIN-SUFFIX,qq.com,DIRECT" in cfg["rules"]
    assert "DOMAIN-SUFFIX,mi.com,DIRECT" in cfg["rules"]
    assert "GEOIP,CN,DIRECT" in cfg["rules"]


def test_final_config_bitz_groups_are_symmetric(monkeypatch):
    fine_names = ["Fine-1", "Fine-2"]
    groups = bf.build_proxy_groups(fine_names, ["Bitz-1", "Bitz-2"])
    by_name = {g["name"]: g for g in groups}
    assert {"Fine", "Fine-Auto", "Bitz", "Bitz-Auto"} <= set(by_name)
    # Both groups expose their own Auto + DIRECT so each stays manually selectable.
    for name in ("Fine", "Bitz"):
        assert by_name[name]["type"] == "select"
        assert by_name[name]["proxies"][0] == f"{name}-Auto"
        assert "DIRECT" in by_name[name]["proxies"]
    # Fine keeps listing every validated node; Bitz lists the fetched nodes.
    assert by_name["Fine"]["proxies"] == ["Fine-Auto", "DIRECT"] + fine_names
    # Fine stays inside Bitz as the escape hatch for a failed upstream fetch.
    assert by_name["Bitz"]["proxies"] == ["Bitz-Auto", "DIRECT", "Fine", "Bitz-1", "Bitz-2"]
    assert by_name["Bitz"]["default-selected"] == "Bitz-Auto"
    assert by_name["Bitz-Auto"]["type"] == "url-test"
    # Real names instead of `include-all-providers`, so non-mihomo clients can
    # read the same file.
    assert by_name["Bitz-Auto"]["proxies"] == ["Bitz-1", "Bitz-2"]
    assert by_name["Bitz-Auto"]["url"] == bf.BITZ_HEALTH_CHECK_URL


def test_bitz_fetch_failure_degrades_to_fine_only(monkeypatch):
    # A half-built profile must never point MATCH at an empty group.
    monkeypatch.setenv(bf.BITZ_ALLOWED_HOSTS_ENV, "upstream.example")
    monkeypatch.setenv(bf.BITZ_URL_ENV, "https://upstream.example/sub")
    monkeypatch.setattr(bf, "fetch_bitz_nodes", lambda url, timeout=30: (_ for _ in ()).throw(RuntimeError("upstream down")))
    cfg = bf.build_config([_fine_node()])
    assert cfg["rules"][-1] == "MATCH,Fine"
    assert {g["name"] for g in cfg["proxy-groups"]} == {"Fine", "Fine-Auto"}


def test_proxy_from_uri_expands_the_protocols_the_upstream_serves():
    trojan = bf.proxy_from_uri("trojan://pw@h.example:443?sni=s.example&allowInsecure=1#节点")
    assert trojan["name"] == "节点"
    assert trojan["type"] == "trojan" and trojan["password"] == "pw"
    assert trojan["sni"] == "s.example" and trojan["skip-cert-verify"] is True
    vless = bf.proxy_from_uri("vless://11111111-2222-3333-4444-555555555555@h.example:443?security=reality&pbk=k&sid=1&flow=xtls-rprx-vision#v")
    assert vless["type"] == "vless" and vless["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert vless["reality-opts"] == {"public-key": "k", "short-id": "1"}
    assert bf.proxy_from_uri("http://nope") is None


def test_repository_contains_no_credential_bearing_url():
    # Regression guard for the 2026-10-04 incident, where a paid upstream URL with
    # its token was committed into the publicly published profile. Rather than
    # free-text scanning (a node's ws path can be 16 hex chars and looks identical
    # to a secret), this extracts URLs and reuses the production detector so the
    # two can never drift apart.
    repo_root = Path(bf.__file__).resolve().parent
    paid_host = "cont." + "bbkcdpub" + ".com"
    url_re = re.compile(r"https?://[^\s\"'<>]+")
    patterns = ("*.py", "*.yml", "*.yaml", "*.sh", "*.md", "*.json", "*.toml")
    offenders = []
    for path in sorted(p for pat in patterns for p in repo_root.rglob(pat)):
        # This file intentionally holds credential-shaped fixtures for the tests below.
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if paid_host in text:
            offenders.append(f"{path.relative_to(repo_root)}: paid upstream host")
        for url in url_re.findall(text):
            if bf.bitz_url_carries_credential(url):
                offenders.append(f"{path.relative_to(repo_root)}: {url[:72]}")
    assert offenders == []


def test_bitz_url_is_refused_when_host_is_not_approved(monkeypatch):
    # Publishing runs through a public repo, so an unapproved host must fail the
    # build rather than silently shipping whatever URL was configured.
    monkeypatch.setenv(bf.BITZ_URL_ENV, "https://paid-upstream.example.net/api/v1/client/sub.conf")
    monkeypatch.delenv(bf.BITZ_ALLOWED_HOSTS_ENV, raising=False)
    with pytest.raises(SystemExit, match="refusing to publish"):
        bf.build_config([_fine_node()])


def test_bitz_url_is_refused_when_it_carries_a_credential(monkeypatch):
    # The grep-based gates downstream only recognise `token=`. A path-style or
    # UUID-style credential slips past them, so the build has to reject it here.
    monkeypatch.setenv(bf.BITZ_ALLOWED_HOSTS_ENV, "relay.example")
    for url in (
        "https://relay.example/sub?token=PLACEHOLDER0000",
        "https://relay.example/api/v1/client/subscribe/7f3a9c2e5b1d4086aaaaaaaaaaaaaaaa",
        "https://relay.example/sub?key=abcd1234abcd1234",
    ):
        monkeypatch.setenv(bf.BITZ_URL_ENV, url)
        with pytest.raises(SystemExit, match="embeds a credential"):
            bf.build_config([_fine_node()])


def test_approved_tokenless_bitz_url_is_accepted(monkeypatch):
    monkeypatch.setenv(bf.BITZ_ALLOWED_HOSTS_ENV, "relay.example")
    monkeypatch.setenv(bf.BITZ_URL_ENV, "https://relay.example/sub")
    seen = []
    monkeypatch.setattr(bf, "fetch_bitz_nodes", lambda url, timeout=30: (seen.append(url), [_bitz_node()])[1])
    cfg = bf.build_config([_fine_node()])
    assert seen == ["https://relay.example/sub"]
    assert cfg["rules"][-1] == "MATCH,Bitz"


def test_credential_bearing_url_is_allowed_once_accepted(monkeypatch):
    # Owner decision 2026-10-07: usability over secrecy. Publishing the fetched
    # nodes is equivalent to publishing the token, and that risk was accepted.
    monkeypatch.setenv(bf.BITZ_ALLOWED_HOSTS_ENV, "relay.example")
    monkeypatch.setenv(bf.BITZ_PUBLIC_ENV, "1")
    monkeypatch.setenv(bf.BITZ_URL_ENV, "https://relay.example/sub?token=PLACEHOLDER0000")
    monkeypatch.setattr(bf, "fetch_bitz_nodes", lambda url, timeout=30: [_bitz_node()])
    cfg = bf.build_config([_fine_node()])
    assert cfg["rules"][-1] == "MATCH,Bitz"




def test_load_previous_published_nodes_ignores_bitz_group(tmp_path, monkeypatch):
    profile = tmp_path / "live_clash.yaml"
    profile.write_text(
        "proxies:\n"
        "  - name: fine-1\n"
        "    type: trojan\n"
        "    server: fine.example\n"
        "    port: 443\n"
        "    password: fine\n"
        "    tls: true\n"
        "  - name: bitz-1\n"
        "    type: trojan\n"
        "    server: bitz.example\n"
        "    port: 443\n"
        "    password: bitz\n"
        "    tls: true\n"
        "proxy-groups:\n"
        "  - name: Fine\n"
        "    type: select\n"
        "    proxies: [Fine-Auto, DIRECT, fine-1]\n"
        "  - name: Bitz\n"
        "    type: select\n"
        "    proxies: [Bitz-Auto, DIRECT, bitz-1]\n",
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
        ]},
    )
    files = discovery.candidate_files({"full_name":"x/y","default_branch":"main"})
    assert "sub" in files
    assert "README.md" in files
    assert "notes.log" not in files

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


def test_pool_build_gates_are_expanded_without_relaxing_shenzhen():
    cfg = fc.load_rules()
    assert cfg["nodes"]["candidate_gate"] == "reachable"
    assert cfg["nodes"]["min_clean_score"] == 60
    assert cfg["nodes"]["max_per_server"] == 3
    assert cfg["nodes"]["max_per_org"] == 6
    assert cfg["shenzhen_probe"]["reject_above_ms"] == 350
    assert cfg["shenzhen_probe"]["reject_loss_pct"] == 10
    assert cfg["retention"]["enabled"] is True
    assert cfg["retention"]["max_previous_nodes"] == 20

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
