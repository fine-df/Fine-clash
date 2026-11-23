# -*- coding: utf-8 -*-
"""Build the single public Clash/Mihomo profile from LIVE free node sources.

Architecture (2026-10-24, fail-safe flat aggregation):
- One subscription link (jsDelivr -> live_clash.yaml) is consumed by FOUR clients
  behind the GFW (iOS/Shadowrocket, Android/mihomo, router/ShellCrash, PC/Clash
  Verge). Every one of them must be able to PARSE the file and find live nodes.
- Why a flat `proxies:` list (not proxy-providers):
    * The router's `check_groups` validator (_fine_sync.sh) HARD-rejects any
      profile containing `proxy-providers:` (legacy guard), so a provider-based
      file would make the router refuse the update.
    * Shadowrocket's Clash parser is partial and does not reliably consume
      `proxy-providers:` / `use:` — risking the one currently-working end.
  A flat list is universally parseable, so all four ends stay alive.
- "Always live" is achieved by (a) aggregating MANY nodes from MULTIPLE free
  sources (diversity => some always survive), and (b) the CI rebuilding this file
  on a schedule (every few hours) so the embedded snapshot never freezes. The
  previous failure (frozen pool) came from a China-network publish gate that the
  US runner could not satisfy; that gate is gone, so the profile now regenerates
  continuously. Clients still url-test locally (AUTO group) to pick the fastest.
- Free-only: sources MUST be public free aggregators. No paid airports, no Bitz,
  no收费上游 (permanent red line).
"""
from __future__ import annotations
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
import requests
import yaml

OUT = Path("live_clash.yaml")
CFG = Path("config.yaml")

# ---- Free source catalog -----
# 2026-11-21 SOURCE SWAP (round 3): strict per-node delay tests showed Au1rxx
# verified shards decayed to ~10/2553 live, and an earlier 89-alive snapshot
# fell to 18 after 25 minutes. Replaced with live-tested public free sources:
#   - yy1588133/proxy-pool: 1183 nodes; 252 alive at probe, 182 still alive
#     22 minutes later (72% retention) -- by far the best pool tested.
#   - OgdenThomas/freesub and kooker/FreeSubsCheck: small actively-refreshed
#     YAML pools kept as diversity backup.
# 2026-11-21 ROLLBACK (round 4): round 3 added http/socks5 and let yypool's
# mihomo-private fields (x-toolall-mihomo, xhttp-opts, packet-encoding, ...)
# and non-standard networks (xhttp/httpupgrade/http) into the flat proxies.
# Shadowrocket (iOS) has a partial Clash parser and stopped being able to
# update/parse the profile. Roll back to the exact shape that worked for a
# month: 4 standard types + a strict per-type field whitelist + standard
# networks only. hysteria/wireguard/anytls/xhttp/httpupgrade stay excluded.
# The builder runs on a US GitHub Actions runner where raw.githubusercontent.com
# is directly reachable; jsDelivr is only for CLIENT-side pull of the final file.
# Each entry: id, url, prefix (avoid name collisions), take (max per source).
SOURCES = [
    {"id": "yypool-main", "url": "https://raw.githubusercontent.com/yy1588133/proxy-pool/main/clash.yaml", "prefix": "YP-", "take": 2000},
    {"id": "freesub-all", "url": "https://raw.githubusercontent.com/OgdenThomas/freesub/main/output/clash.yaml", "prefix": "FS-", "take": 1000},
    {"id": "kooker-all", "url": "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/all.yaml", "prefix": "KA-", "take": 200},
    {"id": "kooker-mihomo", "url": "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/mihomo.yaml", "prefix": "KM-", "take": 200},
]

ALLOWED_TYPES = {"vmess", "vless", "trojan", "ss"}

# Strict field whitelist per type: only fields present in the config that
# worked on all four ends for a month. Drops mihomo-private junk fields that
# Shadowrocket's parser rejects (x-toolall-mihomo, sub_tag, xudp,
# packet-encoding, delay, xhttp-opts, httpupgrade-opts, client-fingerprint...).
_COMMON_FIELDS = {"name", "server", "port", "type", "udp"}
ALLOWED_FIELDS = {
    "ss":     _COMMON_FIELDS | {"cipher", "password", "plugin", "plugin-opts"},
    "vmess":  _COMMON_FIELDS | {"uuid", "alterId", "cipher", "tls", "servername", "skip-cert-verify", "network", "ws-opts", "grpc-opts", "sni", "alpn"},
    "vless":  _COMMON_FIELDS | {"uuid", "flow", "tls", "servername", "skip-cert-verify", "network", "ws-opts", "grpc-opts", "reality-opts", "sni", "alpn"},
    "trojan": _COMMON_FIELDS | {"password", "sni", "alpn", "tls", "skip-cert-verify", "network", "ws-opts", "grpc-opts"},
}
# Shadowrocket cannot handle these Clash.Meta network modes.
ALLOWED_NETWORKS = {"ws", "grpc", "tcp", "h2"}
ALLOWED_WS_FIELDS = {"path", "headers"}
ALLOWED_REALITY_FIELDS = {"public-key", "short-id"}
ALLOWED_GRPC_FIELDS = {"grpc-service-name", "grpc-mode"}
HEALTH_URL = "https://www.google.com/generate_204"

# ---- Live proxy probe (restores Gemini / Google-Play preference + node
# retention that were lost in the 2026-10-24 flat-aggregation rewrite) ----
# A real mihomo tunnel pushes traffic THROUGH each candidate node to probe which
# nodes can actually open Gemini / Google Play / google-204. Nodes that pass are
# ranked FIRST so the client-side url-test (AUTO group) and the default-selected
# pick prefer them; the previous profile's still-alive nodes stay pinned on top
# (continuity). This only REORDERS nodes -- fields are untouched, so the four
# clients' parse compatibility is unchanged.
PROBE_URLS = {
    "gemini": "https://gemini.google.com/",
    "google_play": "https://play.google.com/store",
    "google": "https://www.google.com/generate_204",
}
# How many fresh nodes to probe (plus the previous profile's nodes). Kept small
# so CI stays well under the timeout; unprobed nodes are still published, just
# ranked after the probed ones.
PROBE_TEST_COUNT = 100
PROBE_WORKERS = 6
PROBE_TIMEOUT_SECONDS = 8
PROBE_SWITCH_WAIT_SECONDS = 0.4
PROBE_SUCCESS_STATUSES = (200, 204, 301, 302)
# Google serves a 302 to google.com/sorry when it flags the node IP as abusive
# (shared free-node IP). That means the endpoint is NOT actually reachable for a
# real user -- treat it as failed.
PROBE_CHALLENGE_MARKERS = ("sorry", "unusual traffic", "captcha", "access denied")
# Continuity reserve: keep up to this many previous-profile nodes pinned on top.
MAX_PREVIOUS_NODES = 20
# Score weights: Gemini and Google Play are the user's hard requirements.
SCORE_GEMINI = 25
SCORE_PLAY = 20
SCORE_GOOGLE = 20

# ---- Shenzhen (China) reachability probe ----
# The CI runner is in the US; a node that is reachable from the US is often NOT
# reachable from China behind the GFW. The 2026-10-24 refactor dropped the old
# fine_clash.py Shenzhen probe (Globalping), leaving "alive" ranked purely by
# US-side HTTP reachability -- which produced nodes that Chinese clients could
# not even TCP-connect to (measured ~4% China-usable). We restore a lightweight
# Globalping TCP ping from a Shenzhen probe to filter/rank by real China reach.
SHENZHEN_ENABLED = True
SHENZHEN_CITY = "Shenzhen"
SHENZHEN_TEST_COUNT = 60   # top-alive nodes to re-check from Shenzhen
SHENZHEN_PACKETS = 3
SHENZHEN_WORKERS = 8
SHENZHEN_POLL_SECONDS = 2
SHENZHEN_TIMEOUT_SECONDS = 18
# A China-usable node must TCP-connect from Shenzhen. Loss is coarse (0/33/66/100
# with 3 packets); reject only total loss, and prefer low ping.
SHENZHEN_REJECT_LOSS_PCT = 100
SHENZHEN_REJECT_ABOVE_MS = 800

# ---- Automatic source failover ----
# Keep at least this many sources that are still producing alive nodes. When the
# count drops below it (sources die / get deleted), auto-discover fresh free
# sources on GitHub and persist them so the next runs keep a healthy pool.
# This is the fix for the "all sources dead, nothing usable for days" outage.
FALLBACK_MIN_GOOD_SOURCES = 3
FALLBACK_MAX_SOURCES = 5
FALLBACK_SOURCES_FILE = Path("data/fallback_sources.json")
FALLBACK_QUERIES = [
    "clash订阅 in:name,description,readme archived:false stars:>=20",
    "v2ray free in:name,description,readme archived:false stars:>=20",
    "v2ray subscription in:name,description,readme archived:false stars:>=20",
]
FALLBACK_EXCLUDE_REPOS = {
    "clash-verge-rev/clash-verge-rev",
    "hiddify/Hiddify-Manager",
    "hiddify/hiddify-app",
    "KaringX/clashmi",
    "mihomo-party-org/clash-party",
    "nelvko/clashctl",
    "sub-store-org/Sub-Store",
    "Johnshall/Shadowrocket-ADBlock-Rules-Forever",
    "githubvpn007/v2rayNvpn",
    "dongyubin/Free-AppleId-Serve",
    "DiningFactory/panda-vpn-pro",
}
# Previously discovered and verified free YAML sources. Checked FIRST on
# failover (more reliable than a blind GitHub search), then GitHub search
# tops up if these are also dead.
FALLBACK_CANDIDATE_SOURCES = [
    {"id": "freeharbor", "url": "https://raw.githubusercontent.com/Leechuihui/FreeHarbor/main/clients/clash.yaml", "prefix": "FH-", "take": 1000},
    {"id": "snakem982", "url": "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml", "prefix": "SN-", "take": 1000},
]

# Junk / decoy / placeholder node names from free aggregators (not real proxies).
JUNK_RE = re.compile(
    r"(防范|渗透|测试|占位|无效|过期|dead|expired|机场|订阅|示例|demo|fake|"
    r"test|unknown|null|占位符|临时|失效|不可用|广告|引流)",
    re.IGNORECASE,
)
# Domestic "exit" nodes are useless as a GFW bypass in the flat list.
CN_RE = re.compile(r"(🇨🇳|中国|cn[-_])", re.IGNORECASE)

VIDEO_DOMAINS = ["youtube.com","youtu.be","ytimg.com","googlevideo.com","netflix.com","nflxvideo.net","nflximg.net","twitch.tv","ttvnw.net","vimeo.com"]
STORE_DOMAINS = ["play.google.com","googleplay.com","dl.google.com","gvt1.com","gvt2.com","microsoft.com","microsoftstore.com","apps.microsoft.com","steampowered.com","steamcommunity.com"]
WECHAT_DIRECT = ["DOMAIN-SUFFIX,weixin.qq.com,DIRECT","DOMAIN-SUFFIX,wx.qq.com,DIRECT","DOMAIN-SUFFIX,wechat.com,DIRECT","DOMAIN-SUFFIX,qpic.cn,DIRECT","DOMAIN-SUFFIX,qlogo.cn,DIRECT","DOMAIN-SUFFIX,gtimg.cn,DIRECT","DOMAIN-SUFFIX,gtimg.com,DIRECT","DOMAIN-SUFFIX,qq.com,DIRECT","DOMAIN-SUFFIX,tenpay.com,DIRECT","DOMAIN-SUFFIX,wechatpay.cn,DIRECT","DOMAIN-SUFFIX,tencent.com,DIRECT","DOMAIN-SUFFIX,tencent-cloud.com,DIRECT","DOMAIN-SUFFIX,myqcloud.com,DIRECT","DOMAIN-SUFFIX,tencentcos.cn,DIRECT"]
WPS_DIRECT = ["DOMAIN-SUFFIX,wps.cn,DIRECT","DOMAIN-SUFFIX,wps.com,DIRECT","DOMAIN-SUFFIX,kdocs.cn,DIRECT","DOMAIN-SUFFIX,kdocs.com,DIRECT","DOMAIN-SUFFIX,kingsoft.com,DIRECT"]
XIAOMI_DIRECT = ["DOMAIN-SUFFIX,mi.com,DIRECT","DOMAIN-SUFFIX,xiaomi.com,DIRECT","DOMAIN-SUFFIX,miwifi.com,DIRECT","DOMAIN-SUFFIX,miui.com,DIRECT","DOMAIN-SUFFIX,mijia.com,DIRECT","DOMAIN-SUFFIX,xiaomi.cn,DIRECT"]
LOCAL_IOT_DIRECT = ["IP-CIDR,224.0.0.0/4,DIRECT,no-resolve","IP-CIDR,169.254.0.0/16,DIRECT,no-resolve"]
PRIVATE_DIRECT = ["DOMAIN-SUFFIX,lan,DIRECT","DOMAIN-SUFFIX,local,DIRECT","DOMAIN-SUFFIX,localhost,DIRECT","DOMAIN-SUFFIX,cn,DIRECT","DOMAIN-SUFFIX,com.cn,DIRECT","DOMAIN-SUFFIX,net.cn,DIRECT","DOMAIN-SUFFIX,gov.cn,DIRECT","DOMAIN-SUFFIX,edu.cn,DIRECT","IP-CIDR,10.0.0.0/8,DIRECT,no-resolve","IP-CIDR,172.16.0.0/12,DIRECT,no-resolve","IP-CIDR,192.168.0.0/16,DIRECT,no-resolve","IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"]
# Keep subscription-refresh traffic on domestic-reachable links so the client can
# re-pull this very file even when its current nodes are slow/dead.
SUBSCRIPTION_CDN_DIRECT = ["DOMAIN-SUFFIX,jsdelivr.net,DIRECT","DOMAIN-SUFFIX,github.com,DIRECT","DOMAIN-SUFFIX,raw.githubusercontent.com,DIRECT"]

UA = "Fine-clash-builder/1.0 (+https://github.com/fine-df/Fine-clash)"


def fetch_yaml(url, timeout=30, retries=2):
    ctx = ssl.create_default_context()
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                text = r.read().decode("utf-8", "replace")
            return yaml.safe_load(text) or {}
        except Exception as e:
            if attempt == retries:
                print(f"fetch_yaml WARN: failed {url}: {e}")
                return None
    return None


def fingerprint(n):
    keys = ("type", "server", "port", "uuid", "password", "cipher", "sni", "servername")
    return "|".join(str(n.get(k, "")) for k in keys)


def valid_node(n):
    if not isinstance(n, dict):
        return False
    for k in ("name", "server", "port", "type"):
        if not n.get(k):
            return False
    if str(n.get("type")) not in ALLOWED_TYPES:
        return False
    name = str(n.get("name", ""))
    if JUNK_RE.search(name):
        return False
    if CN_RE.search(name):
        return False
    srv = str(n.get("server", "")).strip()
    if srv in ("", "0.0.0.0", "127.0.0.1", "localhost"):
        return False
    if not re.match(r"^[\w.\-]+$", srv):
        return False
    return True


def clean_name(prefix, node):
    """Build a short ASCII-only proxy name. Au1rxx names (36332, pure ASCII)
    worked on Shadowrocket for a month; yypool names carry emoji/CJK/#/[] and
    Shadowrocket fails to update. Name = prefix + type + server + md5(original)
    so it is unique, stable and contains no non-ASCII characters."""
    import hashlib
    raw = str(node.get("name", ""))
    srv = re.sub(r"[^A-Za-z0-9]", "", str(node.get("server", "")))[:24]
    tag = str(node.get("type", "p"))[:6]
    h = hashlib.md5(raw.encode("utf-8", "replace")).hexdigest()[:8]
    return f"{prefix}{tag}-{srv}-{h}"


def sanitize_node(node):
    """Strip fields/modes Shadowrocket cannot parse. Return None if unusable."""
    t = str(node.get("type"))
    allowed = ALLOWED_FIELDS.get(t)
    if not allowed:
        return None
    net = str(node.get("network", "tcp"))
    if net not in ALLOWED_NETWORKS:
        return None
    clean = {k: v for k, v in node.items() if k in allowed}
    # tcp is the implicit default in Clash; emitting network:tcp is harmless but
    # keep only if present to avoid altering behavior.
    if net != "tcp":
        clean["network"] = net
    else:
        clean.pop("network", None)
    for parent, subfields in (("ws-opts", ALLOWED_WS_FIELDS),
                              ("reality-opts", ALLOWED_REALITY_FIELDS),
                              ("grpc-opts", ALLOWED_GRPC_FIELDS)):
        sub = clean.get(parent)
        if isinstance(sub, dict):
            clean[parent] = {k: v for k, v in sub.items() if k in subfields}
    return clean


def collect_flat(srcs=None):
    """Aggregate a fresh, prefixed, de-duplicated flat node list for all clients."""
    if srcs is None:
        srcs = SOURCES
    flat = []
    seen = set()
    for src in srcs:
        doc = fetch_yaml(src["url"])
        if not doc:
            print(f"collect_flat: source {src['id']} unavailable, skipped")
            continue
        nodes = doc.get("proxies") or []
        if not isinstance(nodes, list):
            continue
        taken = 0
        for n in nodes:
            if taken >= src["take"]:
                break
            if not valid_node(n):
                continue
            node = dict(n)
            node["name"] = clean_name(src["prefix"], node)
            node = sanitize_node(node)
            if not node:
                continue
            fp = fingerprint(node)
            if fp in seen:
                continue
            seen.add(fp)
            flat.append(node)
            taken += 1
        print(f"collect_flat: {src['id']} -> added {taken} (prefix {src['prefix']})")
    return flat


def load_previous_nodes(path, max_nodes=MAX_PREVIOUS_NODES):
    """Load up to max_nodes nodes from the previous published profile.

    The previous profile's proxies are already clean_name'd ASCII nodes, so the
    first one is exactly the node that was default-selected last run -- keeping
    it pinned (when still alive) is what makes the user's active connection
    survive a subscription refresh.
    """
    if not path.is_file():
        return []
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    out = []
    seen = set()
    for n in (doc or {}).get("proxies") or []:
        if not isinstance(n, dict):
            continue
        fp = fingerprint(n)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(n)
        if len(out) >= max_nodes:
            break
    return out


class NodeTester:
    """Probe gemini / google_play / google through a real mihomo tunnel.

    A fresh mihomo instance loads the candidate nodes as a TEST select group;
    each node is selected in turn and the three endpoints are fetched through
    the local mixed-port (i.e. traffic genuinely transits the node). No geodata
    is needed because the probe config uses a single MATCH,TEST rule.
    """

    def __init__(self, binary):
        self.binary = binary
        self.proc = None
        self.tmp = None
        self.proxy_port = None
        self.controller_port = None
        self._log = None
        self.session = requests.Session()

    @staticmethod
    def _alloc_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
        finally:
            s.close()

    def start(self, nodes):
        names = []
        proxies = []
        for i, node in enumerate(nodes):
            name = f"P{i:03d}"
            names.append(name)
            p = dict(node)
            p["name"] = name
            proxies.append(p)
        self.controller_port = self._alloc_port()
        self.proxy_port = self._alloc_port()
        config = {
            "mixed-port": self.proxy_port,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "error",
            "external-controller": f"127.0.0.1:{self.controller_port}",
            "proxies": proxies,
            "proxy-groups": [{"name": "TEST", "type": "select", "proxies": names}],
            "rules": ["MATCH,TEST"],
        }
        self.tmp = Path(tempfile.mkdtemp(prefix="fc-probe-"))
        (self.tmp / "config.yaml").write_text(
            yaml.safe_dump(config, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        self._log = open(self.tmp / "mihomo.log", "w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [self.binary, "-d", str(self.tmp)],
            stdout=self._log, stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self._log.flush()
                detail = (self.tmp / "mihomo.log").read_text(
                    encoding="utf-8", errors="replace")[-2000:]
                raise RuntimeError(f"mihomo exited during probe startup: {detail}")
            try:
                self.session.get(
                    f"http://127.0.0.1:{self.controller_port}/proxies/TEST",
                    timeout=1,
                ).raise_for_status()
                break
            except requests.RequestException:
                time.sleep(0.2)
        else:
            raise RuntimeError("mihomo controller not ready")
        return names

    def choose(self, name):
        self.session.put(
            f"http://127.0.0.1:{self.controller_port}/proxies/TEST",
            json={"name": name}, timeout=5,
        ).raise_for_status()
        time.sleep(PROBE_SWITCH_WAIT_SECONDS)

    def request(self, url):
        proxy = {
            "http": f"http://127.0.0.1:{self.proxy_port}",
            "https": f"http://127.0.0.1:{self.proxy_port}",
        }
        try:
            r = self.session.get(
                url, proxies=proxy, timeout=PROBE_TIMEOUT_SECONDS,
                headers={"User-Agent": UA}, allow_redirects=True,
            )
            if r.status_code not in PROBE_SUCCESS_STATUSES:
                return False
            final_url = (r.url or "").lower()
            if "sorry" in final_url or "/sorry" in final_url:
                return False
            text = r.text[:5000].lower()
            for marker in PROBE_CHALLENGE_MARKERS:
                if marker in text:
                    return False
            return True
        except requests.RequestException:
            return False

    def test_nodes(self, nodes):
        """Return {fingerprint: {"gemini":bool,"google_play":bool,"google":bool}}."""
        if not nodes:
            return {}
        try:
            names = self.start(nodes)
        except RuntimeError as exc:
            # A malformed proxy can make mihomo fail to load the whole batch's
            # TEST group. Isolate the bad node(s) by splitting instead of
            # dropping the entire batch.
            self.stop()
            if len(nodes) <= 1:
                print(f"NodeTester: node skipped ({exc})")
                return {}
            mid = len(nodes) // 2
            left = self.test_nodes(nodes[:mid])
            right = self.test_nodes(nodes[mid:])
            return {**left, **right}
        out = {}
        try:
            for node, name in zip(nodes, names):
                self.choose(name)
                with ThreadPoolExecutor(max_workers=3) as ex:
                    futures = [ex.submit(self.request, url) for url in PROBE_URLS.values()]
                    gemini, play, google = (f.result() for f in futures)
                out[fingerprint(node)] = {
                    "gemini": gemini, "google_play": play, "google": google,
                }
            return out
        finally:
            self.stop()

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
        if self._log is not None:
            try:
                self._log.close()
            except Exception:
                pass
            self._log = None
        if self.tmp is not None:
            shutil.rmtree(self.tmp, ignore_errors=True)
            self.tmp = None


def probe_nodes(nodes, binary):
    """Probe nodes in parallel worker batches; return {fp: result}."""
    nodes = list(nodes)
    if not nodes:
        return {}
    workers = max(1, min(PROBE_WORKERS, len(nodes)))
    batches = [nodes[i::workers] for i in range(workers) if nodes[i::workers]]
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(NodeTester(binary).test_nodes, batch) for batch in batches]
        for fut in futures:
            try:
                results.update(fut.result())
            except Exception as exc:
                print(f"probe_nodes: batch failed ({exc})")
    return results


class ShenzhenProbe:
    """TCP-ping a node from a Shenzhen probe (Globalping) to gauge China reach.

    The US CI runner cannot measure GFW-side reachability itself; Globalping's
    Shenzhen probe gives a China-network perspective. Anonymous (no token) works;
    setting GLOBALPING_API_TOKEN raises the rate limit.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Content-Type": "application/json"})
        token = os.getenv("GLOBALPING_API_TOKEN", "").strip()
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        self.base_url = "https://api.globalping.io/v1/measurements"

    def measure(self, node):
        server = str(node.get("server") or "").strip()
        port = node.get("port")
        if not server or not port:
            return {"ok": False, "status": "invalid"}
        payload = {
            "target": server,
            "type": "ping",
            "locations": [{"city": SHENZHEN_CITY, "limit": 1}],
            "measurementOptions": {
                "protocol": "TCP", "port": port, "packets": SHENZHEN_PACKETS,
            },
        }
        try:
            created = self.session.post(self.base_url, json=payload, timeout=15)
            created.raise_for_status()
            mid = created.json().get("id")
            if not mid:
                return {"ok": False, "status": "no-id"}
            deadline = time.monotonic() + SHENZHEN_TIMEOUT_SECONDS
            result = None
            while time.monotonic() < deadline:
                time.sleep(SHENZHEN_POLL_SECONDS)
                polled = self.session.get(f"{self.base_url}/{mid}", timeout=15)
                polled.raise_for_status()
                result = polled.json()
                if result.get("status") != "in-progress":
                    break
            if not result or result.get("status") == "in-progress":
                return {"ok": False, "status": "timeout"}
            for entry in result.get("results", []):
                stats = (entry.get("result") or {}).get("stats") or {}
                avg = stats.get("avg")
                if avg is None:
                    avg = stats.get("average")
                loss = stats.get("loss")
                if avg is not None:
                    return {
                        "ok": True, "status": "ok",
                        "avg_ms": float(avg),
                        "loss_pct": float(loss) if loss is not None else None,
                    }
            return {"ok": False, "status": "no-stats"}
        except (requests.RequestException, ValueError, TypeError):
            return {"ok": False, "status": "error"}


def _sz_usable(result):
    if not result or not result.get("ok"):
        return False
    avg = result.get("avg_ms")
    loss = result.get("loss_pct")
    if avg is None:
        return False
    if avg > SHENZHEN_REJECT_ABOVE_MS:
        return False
    if loss is not None and loss >= SHENZHEN_REJECT_LOSS_PCT:
        return False
    return True


def _probe_score(result):
    s = 0
    if result.get("gemini"):
        s += SCORE_GEMINI
    if result.get("google_play"):
        s += SCORE_PLAY
    if result.get("google"):
        s += SCORE_GOOGLE
    return s


def _probe_alive(result):
    return bool(result) and bool(
        result.get("gemini") or result.get("google_play") or result.get("google")
    )


def rank_nodes(flat):
    """Reorder the flat pool: continuity + Gemini/Play reachability first.

    Order:
      1. previous-profile nodes still alive (retention; the first one is the
         old default-selected -> sticky continuity).
      2. newly probed alive nodes, highest Gemini/Play score first.
      3. everything else (unprobed or dead) in original order.

    This only REORDERS nodes; fields are untouched, so four-client parse
    compatibility is unchanged. If mihomo is unavailable the original order is
    kept (best-effort, never blocks publishing).
    """
    if not flat:
        return flat, {}
    previous = load_previous_nodes(OUT, MAX_PREVIOUS_NODES)
    prev_fps = {fingerprint(n) for n in previous}
    fresh = [n for n in flat if fingerprint(n) not in prev_fps]
    # Sample evenly across sources so every source gets probed (otherwise the
    # first source's nodes fill the whole probe budget and other sources are
    # never counted as alive).
    per_source = {}
    for n in fresh:
        sid = str(n.get("name", "")).split("-")[0]
        per_source.setdefault(sid, []).append(n)
    per_source_limit = max(1, PROBE_TEST_COUNT // max(1, len(per_source)))
    test_fresh = []
    for nodes in per_source.values():
        test_fresh.extend(nodes[:per_source_limit])
    test_set = previous + test_fresh[:PROBE_TEST_COUNT]

    binary = shutil.which("mihomo") or shutil.which("clash")
    if binary:
        try:
            results = probe_nodes(test_set, binary)
        except Exception as exc:
            print(f"rank_nodes: probe failed, keeping original order ({exc})")
            results = {}
    else:
        print("rank_nodes: mihomo binary not found, keeping original order")
        results = {}

    flat_by_fp = {fingerprint(n): n for n in flat}
    # All probed-and-alive nodes (previous + fresh) share one ranking:
    #   (score, is_previous) descending. Score weights Gemini (25) and Google
    #   Play (20) above plain google (20), so Gemini/Play-capable nodes win;
    #   is_previous is the tiebreak so an equal-score previous node stays pinned
    #   (continuity), while a stale previous node that lost Gemini/Play yields
    #   to a fresh one.
    alive = []
    for node in test_set:
        fp = fingerprint(node)
        result = results.get(fp)
        if not _probe_alive(result):
            continue
        alive.append((node, fp in prev_fps, result))
    # China-reachability re-check: the US-side probe above proves "reachable
    # from the US", which does NOT imply "reachable from China behind the GFW"
    # (~4% measured). TCP-ping the top candidates from a Shenzhen probe and rank
    # China-usable nodes first, ordered by Shenzhen ping then Gemini/Play score.
    shenzhen = {}
    if SHENZHEN_ENABLED and alive:
        top = [t[0] for t in alive[:SHENZHEN_TEST_COUNT]]
        try:
            probe = ShenzhenProbe()
            with ThreadPoolExecutor(max_workers=SHENZHEN_WORKERS) as ex:
                futs = {ex.submit(probe.measure, n): n for n in top}
                for fut in as_completed(futs):
                    shenzhen[fingerprint(futs[fut])] = fut.result()
        except Exception as exc:
            print(f"rank_nodes: Shenzhen probe failed ({exc})")
    sz_usable = sum(1 for v in shenzhen.values() if _sz_usable(v))

    def _key(t):
        node, is_prev, result = t
        sz = shenzhen.get(fingerprint(node))
        usable = _sz_usable(sz)
        ping = (sz or {}).get("avg_ms", float("inf"))
        if not isinstance(ping, (int, float)):
            ping = float("inf")
        # usable first; then lower ping; then Gemini/Play score; then previous.
        return (
            0 if usable else 1,
            ping if usable else float("inf"),
            -_probe_score(result),
            not is_prev,
        )

    alive.sort(key=_key)
    ranked_alive = []
    for t in alive:
        cur = flat_by_fp.get(fingerprint(t[0]))
        if cur is not None:
            ranked_alive.append(cur)
    picked_fps = {fingerprint(n) for n in ranked_alive}
    rest = [n for n in flat if fingerprint(n) not in picked_fps]
    ranked = ranked_alive + rest
    alive_by_source = {}
    for n in ranked_alive:
        sid = str(n.get("name", "")).split("-")[0]
        alive_by_source[sid] = alive_by_source.get(sid, 0) + 1
    print(f"rank_nodes: alive_ranked={len(ranked_alive)} "
          f"(previous={sum(1 for t in alive if t[1])}) "
          f"shenzhen_usable={sz_usable}/{len(shenzhen)} "
          f"rest={len(rest)} total={len(ranked)} "
          f"alive_by_source={alive_by_source}")
    return ranked, alive_by_source


def load_fallback_sources():
    """Load persisted fallback sources discovered in previous runs."""
    if not FALLBACK_SOURCES_FILE.is_file():
        return []
    try:
        data = json.loads(FALLBACK_SOURCES_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_fallback_sources(sources):
    FALLBACK_SOURCES_FILE.parent.mkdir(parents=True, exist_ok=True)
    FALLBACK_SOURCES_FILE.write_text(
        json.dumps(sources, ensure_ascii=False, indent=2), encoding="utf-8")


def _repo_yaml_urls(repo):
    branch = repo.get("default_branch") or "main"
    full_name = repo.get("full_name", "")
    paths = [
        f"{branch}/clash.yaml", f"{branch}/sub.yaml", f"{branch}/all.yaml",
        f"{branch}/clash.yml", f"{branch}/output/clash.yaml",
        f"{branch}/subscribe/clash.yaml",
    ]
    return [f"https://raw.githubusercontent.com/{full_name}/{p}" for p in paths]


def discover_fallback(token, max_sources=FALLBACK_MAX_SOURCES):
    """Find replacement sources when the live source count is too low.

    Order: (1) previously verified candidate sources (no token needed),
    (2) GitHub search. Returns entries shaped like SOURCES (id/url/prefix/take)
    so collect_flat can consume them directly.
    """
    found = []
    seen = set()

    # 1. Previously verified candidate sources first (more reliable).
    for src in FALLBACK_CANDIDATE_SOURCES:
        doc = fetch_yaml(src["url"])
        if doc and len(doc.get("proxies") or []) >= 2:
            found.append(dict(src))
            seen.add(src["url"])
            print(f"fallback: candidate source alive {src['url']}")
            if len(found) >= max_sources:
                return found
        else:
            print(f"fallback: candidate source dead {src['url']}")

    # 2. GitHub search tops up.
    if not token:
        print("fallback: no GITHUB_TOKEN, skipping GitHub search")
        return found
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    headers["Authorization"] = f"Bearer {token}"
    cutoff = (datetime.now(timezone.utc) - timedelta(days=14)).date().isoformat()
    for q in FALLBACK_QUERIES:
        try:
            r = requests.get(
                "https://api.github.com/search/repositories",
                params={"q": f"{q} pushed:>={cutoff}", "sort": "stars",
                        "order": "desc", "per_page": 20},
                headers=headers, timeout=20,
            )
            r.raise_for_status()
            items = r.json().get("items", [])
        except requests.RequestException as exc:
            print(f"fallback: search failed ({exc})")
            continue
        for item in items:
            fn = item.get("full_name", "")
            if fn in FALLBACK_EXCLUDE_REPOS:
                continue
            if int(item.get("stargazers_count", 0)) < 20:
                continue
            for url in _repo_yaml_urls(item):
                if url in seen:
                    continue
                seen.add(url)
                doc = fetch_yaml(url)
                if doc and len(doc.get("proxies") or []) >= 2:
                    idx = len(found) + 1
                    found.append({"id": f"fb{idx}", "url": url,
                                  "prefix": f"FB{idx}-", "take": 1000})
                    print(f"fallback: found source {url}")
                    if len(found) >= max_sources:
                        return found
    return found


def build_proxy_groups(flat_names):
    fine_proxies = ["AUTO", "DIRECT"] + flat_names
    return [
        {
            "name": "Fine",
            "type": "select",
            "proxies": fine_proxies,
            "default-selected": flat_names[0] if flat_names else "DIRECT",
        },
        {
            "name": "AUTO",
            "type": "url-test",
            "proxies": flat_names,
            "url": HEALTH_URL,
            "interval": 900,
            "timeout": 8000,
            "tolerance": 250,
            "lazy": True,
            "hidden": True,
        },
    ]


def build_config(flat_nodes):
    flat_names = [n["name"] for n in flat_nodes]
    rules = (LOCAL_IOT_DIRECT + WPS_DIRECT + PRIVATE_DIRECT
             + WECHAT_DIRECT + XIAOMI_DIRECT
             + [f"DOMAIN-SUFFIX,{d},Fine" for d in VIDEO_DOMAINS]
             + [f"DOMAIN-SUFFIX,{d},Fine" for d in STORE_DOMAINS]
             + ["GEOIP,CN,DIRECT"]
             + SUBSCRIPTION_CDN_DIRECT
             + ["MATCH,Fine"])
    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "unified-delay": False,
        "tcp-concurrent": True,
        "profile": {"store-selected": True},
        "proxies": flat_nodes,
        "proxy-groups": build_proxy_groups(flat_names),
        "tun": {"enable": False, "stack": "system", "auto-route": False, "auto-detect-interface": False},
        "dns": {
            "enable": True,
            "ipv6": False,
            "use-hosts": True,
            "enhanced-mode": "redir-host",
            "nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"],
            "nameserver-policy": {
                "+.mi.com": ["223.5.5.5", "119.29.29.29"],
                "+.xiaomi.com": ["223.5.5.5", "119.29.29.29"],
                "+.xiaomi.cn": ["223.5.5.5", "119.29.29.29"],
                "+.mijia.com": ["223.5.5.5", "119.29.29.29"],
                "+.miwifi.com": ["223.5.5.5", "119.29.29.29"],
                "+.miui.com": ["223.5.5.5", "119.29.29.29"],
                "+.weixin.qq.com": ["223.5.5.5", "119.29.29.29"],
                "+.qq.com": ["223.5.5.5", "119.29.29.29"],
                "+.myqcloud.com": ["223.5.5.5", "119.29.29.29"],
                "+.tencentcos.cn": ["223.5.5.5", "119.29.29.29"],
            },
            "fallback": ["https://1.1.1.1/dns-query", "tls://8.8.8.8"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN"},
        },
        "rules": rules,
    }


def main():
    if len(sys.argv) > 1:
        print(f"build_final.py: ignoring legacy arg {sys.argv[1]!r} (no longer used)")
    srcs = SOURCES + load_fallback_sources()
    flat = collect_flat(srcs)
    if not flat:
        print("FATAL: no usable free nodes aggregated from any source; "
              "refusing to overwrite live_clash.yaml.")
        raise SystemExit(1)
    flat, alive_by_source = rank_nodes(flat)
    good_sources = sum(1 for v in alive_by_source.values() if v >= 1)
    if good_sources < FALLBACK_MIN_GOOD_SOURCES:
        token = os.environ.get("GITHUB_TOKEN", "")
        print(f"fallback: only {good_sources} good source(s) "
              f"(< {FALLBACK_MIN_GOOD_SOURCES}), discovering new sources")
        new_sources = discover_fallback(token)
        if new_sources:
            save_fallback_sources(new_sources)
            srcs = SOURCES + load_fallback_sources()
            flat = collect_flat(srcs)
            if flat:
                flat, alive_by_source = rank_nodes(flat)
    config = build_config(flat)
    dumped = yaml.safe_dump(config, allow_unicode=True, sort_keys=False,
                            default_flow_style=False)
    previous_version = 0
    if OUT.is_file():
        try:
            m = re.match(r"^#.*?fine-clash-version:(\d+).*?\n",
                         OUT.read_text(encoding="utf-8"))
            if m:
                previous_version = int(m.group(1))
        except OSError:
            pass
    version = (str(previous_version + 1) if previous_version
               else datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    header = (f"# fine-clash-unified-v4 | fine-clash-version:{version} | "
              f"Fine=free-live-pool | CN->DIRECT | MATCH->Fine | "
              f"schedule-refresh:true | client-urltest:true\n")
    OUT.write_text(header + dumped, encoding="utf-8")
    print(f"written {OUT}: flat={len(config['proxies'])} nodes; "
          f"rules={len(config['rules'])}")


if __name__ == "__main__":
    main()
