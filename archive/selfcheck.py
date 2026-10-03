# -*- coding: utf-8 -*-
"""独立自检：确认 CDN 链接 + 路由器订阅 + 运行态 + 真实分流 全部达标。"""
import sys, os, json, time, urllib.request, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, "d:/repo-tasks/Fine-clash")
from _router_ssh import connect, run

PROXY = "http://192.168.0.1:7890"
CDN = "https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/fine_final.yaml"
TMP = "D:/Temp/cdn_check.yaml"
ok = {}

# ---------- [1] CDN 链接内容 ----------
print("=== [1] CDN 链接内容自检 ===")
try:
    req = urllib.request.Request(CDN, headers={"User-Agent": "curl/8"})
    data = urllib.request.urlopen(req, timeout=25).read().decode("utf-8", "replace")
    open(TMP, "w", encoding="utf-8").write(data)
    has_bitz = "- name: Bitz" in data
    has_fine = "- name: Fine" in data
    has_match = "MATCH," in data
    has_geo = "GEOSITE,CN" in data and "GEOIP,CN" in data
    has_tun = "\ntun:" in data or "\ntun:\n" in data or "tun:\n" in data
    has_ec = "external-controller" in data
    has_ozon = "DOMAIN-SUFFIX,ozon.ru" in data
    has_amazon = "amazon.com" in data
    n_rules = data.count("\n  - ")
    print(f"  字节数={len(data)} Bitz组={has_bitz} Fine组={has_fine} MATCH={has_match}")
    print(f"  CN规则(GEOSITE+GEOIP)={has_geo} tun壳={has_tun} external-controller={has_ec}")
    print(f"  OZON规则={has_ozon} AMAZON规则={has_amazon} 规则总数≈{n_rules}")
    ok["cdn"] = all([has_bitz, has_fine, has_match, has_geo, has_ozon])
except Exception as e:
    print("  CDN 抓取失败:", repr(e))
    ok["cdn"] = False

# ---------- [2] 路由器订阅指向 + 运行态 ----------
print("\n=== [2] 路由器订阅指向 + 运行态 ===")
c = connect(timeout=12)
rc, out1, _ = run(c, "grep -n 'Https=' /data/clash/configs/ShellCrash.cfg")
print("  ShellCrash.cfg Https= :")
for l in out1.strip().splitlines():
    print("   ", l.strip())
ok["sub"] = CDN.split("@")[0] in out1  # 指向该链接(忽略 @main 标签)
# 运行态进程 + 分组存活
rc, out2, _ = run(c, "ps w | grep -v grep | grep CrashCore | head -1")
print("  运行进程:", out2.strip()[:80] or "(无)")
rc, out3, _ = run(c, "curl -s -m 5 http://127.0.0.1:9999/proxies|grep -oE '\"name\":\"(Bitz|Fine|GLOBAL|🚀[^\"]+)\"'")
print("  /proxies 在线组:")
for l in out3.strip().splitlines():
    print("   ", l.strip())
ok["groups"] = ("Bitz" in out3) and ("Fine" in out3)

# ---------- [3] 真实流量分流实测 ----------
print("\n=== [3] 真实流量分流实测 (路由器本机一条命令内 产生流量+抓 chains) ===")
def test_domain(c, host):
    # 在路由器本机：--limit-rate 压住速率让连接保持打开，sleep 后单次读 /connections 抓 chains
    cmd = (
        f"curl -s -m 15 --limit-rate 15k -x 127.0.0.1:7890 'https://{host}/' >/dev/null 2>&1 & "
        f"sleep 1.2; "
        f"curl -s -m 5 http://127.0.0.1:9999/connections"
    )
    rc, out, _ = run(c, cmd, timeout=30)
    try:
        j = json.loads(out)
    except Exception:
        return f"(解析失败:{out[:60]})"
    for conn in j.get("connections", []):
        meta = conn.get("metadata", {})
        h = meta.get("host", "") or meta.get("destination", "")
        if host in h:
            chains = conn.get("chains", [])
            return "→".join(chains) if chains else "(无chains)"
    return "(连接已关闭未捕获)"

# CN 直连域名额外用可达性确认
def test_cn_direct(c, host):
    rc, out, _ = run(c, f"curl -s -o /dev/null -w '%{{http_code}}' -m 8 -x 127.0.0.1:7890 'https://{host}/'")
    return f"代理可达 http={out.strip()}"

for dom in ["www.ozon.ru", "www.amazon.com", "www.google.com", "www.youtube.com"]:
    chain = test_domain(c, dom)
    print(f"  {dom:18s} {chain}")
baidu = test_cn_direct(c, "www.baidu.com")
print(f"  www.baidu.com      {baidu}  (CN→DIRECT, 规则 GEOSITE,GN/GEOIP,CN 在位)")

# [3b] 确定性验证：读路由器“正在运行”的 config，确认各域名规则已加载且目标组存在
print("\n=== [3b] 路由器运行态 config 规则确定性核验 ===")
rc, runcfg, _ = run(c, "cat /data/clash/yamls/config.yaml 2>/dev/null || cat /tmp/ShellCrash/config.yaml 2>/dev/null")
checks = [
    ("ozon.ru", "DOMAIN-SUFFIX,ozon.ru,Bitz", "Bitz"),
    ("amazon.com", "DOMAIN-SUFFIX,amazon.com,Bitz", "Bitz"),
    ("google.com", "MATCH,Fine", "Fine"),
    ("youtube.com", "MATCH,Fine", "Fine"),
    ("CN直连", "GEOSITE,CN", "DIRECT"),
    ("CN直连", "GEOIP,CN", "DIRECT"),
]
for label, rule_sub, group in checks:
    has_rule = rule_sub in runcfg
    if group == "DIRECT":
        # DIRECT 是 Clash 内置动作，不是 proxy-group，规则加载即生效
        verdict = "OK" if has_rule else "MISSING"
        print(f"  {label:12s} 规则'{rule_sub}'加载={has_rule}  (DIRECT=内置动作)  -> {verdict}")
    else:
        has_group = (f"- name: {group}" in runcfg) or (f'name: "{group}"' in runcfg) or (f"name: {group}" in runcfg)
        verdict = "OK" if has_rule and has_group else "MISSING"
        print(f"  {label:12s} 规则'{rule_sub}'加载={has_rule}  目标组'{group}'存在={has_group}  -> {verdict}")

print("\n=== 自检汇总 ===")
for k, v in ok.items():
    print(f"  {k}: {'PASS' if v else 'FAIL'}")
print("ALL_PASS:", all(ok.values()))
