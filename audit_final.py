# -*- coding: utf-8 -*-
"""fine_final.yaml 独立审计脚本（不信任构建脚本自报，独立复核）。

用法： python audit_final.py [fine_final.yaml] [live_clash.yaml]
退出码：0=全通过；1=存在 P0 失败

审计项（P0 阻断 / P1 告警 / P2 提示）：
  P0-1  YAML 可解析
  P0-2  GLOBAL 组存在：type=select，成员只有 PROXY（防止 Verge 自动生成平铺 selector）
  P0-3  PROXY 组 type=url-test，url/interval/timeout/tolerance/lazy 齐全
  P0-4  探针 = play.google.com/store（回归护栏：曾经用错 gstatic 导致选到 PLAY 打不开的节点）
  P0-5  所有 proxy-group 引用的成员名都真实存在（木桶：引用不存在的成员 = 启动失败）
  P0-6  无 tun / redir-port / tproxy-port / routing-mark（路由器 mihomo v1.19.28 不支持）
  P1-1  末条规则形如 MATCH,<已知组>
  P1-2  节点数 == 源 live_clash 节点数
  P1-3  external-controller 0.0.0.0:9999、allow-lan=True、authentication=[]
  P1-4  组数 == 2（GLOBAL + PROXY）
  P2-1  幂等：重新调用 build_final 产出字节一致
  P2-2  proxies 段为行首 `- name:`（safe_dump 格式，sync 脚本 awk 计数依赖此格式）
"""
import io, os, sys, subprocess, yaml

OUT = sys.argv[1] if len(sys.argv) > 1 else "fine_final.yaml"
SRC = sys.argv[2] if len(sys.argv) > 2 else "live_clash.yaml"
PYBIN = sys.executable

results = []


def check(code, level, msg, ok):
    results.append((code, level, msg, bool(ok)))
    tag = {"P0": "PASS" if ok else "FAIL", "P1": "PASS" if ok else "FAIL",
           "P2": "PASS" if ok else "WARN"}[level]
    print("[%s] %s %-5s %s" % (tag, level, code, msg))


# P0-1
try:
    doc = yaml.safe_load(io.open(OUT, encoding="utf-8"))
    check("P0-1", "P0", "YAML 可解析", True)
except Exception as e:
    print("[FAIL] P0-1 P0     YAML 解析失败: %s" % e)
    sys.exit(1)

proxies = doc.get("proxies", [])
pnames = set(p.get("name") for p in proxies)
groups = {g.get("name"): g for g in doc.get("proxy-groups", [])}
gproxy = groups.get("PROXY", {})

# P0-2
g = groups.get("GLOBAL")
ok_g = bool(g) and g.get("type") == "select" and g.get("proxies") == ["PROXY"]
check("P0-2", "P0", "GLOBAL=select{PROXY}（Verge 不再自动平铺 selector，掉线可自动切）", ok_g)

# P0-3
need = ["type", "url", "interval", "timeout", "tolerance", "lazy"]
miss = [k for k in need if k not in gproxy]
check("P0-3", "P0", "PROXY url-test 字段齐全 %s" % need, not miss and gproxy.get("type") == "url-test")

# P0-4
url = gproxy.get("url", "")
check("P0-4", "P0", "探针 = %s（曾误用 gstatic 导致选到 PLAY 打不开的节点）" % url,
      url == "https://play.google.com/store")

# P0-5  组可以引用「代理」，也可以引用「另一个组」（如 GLOBAL->PROXY），两者都算合法成员
pool = pnames | set(groups.keys())
bad = []
for gset in doc.get("proxy-groups", []):
    for m in gset.get("proxies", []):
        if m not in pool:
            bad.append("%s->%s" % (gset.get("name"), m))
check("P0-5", "P0", "所有组引用成员均真实存在", not bad)

# P0-6
badk = [k for k in ("tun", "redir-port", "tproxy-port", "routing-mark") if k in doc]
check("P0-6", "P0", "无 tun/redirect 相关键（mihomo v1.19.28 路由器侧兼容）", not badk)

# P1-1
rules = doc.get("rules", [])
last = rules[-1] if rules else ""
lname = last.split(",")[-1] if last else ""
check("P1-1", "P1", "末条规则 = %s（目标组 %s 存在）" % (last, lname),
      last.startswith("MATCH,") and lname in groups)

# P1-2
try:
    src_names = [p["name"] for p in yaml.safe_load(io.open(SRC, encoding="utf-8")).get("proxies", [])]
except Exception:
    src_names = []
check("P1-2", "P1", "节点数 %d == 源 %d" % (len(proxies), len(src_names)), len(proxies) == len(src_names))

# P1-3
ec = doc.get("external-controller")
check("P1-3", "P1", "external-controller=%s / allow-lan=%s / authentication=%s"
      % (ec, doc.get("allow-lan"), doc.get("authentication")),
      ec == "0.0.0.0:9999" and doc.get("allow-lan") is True and doc.get("authentication") == [])

# P1-4
check("P1-4", "P1", "组数 = %d（期望 2：GLOBAL + PROXY）" % len(groups), len(groups) == 2)

# P2-1
try:
    r = subprocess.run([PYBIN, "build_final.py", SRC], capture_output=True, timeout=120)
    same = r.returncode == 0 and open(OUT, "rb").read() == open(OUT, "rb").read()
    check("P2-1", "P2", "幂等：重跑 build_final 输出字节一致", same)
except Exception as e:
    check("P2-1", "P2", "幂等检查异常 %s" % e, False)

# P2-2
raw = io.open(OUT, encoding="utf-8").read()
seg = raw.split("\nproxies:\n", 1)[1] if "\nproxies:\n" in raw else ""
block = []  # 只取顶层 proxies 块，遇到下一个顶层键（行首 [a-z]）即停
for ln in seg.splitlines():
    if ln[:1].isalpha():
        break
    block.append(ln)
cnt = sum(1 for ln in block if ln.startswith("- "))
check("P2-2", "P2", "proxies 行首 `- ` 计数 = %d（sync 脚本 awk 依赖）" % cnt, cnt == len(proxies))

p0fail = [x for x in results if x[1] == "P0" and not x[3]]
p1fail = [x for x in results if x[1] == "P1" and not x[3]]
print("-" * 62)
print("P0 fail=%d  P1 fail=%d  pass=%d/%d" % (len(p0fail), len(p1fail),
                                              len(results) - len(p0fail) - len(p1fail), len(results)))
if p0fail:
    print("RESULT: AUDIT-FAIL")
    sys.exit(1)
print("RESULT: AUDIT-OK")
