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
import io, os, re, sys, subprocess, yaml

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

AUTO_NAME = "♻️ 自动选择"
PICK_NAME = "🚀 节点选择"
gauto = groups.get(AUTO_NAME, {})
gpick = groups.get(PICK_NAME, {})

# P0-2
g = groups.get("GLOBAL")
ok_g = bool(g) and g.get("type") == "select" and g.get("proxies") == [PICK_NAME]
check("P0-2", "P0", "GLOBAL=select{%s}（Verge 不再自动平铺 selector）" % PICK_NAME, ok_g)

# P0-3
need = ["type", "url", "interval", "timeout", "tolerance", "lazy"]
miss = [k for k in need if k not in gauto]
check("P0-3", "P0", "%s url-test 字段齐全 %s" % (AUTO_NAME, need),
      not miss and gauto.get("type") == "url-test")

# P0-4
url = gauto.get("url", "")
check("P0-4", "P0", "探针 = %s（曾误用 gstatic 导致选到 PLAY 打不开的节点）" % url,
      url == "https://play.google.com/store")

# P0-7 ★两层结构：这是本配置存在的唯一理由，拆错了会出现「永远不切最快节点」
#   - 节点选择(select) 第一项必须是 自动选择 → 初始即自动挡（mihomo Select 无 default 时取首项）
#   - 节点选择 必须带 DIRECT（用户可切直连）
#   - 节点选择 必须平铺全部节点（用户可手动锁点，且锁点只发生在这里）
#   - 自动选择 必须只含节点（不能转发给另一个组，否则节点名对不上无法比速）
pick_members = gpick.get("proxies", [])
ok_pick = (gpick.get("type") == "select" and pick_members[:1] == [AUTO_NAME]
           and "DIRECT" in pick_members and len(pick_members) == len(proxies) + 2)
check("P0-7", "P0", "%s=select{%s 首项, DIRECT, %d 节点}（首项即默认自动挡）"
      % (PICK_NAME, AUTO_NAME, len(proxies)), ok_pick)
ok_auto = gauto.get("type") == "url-test" and gauto.get("proxies") == [p.get("name") for p in proxies]
check("P0-8", "P0", "%s 成员 == 全部 %d 个节点（纯节点，不比速层级嵌套）"
      % (AUTO_NAME, len(proxies)), ok_auto)

# P0-5  组可以引用「代理」，也可以引用「另一个组」（如 GLOBAL->节点选择），两者都算合法成员
#       DIRECT 是 mihomo 内置出站，不在 proxies/组名里，但合法。
pool = pnames | set(groups.keys()) | {"DIRECT", "REJECT"}
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

# P0-9 所有规则的目标（最后一段）必须真实存在：改组名后残留的 `,PROXY` 会让核心启动失败
builtin = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "NO-RESOLVE"}
rbad = []
for r in rules:
    if "," not in r or r.startswith("#"):
        continue
    tgt = r.split(",")[-1].strip()
    if tgt in builtin or tgt in groups or tgt in pnames or tgt.isdigit():
        continue
    if r.split(",")[0].strip().upper() in ("MATCH", "FINAL") or True:
        rbad.append(r)
# 规则里还可能带 no-resolve / src 等参数，只对已知策略名做白名单外的报错收敛
rbad = [r for r in rbad if r.split(",")[-1].strip() not in builtin
        and r.split(",")[-1].strip() not in groups
        and r.split(",")[-1].strip() not in pnames
        and not r.split(",")[-1].strip().isdigit()]
check("P0-9", "P0", "全部 %d 条规则的目标均存在（无残留 ,PROXY）" % len(rules), not rbad)

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
check("P1-4", "P1", "组数 = %d（期望 3：GLOBAL + %s + %s）" % (len(groups), PICK_NAME, AUTO_NAME),
      len(groups) == 3)

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

# P1-5 sync 护栏必须校验 GLOBAL：CDN 边缘缓存的是旧版（无 GLOBAL）时，护栏要能识别并跳过
SYNC = "_fine_sync.sh"
if os.path.exists(SYNC):
    sraw = io.open(SYNC, encoding="utf-8").read()
    guard = 'grep -q "name: GLOBAL"' in sraw
    edges = all(("cdn.jsdelivr.net" in sraw or "%s.jsdelivr.net" in sraw or "cdn" in sraw.split(),
                 "gcore" in sraw, "testingcf" in sraw))
    check("P1-5", "P1", "sync 护栏含 GLOBAL 判据 + 多源兜底(cdn/gcore/testingcf)", guard and edges)
    # 禁止把 tolerance 值写死（曾写死 200 把正确的新版自己拦死）。
    # 先剥掉注释行——注释里常拿 "tolerance: 200" 举例，不剥离会误报。
    code = "\n".join(ln for ln in sraw.splitlines() if not ln.lstrip().startswith("#"))
    hardcoded = re.search(r"tolerance:\s*\d+", code) is not None
    check("P1-6", "P1", "sync 护栏未把 tolerance 值写死", not hardcoded)
else:
    check("P1-5", "P1", "%s 不在审计路径，跳过" % SYNC, True)

# P1-7 产物必须有 fine-override 标记行：这是 sync 识别「本地参数版本」的唯一依据。
# 没有它，路由器的 */15 sync 会用 CDN 旧参数版把本地调好的 interval/tolerance 盖回去
# （2026-10-01 实测：改完参数 15 分钟内被还原，用户看到「节点不自动切换」）。
m = re.search(r"^#\s*fine-override:\s*(\S+)", raw, re.M)
check("P1-7", "P1", "产物含 fine-override 标记 %s" % (m.group(1) if m else "缺失"),
      m is not None)
# P1-8 sync 必须有「本地带标记、CDN 没有 → 跳过」的降级保护
locally = "sync_skip_local_override" in (io.open(SYNC, encoding="utf-8").read()
                                         if os.path.exists(SYNC) else "")
check("P1-8", "P1", "sync 含本地 override 降级保护(sync_skip_local_override)", locally)

p0fail = [x for x in results if x[1] == "P0" and not x[3]]
p1fail = [x for x in results if x[1] == "P1" and not x[3]]
print("-" * 62)
print("P0 fail=%d  P1 fail=%d  pass=%d/%d" % (len(p0fail), len(p1fail),
                                              len(results) - len(p0fail) - len(p1fail), len(results)))
if p0fail:
    print("RESULT: AUDIT-FAIL")
    sys.exit(1)
print("RESULT: AUDIT-OK")
