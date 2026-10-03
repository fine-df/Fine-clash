# -*- coding: utf-8 -*-
"""部署融合版到路由器（fail-closed：自检不过不覆盖）。
1) 备份当前 config + cfg  2) base64 推 fine_merged.yaml  3) 路由器端 CrashCore -t 自检
4) 覆盖持久层+运行态  5) Https= 对齐 fine_final 6) stop/start 重启 7) 基础自检
"""
import sys, io, base64, time, warnings
warnings.filterwarnings("ignore")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"d:/repo-tasks/Fine-clash")
from _router_ssh import connect, run

content = io.open("fine_merged.yaml", encoding="utf-8").read()
data = base64.b64encode(content.encode("utf-8"))
print("push size", len(data), "B")


def push(tr, remote):
    chan = tr.open_session()
    chan.settimeout(120)
    chan.exec_command("base64 -d > %s" % remote)
    off = 0
    while off < len(data):
        try:
            n = chan.send(data[off:off + 4096])
        except Exception:
            return False
        if n <= 0:
            time.sleep(0.2)
            continue
        off += n
        while chan.recv_ready():
            chan.recv(65536)
    try:
        chan.shutdown_write()
    except Exception:
        pass
    time.sleep(0.5)
    while chan.recv_ready():
        chan.recv(65536)
    try:
        st = chan.recv_exit_status()
    except Exception:
        st = -1
    chan.close()
    return st == 0


c = connect()
# 1) 备份
ts = time.strftime("%Y%m%d_%H%M%S")
rc, o, e = run(c,
    "cp /data/clash/yamls/config.yaml /data/clash/yamls/config.yaml.bak_fine_%s;"
    "cp /tmp/ShellCrash/config.yaml /tmp/ShellCrash/config.yaml.bak_fine_%s;"
    "cp /data/clash/configs/ShellCrash.cfg /data/clash/configs/ShellCrash.cfg.bak_fine_%s;"
    "echo backup_ok_%s" % (ts, ts, ts, ts), timeout=60)
print("[backup]", o.strip() or e.strip())

# 2) 推送
ok = False
tr = c.get_transport()
for i in range(3):
    try:
        ok = push(tr, "/tmp/_deploy_fine.yaml")
    except Exception as ex:
        print("push", i, type(ex).__name__, str(ex)[:80])
    if ok:
        break
    try:
        c.close()
    except Exception:
        pass
    time.sleep(2)
    c = connect()
    tr = c.get_transport()
print("[push]", "OK" if ok else "FAIL")
if not ok:
    print("PUSH FAIL -> abort, router untouched"); sys.exit(1)

# 3) 路由器端自检（用真实 CrashCore）
BIN = "/tmp/ShellCrash/CrashCore"
rc, o, e = run(c, "%s -t -d /data/clash -f /tmp/_deploy_fine.yaml 2>&1 | tail -4" % BIN, timeout=120)
out = (o + e)
print("[selftest]", out.strip()[:400])
if "test is successful" not in out:
    print("SELFTEST FAIL -> abort, no change applied to router")
    run(c, "rm -f /tmp/_deploy_fine.yaml", timeout=30)
    sys.exit(1)

# 4) 覆盖持久层 + 运行态
rc, o, e = run(c,
    "cp /tmp/_deploy_fine.yaml /data/clash/yamls/config.yaml && "
    "cp /tmp/_deploy_fine.yaml /tmp/ShellCrash/config.yaml && "
    "rm -f /tmp/_deploy_fine.yaml && echo applied", timeout=60)
print("[apply]", o.strip() or e.strip())

# 5) Https= 对齐 fine_final（core_config 已存在，bfstart 不会重下载，仅语义对齐）
rc, o, e = run(c,
    "sed -i \"s#^Https=.*#Https='https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/fine_final.yaml'#\" "
    "/data/clash/configs/ShellCrash.cfg; grep '^Https=' /data/clash/configs/ShellCrash.cfg", timeout=60)
print("[Https]", o.strip() or e.strip())

# 6) 重启
rc, o, e = run(c, "/data/clash/start.sh stop 2>&1 | tail -1; echo stopped", timeout=120)
print("[stop]", o.strip()[:80])
c.close()
time.sleep(6)
c = connect()
rc, o, e = run(c, "/data/clash/start.sh start 2>&1 | tail -2; echo started", timeout=200)
print("[start]", o.strip()[:150])
c.close()
time.sleep(30)

# 7) 基础自检
c = connect()
rc, o, e = run(c, "pidof CrashCore; echo '---proxies---'; curl -s -m8 http://127.0.0.1:9999/proxies | tr ',' '\\n' | grep -E '\"name\"|Bitz|Fine|节点选择' | head -8", timeout=80)
print("[verify]", o.strip()[:600])
c.close()
