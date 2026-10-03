# -*- coding: utf-8 -*-
"""绕过 jsDelivr 缓存，直接把本地 fine_final.yaml 推上路由器并生效。

背景：jsDelivr 对 GitHub 仓库文件带 s-maxage=43200（12h），commit 后 CDN 仍吐旧版，
端到端会卡在旧配置上。改配置后应：
  1) 本脚本直接推（立刻生效）
  2) _fine_sync.sh 的 tolerance 护栏拦住旧版 CDN，防止 15 分钟后的 sync 把旧版盖回来
  3) CDN 刷新后 sync 自动拉到新版，无需人工
"""
import sys, io, time, base64, warnings
warnings.filterwarnings("ignore")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"d:/repo-tasks/Fine-clash")
from _router_ssh import connect, run

content = io.open("fine_final.yaml", encoding="utf-8").read()
data = base64.b64encode(content.encode("utf-8"))


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
    try:
        while chan.recv_ready():
            chan.recv(65536)
    except Exception:
        pass
    try:
        st = chan.recv_exit_status()
    except Exception:
        st = -1
    chan.close()
    return st == 0


DST = "/tmp/ShellCrash/fine_final.yaml"
TPL = "/data/clash/yamls/config.yaml"

c = connect()
tr = c.get_transport()
ok = False
for i in range(3):
    try:
        ok = push(tr, "/tmp/_deploy_tmp.yaml")
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

cmds = [
    # 自检（用真实存在的 CrashCore）
    "[ -x /tmp/ShellCrash/CrashCore ] && BIN=/tmp/ShellCrash/CrashCore || BIN=/tmp/ctest/CrashCore; "
    "echo BIN=$BIN; $BIN -t -d /data/clash -f /tmp/_deploy_tmp.yaml 2>&1 | sed 's/\\x1b\\[[0-9;]*m//g' | tail -3",
    "grep -c 'tolerance:' /tmp/_deploy_tmp.yaml; grep 'url: https' /tmp/_deploy_tmp.yaml | head -2; echo selfcheck_done",
    # 覆盖运行时文件（路径与 _fine_sync.sh 保持完全一致，避免调度脚本互相覆盖）
    "cp /tmp/_deploy_tmp.yaml %s && cp /tmp/_deploy_tmp.yaml %s && cp /tmp/_deploy_tmp.yaml /tmp/fine_final.yaml && "
    "wc -c %s %s && rm -f /tmp/_deploy_tmp.yaml && echo tpl_copied" % (DST, TPL, DST, TPL),
]
for t in cmds:
    rc, o, e = run(c, t, timeout=180)
    print("=== ", t[:60], "rc", rc)
    print((o.strip() or e.strip()[:200])[:500])

rc, o, e = run(c, "/data/clash/start.sh stop 2>&1 | tail -1; echo stopped", timeout=120)
print("[stop]", o.strip()[:80])
c.close()
time.sleep(6)
c = connect()
rc, o, e = run(c, "/data/clash/start.sh start 2>&1 | tail -2; echo started", timeout=200)
print("[start]", o.strip()[:150])
c.close()
time.sleep(25)
c = connect()
rc, o, e = run(c,
    "curl -s -m 8 http://127.0.0.1:9999/proxies/PROXY | tr ',' '\\n' | grep -E '\"type\"|now|tolerance|url' | head -6; echo",
    timeout=80)
print("[core]", o.strip()[:400])
c.close()
