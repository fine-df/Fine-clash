# -*- coding: utf-8 -*-
"""通用：把本地文件经 base64 流式推上路由器（避开老 dropbear 的 SFTP 协商失败 + 超长参数冲断）。"""
import sys, io, time, base64, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, r"d:/repo-tasks/Fine-clash")
from _router_ssh import connect, run

local = sys.argv[1]
remote = sys.argv[2]
content = io.open(local, encoding="utf-8").read()
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


c = connect()
tr = c.get_transport()
ok = push(tr, remote)
print("[push]", local, "->", remote, "OK" if ok else "FAIL")
if ok:
    rc, o, e = run(c, "chmod +x %s; ash -n %s && echo SYNTAX_OK; wc -l %s" % (remote, remote, remote), timeout=40)
    print(rc, (o.strip() or e.strip())[:300])
c.close()
