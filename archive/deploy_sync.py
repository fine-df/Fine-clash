# -*- coding: utf-8 -*-
"""路由器部署：上传 fine_sync.sh + 安装 crontab（每 15 分钟同步订阅）。"""
import sys, io, os, time, warnings
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"d:/repo-tasks/Fine-clash")
import paramiko
from _router_ssh import connect, run, HOST, PORT, USER, PASSWORD

paramiko.Transport._disabled_algorithms = {"kex": (), "cipher": (), "mac": (), "hostkey": ()}


def conn(tries=5):
    last = None
    for i in range(tries):
        try:
            return connect(timeout=15)
        except Exception as ex:
            last = ex
            print("connect retry", i, type(ex).__name__, str(ex)[:80])
            time.sleep(3)
    raise last


def sftp_put(c, local, remote, tries=3):
    """dropbear 的 sftp 子系统会 EOF，改用 base64 经 stdin 分块写入（历史验证可行）。"""
    import base64
    data = base64.b64encode(open(local, "rb").read())
    for i in range(tries):
        try:
            chan = c.get_transport().open_session()
            chan.settimeout(120)
            chan.exec_command("base64 -d > %s" % remote)
            off = 0
            while off < len(data):
                n = chan.send(data[off:off + 4096])
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
                rc = chan.recv_exit_status()
            except Exception:
                rc = -1
            chan.close()
            if rc == 0:
                return True
            print("scp rc", rc)
        except Exception as ex:
            print("scp retry", i, type(ex).__name__, str(ex)[:80])
            time.sleep(2)
    return False


LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_fine_sync.sh")
c = conn()
ok = sftp_put(c, LOCAL, "/data/clash/fine_sync.sh")
print("[upload]", ok)
if ok:
    rc, o, e = run(c, "chmod +x /data/clash/fine_sync.sh && ls -l /data/clash/fine_sync.sh && sh -n /data/clash/fine_sync.sh && echo syntax_ok", timeout=60)
    print("[chmod]", o.strip()[:300], e[:200])

cron = "*/15 * * * * /bin/ash /data/clash/fine_sync.sh >/dev/null 2>&1 #Fine订阅自动同步(jsDelivr)"
rc, o, e = run(c,
               "grep -v 'fine_sync\\.sh' /etc/crontabs/root 2>/dev/null > /tmp/_cron.new; echo '%s' >> /tmp/_cron.new; crontab /tmp/_cron.new 2>&1; crontab -l; rm -f /tmp/_cron.new" % cron,
               timeout=90)
print("[crontab]\n", o.strip()[:800])
c.close()
