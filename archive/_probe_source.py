# -*- coding: utf-8 -*-
"""连路由器，抓 ShellCrash 的订阅源 URL（[BL] 好节点来源）。"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from _router_ssh import connect, run

c = connect()
if not c:
    print("CONNECT_FAIL"); sys.exit(1)

# 搜索订阅地址（避免复杂引号，直接用简单 grep）
cmd = r"grep -rEoh 'https?://[^ ]+' /data/clash 2>/dev/null | sort -u | head -40"
o = run(c, cmd, timeout=15)
print("==== found urls in /data/clash ====")
print(o)
c.close()
