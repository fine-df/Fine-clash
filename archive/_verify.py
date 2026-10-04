# -*- coding: utf-8 -*-
from _router_ssh import connect, run

c = connect()
checks = [
    ("running DST head", "head -1 /tmp/ShellCrash/fine_final.yaml"),
    ("running TPL head", "head -1 /data/clash/yamls/config.yaml"),
    ("core PROXY url", "curl -s -m 8 http://127.0.0.1:9999/proxies/PROXY 2>/dev/null | grep -o '\"url\":\"[^\"]*\"' | head -1"),
    ("gemini via 127", "curl -s -m 10 -x http://127.0.0.1:7890 https://gemini.google.com/ -o /dev/null -w 'http=%{http_code}'"),
    ("google204 via 127", "curl -s -m 10 -x http://127.0.0.1:7890 https://www.google.com/generate_204 -o /dev/null -w 'http=%{http_code}'"),
    ("trigger sync (expect keep_local)", "ash /data/clash/fine_sync.sh 2>&1 | tail -4"),
    ("post-sync DST head", "head -1 /tmp/ShellCrash/fine_final.yaml"),
    ("post-sync gemini via 127", "curl -s -m 10 -x http://127.0.0.1:7890 https://gemini.google.com/ -o /dev/null -w 'http=%{http_code}'"),
]
for name, t in checks:
    rc, o, e = run(c, t, timeout=90)
    print("### %s (rc=%s)" % (name, rc))
    print((o.strip() or e.strip())[:400])
    print()
c.close()
