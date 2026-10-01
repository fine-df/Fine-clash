# -*- coding: utf-8 -*-
"""在当前选中节点下实测 PLAY 商店 / GEMINI / gstatic 的真实 HTTP 响应。"""
import sys, io, json, warnings
warnings.filterwarnings("ignore")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"d:/repo-tasks/Fine-clash")
from _router_ssh import connect, run

# 注意：dropbear 对含中文/emoji 的命令行会直接关 channel（Channel closed），
# 所以远程 CMD 一律保持纯 ASCII；组名查询放到本机 API 侧做。
CMD = r'''
echo "--- step1: single hop (no follow) ---"
echo "--- 单跳（不 follow） ---"
curl -s -m 20 -x 127.0.0.1:7890 -o /dev/null -D /tmp/_h.txt -w "code=%{http_code} total=%{time_total}s\n" "https://play.google.com/store"
grep -i -E "^location:|^server:" /tmp/_h.txt | head -3
echo "--- follow redirect（用户真实体验） ---"
curl -sL -m 25 -x 127.0.0.1:7890 -o /dev/null -w "final=%{http_code} url=%{url_effective} total=%{time_total}s\n" "https://play.google.com/store"
echo "--- 其它探针 ---"
for u in https://gemini.google.com/ https://www.gstatic.com/generate_204; do
  printf "%-36s " "$u"
  curl -sL -m 20 -x 127.0.0.1:7890 -o /dev/null -w "code=%{http_code} total=%{time_total}s\n" "$u"
done
echo "--- 直连对照（无代理） ---"
curl -s -m 12 -o /dev/null -w "direct=%{http_code} total=%{time_total}s\n" "https://play.google.com/store"
'''

c = connect()
try:
    print(run(c, CMD, timeout=200)[1])
finally:
    c.close()
