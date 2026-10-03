# -*- coding: utf-8 -*-
"""盯 PROXY(url-test) 的选点：每轮打印 当前选中 / 该节点延迟 / 全场最小 / 存活数。

★ 关键坑（2026-10-01 踩到）：mihomo 的 `history` 是**追加**的数组，最新一条在**末尾**
  （history[-1]），history[0] 是这一节点最早的一条记录（最多保留 10 条）。
  用 history[0] 判"谁最快"＝拿 10 轮前的数据下结论，会得出"没切到最快节点"的假象。
  这里统一取 history[-1]，并打印该记录的年龄（秒），年龄过大说明该节点本轮没被测。

只读 API，不改任何配置。用法：python monitor_pick.py [样本数] [间隔秒]
"""
import sys, io, time, datetime, warnings
import requests, urllib.parse

warnings.filterwarnings("ignore")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

B = "http://192.168.0.1:9999"
GRP = sys.argv[1] if len(sys.argv) > 1 else "♻️ 自动选择"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 4
GAP = int(sys.argv[3]) if len(sys.argv) > 3 else 60


def latest(node):
    """返回 (delay, age_sec)；无记录返回 (0, -1)。"""
    h = node.get("history") or []
    if not h:
        return 0, -1
    rec = h[-1]
    try:
        t = datetime.datetime.fromisoformat(rec["time"].replace("Z", "+00:00"))
        age = (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds()
    except Exception:
        age = -1
    return rec.get("delay", 0), age


def snap():
    px = requests.get(B + "/proxies/" + urllib.parse.quote(GRP, safe=""), timeout=20).json()
    now = px["now"]
    rows = []
    for n in px["all"]:
        d = requests.get(B + "/proxies/" + urllib.parse.quote(n, safe=""), timeout=12).json()
        delay, age = latest(d)
        rows.append((delay, age, n))
    alive = sorted([r for r in rows if r[0] > 0], key=lambda x: x[0])
    return now, alive


for i in range(N):
    now, alive = snap()
    matched = [(d, a) for d, a, n in alive if n == now]
    fast = alive[0] if alive else (0, -1, "-")
    dsel, asel = matched[0] if matched else (0, -1)
    if not matched:
        verdict = "选中节点本轮无有效测速"
    elif now == fast[2]:
        verdict = "OK 已选中最快"
    else:
        verdict = "偏差 +%dms（最快 %s）" % (dsel - fast[0], fast[2][:26])
    print("t+%3ds 存活=%2d | 选中 %-28s %5sms(age%4ds) | min %5sms %-26s %s"
          % (GAP * (i + 1), len(alive), now[:28], dsel, int(asel), fast[0], fast[2][:26], verdict))
    if i < N - 1:
        time.sleep(GAP)
