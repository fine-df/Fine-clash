# -*- coding: utf-8 -*-
"""把路由器订阅切到 live_clash.yaml（四端统一分流版）。
策略：SFTP 直推本地已校验分流版到持久层，绕开 jsDelivr 边缘缓存不一致。
fail-closed：先备份 + 路由器端 CrashCore -t 自检通过才重启。
"""
import sys, time, warnings, os
warnings.filterwarnings("ignore")
sys.path.insert(0, "d:/repo-tasks/Fine-clash")
from _router_ssh import connect, run, put

TS = time.strftime("%Y%m%d_%H%M%S")
LOCAL = "d:/Documents/WorkBuddy/2026-10-01-08-06-53/Fine-clash/live_clash.yaml"
PERSIST = "/data/clash/yamls/config.yaml"
CFG = "/data/clash/configs/ShellCrash.cfg"
BIN = "/data/clash/CrashCore"
# @commit 固定版本：绕过 @main 边缘缓存不一致，保证路由器拿到与 PC 验证一致的版本
COMMIT = "526a452"
PINNED = f"https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@{COMMIT}/live_clash.yaml"
c = connect(timeout=12)

def step(label, cmd, timeout=60):
    rc, out, err = run(c, cmd, timeout=timeout)
    print(f"[{label}] rc={rc}")
    if out.strip():
        print(out.strip()[:1400])
    return rc, out, err

# 1) 备份
step("1.backup", f"cp {CFG} {CFG}.bak_live_{TS}; cp {PERSIST} {PERSIST}.bak_live_{TS} 2>/dev/null; echo backed")
# 2) Https= 指向 live_clash（用户要的 @main 统一链接；将来自动重拉也用它）
step("2.sed-Https", "sed -i 's#fine_final.yaml#live_clash.yaml#' " + CFG)
step("2.verify-Https", "grep '^Https=' " + CFG)
# 3) 路由器用 @commit 固定版本拉取（规避 @main 边缘缓存不一致）
step("3.curl-config", f"curl -s -m 40 '{PINNED}' -o {PERSIST}; echo size=$(wc -c < {PERSIST})")
rc, out, _ = step("3.verify-content", f"grep -cE '^- name: (Bitz|Fine|GLOBAL)' {PERSIST}")
if out.strip() == "0" or rc != 0:
    print("!! 拉到的不是分流版（无 Bitz/Fine/GLOBAL），回滚并中止")
    step("rollback", f"cp {CFG}.bak_live_{TS} {CFG}; cp {PERSIST}.bak_live_{TS} {PERSIST} 2>/dev/null; echo rolled")
    sys.exit(1)
# 4) 路由器端校验（-d /data/clash 避开只读 /root/.config）
rc, out, _ = step("4.CrashCore-t", f"{BIN} -t -f {PERSIST} -d /data/clash 2>&1 | tail -3", timeout=40)
if "test is successful" not in out:
    print("!! 校验失败，回滚并中止")
    step("rollback", f"cp {CFG}.bak_live_{TS} {CFG}; cp {PERSIST}.bak_live_{TS} {PERSIST} 2>/dev/null; echo rolled")
    sys.exit(1)
# 5) 杀旧 + 重启
step("5.kill", "kill -9 $(pidof CrashCore) 2>/dev/null; sleep 2; echo killed")
step("5.restart", "/bin/ash /data/clash/dual_start.sh >/dev/null 2>&1 & echo restarted")
time.sleep(7)
# 6) 验证
step("6.pid", "ps w | grep -v grep | grep CrashCore | head -1")
step("6.groups", "curl -s -m 5 http://127.0.0.1:9999/proxies | grep -oE '\"name\":\"(Bitz|Fine|GLOBAL|🚀[^\"]+)\"'")
print("DEPLOY_DONE")
