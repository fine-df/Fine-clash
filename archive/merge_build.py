# -*- coding: utf-8 -*-
"""合并：融合版分流规则(fine_final) + 路由器壳(端口/控制器/tun/dns)。
只动 proxy-groups / rules / proxies（分流逻辑），其余壳保留路由器验证过的。
"""
import sys, io, warnings, yaml
warnings.filterwarnings("ignore")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

fine = yaml.safe_load(open("fine_final.yaml", encoding="utf-8").read())
shell = yaml.safe_load(open("router_run.yaml", encoding="utf-8").read())

merged = dict(fine)  # 分流主体：proxies / proxy-groups / rules / mixed-port / allow-lan / mode / dns
# 补路由器壳（fine_final 缺的）
merged["external-controller"] = shell.get("external-controller", ":9999")
merged["secret"] = shell.get("secret", "")
merged["tun"] = shell.get("tun")
merged["dns"] = shell.get("dns")  # 用路由器验证过的 dns 壳
merged["allow-lan"] = True
merged["mode"] = "rule"
# 保留 shell 可能有的其它壳段（profile/experimental 等），fine 未定义时补回
for k in ("profile", "experimental", "interface-name", "routing-mark", "ipv6"):
    if k in shell and k not in merged:
        merged[k] = shell[k]

out = yaml.safe_dump(merged, allow_unicode=True, sort_keys=False)
open("fine_merged.yaml", "w", encoding="utf-8").write(out)

# 自检
print("merged bytes:", len(out))
print("proxies:", len(merged.get("proxies", [])))
print("groups:", [g["name"] for g in merged.get("proxy-groups", [])])
print("rules:", len(merged.get("rules", [])))
print("external-controller:", merged.get("external-controller"))
print("tun.enable:", merged.get("tun", {}).get("enable") if isinstance(merged.get("tun"), dict) else merged.get("tun"))
# 组引用完整性
pnames = {p["name"] for p in merged.get("proxies", [])}
for g in merged.get("proxy-groups", []):
    for ref in g.get("proxies", []):
        if ref not in pnames and ref not in ("DIRECT", "REJECT"):
            print("!! DANGLING in group", g["name"], "->", ref)
print("refcheck done")
