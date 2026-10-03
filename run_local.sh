#!/usr/bin/env bash
# 本地运行完整管线（发现+实测+发布），复用仓库 fine_clash.py。
# 需要本地 mihomo 二进制（d:/Program Files/mihomo/mihomo.exe）与 geo 数据。
set -e
export PATH="/d/Program Files/mihomo:$PATH"
export MIHOMO_GEO_DIR="/d/Program Files/mihomo/geo"
cd "/d/repo-tasks/Fine-clash"
PY="C:/Users/Administrator/.workbuddy/binaries/python/envs/fineclash/Scripts/python.exe"
echo "== which mihomo =="; which mihomo
echo "== run discovery+test+publish =="
"$PY" fine_clash.py run
echo "== build final 4-group =="
"$PY" build_final.py live_clash.yaml
echo "== mirror + deploy =="
cp live_clash.yaml fine_final.yaml
"$PY" _deploy_cfg.py
echo "DONE"
