#!/bin/ash
# Fine-clash 订阅自动同步（CI 产出 -> jsDelivr -> 路由器）
# 由 deploy_sync.py 部署，crontab 每 15 分钟跑一次
PATH=$PATH:/tmp/ShellCrash:/tmp/ctest:/data/clash/bin
export PATH
BASE="https://%s.jsdelivr.net/gh/fine-df/Fine-clash@main/fine_final.yaml"
EDGES="cdn gcore testingcf"
DST=/tmp/ShellCrash/fine_final.yaml
TPL=/data/clash/yamls/config.yaml
TMP=/tmp/fine_sync.tmp
BIN=/tmp/ShellCrash/CrashCore
[ -x "$BIN" ] || BIN=/tmp/ctest/CrashCore
rm -f "$TMP"
# 多源轮询：三个 jsDelivr 边缘实测路由器都可达（cdn/gcore/testingcf 均 200），
# 主源缓存陈旧时（jsDelivr @main 缓存 s-maxage=43200，最长 ~12h）可以换源兜底。
# 多源轮询 + 取最高版本：jsDelivr @main 多边缘缓存不一致（cdn/gcore/testingcf 各持一份，
# s-maxage=43200 最长 ~12h），且历史上 gcore 边缘曾滞留带 gemini 私货的旧 v4。
# 所以不能「第一个可用就拿下」，而要遍历所有边缘、挑版本号最高的那份做判据。
BEST=""; BESTV=0
for e in $EDGES; do
  u=$(printf "$BASE" "$e")
  h=$(curl -s -m 25 -o "$TMP" -w "%{http_code}" "$u")
  if [ "$h" = "200" ] && grep -q "name: GLOBAL" "$TMP"; then
    V=$(head -1 "$TMP" 2>/dev/null | sed 's/.*fine-override: v//; s/ .*//'); [ -z "$V" ] && V=0
    if [ "$V" -gt "$BESTV" ] 2>/dev/null; then BESTV=$V; BEST="$u"; cp "$TMP" "$TMP.best"; fi
  else
    echo "sync_edge_skip ${e} http=${h}"
  fi
  rm -f "$TMP"
done
if [ -z "$BEST" ]; then
  echo "sync_skip_stale_cdn_all_edges"
  exit 0
fi
cp "$TMP.best" "$TMP"; rm -f "$TMP.best"
SRC="$BEST"; USED=$(echo "$BEST" | sed 's#.*//##; s#\.jsdelivr.*##')
echo "sync_src=$USED v$BESTV"
# ★版本单调护栏（2026-10-03 血案根因修复）：
#   旧逻辑「第一个可用边缘就覆盖」+ 仅按 GLOBAL 判新旧 → 本地调过的 v5 play 被 gcore 边缘
#   滞留的 v4 gemini 反复盖回（二者都带 GLOBAL，版本号却相等，旧护栏判不出谁新）。
#   新规则：只接受「CDN 最高版本 严格大于 本地版本」的更新；同版本或更低一律保留本地。
#   bump OVERRIDE_TAG（如 v5→v6）并推 @main 后，CDN 刷新到更高版本才会被 sync 接纳。
DV=$(head -1 "$DST" 2>/dev/null | sed 's/.*fine-override: v//; s/ .*//'); [ -z "$DV" ] && DV=0
if [ "$BESTV" -le "$DV" ] 2>/dev/null; then
  echo "sync_keep_local(cdn=v$BESTV <= local=v$DV)"
  rm -f "$TMP"
  exit 0
fi
# 内容护栏：必须是带 url-test PROXY 组的 mihomo 配置
grep -q "type: url-test" "$TMP" || { echo "sync_fail_content"; rm -f "$TMP"; exit 1; }
grep -q "^proxies:" "$TMP" || { echo "sync_fail_noproxies"; rm -f "$TMP"; exit 1; }
# 节点数下限：CI 若因全源失败而吐出残缺配置，宁可沿用旧配置也不把烂池子灌进路由器
# 注意（踩过两次的坑）：
#  - 别 grep "^  - name:"：build_final.py 用 yaml.safe_dump 重 dump 后，
#    proxies 条目变成 **行首** "- 🇯🇵 Japan | [BL]"（纯字符串列表），该模式恒返回 0；
#  - 也别 grep "^  - "：缩进是 0 不是 2。
# 正解：从第一个顶层 ^proxies: 块内统计行首 "- " 条目数（实测 20 个节点 = 20）。
NPROXY=$(awk '/^proxies:/{f=1;next} /^[a-z]/{f=0} f&&/^- /{c++} END{print c+0}' "$TMP")
[ "$NPROXY" -ge 3 ] || { echo "sync_fail_too_few_nodes=${NPROXY}"; rm -f "$TMP"; exit 1; }
# 格式闸门：只要求「当前格式标记」存在，别把值写死。
#  - tolerance：曾经写死 tolerance: 200，新配置改成 100 后被自己拦死，自动链路静默断掉；
#  - name: GLOBAL 已在上文作为「新版判据」（CDN 旧版没有这一行，会被挡住，本地新版不受影响）。
#  两者都只做"是不是目标格式"的判定，具体可用性交给 CrashCore -t 兜底。
grep -q "tolerance:" "$TMP" || { echo "sync_skip_stale_cdn"; rm -f "$TMP"; exit 0; }
grep -q "name: GLOBAL" "$TMP" || { echo "sync_skip_no_global"; rm -f "$TMP"; exit 0; }
if [ -f "$DST" ] && cmp -s "$TMP" "$DST"; then
  echo "sync_same"
  rm -f "$TMP"
  exit 0
fi
# 先自检，不过就不动线上模板
"$BIN" -t -d /data/clash -f "$TMP" >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "sync_selfcheck_fail"
  rm -f "$TMP"
  exit 1
fi
cp "$TMP" "$DST"
cp "$TMP" "$TPL"
rm -f "$TMP"
echo "sync_updated_tpl_$(date '+%m-%d %H:%M')"
/data/clash/start.sh stop >/dev/null 2>&1
sleep 5
/data/clash/start.sh start >/dev/null 2>&1
echo "sync_restarted"
