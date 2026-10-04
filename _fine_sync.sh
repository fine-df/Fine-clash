#!/bin/ash
# Fine-Clash: router syncs the ONLY public subscription.
PATH=$PATH:/tmp/ShellCrash:/tmp/ctest:/data/clash/bin
export PATH

URL="https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml"
DST="/tmp/ShellCrash/live_clash.yaml"
TPL="/data/clash/yamls/config.yaml"
TMP="/tmp/live_clash.sync"
BIN="/tmp/ShellCrash/CrashCore"
[ -x "$BIN" ] || BIN="/tmp/ctest/CrashCore"

rm -f "$TMP"
HTTP=$(curl -fsS -m 30 -o "$TMP" -w "%{http_code}" "$URL" || true)
if [ "$HTTP" != "200" ]; then
  echo "sync_skip_http_$HTTP"
  rm -f "$TMP"
  exit 0
fi

grep -q '^proxy-providers:' "$TMP" || { echo "sync_fail_no_provider"; rm -f "$TMP"; exit 1; }
grep -q '^  BitzPool:' "$TMP" || { echo "sync_fail_no_bitz_pool"; rm -f "$TMP"; exit 1; }
grep -q '^  - name: Bitz' "$TMP" || { echo "sync_fail_no_bitz_group"; rm -f "$TMP"; exit 1; }
grep -q '^  - name: Fine' "$TMP" || { echo "sync_fail_no_fine_group"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,ozon.ru,Bitz' "$TMP" || { echo "sync_fail_no_ozon_rule"; rm -f "$TMP"; exit 1; }
grep -q 'MATCH,Fine' "$TMP" || { echo "sync_fail_no_match_fine"; rm -f "$TMP"; exit 1; }
grep -q 'GEOIP,CN,DIRECT' "$TMP" || { echo "sync_fail_no_cn_direct"; rm -f "$TMP"; exit 1; }
if grep -Eq 'fine_final.yaml|fine-override:' "$TMP"; then
  echo "sync_fail_obsolete_profile"
  rm -f "$TMP"
  exit 1
fi

"$BIN" -t -d /data/clash -f "$TMP" >/dev/null 2>&1 || {
  echo "sync_selfcheck_fail"
  rm -f "$TMP"
  exit 1
}

if [ -f "$DST" ] && cmp -s "$TMP" "$DST"; then
  echo "sync_same"
  rm -f "$TMP"
  exit 0
fi

cp "$TMP" "$DST"
cp "$TMP" "$TPL"
rm -f "$TMP"
/data/clash/start.sh stop >/dev/null 2>&1
sleep 5
/data/clash/start.sh start >/dev/null 2>&1
echo "sync_updated_$(date '+%m-%d %H:%M')"
