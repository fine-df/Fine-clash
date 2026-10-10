#!/bin/ash
# Fine-Clash: router syncs the ONLY public subscription.
PATH=$PATH:/tmp/ShellCrash:/tmp/ctest:/data/clash/bin
export PATH

URL="https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml"
DST="/tmp/ShellCrash/live_clash.yaml"
ACTIVE="/tmp/ShellCrash/config.yaml"
TPL="/data/clash/yamls/config.yaml"
TMP="/tmp/live_clash.sync"
BACKUP="/tmp/live_clash.template.bak"
BIN="/tmp/ShellCrash/CrashCore"
[ -x "$BIN" ] || BIN="/tmp/ctest/CrashCore"

rm -f "$TMP"
HTTP=$(curl -fsS -m 30 -o "$TMP" -w "%{http_code}" "$URL" || true)
if [ "$HTTP" != "200" ]; then
  echo "sync_fail_http_$HTTP"
  rm -f "$TMP"
  exit 1
fi

grep -q '^mode: rule$' "$TMP" || { echo "sync_fail_not_rule_mode"; rm -f "$TMP"; exit 1; }
# 自 build_final 移除 GLOBAL 内置组后，订阅不再含 GLOBAL（mihomo 运行态会自动生成内置 GLOBAL）
grep -q '^- name: Fine$' "$TMP" || { echo "sync_fail_no_fine_group"; rm -f "$TMP"; exit 1; }
grep -q '^- name: Fine-Auto$' "$TMP" || { echo "sync_fail_no_fine_auto_group"; rm -f "$TMP"; exit 1; }
grep -q '  - Fine-Auto' "$TMP" || { echo "sync_fail_fine_no_auto"; rm -f "$TMP"; exit 1; }
grep -q '  - DIRECT' "$TMP" || { echo "sync_fail_fine_no_direct"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,youtube.com,Fine' "$TMP" || { echo "sync_fail_no_video_rule"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,play.google.com,Fine' "$TMP" || { echo "sync_fail_no_store_rule"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,cn,DIRECT' "$TMP" || { echo "sync_fail_no_cn_rule"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,qq.com,DIRECT' "$TMP" || { echo "sync_fail_no_qq_rule"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,mi.com,DIRECT' "$TMP" || { echo "sync_fail_no_xiaomi_rule"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,wps.cn,DIRECT' "$TMP" || { echo "sync_fail_no_wps_cn_direct"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,wps.com,DIRECT' "$TMP" || { echo "sync_fail_no_wps_com_direct"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,wps365.com,DIRECT' "$TMP" || { echo "sync_fail_no_wps365_com_direct"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,kdocs.cn,DIRECT' "$TMP" || { echo "sync_fail_no_kdocs_direct"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,wpscdn.cn,DIRECT' "$TMP" || { echo "sync_fail_no_wpscdn_cn_direct"; rm -f "$TMP"; exit 1; }
grep -q 'DOMAIN-SUFFIX,wpscdn.com,DIRECT' "$TMP" || { echo "sync_fail_no_wpscdn_com_direct"; rm -f "$TMP"; exit 1; }
grep -q 'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve' "$TMP" || { echo "sync_fail_no_private_lan_rule"; rm -f "$TMP"; exit 1; }
grep -q 'GEOIP,CN,DIRECT' "$TMP" || { echo "sync_fail_no_cn_direct"; rm -f "$TMP"; exit 1; }

# 两种合法布局：Fine-only（默认，公开构建）；或 Fine + Bitz 对称双组（Bitz 兜底其余代理流量）。
# 两种布局都必须保证 MATCH 指向一个真实存在的组，避免落到空组导致断网。
if grep -q '^- name: Bitz$' "$TMP"; then BITZ_LAYOUT=1; else BITZ_LAYOUT=0; fi
if [ "$BITZ_LAYOUT" = 1 ]; then
  grep -q '^- name: Bitz-Auto$' "$TMP" || { echo "sync_fail_no_bitz_auto_group"; rm -f "$TMP"; exit 1; }
  grep -q '  - Bitz-Auto' "$TMP" || { echo "sync_fail_bitz_no_auto"; rm -f "$TMP"; exit 1; }
  grep -q 'MATCH,Bitz' "$TMP" || { echo "sync_fail_no_match_bitz"; rm -f "$TMP"; exit 1; }
  # 节点是内联的，不再有 proxy-provider 段。Bitz 组若没成员，MATCH 会落空组导致全断网。
  MEM=$(awk '/^- name: Bitz$/{f=1;next} /^- name:/{f=0} f&&/^    - /{c++} END{print c+0}' "$TMP")
  [ "$MEM" -ge 4 ] || { echo "sync_fail_empty_bitz_group"; rm -f "$TMP"; exit 1; }
else
  grep -q 'MATCH,Fine' "$TMP" || { echo "sync_fail_no_match_fine"; rm -f "$TMP"; exit 1; }
fi

if grep -Eq 'GEOSITE,' "$TMP"; then
  echo "sync_fail_geosite_dependency"
  rm -f "$TMP"
  exit 1
fi
# proxy-providers 只属于 Bitz 布局；Fine-only 订阅里出现 provider 说明架构回退到废弃版本。
if [ "$BITZ_LAYOUT" = 0 ] && grep -Eq '^proxy-providers:' "$TMP"; then
  echo "sync_fail_obsolete_provider_architecture"
  rm -f "$TMP"
  exit 1
fi
# 硬红线：订阅 URL / 明文 token 不得出现在公开订阅里（2026-10-04 事故后的护栏）。
# 2026-10-07 起 Bitz 走「构建期内联节点」：token 只存在 CI Secret 里，
# 出现在订阅中的是已展开的节点（server/password/uuid）——业主已接受该公开尺度。
if grep -Eq 'cont\.bbkcdpub\.com|token=' "$TMP"; then
  echo "sync_fail_public_profile_contains_token"
  rm -f "$TMP"
  exit 1
fi
if grep -Eq 'fine_final.yaml|fine-override:' "$TMP"; then
  echo "sync_fail_obsolete_profile"
  rm -f "$TMP"
  exit 1
fi

REMOTE_VER=$(sed -n '1s/.*fine-clash-version:\([0-9][0-9]*\).*/\1/p' "$TMP")
LOCAL_VER=$(sed -n '1s/.*fine-clash-version:\([0-9][0-9]*\).*/\1/p' "$DST" 2>/dev/null || true)
REMOTE_VER=${REMOTE_VER:-0}
LOCAL_VER=${LOCAL_VER:-0}
if [ "$REMOTE_VER" = "0" ]; then
  echo "sync_fail_missing_remote_version"
  rm -f "$TMP"
  exit 1
fi

# Count members of a named policy group in either block-list or inline-list YAML.
# Checking total server entries is insufficient: Bitz nodes can mask an empty Fine-Auto.
group_member_count() {
  awk -v wanted="$2" '
    function inline_count(line, rest, left, right, n, items) {
      left=index(line, "[")
      right=index(line, "]")
      if (!left || right <= left) return 0
      rest=substr(line, left+1, right-left-1)
      if (rest ~ /^[[:space:]]*$/) return 0
      n=split(rest, items, ",")
      return n
    }
    /^- name: / { current=($0 == "- name: " wanted); in_proxies=0; next }
    current && index($0, "proxies: [") { count += inline_count($0); in_proxies=0; next }
    current && /^  proxies:[[:space:]]*$/ { in_proxies=1; next }
    current && in_proxies && /^  - / { count++; next }
    current && in_proxies && /^  [^ -][^:]*:/ { in_proxies=0 }
    END { print count+0 }
  ' "$1"
}

runtime_profile_ok() {
  [ -s "$ACTIVE" ] || return 1
  grep -q '^- name: Fine$' "$ACTIVE" || return 1
  grep -q '^- name: Fine-Auto$' "$ACTIVE" || return 1
  grep -Fq 'DOMAIN-SUFFIX,wps.cn,DIRECT' "$ACTIVE" || return 1
  grep -Fq 'DOMAIN-SUFFIX,wps.com,DIRECT' "$ACTIVE" || return 1
  grep -Fq 'DOMAIN-SUFFIX,wps365.com,DIRECT' "$ACTIVE" || return 1
  grep -Fq 'DOMAIN-SUFFIX,kdocs.cn,DIRECT' "$ACTIVE" || return 1
  grep -Fq 'DOMAIN-SUFFIX,wpscdn.cn,DIRECT' "$ACTIVE" || return 1
  grep -Fq 'DOMAIN-SUFFIX,wpscdn.com,DIRECT' "$ACTIVE" || return 1
  REMOTE_FINE_COUNT=$(group_member_count "$TMP" "Fine")
  ACTIVE_FINE_COUNT=$(group_member_count "$ACTIVE" "Fine")
  REMOTE_FINE_AUTO_COUNT=$(group_member_count "$TMP" "Fine-Auto")
  ACTIVE_FINE_AUTO_COUNT=$(group_member_count "$ACTIVE" "Fine-Auto")
  [ "${REMOTE_FINE_AUTO_COUNT:-0}" -gt 0 ] || return 1
  [ "${ACTIVE_FINE_AUTO_COUNT:-0}" -ge "${REMOTE_FINE_AUTO_COUNT:-0}" ] || return 1
  [ "${REMOTE_FINE_COUNT:-0}" -gt 2 ] || return 1
  [ "${ACTIVE_FINE_COUNT:-0}" -ge "${REMOTE_FINE_COUNT:-0}" ] || return 1
  REMOTE_NODE_COUNT=$(grep -c '  server:' "$TMP" 2>/dev/null || true)
  ACTIVE_NODE_COUNT=$(grep -c '  server:' "$ACTIVE" 2>/dev/null || true)
  [ "${REMOTE_NODE_COUNT:-0}" -gt 0 ] && [ "${ACTIVE_NODE_COUNT:-0}" -ge "${REMOTE_NODE_COUNT:-0}" ]
}
if [ "$REMOTE_VER" -le "$LOCAL_VER" ]; then
  if runtime_profile_ok; then
    echo "sync_keep_local_remote_ver_${REMOTE_VER}_local_ver_${LOCAL_VER}"
    rm -f "$TMP"
    exit 0
  fi
  echo "sync_repair_runtime_profile_remote_ver_${REMOTE_VER}_local_ver_${LOCAL_VER}"
  echo "runtime_group_counts remote_Fine=${REMOTE_FINE_COUNT:-0} active_Fine=${ACTIVE_FINE_COUNT:-0} remote_Fine_Auto=${REMOTE_FINE_AUTO_COUNT:-0} active_Fine_Auto=${ACTIVE_FINE_AUTO_COUNT:-0}"
fi

"$BIN" -t -d /data/clash -f "$TMP" >/dev/null 2>&1 || {
  echo "sync_selfcheck_fail"
  rm -f "$TMP"
  exit 1
}

if [ -f "$DST" ] && cmp -s "$TMP" "$DST" && runtime_profile_ok; then
  echo "sync_same"
  rm -f "$TMP"
  exit 0
fi

rm -f "$BACKUP"
if [ -f "$TPL" ]; then
  cp "$TPL" "$BACKUP" || { echo "sync_fail_backup_template"; rm -f "$TMP"; exit 1; }
fi
cp "$TMP" "$TPL" || { echo "sync_fail_write_template"; rm -f "$TMP" "$BACKUP"; exit 1; }
/data/clash/start.sh stop >/dev/null 2>&1
sleep 5
/data/clash/start.sh start >/dev/null 2>&1
sleep 3
if ! runtime_profile_ok; then
  echo "sync_fail_runtime_profile_not_updated"
  echo "runtime_group_counts remote_Fine=${REMOTE_FINE_COUNT:-0} active_Fine=${ACTIVE_FINE_COUNT:-0} remote_Fine_Auto=${REMOTE_FINE_AUTO_COUNT:-0} active_Fine_Auto=${ACTIVE_FINE_AUTO_COUNT:-0}"
  if [ -s "$BACKUP" ]; then
    cp "$BACKUP" "$TPL"
    /data/clash/start.sh stop >/dev/null 2>&1
    sleep 5
    /data/clash/start.sh start >/dev/null 2>&1
  fi
  rm -f "$TMP" "$BACKUP"
  exit 1
fi
cp "$TMP" "$DST" || { echo "sync_fail_save_checkpoint"; rm -f "$TMP" "$BACKUP"; exit 1; }
rm -f "$TMP" "$BACKUP"
echo "sync_updated_$(date '+%m-%d %H:%M')"
