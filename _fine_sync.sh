#!/bin/ash
# Fine-Clash: router syncs the ONLY public subscription.
PATH=$PATH:/tmp/ShellCrash:/tmp/ctest:/data/clash/bin
export PATH

URLS='https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml
https://testingcf.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml
https://fastly.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml
https://raw.githubusercontent.com/fine-df/Fine-clash/main/live_clash.yaml'
DST="/tmp/ShellCrash/live_clash.yaml"
ACTIVE="/tmp/ShellCrash/config.yaml"
TPL="/data/clash/yamls/config.yaml"
TMP="/tmp/live_clash.sync"
FETCH_BEST="/tmp/live_clash.sync.best"
CURL_ERR="/tmp/live_clash.sync.curl.err"
BACKUP="/tmp/live_clash.template.bak"
BIN="/tmp/ShellCrash/CrashCore"
[ -x "$BIN" ] || BIN="/tmp/ctest/CrashCore"

# Older router curl/PolarSSL builds can fail TLS negotiation with one CDN edge.
# Try several HTTPS mirrors without disabling certificate verification, and choose
# the newest structurally plausible profile returned by any mirror.
rm -f "$TMP" "$FETCH_BEST" "$CURL_ERR"
HTTP=000
BEST_VER=0
BEST_URL=""
for URL in $URLS; do
  rm -f "$TMP" "$CURL_ERR"
  HTTP=$(curl -fsS --connect-timeout 8 -m 15 -o "$TMP" -w "%{http_code}" "$URL" 2>"$CURL_ERR" || true)
  VERSION=$(sed -n '1s/.*fine-clash-version:\([0-9][0-9]*\).*/\1/p' "$TMP" 2>/dev/null || true)
  case "$VERSION" in
    ''|*[!0-9]*)
      echo "sync_fetch_invalid_version_url_$URL"
      ;;
    *)
      if [ "$HTTP" = "200" ] && [ -s "$TMP" ] &&
        [ "$VERSION" -gt 0 ] &&
        grep -q '^mode: rule$' "$TMP" &&
        grep -q '^- name: Fine$' "$TMP" &&
        grep -q '^- name: Fine-Auto$' "$TMP"; then
        echo "sync_fetch_candidate_version_$VERSION from $URL"
        if [ "$VERSION" -gt "$BEST_VER" ]; then
          cp "$TMP" "$FETCH_BEST" || { echo "sync_fail_save_best_mirror"; rm -f "$TMP" "$FETCH_BEST" "$CURL_ERR"; exit 1; }
          BEST_VER="$VERSION"
          BEST_URL="$URL"
        fi
      else
        echo "sync_fetch_reject_response_http_$HTTP url $URL"
      fi
      ;;
  esac
  if [ "$HTTP" != "200" ] || [ ! -s "$TMP" ]; then
    echo "sync_fetch_failed_http_$HTTP url $URL"
    if [ -s "$CURL_ERR" ]; then sed -n '1p' "$CURL_ERR"; fi
  fi
done
if [ ! -s "$FETCH_BEST" ]; then
  echo "sync_fail_all_subscription_urls"
  rm -f "$TMP" "$FETCH_BEST" "$CURL_ERR"
  exit 1
fi
cp "$FETCH_BEST" "$TMP" || { echo "sync_fail_restore_best_mirror"; rm -f "$TMP" "$FETCH_BEST" "$CURL_ERR"; exit 1; }
echo "sync_fetch_selected_version_$BEST_VER"
echo "sync_fetch_selected_source_$BEST_URL"
rm -f "$FETCH_BEST" "$CURL_ERR"

grep -q '^mode: rule$' "$TMP" || { echo "sync_fail_not_rule_mode"; rm -f "$TMP"; exit 1; }
# 自 build_final 移除 GLOBAL 内置组后，订阅不再含 GLOBAL（mihomo 运行态会自动生成内置 GLOBAL）
grep -q '^- name: Fine$' "$TMP" || { echo "sync_fail_no_fine_group"; rm -f "$TMP"; exit 1; }
grep -q '^- name: Fine-Auto$' "$TMP" || { echo "sync_fail_no_fine_auto_group"; rm -f "$TMP"; exit 1; }
grep -q '  - Fine-Auto' "$TMP" || { echo "sync_fail_fine_no_auto"; rm -f "$TMP"; exit 1; }
grep -q '  - DIRECT' "$TMP" || { echo "sync_fail_fine_no_direct"; rm -f "$TMP"; exit 1; }
GROUP_NAMES=$(grep '^- name: ' "$TMP" | sed 's/^- name: //' | tr '\n' ' ')
[ "$GROUP_NAMES" = "Fine Fine-Auto " ] || { echo "sync_fail_unsupported_group_layout"; rm -f "$TMP"; exit 1; }
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

# The public subscription has one supported layout and one fallback group.
grep -q 'MATCH,Fine' "$TMP" || { echo "sync_fail_no_match_fine"; rm -f "$TMP"; exit 1; }

if grep -Eq 'GEOSITE,' "$TMP"; then
  echo "sync_fail_geosite_dependency"
  rm -f "$TMP"
  exit 1
fi
# Provider-based upstream subscriptions are not part of this profile.
if grep -Eq '^proxy-providers:' "$TMP"; then
  echo "sync_fail_unsupported_proxy_providers"
  rm -f "$TMP"
  exit 1
fi
# Credentials must never be published in the public profile.
if grep -Eq 'token=' "$TMP"; then
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
# Checking total server entries is insufficient: unrelated proxies can mask an empty Fine-Auto.
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
