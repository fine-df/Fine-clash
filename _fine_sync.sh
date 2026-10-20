#!/bin/ash
# Fine-Clash: router syncs the ONLY public subscription.
# Sourceable for tests: the main flow only runs when this file is executed
# directly (basename == _fine_sync.sh). Sourcing it exposes check_groups() and
# vercmp() for the test suite without triggering any network/curl side effects.
PATH=$PATH:/tmp/ShellCrash:/tmp/ctest:/data/clash/bin
export PATH

URL="https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml"
DST="/tmp/ShellCrash/live_clash.yaml"
TPL="/data/clash/yamls/config.yaml"
TMP="/tmp/live_clash.sync"
BIN="/tmp/ShellCrash/CrashCore"
[ -x "$BIN" ] || BIN="/tmp/ctest/CrashCore"

# vercmp REMOTE LOCAL -> 0 (true/success) if REMOTE is strictly newer than LOCAL.
# The version is a zero-padded 14-digit timestamp (YYYYMMDDHHMMSS), so
# lexicographic comparison equals numeric comparison. We compare as numbers via
# awk (double precision covers 14 digits exactly), falling back to the shell '<'
# operator on shells that lack awk. This avoids the 32-bit integer overflow that
# the old `[ "$REMOTE" -le "$LOCAL" ]` suffered on BusyBox/ash with 14-digit ids.
vercmp() {
    r="$1"; l="$2"
    [ -z "$r" ] && return 1          # no remote version -> never treat as newer
    [ -z "$l" ] && return 0          # no local version -> remote is effectively newer
    [ "$r" = "$l" ] && return 1      # equal -> not newer
    if command -v awk >/dev/null 2>&1; then
        awk -v a="$r" -v b="$l" 'BEGIN{ if (a ~ /^[0-9]+$/ && b ~ /^[0-9]+$/) { exit (a+0 > b+0) ? 0 : 1 }; exit (a > b) ? 0 : 1 }'
        return $?
    fi
    [ "$r" '<' "$l" ] && return 1    # remote < local -> not newer
    return 0
}

# check_groups FILE -> 0 if the downloaded config matches the generator's current
# contract (Fine + AUTO groups, required direct/proxy rules, no risky markers).
# On failure it prints a sync_fail_* reason to stdout and returns 1. The GLOBAL
# group is intentionally NOT required: the generator only emits Fine and AUTO.
check_groups() {
    f="$1"
    grep -q '^mode: rule$' "$f" || { echo "sync_fail_not_rule_mode"; return 1; }
    # proxy-groups are emitted by yaml.safe_dump and indented under the key, so
    # the group-name lines are "  - name: Fine". Allow leading whitespace.
    grep -Eq '^[[:space:]]*- name: Fine$' "$f" || { echo "sync_fail_no_fine_group"; return 1; }
    grep -Eq '^[[:space:]]*- name: AUTO$' "$f" || { echo "sync_fail_no_auto_group"; return 1; }
    grep -q '  - AUTO' "$f" || { echo "sync_fail_fine_no_auto"; return 1; }
    grep -q '  - DIRECT' "$f" || { echo "sync_fail_fine_no_direct"; return 1; }
    grep -q 'DOMAIN-SUFFIX,youtube.com,Fine' "$f" || { echo "sync_fail_no_video_rule"; return 1; }
    grep -q 'DOMAIN-SUFFIX,play.google.com,Fine' "$f" || { echo "sync_fail_no_store_rule"; return 1; }
    grep -q 'DOMAIN-SUFFIX,cn,DIRECT' "$f" || { echo "sync_fail_no_cn_rule"; return 1; }
    grep -q 'DOMAIN-SUFFIX,qq.com,DIRECT' "$f" || { echo "sync_fail_no_qq_rule"; return 1; }
    grep -q 'DOMAIN-SUFFIX,mi.com,DIRECT' "$f" || { echo "sync_fail_no_xiaomi_rule"; return 1; }
    grep -q 'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve' "$f" || { echo "sync_fail_no_private_lan_rule"; return 1; }
    grep -q 'GEOIP,CN,DIRECT' "$f" || { echo "sync_fail_no_cn_direct"; return 1; }
    grep -q 'MATCH,Fine' "$f" || { echo "sync_fail_no_match_fine"; return 1; }
    grep -Eq 'GEOSITE,' "$f" && { echo "sync_fail_geosite_dependency"; return 1; }
    grep -Eq 'proxy-providers:' "$f" && { echo "sync_fail_obsolete_provider_architecture"; return 1; }
    grep -Eq 'cont\.bbkcdpub\.com|token=' "$f" && { echo "sync_fail_public_profile_contains_token"; return 1; }
    grep -Eq 'fine_final.yaml|fine-override:' "$f" && { echo "sync_fail_obsolete_profile"; return 1; }
    return 0
}

main() {
    rm -f "$TMP"
    HTTP=$(curl -fsS -m 30 -o "$TMP" -w "%{http_code}" "$URL" || true)
    if [ "$HTTP" != "200" ]; then
        echo "sync_skip_http_$HTTP"
        rm -f "$TMP"
        exit 0
    fi

    # Validate the downloaded config against the current generator contract.
    # Any failure aborts BEFORE the router's existing config is touched.
    if ! check_groups "$TMP"; then
        rm -f "$TMP"
        exit 1
    fi

    REMOTE_VER=$(sed -n '1s/.*fine-clash-version:\([0-9][0-9]*\).*/\1/p' "$TMP")
    LOCAL_VER=$(sed -n '1s/.*fine-clash-version:\([0-9][0-9]*\).*/\1/p' "$DST" 2>/dev/null || true)
    REMOTE_VER=${REMOTE_VER:-0}
    LOCAL_VER=${LOCAL_VER:-0}
    # Keep the local config when the remote is not strictly newer (covers equal,
    # older, or unparseable remote versions). Uses vercmp to avoid 32-bit overflow.
    if ! vercmp "$REMOTE_VER" "$LOCAL_VER"; then
        echo "sync_keep_local_remote_ver_${REMOTE_VER}_local_ver_${LOCAL_VER}"
        rm -f "$TMP"
        exit 0
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

    # All checks passed: only now is the router's config replaced.
    cp "$TMP" "$DST"
    cp "$TMP" "$TPL"
    rm -f "$TMP"
    /data/clash/start.sh stop >/dev/null 2>&1
    sleep 5
    /data/clash/start.sh start >/dev/null 2>&1
    echo "sync_updated_$(date '+%m-%d %H:%M')"
}

# Only run the main flow when executed as a script (not when sourced for tests).
if [ "${0##*/}" = "_fine_sync.sh" ]; then
    main
fi
