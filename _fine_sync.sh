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
grep -q 'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve' "$TMP" || { echo "sync_fail_no_private_lan_rule"; rm -f "$TMP"; exit 1; }
grep -q 'GEOIP,CN,DIRECT' "$TMP" || { echo "sync_fail_no_cn_direct"; rm -f "$TMP"; exit 1; }

# 两种合法布局：Fine-only（默认，公开构建）；或 Fine + Bitz 对称双组（Bitz 兜底其余代理流量）。
# 两种布局都必须保证 MATCH 指向一个真实存在的组，避免落到空组导致断网。
if grep -q '^- name: Bitz$' "$TMP"; then BITZ_LAYOUT=1; else BITZ_LAYOUT=0; fi
if [ "$BITZ_LAYOUT" = 1 ]; then
  grep -q '^  BitzPool:' "$TMP" || { echo "sync_fail_no_bitz_pool"; rm -f "$TMP"; exit 1; }
  grep -q '^- name: Bitz-Auto$' "$TMP" || { echo "sync_fail_no_bitz_auto_group"; rm -f "$TMP"; exit 1; }
  grep -q '  - Bitz-Auto' "$TMP" || { echo "sync_fail_bitz_no_auto"; rm -f "$TMP"; exit 1; }
  grep -q 'MATCH,Bitz' "$TMP" || { echo "sync_fail_no_match_bitz"; rm -f "$TMP"; exit 1; }
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
# 硬红线：付费上游凭证绝不能以明文出现在公开订阅里（2026-10-04 事故后的护栏）。
# 因此 Bitz 若要上线，其 provider URL 必须是不含 token 的中继地址。
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
if [ -n "$LOCAL_VER" ] && [ "$REMOTE_VER" -le "$LOCAL_VER" ]; then
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

cp "$TMP" "$DST"
cp "$TMP" "$TPL"
rm -f "$TMP"
/data/clash/start.sh stop >/dev/null 2>&1
sleep 5
/data/clash/start.sh start >/dev/null 2>&1
echo "sync_updated_$(date '+%m-%d %H:%M')"
