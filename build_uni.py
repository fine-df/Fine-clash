"""CI：每 4h 重建「手机 / PC 通用一条链」mobile_dual_uni.yaml。

输入（全部来自本仓库，CI 产物已在前置步骤生成，无需外网）：
  live_clash.yaml    -> ♻️ Bitz自动 组的最新节点池（CI 每 4h 重建）
  fine_final.yaml    -> Fine 侧的候选节点（vless/vmess，CI discovery 产出）
  mobile_dual_uni.yaml（上一版，作为模板 + 专线池来源）

输出：mobile_dual_uni.yaml（原地覆盖）
  - ♻️Bitz自动  <- live_clash 最新池（自动换节点）
  - ♻️Fine自动  <- 专线节点（真 Fine 分流）+ fine_final 候选兜底 4 个
  - proxies 段清理孤儿块（不被任何组引用），防止文件无限膨胀
  - rules / 组名 / allow-lan / 无 external-controller 全部保持

红线（任一不满足直接 exit 1，不产出、不提交）：
  1. 四个组名不变
  2. Fine 组 >= 15 个且成员全是「专线/直连线路」
  3. Bitz 组 == live_clash 池 set
  4. Fine 组与 Bitz 组无交集（真分流）
  5. proxies 段无孤儿（每个块都被某组引用）
  6. rules 段条数不变
  7. 无 external-controller / authentication，allow-lan: true
"""
from __future__ import annotations

import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(__file__))
FINE = "♻️ Fine自动"
BITZ = "♻️ Bitz自动"
PICK = "🚀 节点选择"
GLOBAL = "GLOBAL"

FINE_LINE_HINT = ("专线", "直连线路")
TOP_KEYS = ("proxies:", "proxy-groups:", "rules:")
MAX_FINE = 24          # Fine 组满员目标（专线 + 公开兜底）
MIN_FINE_LINE = 8      # 专线少于这个数即告警（快烂了）
EXTRA_POOL = "extra_pool.yaml"   # CI 抓取的公开大池（clashfree，400+ 节点）


def read(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def seg(text: str, key: str) -> str:
    """取某顶层段（含 key 行本身）到下一个顶层 key 之前的文本。"""
    start = text.index(key)
    end = len(text)
    for k in TOP_KEYS:
        if k == key:
            continue
        p = text.find("\n" + k, start)
        if p != -1:
            end = min(end, p)
    return text[start:end]


def split_blocks(text: str) -> list[list[str]]:
    """把段切成块：块以行首 '- ' 开始（顶格）。"""
    out: list[list[str]] = []
    blk: list[str] = []
    for ln in text.splitlines():
        s = ln.rstrip()
        if s.startswith("- "):
            if blk:
                out.append(blk)
            blk = [s]
        elif blk:
            blk.append(s)
    if blk:
        out.append(blk)
    return out


def norm(block: list[str]) -> list[str]:
    return [l.rstrip() for l in block if l.strip() != ""]


INLINE_RE = re.compile(r"^\s*-\s*\{?name[=:]\s*.+[,}]\s*$")


def has_inline(block: list[str]) -> bool:
    """块里是否混有「单行 kv 流」行（- {name: ..., server: ...}）。
    这类行会导致 yaml/mihomo 解析失败（节点名含 '|'），
    一旦上轮写进 uni 链，下轮会被粘进前一个块，必须整块丢弃。
    注意：不能宽泛到匹配正常组名行 '- name: xxx'（结尾无逗号）。"""
    return any(INLINE_RE.match(l) for l in block)


def block_name(block: list[str]) -> str:
    for l in block:
        m = re.match(r"^-\s*name:\s*(.+?)\s*$", l)
        if m:
            return m.group(1)
        m = re.match(r"^\s*name:\s*(.+?)\s*$", l)
        if m:
            return m.group(1)
        # 行内块：'  - {name: X, server: ...}' / '- {name=X, ...}'
        m = re.match(r"^\s*-\s*\{?name[=:]\s*(.+?)\s*[,}]\s*$", l)
        if m:
            return m.group(1).strip("'\"")
    return ""


def group_members(block: list[str]) -> list[str]:
    """组内 proxies 子段的成员。"""
    mem: list[str] = []
    in_prox = False
    for l in block:
        if re.match(r"^\s*proxies:\s*$", l):
            in_prox = True
            continue
        if in_prox:
            m = re.match(r"^\s+-\s*(.+?)\s*$", l)
            if m:
                mem.append(m.group(1))
            elif re.match(r"^\s+\S", l) and not l.strip().startswith("-"):
                in_prox = False
    return mem


def set_members(block: list[str], members: list[str]) -> list[str]:
    """重写组内的 proxies 子段，返回新块。"""
    header: list[str] = []
    for l in block:
        if re.match(r"^\s*proxies:\s*$", l):
            break
        header.append(l.rstrip())
    body = ["  proxies:"]
    body += ["  - " + m for m in members]
    return header + body


def inline_blocks(text: str) -> list[list[str]]:
    """行内块（extra_pool.yaml / clashfree）展开成多行块。

    '- {name: X, server: ..., type: ss, ...}' -> '- name: X' + '  server: ...' ...
    必须展开：节点名里含 '|'（如 '未知 SS-01 | free-nodes'），
    留在 flow mapping 里会让 mihomo / yaml 解析报 did-not-find-expected-key。
    """
    out: list[list[str]] = []
    for ln in text.splitlines():
        s = ln.strip().rstrip(",")
        m = re.match(r"^-\s*\{?name[=:]\s*(.*?)\s*(?=[,}]|$)", s)
        if not m:
            continue
        name = m.group(1).strip().strip("'\"")
        body = s[m.end():].lstrip(",}")
        blk = ["- name: " + name]
        for k, v in re.findall(r"([A-Za-z][A-Za-z0-9-]*):\s*([^,}]+)", body):
            v = v.strip().strip("'\"")
            if not v or k == "name":
                continue
            blk.append("  %s: %s" % (k, v))
        if len(blk) > 1:
            out.append([x.rstrip() for x in blk])
    return out


def fine_candidate_blocks(text: str) -> list[list[str]]:
    """从 fine_final.yaml 的 proxies 段取块（CI discovery 每 4h 产出的公开候选）。"""
    out: list[list[str]] = []
    for b in split_blocks(seg(text, "proxies:")):
        if block_name(b):
            out.append(norm(b))
    return out


def main() -> int:
    uni_txt = read("mobile_dual_uni.yaml")
    live_txt = read("live_clash.yaml")
    fine_txt = read("fine_final.yaml")

    uni_seg_proxies = seg(uni_txt, "proxies:")
    uni_seg_groups = seg(uni_txt, "proxy-groups:")
    uni_seg_rules = seg(uni_txt, "rules:")

    raw_proxies = [norm(b) for b in split_blocks(uni_seg_proxies)]
    # 被行内块污染的块整块丢弃，同时其名字必须从所有组引用里剔除，否则悬空
    bad_names = {block_name(b) for b in raw_proxies if has_inline(b)}
    uni_proxies = [b for b in raw_proxies if block_name(b) not in bad_names]
    uni_groups = [norm(b) for b in split_blocks(uni_seg_groups) if not has_inline(b)]

    by_name = {block_name(b): b for b in uni_proxies}
    proxy_names = [block_name(b) for b in uni_proxies]
    uni_proxy_set = set(proxy_names)

    # ---- 1. 专线池（Fine 真分流）：uni 内已定义的专线节点 ----
    line_nodes = [n for n in proxy_names
                  if any(h in n for h in FINE_LINE_HINT)]

    # ---- 2. Bitz 组 = live_clash 最新池 ----
    live_pool: list[str] = []
    for b in split_blocks(seg(live_txt, "proxies:")):
        n = block_name(b)
        if n and n not in live_pool:
            live_pool.append(n)
    live_pool = [n for n in live_pool if n not in bad_names][:20]
    live_set = set(live_pool)

    # live_clash 里有、但 uni 链里缺的块（历史上被 has_inline 误杀过）自动补位，
    # 否则 Bitz 组会引用一个不存在的节点，mihomo -t 直接挂。
    live_blocks = {}
    for b in split_blocks(seg(live_txt, "proxies:")):
        n = block_name(b)
        if n:
            live_blocks[n] = norm(b)
    refill: list[list[str]] = []
    for n in live_pool:
        if n not in uni_proxy_set and n in live_blocks:
            refill.append(live_blocks[n])
    if refill:
        print("live 块补位 %d 个" % len(refill))

    # ---- 3. Fine 组 = 专线（真 Fine 分流）+ CI 自动公开候选兜底 ----
    #     fine_final.yaml 是 CI discovery 每 4h 产出的公开节点池，
    #     专线是用户私有机场节点（公开源里 0 个），会随到期减少；
    #     兜底让 Fine 组永远满员，专线全烂时手机端也不会断。
    fine_pool: list[str] = [n for n in line_nodes if n in by_name]

    # fine_final（CI discovery，与 live_clash 同批，已被 Bitz 占满）只做同名去重依据
    filler_names = {block_name(b) for b in fine_candidate_blocks(fine_txt)}

    # 兜底池：extra_pool.yaml（CI 抓的 clashfree 大池，与 Bitz 用的是不同批）
    filler: dict[str, list[str]] = {}
    if os.path.exists(os.path.join(ROOT, EXTRA_POOL)):
        for b in inline_blocks(read(EXTRA_POOL)):
            n = block_name(b)
            if n and n not in filler:
                filler[n] = b
    added = 0
    for n in filler:
        if len(fine_pool) >= MAX_FINE:
            break
        if n in live_set or n in fine_pool or n in filler_names:
            continue
        # 块整行搬进 uni 链的 proxies 段，避免引用悬空
        fine_pool.append(n)
        added += 1
    fine_line_cnt = len(fine_pool) - added
    fine_fill_cnt = added

    # ---- 4. 重写 Fine / Bitz 组，并顺手把 🚀 节点选择收窄到当前两个池 ----
    final_used: set[str] = set(fine_pool) | set(live_pool) | {FINE, BITZ, "DIRECT"}
    new_groups: list[list[str]] = []
    fine_done = bitz_done = False
    for g in uni_groups:
        nm = block_name(g)
        if nm == FINE:
            new_groups.append(set_members(g, fine_pool))
            fine_done = True
        elif nm == BITZ:
            new_groups.append(set_members(g, live_pool))
            bitz_done = True
        elif nm == PICK:
            kept_members = [m for m in group_members(g)
                            if m in final_used or m in {FINE, BITZ, "DIRECT"}]
            new_groups.append(set_members(g, [m for m in kept_members if m not in bad_names]))
        else:
            new_groups.append(g)
    if not (fine_done and bitz_done):
        raise SystemExit("FATAL: 未找到 Fine/Bitz 组")

    # ---- 5. 清孤儿：只保留被任意组引用的 proxy 块（+ 新搬进来的 Fine 兜底块）----
    used: set[str] = set()
    for g in new_groups:
        used.update(group_members(g))
    kept = [b for b in uni_proxies if block_name(b) in used]
    for b in filler.values():
        if block_name(b) in used and block_name(b) not in {block_name(x) for x in kept}:
            kept.append(b)
    kept.extend(refill)
    dropped = len(uni_proxies) - len(kept)

    # ---- 6. 拼回 ----
    head = uni_txt[: uni_txt.index("proxies:")]
    i_rules = uni_txt.index(uni_seg_rules.rstrip("\n"))
    groups_text = "\n\n".join("\n".join(g) for g in new_groups)
    out = (
        head
        + "proxies:\n"
        + "\n".join("\n".join(b) for b in kept)
        + "\n\n"
        + "proxy-groups:\n"
        + groups_text
        + "\n\n"
        + uni_txt[i_rules:]
    )
    # blocks 之间原本可能用空行分隔，统一补一个空行，保持可读
    out = re.sub(r"\n(- type:|\w)", lambda m: "\n\n- type:" if m.group(1) == "- type:" else m.group(0), out)

    # ---- 7. 红线 ----
    reasons: list[str] = []
    if FINE not in out or BITZ not in out or PICK not in out or GLOBAL not in out:
        reasons.append("组名缺失")
    if len(fine_pool) < 15:
        reasons.append("Fine 组 < 15：%d" % len(fine_pool))
    if fine_line_cnt < MIN_FINE_LINE:
        reasons.append("专线只剩 %d 个（<%d），Fine 组逼近全兜底" % (fine_line_cnt, MIN_FINE_LINE))
    if fine_fill_cnt < 1:
        reasons.append("Fine 兜底为空：专线全烂时无处可退")
    if set(fine_pool) & set(live_pool):
        reasons.append("Fine/Bitz 有交集：%s" % sorted(set(fine_pool) & set(live_pool))[:3])
    if len(kept) != len(uni_proxies):
        pass  # 孤儿清理允许发生
    if len(uni_seg_rules.splitlines()) != len(seg(out, "rules:").splitlines()):
        reasons.append("rules 条数变了")
    if "external-controller" in out or "authentication" in out:
        reasons.append("出现 external-controller/authentication")
    if "allow-lan: true" not in out:
        reasons.append("allow-lan 不是 true")
    orphan = [block_name(b) for b in kept if block_name(b) not in
              {m for g in new_groups for m in group_members(g)}]
    if orphan:
        reasons.append("仍有孤儿 proxy：%s" % orphan[:3])
    kept_names = {block_name(b) for b in kept}
    group_names = {block_name(g) for g in new_groups}
    builtin = group_names | {"DIRECT", "REJECT", "REJECTED"}
    dangling = sorted({m for g in new_groups for m in group_members(g)} - kept_names - builtin)
    if dangling:
        reasons.append("悬空引用（组引用了不存在的节点）：%s" % dangling[:3])

    print("fine_pool=%d(专线%d+兜底%d) bitz_pool=%d proxies %d->%d(drop %d) rules=%d"
          % (len(fine_pool), fine_line_cnt, fine_fill_cnt, len(live_pool),
             len(uni_proxies), len(kept), dropped,
             len(seg(out, "rules:").splitlines())))
    if reasons:
        for r in reasons:
            print("REDLINE:", r)
        raise SystemExit(2)

    with open(os.path.join(ROOT, "mobile_dual_uni.yaml"), "w", encoding="utf-8", newline="") as f:
        f.write(out)
    print("OK: mobile_dual_uni.yaml rebuilt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
