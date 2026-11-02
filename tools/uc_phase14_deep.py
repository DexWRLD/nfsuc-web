"""Deeper Phase 14 measurements: graphics chain, clean islands, the old frontier."""

import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

import uc_code_analyze as uca
import uc_frontier as uf
import uc_initprov as ip
import uc_phase14_cut as cut
import uc_phase7_test as p7

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTIER = os.path.join(ROOT, "analysis", "undercover", "runtime-frontier.json")


def hx(n):
    return "0x%08X" % n


def disasm_until(blob, base, va, stop, limit=180):
    md = cut._md()
    lines = []
    cur = va
    for _ in range(limit):
        insn = next(md.disasm(blob[cur - base:cur - base + 15], cur), None)
        if insn is None:
            lines.append((cur, "??"))
            break
        lines.append((insn.address, "%s %s" % (insn.mnemonic, insn.op_str)))
        cur = insn.address + insn.size
        if insn.address >= stop or insn.mnemonic.startswith("ret"):
            break
    return lines


def callers_of(blob, base, dest):
    sites = []
    for off in range(len(blob) - 5):
        op = blob[off]
        if op not in (0xE8, 0xE9):
            continue
        rel = int.from_bytes(blob[off + 1:off + 5], "little", signed=True)
        if (base + off + 5 + rel) & 0xFFFFFFFF == dest:
            sites.append((base + off, "call" if op == 0xE8 else "jmp"))
    return sites


def data_dwords(sections, target):
    hits = []
    raw = target.to_bytes(4, "little")
    for sec in sections:
        buf = sec.get("raw")
        if not buf or sec["name"] in uca.PROTECTED:
            continue
        start = 0
        while True:
            i = buf.find(raw, start)
            if i < 0:
                break
            hits.append((sec["name"], sec["va"] + i))
            start = i + 1
    return hits


def closure_imports(by, thunks, functions):
    names = collections.Counter()
    unknown = 0
    for va in functions:
        for target in cut.call_edges(by, va):
            row = thunks.get(target)
            if row:
                names[row.get("symbol") or "ordinal"] += 1
            elif target not in by or by[target].get("label") != "HIGH_CONFIDENCE":
                if target not in (cut.HELPER, cut.UNKNOWN_B):
                    unknown += 1
    return names, unknown


def clean_islands(ctx, limit=20):
    sys.setrecursionlimit(8000)
    children = ctx["children"]
    allowed = {va for va, lab in ctx["labels"].items() if lab == cut.NONE}
    memo = {}
    visiting = set()

    def close(root):
        if root in memo:
            return memo[root]
        if root in visiting or root not in allowed:
            return None
        visiting.add(root)
        functions = {root}
        depth = 1
        for kid in children.get(root, []):
            if kid not in allowed:
                continue
            sub = close(kid)
            if not sub:
                continue
            functions.update(sub[0])
            depth = max(depth, sub[1] + 1)
        visiting.remove(root)
        memo[root] = (functions, depth)
        return memo[root]

    incoming = collections.Counter()
    for va in allowed:
        for kid in children.get(va, []):
            if kid in allowed:
                incoming[kid] += 1
    dirty = set()
    own_names = {}
    for va in allowed:
        names, unknown = closure_imports(ctx["by"], ctx["thunks"], [va])
        own_names[va] = names
        if unknown or any(n not in uf.IMPLEMENTED for n in names):
            dirty.add(va)

    state = {}

    def tainted(va):
        if va in state:
            return state[va]
        if va in dirty:
            state[va] = True
            return True
        state[va] = False
        bad = False
        for kid in children.get(va, []):
            if kid in allowed and tainted(kid):
                bad = True
                break
        state[va] = bad
        if bad:
            dirty.add(va)
        return bad

    for va in list(allowed):
        tainted(va)
    ranked = []
    for root in allowed:
        if incoming[root] or root in dirty:
            continue
        rec = close(root)
        if not rec:
            continue
        names = collections.Counter()
        for va in rec[0]:
            names.update(own_names.get(va, {}))
        ranked.append((root, len(rec[0]), rec[1], sorted(names)))
    ranked.sort(key=lambda item: (-item[1], item[0]))
    out = []
    seen = []
    for item in ranked:
        rec = close(item[0])
        key = frozenset(rec[0])
        if any(key <= prev for prev in seen):
            continue
        seen.append(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def main():
    ctx = cut.analyze()
    blob, base, by = ctx["blob"], ctx["base"], ctx["by"]
    labels = ctx["labels"]
    print("DEPENDENT")
    for va, lab in sorted(labels.items(), key=lambda kv: (kv[1], kv[0])):
        if lab == cut.NONE:
            continue
        direct = va in ctx["confirmed"]
        print(hx(va), lab, "DIRECT" if direct else "TRANSITIVE", "sites", len(ctx["confirmed"].get(va, [])))

    frontier = json.load(open(FRONTIER, encoding="utf-8"))
    old = [int(x, 16) for x in frontier["only_indirect"]["functions"]]
    print("OLD102", len(old), collections.Counter(labels.get(va, "ABSENT") for va in old))
    print("OLD102_HITS", [hx(va) for va in old if labels.get(va) != cut.NONE])

    print("CLEAN")
    for root, size, depth, names in clean_islands(ctx):
        print(hx(root), size, depth, names)

    print("D3D_FN", hx(cut.D3D_FN), by[cut.D3D_FN]["label"], by[cut.D3D_FN]["score"], by[cut.D3D_FN].get("insns"))
    for addr, text in disasm_until(blob, base, cut.D3D_FN, cut.D3D_SITE + 8, 80):
        print("  ", hx(addr), text)

    print("CALLERS")
    image = p7.read_sections(cut.GAME)
    import bisect
    vas = sorted(by)
    for eip, kind in callers_of(blob, base, cut.D3D_FN):
        owner = vas[bisect.bisect_right(vas, eip) - 1]
        reached = bool(cut.cfg_sites(blob, base, owner, {eip}))
        print(" ", kind, hx(eip), "owner", hx(owner), by[owner]["label"], "cfg", reached,
              "reachable", bool(by[owner].get("reachable")))
        start = owner if reached else max(cut.D3D_FN, eip - 48)
        for addr, text in disasm_until(blob, base, eip - 24, eip + 8, 20):
            print("   ", hx(addr), text)
    print("DATA_PTRS", [(name, hx(va)) for name, va in data_dwords(image["sections"], cut.D3D_FN)])

    calls = by[cut.D3D_FN].get("calls") or []
    print("D3D_CALLEES")
    for text in calls:
        va = int(text, 16)
        row = by.get(va)
        print(" ", hx(va), None if row is None else row.get("label"), labels.get(va, "NOT_IN_REACHABLE_HIGH"),
              "reachable" if row and row.get("reachable") else "not_reachable")
    for va in (0x0072DD00, 0x0072DCA0, 0x0072E2A0, 0x0072E612):
        row = by.get(va)
        print(" NEAR", hx(va), None if row is None else (row.get("label"), row.get("score"), row.get("reachable"),
              labels.get(va, "NOT_IN_REACHABLE_HIGH")))

    # Globals read by the linear prefix, with ordinary writers.
    slots = []
    md = cut._md()
    cur = cut.D3D_FN
    for _ in range(40):
        insn = next(md.disasm(blob[cur - base:cur - base + 15], cur), None)
        if insn is None or insn.address > cut.D3D_SITE:
            break
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                slots.append(op.mem.disp & 0xFFFFFFFF)
        cur = insn.address + insn.size
    print("SLOTS")
    info = uca.read_inputs(cut.GAME)
    for slot in sorted(set(slots)):
        writers = []
        for off in ip.iter_immediates(blob, base, slot):
            classified = ip.classify_encoding(blob, base, off, slot)
            if classified and classified[0] == "WRITE":
                writers.append(classified)
        sec = None
        for s in info["sections"]:
            if s["va"] <= slot < s["va"] + s["vsize"]:
                sec = s["name"]
        thunk = None
        for _tva, meta in ctx["thunks"].items():
            slot_text = meta.get("iat_slot") or "0"
            if int(slot_text, 16) == slot:
                thunk = meta.get("symbol")
        print(hx(slot), sec, "import", thunk, "abs_writers", len(writers))

    print("SUBSYSTEMS")
    interesting = ("Direct3DCreate9", "DirectInput8Create", "GetTickCount", "_time64",
                   "fopen", "fclose", "fread", "fwrite", "_beginthreadex", "_endthreadex",
                   "malloc", "free")
    rev = collections.defaultdict(list)
    for va in ctx["high_list"]:
        for target in cut.call_edges(by, va):
            rev[target].append(va)
    for thunk, meta in sorted(ctx["thunks"].items()):
        name = meta.get("symbol") or ""
        dll = meta.get("dll") or ""
        if name not in interesting and "DSOUND" not in dll and "D3DX" not in name and "XINPUT" not in dll:
            continue
        owners = rev.get(thunk, [])
        kinds = collections.Counter(labels.get(va, "ABSENT") for va in owners)
        print(name or dll, hx(thunk), "high_callers", len(owners), dict(kinds))

    b_owners = []
    for eip, kind in callers_of(blob, base, cut.UNKNOWN_B):
        import bisect
        vas = sorted(by)
        owner = vas[bisect.bisect_right(vas, eip) - 1]
        reached = bool(cut.cfg_sites(blob, base, owner, {eip}))
        b_owners.append((hx(eip), hx(owner), by[owner]["label"], bool(by[owner].get("reachable")), reached,
                         labels.get(owner, "NOT_REACHABLE_HIGH")))
    print("UNKNOWN_B", b_owners)
    extremes = frontier.get("all_node_extremes") or {}
    ready = extremes.get("READY") or {}
    ready_fns = [int(x, 16) for x in ready.get("functions") or []]
    print("READY_ROOT", ready.get("root"), "overlap",
          [hx(va) for va in ready_fns if labels.get(va) != cut.NONE])
    for key in ("READY_WITH_IMPLEMENTED_IMPORTS", "only_indirect"):
        rec = extremes.get(key) or frontier.get(key) or {}
        fns = [int(x, 16) for x in rec.get("functions") or []]
        print(key, rec.get("root"), rec.get("size"), "overlap",
              sum(1 for va in fns if labels.get(va) not in (cut.NONE, None)))


if __name__ == "__main__":
    main()
