"""Phase 14 dependency cut around the unavailable helper 0x00686000.

Reads ordinary .text and the function map. Does not execute the game, does not
read protected sections, and does not substitute an implementation for the helper.
"""

import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

import uc_code_analyze as uca
import uc_frontier as uf

HELPER = 0x00686000
UNKNOWN_B = 0x0055FF30
D3D_CREATE = 0x0087A79C
D3D_FN = 0x0072E340
D3D_SITE = 0x0072E3B9
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MAP_PATH = os.path.join(ROOT, "analysis", "undercover", "function-map.json")
ABI_PATH = os.path.join(ROOT, "analysis", "undercover", "import-abi.json")

MUST = "MUST_REACH_EXTERNAL_HELPER"
MAY = "MAY_REACH_EXTERNAL_HELPER"
NONE = "NO_PATH_TO_EXTERNAL_HELPER"


def _md():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


def load_map():
    data = json.load(open(MAP_PATH, encoding="utf-8"))
    by = {int(row["va"], 16): row for row in data["functions"]}
    return by


def load_thunks():
    abi = json.load(open(ABI_PATH, encoding="utf-8"))
    thunks = {}
    for row in abi["imports"]:
        thunks[int(row["thunk"], 16)] = row
    return thunks


def high_set(by, thunks):
    out = []
    for va, row in by.items():
        if row.get("label") != "HIGH_CONFIDENCE":
            continue
        if va in thunks:
            continue
        if not row.get("reachable"):
            continue
        out.append(va)
    return out


def call_edges(by, va):
    kids = []
    for key in ("calls", "tails"):
        for text in by[va].get(key) or []:
            kids.append(int(text, 16))
    return kids


def cfg_sites(blob, base, entry, targets, limit=8000):
    """Instruction addresses inside `targets` reached from `entry`."""
    md = _md()
    found = set()
    seen = set()
    stack = [entry]
    n = 0
    while stack and n < limit and len(found) < len(targets):
        va = stack.pop()
        if va in seen or va < base or va >= base + len(blob):
            continue
        seen.add(va)
        cur = va
        while n < limit:
            insn = next(md.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                break
            n += 1
            if insn.address in targets:
                found.add(insn.address)
            m = insn.mnemonic
            nxt = insn.address + insn.size
            if m.startswith("ret") or m == "int3":
                break
            if m == "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                stack.append(insn.operands[0].imm & 0xFFFFFFFF)
                break
            if m.startswith("j") and m != "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                stack.append(insn.operands[0].imm & 0xFFFFFFFF)
                cur = nxt
                continue
            if m == "jmp":
                break
            if nxt < base or nxt >= base + len(blob):
                break
            cur = nxt
    return found


def direct_callers(blob, base, by, high):
    """Call sites of the helper, split by whether the owner CFG reaches them."""
    sites = []
    for off in range(len(blob) - 5):
        if blob[off] != 0xE8:
            continue
        rel = int.from_bytes(blob[off + 1:off + 5], "little", signed=True)
        dest = (base + off + 5 + rel) & 0xFFFFFFFF
        if dest == HELPER:
            sites.append(base + off)
    vas = sorted(by)
    import bisect
    owners = collections.defaultdict(list)
    for eip in sites:
        owner = vas[bisect.bisect_right(vas, eip) - 1]
        owners[owner].append(eip)
    confirmed = {}
    span_only = {}
    for owner, eips in owners.items():
        row = by[owner]
        if row.get("label") != "HIGH_CONFIDENCE" or owner not in high:
            span_only[owner] = eips
            continue
        hit = cfg_sites(blob, base, owner, set(eips))
        if hit:
            confirmed[owner] = sorted(hit)
        missed = [eip for eip in eips if eip not in hit]
        if missed:
            span_only[owner] = missed
    map_recorded = []
    for va in high:
        if HELPER in call_edges(by, va):
            map_recorded.append(va)
    return {
        "sites": sites,
        "confirmed": confirmed,
        "span_only": span_only,
        "map_recorded": map_recorded,
    }


def build_children(by, high):
    allow = set(high)
    children = {}
    for va in high:
        kids = []
        for target in call_edges(by, va):
            if target in allow:
                kids.append(target)
        children[va] = kids
    return children


def ancestors(children, seeds):
    rev = collections.defaultdict(set)
    for va, kids in children.items():
        for kid in kids:
            rev[kid].add(va)
    seen = set(seeds)
    stack = list(seeds)
    while stack:
        va = stack.pop()
        for parent in rev.get(va, ()):
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
    return seen


def decode_graph(blob, base, entry, limit=6000):
    """Successors and cut-call addresses for one function body."""
    md = _md()
    succs = {}
    calls = {}
    n = 0
    stack = [entry]
    seen = set()
    while stack and n < limit:
        va = stack.pop()
        if va in seen or va < base or va >= base + len(blob):
            continue
        seen.add(va)
        cur = va
        while n < limit:
            insn = next(md.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                succs[cur] = []
                break
            n += 1
            m = insn.mnemonic
            nxt = insn.address + insn.size
            if m.startswith("ret") or m == "int3":
                succs[insn.address] = []
                break
            if m in ("call", "jmp") and insn.operands and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm & 0xFFFFFFFF
                calls[insn.address] = target
                if m == "jmp":
                    succs[insn.address] = [target] if base <= target < base + len(blob) else []
                    if base <= target < base + len(blob):
                        stack.append(target)
                    break
                succs[insn.address] = [nxt]
                cur = nxt
                continue
            if m.startswith("j") and m != "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm & 0xFFFFFFFF
                succs[insn.address] = [nxt, target]
                stack.append(target)
                cur = nxt
                continue
            if m == "jmp":
                succs[insn.address] = []
                break
            succs[insn.address] = [nxt]
            cur = nxt
    return succs, calls


def path_class(succs, calls, entry, must_callees, may_callees):
    """Bounded path class. A cut call is the helper or a callee already MUST."""
    memo = {}
    gray = set()

    def walk(va):
        if va in memo:
            return memo[va]
        if va in gray or va not in succs:
            return False, False
        gray.add(va)
        target = calls.get(va)
        if target == HELPER or target in must_callees:
            hits, avoids = True, False
        else:
            hits = target in may_callees
            avoids = target in may_callees
            nexts = succs.get(va) or []
            if not nexts:
                avoids = True
            for nxt in nexts:
                h, a = walk(nxt)
                hits = hits or h
                avoids = avoids or a
        gray.remove(va)
        memo[va] = (hits, avoids)
        return hits, avoids

    hits, avoids = walk(entry)
    if hits and not avoids:
        return MUST
    if hits:
        return MAY
    return NONE


def classify_dependent(blob, base, children, dependent, direct):
    """Callees first, then callers. Cycles stay MAY unless a local cut is total."""
    rev = collections.defaultdict(set)
    for va, kids in children.items():
        if va not in dependent:
            continue
        for kid in kids:
            if kid in dependent:
                rev[kid].add(va)
    order = []
    seen = set()
    temp = set()

    def visit(va):
        if va in seen or va not in dependent:
            return
        if va in temp:
            return
        temp.add(va)
        for kid in children.get(va, []):
            if kid in dependent:
                visit(kid)
        temp.remove(va)
        seen.add(va)
        order.append(va)

    for va in dependent:
        visit(va)
    labels = {}
    graphs = {}
    for va in order:
        if va not in graphs:
            graphs[va] = decode_graph(blob, base, va)
        succs, calls = graphs[va]
        must_callees = {k for k, lab in labels.items() if lab == MUST}
        may_callees = {k for k, lab in labels.items() if lab == MAY}
        if not succs:
            labels[va] = MAY if va in direct or any(k in dependent for k in children.get(va, [])) else NONE
            continue
        labels[va] = path_class(succs, calls, va, must_callees, may_callees)
        if va in direct and labels[va] == NONE:
            labels[va] = MAY
    return labels


def close_size(children, allowed):
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
            if sub[1] + 1 > depth:
                depth = sub[1] + 1
        visiting.remove(root)
        memo[root] = (functions, depth)
        return memo[root]

    incoming = collections.Counter()
    for va in allowed:
        for kid in children.get(va, []):
            if kid in allowed:
                incoming[kid] += 1
    roots = [va for va in allowed if incoming[va] == 0]
    ranked = []
    for root in roots:
        rec = close(root)
        if rec:
            ranked.append((root, rec[0], rec[1]))
    ranked.sort(key=lambda item: (-len(item[1]), item[0]))
    best = []
    covered = []
    for root, functions, depth in ranked:
        key = frozenset(functions)
        if any(key <= prev for prev in covered):
            continue
        covered.append(key)
        best.append((root, functions, depth))
        if len(best) >= 20:
            break
    return best


def import_facts(by, thunks, functions):
    imports = collections.Counter()
    classes = collections.Counter()
    protected = []
    unknown = []
    for va in functions:
        for target in call_edges(by, va):
            row = thunks.get(target)
            if row:
                name = row.get("symbol") or ("ordinal_%s" % row.get("ordinal"))
                imports[name] += 1
                classes[uf.classify_symbol(row.get("dll"), row.get("symbol"))] += 1
            elif target == HELPER or target == UNKNOWN_B:
                protected.append(target)
            elif target not in by or by[target].get("label") != "HIGH_CONFIDENCE":
                unknown.append(target)
    return imports, classes, protected, unknown


def section_name(sections, va):
    for sec in sections:
        if sec["va"] <= va < sec["va"] + sec["vsize"]:
            return sec["name"]
    return None


def scan_body(blob, base, entry, sections, limit=2500):
    md = _md()
    indirect = []
    fs = 0
    data = []
    rdata = []
    prot = []
    n = 0
    stack = [entry]
    seen = set()
    while stack and n < limit:
        va = stack.pop()
        if va in seen or va < base or va >= base + len(blob):
            continue
        seen.add(va)
        cur = va
        while n < limit:
            insn = next(md.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                break
            n += 1
            if insn.bytes and insn.bytes[0] in (0x64, 0x65):
                fs += 1
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                    disp = op.mem.disp & 0xFFFFFFFF
                    name = section_name(sections, disp)
                    if name in uca.PROTECTED:
                        prot.append(disp)
                    elif name == ".data":
                        data.append(disp)
                    elif name == ".rdata":
                        rdata.append(disp)
            m = insn.mnemonic
            nxt = insn.address + insn.size
            if m.startswith("ret") or m == "int3":
                break
            if m == "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                stack.append(insn.operands[0].imm & 0xFFFFFFFF)
                break
            if m.startswith("j") and m != "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                stack.append(insn.operands[0].imm & 0xFFFFFFFF)
                cur = nxt
                continue
            if m in ("call", "jmp") and insn.operands and insn.operands[0].type != X86_OP_IMM:
                indirect.append(insn.address)
                if m == "jmp":
                    break
            if nxt < base or nxt >= base + len(blob):
                break
            cur = nxt
    return {"indirect": indirect, "fs": fs, "data": data, "rdata": rdata, "prot": prot}


def e8_to(blob, base, dest):
    sites = []
    for off in range(len(blob) - 5):
        if blob[off] != 0xE8:
            continue
        rel = int.from_bytes(blob[off + 1:off + 5], "little", signed=True)
        if (base + off + 5 + rel) & 0xFFFFFFFF == dest:
            sites.append(base + off)
    return sites


def owner_of(vas, by, eip):
    import bisect
    va = vas[bisect.bisect_right(vas, eip) - 1]
    return va, by[va]


def subsystem_of(imports):
    if not imports:
        return "NO_IMPORT"
    kinds = [uf.classify_symbol("", name) for name in imports]
    for kind in ("GRAPHICS_BOUNDARY", "INPUT_BOUNDARY", "AUDIO_BOUNDARY", "FILESYSTEM_BOUNDARY",
                 "TIMING_BOUNDARY", "THREAD_BOUNDARY", "MEMORY_BOUNDARY", "NETWORK_BOUNDARY"):
        if kind in kinds:
            return kind
    if any(k == "UNKNOWN_RUNTIME_DEPENDENCY" for k in kinds):
        return "UNKNOWN_RUNTIME_DEPENDENCY"
    if any(k == "KNOWN_IMPORT_MISSING_HLE" for k in kinds):
        return "KNOWN_IMPORT_MISSING_HLE"
    if any(k == "READY_WITH_IMPLEMENTED_IMPORTS" for k in kinds):
        return "READY_WITH_IMPLEMENTED_IMPORTS"
    return "NO_IMPORT"


def analyze(game=GAME):
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    sections = info["sections"]
    by = load_map()
    thunks = load_thunks()
    high = high_set(by, thunks)
    high_set_s = set(high)
    direct_info = direct_callers(blob, base, by, high_set_s)
    confirmed = set(direct_info["confirmed"])
    children = build_children(by, high)
    dependent = ancestors(children, confirmed)
    labels = classify_dependent(blob, base, children, dependent, confirmed)
    for va in high_set_s:
        labels.setdefault(va, NONE)
    counts = collections.Counter(labels.values())
    independent = {va for va, lab in labels.items() if lab == NONE}
    islands = close_size(children, independent)
    island_rows = []
    for root, functions, depth in islands:
        imports, classes, protected, unknown = import_facts(by, thunks, functions)
        body = scan_body(blob, base, root, sections)
        island_rows.append({
            "root": root,
            "size": len(functions),
            "depth": depth,
            "imports": imports.most_common(12),
            "classes": dict(classes),
            "unknown_targets": len(set(unknown)),
            "protected_targets": sorted(set(protected)),
            "root_indirect": len(body["indirect"]),
            "root_fs": body["fs"],
            "root_protected_mem": len(body["prot"]),
            "subsystem": subsystem_of(imports),
        })
    # 102-function frontier from the published frontier file, if present.
    frontier_path = os.path.join(ROOT, "analysis", "undercover", "runtime-frontier.json")
    old = []
    if os.path.isfile(frontier_path):
        frontier = json.load(open(frontier_path, encoding="utf-8"))
        for rec in frontier.get("largest") or []:
            if int(rec["root"], 16) == 0x0099DCD0:
                old = [int(x, 16) for x in rec["functions"]]
                break
        if not old:
            node = frontier.get("all_node_extremes", {}).get("only_indirect") or {}
            if int(node.get("root", "0"), 16) == 0x0099DCD0:
                old = [int(x, 16) for x in node.get("functions") or []]
    old_counts = collections.Counter(labels.get(va, "ABSENT") for va in old)
    return {
        "high": len(high),
        "direct_functions": len(confirmed),
        "direct_sites_reached": sum(len(v) for v in direct_info["confirmed"].values()),
        "span_only_sites": sum(len(v) for v in direct_info["span_only"].values()),
        "map_recorded": len(direct_info["map_recorded"]),
        "counts": dict(counts),
        "labels": labels,
        "islands": island_rows,
        "old102": old,
        "old102_counts": dict(old_counts),
        "confirmed": direct_info["confirmed"],
        "children": children,
        "by": by,
        "thunks": thunks,
        "blob": blob,
        "base": base,
        "sections": sections,
        "high_list": high,
    }


def graphics(ctx):
    blob, base, by = ctx["blob"], ctx["base"], ctx["by"]
    vas = sorted(by)
    sites = e8_to(blob, base, D3D_FN)
    callers = []
    for eip in sites:
        owner, row = owner_of(vas, by, eip)
        reached = owner in cfg_sites(blob, base, owner, {eip}) if row.get("label") == "HIGH_CONFIDENCE" else False
        callers.append({
            "site": eip,
            "owner": owner,
            "label": row.get("label"),
            "reachable": bool(row.get("reachable")),
            "score": row.get("score"),
            "cfg": reached,
            "helper": ctx["labels"].get(owner, "NOT_HIGH"),
        })
    row = by.get(D3D_FN, {})
    body = scan_body(blob, base, D3D_FN, ctx["sections"], limit=4000)
    # Linear listing of calls up to and just past Direct3DCreate9.
    md = _md()
    calls = []
    cur = D3D_FN
    for _ in range(400):
        insn = next(md.disasm(blob[cur - base:cur - base + 15], cur), None)
        if insn is None:
            break
        if insn.mnemonic == "call":
            if insn.operands and insn.operands[0].type == X86_OP_IMM:
                calls.append((insn.address, insn.operands[0].imm & 0xFFFFFFFF, "direct"))
            else:
                calls.append((insn.address, None, insn.op_str))
        if insn.mnemonic.startswith("ret"):
            break
        cur = insn.address + insn.size
        if insn.address > D3D_SITE + 32:
            break
    d3dx = []
    for thunk, meta in ctx["thunks"].items():
        symbol = meta.get("symbol") or ""
        if not symbol.startswith("D3DX"):
            continue
        call_sites = e8_to(blob, base, thunk)
        owners = []
        for eip in call_sites:
            owner, row_o = owner_of(vas, by, eip)
            owners.append({
                "site": eip,
                "owner": owner,
                "label": row_o.get("label"),
                "helper": ctx["labels"].get(owner, "NOT_HIGH"),
            })
        d3dx.append({
            "thunk": thunk,
            "symbol": symbol,
            "convention": meta.get("calling_convention"),
            "confidence": meta.get("confidence"),
            "owners": owners,
        })
    b_sites = e8_to(blob, base, UNKNOWN_B)
    b_owners = []
    for eip in b_sites:
        owner, row_o = owner_of(vas, by, eip)
        b_owners.append((eip, owner, row_o.get("label"), ctx["labels"].get(owner, "NOT_HIGH")))
    return {
        "function": row,
        "callers": callers,
        "body": body,
        "calls_before_return": calls,
        "d3dx": d3dx,
        "unknown_b": b_owners,
    }


def main():
    ctx = analyze()
    gfx = graphics(ctx)
    summary = {
        "high": ctx["high"],
        "direct_functions": ctx["direct_functions"],
        "direct_sites_reached": ctx["direct_sites_reached"],
        "span_only_sites": ctx["span_only_sites"],
        "map_recorded": ctx["map_recorded"],
        "counts": ctx["counts"],
        "old102_counts": ctx["old102_counts"],
        "old102_len": len(ctx["old102"]),
        "islands": [
            {k: (v if k != "imports" else v) for k, v in row.items()}
            for row in ctx["islands"]
        ],
        "graphics_label": gfx["function"].get("label"),
        "graphics_score": gfx["function"].get("score"),
        "graphics_reasons": gfx["function"].get("reasons"),
        "graphics_callers": gfx["callers"],
        "graphics_calls": gfx["calls_before_return"],
        "graphics_indirect": gfx["body"]["indirect"],
        "graphics_data": sorted(set(gfx["body"]["data"]))[:40],
        "graphics_rdata": sorted(set(gfx["body"]["rdata"]))[:40],
        "graphics_prot": gfx["body"]["prot"],
        "d3dx": gfx["d3dx"],
        "unknown_b": gfx["unknown_b"],
        "must_sample": sorted(va for va, lab in ctx["labels"].items() if lab == MUST)[:30],
        "direct_sample": sorted(ctx["confirmed"])[:40],
    }
    text = json.dumps(summary, indent=2, default=lambda o: hex(o) if isinstance(o, int) else list(o))
    out = os.path.join(ROOT, "analysis", "undercover", "phase14-summary.json")
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.write("\n")
    print("high", summary["high"])
    print("counts", summary["counts"])
    print("direct", summary["direct_functions"], "sites", summary["direct_sites_reached"], "span", summary["span_only_sites"])
    print("old102", summary["old102_len"], summary["old102_counts"])
    print("islands", [(hex(r["root"]), r["size"], r["subsystem"]) for r in summary["islands"][:10]])
    print("d3d", summary["graphics_label"], summary["graphics_score"], summary["graphics_callers"])
    print("wrote", out)


if __name__ == "__main__":
    main()
