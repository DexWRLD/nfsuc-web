"""Phase 16 measurements after CFG discovery repair.

Ordinary .text and existing analysis only. Does not execute the game,
implement Direct3D/TLS/Win32, or substitute 0x00686000.
"""
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

import uc_code_analyze as uca
import uc_frontier as uf
import uc_initprov as ip
import uc_phase7_test as p7
import uc_phase14_cut as cut
import uc_phase15_graphics as g15

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")

HELPER = 0x00686000
UNKNOWN_B = 0x0055FF30
D3D_THUNK = 0x0087A79C
GFX = (0x00766730, 0x0072E5D0, 0x0072E340, 0x0072DD00)
FLAG_WRITER = 0x00722D60
SLOTS = {
    0x00B611D4: 0x008A9F58,
    0x00B61188: 0x008AB180,
    0x00B615C4: 0x008AA3AE,
}
TLS = 0x01882C34
OBJ = 0x01318170


def hx(n):
    return f"0x{n & 0xffffffff:08X}"


def load_map():
    data = json.load(open(os.path.join(ANALYSIS, "function-map.json"), encoding="utf-8"))
    by = {int(row["va"], 16): row for row in data["functions"]}
    return data, by


def e8_sites(blob, base, dest):
    sites = []
    for off in range(len(blob) - 5):
        if blob[off] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        if (base + off + 5 + rel) & 0xFFFFFFFF == dest:
            sites.append((base + off, "call" if blob[off] == 0xE8 else "jmp"))
    return sites


def abs_refs(blob, base, value):
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    out = []
    start = 0
    while True:
        off = blob.find(needle, start)
        if off < 0:
            break
        out.append(base + off)
        start = off + 1
    return out


def owner_of(vas, by, eip):
    import bisect
    i = bisect.bisect_right(vas, eip) - 1
    if i < 0:
        return None, {}
    owner = vas[i]
    return owner, by.get(owner, {})


def classify_slot(blob, base, starts, by, slot_va, value):
    if value == 0:
        return "DATA"
    if not (base <= value < base + len(blob)):
        return "UNKNOWN"
    on = 0 <= (value - base) < len(blob) and starts[value - base] == 1
    if value in by and by[value].get("label") == "HIGH_CONFIDENCE":
        return "VALID_FUNCTION_ENTRY"
    if on and value in by:
        return "VALID_FUNCTION_ENTRY"
    # Interior: value is inside some HIGH function's owned span estimated by next entry.
    vas = sorted(by)
    owner, row = owner_of(vas, by, value)
    if owner is not None and row.get("label") == "HIGH_CONFIDENCE" and owner < value:
        if on:
            return "VALID_INTERIOR_ENTRY"
        return "INVALID_INSTRUCTION_BOUNDARY"
    if on:
        return "SHARED_CODE_ENTRY"
    if not on:
        return "INVALID_INSTRUCTION_BOUNDARY"
    return "UNKNOWN"


def shortest_pred_chain(by, target, pred_index, high_only=False, max_depth=12):
    """BFS predecessors of target through reverse call/tail edges."""
    goal = target
    queue = collections.deque([(goal, [goal])])
    seen = {goal}
    best = None
    while queue:
        node, path = queue.popleft()
        if len(path) > 1:
            row = by.get(path[-1], {})
            if not high_only or (row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable")):
                if best is None or len(path) < len(best):
                    best = path
        if len(path) >= max_depth:
            continue
        for pred in pred_index.get(node, ()):
            if pred in seen:
                continue
            seen.add(pred)
            queue.append((pred, path + [pred]))
    return best


def build_pred_index(by):
    pred = collections.defaultdict(set)
    for va, row in by.items():
        if not row.get("reachable"):
            continue
        for key in ("calls", "tails"):
            for text in row.get(key) or []:
                pred[int(text, 16)].add(va)
    return pred


def cohort_outcomes(old_cohort, by):
    counts = collections.Counter()
    for text in old_cohort:
        va = int(text, 16)
        row = by.get(va)
        if not row:
            counts["OTHER"] += 1
            continue
        if row.get("budget_exceeded") or row.get("termination") == "CFG_BUDGET_EXCEEDED":
            counts["CFG_BUDGET_EXCEEDED"] += 1
        elif row["label"] == "HIGH_CONFIDENCE" and row.get("reachable"):
            counts["PROMOTED_HIGH"] += 1
        elif row["label"] == "MEDIUM_CONFIDENCE":
            counts["REMAINS_MEDIUM"] += 1
        elif row["label"] == "LOW_CONFIDENCE":
            counts["DEMOTED_LOW"] += 1
        elif row["label"] == "REJECTED_DATA_LIKE":
            counts["REJECTED_DATA"] += 1
        elif row.get("termination") == "EXTERNAL_BOUNDARY":
            counts["EXTERNAL_BOUNDARY"] += 1
        else:
            counts["OTHER"] += 1
    return dict(counts)


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    image = p7.read_sections(game)
    data, by = load_map()
    old = json.load(open(os.path.join(ANALYSIS, "phase16-old-24-cohort.json"), encoding="utf-8"))
    try:
        old_map = json.load(open(os.path.join(ANALYSIS, "phase16-old-function-map.json"), encoding="utf-8-sig"))
    except Exception:
        old_map = {"counts": old["counts"], "covered_bytes": old["covered_bytes"], "functions": []}

    starts = bytearray(len(blob))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    off = 0
    while off < len(blob):
        found = list(md.disasm(blob[off:off + 65536], base + off))
        if not found:
            off += 1
            continue
        for insn in found:
            rel = insn.address - base
            if 0 <= rel < len(blob):
                starts[rel] = 1
        off = found[-1].address + found[-1].size - base

    high = {va for va, row in by.items() if row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable")}
    old_high = {
        int(f["va"], 16)
        for f in old_map.get("functions") or []
        if f.get("label") == "HIGH_CONFIDENCE" and f.get("reachable")
    }
    newly_high = sorted(high - old_high)

    # Helper cut via existing Phase 14 machinery.
    print("computing helper cut", file=sys.stderr)
    ctx = cut.analyze()
    must_list = sorted(va for va, lab in ctx["labels"].items() if lab == cut.MUST)
    may_list = sorted(va for va, lab in ctx["labels"].items() if lab == cut.MAY)
    none_list = sorted(va for va, lab in ctx["labels"].items() if lab == cut.NONE)
    must, may, none = len(must_list), len(may_list), len(none_list)
    helper_doc = {
        "source": "tools/uc_phase16.py + uc_phase14_cut.analyze(); reachable high-confidence call graph",
        "reachable_high": len(ctx["high_list"]),
        "must_count": must,
        "may_count": may,
        "independent_count": none,
        "direct_functions": ctx["direct_functions"],
        "direct_sites": ctx["direct_sites_reached"],
        "must": [hx(va) for va in must_list],
        "may": [hx(va) for va in may_list],
        "independent_sample": [hx(va) for va in none_list[:40]],
    }
    with open(os.path.join(ANALYSIS, "helper-cut.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(helper_doc, fh, indent=2)
        fh.write("\n")

    pred = build_pred_index(by)
    d3d_chain = shortest_pred_chain(by, D3D_THUNK, pred, high_only=False)
    d3d_high_chain = shortest_pred_chain(by, D3D_THUNK, pred, high_only=True)

    # Reachability of Direct3DCreate9 from any READY/high seed is deferred to frontier.
    writer_callers = e8_sites(blob, base, FLAG_WRITER)
    writer_abs = abs_refs(blob, base, FLAG_WRITER)
    writer_preds = sorted(pred.get(FLAG_WRITER, ()))

    slot_class = {}
    for slot, value in SLOTS.items():
        slot_class[hx(slot)] = {
            "value": hx(value),
            "class": classify_slot(blob, base, starts, by, slot, value),
            "in_map": value in by,
            "map_label": (by.get(value) or {}).get("label"),
        }

    # TLS absolute writes in ordinary .text among newly promoted / all HIGH.
    tls_writes = []
    for kind, eip, text, conf in [ip.classify_encoding(blob, base, o, TLS) for o in ip.iter_immediates(blob, base, TLS)]:
        if kind != "WRITE":
            continue
        owner, row = owner_of(sorted(by), by, eip)
        tls_writes.append({"eip": hx(eip), "owner": hx(owner) if owner else None, "label": row.get("label"), "text": text})

    obj_refs = []
    for kind, eip, text, conf in [ip.classify_encoding(blob, base, o, OBJ) for o in ip.iter_immediates(blob, base, OBJ)]:
        owner, row = owner_of(sorted(by), by, eip)
        obj_refs.append({
            "kind": kind, "eip": hx(eip), "owner": hx(owner) if owner else None,
            "label": row.get("label"), "reachable": row.get("reachable"), "text": text, "conf": conf,
        })

    gfx_rows = {}
    for va in GFX + (FLAG_WRITER,):
        row = by.get(va, {})
        gfx_rows[hx(va)] = {
            "label": row.get("label"),
            "score": row.get("score"),
            "reachable": row.get("reachable"),
            "insns": row.get("insns"),
            "blocks": row.get("blocks"),
            "termination": row.get("termination"),
            "calls": row.get("calls"),
            "tails": row.get("tails"),
            "callers_e8": [hx(s) for s, _k in e8_sites(blob, base, va)],
            "pred": [hx(p) for p in sorted(pred.get(va, ()))],
        }

    b_sites = e8_sites(blob, base, UNKNOWN_B)
    b_owners = []
    for eip, kind in b_sites:
        owner, row = owner_of(sorted(by), by, eip)
        b_owners.append({
            "site": hx(eip), "kind": kind, "owner": hx(owner) if owner else None,
            "label": row.get("label"), "reachable": row.get("reachable"),
        })

    # Independent-of-helper chain for D3D: walk predecessors that are NO_PATH.
    indep_chain = None
    if d3d_chain:
        labels = ctx["labels"]
        if all(labels.get(va, cut.NONE) == cut.NONE for va in d3d_chain if va in high or va == D3D_THUNK):
            indep_chain = [hx(v) for v in d3d_chain]

    hc = json.load(open(os.path.join(ANALYSIS, "high-confidence.json"), encoding="utf-8"))
    out = {
        "old_counts": old_map.get("counts") or old["counts"],
        "new_counts": data["counts"],
        "old_covered_bytes": old_map.get("covered_bytes") or old["covered_bytes"],
        "new_covered_bytes": data["covered_bytes"],
        "text_size": data["text_size"],
        "old_coverage_pct": round(100 * (old_map.get("covered_bytes") or old["covered_bytes"]) / data["text_size"], 2),
        "new_coverage_pct": round(100 * data["covered_bytes"] / data["text_size"], 2),
        "cohort_size": old["cohort_size"],
        "cohort_outcomes": cohort_outcomes(old["cohort"], by),
        "cfg_budget_exceeded": data.get("cfg_budget_exceeded"),
        "strong_cfg_enrolled": data.get("strong_cfg_enrolled"),
        "termination_counts": data.get("termination_counts"),
        "newly_high_count": len(newly_high),
        "lost_high_count": len(old_high - high),
        "generation": hc,
        "helper_cut": {"MUST": must, "MAY": may, "NO_PATH": none, "high": len(ctx["high_list"])},
        "unknown_b": b_owners,
        "graphics": gfx_rows,
        "d3d_shortest_chain": [hx(v) for v in d3d_chain] if d3d_chain else None,
        "d3d_high_chain": [hx(v) for v in d3d_high_chain] if d3d_high_chain else None,
        "d3d_independent_chain": indep_chain,
        "flag_writer_e8_callers": len(writer_callers),
        "flag_writer_abs_refs": len(writer_abs),
        "flag_writer_preds": [hx(p) for p in writer_preds],
        "slots": slot_class,
        "tls_writes": tls_writes,
        "object_refs": obj_refs[:80],
        "object_ref_kinds": dict(collections.Counter(r["kind"] for r in obj_refs)),
        "phase5_failures": {
            hx(va): (by.get(va) or {}).get("label")
            for va in (0x00401DC0, 0x00780150, 0x007C8350, 0x007C9010, 0x00841BF0, 0x00A945E0)
        },
    }
    path = os.path.join(ANALYSIS, "phase16-raw.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print("HIGH", data["counts"]["HIGH_CONFIDENCE"], "covered", out["new_coverage_pct"])
    print("cohort", out["cohort_outcomes"])
    print("cut", out["helper_cut"])
    print("d3d", out["d3d_shortest_chain"])
    print("writer preds", out["flag_writer_preds"], "e8", out["flag_writer_e8_callers"])
    print("slots", {k: v["class"] for k, v in slot_class.items()})
    print("wrote", path)


if __name__ == "__main__":
    main()
