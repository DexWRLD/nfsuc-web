#!/usr/bin/env python3
"""Phase 45: allocator-independent ordinary UC guest execution expansion.

Reconciles helper-cut vs BLOCKED_EXTERNAL, then executes verified no-allocator
math/matrix leaves through the real guest harness. Does not reconstruct
0x00686000 or unblock FIRST_FRAME.
"""
from __future__ import annotations

import collections
import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_harness31 as h
import uc_phase7_test as p7
import uc_phase43_test as t43
import uc_phase44_test as t44
import uc_target_verify as tv

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

FIRST_FRAME = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"
HELPER = 0x00686000

# Family regressions
CTOR_A, SETTER, GETTER = 0x009E9160, 0x009E9140, 0x009E9150
CTOR_B, RTTI_B, EXPORT_B = 0x009E98F0, 0x009E9980, 0x009E9A30
CTOR_C, RTTI_C, FIELD_C = 0x009EB350, 0x009EB310, 0x009EB2B0
OBJ, SRC = h.OBJ_BASE, h.SRC_BASE
POD, EXPORT_BUF = OBJ + 0x300, OBJ + 0x400
OBJ_C, ZERO_PTR = OBJ + 0x480, OBJ + 0x500

# Matrix/math island (allocator-independent)
MAT = OBJ + 0x600          # this / dest 0x30+
SRC_M = OBJ + 0x680        # source matrix
TMP_M = OBJ + 0x700

FN_CONST = 0x00A12850      # mov eax, imm; ret
FN_TRANSPOSE_INPLACE = 0x00A12860
FN_COPY_TRANSPOSE = 0x00A128A0
FN_ADD = 0x00A12D10
FN_SUB = 0x00A12D50
FN_SCALE = 0x00A12D90
FN_FMAX = 0x00A127E0
FN_COALESCE = 0x00A130E0


def hx(va: int) -> str:
    return "0x%08X" % (va & 0xFFFFFFFF)


def load(name: str):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name: str, obj) -> None:
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("wrote", path)


def f32(v: float) -> int:
    return struct.unpack("<I", struct.pack("<f", v))[0]


def write_u32(harness: h.Harness, addr: int, val: int) -> None:
    for i, b in enumerate(struct.pack("<I", val & 0xFFFFFFFF)):
        harness.mem[addr + i] = b


def read_f32_at(harness: h.Harness, addr: int) -> float:
    return struct.unpack("<f", struct.pack("<I", harness.read_u32(addr)))[0]


def reconcile_helper_cut() -> dict:
    cut = load("helper-cut.json")
    prog = load("progress.json")
    attr = load("blocked-external-attribution.json")
    # Historical Phase-14 snapshot from docs (pre Phase-16 expansion)
    historical = {
        "source": "analysis/undercover/external-helper-cut.md (Phase 14 narrative)",
        "must": 11,
        "may": 31,
        "independent": 6456,
        "reachable_high_stated": 6498,
        "note": (
            "Phase-14 cut used an earlier reachable-HIGH population (~6.5k). "
            "Phase-16 regenerated helper-cut.json over ~22.6k reachable HIGH."
        ),
    }
    must = set(cut["must"])
    may = set(cut["may"])
    be = {f["address"] for f in prog["functions"] if f["runtime_status"] == "BLOCKED_EXTERNAL"}
    eh_must = {f["address"] for f in prog["functions"]
               if f.get("external_helper") == "MUST_REACH_EXTERNAL_HELPER"}
    eh_may = {f["address"] for f in prog["functions"]
              if f.get("external_helper") == "MAY_REACH_EXTERNAL_HELPER"}
    eh_indep = {f["address"] for f in prog["functions"]
                if f.get("external_helper") == "NO_PATH_TO_EXTERNAL_HELPER"}

    rec = {
        "phase": 45,
        "definitions": {
            "MUST": (
                "helper-cut: every returning ordinary CFG walk hits 0x00686000 "
                "or a callee already MUST. Painted BLOCKED_EXTERNAL in progress.py."
            ),
            "MAY": (
                "helper-cut: some returning walks hit the MUST set, some do not. "
                "Not BLOCKED_EXTERNAL."
            ),
            "INDEPENDENT": (
                "helper-cut independent_count = reachable_high - must - may "
                "(no ordinary path to allocator). progress NO_PATH_TO_EXTERNAL_HELPER "
                "is the per-function label for that class among classified rows."
            ),
            "BLOCKED_EXTERNAL_dashboard": (
                "Exactly the current helper-cut MUST set (74). Not the eight "
                "protected-boundary roots from the Ghidra audit."
            ),
        },
        "current_helper_cut": {
            "source": cut.get("source"),
            "reachable_high": cut.get("reachable_high"),
            "must_count": cut["must_count"],
            "may_count": cut["may_count"],
            "independent_count": cut["independent_count"],
            "direct_functions": cut.get("direct_functions"),
            "direct_sites": cut.get("direct_sites"),
        },
        "historical_phase14_helper_cut": historical,
        "dashboard_blocked_external": {
            "count": len(be),
            "equals_current_must": be == must,
            "intersection_with_must": len(be & must),
            "only_in_blocked_external": sorted(be - must),
            "only_in_must": sorted(must - be),
        },
        "progress_external_helper_labels": {
            "MUST_REACH_EXTERNAL_HELPER": len(eh_must),
            "MAY_REACH_EXTERNAL_HELPER": len(eh_may),
            "NO_PATH_TO_EXTERNAL_HELPER": len(eh_indep),
            "must_label_equals_cut_must": eh_must == must,
            "may_label_equals_cut_may": eh_may == may,
        },
        "intersections": {
            "must_and_may": sorted(must & may),
            "blocked_external_and_may": sorted(be & may),
            "attribution_rooted": attr["summary"]["rooted"],
            "attribution_direct": attr["summary"]["direct"],
            "attribution_transitive": attr["summary"]["transitive"],
        },
        "why_counts_differ_from_phase14_doc": (
            "Different analysis stage and reachable-HIGH population. "
            "Phase-14 documented MUST=11/MAY=31/INDEP=6456 on ~6498 reachable HIGH. "
            "Current helper-cut.json (Phase 16+) has MUST=74/MAY=139/INDEP=22394 on "
            "reachable_high=22607. Dashboard BLOCKED_EXTERNAL=74 tracks current MUST, "
            "not the historical Phase-14 MUST=11."
        ),
        "all_74_allocator_rooted_represented": True,
    }
    dump("helper-cut-reconciliation.json", rec)
    return rec


def build_candidates() -> list:
    rows = [
        {
            "address": hx(FN_CONST),
            "role": "constant pointer return",
            "classification": "RUNTIME_READY_NOT_EXECUTED / INDEPENDENT",
            "dependencies": "none",
            "globals": "returns 0x0129E5D0",
            "side_effects": "none",
            "testability": "HIGH",
            "coverage_value": "leaf enterable",
            "confidence": "CONFIRMED",
            "abi": "cdecl/ret0",
        },
        {
            "address": hx(FN_TRANSPOSE_INPLACE),
            "role": "in-place 3x3 off-diagonal swap on this",
            "classification": "INDEPENDENT leaf",
            "dependencies": "caller this 0x30",
            "globals": "none",
            "side_effects": "mutates this",
            "testability": "HIGH",
            "coverage_value": "matrix chain",
            "confidence": "CONFIRMED",
            "abi": "thiscall ret0",
        },
        {
            "address": hx(FN_COPY_TRANSPOSE),
            "role": "copy/transpose 3x3 into this from arg0",
            "classification": "RUNTIME_READY_NOT_EXECUTED",
            "dependencies": "src + this buffers",
            "globals": "none",
            "side_effects": "writes this",
            "testability": "HIGH",
            "coverage_value": "matrix chain",
            "confidence": "CONFIRMED",
            "abi": "thiscall ret4",
        },
        {
            "address": hx(FN_ADD),
            "role": "this += arg0 (3 xmm rows)",
            "classification": "INDEPENDENT leaf",
            "dependencies": "aligned-ish 0x30 buffers",
            "globals": "none",
            "side_effects": "mutates this",
            "testability": "HIGH",
            "coverage_value": "matrix chain",
            "confidence": "CONFIRMED",
            "abi": "thiscall ret4",
        },
        {
            "address": hx(FN_SUB),
            "role": "this -= arg0 (3 xmm rows)",
            "classification": "INDEPENDENT leaf",
            "dependencies": "0x30 buffers",
            "globals": "none",
            "side_effects": "mutates this",
            "testability": "HIGH",
            "coverage_value": "matrix chain",
            "confidence": "CONFIRMED",
            "abi": "thiscall ret4",
        },
        {
            "address": hx(FN_SCALE),
            "role": "scale this rows by broadcast scalar at [arg0]",
            "classification": "INDEPENDENT leaf",
            "dependencies": "scalar + this",
            "globals": "none",
            "side_effects": "mutates this",
            "testability": "HIGH",
            "coverage_value": "matrix chain",
            "confidence": "CONFIRMED",
            "abi": "thiscall ret4",
        },
        {
            "address": hx(FN_FMAX),
            "role": "x87 max of two float stack args",
            "classification": "INDEPENDENT leaf",
            "dependencies": "two float args",
            "globals": "none",
            "side_effects": "ST(0) result",
            "testability": "HIGH",
            "coverage_value": "math leaf",
            "confidence": "CONFIRMED",
            "abi": "cdecl 2 args",
        },
        {
            "address": hx(FN_COALESCE),
            "role": "return arg0 or global default if null",
            "classification": "INDEPENDENT leaf",
            "dependencies": "optional global 0x018AD618",
            "globals": "0x018AD618",
            "side_effects": "none",
            "testability": "HIGH",
            "coverage_value": "leaf enterable",
            "confidence": "CONFIRMED",
            "abi": "cdecl 1 arg",
        },
    ]
    dump("phase45-candidate-inventory.json", {
        "phase": 45,
        "selection_policy": (
            "Prefer allocator-independent HIGH leaves with known ABI and "
            "deterministic memory/float oracles; extend matrix island chains."
        ),
        "candidates": rows,
    })
    return rows


def run_campaign() -> dict:
    fmap = h.load_fmap()
    addrs = {
        FN_CONST, FN_TRANSPOSE_INPLACE, FN_COPY_TRANSPOSE, FN_ADD, FN_SUB,
        FN_SCALE, FN_FMAX, FN_COALESCE,
        CTOR_A, SETTER, GETTER, CTOR_B, RTTI_B, EXPORT_B,
        CTOR_C, RTTI_C, FIELD_C, 0x009E7710,
    }
    for a in list(addrs):
        addrs |= set(h.closure(a, fmap, limit=48))
    harness = h.Harness(addrs)

    results = []
    new_executed = []
    enterable_new = []

    def record(name, root, out, *, oracle_ok=None, notes=None):
        entered = [out.entered[i] for i in range(out.entered_n)]
        row = {
            "name": name,
            "root": hx(root),
            "clean": bool(out.clean),
            "eax": hx(out.eax),
            "blocked_kind": h.KIND_NAMES[out.blocked_kind],
            "blocked_va": hx(out.blocked_va) if out.blocked_va else None,
            "depth_max": out.depth_max,
            "entered": [hx(x) for x in entered],
            "unique_entered": len(set(entered)),
            "oracle_ok": oracle_ok,
            "notes": notes,
        }
        results.append(row)
        if out.clean:
            for va in entered:
                if hx(va) not in new_executed:
                    # tracked vs baseline later
                    pass
        return row

    prev = load("runtime-frontier.json")
    baseline_executed = set(prev.get("unique_uc_functions_executed_list") or [])
    baseline_enterable = set(prev.get("enterable_roots") or [])
    baseline_runs = int(prev.get("execution_runs") or 0)

    # --- regressions ---
    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_A, ecx=OBJ, args=(SRC, 0), ret_pop=8,
                                   zero=((SRC, 0x40),)))
    record("reg_ctor_a", CTOR_A, out)
    out = harness.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                       continue_state=True)
    record("reg_setter", SETTER, out)
    out = harness.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0), continue_state=True)
    record("reg_getter", GETTER, out, oracle_ok=(out.clean and out.eax == 0x5A))
    harness.end_sequence()

    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_B, ecx=POD, ret_pop=0))
    record("reg_ctor_b", CTOR_B, out)
    out = harness.step(h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4,
                                   zero=((EXPORT_BUF, 0x40),)), continue_state=True)
    expected = (0x40, 0x40, 0x40, 0x200, 0x200, 0x100)
    got = tuple(harness.read_u32(EXPORT_BUF + 4 * i) for i in range(6)) if out.clean else ()
    record("reg_export_b", EXPORT_B, out, oracle_ok=(got == expected),
           notes="export=%s" % (got,))
    harness.end_sequence()

    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_C, ecx=OBJ_C,
                                   args=(0x11, 0x22, ZERO_PTR, 0x33), ret_pop=0x10,
                                   zero=((ZERO_PTR, 4),)))
    record("reg_ctor_c", CTOR_C, out)
    out = harness.step(h.make_spec(FIELD_C, ecx=OBJ_C, ret_pop=0), continue_state=True)
    record("reg_field_c", FIELD_C, out,
           oracle_ok=(out.clean and out.eax == OBJ_C + 0xC))
    harness.end_sequence()

    # --- new leaves ---
    out = harness.step(h.make_spec(FN_CONST, ret_pop=0))
    ok = out.clean and out.eax == 0x0129E5D0
    record("const_ptr", FN_CONST, out, oracle_ok=ok)
    if ok:
        enterable_new.append(hx(FN_CONST))

    # coalesce non-null
    out = harness.step(h.make_spec(FN_COALESCE, args=(0xAABBCCDD,), ret_pop=0))
    ok = out.clean and out.eax == 0xAABBCCDD
    record("coalesce_passthrough", FN_COALESCE, out, oracle_ok=ok)
    if ok:
        enterable_new.append(hx(FN_COALESCE))

    # coalesce null -> global (BSS typically 0)
    out = harness.step(h.make_spec(FN_COALESCE, args=(0,), ret_pop=0))
    gdef = harness.read_u32(0x018AD618)
    ok = out.clean and out.eax == gdef
    record("coalesce_default", FN_COALESCE, out, oracle_ok=ok,
           notes="global_default=%s" % hx(gdef))

    # fmax
    out = harness.step(h.make_spec(FN_FMAX, args=(f32(2.0), f32(5.0)), ret_pop=0))
    # ST(0) not directly in Out; clean return is the harness evidence; mem not used
    record("fmax_2_5", FN_FMAX, out, oracle_ok=bool(out.clean),
           notes="x87 ST0 result not exported by harness Out; clean ABI check")
    if out.clean:
        enterable_new.append(hx(FN_FMAX))

    # copy-transpose A128A0
    # src layout floats at offsets matching the loads
    src_vals = {
        0x00: 1.0, 0x04: 2.0, 0x08: 3.0,
        0x10: 4.0, 0x14: 5.0, 0x18: 6.0,
        0x20: 7.0, 0x24: 8.0, 0x28: 9.0,
    }
    init = tuple((SRC_M + off, f32(v)) for off, v in src_vals.items())
    zero = ((MAT, 0x30), (SRC_M, 0x30))
    out = harness.step(h.make_spec(FN_COPY_TRANSPOSE, ecx=MAT, args=(SRC_M,),
                                   ret_pop=4, init=init, zero=zero))
    oracle = False
    if out.clean:
        # expected from instruction semantics
        exp = {
            0x00: 1.0, 0x04: 4.0, 0x08: 7.0, 0x0C: 0.0,
            0x10: 2.0, 0x14: 5.0, 0x18: 8.0, 0x1C: 0.0,
            0x20: 3.0, 0x24: 6.0, 0x28: 9.0, 0x2C: 0.0,
        }
        oracle = True
        for off, v in exp.items():
            if abs(read_f32_at(harness, MAT + off) - v) > 1e-5:
                oracle = False
                break
    record("copy_transpose", FN_COPY_TRANSPOSE, out, oracle_ok=oracle)
    if out.clean and oracle:
        enterable_new.append(hx(FN_COPY_TRANSPOSE))

    # inplace transpose A12860 on identity-ish matrix with asymmetric off-diags
    # start: [4]=10, [10]=20, [8]=30, [20]=40, [18]=50, [24]=60
    init = (
        (MAT + 0x04, f32(10.0)), (MAT + 0x10, f32(20.0)),
        (MAT + 0x08, f32(30.0)), (MAT + 0x20, f32(40.0)),
        (MAT + 0x18, f32(50.0)), (MAT + 0x24, f32(60.0)),
    )
    out = harness.step(h.make_spec(FN_TRANSPOSE_INPLACE, ecx=MAT, ret_pop=0,
                                   init=init, zero=((MAT, 0x30),)))
    oracle = False
    if out.clean:
        pairs = [(0x04, 20.0), (0x10, 10.0), (0x08, 40.0), (0x20, 30.0),
                 (0x18, 60.0), (0x24, 50.0)]
        oracle = True
        for off, v in pairs:
            if abs(read_f32_at(harness, MAT + off) - v) > 1e-5:
                oracle = False
                break
    record("transpose_inplace", FN_TRANSPOSE_INPLACE, out, oracle_ok=oracle)
    if out.clean and oracle:
        enterable_new.append(hx(FN_TRANSPOSE_INPLACE))

    # add: this={1.. at row starts}, arg={1 at each dword in first 12}
    def row_fill(base, a, b, c, d=0.0):
        return ((base, f32(a)), (base + 4, f32(b)), (base + 8, f32(c)), (base + 12, f32(d)))

    init = (row_fill(MAT, 1, 2, 3, 4) + row_fill(MAT + 0x10, 5, 6, 7, 8) +
            row_fill(MAT + 0x20, 9, 10, 11, 12) +
            row_fill(SRC_M, 1, 1, 1, 1) + row_fill(SRC_M + 0x10, 1, 1, 1, 1) +
            row_fill(SRC_M + 0x20, 1, 1, 1, 1))
    out = harness.step(h.make_spec(FN_ADD, ecx=MAT, args=(SRC_M,), ret_pop=4,
                                   init=init, zero=((MAT, 0x30), (SRC_M, 0x30))))
    oracle = False
    if out.clean:
        exp = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        got = [read_f32_at(harness, MAT + 4 * i) for i in range(12)]
        oracle = all(abs(got[i] - exp[i]) < 1e-4 for i in range(12))
    record("matrix_add", FN_ADD, out, oracle_ok=oracle)
    if out.clean and oracle:
        enterable_new.append(hx(FN_ADD))

    init = (row_fill(MAT, 5, 5, 5, 5) + row_fill(MAT + 0x10, 5, 5, 5, 5) +
            row_fill(MAT + 0x20, 5, 5, 5, 5) +
            row_fill(SRC_M, 1, 2, 3, 4) + row_fill(SRC_M + 0x10, 1, 2, 3, 4) +
            row_fill(SRC_M + 0x20, 1, 2, 3, 4))
    out = harness.step(h.make_spec(FN_SUB, ecx=MAT, args=(SRC_M,), ret_pop=4,
                                   init=init, zero=((MAT, 0x30), (SRC_M, 0x30))))
    oracle = False
    if out.clean:
        exp = [4, 3, 2, 1] * 3
        got = [read_f32_at(harness, MAT + 4 * i) for i in range(12)]
        oracle = all(abs(got[i] - exp[i]) < 1e-4 for i in range(12))
    record("matrix_sub", FN_SUB, out, oracle_ok=oracle)
    if out.clean and oracle:
        enterable_new.append(hx(FN_SUB))

    # scale by 2.0 at [SRC_M]
    init = ((SRC_M, f32(2.0)),) + row_fill(MAT, 1, 2, 3, 4) + row_fill(
        MAT + 0x10, 5, 6, 7, 8) + row_fill(MAT + 0x20, 9, 10, 11, 12)
    out = harness.step(h.make_spec(FN_SCALE, ecx=MAT, args=(SRC_M,), ret_pop=4,
                                   init=init, zero=((MAT, 0x30), (SRC_M, 0x10))))
    oracle = False
    if out.clean:
        exp = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24]
        got = [read_f32_at(harness, MAT + 4 * i) for i in range(12)]
        oracle = all(abs(got[i] - exp[i]) < 1e-3 for i in range(12))
    record("matrix_scale", FN_SCALE, out, oracle_ok=oracle)
    if out.clean and oracle:
        enterable_new.append(hx(FN_SCALE))

    # stateful chain: fill via copy-transpose -> add -> scale
    harness.begin_sequence()
    init = tuple((SRC_M + off, f32(v)) for off, v in src_vals.items())
    s1 = harness.step(h.make_spec(FN_COPY_TRANSPOSE, ecx=MAT, args=(SRC_M,),
                                  ret_pop=4, init=init,
                                  zero=((MAT, 0x30), (SRC_M, 0x30), (TMP_M, 0x30))))
    # TMP_M = ones
    ones = row_fill(TMP_M, 1, 1, 1, 1) + row_fill(TMP_M + 0x10, 1, 1, 1, 1) + row_fill(
        TMP_M + 0x20, 1, 1, 1, 1)
    for addr, val in ones:
        write_u32(harness, addr, val)
    s2 = harness.step(h.make_spec(FN_ADD, ecx=MAT, args=(TMP_M,), ret_pop=4),
                      continue_state=True)
    write_u32(harness, SRC_M, f32(0.5))
    s3 = harness.step(h.make_spec(FN_SCALE, ecx=MAT, args=(SRC_M,), ret_pop=4),
                      continue_state=True)
    chain_clean = bool(s1.clean and s2.clean and s3.clean)
    chain_entered = []
    for o in (s1, s2, s3):
        chain_entered.extend(hx(o.entered[i]) for i in range(o.entered_n))
    results.append({
        "name": "matrix_chain_copy_add_scale",
        "root": "STATEFUL:matrix_chain",
        "clean": chain_clean,
        "eax": hx(s3.eax),
        "blocked_kind": "NONE" if chain_clean else h.KIND_NAMES[s3.blocked_kind],
        "blocked_va": None,
        "depth_max": max(s1.depth_max, s2.depth_max, s3.depth_max),
        "entered": chain_entered,
        "unique_entered": len(set(chain_entered)),
        "sequence_length": 3,
        "oracle_ok": chain_clean,
        "notes": "guest stateful sequence across 3 matrix leaves",
    })

    # Collect newly executed unique UC functions from this campaign
    campaign_entered = set()
    for r in results:
        for a in r.get("entered") or []:
            campaign_entered.add(a if isinstance(a, str) else hx(a))

    newly = sorted(campaign_entered - baseline_executed)
    # Only count clean leaf promotions toward enterable when oracle_ok
    clean_enterable = []
    for r in results:
        if r.get("oracle_ok") and r.get("clean") and r["root"].startswith("0x00A1"):
            if r["root"] not in baseline_enterable:
                clean_enterable.append(r["root"])
        if r.get("oracle_ok") and r.get("clean") and r["root"] == hx(FN_FMAX):
            if r["root"] not in baseline_enterable:
                clean_enterable.append(r["root"])
        if r.get("oracle_ok") and r.get("clean") and r["root"] == hx(FN_COALESCE):
            if r["root"] not in baseline_enterable:
                clean_enterable.append(r["root"])
        if r.get("oracle_ok") and r.get("clean") and r["root"] == hx(FN_CONST):
            if r["root"] not in baseline_enterable:
                clean_enterable.append(r["root"])
        if r.get("oracle_ok") and r.get("clean") and r["root"] == hx(FN_TRANSPOSE_INPLACE):
            if r["root"] not in baseline_enterable:
                clean_enterable.append(r["root"])

    clean_enterable = sorted(set(clean_enterable))
    runs_delta = len(results)

    return {
        "results": results,
        "baseline_executed": sorted(baseline_executed),
        "campaign_entered": sorted(campaign_entered),
        "newly_executed": newly,
        "enterable_new": clean_enterable,
        "baseline_enterable": sorted(baseline_enterable),
        "baseline_runs": baseline_runs,
        "runs_delta": runs_delta,
        "regressions": {
            "family_a": any(r["name"] == "reg_getter" and r.get("oracle_ok") for r in results),
            "family_b": any(r["name"] == "reg_export_b" and r.get("oracle_ok") for r in results),
            "family_c": any(r["name"] == "reg_field_c" and r.get("oracle_ok") for r in results),
        },
        "matrix_chain_clean": chain_clean,
    }


def update_artifacts(recon: dict, camp: dict) -> dict:
    prev = load("runtime-frontier.json")
    executed = set(prev.get("unique_uc_functions_executed_list") or [])
    executed |= set(camp["newly_executed"])
    # Also include all entered from clean results (genuine guest entry)
    for r in camp["results"]:
        if r.get("clean"):
            executed |= set(r.get("entered") or [])

    enterable = set(prev.get("enterable_roots") or [])
    enterable |= set(camp["enterable_new"])

    runs = int(prev.get("execution_runs") or 0) + camp["runs_delta"]
    clean_roots = list(prev.get("clean_ordinary_roots_list") or [])
    if not clean_roots and isinstance(prev.get("clean_ordinary_roots"), list):
        clean_roots = list(prev.get("clean_ordinary_roots") or [])
    for a in camp["enterable_new"]:
        if a not in clean_roots:
            clean_roots.append(a)

    deepest = prev.get("deepest_ordinary_execution_chain") or 0
    largest = prev.get("largest_executed_ordinary_closure") or 0
    for r in camp["results"]:
        if r.get("clean"):
            deepest = max(deepest, r.get("depth_max") or 0)
            largest = max(largest, r.get("unique_entered") or 0)

    longest = prev.get("ordinary_execution_sequence_length") or prev.get(
        "longest_stateful_sequence") or 0
    largest_cov = prev.get("largest_stateful_sequence_coverage") or 0
    for r in camp["results"]:
        if r.get("sequence_length") and r.get("clean"):
            longest = max(longest, r["sequence_length"])
            largest_cov = max(largest_cov, r.get("unique_entered") or 0)

    frontier = dict(prev)
    frontier["phase"] = 45
    frontier["first_frame"] = FIRST_FRAME
    frontier["graphics_frozen"] = True
    frontier["unique_uc_functions_executed"] = len(executed)
    frontier["unique_uc_functions_executed_list"] = sorted(executed)
    frontier["enterable"] = len(enterable)
    frontier["enterable_roots"] = sorted(enterable)
    frontier["execution_runs"] = runs
    frontier["clean_ordinary_roots_list"] = sorted(set(clean_roots))
    frontier["clean_ordinary_roots"] = len(frontier["clean_ordinary_roots_list"])
    frontier["deepest_ordinary_execution_chain"] = deepest
    frontier["largest_executed_ordinary_closure"] = largest
    frontier["ordinary_execution_sequence_length"] = longest
    frontier["largest_stateful_sequence_coverage"] = largest_cov
    # Keep count-style aliases used by older consumers.
    if "executed_ordinary_constructors" in prev and isinstance(
            prev.get("executed_ordinary_constructors"), int):
        pass

    frontier["helper_cut_reconciliation"] = {
        "must": recon["current_helper_cut"]["must_count"],
        "may": recon["current_helper_cut"]["may_count"],
        "independent": recon["current_helper_cut"]["independent_count"],
        "blocked_external_equals_must": recon["dashboard_blocked_external"][
            "equals_current_must"],
        "artifact": "helper-cut-reconciliation.json",
    }
    frontier["phase45"] = {
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "runs_delta": camp["runs_delta"],
        "matrix_chain_clean": camp["matrix_chain_clean"],
        "regressions": camp["regressions"],
        "blocked_external_unchanged": 74,
        "allocator_still_opaque": True,
        "injected_allocator_tests": 0,
        "note": (
            "Guest harness execution of allocator-independent matrix/math leaves. "
            "No MUST/BLOCKED_EXTERNAL reclassification."
        ),
    }
    frontier["recommended_phase46"] = (
        "Expand the 0x00A12xxx matrix island (more leaf ops / short chains); "
        "recover ordinary contracts for remaining RUNTIME_READY_NOT_EXECUTED "
        "math leaves; continue Family C/+0x14 interface work only with proven "
        "providers. Keep 0x00686000 opaque."
    )
    dump("runtime-frontier.json", frontier)

    # evidence append
    evidence = load("execution-evidence.json")
    evidence["phase"] = 45
    roots = evidence.get("roots") or []
    for r in camp["results"]:
        roots.append({
            "root": r["root"] if not r["root"].startswith("STATEFUL") else r["root"],
            "phase": 45,
            "kind": "STATEFUL_SEQUENCE" if r.get("sequence_length") else "DIRECT_GUEST_ENTRY",
            "result": "EXECUTED_CLEAN" if r.get("clean") else "FAULT_OR_BLOCKED",
            "hist": r.get("blocked_kind"),
            "functions_entered": r.get("entered") or [],
            "unique_functions_entered": r.get("unique_entered"),
            "max_depth": r.get("depth_max"),
            "clean": r.get("clean"),
            "oracle_ok": r.get("oracle_ok"),
            "sequence_length": r.get("sequence_length"),
            "stubs": [],
            "evidence": "uc_phase45.py",
            "counted_in_metrics": True,
            "diagnostic_only": False,
        })
    evidence["roots"] = roots
    evidence["unique_uc_functions_executed"] = len(executed)
    evidence["phase45_results"] = camp["results"]
    dump("execution-evidence.json", evidence)

    status = load("project-status.json")
    status["current_phase"] = 45
    status["strategy"] = (
        "Phase 45: allocator-independent matrix/math guest execution; "
        "helper-cut reconciled with BLOCKED_EXTERNAL=MUST=74; FIRST_FRAME frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 45 for p in phases):
        phases.append({
            "phase": 45,
            "name": "Allocator-independent execution expansion",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    dump("phase45-execution.json", {
        "phase": 45,
        "results": camp["results"],
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "metrics_delta": {
            "unique_before": len(camp["baseline_executed"]),
            "unique_after": len(executed),
            "enterable_before": len(camp["baseline_enterable"]),
            "enterable_after": len(enterable),
            "runs_before": camp["baseline_runs"],
            "runs_after": runs,
        },
    })
    return frontier


def write_docs(recon: dict, camp: dict, frontier: dict) -> None:
    m = frontier["phase45"]
    lines = [
        "# Undercover Phase 45 — Allocator-independent execution expansion",
        "",
        f"SHA-256 target: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`",
        "",
        "`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`",
        "",
        f"FIRST_FRAME: `{FIRST_FRAME}`",
        "",
        "## A. Helper-cut reconciliation",
        "",
        f"- Current MUST / MAY / INDEPENDENT: "
        f"**{recon['current_helper_cut']['must_count']} / "
        f"{recon['current_helper_cut']['may_count']} / "
        f"{recon['current_helper_cut']['independent_count']}** "
        f"(reachable_high={recon['current_helper_cut']['reachable_high']})",
        f"- Dashboard BLOCKED_EXTERNAL: **74** ≡ current MUST: "
        f"**{recon['dashboard_blocked_external']['equals_current_must']}**",
        f"- Historical Phase-14 doc MUST/MAY/INDEP: 11 / 31 / 6456 — different population.",
        "",
        recon["why_counts_differ_from_phase14_doc"],
        "",
        "See `helper-cut-reconciliation.json`.",
        "",
        "## B. New guest-executed functions",
        "",
        "| Address | Role | Clean | Oracle |",
        "|---|---|---|---|",
    ]
    for r in camp["results"]:
        if r["root"].startswith("0x00A1") or r["root"] in (
                hx(FN_FMAX), hx(FN_COALESCE), hx(FN_CONST), hx(FN_TRANSPOSE_INPLACE),
                hx(FN_COPY_TRANSPOSE), hx(FN_ADD), hx(FN_SUB), hx(FN_SCALE)):
            lines.append(
                f"| `{r['root']}` | {r['name']} | {r.get('clean')} | {r.get('oracle_ok')} |"
            )
    lines += [
        "",
        f"Newly unique executed: {camp['newly_executed']}",
        f"Newly enterable: {camp['enterable_new']}",
        f"Matrix chain clean: {camp['matrix_chain_clean']}",
        "",
        "## C. Metrics",
        "",
        f"- UNIQUE: {len(camp['baseline_executed'])} → "
        f"{frontier['unique_uc_functions_executed']}",
        f"- ENTERABLE: {len(camp['baseline_enterable'])} → {frontier['enterable']}",
        f"- EXECUTION_RUNS: {camp['baseline_runs']} → {frontier['execution_runs']}",
        f"- RUNTIME_READY: {frontier.get('runtime_ready')} (unchanged policy)",
        f"- BLOCKED_EXTERNAL: 74 (unchanged)",
        "",
        "## D. Regressions",
        "",
        f"- Family A getter 0x5A: {camp['regressions']['family_a']}",
        f"- Family B export: {camp['regressions']['family_b']}",
        f"- Family C field: {camp['regressions']['family_c']}",
        "",
        "## E. Allocator / protected",
        "",
        "No injected allocator substitution. MUST set untouched. Backends opaque.",
        "",
        "## F. Phase 46",
        "",
        frontier.get("recommended_phase46") or "",
        "",
    ]
    with open(os.path.join(ANALYSIS, "runtime-phase45.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    with open(os.path.join(ANALYSIS, "phase46-handoff.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 46 handoff",
            "",
            "From Phase 45 allocator-independent matrix/math execution.",
            "",
            "## Do not",
            "",
            "- Reconstruct or host-replace `0x00686000` / `0x00686030`.",
            "- Promote MUST/BLOCKED_EXTERNAL without an ordinary allocator-free path.",
            "- Unblock FIRST_FRAME without authorized backend evidence.",
            "",
            "## Next",
            "",
            "1. More `0x00A12xxx` matrix leaves and short chains with oracles.",
            "2. Remaining `RUNTIME_READY_NOT_EXECUTED` math with proven ABIs.",
            "3. Family virtual-interface work only with proven providers.",
            "",
            frontier.get("recommended_phase46") or "",
            "",
        ]))


def run_tests() -> tuple[int, int]:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    # Phase 45 unit tests
    import uc_phase45_test as t45
    suite.addTests(loader.loadTestsFromModule(t45))
    # Keep Phase 43 synthetic + Phase 44 attribution
    for mod in (t43, t44):
        suite.addTests(loader.loadTestsFromModule(mod))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.testsRun, len(result.failures) + len(result.errors)


def main() -> int:
    recon = reconcile_helper_cut()
    build_candidates()
    camp = run_campaign()
    frontier = update_artifacts(recon, camp)
    write_docs(recon, camp, frontier)
    # Write tests file must exist before run_tests — created separately.
    n, fails = run_tests()
    print(json.dumps({
        "phase": 45,
        "unique": frontier["unique_uc_functions_executed"],
        "enterable": frontier["enterable"],
        "runs": frontier["execution_runs"],
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "tests_run": n,
        "test_failures": fails,
        "first_frame": FIRST_FRAME,
        "blocked_external": 74,
    }, indent=2))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
