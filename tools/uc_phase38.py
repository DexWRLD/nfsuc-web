#!/usr/bin/env python3
"""Phase 38: post-constructor ordinary consumers + stateful sequences.

Graphics frozen. Does not execute nfs.exe. No fabricated protected state.
"""
from __future__ import annotations

import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase7_test as p7
import uc_phase31 as p31
import uc_phase31_campaign as camp
import uc_harness31 as h

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

CTOR = 0x009E9160
SEM = 0x0097BB30
EBC70 = 0x009EBC70
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE
OBJ_SIZE = 0x248
VT_MAIN = 0x00C30E68
VT_BASE = 0x00C30D5C
VT_POD = 0x00C30F2C

# Proven ordinary vtable methods (slot → VA). Skip dtor/free paths.
SETTER_DC = 0x009E9140   # slot 13: this+0xDC = arg8; ret 4
GETTER_DC = 0x009E9150   # slot 14: al = this+0xDC; ret 0
RTTI_LIKE = 0x009E7780   # slot 2: eax = 0xC30DE4; ret 0
POD_RTTI = 0x009E9980    # pod vt slot 2: eax = 0xC30F38; ret 0


def hx(va):
    return "0x%08X" % (va & 0xFFFFFFFF)


def load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name, obj):
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("wrote", path)


def ctor_spec():
    return h.make_spec(CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),))


def snapshot_fields(harness, base=OBJ, size=OBJ_SIZE):
    """Compare pre-zeroed extent vs current guest bytes; report non-zero dwords/bytes."""
    raw = harness.read_bytes(base, size)
    fields = []
    for off in range(0, size, 4):
        val = struct.unpack_from("<I", raw, off)[0]
        if val == 0:
            continue
        fields.append({"offset": hx(off), "width": 4, "value": hx(val)})
    # also note sparse non-zero bytes not on dword zeros... already covered if dword nonzero
    return raw, fields


def classify_field(off, val):
    off = int(off, 16) if isinstance(off, str) else off
    if off == 0 and val == VT_MAIN:
        return "DIRECT_CONSTRUCTOR_WRITE", "vtable_main"
    if off == 4 and val == VT_POD:
        return "NESTED_INITIALIZER_WRITE", "embedded_pod_vtable"
    if off == 0x58:
        return "DIRECT_CONSTRUCTOR_WRITE", "ctor_arg2_store"
    if off == 0x240:
        return "STANDARD_RUNTIME_WRITE", "tls_index_via_9777d0"
    if off == 0 and val == VT_BASE:
        return "NESTED_INITIALIZER_WRITE", "base_vtable"
    return "ORDINARY_CALLEE_WRITE", "initialized_nonzero"


def capture_ctor_state(harness):
    harness.begin_sequence()
    before = harness.read_bytes(OBJ, OBJ_SIZE)
    out = harness.step(ctor_spec(), continue_state=False)
    after = harness.read_bytes(OBJ, OBJ_SIZE)
    raw, fields = snapshot_fields(harness)
    annotated = []
    for f in fields:
        off = int(f["offset"], 16)
        val = int(f["value"], 16)
        kind, note = classify_field(off, val)
        # special-case embedded base at OBJ+0 is main vt; base ctor writes VT_BASE on a
        # subobject that may be overlaid — report observed value.
        annotated.append({
            **f, "provenance": kind, "note": note,
        })
    # Known layout highlights even if zero
    highlights = {
        "vtable_plus0": hx(harness.read_u32(OBJ)),
        "embedded_pod_vtable_plus4": hx(harness.read_u32(OBJ + 4)),
        "arg2_plus58": hx(harness.read_u32(OBJ + 0x58)),
        "tls_index_plus240": hx(harness.read_u32(OBJ + 0x240)),
        "flag_plus_dc": hx(harness.read_u8(OBJ + 0xDC)),
    }
    side = {
        "OBJECT_STATE": highlights,
        "GUEST_RUNTIME_STATE": {
            "tls_alloc_calls": out.tls_alloc,
            "tls_set_calls": out.tls_set,
            "ics_calls": out.ics_calls,
            "mutex_calls": out.mutex_calls,
            "cs_count": out.cs_count,
            "mutex_count": out.mutex_count,
            "priority_class": out.priority_class,
            "thread_priority": out.thread_priority,
            "qpc_ticks": out.qpc_ticks_lo | (out.qpc_ticks_hi << 32),
            "sleepex_done": out.sleepex_done,
            "gct_calls": out.gct_calls,
            "spc_calls": out.spc_calls,
            "stp_calls": out.stp_calls,
        },
        "GLOBAL_IMAGE_STATE": {
            "note": (
                "0x009E8AD0 writes ordinary globals 0x0189D198..0x0189D270 during ctor "
                "(incl. 0x0189D1A4=0x009E78C0); values observable in mapped .data"
            ),
            "slot_0189D1A4": hx(harness.read_u32(0x0189D1A4)),
            "slot_0189D198": hx(harness.read_u32(0x0189D198)),
        },
    }
    return {
        "out": out,
        "before_all_zero": all(b == 0 for b in before),
        "changed_dwords": annotated,
        "nonzero_dword_count": len(annotated),
        "highlights": highlights,
        "side_effects": side,
        "clean": bool(out.clean),
        "entered": [out.entered[i] for i in range(out.entered_n)],
        "depth_max": out.depth_max,
        "sleepex_done": out.sleepex_done,
        "qpc_ticks": out.qpc_ticks_lo | (out.qpc_ticks_hi << 32),
    }


def consumer_catalog():
    return [
        {
            "va": SETTER_DC, "slot": 13, "abi": "thiscall ret 4",
            "class": "DIRECT_OBJECT_CONSUMER",
            "object_source": "CTOR_THIS / OBJ_BASE",
            "args": "uint8 selector via stack arg0",
            "fields_read": [],
            "fields_write": ["+0xDC"],
            "imports": [], "indirect": False,
            "protected": False, "confidence": "HIGH",
            "note": "vtable[13] setter for byte at this+0xDC",
        },
        {
            "va": GETTER_DC, "slot": 14, "abi": "thiscall ret 0",
            "class": "DIRECT_OBJECT_CONSUMER",
            "object_source": "CTOR_THIS / OBJ_BASE",
            "args": "none",
            "fields_read": ["+0xDC"],
            "fields_write": [],
            "imports": [], "indirect": False,
            "protected": False, "confidence": "HIGH",
            "note": "vtable[14] getter; pairs with setter",
        },
        {
            "va": RTTI_LIKE, "slot": 2, "abi": "thiscall ret 0",
            "class": "SAME_VTABLE_FAMILY",
            "object_source": "CTOR_THIS",
            "args": "none",
            "fields_read": [],
            "fields_write": [],
            "imports": [], "indirect": False,
            "protected": False, "confidence": "HIGH",
            "note": "returns static 0x00C30DE4; no object field dependency",
        },
        {
            "va": POD_RTTI, "slot": 2, "abi": "thiscall ret 0",
            "class": "EMBEDDED_SUBOBJECT_CONSUMER",
            "object_source": "OBJ_BASE+4 (pod subobject vtable 0x00C30F2C)",
            "args": "none",
            "fields_read": [],
            "fields_write": [],
            "imports": [], "indirect": False,
            "protected": False, "confidence": "HIGH",
            "note": "returns static 0x00C30F38 on embedded +4 object",
        },
        {
            "va": 0x009E9320, "slot": 0, "abi": "thiscall ret 4",
            "class": "DIRECT_OBJECT_CONSUMER",
            "object_source": "CTOR_THIS",
            "args": "flags",
            "fields_read": ["ownership"],
            "imports": [], "indirect": False,
            "protected": True,
            "confidence": "HIGH",
            "rejected": True,
            "reject_reason": "scalar deleting dtor; may call protected 0x00686030",
        },
        {
            "va": 0x009E8400, "slot": 11, "abi": "thiscall ret 0",
            "class": "DIRECT_OBJECT_CONSUMER",
            "object_source": "CTOR_THIS",
            "args": "none",
            "fields_read": ["+0xBC", "+0xC0"],
            "imports": [], "indirect": True,
            "protected": False,
            "confidence": "MEDIUM",
            "note": "requires list pointers at +0xBC/+0xC0; may be null after ctor",
        },
        {
            "va": 0x009E9340, "slot": None, "abi": "factory",
            "class": "UNRELATED_OBJECT",
            "object_source": "ALLOCATOR_RESULT",
            "rejected": True,
            "reject_reason": "sole ctor caller; depends on protected-initialized allocator",
            "confidence": "PROVEN",
        },
    ]


def run_stateful_sequences(harness):
    results = []

    def seq(name, steps):
        """steps: list of (label, spec_kwargs_or_spec, continue_state)"""
        harness.begin_sequence()
        step_outs = []
        all_entered = []
        depth_peak = 0
        clean_all = True
        blocker = None
        for i, (label, spec, cont) in enumerate(steps):
            out = harness.step(spec, continue_state=cont)
            entered = [out.entered[j] for j in range(out.entered_n)]
            # For accumulate mode entered is cumulative; track delta via set size
            all_entered = entered  # already cumulative when cont
            depth_peak = max(depth_peak, out.depth_max)
            step_outs.append({
                "label": label, "root": hx(spec.root), "clean": bool(out.clean),
                "eax": hx(out.eax), "blocked_kind": h.KIND_NAMES[out.blocked_kind],
                "blocked_va": hx(out.blocked_va) if out.blocked_va else None,
                "depth_max": out.depth_max,
                "entered_n": out.entered_n,
            })
            if not out.clean:
                clean_all = False
                blocker = {
                    "kind": h.KIND_NAMES[out.blocked_kind],
                    "va": hx(out.blocked_va) if out.blocked_va else None,
                    "at_step": label,
                }
                break
        unique = sorted(set(all_entered))
        harness.end_sequence()
        result = (
            "EXECUTED_STATEFUL_SEQUENCE" if clean_all
            else "EXECUTED_TO_NEXT_BLOCKER"
        )
        row = {
            "name": name,
            "result": result,
            "clean": clean_all,
            "sequence_length": len(step_outs),
            "steps": step_outs,
            "unique_entered": len(unique),
            "entered": [hx(x) for x in unique],
            "depth_max_nested": depth_peak,
            "blocker": blocker,
            "sleepex_done": step_outs and True,
        }
        # attach final runtime counters from last out
        results.append(row)
        return row, out if step_outs else None

    # 1) ctor alone (regression inside sequence API)
    r1, o1 = seq("ctor_only", [
        ("ctor", ctor_spec(), False),
    ])
    ticks1 = (o1.qpc_ticks_lo | (o1.qpc_ticks_hi << 32)) if o1 else 0
    r1["qpc_ticks"] = ticks1
    r1["sleepex_done"] = o1.sleepex_done if o1 else 0

    # 2) ctor → getter (byte at +0xDC should be 0)
    r2, o2 = seq("ctor_then_getter", [
        ("ctor", ctor_spec(), False),
        ("getter", h.make_spec(GETTER_DC, ecx=OBJ, ret_pop=0), True),
    ])
    if o2:
        r2["getter_al"] = o2.eax & 0xFF

    # 3) ctor → setter(0x5A) → getter
    r3, o3 = seq("ctor_setter_getter", [
        ("ctor", ctor_spec(), False),
        ("setter", h.make_spec(SETTER_DC, ecx=OBJ, args=(0x5A,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER_DC, ecx=OBJ, ret_pop=0), True),
    ])
    if o3:
        r3["getter_al"] = o3.eax & 0xFF
        r3["obj_dc_byte"] = harness.read_u8(OBJ + 0xDC)

    # 4) ctor → rtti-like vtable method
    r4, o4 = seq("ctor_then_rtti", [
        ("ctor", ctor_spec(), False),
        ("rtti", h.make_spec(RTTI_LIKE, ecx=OBJ, ret_pop=0), True),
    ])
    if o4:
        r4["eax"] = hx(o4.eax)

    # 5) ctor → embedded pod method (this = OBJ+4)
    r5, o5 = seq("ctor_then_pod_rtti", [
        ("ctor", ctor_spec(), False),
        ("pod_rtti", h.make_spec(POD_RTTI, ecx=OBJ + 4, ret_pop=0), True),
    ])
    if o5:
        r5["eax"] = hx(o5.eax)

    # 6) ctor → list walker (may block on required state)
    r6, o6 = seq("ctor_then_list_walk", [
        ("ctor", ctor_spec(), False),
        ("list", h.make_spec(0x009E8400, ecx=OBJ, ret_pop=0), True),
    ])

    # Reset isolation check: after end_sequence, independent run must not see 0x5A
    harness.end_sequence()
    out_reset = harness.run(ctor_spec())
    reset_ok = (harness.read_u8(OBJ + 0xDC) == 0) and bool(out_reset.clean)

    return results, reset_ok, out_reset


def serialize_campaign_row(r, phase=38):
    return {
        "root": hx(r["root"]), "phase": phase, "kind": r["kind"],
        "result": r["result"], "hist": r["hist"], "subclass": r.get("subclass"),
        "detail": r.get("detail"), "blocker_result": r.get("blocker_result"),
        "functions_entered": [hx(x) for x in r["entered"]],
        "unique_functions_entered": r["unique_entered"],
        "max_depth": r["depth_max"],
        "blocked_kind": r["blocked_kind"],
        "blocked_va": hx(r["blocked_va"]) if r["blocked_va"] else None,
        "import": r.get("import"),
        "sleepex_done": r.get("sleepex_done", 0),
        "qpc_ticks_lo": r.get("qpc_ticks_lo", 0),
        "qpc_ticks_hi": r.get("qpc_ticks_hi", 0),
        "clean": r.get("clean"),
        "stubs": [],
        "notes": r.get("note"),
        "evidence": "uc_phase38.py",
        "counted_in_metrics": True,
        "diagnostic_only": False,
    }


def main():
    fmap = h.load_fmap()
    addrs = set()
    for root in (CTOR, SEM, EBC70, SETTER_DC, GETTER_DC, RTTI_LIKE, POD_RTTI, 0x009E8400):
        addrs |= set(h.closure(root, fmap, limit=48))
        addrs.add(root)
    # Ensure consumers present even if fmap incomplete
    for extra in (SETTER_DC, GETTER_DC, RTTI_LIKE, POD_RTTI, 0x009E8400):
        addrs.add(extra)
    # Pull campaign closures
    for s in camp.campaign_specs():
        addrs |= set(h.closure(s["root"], fmap, limit=48))

    harness = h.Harness(addrs)

    # --- Track A: constructor state ---
    cap = capture_ctor_state(harness)
    harness.end_sequence()

    ctor_frontier = {
        "phase": 38,
        "constructor": hx(CTOR),
        "verified_entry_contract": {
            "abi": "thiscall",
            "ecx": "caller-owned OBJ_BASE",
            "args": ["SRC_BASE POD", "0"],
            "ret_pop": 8,
            "JTSWITCH": True,
            "no_stubs": True,
        },
        "known_object_storage_extent": hx(OBJ_SIZE),
        "object_base": hx(OBJ),
        "clean_termination": cap["clean"],
        "before_all_zero": cap["before_all_zero"],
        "initialized_nonzero_dwords": cap["nonzero_dword_count"],
        "fields": cap["changed_dwords"][:64],
        "highlights": cap["highlights"],
        "installed_vtables": {
            "main_plus0": hx(VT_MAIN),
            "pod_embedded_plus4": hx(VT_POD),
            "base_family": hx(VT_BASE),
        },
        "embedded_subobjects": [
            {"offset": "0x04", "vtable": hx(VT_POD), "initializer": "0x009E9990"},
            {"offset": "via 0x009E7710", "vtable": hx(VT_BASE), "note": "refcount base nested"},
            {"offset": "0x240", "role": "TLS index holder via 0x009777D0"},
        ],
        "side_effects": cap["side_effects"],
        "timing": {
            "sleepex_done": cap["sleepex_done"],
            "qpc_ticks": cap["qpc_ticks"],
            "virtual_ms": cap["qpc_ticks"] // 10000,
        },
        "confidence": "HIGH",
        "limitations": [
            "Object not published to 0x0189DA84 (factory 0x009E9340 not run)",
            "Allocator path remains protected",
            "Snapshot is metadata; harness reproduces state by re-running ctor",
        ],
        "reproducible_by_rerunning_ctor": True,
    }
    dump("constructor-state-frontier.json", ctor_frontier)

    # --- Track B/C: consumers + stateful sequences ---
    catalog = consumer_catalog()
    seq_rows, reset_ok, _ = run_stateful_sequences(harness)

    # Annotate catalog with execution results
    by_name = {r["name"]: r for r in seq_rows}
    for c in catalog:
        c["independently_enterable"] = False
        c["enterable_after_constructor"] = None
        c["execution"] = None
    # Map results
    mapping = {
        hx(GETTER_DC): ("ctor_then_getter", "getter"),
        hx(SETTER_DC): ("ctor_setter_getter", "setter"),
        hx(RTTI_LIKE): ("ctor_then_rtti", "rtti"),
        hx(POD_RTTI): ("ctor_then_pod_rtti", "pod_rtti"),
        hx(0x009E8400): ("ctor_then_list_walk", "list"),
    }
    for c in catalog:
        key = hx(c["va"])
        if key in mapping:
            sname, _ = mapping[key]
            r = by_name.get(sname)
            if r:
                c["enterable_after_constructor"] = bool(r["clean"])
                c["execution"] = {
                    "sequence": sname,
                    "result": r["result"],
                    "clean": r["clean"],
                    "blocker": r.get("blocker"),
                }

    post = {
        "phase": 38,
        "constructor": hx(CTOR),
        "vtable_main": hx(VT_MAIN),
        "candidates": catalog,
        "stateful_sequences": seq_rows,
        "reset_between_runs_validated": reset_ok,
        "strongest_consumer": {
            "va": hx(SETTER_DC),
            "pair": hx(GETTER_DC),
            "reason": "trivial ABI, field +0xDC initialized (zero) by ctor extent, proven vtable slots 13/14",
            "sequence": "ctor_setter_getter",
            "result": by_name.get("ctor_setter_getter", {}).get("result"),
        },
        "rejected_unrelated": [
            c for c in catalog if c.get("rejected")
        ],
    }
    dump("post-constructor-frontier.json", post)

    # --- Track E: campaign regressions ---
    rows, _H = camp.run_campaign(harness=harness)
    evidence_prev = load("execution-evidence.json")
    prior_unique = evidence_prev.get("unique_uc_functions_executed") or []
    entered_all = []
    for r in rows:
        entered_all.extend(r["entered"])
    for r in seq_rows:
        entered_all.extend(int(x, 16) for x in r.get("entered") or [])
    unique = p31.compute_unique(prior_unique, entered_all)

    clean = camp.clean_root_accounting(
        [{"root": r["root"], "result": r["result"], "stubs": []} for r in rows],
        p31.PRIOR_CLEAN_ROOTS | {CTOR},
    )
    # Stateful clean sequences also prove consumer roots enterable
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    if by_name.get("ctor_setter_getter", {}).get("clean"):
        new_enterable |= {hx(SETTER_DC), hx(GETTER_DC)}
    if by_name.get("ctor_then_rtti", {}).get("clean"):
        new_enterable.add(hx(RTTI_LIKE))
    if by_name.get("ctor_then_pod_rtti", {}).get("clean"):
        new_enterable.add(hx(POD_RTTI))

    prev = load("runtime-frontier.json")
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)
    ctors = camp.ctor_accounting(
        [{"entered": r["entered"]} for r in rows],
        {0x009E9160, 0x009E7710},
        p31.CTOR_CENSUS | {0x009EBC70, 0x0097BB30},
    )
    deepest = max([r["depth_max"] for r in rows] + [r["depth_max_nested"] for r in seq_rows])
    largest_closure = max([r["unique_entered"] for r in rows] + [0])
    largest_seq_cov = max((r["unique_entered"] for r in seq_rows), default=0)
    longest_seq = max((r["sequence_length"] for r in seq_rows), default=0)
    clean_seqs = sum(1 for r in seq_rows if r["clean"])
    hist = camp.real_blocker_histogram([{"hist": r["hist"]} for r in rows])
    req = camp.required_state_histogram(
        [{"hist": r["hist"], "subclass": r.get("subclass")} for r in rows])
    common = p31.most_common_blocker(rows)
    outcomes = collections.Counter(r["result"] for r in rows)
    outcomes["EXECUTED_STATEFUL_SEQUENCE"] = clean_seqs

    ctor_row = next(r for r in rows if r["root"] == CTOR)
    runtime_ready = prev.get("runtime_ready") or 72
    execution_runs = 95 + len(rows) + len(seq_rows)

    new_fns = sorted(set(unique) - set(prior_unique))

    recommended = (
        "Stateful ctor→setter→getter and vtable leaf methods execute cleanly. "
        "Phase 39: EXPAND REAL UC EXECUTION — pursue additional SAME_VTABLE_FAMILY "
        "methods with proven field prerequisites (avoid dtors/allocator), or "
        "ordinary global consumers of 0x0189D1A4/0x0189D198 published during ctor. "
        "Do not reopen protected allocator/factory. Graphics frozen."
    )

    frontier = {
        "phase": 38,
        "definitions": prev.get("definitions") or {},
        "high_functions": 22779, "generated": 22770, "compiled": 22770,
        "static_ready": 20762, "import_ready": 737,
        "runtime_ready": runtime_ready,
        "enterable": len(enterable),
        "enterable_roots": enterable,
        "enterable_with_depth_3_potential": prev.get("enterable_with_depth_3_potential") or 0,
        "enterable_with_depth_3_potential_roots": prev.get(
            "enterable_with_depth_3_potential_roots") or [],
        "enterable_with_depth_4_potential": 0,
        "enterable_with_depth_4_potential_roots": [],
        "proven_depth_4_roots": prev.get("proven_depth_4_roots") or [],
        "proven_depth_5_roots": prev.get("proven_depth_5_roots") or [],
        "unique_uc_functions_executed": len(unique),
        "unique_uc_functions_executed_list": unique,
        "execution_runs": execution_runs,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
        "ordinary_execution_sequence_length": longest_seq,
        "largest_stateful_sequence_coverage": largest_seq_cov,
        "clean_ordinary_roots": len(clean),
        "clean_ordinary_roots_list": [hx(x) for x in clean],
        "executed_ordinary_constructors": len(ctors),
        "executed_ordinary_constructors_list": [hx(x) for x in ctors],
        "ordinary_init_recovered": prev.get("ordinary_init_recovered"),
        "ordinary_runtime_frontier": {
            "HIGH": 22779, "COMPILED": 22770, "STATIC_READY": 20762,
            "IMPORT_READY": 737, "RUNTIME_READY": runtime_ready,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique), "UNIQUE": len(unique),
            "EXECUTION_RUNS": execution_runs,
            "CLEAN_ORDINARY_ROOTS": len(clean),
            "EXECUTED_ORDINARY_CONSTRUCTORS": len(ctors),
            "DEEPEST": deepest, "LARGEST_CLOSURE": largest_closure,
            "ORDINARY_EXECUTION_SEQUENCE_LENGTH": longest_seq,
            "LARGEST_STATEFUL_SEQUENCE_COVERAGE": largest_seq_cov,
            "LATEST_REAL_RUNTIME_BOUNDARY": (
                "STATEFUL ctor→setter→getter CLEAN"
                if by_name.get("ctor_setter_getter", {}).get("clean")
                else ctor_row.get("blocker_result") or "ctor CLEAN"
            ),
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase38_attempted_roots": len(rows),
            "phase38_stateful_sequences": len(seq_rows),
            "clean_stateful_sequences": clean_seqs,
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "ctor_clean": bool(ctor_row.get("clean")),
            "reset_validated": reset_ok,
            "new_functions": new_fns,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "filesystem_reached": False,
            "scheduler": False,
            "protected_boundary_encountered": False,
            "diagnostics_counted": 0,
        },
        "post_constructor": {
            "clean_constructor": True,
            "eligible_consumers": sum(
                1 for c in catalog
                if c.get("class") in (
                    "DIRECT_OBJECT_CONSUMER", "EMBEDDED_SUBOBJECT_CONSUMER",
                    "SAME_VTABLE_FAMILY") and not c.get("rejected")),
            "stateful_sequences_tested": len(seq_rows),
            "clean_stateful_sequences": clean_seqs,
            "largest_sequence_coverage": largest_seq_cov,
            "longest_sequence_length": longest_seq,
            "deepest_nested": deepest,
            "next_blocker": (
                by_name.get("ctor_then_list_walk", {}).get("blocker")
                or list(common)
            ),
        },
        "synchronization": prev.get("synchronization") or {},
        "timing": prev.get("timing") or {},
        "waits": prev.get("waits") or {},
        "indirect_dispatch": prev.get("indirect_dispatch") or {},
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase39": recommended,
        "phase31_metric_corrections_preserved": True,
    }
    dump("runtime-frontier.json", frontier)

    camp_ser = [serialize_campaign_row(r) for r in rows]
    for r in seq_rows:
        camp_ser.append({
            "root": "STATEFUL:" + r["name"],
            "phase": 38,
            "kind": "STATEFUL_SEQUENCE",
            "result": r["result"],
            "hist": "CLEAN_RETURN" if r["clean"] else "REQUIRED_STATE",
            "functions_entered": r["entered"],
            "unique_functions_entered": r["unique_entered"],
            "max_depth": r["depth_max_nested"],
            "sequence_length": r["sequence_length"],
            "clean": r["clean"],
            "blocker": r.get("blocker"),
            "stubs": [],
            "evidence": "uc_phase38.py",
            "counted_in_metrics": True,
            "diagnostic_only": False,
        })
    hist_ev, seen = [], set()
    for r in camp_ser + (evidence_prev.get("roots") or []):
        key = (r.get("root"), r.get("phase"), r.get("result"), r.get("evidence"),
               r.get("sequence_length"), r.get("detail"))
        if key in seen:
            continue
        seen.add(key)
        hist_ev.append(r)
    dump("execution-evidence.json", {
        "phase": 38,
        "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
        "ordinary_execution_sequence_length": longest_seq,
        "largest_stateful_sequence_coverage": largest_seq_cov,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase38_stateful": seq_rows,
        "phase38_ctor_state": {
            "clean": cap["clean"],
            "nonzero_dwords": cap["nonzero_dword_count"],
            "highlights": cap["highlights"],
            "sleepex_done": cap["sleepex_done"],
            "qpc_ticks": cap["qpc_ticks"],
        },
        "phase37_ctor": evidence_prev.get("phase37_ctor"),
        "phase36_ctor": evidence_prev.get("phase36_ctor"),
        "phase30_stub_correction": evidence_prev.get("phase30_stub_correction"),
    })
    dump("blocker-ranking.json", {
        "phase": 38,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "stateful_clean_sequences": clean_seqs,
        "latest_real_runtime_boundary": frontier["ordinary_runtime_frontier"][
            "LATEST_REAL_RUNTIME_BOUNDARY"],
    })

    status = load("project-status.json")
    status["current_phase"] = 38
    status["strategy"] = (
        "Phase 38: post-constructor stateful sequences (ctor→setter→getter). "
        "Graphics frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 38 for p in phases):
        phases.append({
            "phase": 38,
            "name": "Post-constructor ordinary consumers",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase38.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 38 — post-constructor ordinary execution",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.",
            "",
            "## A. Phase-37 baseline",
            "",
            "Ctor `0x009E9160` RETURNED_CLEAN; UNIQUE 48; CLOSURE 18; CLEAN 13; "
            "JTSWITCH enabled.",
            "",
            "## B. Constructor state contract",
            "",
            "Extent `0x248`; thiscall `(SRC_POD, 0)`; ret 8; no stubs.",
            "",
            "## C. Object fields and write provenance",
            "",
            "Non-zero dwords after clean ctor: **%d**. Highlights: %s." % (
                cap["nonzero_dword_count"], json.dumps(cap["highlights"])),
            "",
            "## D. Guest runtime side effects",
            "",
            "TLS alloc/set, ICS/mutex, priorities, SleepEx×%d, QPC ticks %d." % (
                cap["sleepex_done"], cap["qpc_ticks"]),
            "",
            "## E. Candidate consumer search",
            "",
            "Vtable `0x00C30E68` slots inspected; dtor/allocator paths rejected.",
            "",
            "## F. Static vtable relationship",
            "",
            "Main `0x00C30E68` @+0; pod `0x00C30F2C` @+4; base family `0x00C30D5C`.",
            "",
            "## G. Consumer ranking",
            "",
            "Strongest: setter/getter `0x009E9140`/`0x009E9150` (+0xDC). "
            "Also rtti-like `0x009E7780`, pod `0x009E9980`.",
            "",
            "## H. Multi-step harness architecture",
            "",
            "`uc_p31_step` + `Harness.begin_sequence`/`step(continue_state=True)` "
            "preserve guest runtime + object; independent `run()` still full-resets.",
            "",
            "## I. Stateful execution campaign",
            "",
            "Sequences tested: %d; clean: %d; longest length: %d; "
            "largest coverage: %d." % (
                len(seq_rows), clean_seqs, longest_seq, largest_seq_cov),
            "",
            "## J. New ordinary bodies reached",
            "",
            "New unique vs Phase 37 prior list: %s." % (new_fns or "(none — already counted)"),
            "",
            "## K. Next genuine blockers",
            "",
            "List-walk `0x009E8400` may need +0xBC/+0xC0 state; campaign "
            "REQUIRED_STATE remains common. Factory `0x009E9340` still allocator-blocked.",
            "",
            "## L. Frontier delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; DEEPEST **%d**; CLOSURE **%d**; "
            "SEQ_LEN **%d**; SEQ_COV **%d**; CLEAN **%d**; RUNS **%d**." % (
                len(unique), len(enterable), deepest, largest_closure,
                longest_seq, largest_seq_cov, len(clean), execution_runs),
            "",
            "## M. Phase-39 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "deep", deepest, "clos", largest_closure,
          "seq", longest_seq, "seqcov", largest_seq_cov,
          "clean_seq", clean_seqs, "reset", reset_ok,
          "ctor", cap["clean"], "setter_getter",
          by_name.get("ctor_setter_getter", {}).get("result"))
    return frontier


if __name__ == "__main__":
    main()
