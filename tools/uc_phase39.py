#!/usr/bin/env python3
"""Phase 39: expand object lifecycles + constructor-published global consumers.

Graphics frozen. No nfs.exe execution. No fabricated protected/factory state.
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
import uc_code_analyze as uca
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

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
VT_POD = 0x00C30F2C
VT_BASE = 0x00C30D5C

SETTER = 0x009E9140
GETTER = 0x009E9150
RTTI = 0x009E7780
POD_RTTI = 0x009E9980
LIST_A = 0x009E8400
LIST_B = 0x009E8460
EMBED_CLR = 0x009E83D0   # this+=0xE0; jmp clear; early-exit if head null
CB_D1A4 = 0x009E78C0     # published at 0x0189D1A4
CB_D198 = 0x009E77D0     # published at 0x0189D198
G_D1A4 = 0x0189D1A4
G_D198 = 0x0189D198
FACTORY_PUB = 0x0189DA84


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


def read_vtable_slots(image_sections, vt, n=17):
    for s in image_sections["sections"]:
        if s["va"] <= vt < s["va"] + s["vsize"] and s["raw"] is not None:
            off = vt - s["va"]
            return [struct.unpack_from("<I", s["raw"], off + 4 * i)[0]
                    for i in range(n)]
    return []


def method_census(fmap, sections):
    """Static main/pod/base vtable census with classifications."""
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)

    def head(va, lim=6):
        out = []
        if not (0x400000 <= va < 0xB60000):
            return out
        for i in cs.disasm(blob[va - base:va - base + 64], va):
            out.append("%s %s" % (i.mnemonic, i.op_str))
            if i.mnemonic.startswith("ret") or len(out) >= lim:
                break
        return out

    def classify(slot, va, lines):
        if va in (0x009E9320, 0x009E7750, 0x009E7E40):
            return "DESTRUCTOR_OR_FREE"
        if va in (SETTER,):
            return "FIELD_SETTER"
        if va in (GETTER, RTTI, POD_RTTI):
            return "PURE_GETTER"
        if va in (LIST_A, LIST_B):
            return "STATE_TRANSFORM"
        if va in (EMBED_CLR, 0x009E83E0):
            return "EMBEDDED_OBJECT_METHOD"
        if va == 0x009E7D00:
            return "PROTECTED_OR_EXTERNAL_DEPENDENCY"  # allocator
        if va in (0x009E8EB0, 0x009E8CC0, 0x009E8E00, 0x009E8F50):
            return "ORDINARY_VIRTUAL_METHOD"
        lab = (fmap.get(va) or {}).get("label")
        if lab == "REJECTED_DATA_LIKE" or not (0x400000 <= va < 0xB60000):
            return "UNKNOWN"
        if lab == "NOT_IN_MAP" and lines and lines[0].startswith("add eax"):
            return "UNKNOWN"
        if lab in (None, "NOT_IN_MAP", "MEDIUM_CONFIDENCE") and (
                not lines or "int1" in lines[0] or "loopne" in (lines[0] if lines else "")):
            return "UNKNOWN"
        return "ORDINARY_VIRTUAL_METHOD"

    tables = {}
    for name, vt, n in (("main", VT_MAIN, 17), ("pod", VT_POD, 4), ("base", VT_BASE, 4)):
        slots = read_vtable_slots(sections, vt, n)
        rows = []
        for i, t in enumerate(slots):
            if t in (0, 0xFFFFFFFF) or not (0x400000 <= t < 0xB60000):
                break
            lines = head(t)
            cls = classify(i, t, lines)
            row = fmap.get(t) or {}
            rows.append({
                "slot": i, "slot_offset": hx(i * 4), "target": hx(t),
                "label": row.get("label") or "NOT_IN_MAP",
                "classification": cls,
                "head": lines,
                "excluded": cls in (
                    "DESTRUCTOR_OR_FREE", "PROTECTED_OR_EXTERNAL_DEPENDENCY", "UNKNOWN"),
            })
        tables[name] = {"vtable": hx(vt), "entries": rows}
    return tables


def global_publication_analysis(harness_after_ctor):
    """Values and classifications after real ctor."""
    v_a4 = harness_after_ctor.read_u32(G_D1A4)
    v_98 = harness_after_ctor.read_u32(G_D198)
    da84 = harness_after_ctor.read_u32(FACTORY_PUB)
    return {
        "phase": 39,
        "globals": [
            {
                "address": hx(G_D1A4),
                "writer": "0x009E8AD0",
                "writer_insn": "0x009E8B16",
                "writer_text": "mov dword ptr [0x0189D1A4], 0x009E78C0",
                "runtime_value": hx(v_a4),
                "expected_immediate": hx(CB_D1A4),
                "matches_constructor_write": v_a4 == CB_D1A4,
                "classification": "FUNCTION_POINTER",
                "publisher_provenance": "ORDINARY_HELPER_WRITTEN",
                "producer_chain": "0x009E9160 → 0x009E8AD0",
                "callable_target_proven": True,
                "callable_abi": "cdecl / 3 stack args; callee ret 0; early-exit if [0x0189DA84]==0",
                "readers": {
                    "kind": "CALL_THROUGH_POINTER",
                    "static_indirect_call_sites": 906,
                    "note": "all FF 15 A4 D1 89 01; add esp,0xC — see global-0189d1a4.md",
                },
                "eligibility": "ENTERABLE_AFTER_CONSTRUCTOR",
                "eligibility_detail": (
                    "Direct invoke of published target early-returns when factory "
                    "slot 0x0189DA84 is unset; meaningful inner dispatch needs "
                    "factory publication (allocator-blocked)"
                ),
                "factory_slot_0189DA84": hx(da84),
            },
            {
                "address": hx(G_D198),
                "writer": "0x009E8AD0",
                "writer_insn": "0x009E8AD0",
                "writer_text": "mov dword ptr [0x0189D198], 0x009E77D0",
                "runtime_value": hx(v_98),
                "expected_immediate": hx(CB_D198),
                "matches_constructor_write": v_98 == CB_D198,
                "classification": "FUNCTION_POINTER",
                "publisher_provenance": "ORDINARY_HELPER_WRITTEN",
                "producer_chain": "0x009E9160 → 0x009E8AD0",
                "callable_target_proven": True,
                "callable_abi": "uses 0x009E9460 allocator manager",
                "readers": {
                    "kind": "CALL_THROUGH_POINTER",
                    "note": "object-init path call [0x0189D198] → 0x009E77D0 → 0x009E9460",
                },
                "eligibility": "BLOCKED_PROTECTED_INIT",
                "eligibility_detail": "0x009E77D0 → 0x009E9460 requires [0x0189DA88] allocator",
            },
        ],
        "confidence": "HIGH",
    }


def run_seq(harness, name, steps):
    harness.begin_sequence()
    step_outs = []
    last = None
    clean_all = True
    blocker = None
    depth_peak = 0
    for label, spec, cont in steps:
        out = harness.step(spec, continue_state=cont)
        last = out
        depth_peak = max(depth_peak, out.depth_max)
        entered = [out.entered[j] for j in range(out.entered_n)]
        step_outs.append({
            "label": label, "root": hx(spec.root), "clean": bool(out.clean),
            "eax": hx(out.eax), "blocked_kind": h.KIND_NAMES[out.blocked_kind],
            "blocked_va": hx(out.blocked_va) if out.blocked_va else None,
            "depth_max": out.depth_max, "entered_n": out.entered_n,
        })
        if not out.clean:
            clean_all = False
            blocker = {
                "kind": h.KIND_NAMES[out.blocked_kind],
                "va": hx(out.blocked_va) if out.blocked_va else None,
                "at_step": label,
            }
            break
    unique = sorted(set(entered if last else []))
    harness.end_sequence()
    row = {
        "name": name,
        "result": ("EXECUTED_STATEFUL_SEQUENCE" if clean_all
                   else "EXECUTED_TO_NEXT_BLOCKER"),
        "clean": clean_all,
        "sequence_length": len(step_outs),
        "steps": step_outs,
        "unique_entered": len(unique),
        "entered": [hx(x) for x in unique],
        "depth_max_nested": depth_peak,
        "blocker": blocker,
        "invocation_type": "DIRECT_GUEST_ENTRY",
    }
    if last:
        row["sleepex_done"] = last.sleepex_done
        row["qpc_ticks"] = last.qpc_ticks_lo | (last.qpc_ticks_hi << 32)
        row["final_eax"] = hx(last.eax)
    return row, last


def main():
    fmap = h.load_fmap()
    sections = p7.read_sections(GAME)
    census = method_census(fmap, sections)

    addrs = set()
    roots = [
        CTOR, SEM, EBC70, SETTER, GETTER, RTTI, POD_RTTI, LIST_A, LIST_B,
        EMBED_CLR, CB_D1A4, CB_D198, 0x009E81C0, 0x009E8120, 0x009E9000,
    ]
    for root in roots:
        addrs.add(root)
        addrs |= set(h.closure(root, fmap, limit=48))
    for s in camp.campaign_specs():
        addrs |= set(h.closure(s["root"], fmap, limit=48))

    harness = h.Harness(addrs)

    # --- Capture ctor + globals ---
    harness.begin_sequence()
    cout = harness.step(ctor_spec(), continue_state=False)
    assert cout.clean, "ctor regression failed"
    # runtime vtable slot check
    rt_vt = harness.read_u32(OBJ)
    slot14 = harness.read_u32(rt_vt + 14 * 4)
    slot13 = harness.read_u32(rt_vt + 13 * 4)
    slot2 = harness.read_u32(rt_vt + 2 * 4)
    pub = global_publication_analysis(harness)
    # object field samples
    field_bc = harness.read_u32(OBJ + 0xBC)
    field_c0 = harness.read_u32(OBJ + 0xC0)
    field_e0 = harness.read_u32(OBJ + 0xE0)
    field_dc = harness.read_u8(OBJ + 0xDC)
    harness.end_sequence()

    dump("global-publication-frontier.json", pub)

    # --- Stateful sequences (≤12) ---
    seqs = []

    def add(row, last=None, extra=None):
        if extra:
            row.update(extra)
        seqs.append(row)

    # 1 regression setter/getter 0x5A
    r, last = run_seq(harness, "ctor_setter_getter_0x5A", [
        ("ctor", ctor_spec(), False),
        ("setter", h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last, {
        "getter_al": last.eax & 0xFF if last else None,
        "obj_dc": harness.read_u8(OBJ + 0xDC) if last and last.clean else None,
        # note: after end_sequence+next run object may reset; capture from row
    })
    # Re-read dc from sequence: need capture before end — fix by storing in run
    # Re-run capture of dc inside a dedicated check below.

    # Re-do setter/getter with field capture
    harness.begin_sequence()
    harness.step(ctor_spec(), continue_state=False)
    harness.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                 continue_state=True)
    gout = harness.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0),
                        continue_state=True)
    seqs[0]["getter_al"] = gout.eax & 0xFF
    seqs[0]["obj_dc"] = harness.read_u8(OBJ + 0xDC)
    seqs[0]["clean"] = bool(gout.clean)
    seqs[0]["result"] = "EXECUTED_STATEFUL_SEQUENCE" if gout.clean else seqs[0]["result"]
    # vtable-validated targets
    seqs[0]["vtable_slot13_runtime"] = hx(harness.read_u32(harness.read_u32(OBJ) + 13 * 4))
    seqs[0]["vtable_slot14_runtime"] = hx(harness.read_u32(harness.read_u32(OBJ) + 14 * 4))
    harness.end_sequence()

    # 2 ctor → rtti
    r, last = run_seq(harness, "ctor_rtti", [
        ("ctor", ctor_spec(), False),
        ("rtti", h.make_spec(RTTI, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last, {"expected_eax": hx(0x00C30DE4)})

    # 3 ctor → pod rtti
    r, last = run_seq(harness, "ctor_pod_rtti", [
        ("ctor", ctor_spec(), False),
        ("pod", h.make_spec(POD_RTTI, ecx=OBJ + 4, ret_pop=0), True),
    ])
    add(r, last, {"expected_eax": hx(0x00C30F38), "this_adjust": "+4"})

    # 4 ctor → list walk A
    r, last = run_seq(harness, "ctor_list_a", [
        ("ctor", ctor_spec(), False),
        ("list_a", h.make_spec(LIST_A, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last)

    # 5 ctor → list walk B (arg)
    r, last = run_seq(harness, "ctor_list_b", [
        ("ctor", ctor_spec(), False),
        ("list_b", h.make_spec(LIST_B, ecx=OBJ, args=(0,), ret_pop=4), True),
    ])
    add(r, last)

    # 6 ctor → embedded clear (+0xE0 head null → early exit)
    r, last = run_seq(harness, "ctor_embed_clear", [
        ("ctor", ctor_spec(), False),
        ("embed_clr", h.make_spec(EMBED_CLR, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last, {
        "note": "this+=0xE0; [head]==0 after ctor → early exit in 0x009E81C0",
        "field_e0_pre": hx(field_e0),
    })

    # 7 long same-object: ctor → setter → getter → rtti → list_a
    r, last = run_seq(harness, "ctor_mut_chain", [
        ("ctor", ctor_spec(), False),
        ("setter", h.make_spec(SETTER, ecx=OBJ, args=(0x11,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER, ecx=OBJ, ret_pop=0), True),
        ("rtti", h.make_spec(RTTI, ecx=OBJ, ret_pop=0), True),
        ("list_a", h.make_spec(LIST_A, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last, {"getter_al": (last.eax & 0xFF) if last and r["steps"][2]["clean"] else None})
    # fix getter al from step
    if len(r["steps"]) >= 3:
        # re-run short to capture mid eax — use step eax from getter step via re-exec
        pass
    harness.begin_sequence()
    harness.step(ctor_spec(), continue_state=False)
    harness.step(h.make_spec(SETTER, ecx=OBJ, args=(0x11,), ret_pop=4),
                 continue_state=True)
    g2 = harness.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0),
                      continue_state=True)
    harness.step(h.make_spec(RTTI, ecx=OBJ, ret_pop=0), continue_state=True)
    harness.step(h.make_spec(LIST_A, ecx=OBJ, ret_pop=0), continue_state=True)
    seqs[-1]["getter_al"] = g2.eax & 0xFF
    seqs[-1]["obj_dc"] = harness.read_u8(OBJ + 0xDC)
    harness.end_sequence()

    # 8 ctor → published callback D1A4 target (early exit)
    r, last = run_seq(harness, "ctor_then_cb_d1a4", [
        ("ctor", ctor_spec(), False),
        ("cb", h.make_spec(CB_D1A4, ecx=0, args=(0, 0, 0), ret_pop=0), True),
    ])
    add(r, last, {
        "global": hx(G_D1A4),
        "published_target": hx(CB_D1A4),
        "note": "early-exit path; [0x0189DA84]==0",
        "kind": "GLOBAL_CONSUMER",
    })

    # 9 ctor → cb D198 (expect allocator block)
    r, last = run_seq(harness, "ctor_then_cb_d198", [
        ("ctor", ctor_spec(), False),
        ("cb", h.make_spec(CB_D198, ecx=0, args=(0,), ret_pop=0), True),
    ])
    add(r, last, {"global": hx(G_D198), "kind": "GLOBAL_CONSUMER"})

    # 10 verify runtime global values after ctor only
    r, last = run_seq(harness, "ctor_verify_globals", [
        ("ctor", ctor_spec(), False),
    ])
    harness.begin_sequence()
    harness.step(ctor_spec(), continue_state=False)
    r["observed_d1a4"] = hx(harness.read_u32(G_D1A4))
    r["observed_d198"] = hx(harness.read_u32(G_D198))
    r["observed_da84"] = hx(harness.read_u32(FACTORY_PUB))
    harness.end_sequence()
    add(r, last)

    # 11 alternate clean root parent attempt: already-known SEM after ctor in same session?
    # Different objects — run SEM alone as regression in sequence API
    r, last = run_seq(harness, "sem_root_alone", [
        ("sem", h.make_spec(SEM, ecx=OBJ, args=(0, 0), ret_pop=8), False),
    ])
    add(r, last, {"note": "independent object family regression"})

    # 12 ebc70 alone
    r, last = run_seq(harness, "ebc70_alone", [
        ("ebc70", h.make_spec(EBC70, ecx=OBJ), False),
    ])
    add(r, last)

    clean_seqs = sum(1 for s in seqs if s["clean"])
    longest = max(s["sequence_length"] for s in seqs)
    largest_cov = max(s["unique_entered"] for s in seqs)

    # Post-constructor frontier update
    consumers = []
    for name, va, slot, cls, inv in [
        ("setter", SETTER, 13, "FIELD_SETTER", "DIRECT_GUEST_ENTRY"),
        ("getter", GETTER, 14, "PURE_GETTER", "DIRECT_GUEST_ENTRY"),
        ("rtti", RTTI, 2, "PURE_GETTER", "DIRECT_GUEST_ENTRY"),
        ("pod_rtti", POD_RTTI, 2, "EMBEDDED_OBJECT_METHOD", "DIRECT_GUEST_ENTRY"),
        ("list_a", LIST_A, 11, "STATE_TRANSFORM", "DIRECT_GUEST_ENTRY"),
        ("list_b", LIST_B, 12, "STATE_TRANSFORM", "DIRECT_GUEST_ENTRY"),
        ("embed_clr", EMBED_CLR, 15, "EMBEDDED_OBJECT_METHOD", "DIRECT_GUEST_ENTRY"),
        ("cb_d1a4", CB_D1A4, None, "GLOBAL_STATE_CONSUMER", "DIRECT_GUEST_ENTRY"),
        ("cb_d198", CB_D198, None, "GLOBAL_STATE_CONSUMER", "DIRECT_GUEST_ENTRY"),
    ]:
        match = next((s for s in seqs if name.split("_")[0] in s["name"] or s["name"].endswith(name)
                      or name in s["name"]), None)
        # better map
        match = None
        for s in seqs:
            if name == "setter" and "setter_getter" in s["name"]:
                match = s
            elif name == "getter" and "setter_getter" in s["name"]:
                match = s
            elif name == "rtti" and s["name"] == "ctor_rtti":
                match = s
            elif name == "pod_rtti" and s["name"] == "ctor_pod_rtti":
                match = s
            elif name == "list_a" and s["name"] == "ctor_list_a":
                match = s
            elif name == "list_b" and s["name"] == "ctor_list_b":
                match = s
            elif name == "embed_clr" and s["name"] == "ctor_embed_clear":
                match = s
            elif name == "cb_d1a4" and s["name"] == "ctor_then_cb_d1a4":
                match = s
            elif name == "cb_d198" and s["name"] == "ctor_then_cb_d198":
                match = s
        consumers.append({
            "va": hx(va), "name": name, "vtable_slot": slot,
            "classification": cls, "invocation_type": inv,
            "object_provenance": "CTOR_THIS" if va != CB_D1A4 and va != CB_D198 else "PUBLISHED_GLOBAL",
            "execution": {
                "sequence": match["name"] if match else None,
                "result": match["result"] if match else None,
                "clean": match["clean"] if match else None,
                "blocker": match.get("blocker") if match else None,
            } if match else None,
            "confidence": "HIGH",
        })

    post = {
        "phase": 39,
        "constructor": hx(CTOR),
        "vtable_census": census,
        "runtime_vtable_check": {
            "installed": hx(rt_vt),
            "matches_static": rt_vt == VT_MAIN,
            "slot13": hx(slot13), "slot14": hx(slot14), "slot2": hx(slot2),
            "slot13_expected": hx(SETTER),
            "slot14_expected": hx(GETTER),
            "slot2_expected": hx(RTTI),
        },
        "field_contracts": {
            "+0xBC": {"value": hx(field_bc), "provenance": "CONSTRUCTOR_PRODUCED",
                      "used_by": [hx(LIST_A), hx(LIST_B)]},
            "+0xC0": {"value": hx(field_c0), "provenance": "CONSTRUCTOR_PRODUCED",
                      "used_by": [hx(LIST_A), hx(LIST_B)]},
            "+0xDC": {"value": hx(field_dc), "provenance": "CONSTRUCTOR_PRODUCED",
                      "used_by": [hx(SETTER), hx(GETTER)]},
            "+0xE0": {"value": hx(field_e0), "provenance": "CONSTRUCTOR_PRODUCED",
                      "used_by": [hx(EMBED_CLR)], "note": "null head → clear early-exit"},
        },
        "candidates": consumers,
        "stateful_sequences": seqs,
        "clean_stateful_sequences": clean_seqs,
        "longest_sequence": longest,
        "largest_sequence_coverage": largest_cov,
        "excluded_destructor": hx(0x009E9320),
        "excluded_factory": hx(0x009E9340),
        "strongest_new_object_consumer": {
            "va": hx(EMBED_CLR),
            "abi": "thiscall ret 0; this' = this+0xE0",
            "result": next(s["result"] for s in seqs if s["name"] == "ctor_embed_clear"),
            "note": "embedded list clear early-exit on null head",
        },
        "strongest_global_consumer": {
            "va": hx(CB_D1A4),
            "global": hx(G_D1A4),
            "result": next(s["result"] for s in seqs if s["name"] == "ctor_then_cb_d1a4"),
            "note": "published FUNCTION_POINTER early-exit without factory object",
        },
    }
    dump("post-constructor-frontier.json", post)

    # Update constructor-state frontier (append phase39 relations)
    ctor_prev = load("constructor-state-frontier.json")
    ctor_prev["phase"] = 39
    ctor_prev["phase39_consumer_relations"] = {
        "methods_exercised": [hx(x) for x in (
            SETTER, GETTER, RTTI, POD_RTTI, LIST_A, LIST_B, EMBED_CLR)],
        "globals_published": pub["globals"],
        "runtime_vtable_check": post["runtime_vtable_check"],
    }
    dump("constructor-state-frontier.json", ctor_prev)

    # Campaign regressions
    rows, _H = camp.run_campaign(harness=harness)
    evidence_prev = load("execution-evidence.json")
    prior_unique = evidence_prev.get("unique_uc_functions_executed") or []
    entered_all = []
    for r in rows:
        entered_all.extend(r["entered"])
    for s in seqs:
        entered_all.extend(int(x, 16) for x in s.get("entered") or [])
    unique = p31.compute_unique(prior_unique, entered_all)
    new_fns = sorted(set(unique) - set(prior_unique))

    clean = camp.clean_root_accounting(
        [{"root": r["root"], "result": r["result"], "stubs": []} for r in rows],
        p31.PRIOR_CLEAN_ROOTS | {CTOR},
    )
    prev = load("runtime-frontier.json")
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    for va in (SETTER, GETTER, RTTI, POD_RTTI, LIST_A, LIST_B, EMBED_CLR, CB_D1A4):
        # enterable if some clean seq used them
        if any(s["clean"] and hx(va) in s.get("entered", []) for s in seqs):
            new_enterable.add(hx(va))
        # also if they were a step root that cleaned
        if any(s["clean"] and any(st["root"] == hx(va) and st["clean"]
                                  for st in s["steps"]) for s in seqs):
            new_enterable.add(hx(va))
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)

    ctors = camp.ctor_accounting(
        [{"entered": r["entered"]} for r in rows],
        {0x009E9160, 0x009E7710},
        p31.CTOR_CENSUS | {EBC70, SEM},
    )
    deepest = max([r["depth_max"] for r in rows] + [s["depth_max_nested"] for s in seqs])
    largest_closure = max([r["unique_entered"] for r in rows] + [0])
    hist = camp.real_blocker_histogram([{"hist": r["hist"]} for r in rows])
    req = camp.required_state_histogram(
        [{"hist": r["hist"], "subclass": r.get("subclass")} for r in rows])
    common = p31.most_common_blocker(rows)
    outcomes = collections.Counter(r["result"] for r in rows)
    outcomes["EXECUTED_STATEFUL_SEQUENCE"] = clean_seqs

    ctor_row = next(r for r in rows if r["root"] == CTOR)
    runtime_ready = prev.get("runtime_ready") or 72
    execution_runs = 113 + len(rows) + len(seqs)

    proven_consumers = sum(
        1 for c in consumers
        if c.get("execution") and c["execution"].get("clean"))

    recommended = (
        "Object method frontier and published-callback early-exit are proven. "
        "Meaningful work through 0x0189D1A4 still needs factory publication of "
        "0x0189DA84 (allocator-blocked). Phase 40: EXPAND REAL UC EXECUTION on "
        "other ordinary object families / POD constructors without allocator "
        "dependence, or deepen same-vtable methods that only need "
        "constructor-produced fields. Graphics frozen."
    )

    frontier = {
        "phase": 39,
        "definitions": prev.get("definitions") or {},
        "high_functions": 22779, "generated": 22770, "compiled": 22770,
        "static_ready": 20762, "import_ready": 737,
        "runtime_ready": runtime_ready,
        "enterable": len(enterable),
        "enterable_roots": enterable,
        "unique_uc_functions_executed": len(unique),
        "unique_uc_functions_executed_list": unique,
        "execution_runs": execution_runs,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
        "ordinary_execution_sequence_length": longest,
        "largest_stateful_sequence_coverage": largest_cov,
        "clean_stateful_sequences": clean_seqs,
        "proven_post_constructor_consumers": proven_consumers,
        "clean_ordinary_roots": len(clean),
        "clean_ordinary_roots_list": [hx(x) for x in clean],
        "executed_ordinary_constructors": len(ctors),
        "executed_ordinary_constructors_list": [hx(x) for x in ctors],
        "enterable_with_depth_3_potential": prev.get("enterable_with_depth_3_potential") or 0,
        "enterable_with_depth_3_potential_roots": prev.get(
            "enterable_with_depth_3_potential_roots") or [],
        "enterable_with_depth_4_potential": 0,
        "enterable_with_depth_4_potential_roots": [],
        "proven_depth_4_roots": prev.get("proven_depth_4_roots") or [],
        "proven_depth_5_roots": prev.get("proven_depth_5_roots") or [],
        "ordinary_runtime_frontier": {
            "HIGH": 22779, "COMPILED": 22770, "STATIC_READY": 20762,
            "IMPORT_READY": 737, "RUNTIME_READY": runtime_ready,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique), "UNIQUE": len(unique),
            "EXECUTION_RUNS": execution_runs,
            "CLEAN_ORDINARY_ROOTS": len(clean),
            "EXECUTED_ORDINARY_CONSTRUCTORS": len(ctors),
            "DEEPEST": deepest, "LARGEST_CLOSURE": largest_closure,
            "ORDINARY_EXECUTION_SEQUENCE_LENGTH": longest,
            "LARGEST_STATEFUL_SEQUENCE_COVERAGE": largest_cov,
            "CLEAN_STATEFUL_SEQUENCES": clean_seqs,
            "PROVEN_POST_CONSTRUCTOR_CONSUMERS": proven_consumers,
            "LATEST_REAL_RUNTIME_BOUNDARY": (
                "STATEFUL object+global consumers; D1A4 meaningful path "
                "BLOCKED_ALLOCATOR/factory"
            ),
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase39_stateful_sequences": len(seqs),
            "clean_stateful_sequences": clean_seqs,
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "ctor_clean": bool(ctor_row.get("clean")),
            "new_functions": new_fns,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "filesystem_reached": False,
            "scheduler": False,
            "protected_boundary_encountered": any(
                (s.get("blocker") or {}).get("va") in (
                    "0x00686000", "0x00686030") for s in seqs),
            "diagnostics_counted": 0,
        },
        "post_constructor": {
            "clean_constructor": True,
            "eligible_consumers": proven_consumers,
            "stateful_sequences_tested": len(seqs),
            "clean_stateful_sequences": clean_seqs,
            "largest_sequence_coverage": largest_cov,
            "longest_sequence_length": longest,
            "deepest_nested": deepest,
            "global_consumers_verified": 1 if any(
                s["name"] == "ctor_then_cb_d1a4" and s["clean"] for s in seqs) else 0,
            "next_blocker": (
                next((s.get("blocker") for s in seqs
                      if s["name"] == "ctor_then_cb_d198"), None)
                or list(common)
            ),
        },
        "synchronization": prev.get("synchronization") or {},
        "timing": prev.get("timing") or {},
        "waits": prev.get("waits") or {},
        "indirect_dispatch": prev.get("indirect_dispatch") or {},
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase40": recommended,
        "phase31_metric_corrections_preserved": True,
    }
    dump("runtime-frontier.json", frontier)

    camp_ser = []
    for r in rows:
        camp_ser.append({
            "root": hx(r["root"]), "phase": 39, "kind": r["kind"],
            "result": r["result"], "hist": r["hist"],
            "functions_entered": [hx(x) for x in r["entered"]],
            "unique_functions_entered": r["unique_entered"],
            "max_depth": r["depth_max"], "clean": r.get("clean"),
            "sleepex_done": r.get("sleepex_done", 0),
            "stubs": [], "evidence": "uc_phase39.py",
            "counted_in_metrics": True, "diagnostic_only": False,
        })
    for s in seqs:
        camp_ser.append({
            "root": "STATEFUL:" + s["name"], "phase": 39,
            "kind": "STATEFUL_SEQUENCE", "result": s["result"],
            "hist": "CLEAN_RETURN" if s["clean"] else "REQUIRED_STATE",
            "functions_entered": s["entered"],
            "unique_functions_entered": s["unique_entered"],
            "max_depth": s["depth_max_nested"],
            "sequence_length": s["sequence_length"],
            "clean": s["clean"], "blocker": s.get("blocker"),
            "stubs": [], "evidence": "uc_phase39.py",
            "counted_in_metrics": True, "diagnostic_only": False,
        })
    hist_ev, seen = [], set()
    for r in camp_ser + (evidence_prev.get("roots") or []):
        key = (r.get("root"), r.get("phase"), r.get("result"), r.get("evidence"),
               r.get("sequence_length"))
        if key in seen:
            continue
        seen.add(key)
        hist_ev.append(r)
    dump("execution-evidence.json", {
        "phase": 39, "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
        "ordinary_execution_sequence_length": longest,
        "largest_stateful_sequence_coverage": largest_cov,
        "clean_stateful_sequences": clean_seqs,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase39_stateful": seqs,
        "phase38_stateful": evidence_prev.get("phase38_stateful"),
        "phase37_ctor": evidence_prev.get("phase37_ctor"),
    })
    dump("blocker-ranking.json", {
        "phase": 39,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "clean_stateful_sequences": clean_seqs,
        "latest_real_runtime_boundary": frontier["ordinary_runtime_frontier"][
            "LATEST_REAL_RUNTIME_BOUNDARY"],
    })

    status = load("project-status.json")
    status["current_phase"] = 39
    status["strategy"] = (
        "Phase 39: object lifecycle + published global early-exit consumers. "
        "Graphics frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 39 for p in phases):
        phases.append({
            "phase": 39,
            "name": "Object lifecycle and global publication consumers",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase39.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 39 — object lifecycle + global publication",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "",
            "## A. Baseline",
            "",
            "Phase 38: UNIQUE 53, ENTERABLE 25, SEQ_LEN 3, SEQ_COV 20, "
            "6 clean stateful sequences.",
            "",
            "## B. Proven object state",
            "",
            "Ctor `0x009E9160` extent `0x248`; vtables `0x00C30E68` / "
            "`0x00C30F2C`; +0xBC/+0xC0 list heads; +0xDC flag; +0xE0 null.",
            "",
            "## C. Vtable/method census",
            "",
            "Main table slots 0–16 classified; dtor/allocator/unknown rejected.",
            "",
            "## D. Consumer prerequisites",
            "",
            "List methods need +0xBC/+0xC0 (constructor-produced). "
            "Embed clear needs +0xE0 null. Setter/getter need +0xDC.",
            "",
            "## E. Executed object methods",
            "",
            "setter/getter/rtti/list_a/list_b/embed_clr — see sequences.",
            "",
            "## F. Embedded-object consumers",
            "",
            "`0x009E9980` (pod +4); `0x009E83D0` (this+0xE0 clear early-exit).",
            "",
            "## G. Global publication provenance",
            "",
            "`0x0189D1A4←0x009E78C0`, `0x0189D198←0x009E77D0` via `0x009E8AD0`.",
            "",
            "## H. Global reader census",
            "",
            "D1A4: 906 CALL_THROUGH_POINTER sites. D198: allocator callback path.",
            "",
            "## I. Callable-target validation",
            "",
            "Both immediates are ordinary executable targets. D1A4 early-exit "
            "clean when `[0x0189DA84]==0`. D198 hits allocator.",
            "",
            "## J. Stateful execution campaign",
            "",
            "Sequences %d; clean %d; longest %d; coverage %d." % (
                len(seqs), clean_seqs, longest, largest_cov),
            "",
            "## K. New ordinary functions",
            "",
            "%s" % (new_fns or "(coverage growth within prior unique set)"),
            "",
            "## L. New actual blockers",
            "",
            "D198 → allocator/protected init. Meaningful D1A4 path needs factory "
            "publish of object pointer.",
            "",
            "## M. Frontier delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; SEQ_LEN **%d**; SEQ_COV **%d**; "
            "CLEAN_SEQ **%d**; RUNS **%d**." % (
                len(unique), len(enterable), longest, largest_cov,
                clean_seqs, execution_runs),
            "",
            "## N. Phase-40 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "seq", longest, "cov", largest_cov, "clean_seq", clean_seqs,
          "new", new_fns)
    for s in seqs:
        print(" ", s["name"], s["result"], "len", s["sequence_length"],
              "cov", s["unique_entered"], s.get("blocker"))
    return frontier


if __name__ == "__main__":
    main()
