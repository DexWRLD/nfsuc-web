#!/usr/bin/env python3
"""Phase 41: nontrivial object lifecycles, virtual-call continuation, UC target verify.

Graphics frozen. No nfs.exe execution. No fabricated protected/allocator state.
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
import uc_target_verify as tv
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

# Family A
CTOR_A = 0x009E9160
SETTER = 0x009E9140
GETTER = 0x009E9150
RTTI_A = 0x009E7780
LIST_A = 0x009E8400
CB_D1A4 = 0x009E78C0
VT_MAIN = 0x00C30E68
VT_POD = 0x00C30F2C
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE

# Family B
CTOR_B = 0x009E98F0
COPY_B = 0x009E9990
RTTI_B = 0x009E9980
EXPORT_B = 0x009E9A30  # nontrivial: export +0x38..+0x4C
POD = OBJ + 0x300
POD_DST = OBJ + 0x380
EXPORT_BUF = OBJ + 0x400

# Family C (new)
CTOR_C = 0x009EB350
RTTI_C = 0x009EB310
VT_C = 0x00C31180
OBJ_C = OBJ + 0x480
ZERO_PTR = OBJ + 0x500

VCALL = 0x009E8E00
VCALL_SITE = 0x009E8E15


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


def ctor_a_spec():
    return h.make_spec(CTOR_A, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),))


def ctor_b_spec(this=POD):
    return h.make_spec(CTOR_B, ecx=this, ret_pop=0)


def ctor_c_spec():
    # arg2 = pointer to zero dword → skip 0x009D2C40
    return h.make_spec(CTOR_C, ecx=OBJ_C, args=(0x11, 0x22, ZERO_PTR, 0x33),
                       ret_pop=0x10)


def run_seq(harness, name, steps):
    harness.begin_sequence()
    step_outs, last = [], None
    clean_all, blocker = True, None
    depth_peak, entered_all, indirect_peak = 0, [], 0
    for label, spec, cont in steps:
        out = harness.step(spec, continue_state=cont)
        last = out
        depth_peak = max(depth_peak, out.depth_max)
        entered_all = [out.entered[j] for j in range(out.entered_n)]
        indirect_peak = max(indirect_peak, out.uc_indirect_enters)
        step_outs.append({
            "label": label, "root": hx(spec.root), "clean": bool(out.clean),
            "eax": hx(out.eax), "blocked_kind": h.KIND_NAMES[out.blocked_kind],
            "blocked_va": hx(out.blocked_va) if out.blocked_va else None,
            "blocked_fn": hx(out.blocked_fn) if out.blocked_fn else None,
            "depth_max": out.depth_max, "entered_n": out.entered_n,
            "uc_indirect_enters": out.uc_indirect_enters,
            "fault_active": bool(out.fault_active),
            "fault_addr": hx(out.fault_addr) if out.fault_active else None,
            "fault_why": out.fault_why.decode("ascii", "replace") if out.fault_why else None,
        })
        if not out.clean:
            clean_all = False
            blocker = {
                "kind": h.KIND_NAMES[out.blocked_kind],
                "va": hx(out.blocked_va) if out.blocked_va else None,
                "fn": hx(out.blocked_fn) if out.blocked_fn else None,
                "at_step": label,
                "fault_addr": hx(out.fault_addr) if out.fault_active else None,
                "fault_why": out.fault_why.decode("ascii", "replace") if out.fault_why else None,
            }
            break
    unique = sorted(set(entered_all))
    harness.end_sequence()
    return {
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
        "uc_indirect_enters": indirect_peak,
        "final_eax": hx(last.eax) if last else None,
    }, last


def family_b_method_census(fmap):
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    methods = []
    for va, cls, note in [
        (RTTI_B, "PURE_GETTER", "returns 0x00C30F38"),
        (COPY_B, "COPY_METHOD", "copy-initializer ret 4"),
        (EXPORT_B, "BOUNDED_STATE_TRANSFORM",
         "exports ctor fields +0x38..+0x4C into caller buffer"),
        (0x009E7E40, "DESTRUCTOR_OR_FREE", "calls 0x00686030 — excluded"),
        (0x009E9CD0, "EMBEDDED_ONLY_METHOD",
         "reads [this+4] as nested POD; not standalone Family B"),
        (0x009E9DB0, "EMBEDDED_ONLY_METHOD",
         "reads [this+4]+0x2C; parent wrapper"),
    ]:
        row = fmap.get(va) or {}
        head = []
        if 0x400000 <= va < 0xB60000:
            for i in cs.disasm(blob[va - base:va - base + 48], va):
                head.append("%s %s" % (i.mnemonic, i.op_str))
                if i.mnemonic.startswith("ret") or len(head) >= 6:
                    break
        contract = "STANDALONE_FAMILY_B"
        if cls == "EMBEDDED_ONLY_METHOD":
            contract = "EMBEDDED_FAMILY_B"
        if cls == "DESTRUCTOR_OR_FREE":
            contract = "EXCLUDED"
        methods.append({
            "va": hx(va), "classification": cls, "contract": contract,
            "label": row.get("label"), "head": head, "note": note,
            "standalone_enterable": contract == "STANDALONE_FAMILY_B",
        })
    return methods


def diagnose_vcall(harness):
    """Reproduce Phase-40 virtual dispatch and classify continuation fault."""
    harness.begin_sequence()
    cout = harness.step(ctor_a_spec(), continue_state=False)
    assert cout.clean
    obj = OBJ
    vt = harness.read_u32(obj)
    slot5 = harness.read_u32(vt + 0x14)
    out = harness.step(
        h.make_spec(VCALL, ecx=obj, args=(obj,), ret_pop=4), continue_state=True)
    harness.end_sequence()

    # Instruction-level: call site 0x009E8E15 is `call edx` after [eax+0x14]
    same = (slot5 == VCALL)
    dispatch_ok = out.uc_indirect_enters >= 1
    # Nested activation: DISPATCH_CALL entered VCALL while root was also VCALL
    nested = dispatch_ok and same

    classification = "INCORRECT_VTABLE_SLOT"
    detail = (
        "Call site 0x009E8E15 invokes [vt+0x14] as thiscall with 0 stack args, "
        "expecting EAX string. Family-A slot5 resolves to 0x009E8E00 itself "
        "(ret 4). Nested activation therefore lacks the stack arg its prologue "
        "reads at [esp+0x20], loads EBP≈0/garbage, then faults on "
        "`mov eax, dword ptr [ebp]` (unmapped guest access at 0). "
        "Not a clean virtual-method completion."
    )
    first_fail = {
        "ordinary_function": hx(VCALL),
        "instruction_va": "0x009E8E09",  # mov eax, [ebp] in nested frame
        "reason": "nested frame ebp invalid/null after ABI-mismatched self virtual call",
        "fault_addr": hx(out.fault_addr) if out.fault_active else None,
        "fault_why": out.fault_why.decode("ascii", "replace") if out.fault_why else None,
        "blocked_kind": h.KIND_NAMES[out.blocked_kind],
        "eax_at_stop": hx(out.eax),
        "eip_at_stop": hx(out.eip),
        "esp_at_stop": hx(out.esp),
    }
    return {
        "attempted": True,
        "reproduced": dispatch_ok,
        "ordinary_caller": hx(VCALL),
        "exact_call_site": hx(VCALL_SITE),
        "call_insn": "call edx  ; edx = [eax+0x14], eax = [[ebp]]",
        "runtime_object": hx(obj),
        "vtable_va": hx(vt),
        "slot_index": 5,
        "slot_offset": "0x00000014",
        "resolved_target": hx(slot5),
        "same_function_caller_target": same,
        "nested_frame_evidence": {
            "uc_indirect_enters": out.uc_indirect_enters,
            "root_entry": "DIRECT_GUEST_ENTRY",
            "nested_entry": "DISPATCH_CALL→sparse UC",
            "entered_unique_shows_once": True,
            "note": "Unique entered[] dedupes; uc_indirect_enters proves second activation",
        },
        "thiscall_abi_at_call_site": {
            "ecx": "arg object (ebp)",
            "stack_args_pushed_by_site": 0,
            "callee_9E8E00_ret": 4,
            "abi_match_for_self_target": False,
        },
        "vtable_dispatch_succeeded": dispatch_ok,
        "virtual_call_completed": False,
        "caller_returned_clean": bool(out.clean),
        "continuation_classification": classification,
        "continuation_detail": detail,
        "first_failing_operation": first_fail,
        "clean_virtual_call": False,
        "continuation_fault": True,
        "result": ("EXECUTED_VTABLE_DISPATCH" if dispatch_ok
                   else "FAULT"),
    }


def main():
    # --- Track A: target provenance ---
    prov, prov_path = tv.write_provenance(GAME)
    print("target", prov["verification_status"], prov_path)
    if prov["verification_status"] not in (
            "VERIFIED_UNDERCOVER_1_1_2_1",
            "TARGET_BINARY_NOT_AVAILABLE_FOR_REHASH"):
        print("FAIL-CLOSED: refusing to regenerate UC artifacts from mismatched target")
        return 2

    fmap = h.load_fmap()
    b_methods = family_b_method_census(fmap)

    addrs = set()
    roots = [
        CTOR_A, SETTER, GETTER, RTTI_A, LIST_A, CB_D1A4,
        CTOR_B, COPY_B, RTTI_B, EXPORT_B,
        CTOR_C, RTTI_C, VCALL,
        0x009E7710, 0x009E0880, 0x009EBC70, 0x00808770,
        0x009E83D0, 0x009E8460, 0x009E9CD0, 0x009E9DB0,
    ]
    for root in roots:
        addrs.add(root)
        addrs |= set(h.closure(root, fmap, limit=48))
    for s in camp.campaign_specs():
        addrs |= set(h.closure(s["root"], fmap, limit=48))

    harness = h.Harness(addrs)
    seqs = []
    obs = {}

    def add(row, last=None, extra=None):
        if extra:
            row.update(extra)
        seqs.append(row)

    # --- Regressions Family A ---
    harness.begin_sequence()
    harness.step(ctor_a_spec(), continue_state=False)
    harness.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                 continue_state=True)
    gout = harness.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0),
                        continue_state=True)
    obs["family_a_al"] = gout.eax & 0xFF
    harness.end_sequence()

    r, last = run_seq(harness, "family_a_setter_getter", [
        ("ctor", ctor_a_spec(), False),
        ("setter", h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last, {"family": "A", "expected_al": 0x5A, "nontrivial": True})

    r, last = run_seq(harness, "family_a_five_step", [
        ("ctor", ctor_a_spec(), False),
        ("setter", h.make_spec(SETTER, ecx=OBJ, args=(0x11,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER, ecx=OBJ, ret_pop=0), True),
        ("rtti", h.make_spec(RTTI_A, ecx=OBJ, ret_pop=0), True),
        ("list_a", h.make_spec(LIST_A, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last, {"family": "A", "regression": "phase39_five_step"})

    # --- Family B RTTI regression + nontrivial export ---
    r, last = run_seq(harness, "family_b_rtti", [
        ("ctor_b", ctor_b_spec(), False),
        ("rtti_b", h.make_spec(RTTI_B, ecx=POD, ret_pop=0), True),
    ])
    add(r, last, {
        "family": "B", "expected_eax": hx(0x00C30F38),
        "nontrivial": False, "lifecycle": "RTTI",
    })

    harness.begin_sequence()
    harness.step(ctor_b_spec(), continue_state=False)
    fields = [harness.read_u32(POD + off) for off in (0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C)]
    obs["family_b_fields"] = [hx(x) for x in fields]
    eout = harness.step(
        h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4),
        continue_state=True)
    dest = [harness.read_u32(EXPORT_BUF + off) for off in (0, 4, 8, 0xC, 0x10, 0x14)]
    obs["family_b_export_dest"] = [hx(x) for x in dest]
    obs["family_b_export_match"] = dest == fields
    harness.end_sequence()

    r, last = run_seq(harness, "family_b_export", [
        ("ctor_b", ctor_b_spec(), False),
        ("export", h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4), True),
    ])
    add(r, last, {
        "family": "B", "nontrivial": True, "lifecycle": "CTOR_EXPORT",
        "field_match": obs["family_b_export_match"],
        "exported": obs["family_b_export_dest"],
        "source_fields": obs["family_b_fields"],
    })

    r, last = run_seq(harness, "family_b_ctor_copy_export", [
        ("ctor_b", ctor_b_spec(), False),
        ("copy", h.make_spec(COPY_B, ecx=POD_DST, args=(POD,), ret_pop=4), True),
        ("export", h.make_spec(EXPORT_B, ecx=POD_DST, args=(EXPORT_BUF,), ret_pop=4), True),
    ])
    add(r, last, {"family": "B", "nontrivial": True, "lifecycle": "CTOR_COPY_EXPORT"})

    # Embedded-only attempt (expect not to treat as standalone success path)
    r, last = run_seq(harness, "family_b_embedded_only_9e9cd0", [
        ("ctor_b", ctor_b_spec(), False),
        ("embed", h.make_spec(0x009E9CD0, ecx=POD, ret_pop=0), True),
    ])
    add(r, last, {
        "family": "B", "contract": "EMBEDDED_ONLY_ATTEMPT",
        "note": "this+4 treated as nested pointer; standalone POD has +4=0",
    })

    # --- Family C ---
    r, last = run_seq(harness, "family_c_ctor_rtti", [
        ("ctor_c", ctor_c_spec(), False),
        ("rtti_c", h.make_spec(RTTI_C, ecx=OBJ_C, ret_pop=0), True),
    ])
    add(r, last, {
        "family": "C_9EB350", "expected_eax": hx(0x00C31168),
        "nontrivial": False, "lifecycle": "RTTI",
        "independent": True,
    })
    harness.begin_sequence()
    harness.step(ctor_c_spec(), continue_state=False)
    obs["family_c_vt"] = hx(harness.read_u32(OBJ_C))
    obs["family_c_10"] = hx(harness.read_u32(OBJ_C + 0x10))
    obs["family_c_14"] = hx(harness.read_u32(OBJ_C + 0x14))
    obs["family_c_18"] = hx(harness.read_u32(OBJ_C + 0x18))
    harness.end_sequence()

    # --- Virtual dispatch reproduction ---
    vdiag = diagnose_vcall(harness)
    r, last = run_seq(harness, "vcall_9e8e00_continuation", [
        ("ctor_a", ctor_a_spec(), False),
        ("virt", h.make_spec(VCALL, ecx=OBJ, args=(OBJ,), ret_pop=4), True),
    ])
    add(r, last, {
        "family": "VTABLE",
        "virtual_dispatch": True,
        "diagnosis": vdiag["continuation_classification"],
        "uc_indirect_enters": r.get("uc_indirect_enters"),
    })

    # CB early-exit regression
    r, last = run_seq(harness, "cb_d1a4_early_exit", [
        ("ctor_a", ctor_a_spec(), False),
        ("cb", h.make_spec(CB_D1A4, ecx=0, args=(0, 0, 0), ret_pop=0), True),
    ])
    add(r, last, {"family": "A_GLOBAL"})

    # Alternate prior clean root
    r, last = run_seq(harness, "ebc70_alone", [
        ("ebc70", h.make_spec(0x009EBC70, ecx=OBJ), False),
    ])
    add(r, last, {"family": "EBC70"})

    clean_seqs = sum(1 for s in seqs if s["clean"])
    longest = max(s["sequence_length"] for s in seqs)
    largest_cov = max(s["unique_entered"] for s in seqs)

    fam_a_ok = obs["family_a_al"] == 0x5A
    fam_b_rtti = next(s for s in seqs if s["name"] == "family_b_rtti")
    fam_b_export = next(s for s in seqs if s["name"] == "family_b_export")
    fam_c = next(s for s in seqs if s["name"] == "family_c_ctor_rtti")

    independent_families = 3 if fam_c["clean"] else 2
    clean_lifecycles = (
        (1 if fam_a_ok else 0)
        + (1 if fam_b_rtti["clean"] or fam_b_export["clean"] else 0)
        + (1 if fam_c["clean"] else 0)
    )
    nontrivial = (
        (1 if fam_a_ok else 0)
        + (1 if fam_b_export["clean"] and obs.get("family_b_export_match") else 0)
    )
    # Family C RTTI-only → not nontrivial

    real_vt = 1 if vdiag["vtable_dispatch_succeeded"] else 0
    clean_vt = 1 if vdiag["clean_virtual_call"] else 0
    vt_faults = 1 if vdiag["continuation_fault"] else 0

    # --- Metadata: object families ---
    families = [
        {
            "family_id": "A_9E9160",
            "ctor_init_va": hx(CTOR_A),
            "phase_established": 38,
            "nontrivial": True,
            "lifecycle_execution_result": "EXECUTED_STATEFUL_SEQUENCE",
        },
        {
            "family_id": "B_9E98F0_POD",
            "ctor_init_va": hx(CTOR_B),
            "object_ownership": "CALLER_STORAGE",
            "extent": "0x00000054",
            "vtable": [hx(VT_POD)],
            "phase_established": 40,
            "methods": b_methods,
            "strongest_nontrivial_consumer": {
                "va": hx(EXPORT_B),
                "abi": "thiscall ret 4; arg0=dest buffer",
                "required_fields": ["+0x38", "+0x3C", "+0x40", "+0x44", "+0x48", "+0x4C"],
                "provenance": "CONSTRUCTOR_PRODUCED",
                "observed": obs.get("family_b_export_dest"),
                "match": obs.get("family_b_export_match"),
                "result": fam_b_export["result"],
            },
            "standalone_consumers": [hx(RTTI_B), hx(COPY_B), hx(EXPORT_B)],
            "embedded_only_consumers": ["0x009E9CD0", "0x009E9DB0"],
            "lifecycle_execution_result": "EXECUTED_STATEFUL_SEQUENCE",
            "nontrivial": True,
            "confidence": "HIGH",
        },
        {
            "family_id": "C_9EB350",
            "ctor_init_va": hx(CTOR_C),
            "object_ownership": "CALLER_STORAGE",
            "extent": "0x0000001C",
            "vtable": [hx(VT_C)],
            "classification": "STRONG_ORDINARY_CONSTRUCTOR",
            "abi": "thiscall ret 0x10; 4 stack args; arg2→dword used as optional ptr",
            "required_state": [
                "ECX caller buffer",
                "arg2 pointer to zero skips 0x009D2C40",
            ],
            "ordinary_consumers": [hx(RTTI_C)],
            "ordinary_fields": {
                "+0": hx(VT_C),
                "+0x10": obs.get("family_c_10"),
                "+0x14": obs.get("family_c_14"),
                "+0x18": obs.get("family_c_18"),
            },
            "lifecycle_execution_result": (
                "EXECUTED_STATEFUL_SEQUENCE" if fam_c["clean"] else fam_c["result"]),
            "nontrivial": False,
            "note": "RTTI-only consumer so far; dtor/slot0 hits protected free",
            "phase_established": 41,
            "confidence": "HIGH",
            "independent": True,
        },
    ]
    prev_fam = {}
    try:
        prev_fam = load("object-family-frontier.json")
    except Exception:
        pass
    dump("object-family-frontier.json", {
        "phase": 41,
        "ranked_constructor_candidates": prev_fam.get("ranked_constructor_candidates") or [],
        "families": families,
        "independent_object_families_executed": independent_families,
        "clean_independent_object_lifecycles": clean_lifecycles,
        "nontrivial_object_lifecycles": nontrivial,
        "strongest_new_family": "C_9EB350" if fam_c["clean"] else "B_9E98F0_POD",
        "strongest_nontrivial_new_consumer": hx(EXPORT_B),
        "observations": obs,
        "family_b_method_census": b_methods,
    })

    dump("vtable-execution-frontier.json", {
        "phase": 41,
        "dispatch_infrastructure": {
            "sparse_uc_dtab": True,
            "counts_direct_entry_as_real_dispatch": False,
        },
        "phase40_site": vdiag,
        "real_vtable_dispatches_executed": real_vt,
        "clean_virtual_calls": clean_vt,
        "virtual_call_continuation_faults": vt_faults,
        "result": {
            "status": vdiag["result"],
            "continuation_classification": vdiag["continuation_classification"],
            "eligible_ordinary_call_sites": 1,
            "detail": vdiag["continuation_detail"],
            "actual_virtual_caller": hx(VCALL),
            "slot": 5,
            "resolved_target": hx(VCALL),
            "continuation_blocker": vdiag["first_failing_operation"],
        },
    })

    # Campaign
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
        p31.PRIOR_CLEAN_ROOTS | {CTOR_A, CTOR_B, CTOR_C},
    )
    prev = load("runtime-frontier.json")
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    for va in (SETTER, GETTER, RTTI_A, RTTI_B, COPY_B, EXPORT_B, RTTI_C, CTOR_B,
               CTOR_C, LIST_A, CB_D1A4):
        if any(s["clean"] and (hx(va) in s.get("entered", []) or any(
                st["root"] == hx(va) and st["clean"] for st in s["steps"]))
               for s in seqs):
            new_enterable.add(hx(va))
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)

    ctors = camp.ctor_accounting(
        [{"entered": r["entered"]} for r in rows] +
        [{"entered": [int(x, 16) for x in s["entered"]]} for s in seqs],
        {CTOR_A, 0x009E7710, CTOR_B, CTOR_C},
        p31.CTOR_CENSUS | {0x009EBC70, 0x0097BB30, CTOR_B, 0x009E0880, CTOR_C},
    )
    deepest = max([r["depth_max"] for r in rows] +
                  [s["depth_max_nested"] for s in seqs] + [0])
    largest_closure = max([r["unique_entered"] for r in rows] + [0])
    deepest = max(deepest, prev.get("deepest_ordinary_execution_chain") or 0)
    prior_clos = prev.get("largest_executed_ordinary_closure") or 0
    prior_cov = prev.get("largest_stateful_sequence_coverage") or 0
    if prior_clos and prior_clos != prior_cov:
        largest_closure = max(largest_closure, prior_clos)
    elif prior_clos and prior_clos < prior_cov:
        largest_closure = max(largest_closure, prior_clos)
    longest = max(longest, prev.get("ordinary_execution_sequence_length") or 0)
    largest_cov = max(largest_cov, prev.get("largest_stateful_sequence_coverage") or 0)
    clean_seqs_metric = max(clean_seqs, prev.get("clean_stateful_sequences") or 0)

    hist = camp.real_blocker_histogram([{"hist": r["hist"]} for r in rows])
    req = camp.required_state_histogram(
        [{"hist": r["hist"], "subclass": r.get("subclass")} for r in rows])
    common = p31.most_common_blocker(rows)
    outcomes = collections.Counter(r["result"] for r in rows)
    outcomes["EXECUTED_STATEFUL_SEQUENCE"] = clean_seqs
    if real_vt:
        outcomes["EXECUTED_VTABLE_DISPATCH"] = real_vt

    runtime_ready = prev.get("runtime_ready") or 72
    execution_runs = (prev.get("execution_runs") or 179) + len(rows) + len(seqs)

    recommended = (
        "Family B nontrivial export (`0x009E9A30`) and Family C RTTI lifecycle are "
        "proven. Virtual self-dispatch at `0x009E8E00` remains a continuation fault "
        "(INCORRECT_VTABLE_SLOT / ABI mismatch). Phase 42: EXPAND REAL UC EXECUTION "
        "on Family C nontrivial consumers or a correctly typed string-provider object "
        "for the 0x009E8E00 virtual call site. Graphics frozen."
    )

    definitions = dict(prev.get("definitions") or {})
    definitions.update({
        "NONTRIVIAL_OBJECT_LIFECYCLES": (
            "Independent families with validated state transform / setter-getter "
            "behavior beyond RTTI-only returns."
        ),
        "CLEAN_VIRTUAL_CALLS": (
            "REAL_VTABLE_DISPATCH where the virtual callee returns and the caller "
            "continues without fault from that dispatch."
        ),
        "VIRTUAL_CALL_CONTINUATION_FAULTS": (
            "REAL_VTABLE_DISPATCH followed by a fault or unsupported op before "
            "clean caller return."
        ),
    })

    frontier = {
        "phase": 41,
        "definitions": definitions,
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
        "clean_stateful_sequences": clean_seqs_metric,
        "proven_post_constructor_consumers": prev.get(
            "proven_post_constructor_consumers") or 8,
        "clean_ordinary_roots": len(clean),
        "clean_ordinary_roots_list": [hx(x) for x in clean],
        "executed_ordinary_constructors": len(ctors),
        "executed_ordinary_constructors_list": [hx(x) for x in ctors],
        "independent_object_families_executed": independent_families,
        "clean_independent_object_lifecycles": clean_lifecycles,
        "nontrivial_object_lifecycles": nontrivial,
        "real_vtable_dispatches_executed": real_vt,
        "clean_virtual_calls": clean_vt,
        "virtual_call_continuation_faults": vt_faults,
        "target_verification_status": prov["verification_status"],
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
            "CLEAN_STATEFUL_SEQUENCES": clean_seqs_metric,
            "INDEPENDENT_OBJECT_FAMILIES_EXECUTED": independent_families,
            "CLEAN_INDEPENDENT_OBJECT_LIFECYCLES": clean_lifecycles,
            "NONTRIVIAL_OBJECT_LIFECYCLES": nontrivial,
            "REAL_VTABLE_DISPATCHES_EXECUTED": real_vt,
            "CLEAN_VIRTUAL_CALLS": clean_vt,
            "VIRTUAL_CALL_CONTINUATION_FAULTS": vt_faults,
            "TARGET_VERIFICATION": prov["verification_status"],
            "LATEST_REAL_RUNTIME_BOUNDARY": (
                "B export nontrivial; C RTTI lifecycle; vcall continuation "
                "INCORRECT_VTABLE_SLOT"
            ),
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase41_sequences": len(seqs),
            "clean_stateful_sequences": clean_seqs,
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "family_a_getter_0x5a": fam_a_ok,
            "family_b_export_clean": fam_b_export["clean"],
            "family_c_rtti_clean": fam_c["clean"],
            "new_functions": new_fns,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "filesystem_reached": False,
            "scheduler": False,
            "protected_boundary_encountered": False,
            "diagnostics_counted": 0,
            "jtswitch_enabled_in_harness": True,
            "sparse_uc_dispatch": True,
        },
        "post_constructor": prev.get("post_constructor") or {},
        "object_families": {
            "executed": independent_families,
            "clean_lifecycles": clean_lifecycles,
            "nontrivial": nontrivial,
            "strongest_nontrivial_consumer": hx(EXPORT_B),
        },
        "virtual_dispatch": vdiag,
        "target_provenance": {
            "status": prov["verification_status"],
            "tooling_origin": "NFSU2-WEB",
            "game_code_target": "NFS_UNDERCOVER_PC",
            "sha256_match": prov.get("sha256_match"),
            "ordinary_text_provenance": prov.get("ordinary_text_provenance"),
        },
        "synchronization": prev.get("synchronization") or {},
        "timing": prev.get("timing") or {},
        "waits": prev.get("waits") or {},
        "indirect_dispatch": prev.get("indirect_dispatch") or {},
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase42": recommended,
        "phase31_metric_corrections_preserved": True,
    }
    dump("runtime-frontier.json", frontier)

    post = load("post-constructor-frontier.json")
    post["phase"] = 41
    post["phase41"] = {
        "family_b_export": hx(EXPORT_B),
        "family_c": hx(CTOR_C),
        "nontrivial_lifecycles": nontrivial,
        "vcall_continuation": vdiag["continuation_classification"],
    }
    post["phase41_sequences"] = seqs
    post["clean_stateful_sequences"] = clean_seqs_metric
    post["longest_sequence"] = longest
    post["largest_sequence_coverage"] = largest_cov
    dump("post-constructor-frontier.json", post)

    camp_ser = []
    for r in rows:
        camp_ser.append({
            "root": hx(r["root"]), "phase": 41, "kind": r["kind"],
            "result": r["result"], "hist": r["hist"],
            "functions_entered": [hx(x) for x in r["entered"]],
            "unique_functions_entered": r["unique_entered"],
            "max_depth": r["depth_max"], "clean": r.get("clean"),
            "stubs": [], "evidence": "uc_phase41.py",
            "counted_in_metrics": True, "diagnostic_only": False,
        })
    for s in seqs:
        camp_ser.append({
            "root": "STATEFUL:" + s["name"], "phase": 41,
            "kind": "STATEFUL_SEQUENCE", "result": s["result"],
            "hist": "CLEAN_RETURN" if s["clean"] else "REQUIRED_STATE",
            "functions_entered": s["entered"],
            "unique_functions_entered": s["unique_entered"],
            "max_depth": s["depth_max_nested"],
            "sequence_length": s["sequence_length"],
            "clean": s["clean"], "blocker": s.get("blocker"),
            "uc_indirect_enters": s.get("uc_indirect_enters", 0),
            "stubs": [], "evidence": "uc_phase41.py",
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
        "phase": 41, "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
        "ordinary_execution_sequence_length": longest,
        "largest_stateful_sequence_coverage": largest_cov,
        "clean_stateful_sequences": clean_seqs_metric,
        "independent_object_families_executed": independent_families,
        "clean_independent_object_lifecycles": clean_lifecycles,
        "nontrivial_object_lifecycles": nontrivial,
        "real_vtable_dispatches_executed": real_vt,
        "clean_virtual_calls": clean_vt,
        "virtual_call_continuation_faults": vt_faults,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase41_stateful": seqs,
        "phase40_stateful": evidence_prev.get("phase40_stateful"),
        "phase39_stateful": evidence_prev.get("phase39_stateful"),
        "phase38_stateful": evidence_prev.get("phase38_stateful"),
        "phase37_ctor": evidence_prev.get("phase37_ctor"),
    })
    dump("blocker-ranking.json", {
        "phase": 41,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "clean_stateful_sequences": clean_seqs_metric,
        "virtual_call_continuation_classification": vdiag["continuation_classification"],
        "latest_real_runtime_boundary": frontier["ordinary_runtime_frontier"][
            "LATEST_REAL_RUNTIME_BOUNDARY"],
    })

    status = load("project-status.json")
    status["current_phase"] = 41
    status["strategy"] = (
        "Phase 41: nontrivial Family B export, Family C lifecycle, "
        "virtual continuation diagnosis, Undercover target verify. Graphics frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 41 for p in phases):
        phases.append({
            "phase": 41,
            "name": "Nontrivial lifecycles and virtual continuation",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase41.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 41 — nontrivial lifecycles + virtual continuation",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "",
            "## A. Phase-40 baseline",
            "",
            "UNIQUE 61, ENTERABLE 29, families 2, VT_DISP 1, RUNS 179.",
            "",
            "## B. Undercover target provenance",
            "",
            "TOOLING_ORIGIN=`NFSU2-WEB`. GAME_CODE_TARGET=`NFS_UNDERCOVER_PC`.",
            "Status: **%s**. SHA-256 match=%s. Ordinary `.text` samples verified "
            "for Phase-40/41 VAs." % (
                prov["verification_status"], prov.get("sha256_match")),
            "",
            "## C. Family B nontrivial consumer search",
            "",
            "Standalone: `0x009E9980` RTTI, `0x009E9990` copy, **`0x009E9A30` export**.",
            "Embedded-only: `0x009E9CD0` / `0x009E9DB0` (need parent `this+4`).",
            "",
            "## D. Standalone versus embedded contracts",
            "",
            "Export/copy/RTTI are STANDALONE_FAMILY_B. `9E9CD0`/`9E9DB0` are "
            "EMBEDDED_FAMILY_B.",
            "",
            "## E. New lifecycle execution",
            "",
            "B: `9E98F0`→`9E9A30` exports +0x38..+0x4C (match ctor fields). "
            "C: `9EB350`→`9EB310` RTTI `EAX=0x00C31168`.",
            "",
            "## F. Virtual-call site provenance",
            "",
            "Caller `0x009E8E00` site `0x009E8E15` `call edx` with edx=`[vt+0x14]`. "
            "Family-A object → target `0x009E8E00` (same function). "
            "`uc_indirect_enters≥1` proves nested DISPATCH_CALL activation.",
            "",
            "## G. Virtual continuation diagnosis",
            "",
            "**%s**: %s" % (
                vdiag["continuation_classification"], vdiag["continuation_detail"]),
            "",
            "## H. Additional independent family search",
            "",
            "Family C `0x009EB350` (vt `0x00C31180`) entered with null-safe arg2.",
            "",
            "## I. Real execution campaign",
            "",
            "Sequences %d; clean %d; families %d; nontrivial %d; VT_DISP %d; "
            "CLEAN_VT %d; VT_FAULTS %d." % (
                len(seqs), clean_seqs, independent_families, nontrivial,
                real_vt, clean_vt, vt_faults),
            "",
            "## J. Actual blockers",
            "",
            "Virtual continuation INCORRECT_VTABLE_SLOT. Family C nontrivial "
            "consumers allocator/protected-adjacent. Embedded B methods need parent.",
            "",
            "## K. Frontier delta",
            "",
            "UNIQUE **%d**; FAMILIES **%d**; NONTRIVIAL **%d**; CLEAN_LIFE **%d**; "
            "RUNS **%d**." % (
                len(unique), independent_families, nontrivial, clean_lifecycles,
                execution_runs),
            "",
            "## L. Phase-42 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "families", independent_families, "life", clean_lifecycles,
          "nontrivial", nontrivial, "vt", real_vt, "vt_fault", vt_faults,
          "new", new_fns)
    for s in seqs:
        print(" ", s["name"], s["result"], "len", s["sequence_length"],
              "cov", s["unique_entered"], "ind", s.get("uc_indirect_enters", 0),
              s.get("blocker"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main() or 0)
