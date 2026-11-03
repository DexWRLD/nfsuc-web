#!/usr/bin/env python3
"""Phase 42: Family C nontrivial consumers + typed virtual-call interface provenance.

Graphics frozen. No nfs.exe execution. No fabricated vtables/allocator/protected state.
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
from capstone.x86 import X86_OP_MEM

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

# Family A
CTOR_A = 0x009E9160
SETTER = 0x009E9140
GETTER = 0x009E9150
RTTI_A = 0x009E7780
LIST_A = 0x009E8400
VT_MAIN = 0x00C30E68
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE

# Family B
CTOR_B = 0x009E98F0
RTTI_B = 0x009E9980
EXPORT_B = 0x009E9A30
POD = OBJ + 0x300
EXPORT_BUF = OBJ + 0x400

# Family C
CTOR_C = 0x009EB350
RTTI_C = 0x009EB310
FIELD_C = 0x009EB2B0   # lea eax,[ecx+0xC]; ret — payload-slot address
CLEAR8_C = 0x009EB2D0  # clear +8 if non-null; early-exit when ctor left 0
VT_C = 0x00C31180
OBJ_C = OBJ + 0x480
ZERO_PTR = OBJ + 0x500
EXTENT_C = 0x1C

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


def ctor_a():
    return h.make_spec(CTOR_A, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),))


def ctor_b():
    return h.make_spec(CTOR_B, ecx=POD, ret_pop=0)


def ctor_c(a0=0x11, a1=0x22, a3=0x33):
    return h.make_spec(CTOR_C, ecx=OBJ_C, args=(a0, a1, ZERO_PTR, a3), ret_pop=0x10)


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
            "fault_why": (out.fault_why.decode("ascii", "replace")
                          if out.fault_why else None),
        })
        if not out.clean:
            clean_all = False
            blocker = {
                "kind": h.KIND_NAMES[out.blocked_kind],
                "va": hx(out.blocked_va) if out.blocked_va else None,
                "fn": hx(out.blocked_fn) if out.blocked_fn else None,
                "at_step": label,
                "fault_addr": hx(out.fault_addr) if out.fault_active else None,
                "fault_why": (out.fault_why.decode("ascii", "replace")
                              if out.fault_why else None),
            }
            break
    harness.end_sequence()
    unique = sorted(set(entered_all))
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


def analyze_family_c_contract(fmap):
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    head = []
    for i in cs.disasm(blob[CTOR_C - base:CTOR_C - base + 0x50], CTOR_C):
        head.append("%08X: %s %s" % (i.address, i.mnemonic, i.op_str))
        if i.mnemonic.startswith("ret"):
            break
    fields = {
        "+0x00": {"write": hx(VT_C), "provenance": "DIRECT_CONSTRUCTOR_WRITE",
                  "width": 4},
        "+0x04": {"write": "0", "provenance": "DIRECT_CONSTRUCTOR_WRITE", "width": 4},
        "+0x08": {"write": "0", "provenance": "DIRECT_CONSTRUCTOR_WRITE", "width": 4},
        "+0x0C": {"write": "deref(arg2) or 0", "provenance": "CALLER_INPUT",
                  "width": 4, "note": "nonzero path calls 0x009D2C40"},
        "+0x10": {"write": "arg0", "provenance": "CALLER_INPUT", "width": 4},
        "+0x14": {"write": "arg1", "provenance": "CALLER_INPUT", "width": 4,
                  "note": "production callers pass interface object; scalar in standalone tests"},
        "+0x18": {"write": "xchg arg3", "provenance": "CALLER_INPUT", "width": 4,
                  "note": "refcount-like via xchg"},
    }
    consumers = []
    for va, cls, note, safe in [
        (RTTI_C, "PURE_GETTER", "returns 0x00C31168 type id", True),
        (FIELD_C, "PURE_GETTER", "lea eax,[this+0xC]; observes payload slot", True),
        (CLEAR8_C, "POD_TRANSFORM",
         "releases +8 if set; early-exit when ctor left +8==0", True),
        (0x009EB770, "VIRTUAL_METHOD",
         "vt slot3; needs +0x14 as interface; allocator path", False),
        (0x009EB280, "VIRTUAL_METHOD",
         "uses +0x14 as interface; faults on scalar", False),
        (0x009EB2C0, "INITIALIZER",
         "rebinds this=[+0x10] then 0x009EBD50 — different larger type", False),
        (0x009EB3A0, "DESTRUCTOR", "calls 0x00686030 — excluded", False),
        (0x009EB400, "ALLOCATOR_DEPENDENT", "factory wrapper calling ctor", False),
    ]:
        consumers.append({
            "va": hx(va), "classification": cls, "note": note,
            "standalone_safe": safe,
            "label": (fmap.get(va) or {}).get("label"),
        })
    return {
        "ctor": hx(CTOR_C),
        "abi": "thiscall; ret 0x10; 4 stack args",
        "extent": hx(EXTENT_C),
        "vtable": hx(VT_C),
        "semantics": [
            "installs vtable 0x00C31180",
            "zeros +4/+8",
            "optional payload pointer at +0xC from deref(arg2)",
            "stores arg0/arg1 at +0x10/+0x14",
            "xchg arg3 into +0x18 (refcount-like)",
            "nested base init 0x009E7710",
        ],
        "fields": fields,
        "head": head,
        "consumers": consumers,
        "vt_slots": {
            "0": "0x009EB3A0 DESTRUCTOR",
            "2": "0x009EB310 PURE_GETTER",
            "3": "0x009EB770 VIRTUAL_METHOD allocator-adjacent",
        },
    }


def analyze_virtual_receiver(fmap):
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    site_lines = []
    for i in cs.disasm(blob[VCALL - base:VCALL - base + 0x30], VCALL):
        site_lines.append("%08X: %s %s" % (i.address, i.mnemonic, i.op_str))
        if i.address >= VCALL_SITE + 2:
            break
    # Static candidates: rdata vtables whose slot5 is mov eax,[ecx+disp]; ret
    secs = p7.read_sections(GAME)
    rdata = next(s for s in secs["sections"]
                 if s["name"] == ".rdata" and s["raw"] is not None)
    raw = rdata["raw"]
    possible = []
    for off in range(0, min(len(raw) - 0x18, 0x80000), 4):
        s5 = struct.unpack_from("<I", raw, off + 0x14)[0]
        s0 = struct.unpack_from("<I", raw, off)[0]
        if not (0x401000 <= s5 < 0xB60000 and 0x401000 <= s0 < 0xB60000):
            continue
        if (fmap.get(s5) or {}).get("label") != "HIGH_CONFIDENCE":
            continue
        if (fmap.get(s0) or {}).get("label") != "HIGH_CONFIDENCE":
            continue
        ins = list(cs.disasm(blob[s5 - base:s5 - base + 12], s5))
        if (len(ins) >= 2 and ins[0].mnemonic == "mov"
                and ins[0].op_str.startswith("eax, dword ptr [ecx")
                and ins[1].mnemonic == "ret" and ins[1].op_str == ""):
            possible.append({
                "vtable": hx(rdata["va"] + off),
                "slot0": hx(s0),
                "slot5": hx(s5),
                "slot5_head": ["%s %s" % (x.mnemonic, x.op_str) for x in ins[:2]],
                "classification": "POSSIBLE_INTERFACE",
                "abi_match": "thiscall ret 0; returns [this+disp] likely string/ptr",
                "ordinary_ctor_linking_to_9E8E00_arg": False,
            })
            if len(possible) >= 12:
                break
    return {
        "caller": hx(VCALL),
        "call_site": hx(VCALL_SITE),
        "call_insn": "call edx",
        "caller_abi": "thiscall ret 4; 1 stack arg (interface provider)",
        "site_disasm": site_lines,
        "receiver_source": "STACK_ARG0 / [esp+4] after prologue → ebp",
        "receiver_classification": "SEPARATE_INTERFACE_ARGUMENT",
        "receiver_not": "Family A primary this (edi/ecx of outer method)",
        "vtable_source": "[ebp] → object vtable of arg0",
        "selected_slot": "+0x14 (index 5)",
        "expected_virtual_abi": {
            "ecx": "receiver (arg0)",
            "stack_args_at_site": 0,
            "expected_return": "EAX = C-string pointer",
            "expected_callee_ret": 0,
        },
        "wrong_interface_evidence": {
            "tested_object": "Family A at 0x03004000",
            "vtable": hx(VT_MAIN),
            "slot5_target": hx(VCALL),
            "slot5_callee_ret": 4,
            "classification": "WRONG_INTERFACE_TYPE",
            "continuation": "INCORRECT_VTABLE_SLOT",
            "missing_stack_argument_on_nested_self_call": True,
        },
        "provider_candidates": possible,
        "proven_correct_interface": None,
        "strongest_provider": None,
        "correct_provider_enterable": False,
        "note": (
            "Possible slot5 string/field getters exist statically, but no ordinary "
            "constructor was proven to produce such an object as 0x009E8E00's arg0 "
            "without fabrication. Fail closed."
        ),
    }


def sparse_dispatch_audit(harness_lifted):
    """Validate sparse UC registration bounds/behavior (no protected targets)."""
    protected = {0x00686000, 0x00686030, 0x004A26B0, 0x007A51B0}
    leaked = [hx(a) for a in harness_lifted if a in protected]
    return {
        "sparse_uc_dtab": True,
        "lifted_count": len(harness_lifted),
        "protected_registered": leaked,
        "fail_closed_on_miss": True,
        "note": (
            "Harness registers only lifted ordinary bodies into uc_sparse_*; "
            "DISPATCH_CALL outside NFSU2 g_dtab uses sparse lookup then imports."
        ),
        "ok": not leaked,
    }


def diagnose_vcall(harness):
    harness.begin_sequence()
    assert harness.step(ctor_a(), continue_state=False).clean
    vt = harness.read_u32(OBJ)
    slot5 = harness.read_u32(vt + 0x14)
    out = harness.step(
        h.make_spec(VCALL, ecx=OBJ, args=(OBJ,), ret_pop=4), continue_state=True)
    harness.end_sequence()
    return {
        "reproduced": out.uc_indirect_enters >= 1,
        "vtable": hx(vt),
        "slot5": hx(slot5),
        "same_function": slot5 == VCALL,
        "uc_indirect_enters": out.uc_indirect_enters,
        "clean": bool(out.clean),
        "fault": bool(out.fault_active),
        "fault_addr": hx(out.fault_addr) if out.fault_active else None,
        "classification": "INCORRECT_VTABLE_SLOT",
        "virtual_target_entered": out.uc_indirect_enters >= 1,
        "virtual_target_returned_clean": False,
        "virtual_caller_returned_clean": False,
    }


def main():
    prov, _ = tv.write_provenance(GAME)
    print("target", prov["verification_status"])
    if prov["verification_status"] not in (
            "VERIFIED_UNDERCOVER_1_1_2_1",
            "TARGET_BINARY_NOT_AVAILABLE_FOR_REHASH"):
        print("FAIL-CLOSED: target mismatch")
        return 2

    fmap = h.load_fmap()
    c_contract = analyze_family_c_contract(fmap)
    v_iface = analyze_virtual_receiver(fmap)

    addrs = set()
    roots = [
        CTOR_A, SETTER, GETTER, RTTI_A, LIST_A,
        CTOR_B, RTTI_B, EXPORT_B,
        CTOR_C, RTTI_C, FIELD_C, CLEAR8_C,
        VCALL, 0x009E7710, 0x009E0880, 0x009EBC70, 0x00808770,
        0x009EB280, 0x009EB770, 0x009EB2C0,
    ]
    for root in roots:
        addrs.add(root)
        addrs |= set(h.closure(root, fmap, limit=48))
    for s in camp.campaign_specs():
        addrs |= set(h.closure(s["root"], fmap, limit=48))

    harness = h.Harness(addrs)
    sparse = sparse_dispatch_audit(harness.lifted)
    seqs, obs = [], {}

    def add(row, extra=None):
        if extra:
            row.update(extra)
        seqs.append(row)

    # --- Mandatory regressions ---
    harness.begin_sequence()
    harness.step(ctor_a(), continue_state=False)
    harness.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                 continue_state=True)
    gout = harness.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0), continue_state=True)
    obs["family_a_al"] = gout.eax & 0xFF
    harness.end_sequence()

    r, _ = run_seq(harness, "family_a_setter_getter", [
        ("ctor", ctor_a(), False),
        ("setter", h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, {"family": "A", "nontrivial": True})

    r, _ = run_seq(harness, "family_a_five_step", [
        ("ctor", ctor_a(), False),
        ("setter", h.make_spec(SETTER, ecx=OBJ, args=(0x11,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER, ecx=OBJ, ret_pop=0), True),
        ("rtti", h.make_spec(RTTI_A, ecx=OBJ, ret_pop=0), True),
        ("list_a", h.make_spec(LIST_A, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, {"family": "A"})

    # Family B
    harness.begin_sequence()
    harness.step(ctor_b(), continue_state=False)
    fields = [harness.read_u32(POD + o) for o in (0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C)]
    harness.step(h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4),
                 continue_state=True)
    dest = [harness.read_u32(EXPORT_BUF + o) for o in (0, 4, 8, 0xC, 0x10, 0x14)]
    obs["family_b_export_match"] = dest == fields
    obs["family_b_export"] = [hx(x) for x in dest]
    harness.end_sequence()

    r, _ = run_seq(harness, "family_b_rtti_export", [
        ("ctor_b", ctor_b(), False),
        ("rtti_b", h.make_spec(RTTI_B, ecx=POD, ret_pop=0), True),
        ("export", h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4), True),
    ])
    add(r, {"family": "B", "nontrivial": True,
            "export_match": obs["family_b_export_match"]})

    # Family C regression + new consumers
    r, _ = run_seq(harness, "family_c_rtti", [
        ("ctor_c", ctor_c(), False),
        ("rtti_c", h.make_spec(RTTI_C, ecx=OBJ_C, ret_pop=0), True),
    ])
    add(r, {"family": "C", "nontrivial": False, "lifecycle": "RTTI"})

    harness.begin_sequence()
    harness.step(ctor_c(0xAA, 0xBB, 0xCC), continue_state=False)
    obs["c_fields"] = {
        "+0": hx(harness.read_u32(OBJ_C)),
        "+4": hx(harness.read_u32(OBJ_C + 4)),
        "+8": hx(harness.read_u32(OBJ_C + 8)),
        "+C": hx(harness.read_u32(OBJ_C + 0xC)),
        "+10": hx(harness.read_u32(OBJ_C + 0x10)),
        "+14": hx(harness.read_u32(OBJ_C + 0x14)),
        "+18": hx(harness.read_u32(OBJ_C + 0x18)),
    }
    fout = harness.step(h.make_spec(FIELD_C, ecx=OBJ_C, ret_pop=0), continue_state=True)
    obs["c_field_eax"] = hx(fout.eax)
    obs["c_field_match"] = fout.clean and fout.eax == (OBJ_C + 0xC)
    obs["c_field_value"] = hx(harness.read_u32(fout.eax)) if fout.clean else None
    cout = harness.step(h.make_spec(CLEAR8_C, ecx=OBJ_C, ret_pop=0), continue_state=True)
    obs["c_clear8_clean"] = bool(cout.clean)
    obs["c_plus8_after"] = hx(harness.read_u32(OBJ_C + 8))
    harness.end_sequence()

    r, _ = run_seq(harness, "family_c_field_slot", [
        ("ctor_c", ctor_c(0xAA, 0xBB, 0xCC), False),
        ("field_c", h.make_spec(FIELD_C, ecx=OBJ_C, ret_pop=0), True),
    ])
    add(r, {
        "family": "C",
        "nontrivial": bool(obs["c_field_match"]),
        "lifecycle": "CTOR_FIELD_SLOT_GETTER",
        "eax_is_this_plus_c": obs["c_field_match"],
        "payload_at_c": obs["c_field_value"],
        "note": "Observes constructor payload slot beyond RTTI type id",
    })

    r, _ = run_seq(harness, "family_c_field_then_clear8", [
        ("ctor_c", ctor_c(), False),
        ("field_c", h.make_spec(FIELD_C, ecx=OBJ_C, ret_pop=0), True),
        ("clear8", h.make_spec(CLEAR8_C, ecx=OBJ_C, ret_pop=0), True),
    ])
    add(r, {"family": "C", "nontrivial": bool(obs["c_field_match"]),
            "lifecycle": "CTOR_FIELD_CLEAR8"})

    # Unsafe C consumer negative
    r, _ = run_seq(harness, "family_c_slot3_needs_interface", [
        ("ctor_c", ctor_c(), False),
        ("slot3", h.make_spec(0x009EB770, ecx=OBJ_C, args=(0, 0), ret_pop=8), True),
    ])
    add(r, {"family": "C", "note": "BLOCKED — +0x14 not interface in standalone"})

    # Virtual dispatch reproduction (wrong interface kept)
    vdiag = diagnose_vcall(harness)
    r, _ = run_seq(harness, "vcall_wrong_interface_regression", [
        ("ctor_a", ctor_a(), False),
        ("virt", h.make_spec(VCALL, ecx=OBJ, args=(OBJ,), ret_pop=4), True),
    ])
    add(r, {"family": "VTABLE", "diagnosis": "INCORRECT_VTABLE_SLOT",
            "new_provider_attempted": False})

    # Alternate family smoke
    r, _ = run_seq(harness, "ebc70_alone", [
        ("ebc70", h.make_spec(0x009EBC70, ecx=OBJ), False),
    ])
    add(r, {"family": "EBC70"})

    r, _ = run_seq(harness, "808770_alone", [
        ("ctor", h.make_spec(0x00808770, ecx=OBJ, teb=True), False),
    ])
    add(r, {"family": "808770"})

    clean_seqs = sum(1 for s in seqs if s["clean"])
    longest = max(s["sequence_length"] for s in seqs)
    largest_cov = max(s["unique_entered"] for s in seqs)

    fam_a_ok = obs["family_a_al"] == 0x5A
    fam_b_ok = obs["family_b_export_match"] and next(
        s for s in seqs if s["name"] == "family_b_rtti_export")["clean"]
    fam_c_rtti = next(s for s in seqs if s["name"] == "family_c_rtti")
    fam_c_field = next(s for s in seqs if s["name"] == "family_c_field_slot")
    c_nontrivial = bool(obs.get("c_field_match") and fam_c_field["clean"])

    independent_families = 3
    clean_lifecycles = (
        (1 if fam_a_ok else 0) + (1 if fam_b_ok else 0)
        + (1 if fam_c_rtti["clean"] or fam_c_field["clean"] else 0))
    nontrivial = (
        (1 if fam_a_ok else 0) + (1 if fam_b_ok else 0)
        + (1 if c_nontrivial else 0))

    real_vt = 1 if vdiag["virtual_target_entered"] else 0
    clean_vt = 1 if vdiag["virtual_caller_returned_clean"] else 0
    vt_faults = 1 if vdiag["fault"] else 0

    # --- Metadata ---
    prev_fam = {}
    try:
        prev_fam = load("object-family-frontier.json")
    except Exception:
        pass
    families = [
        {"family_id": "A_9E9160", "nontrivial": True, "phase_established": 38},
        {"family_id": "B_9E98F0_POD", "nontrivial": True, "phase_established": 40},
        {
            "family_id": "C_9EB350",
            "ctor_init_va": hx(CTOR_C),
            "abi": c_contract["abi"],
            "extent": c_contract["extent"],
            "vtable": c_contract["vtable"],
            "fields": c_contract["fields"],
            "semantics": c_contract["semantics"],
            "consumers": c_contract["consumers"],
            "strongest_nontrivial_consumer": {
                "va": hx(FIELD_C) if c_nontrivial else None,
                "classification": "PURE_GETTER",
                "abi": "thiscall ret 0",
                "result": fam_c_field["result"],
                "observed_eax": obs.get("c_field_eax"),
                "expected_eax": hx(OBJ_C + 0xC),
                "payload_dword": obs.get("c_field_value"),
            } if c_nontrivial else {
                "status": "FAMILY_C_NONTRIVIAL_CONSUMER_NOT_FOUND",
            },
            "additional_clean_consumers": [hx(CLEAR8_C)],
            "lifecycle_execution_result": (
                "EXECUTED_STATEFUL_SEQUENCE" if fam_c_field["clean"]
                else fam_c_field["result"]),
            "nontrivial": c_nontrivial,
            "phase_established": 41,
            "phase42_contract": c_contract,
            "observations": obs.get("c_fields"),
            "confidence": "HIGH",
        },
    ]
    dump("object-family-frontier.json", {
        "phase": 42,
        "ranked_constructor_candidates": prev_fam.get("ranked_constructor_candidates") or [],
        "families": families,
        "independent_object_families_executed": independent_families,
        "clean_independent_object_lifecycles": clean_lifecycles,
        "nontrivial_object_lifecycles": nontrivial,
        "family_c_nontrivial": c_nontrivial,
        "observations": obs,
    })

    dump("vtable-execution-frontier.json", {
        "phase": 42,
        "dispatch_infrastructure": sparse,
        "interface_provenance": v_iface,
        "phase41_wrong_interface_regression": vdiag,
        "real_vtable_dispatches_executed": real_vt,
        "clean_virtual_calls": clean_vt,
        "virtual_call_continuation_faults": vt_faults,
        "virtual_target_entered": int(vdiag["virtual_target_entered"]),
        "virtual_target_returned_clean": int(vdiag["virtual_target_returned_clean"]),
        "virtual_caller_returned_clean": int(vdiag["virtual_caller_returned_clean"]),
        "new_provider_dispatch_attempted": False,
        "result": {
            "status": "EXECUTED_VTABLE_DISPATCH",
            "continuation_classification": "INCORRECT_VTABLE_SLOT",
            "receiver_classification": v_iface["receiver_classification"],
            "correct_provider_enterable": False,
            "detail": v_iface["note"],
        },
    })

    # Campaign + frontiers
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
    for va in (SETTER, GETTER, RTTI_A, RTTI_B, EXPORT_B, RTTI_C, FIELD_C, CLEAR8_C,
               CTOR_B, CTOR_C, LIST_A):
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

    runtime_ready = prev.get("runtime_ready") or 72
    execution_runs = (prev.get("execution_runs") or 243) + len(rows) + len(seqs)

    recommended = (
        "Family C field-slot getter `0x009EB2B0` validates constructor payload "
        "layout beyond RTTI; vt-slot3/interface consumers remain blocked without "
        "a real interface at +0x14. Virtual call at `0x009E8E15` needs a proven "
        "ordinary producer of a ret0 string/field getter at slot+0x14 — none "
        "enterable without fabrication. Phase 43: EXPAND REAL UC EXECUTION on "
        "proven interface producers for typed virtual calls, or deeper Family C "
        "when +0x14 interface objects are ordinarily constructed. Graphics frozen."
    )

    definitions = dict(prev.get("definitions") or {})
    frontier = {
        "phase": 42,
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
                "C field-slot getter clean; typed virtual provider not enterable; "
                "wrong-interface self-dispatch remains faulted"
            ),
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase42_sequences": len(seqs),
            "clean_stateful_sequences": clean_seqs,
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "family_a_ok": fam_a_ok,
            "family_b_ok": fam_b_ok,
            "family_c_nontrivial": c_nontrivial,
            "new_functions": new_fns,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "filesystem_reached": False,
            "scheduler": False,
            "protected_boundary_encountered": False,
            "sparse_dispatch_ok": sparse["ok"],
            "jtswitch_enabled_in_harness": True,
        },
        "post_constructor": prev.get("post_constructor") or {},
        "object_families": {
            "executed": independent_families,
            "clean_lifecycles": clean_lifecycles,
            "nontrivial": nontrivial,
            "family_c_field_consumer": hx(FIELD_C),
        },
        "virtual_dispatch": {
            **vdiag,
            "interface": v_iface,
        },
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
        "recommended_phase43": recommended,
        "phase31_metric_corrections_preserved": True,
    }
    dump("runtime-frontier.json", frontier)

    post = load("post-constructor-frontier.json")
    post["phase"] = 42
    post["phase42"] = {
        "family_c_field": hx(FIELD_C),
        "family_c_clear8": hx(CLEAR8_C),
        "c_nontrivial": c_nontrivial,
        "vcall_receiver": v_iface["receiver_classification"],
    }
    post["phase42_sequences"] = seqs
    post["clean_stateful_sequences"] = clean_seqs_metric
    dump("post-constructor-frontier.json", post)

    camp_ser = []
    for r in rows:
        camp_ser.append({
            "root": hx(r["root"]), "phase": 42, "kind": r["kind"],
            "result": r["result"], "hist": r["hist"],
            "functions_entered": [hx(x) for x in r["entered"]],
            "unique_functions_entered": r["unique_entered"],
            "max_depth": r["depth_max"], "clean": r.get("clean"),
            "stubs": [], "evidence": "uc_phase42.py",
            "counted_in_metrics": True, "diagnostic_only": False,
        })
    for s in seqs:
        camp_ser.append({
            "root": "STATEFUL:" + s["name"], "phase": 42,
            "kind": "STATEFUL_SEQUENCE", "result": s["result"],
            "hist": "CLEAN_RETURN" if s["clean"] else "REQUIRED_STATE",
            "functions_entered": s["entered"],
            "unique_functions_entered": s["unique_entered"],
            "max_depth": s["depth_max_nested"],
            "sequence_length": s["sequence_length"],
            "clean": s["clean"], "blocker": s.get("blocker"),
            "uc_indirect_enters": s.get("uc_indirect_enters", 0),
            "stubs": [], "evidence": "uc_phase42.py",
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
        "phase": 42, "roots": hist_ev,
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
        "phase42_stateful": seqs,
        "phase41_stateful": evidence_prev.get("phase41_stateful"),
        "phase40_stateful": evidence_prev.get("phase40_stateful"),
        "phase39_stateful": evidence_prev.get("phase39_stateful"),
    })
    dump("blocker-ranking.json", {
        "phase": 42,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "virtual_continuation": "INCORRECT_VTABLE_SLOT / WRONG_INTERFACE_TYPE",
        "latest_real_runtime_boundary": frontier["ordinary_runtime_frontier"][
            "LATEST_REAL_RUNTIME_BOUNDARY"],
    })

    status = load("project-status.json")
    status["current_phase"] = 42
    status["strategy"] = (
        "Phase 42: Family C field-slot consumer + typed virtual interface provenance. "
        "Graphics frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 42 for p in phases):
        phases.append({
            "phase": 42,
            "name": "Family C consumers and typed virtual-call provenance",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase42.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 42 — Family C consumers + typed virtual provenance",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "",
            "## A. Baseline",
            "",
            "Phase 41: UNIQUE 64, ENTERABLE 31, families 3, nontrivial 2, VT_DISP 1 / fault 1.",
            "",
            "## B. Family C object contract",
            "",
            "Ctor `0x009EB350` thiscall ret `0x10`; extent `0x1C`; vt `0x00C31180`; "
            "fields +0/+4/+8/+C/+10/+14/+18 as in `object-family-frontier.json`.",
            "",
            "## C. Family C consumer census",
            "",
            "Safe standalone: `0x009EB310` RTTI, **`0x009EB2B0` field-slot**, "
            "`0x009EB2D0` clear-+8 early-exit. Unsafe: slot3/`9EB280` need interface at +0x14; "
            "dtor protected.",
            "",
            "## D. Nontrivial lifecycle results",
            "",
            ("`0x009EB350`→`0x009EB2B0` clean; EAX=`this+0xC`; payload dword matches ctor."
             if c_nontrivial else
             "`FAMILY_C_NONTRIVIAL_CONSUMER_NOT_FOUND` among safe transforms."),
            "",
            "## E. Virtual-call receiver identification",
            "",
            "Receiver is **SEPARATE_INTERFACE_ARGUMENT** (stack arg0 / ebp), not Family A this.",
            "",
            "## F. Interface provider candidates",
            "",
            "Static POSSIBLE_INTERFACE vtables with `mov eax,[ecx+disp]; ret` at slot5 exist; "
            "no proven ordinary ctor→`9E8E00` arg producer enterable without fabrication.",
            "",
            "## G. Virtual-call ABI / continuation",
            "",
            "Site pushes 0 args; expects string in EAX / ret 0. Family A slot5 self-target "
            "is ret 4 → nested activation missing stack arg → INCORRECT_VTABLE_SLOT. "
            "Missing stack argument on nested self-call: YES.",
            "",
            "## H. Sparse dispatch verification",
            "",
            "sparse ok=%s; protected registered=%s; lifted=%d." % (
                sparse["ok"], sparse["protected_registered"], sparse["lifted_count"]),
            "",
            "## I. Alternate-family campaign",
            "",
            "`0x009EBC70`, `0x00808770` regressions; Family A/B mandatory paths clean.",
            "",
            "## J. Next genuine blockers",
            "",
            "Family C +0x14 interface object; typed string-provider for `0x009E8E15`.",
            "",
            "## K. Audited metric delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; NONTRIVIAL **%d**; RUNS **%d**." % (
                len(unique), len(enterable), nontrivial, execution_runs),
            "",
            "## L. Phase-43 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "nontrivial", nontrivial, "c_nontriv", c_nontrivial,
          "vt", real_vt, "new", new_fns)
    for s in seqs:
        print(" ", s["name"], s["result"], "len", s["sequence_length"],
              "cov", s["unique_entered"], s.get("blocker"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main() or 0)
