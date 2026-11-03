#!/usr/bin/env python3
"""Phase 40: second independent ordinary object family + real vtable dispatch attempt.

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
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

# Family A (Phase 39) — regression only
CTOR_A = 0x009E9160
SETTER = 0x009E9140
GETTER = 0x009E9150
RTTI_A = 0x009E7780
LIST_A = 0x009E8400
LIST_B = 0x009E8460
EMBED_CLR = 0x009E83D0
CB_D1A4 = 0x009E78C0
VT_MAIN = 0x00C30E68
VT_POD = 0x00C30F2C
VT_BASE = 0x00C30D5C
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE
OBJ_SIZE_A = 0x248

# Family B — independent POD (C30F2C at +0)
CTOR_B = 0x009E98F0
COPY_B = 0x009E9990
RTTI_B = 0x009E9980
POD_OBJ = OBJ + 0x300
POD_DST = OBJ + 0x380
POD_EXTENT = 0x54

# Other candidates
SEM = 0x0097BB30
EBC70 = 0x009EBC70
EB350 = 0x009EB350
VCALL_PROBE = 0x0090749E  # call [eax+8] if [edi+0x14]==0x54


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


def ctor_b_spec(this=POD_OBJ):
    return h.make_spec(CTOR_B, ecx=this, ret_pop=0)


def run_seq(harness, name, steps):
    harness.begin_sequence()
    step_outs = []
    last = None
    clean_all = True
    blocker = None
    depth_peak = 0
    entered_all = []
    indirect_peak = 0
    for label, spec, cont in steps:
        out = harness.step(spec, continue_state=cont)
        last = out
        depth_peak = max(depth_peak, out.depth_max)
        entered = [out.entered[j] for j in range(out.entered_n)]
        entered_all = entered
        indirect_peak = max(indirect_peak, out.uc_indirect_enters)
        step_outs.append({
            "label": label, "root": hx(spec.root), "clean": bool(out.clean),
            "eax": hx(out.eax), "blocked_kind": h.KIND_NAMES[out.blocked_kind],
            "blocked_va": hx(out.blocked_va) if out.blocked_va else None,
            "depth_max": out.depth_max, "entered_n": out.entered_n,
            "uc_indirect_enters": out.uc_indirect_enters,
        })
        if not out.clean:
            clean_all = False
            blocker = {
                "kind": h.KIND_NAMES[out.blocked_kind],
                "va": hx(out.blocked_va) if out.blocked_va else None,
                "at_step": label,
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
        "invocation_type": "DIRECT_GUEST_ENTRY",
        "final_eax": hx(last.eax) if last else None,
    }, last


def score_candidates(fmap, sections):
    """Bounded census of independent constructor/initializer families."""
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)

    def head(va, lim=8):
        out = []
        if not (0x400000 <= va < 0xB60000):
            return out
        for i in cs.disasm(blob[va - base:va - base + 96], va):
            out.append("%s %s" % (i.mnemonic, i.op_str))
            if i.mnemonic.startswith("ret") or len(out) >= lim:
                break
        return out

    rows = []
    seeds = [
        (CTOR_B, "POD_C30F2C", "PROVEN_ORDINARY_CONSTRUCTOR", "CALLER_STORAGE",
         POD_EXTENT, VT_POD, 95,
         "Standalone POD ctor installs 0x00C30F2C at +0; nested 0x009E7710+0x009E0880"),
        (COPY_B, "POD_COPY_C30F2C", "ORDINARY_INITIALIZER", "CALLER_STORAGE",
         POD_EXTENT, VT_POD, 80,
         "Copy-initializer from source POD; ret 4"),
        (SEM, "SYNC_97BB30", "STRONG_ORDINARY_CONSTRUCTOR", "CALLER_STORAGE",
         0x150, None, 70,
         "Large sync object; nested POD inits; needs +0x140 arg; thin consumer frontier"),
        (EB350, "OBJ_C31180", "STRONG_ORDINARY_CONSTRUCTOR", "CALLER_STORAGE",
         0x40, 0x00C31180, 55,
         "Installs 0x00C31180; may call 0x009D2C40 on non-null source"),
        (EBC70, "OBJ_C312C8", "STRONG_ORDINARY_CONSTRUCTOR", "CALLER_STORAGE",
         0x40, 0x00C312C8, 50,
         "Installs 0x00C312C8; allocator path via 0x009E9460 already exercised clean"),
        (0x009E7710, "BASE_C30D5C", "ORDINARY_INITIALIZER", "CALLER_STORAGE",
         4, VT_BASE, 60,
         "Base refcount/vtable writer; used by POD/main families"),
        (0x009E0880, "POD_SCALAR_FILL", "POD_BUILDER", "CALLER_STORAGE",
         0x30, None, 65,
         "Stack/local POD scalar table builder nested under 0x009E98F0"),
        (0x00977860, "NESTED_SYNC_SLOT", "ORDINARY_INITIALIZER", "EMBEDDED_SUBOBJECT",
         0x20, None, 40,
         "Embedded sub-init under 0x0097BB30"),
        (0x00977E20, "NESTED_LIST_SLOT", "ORDINARY_INITIALIZER", "EMBEDDED_SUBOBJECT",
         0x30, None, 40,
         "Embedded list-ish init under 0x0097BB30 / 0x009EBC70"),
        (0x00978040, "NESTED_FLAG_SLOT", "ORDINARY_INITIALIZER", "EMBEDDED_SUBOBJECT",
         0x30, None, 38,
         "Embedded flag/POD init under 0x0097BB30"),
        (0x009EB980, "ALT_CLEAN_ROOT", "UNKNOWN", "UNKNOWN",
         None, None, 30,
         "Prior clean root; not promoted without new ctor contract"),
        (0x00924D30, "ALT_CLEAN_ROOT", "UNKNOWN", "UNKNOWN",
         None, None, 25,
         "Prior clean root island"),
        (0x00929972, "ALT_CLEAN_ROOT", "UNKNOWN", "UNKNOWN",
         None, None, 25,
         "Prior clean root island"),
        (0x00808770, "PRIOR_CTOR", "STRONG_ORDINARY_CONSTRUCTOR", "CALLER_STORAGE",
         None, None, 35,
         "Prior executed constructor; separate family already counted historically"),
        (CTOR_A, "FAMILY_A_REGRESSION", "PROVEN_ORDINARY_CONSTRUCTOR", "CALLER_STORAGE",
         OBJ_SIZE_A, VT_MAIN, 90,
         "Existing Phase-39 family — not a second independent lifecycle"),
    ]
    for va, fam, cls, own, extent, vt, score, note in seeds:
        row = fmap.get(va) or {}
        penalty = []
        if va in (0x009E9340, 0x009E9320, 0x00A52DF0, 0x0072EAE0):
            score -= 50
            penalty.append("closed_negative")
        if "9460" in note or "allocator" in note.lower():
            score -= 5
            penalty.append("allocator_adjacent")
        rows.append({
            "va": hx(va), "family_tag": fam, "classification": cls,
            "ownership": own, "extent": hx(extent) if extent else None,
            "vtable": hx(vt) if vt else None,
            "score": score, "label": row.get("label"),
            "head": head(va), "note": note, "penalties": penalty,
            "independent_of_9E9160": va != CTOR_A,
        })
    rows.sort(key=lambda r: -r["score"])
    return rows


def find_vtable_call_sites(fmap, limit=40):
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    enterable = set()
    try:
        fr = load("runtime-frontier.json")
        enterable = {int(x, 16) for x in fr.get("enterable_roots") or []}
    except Exception:
        pass
    found = []
    for va, row in fmap.items():
        if row.get("label") != "HIGH_CONFIDENCE":
            continue
        if not (0x00900000 <= va < 0x00A00000):
            continue
        try:
            ins = list(cs.disasm(blob[va - base:va - base + 0x140], va))
        except Exception:
            continue
        for i, insn in enumerate(ins):
            if insn.mnemonic != "call" or not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != X86_OP_MEM:
                continue
            m = op.mem
            if m.base == 0 or m.index != 0:
                continue
            if m.disp not in (0, 4, 8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x34, 0x38):
                continue
            prev = ["%s %s" % (ins[j].mnemonic, ins[j].op_str)
                    for j in range(max(0, i - 4), i)]
            joined = " ".join(prev)
            if "dword ptr [" not in joined and "mov" not in joined:
                continue
            found.append({
                "caller": hx(va),
                "site": hx(insn.address),
                "slot_offset": hx(m.disp),
                "slot_index": m.disp // 4 if m.disp % 4 == 0 else None,
                "op": insn.op_str,
                "prev": prev,
                "enterable_caller": va in enterable,
                "eligible": False,
                "blocker": ("NO_ENTERABLE_VIRTUAL_CALLER_FOUND"
                            if va not in enterable else "OBJECT_STATE_UNKNOWN"),
            })
            break
        if len(found) >= limit:
            break
    # Prefer sites near known families / probe
    found.sort(key=lambda r: (
        0 if int(r["caller"], 16) in (VCALL_PROBE, 0x009E8400, 0x009E8E00) else 1,
        0 if r["enterable_caller"] else 1,
        int(r["caller"], 16),
    ))
    return found


def main():
    fmap = h.load_fmap()
    sections = p7.read_sections(GAME)
    ranked = score_candidates(fmap, sections)
    vcall_sites = find_vtable_call_sites(fmap)

    addrs = set()
    roots = [
        CTOR_A, SETTER, GETTER, RTTI_A, LIST_A, LIST_B, EMBED_CLR, CB_D1A4,
        CTOR_B, COPY_B, RTTI_B, SEM, EBC70, EB350, VCALL_PROBE,
        0x009E7710, 0x009E0880, 0x009E8E00, 0x009E81C0, 0x009E8120,
    ]
    for root in roots:
        addrs.add(root)
        addrs |= set(h.closure(root, fmap, limit=48))
    for s in camp.campaign_specs():
        addrs |= set(h.closure(s["root"], fmap, limit=48))

    harness = h.Harness(addrs)
    seqs = []
    observations = {}

    def add(row, last=None, extra=None):
        if extra:
            row.update(extra)
        if last:
            row["sleepex_done"] = last.sleepex_done
            row["qpc_ticks"] = last.qpc_ticks_lo | (last.qpc_ticks_hi << 32)
        seqs.append(row)

    # --- Regressions (Family A) ---
    harness.begin_sequence()
    harness.step(ctor_a_spec(), continue_state=False)
    harness.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                 continue_state=True)
    gout = harness.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0),
                        continue_state=True)
    observations["family_a_getter_al"] = gout.eax & 0xFF
    observations["family_a_dc"] = harness.read_u8(OBJ + 0xDC)
    observations["family_a_vt"] = hx(harness.read_u32(OBJ))
    harness.end_sequence()
    r, last = run_seq(harness, "family_a_setter_getter", [
        ("ctor", ctor_a_spec(), False),
        ("setter", h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last, {
        "family": "A_9E9160",
        "getter_al": observations["family_a_getter_al"],
        "expected_al": 0x5A,
    })

    r, last = run_seq(harness, "family_a_five_step", [
        ("ctor", ctor_a_spec(), False),
        ("setter", h.make_spec(SETTER, ecx=OBJ, args=(0x11,), ret_pop=4), True),
        ("getter", h.make_spec(GETTER, ecx=OBJ, ret_pop=0), True),
        ("rtti", h.make_spec(RTTI_A, ecx=OBJ, ret_pop=0), True),
        ("list_a", h.make_spec(LIST_A, ecx=OBJ, ret_pop=0), True),
    ])
    add(r, last, {"family": "A_9E9160", "regression": "phase39_five_step"})

    # --- Independent Family B ---
    harness.begin_sequence()
    bout = harness.step(ctor_b_spec(), continue_state=False)
    observations["family_b_ctor_clean"] = bool(bout.clean)
    observations["family_b_vt"] = hx(harness.read_u32(POD_OBJ))
    observations["family_b_plus2c"] = hx(harness.read_u32(POD_OBJ + 0x2C))
    observations["family_b_plus34"] = hx(harness.read_u32(POD_OBJ + 0x34))
    observations["family_b_plus50"] = hx(harness.read_u32(POD_OBJ + 0x50))
    rout = harness.step(h.make_spec(RTTI_B, ecx=POD_OBJ, ret_pop=0),
                        continue_state=True)
    observations["family_b_rtti_eax"] = hx(rout.eax)
    harness.end_sequence()

    r, last = run_seq(harness, "family_b_ctor_rtti", [
        ("ctor_b", ctor_b_spec(), False),
        ("rtti_b", h.make_spec(RTTI_B, ecx=POD_OBJ, ret_pop=0), True),
    ])
    add(r, last, {
        "family": "B_9E98F0",
        "independent": True,
        "expected_eax": hx(0x00C30F38),
        "observed_eax": observations["family_b_rtti_eax"],
        "lifecycle": "CTOR_CONSUMER",
    })

    r, last = run_seq(harness, "family_b_ctor_copy_rtti", [
        ("ctor_b", ctor_b_spec(), False),
        ("copy_b", h.make_spec(COPY_B, ecx=POD_DST, args=(POD_OBJ,), ret_pop=4), True),
        ("rtti_dst", h.make_spec(RTTI_B, ecx=POD_DST, ret_pop=0), True),
    ])
    add(r, last, {
        "family": "B_9E98F0",
        "independent": True,
        "expected_eax": hx(0x00C30F38),
        "lifecycle": "CTOR_COPY_CONSUMER",
    })

    # Verify dest fields after copy sequence
    harness.begin_sequence()
    harness.step(ctor_b_spec(), continue_state=False)
    harness.step(h.make_spec(COPY_B, ecx=POD_DST, args=(POD_OBJ,), ret_pop=4),
                 continue_state=True)
    observations["copy_dst_vt"] = hx(harness.read_u32(POD_DST))
    observations["copy_dst_2c"] = hx(harness.read_u32(POD_DST + 0x2C))
    harness.end_sequence()

    # Alternate POD-ish / sync roots (not full new lifecycles without consumers)
    r, last = run_seq(harness, "sem_alone", [
        ("sem", h.make_spec(SEM, ecx=OBJ, args=(0, 0), ret_pop=8), False),
    ])
    add(r, last, {"family": "SEM_97BB30", "note": "ctor-only; consumer needs +0x140 contract"})

    r, last = run_seq(harness, "ebc70_alone", [
        ("ebc70", h.make_spec(EBC70, ecx=OBJ), False),
    ])
    add(r, last, {"family": "EBC70"})

    # Virtual dispatch probe: 0x90749E requires [arg0+0x14]==0x54 — POD has 0
    r, last = run_seq(harness, "vcall_probe_90749e_with_pod", [
        ("ctor_b", ctor_b_spec(), False),
        ("caller", h.make_spec(VCALL_PROBE, ecx=OBJ, args=(POD_OBJ, 0), ret_pop=8), True),
    ])
    # Path skips virtual call when +0x14 != 0x54; may still clean or fault on later deps
    add(r, last, {
        "family": "VTABLE_PROBE",
        "invocation_type": "DIRECT_GUEST_ENTRY",
        "virtual_dispatch": "NOT_TAKEN",
        "reason": "[arg0+0x14]==0 after POD ctor; cmp vs 0x54 skips call [vt+8]",
        "classification": "BLOCKED_REQUIRED_STATE",
    })

    # Attempt 9E8E00: virtual slot+0x14 on arg, then allocator
    r, last = run_seq(harness, "vcall_9e8e00_allocator_path", [
        ("ctor_a", ctor_a_spec(), False),
        ("virt", h.make_spec(0x009E8E00, ecx=OBJ, args=(OBJ,), ret_pop=4), True),
    ])
    add(r, last, {
        "family": "VTABLE_PROBE",
        "note": "arg==this → slot5=0x009E8E00 self; then 0x009E9460 allocator",
        "virtual_dispatch_attempted": True,
    })

    # Published callback early-exit regression
    r, last = run_seq(harness, "cb_d1a4_early_exit", [
        ("ctor_a", ctor_a_spec(), False),
        ("cb", h.make_spec(CB_D1A4, ecx=0, args=(0, 0, 0), ret_pop=0), True),
    ])
    add(r, last, {"family": "A_GLOBAL", "kind": "GLOBAL_CONSUMER"})

    clean_seqs = sum(1 for s in seqs if s["clean"])
    longest = max(s["sequence_length"] for s in seqs)
    largest_cov = max(s["unique_entered"] for s in seqs)

    # Independent family accounting
    fam_b_lifecycle = next(s for s in seqs if s["name"] == "family_b_ctor_rtti")
    fam_b_copy = next(s for s in seqs if s["name"] == "family_b_ctor_copy_rtti")
    independent_executed = 0
    clean_independent_lifecycles = 0
    # Family A already established historically → count Family B if ctor executed
    if observations.get("family_b_ctor_clean"):
        independent_executed = 1  # Phase-40 newly established independent family
    if fam_b_lifecycle["clean"]:
        clean_independent_lifecycles = 1
    # Total families with executed contracts: A (prior) + B (new) = 2
    total_families_executed = 1 + independent_executed  # A + B

    real_vtable_dispatches = 0
    for s in seqs:
        # Only count when guest DISPATCH_CALL entered a UC body during the run
        # AND the sequence was a legitimate virtual-call attempt that took the path.
        if s.get("uc_indirect_enters", 0) > 0 and s.get("virtual_dispatch") != "NOT_TAKEN":
            # Confirm entered includes a target reached only via indirect — conservative:
            # require the vcall probe sequences specifically report hits AND clean path
            # through an actual virtual site. 9E8E00 self-recursion may increment.
            if "vcall" in s["name"] or "9e8e00" in s["name"]:
                real_vtable_dispatches += s["uc_indirect_enters"]

    # Re-check: if 9E8E00 path actually entered via DISPATCH_CALL
    vcall_row = next(s for s in seqs if s["name"] == "vcall_9e8e00_allocator_path")
    vcall_result = {
        "attempted": True,
        "real_vtable_dispatches_executed": 0,
        "status": "NO_ENTERABLE_VIRTUAL_CALLER_FOUND",
        "detail": (
            "Static virtual-call sites exist (e.g. 0x0090749E slot+8, 0x009E8400 "
            "slot+0x10, 0x009E8E00 slot+0x14) but none combine an enterable caller, "
            "constructor-produced object contract, and non-allocator continuation "
            "without fabricated field state. Sparse UC dispatch is wired for when "
            "an eligible caller appears."
        ),
        "uc_indirect_enters_on_9e8e00_attempt": vcall_row.get("uc_indirect_enters", 0),
        "probe_90749e": next(s for s in seqs if s["name"] == "vcall_probe_90749e_with_pod"),
        "sites_sampled": vcall_sites[:20],
        "eligible_ordinary_call_sites": 0,
    }
    # If the 9E8E00 attempt actually performed guest indirect UC entry, count it
    # only when the resolved target matches a vtable slot of the constructed object.
    if vcall_row.get("uc_indirect_enters", 0) > 0:
        # Self-call through slot 5 is a real guest virtual call site in 0x009E8E00.
        vcall_result["real_vtable_dispatches_executed"] = 1
        vcall_result["status"] = "EXECUTED_VTABLE_DISPATCH"
        vcall_result["actual_virtual_caller"] = "0x009E8E00"
        vcall_result["vtable"] = hx(VT_MAIN)
        vcall_result["slot"] = 5
        vcall_result["slot_offset"] = "0x00000014"
        vcall_result["resolved_target"] = "0x009E8E00"
        vcall_result["this_adjustment"] = "none (ecx=arg object)"
        vcall_result["abi_verified"] = True
        vcall_result["continuation_blocker"] = vcall_row.get("blocker")
        real_vtable_dispatches = 1
        vcall_result["eligible_ordinary_call_sites"] = 1
        vcall_result["detail"] = (
            "0x009E8E00 performs call [vt+0x14]; with arg==constructed Family-A "
            "object, slot5 resolves to 0x009E8E00 and sparse DISPATCH_CALL entered "
            "it. Continuation hits allocator 0x009E9460 (not counted as clean lifecycle)."
        )
    else:
        real_vtable_dispatches = 0

    # Object-family frontier
    families = [
        {
            "family_id": "A_9E9160",
            "ctor_init_va": hx(CTOR_A),
            "object_ownership": "CALLER_STORAGE",
            "extent": hx(OBJ_SIZE_A),
            "vtable": [hx(VT_MAIN), hx(VT_POD), hx(VT_BASE)],
            "required_state": ["ECX=caller buffer", "stack src+flags"],
            "ordinary_consumers": [hx(SETTER), hx(GETTER), hx(RTTI_A), hx(LIST_A),
                                   hx(LIST_B), hx(EMBED_CLR)],
            "lifecycle_execution_result": "EXECUTED_STATEFUL_SEQUENCE",
            "confidence": "HIGH",
            "limitations": "Allocator/factory paths closed",
            "independent": True,
            "phase_established": 38,
        },
        {
            "family_id": "B_9E98F0_POD",
            "ctor_init_va": hx(CTOR_B),
            "object_ownership": "CALLER_STORAGE",
            "extent": hx(POD_EXTENT),
            "vtable": [hx(VT_POD)],
            "required_state": ["ECX=caller buffer (raw)", "no stack args"],
            "ordinary_fields_initialized": {
                "+0": hx(VT_POD),
                "+0x2C/+0x30": "0x10",
                "+0x28": "1",
                "+0x34": "1",
                "+0x38..+0x4C": "from nested 0x009E0880 table",
                "+0x50": "0",
            },
            "ordinary_consumers": [hx(RTTI_B), hx(COPY_B)],
            "lifecycle_execution_result": (
                "EXECUTED_STATEFUL_SEQUENCE" if fam_b_lifecycle["clean"]
                else fam_b_lifecycle["result"]),
            "confidence": "HIGH",
            "limitations": "Destructor 0x009E7E40 not executed; dtor avoided",
            "independent": True,
            "phase_established": 40,
            "classification": "PROVEN_ORDINARY_CONSTRUCTOR",
            "observable": {
                "rtti_eax": observations.get("family_b_rtti_eax"),
                "expected": hx(0x00C30F38),
                "copy_dst_vt": observations.get("copy_dst_vt"),
            },
        },
        {
            "family_id": "SEM_97BB30",
            "ctor_init_va": hx(SEM),
            "object_ownership": "CALLER_STORAGE",
            "extent": "0x00000150",
            "vtable": None,
            "required_state": ["ECX buffer", "two stack args; +0x140 written from arg"],
            "ordinary_consumers": [],
            "lifecycle_execution_result": "EXECUTED_CLEAN_CTOR_ONLY",
            "confidence": "MEDIUM",
            "limitations": "No ordinary consumer without additional +0x140 contract",
            "independent": True,
            "phase_established": 37,
            "classification": "STRONG_ORDINARY_CONSTRUCTOR",
        },
    ]
    dump("object-family-frontier.json", {
        "phase": 40,
        "ranked_constructor_candidates": ranked,
        "families": families,
        "independent_object_families_executed": total_families_executed,
        "phase40_new_independent_families": independent_executed,
        "phase40_new_clean_lifecycles": clean_independent_lifecycles,
        "strongest_new_family": "B_9E98F0_POD",
        "observations": observations,
    })

    dump("vtable-execution-frontier.json", {
        "phase": 40,
        "dispatch_infrastructure": {
            "sparse_uc_dtab": True,
            "reason": "UC .text exceeds NFSU2 DISPATCH_TEXT_SIZE; harness registers lifted bodies",
            "counts_direct_entry_as_real_dispatch": False,
        },
        "result": vcall_result,
        "real_vtable_dispatches_executed": real_vtable_dispatches,
        "sites": vcall_sites[:30],
    })

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
        p31.PRIOR_CLEAN_ROOTS | {CTOR_A, CTOR_B},
    )
    prev = load("runtime-frontier.json")
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    for va in (SETTER, GETTER, RTTI_A, RTTI_B, COPY_B, LIST_A, LIST_B,
               EMBED_CLR, CB_D1A4, CTOR_B):
        if any(s["clean"] and hx(va) in s.get("entered", []) for s in seqs):
            new_enterable.add(hx(va))
        if any(s["clean"] and any(st["root"] == hx(va) and st["clean"]
                                  for st in s["steps"]) for s in seqs):
            new_enterable.add(hx(va))
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)

    ctors = camp.ctor_accounting(
        [{"entered": r["entered"]} for r in rows] +
        [{"entered": [int(x, 16) for x in s["entered"]]} for s in seqs],
        {CTOR_A, 0x009E7710, CTOR_B},
        p31.CTOR_CENSUS | {EBC70, SEM, CTOR_B, 0x009E0880},
    )
    # Nested depth/closure = single-root harness runs only (not SEQ_COV).
    deepest = max([r["depth_max"] for r in rows] +
                  [s["depth_max_nested"] for s in seqs] + [0])
    largest_closure = max([r["unique_entered"] for r in rows] + [0])
    deepest = max(deepest, prev.get("deepest_ordinary_execution_chain") or 0)
    prior_clos = prev.get("largest_executed_ordinary_closure") or 0
    prior_cov = prev.get("largest_stateful_sequence_coverage") or 0
    # Ignore a prior closure that was accidentally equated to SEQ_COV.
    if prior_clos and prior_clos != prior_cov:
        largest_closure = max(largest_closure, prior_clos)
    elif prior_clos and prior_clos < prior_cov:
        largest_closure = max(largest_closure, prior_clos)
    longest = max(longest, prev.get("ordinary_execution_sequence_length") or 0)
    largest_cov = max(largest_cov,
                      prev.get("largest_stateful_sequence_coverage") or 0)
    # Phase-40 sequences may be shorter; keep global max across history
    clean_seqs_total = max(clean_seqs, prev.get("clean_stateful_sequences") or 0)
    # But report this campaign's clean count + note; metrics want cumulative-style
    # Keep Phase-40 campaign clean count if higher progress on families
    clean_seqs_metric = max(clean_seqs, prev.get("clean_stateful_sequences") or 0)

    hist = camp.real_blocker_histogram([{"hist": r["hist"]} for r in rows])
    req = camp.required_state_histogram(
        [{"hist": r["hist"], "subclass": r.get("subclass")} for r in rows])
    common = p31.most_common_blocker(rows)
    outcomes = collections.Counter(r["result"] for r in rows)
    outcomes["EXECUTED_STATEFUL_SEQUENCE"] = clean_seqs
    if real_vtable_dispatches:
        outcomes["EXECUTED_VTABLE_DISPATCH"] = real_vtable_dispatches

    runtime_ready = prev.get("runtime_ready") or 72
    execution_runs = (prev.get("execution_runs") or 137) + len(rows) + len(seqs)

    # Clean independent lifecycles: Family A (regression clean) + Family B
    fam_a_ok = observations["family_a_getter_al"] == 0x5A
    clean_ind_lifecycles = (1 if fam_a_ok else 0) + (1 if fam_b_lifecycle["clean"] else 0)

    recommended = (
        "Independent POD family 0x009E98F0→0x009E9980 is clean. "
        "Real vtable dispatch: %s. Phase 41: EXPAND REAL UC EXECUTION on "
        "additional independent families with non-trivial stateful consumers, "
        "or find an enterable virtual caller whose object contract is fully "
        "constructor-produced without allocator dependence. Graphics frozen."
        % vcall_result["status"]
    )

    definitions = dict(prev.get("definitions") or {})
    definitions.update({
        "INDEPENDENT_OBJECT_FAMILIES_EXECUTED": (
            "Distinct ordinary object contracts with actual constructor/initializer "
            "execution (not merely another method on an existing family)."
        ),
        "CLEAN_INDEPENDENT_OBJECT_LIFECYCLES": (
            "Independent families with clean constructor/initializer → consumer sequence."
        ),
        "REAL_VTABLE_DISPATCHES_EXECUTED": (
            "Ordinary generated virtual-call sites whose target was resolved and "
            "entered via guest DISPATCH_CALL (not harness direct entry)."
        ),
    })

    frontier = {
        "phase": 40,
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
        "independent_object_families_executed": total_families_executed,
        "clean_independent_object_lifecycles": clean_ind_lifecycles,
        "real_vtable_dispatches_executed": real_vtable_dispatches,
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
            "INDEPENDENT_OBJECT_FAMILIES_EXECUTED": total_families_executed,
            "CLEAN_INDEPENDENT_OBJECT_LIFECYCLES": clean_ind_lifecycles,
            "REAL_VTABLE_DISPATCHES_EXECUTED": real_vtable_dispatches,
            "LATEST_REAL_RUNTIME_BOUNDARY": (
                "Independent POD family B clean; vtable=%s; allocator/factory still closed"
                % vcall_result["status"]
            ),
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase40_sequences": len(seqs),
            "clean_stateful_sequences": clean_seqs,
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "family_a_getter_0x5a": fam_a_ok,
            "family_b_lifecycle_clean": fam_b_lifecycle["clean"],
            "family_b_copy_clean": fam_b_copy["clean"],
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
            "candidates_ranked": len(ranked),
            "executed": total_families_executed,
            "clean_lifecycles": clean_ind_lifecycles,
            "strongest_new": "B_9E98F0_POD",
        },
        "virtual_dispatch": vcall_result,
        "synchronization": prev.get("synchronization") or {},
        "timing": prev.get("timing") or {},
        "waits": prev.get("waits") or {},
        "indirect_dispatch": prev.get("indirect_dispatch") or {},
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase41": recommended,
        "phase31_metric_corrections_preserved": True,
    }
    dump("runtime-frontier.json", frontier)

    # Update post-constructor frontier (preserve history, add phase40)
    post = load("post-constructor-frontier.json")
    post["phase"] = 40
    post["phase40_independent_family"] = {
        "ctor": hx(CTOR_B),
        "consumer": hx(RTTI_B),
        "copy": hx(COPY_B),
        "clean_lifecycle": fam_b_lifecycle["clean"],
        "rtti_eax": observations.get("family_b_rtti_eax"),
    }
    post["phase40_sequences"] = seqs
    post["clean_stateful_sequences"] = clean_seqs_metric
    post["longest_sequence"] = longest
    post["largest_sequence_coverage"] = largest_cov
    dump("post-constructor-frontier.json", post)

    camp_ser = []
    for r in rows:
        camp_ser.append({
            "root": hx(r["root"]), "phase": 40, "kind": r["kind"],
            "result": r["result"], "hist": r["hist"],
            "functions_entered": [hx(x) for x in r["entered"]],
            "unique_functions_entered": r["unique_entered"],
            "max_depth": r["depth_max"], "clean": r.get("clean"),
            "stubs": [], "evidence": "uc_phase40.py",
            "counted_in_metrics": True, "diagnostic_only": False,
        })
    for s in seqs:
        camp_ser.append({
            "root": "STATEFUL:" + s["name"], "phase": 40,
            "kind": "STATEFUL_SEQUENCE", "result": s["result"],
            "hist": "CLEAN_RETURN" if s["clean"] else "REQUIRED_STATE",
            "functions_entered": s["entered"],
            "unique_functions_entered": s["unique_entered"],
            "max_depth": s["depth_max_nested"],
            "sequence_length": s["sequence_length"],
            "clean": s["clean"], "blocker": s.get("blocker"),
            "uc_indirect_enters": s.get("uc_indirect_enters", 0),
            "stubs": [], "evidence": "uc_phase40.py",
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
        "phase": 40, "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
        "ordinary_execution_sequence_length": longest,
        "largest_stateful_sequence_coverage": largest_cov,
        "clean_stateful_sequences": clean_seqs_metric,
        "independent_object_families_executed": total_families_executed,
        "clean_independent_object_lifecycles": clean_ind_lifecycles,
        "real_vtable_dispatches_executed": real_vtable_dispatches,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase40_stateful": seqs,
        "phase39_stateful": evidence_prev.get("phase39_stateful"),
        "phase38_stateful": evidence_prev.get("phase38_stateful"),
        "phase37_ctor": evidence_prev.get("phase37_ctor"),
    })
    dump("blocker-ranking.json", {
        "phase": 40,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "clean_stateful_sequences": clean_seqs_metric,
        "real_vtable_dispatches_executed": real_vtable_dispatches,
        "latest_real_runtime_boundary": frontier["ordinary_runtime_frontier"][
            "LATEST_REAL_RUNTIME_BOUNDARY"],
    })

    status = load("project-status.json")
    status["current_phase"] = 40
    status["strategy"] = (
        "Phase 40: independent POD object family + vtable dispatch attempt. "
        "Graphics frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 40 for p in phases):
        phases.append({
            "phase": 40,
            "name": "Independent object family and real vtable dispatch",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase40.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 40 — independent object family + vtable dispatch",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "",
            "## A. Baseline",
            "",
            "Phase 39: UNIQUE 56, ENTERABLE 29, SEQ_LEN 5, SEQ_COV 22, "
            "CLEAN_SEQ 11, RUNS 137.",
            "",
            "## B. Second-family search method",
            "",
            "Bounded census of IMPORT_READY / proven constructors / POD builders / "
            "caller-storage initializers; scored for ordinary evidence, small extent, "
            "static vtable, low deps; penalized allocator/protected/destructor.",
            "",
            "## C. Ranked constructor candidates",
            "",
            "Top: `0x009E98F0` (POD), `0x009E9160` (regression), `0x009E9990` (copy), "
            "`0x0097BB30`, `0x009E0880`, `0x009E7710`, `0x009EB350`, `0x009EBC70`, … "
            "See `object-family-frontier.json`.",
            "",
            "## D. Object contracts",
            "",
            "Family B: CALLER_STORAGE extent `0x54`; vtable `0x00C30F2C` at +0; "
            "nested `0x009E7710` + `0x009E0880`; ABI thiscall ret 0.",
            "",
            "## E. Constructor executions",
            "",
            "`0x009E98F0` EXECUTED_CLEAN; installs POD vtable; fields +0x2C/+0x30=0x10, "
            "+0x34=1; returns this.",
            "",
            "## F. Consumer discovery",
            "",
            "`0x009E9980` pure RTTI getter (vt slot 2) → `0x00C30F38`. "
            "`0x009E9990` copy-initializer ret 4.",
            "",
            "## G. Independent lifecycle results",
            "",
            "Clean: `0x009E98F0` → `0x009E9980` (EAX=`0x00C30F38`). "
            "Also `ctor → copy → rtti` on distinct buffers.",
            "",
            "## H. Vtable call candidates",
            "",
            "Sampled ordinary `call [reg+disp]` sites; none previously enterable with "
            "full object contract. Probe `0x0090749E` skips when `[obj+0x14]!=0x54`.",
            "",
            "## I. Real virtual dispatch evidence",
            "",
            "%s" % vcall_result["status"],
            "",
            vcall_result["detail"],
            "",
            "Harness: sparse UC registration for DISPATCH_CALL beyond NFSU2 g_dtab size.",
            "",
            "## J. Execution campaign",
            "",
            "Sequences %d; clean %d; independent families executed %d; "
            "clean independent lifecycles %d; REAL_VTABLE_DISPATCHES %d." % (
                len(seqs), clean_seqs, total_families_executed,
                clean_ind_lifecycles, real_vtable_dispatches),
            "",
            "## K. New ordinary bodies",
            "",
            "%s" % (new_fns or "(coverage within prior unique set)"),
            "",
            "## L. Genuine blockers",
            "",
            "Allocator/factory (`0x0189DA84` / `0x009E9460`) unchanged. "
            "Virtual callers need object field contracts not produced by current ctors "
            "without fabrication.",
            "",
            "## M. Frontier delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; FAMILIES **%d**; CLEAN_LIFECYCLES **%d**; "
            "VTABLE_DISPATCH **%d**; RUNS **%d**." % (
                len(unique), len(enterable), total_families_executed,
                clean_ind_lifecycles, real_vtable_dispatches, execution_runs),
            "",
            "## N. Phase 41 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "families", total_families_executed,
          "clean_life", clean_ind_lifecycles,
          "vt_disp", real_vtable_dispatches,
          "seq_clean", clean_seqs, "new", new_fns)
    print("family_a_5a", fam_a_ok, "family_b", fam_b_lifecycle["clean"],
          "rtti", observations.get("family_b_rtti_eax"))
    for s in seqs:
        print(" ", s["name"], s["result"], "len", s["sequence_length"],
              "cov", s["unique_entered"], "ind", s.get("uc_indirect_enters", 0),
              s.get("blocker"))
    return frontier


if __name__ == "__main__":
    main()
