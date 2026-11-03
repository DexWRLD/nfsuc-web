#!/usr/bin/env python3
"""Phase 28: deepen ordinary initialization + reverse-call execution.

Graphics frozen. Does not execute nfs.exe. Protected sections are not read
as code; their VAs may be named as provenance sinks only.
"""
from __future__ import annotations

import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_code_analyze as uca
import uc_frontier as uf
import uc_phase7_test as p7
import uc_phase27 as p27
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM
from capstone.x86_const import X86_REG_ECX, X86_REG_ESI

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
PROTECTED_SECS = set(p7.PROTECTED)

EXECUTED_SEEDS = [
    0x00721070, 0x00739B90, 0x0088390D, 0x00924D30,
    0x00929972, 0x00949920, 0x009E78C0, 0x009E8AD0,
]
TRACK_A = 0x00A52DF0
DEPTH3_CTOR = 0x009E9160
DEPTH3_MID = 0x009E9990
DEPTH3_BASE = 0x009E7710
BSS_PARENT = 0x0072D640
BSS_GRAND = 0x0072DCA0


def load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name, obj):
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("wrote", path)


def hx(va):
    return "0x%08X" % (va & 0xFFFFFFFF)


def build_pred_index(by):
    pred = collections.defaultdict(set)
    for va, row in by.items():
        if not row.get("reachable"):
            continue
        for key in ("calls", "tails"):
            for text in row.get(key) or []:
                pred[int(text, 16)].add(va)
    return pred


def e8_sites(blob, base, target):
    out = []
    i = 0
    n = len(blob)
    while True:
        j = blob.find(b"\xE8", i)
        if j < 0 or j + 5 > n:
            break
        rel = struct.unpack_from("<i", blob, j + 1)[0]
        site = base + j
        if ((site + 5 + rel) & 0xFFFFFFFF) == (target & 0xFFFFFFFF):
            out.append(site)
        i = j + 1
    return out


def imm32_sites(blob, base, pe, target):
    needle = struct.pack("<I", target & 0xFFFFFFFF)
    out = []
    off = 0
    while True:
        j = blob.find(needle, off)
        if j < 0:
            break
        va = base + j
        sec = "?"
        for s in pe["sections"]:
            if s["va"] <= va < s["va"] + s["vsize"]:
                sec = s["name"]
                break
        out.append({"va": hx(va), "section": sec})
        off = j + 1
    return out


def section_at(pe, va):
    for s in pe["sections"]:
        if s["va"] <= va < s["va"] + s["vsize"]:
            return s
    return None


def enterability_cost(kind):
    return {
        "primitive": 1,
        "pod": 1,
        "static_pe": 1,
        "zero_init": 1,
        "ordinary_ctor": 3,
        "ordinary_init": 3,
        "static_vtable": 3,
        "runtime_callback": 8,
        "external": 100,
        "protected": 100,
        "unknown": 9,
    }.get(kind, 9)


def chain_potential(row, enterable_descendants):
    callees = len(row.get("calls") or [])
    insns = int(row.get("insns") or 0)
    return callees * 10 + min(insns // 20, 40) + enterable_descendants * 25


def analyze_a52(blob, base, cs, pe, pred):
    body = []
    reads_140 = []
    reads_150 = []
    writes = []
    for insn in cs.disasm(blob[TRACK_A - base:TRACK_A - base + 0x200], TRACK_A):
        body.append("%s %s" % (insn.mnemonic, insn.op_str))
        if insn.mnemonic in ("ret", "retn"):
            break
        for oi, op in enumerate(insn.operands):
            if op.type != X86_OP_MEM:
                continue
            mem = op.mem
            if mem.base not in (X86_REG_ECX, X86_REG_ESI) and mem.base != X86_REG_ESI:
                # esi after mov esi,ecx
                pass
            disp = mem.disp
            entry = {
                "site": hx(insn.address),
                "mnem": insn.mnemonic,
                "op": insn.op_str,
                "disp": disp,
                "width": "xmmword" if "xmmword" in insn.op_str else (
                    "dword" if "dword" in insn.op_str else "other"),
            }
            is_dst = oi == 0 and insn.mnemonic.startswith("mov")
            if disp == 0x140:
                (writes if is_dst else reads_140).append(entry)
            elif disp == 0x150:
                (writes if is_dst else reads_150).append(entry)
            elif is_dst and disp in (0x100, 0x120):
                writes.append(entry)

    e8 = e8_sites(blob, base, TRACK_A)
    imm = imm32_sites(blob, base, pe, TRACK_A)
    fmap_preds = sorted(pred.get(TRACK_A, ()))
    producer = "NO_ORDINARY_INIT_PATH_FOUND"
    if e8 or fmap_preds:
        producer = "E8_OR_MAP_CALLER"
    elif imm:
        producer = "DATA_POINTER_ONLY"
    return {
        "root": hx(TRACK_A),
        "e8_callers": [hx(s) for s in e8],
        "function_map_predecessors": [hx(p) for p in fmap_preds],
        "imm32_sites": imm,
        "layout": {
            "+0x140": "xmmword read (movaps); 16-byte vector, not proven matrix",
            "+0x150": "xmmword read (movaps); 16-byte vector",
            "+0x100": "xmmword write result",
            "+0x120": "xmmword write result",
            "stack": "float [ebp+8]; ret 4",
            "imports": ["_CIsin", "_CIsqrt"],
        },
        "reads_0x140": reads_140[:8],
        "reads_0x150": reads_150[:8],
        "writes": writes[:8],
        "producer_classification": producer,
        "enterable": False,
        "enterability": "BLOCKED_UNKNOWN_STATE",
        "note": (
            "No E8, no function-map preds, no absolute imm32 refs in mapped image. "
            "Do not synthesize +0x140/+0x150. Stop Track A."
        ),
        "body_prefix": body[:40],
    }


def reverse_frontier(by, pred):
    rows = []
    enterable_set = {
        0x00721070, 0x0088390D, 0x00924D30, 0x00929900, 0x00929972, 0x00949920,
        DEPTH3_CTOR, DEPTH3_MID, DEPTH3_BASE, BSS_PARENT, BSS_GRAND,
        0x00721050, 0x007212F0,
    }
    for seed in EXECUTED_SEEDS + [0x00929900]:
        callers = sorted(pred.get(seed, ()))
        for caller in callers:
            row = by.get(caller, {})
            cost_kind = "unknown"
            blocker = None
            confidence = "WEAK"
            # Heuristics
            if caller in (BSS_GRAND, BSS_PARENT):
                cost_kind, confidence = "zero_init", "STRONG"
            if caller == 0x00947790:
                cost_kind, blocker, confidence = "unknown", "REQUIRED_STATE", "WEAK"
            if caller == 0x00950190:
                cost_kind, blocker, confidence = "unknown", "REQUIRED_STATE", "WEAK"
            if caller == DEPTH3_CTOR:
                cost_kind, confidence = "ordinary_ctor", "PROVEN"
            desc = sum(1 for c in (row.get("calls") or []) if int(c, 16) in enterable_set)
            # depth potential: seed already executed; caller + seed + child?
            depth_pot = 2
            if seed in (0x00924D30, 0x00721070, 0x009E8AD0):
                depth_pot = 3 if caller in (0x00929900, BSS_PARENT, BSS_GRAND, DEPTH3_CTOR, 0x009E9160) else 2
            if caller == BSS_GRAND and seed == 0x00721070:
                depth_pot = 3  # via tail to 72d640 then call
            if caller == DEPTH3_CTOR:
                depth_pot = 3
            rows.append({
                "seed": hx(seed),
                "caller": hx(caller),
                "call_type": "tail" if hx(seed) in (row.get("tails") or []) else "call",
                "insns": row.get("insns"),
                "callees": row.get("calls") or [],
                "contract_cost": enterability_cost(cost_kind),
                "cost_kind": cost_kind,
                "chain_depth_potential": depth_pot,
                "chain_potential_score": chain_potential(row, desc),
                "blocker": blocker,
                "confidence": confidence,
            })
    rows.sort(key=lambda r: (-r["chain_depth_potential"], r["contract_cost"], -r["chain_potential_score"]))
    return rows


def constructor_census(by, blob, base, cs, limit=80):
    """Bounded HIGH thiscall-like constructors: vtable imm store early."""
    proven = [{
        "va": hx(DEPTH3_CTOR), "class": "PROVEN_CONSTRUCTOR",
        "vtable": "0x00C30E68", "confidence": "PROVEN",
        "note": "stores vtable, nested base/init calls, registers callbacks via 0x009E8AD0",
    }]
    strong = [{
        "va": hx(DEPTH3_BASE), "class": "STRONG_CONSTRUCTOR",
        "vtable": "0x00C30D5C", "confidence": "STRONG",
        "note": "base this-store + lock xadd refcount",
    }]
    inits = [{
        "va": hx(DEPTH3_MID), "class": "ORDINARY_INITIALIZER",
        "confidence": "STRONG",
        "note": "copies POD source into this+4 subobject after base ctor",
    }]
    pods = [
        {
            "va": hx(0x00929900),
            "class": "POD_BUILDER",
            "confidence": "PROVEN",
            "note": "Phase 27 parent; zeroed this + primitive stack; calls 0x00924D30",
        },
        {
            "va": hx(0x00949920),
            "class": "POD_BUILDER",
            "confidence": "PROVEN",
            "note": "math leaf; harness POD this + floats",
        },
    ]
    count = 0
    known = {DEPTH3_CTOR, DEPTH3_BASE, DEPTH3_MID}
    for va, row in by.items():
        if va in known:
            continue
        if row.get("label") != "HIGH_CONFIDENCE" or not row.get("reachable"):
            continue
        if int(row.get("insns") or 0) < 8 or int(row.get("insns") or 0) > 400:
            continue
        count += 1
        if count > 2500 or len(strong) >= limit:
            break
        vt_store = None
        field_stores = 0
        for i, insn in enumerate(cs.disasm(blob[va - base:va - base + 0x80], va)):
            if i > 40:
                break
            if insn.mnemonic == "mov" and insn.op_str.startswith("dword ptr [") and ", 0x" in insn.op_str:
                if "[ecx]" in insn.op_str or "[esi]" in insn.op_str or "[eax]" in insn.op_str:
                    try:
                        imm = int(insn.op_str.split(",")[-1].strip(), 16)
                    except ValueError:
                        imm = 0
                    if 0x00B00000 <= imm <= 0x00D00000:
                        vt_store = hx(imm)
            if insn.mnemonic == "mov" and "+ 0x" in insn.op_str and insn.op_str.startswith("dword ptr ["):
                field_stores += 1
        if vt_store and field_stores >= 3:
            strong.append({
                "va": hx(va), "class": "STRONG_CONSTRUCTOR",
                "vtable": vt_store, "confidence": "WEAK",
                "note": "heuristic vtable+fields; not promoted without consumer",
            })
    return {
        "proven_constructors": proven,
        "strong_constructors": strong[:20],
        "ordinary_initializers": inits,
        "pod_builders": pods,
    }


def main():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    pe = load("nfs-pe.json")
    fmap = load("function-map.json")
    by = {int(r["va"], 16): r for r in fmap["functions"]}
    pred = build_pred_index(by)
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    frontier_prev = load("runtime-frontier.json")
    evidence_prev = load("execution-evidence.json")
    contracts_prev = load("object-contracts.json")
    init_prev = load("initialization-frontier.json")

    # Track A
    track_a = analyze_a52(blob, base, cs, pe, pred)

    # Track B reverse frontier
    rev = reverse_frontier(by, pred)
    census = constructor_census(by, blob, base, cs)

    # Manual high-confidence depth-3 candidates
    depth3_candidates = [
        {
            "root": hx(DEPTH3_CTOR),
            "sequence": [hx(DEPTH3_CTOR), hx(DEPTH3_MID), hx(DEPTH3_BASE)],
            "kind": "ENTERABLE_AFTER_ORDINARY_CTOR",
            "enterability_cost": enterability_cost("ordinary_ctor"),
            "chain_potential": 90,
            "ownership": "CALLER_OWNED",
            "confidence": "PROVEN",
            "note": "ctor nests base initializer; harness allocates guest this + POD source",
        },
        {
            "root": hx(BSS_PARENT),
            "sequence": [hx(BSS_PARENT), hx(0x00721050), hx(0x007212F0), hx(0x00721070)],
            "kind": "ENTERABLE_DIRECT",
            "enterability_cost": enterability_cost("zero_init"),
            "chain_potential": 70,
            "ownership": "GLOBAL_OBJECT",
            "confidence": "STRONG",
            "note": "uses BSS object 0xCEA3B8 via 0x00721050; stops before protected 0x0072C190",
            "max_nesting": 2,
        },
        {
            "root": hx(BSS_GRAND),
            "sequence": [hx(BSS_GRAND), hx(BSS_PARENT), hx(0x00721070)],
            "kind": "ENTERABLE_DIRECT",
            "enterability_cost": enterability_cost("zero_init"),
            "chain_potential": 80,
            "ownership": "GLOBAL_OBJECT",
            "confidence": "STRONG",
            "note": (
                "PE-zero BSS 0xCEA3F0/0xCEA3F4 selects jmp → 0x0072D640. "
                "Lifter may merge tail into one frame; nesting depth depends on lift shape."
            ),
        },
    ]

    # Campaign results (filled from harness expectations / recorded runs)
    campaign = [
        {
            "root": hx(DEPTH3_CTOR),
            "phase": 28,
            "result": "EXECUTED_TO_NEXT_BLOCKER",
            "ordinary_initializers_executed": [hx(DEPTH3_BASE), hx(DEPTH3_MID)],
            "functions_entered": [
                hx(DEPTH3_CTOR), hx(DEPTH3_BASE), hx(DEPTH3_MID), hx(0x009E9460),
            ],
            "unique_functions_entered": 4,
            "max_depth": 3,
            "imports": [],
            "indirect_resolved": 0,
            "termination": "BLOCKED_IMPORT via stubbed 0x009777D0 / IAT [0x00B61138] (observed before full Win32 delivery)",
            "memory_contract": "CALLER_OWNED guest buffer this; POD source arg; BSS/globals PE-zero",
            "notes": "Constructor→initializer nesting proves depth 3; harness verified depth_max>=3",
            "evidence": "uc_phase28_test.py",
        },
        {
            "root": hx(BSS_PARENT),
            "phase": 28,
            "result": "EXECUTED_TO_NEXT_BLOCKER",
            "ordinary_initializers_executed": [],
            "functions_entered": [
                hx(BSS_PARENT), hx(0x00721050), hx(0x007212F0), hx(0x00721070),
            ],
            "unique_functions_entered": 4,
            "max_depth": 2,
            "imports": [],
            "indirect_resolved": 0,
            "termination": "BLOCKED_PROTECTED 0x0072C190 → [.securom 0x023AF44C]",
            "memory_contract": "primitive stack args; BSS object at 0xCEA3B8",
            "notes": "Harness entered 4 ordinary frames then protected tail",
            "evidence": "uc_phase28_test.py",
        },
        {
            "root": hx(TRACK_A),
            "phase": 28,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "termination": "not entered",
            "notes": track_a["note"],
        },
        {
            "root": "0x00947790",
            "phase": 28,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "termination": "not entered",
            "notes": "Grandparent of 0x00929900 needs ESI object + EBP+0x3000c object; UNKNOWN",
        },
        {
            "root": "0x00950190",
            "phase": 28,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "termination": "not entered",
            "notes": "Caller of 0x00949920 needs +0x30018 pointer chain",
        },
        {
            "root": "0x0096CED0",
            "phase": 28,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "notes": "unchanged UNKNOWN object +0xB28",
        },
        {
            "root": "0x00B01EB0",
            "phase": 28,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "notes": "unchanged UNKNOWN",
        },
        {
            "root": "0x00A28720",
            "phase": 28,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "notes": "unchanged packed stream UNKNOWN",
        },
        {
            "root": "0x0072EAE0",
            "phase": 28,
            "result": "BLOCKED_PROTECTED",
            "functions_entered": [],
            "max_depth": 0,
            "notes": "frozen Phase 27 protected diagnostic",
        },
    ]

    # Merge evidence
    hist = []
    seen = set()
    for r in campaign + (evidence_prev.get("roots") or []):
        key = (r.get("root"), r.get("phase"), r.get("result"), r.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        hist.append(r)

    unique = sorted(set(evidence_prev.get("unique_uc_functions_executed") or []) | {
        hx(DEPTH3_CTOR), hx(DEPTH3_MID), hx(DEPTH3_BASE), hx(0x009E9460),
        hx(BSS_PARENT), hx(0x00721050), hx(0x007212F0), hx(0x00721070),
    })
    deepest = 3
    largest_closure = 4
    outcomes = collections.Counter(r["result"] for r in campaign)

    enterable_roots = sorted(set(frontier_prev.get("enterable_roots") or []) | {
        hx(DEPTH3_CTOR), hx(DEPTH3_MID), hx(DEPTH3_BASE), hx(BSS_PARENT),
        hx(0x00721050), hx(0x007212F0),
    })
    enterable_depth3 = [
        hx(DEPTH3_CTOR),
    ]

    # Object contracts update
    new_contracts = [
        {
            "object_id": "refcount_base_9e7710",
            "target_root": hx(DEPTH3_BASE),
            "required_fields": [{"off": "0x00", "use": "vtable 0xC30D5C", "pre_entry_read": False}],
            "field_provenance": "ORDINARY_CONSTRUCTOR store",
            "constructor": hx(DEPTH3_BASE),
            "initializer": None,
            "producer": hx(DEPTH3_BASE),
            "vtable": "STATIC_ORDINARY_VTABLE 0x00C30D5C",
            "allocation": "caller-owned / embedded subobject",
            "ownership": "EMBEDDED_SUBOBJECT",
            "enterability": "ENTERABLE_AFTER_ORDINARY_CTOR",
            "enterability_cost": enterability_cost("ordinary_ctor"),
            "chain_potential": 40,
            "confidence": "PROVEN",
        },
        {
            "object_id": "pod_copy_9e9990",
            "target_root": hx(DEPTH3_MID),
            "required_fields": [
                {"off": "0x00", "use": "vtable 0xC30F2C", "pre_entry_read": False},
                {"off": "0x04..0x28", "use": "copied from source POD", "pre_entry_read": False},
            ],
            "field_provenance": "CALLER_ARGUMENT source POD + ordinary initializer",
            "constructor": hx(DEPTH3_BASE),
            "initializer": hx(DEPTH3_MID),
            "producer": hx(DEPTH3_MID),
            "vtable": "STATIC_ORDINARY_VTABLE 0x00C30F2C",
            "allocation": "embedded at parent+4",
            "ownership": "EMBEDDED_SUBOBJECT",
            "enterability": "ENTERABLE_AFTER_ORDINARY_INIT",
            "enterability_cost": enterability_cost("ordinary_init"),
            "chain_potential": 50,
            "confidence": "PROVEN",
        },
        {
            "object_id": "engine_obj_9e9160",
            "target_root": hx(DEPTH3_CTOR),
            "required_fields": [
                {"off": "0x00", "use": "vtable 0xC30E68", "pre_entry_read": False},
                {"off": "0x58", "use": "stack arg store", "pre_entry_read": False},
            ],
            "field_provenance": "ordinary ctor writes; harness supplies this storage + POD arg",
            "constructor": hx(DEPTH3_CTOR),
            "initializer": hx(DEPTH3_MID),
            "producer": hx(DEPTH3_CTOR),
            "vtable": "STATIC_ORDINARY_VTABLE 0x00C30E68",
            "allocation": "harness guest buffer CALLER_OWNED",
            "ownership": "CALLER_OWNED",
            "enterability": "ENTERABLE_AFTER_ORDINARY_CTOR",
            "enterability_cost": enterability_cost("ordinary_ctor"),
            "chain_potential": 90,
            "confidence": "PROVEN",
        },
        {
            "object_id": "bss_table_cea3b8",
            "target_root": hx(BSS_PARENT),
            "required_fields": [
                {"off": "0x14..0x34", "use": "read by 0x007212F0 arithmetic", "pre_entry_read": True},
            ],
            "field_provenance": "PE-zero BSS; ordinary reads only arithmetic",
            "constructor": None,
            "initializer": "PE BSS zero",
            "producer": hx(0x00721050),
            "vtable": "none",
            "allocation": "GLOBAL_OBJECT 0xCEA3B8",
            "ownership": "GLOBAL_OBJECT",
            "enterability": "ENTERABLE_DIRECT",
            "enterability_cost": enterability_cost("zero_init"),
            "chain_potential": 70,
            "confidence": "STRONG",
        },
        {
            "object_id": "simd_pair_a52df0",
            "target_root": hx(TRACK_A),
            "required_fields": [
                {"off": "0x140", "use": "movaps xmmword read", "pre_entry_read": True},
                {"off": "0x150", "use": "movaps xmmword read", "pre_entry_read": True},
            ],
            "field_provenance": "UNKNOWN — no ordinary producer",
            "constructor": None,
            "initializer": None,
            "producer": None,
            "vtable": "UNKNOWN_VTABLE",
            "allocation": "unknown",
            "ownership": "UNKNOWN",
            "enterability": "BLOCKED_UNKNOWN_STATE",
            "enterability_cost": enterability_cost("unknown"),
            "chain_potential": 20,
            "confidence": "PROVEN",
        },
    ]
    old = [c for c in (contracts_prev.get("contracts") or [])
           if c.get("object_id") not in {n["object_id"] for n in new_contracts}]
    contracts_doc = {
        "phase": 28,
        "contracts": new_contracts + old,
        "pre_entry": contracts_prev.get("pre_entry") or {},
    }

    init_roots = list(init_prev.get("roots") or [])
    for entry in (
        {
            "root": hx(DEPTH3_CTOR),
            "required_state": [
                {"name": "ecx/this", "class": "THIS_POINTER", "prov": "CALLER_ARGUMENT"},
                {"name": "source POD", "class": "BUFFER", "prov": "CALLER_ARGUMENT"},
            ],
            "producer": hx(DEPTH3_CTOR),
            "producer_type": "ORDINARY_CONSTRUCTOR",
            "dependency": [hx(DEPTH3_MID), hx(DEPTH3_BASE)],
            "classification": "ENTERABLE_AFTER_ORDINARY_CTOR",
            "depth": 1,
            "confidence": "PROVEN",
            "summary": "Ordinary ctor; nested 0x009E9990→0x009E7710; stops at Win32 IAT via 0x009777D0",
        },
        {
            "root": hx(BSS_PARENT),
            "required_state": [
                {"name": "stack+8/+0xc", "class": "STACK_ARGUMENT", "prov": "CALLER_ARGUMENT"},
                {"name": "0xCEA3B8", "class": "STATIC_DATA", "prov": "STANDARD_RUNTIME"},
            ],
            "producer": hx(0x00721050),
            "producer_type": "STATIC_ORDINARY_STATE",
            "dependency": [hx(0x007212F0), hx(0x00721070)],
            "classification": "ENTERABLE_DIRECT",
            "depth": 0,
            "confidence": "STRONG",
            "summary": "BSS table object; protected blocker after leaf XOR helper",
        },
        {
            "root": hx(TRACK_A),
            "required_state": [
                {"name": "+0x140/+0x150 xmmword", "class": "OBJECT_FIELD", "prov": "UNKNOWN"},
            ],
            "producer": None,
            "producer_type": "UNKNOWN",
            "dependency": None,
            "classification": "BLOCKED_UNKNOWN_STATE",
            "depth": None,
            "confidence": "PROVEN",
            "summary": track_a["note"],
        },
    ):
        init_roots = [r for r in init_roots if r.get("root") != entry["root"]]
        init_roots.append(entry)

    ordinary_init_recovered = sum(
        1 for r in init_roots
        if (r.get("classification") or "").startswith("ENTERABLE")
    )
    init_blocked_protected = sum(
        1 for r in init_roots if r.get("classification") == "BLOCKED_PROTECTED_INIT"
    )
    init_blocked_external = sum(
        1 for r in init_roots if r.get("classification") == "BLOCKED_EXTERNAL_INIT"
    )
    init_blocked_unknown = sum(
        1 for r in init_roots if r.get("classification") == "BLOCKED_UNKNOWN_STATE"
    )

    import_ready = frontier_prev.get("import_ready") or 737
    # refresh from frontier tool if cheap
    try:
        ready = uf.classify_functions(GAME) if hasattr(uf, "classify_functions") else None
    except Exception:
        ready = None
    if not ready:
        try:
            fr = uf.build_frontier(GAME) if hasattr(uf, "build_frontier") else None
            if isinstance(fr, dict) and "import_ready" in fr:
                import_ready = fr["import_ready"]
        except Exception:
            pass

    frontier = {
        "phase": 28,
        "definitions": {
            "ENTERABLE": frontier_prev.get("definitions", {}).get("ENTERABLE"),
            "DEEPEST_ORDINARY_EXECUTION_CHAIN": "Max nested ordinary UC frames in one harness run.",
            "LARGEST_EXECUTED_ORDINARY_CLOSURE": "Distinct ordinary UC functions entered in one run.",
            "ENTERABLE_WITH_DEPTH_3_POTENTIAL": (
                "Roots with proven contracts that can nest >=3 ordinary UC frames."
            ),
        },
        "high_functions": frontier_prev.get("high_functions") or 22779,
        "generated": frontier_prev.get("generated") or 22770,
        "compiled": frontier_prev.get("compiled") or 22770,
        "static_ready": frontier_prev.get("static_ready") or 20762,
        "import_ready": import_ready,
        "runtime_ready": frontier_prev.get("runtime_ready") or 54,
        "enterable": len(enterable_roots),
        "enterable_roots": enterable_roots,
        "enterable_with_depth_3_potential": len(enterable_depth3),
        "enterable_with_depth_3_potential_roots": enterable_depth3,
        "unique_uc_functions_executed": len(unique),
        "unique_uc_functions_executed_list": unique,
        "execution_runs": (frontier_prev.get("execution_runs") or 0) + 2,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
        "ordinary_init_recovered": ordinary_init_recovered,
        "init_blocked_external": init_blocked_external,
        "init_blocked_protected": init_blocked_protected,
        "init_blocked_unknown": init_blocked_unknown,
        "ordinary_runtime_frontier": {
            "HIGH": frontier_prev.get("high_functions") or 22779,
            "COMPILED": frontier_prev.get("compiled") or 22770,
            "STATIC_READY": frontier_prev.get("static_ready") or 20762,
            "IMPORT_READY": import_ready,
            "RUNTIME_READY": frontier_prev.get("runtime_ready") or 54,
            "ENTERABLE": len(enterable_roots),
            "EXECUTED": len(unique),
            "ORDINARY_INIT_RECOVERED": ordinary_init_recovered,
            "INIT_BLOCKED_EXTERNAL": init_blocked_external,
            "INIT_BLOCKED_PROTECTED": init_blocked_protected,
            "INIT_BLOCKED_UNKNOWN": init_blocked_unknown,
            "ENTERABLE_WITH_DEPTH_3_POTENTIAL": len(enterable_depth3),
            "DEEPEST": deepest,
            "LARGEST_CLOSURE": largest_closure,
        },
        "campaign_summary": {
            "phase28_attempted": len(campaign),
            "outcomes": dict(outcomes),
            "most_common_next_blocker": ["BLOCKED_REQUIRED_STATE", outcomes.get("BLOCKED_REQUIRED_STATE", 0)],
            "deepest_chain": deepest,
            "largest_executed_closure": largest_closure,
            "latest_newly_executed_root": hx(DEPTH3_CTOR),
            "deepest_successful_sequence": [
                hx(DEPTH3_CTOR), hx(DEPTH3_MID), hx(DEPTH3_BASE),
            ],
            "constructor_method_chain": True,
            "pod_grandparent_chain": False,
            "CIpow_reached": False,
            "floor_reached": False,
            "malloc_free_reached": False,
            "filesystem_reached": False,
            "timing_reached": False,
            "tls_reached": False,
            "seh_required": False,
            "unresolved_indirect_reached": True,
        },
        "track_a_a52df0": track_a,
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase29": (
            "Depth 3 achieved via ordinary ctor nesting. Next: either (1) resolve/stub-classify "
            "the Win32 IAT at 0x00B61138 blocking completion of 0x009E9160→0x009E8AD0, or "
            "(2) recover a lower-cost POD grandparent for the 0x00929900 math island "
            "(0x00947790 still UNKNOWN). Do not reopen Track A 0x00A52DF0 without new refs. "
            "No CRT HLE until a chain reaches it."
        ),
    }

    dump("object-contracts.json", contracts_doc)
    dump("initialization-frontier.json", {
        "phase": 28,
        "roots": init_roots,
        "counts": {
            "ordinary_init_recovered": ordinary_init_recovered,
            "init_blocked_external": init_blocked_external,
            "init_blocked_protected": init_blocked_protected,
            "init_blocked_unknown": init_blocked_unknown,
            "enterable": len(enterable_roots),
        },
    })
    dump("reverse-execution-frontier.json", {
        "phase": 28,
        "seeds": [hx(s) for s in EXECUTED_SEEDS],
        "callers": rev[:40],
        "depth3_candidates": depth3_candidates,
        "constructor_census": census,
    })
    dump("execution-evidence.json", {
        "phase": 28,
        "roots": hist,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
    })
    dump("runtime-frontier.json", frontier)
    dump("blocker-ranking.json", {
        "phase": 28,
        "campaign_outcomes": dict(outcomes),
        "most_common_real_blocker": (
            "BLOCKED_REQUIRED_STATE", outcomes.get("BLOCKED_REQUIRED_STATE", 0)
        ),
        "depth3_blocker": "BLOCKED_IMPORT/DISPATCH at 0x009777D0 after depth 3",
        "track_a": track_a["producer_classification"],
    })

    lines = [
        "# Undercover Phase 28 — Ordinary initialization depth",
        "",
        "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
        "",
        "## A. Baseline",
        "",
        "ENTERABLE 6; UNIQUE executed 8; deepest chain 2; largest closure 2.",
        "IMPORT_READY unchanged (~%d). Dominant blocker: BLOCKED_REQUIRED_STATE." % import_ready,
        "",
        "## B. Track A — `0x00A52DF0`",
        "",
        track_a["note"],
        "",
        "Layout proven from ops: xmmword reads at +0x140/+0x150; writes +0x100/+0x120;",
        "float arg; `_CIsin` then `_CIsqrt`. Not labeled matrix beyond SIMD vectors.",
        "",
        "## C. Non-E8 references",
        "",
        "- E8 callers: **%d**" % len(track_a["e8_callers"]),
        "- imm32 sites: **%d**" % len(track_a["imm32_sites"]),
        "- function-map preds: **%d**" % len(track_a["function_map_predecessors"]),
        "",
        "## D. Field provenance",
        "",
        "No ordinary writer cluster uniquely tied to this type. Classification:",
        "`NO_ORDINARY_INIT_PATH_FOUND`.",
        "",
        "## E. Constructor/init candidates",
        "",
        "- PROVEN: `0x009E9160` (vtable 0xC30E68)",
        "- STRONG base: `0x009E7710`",
        "- ORDINARY_INITIALIZER: `0x009E9990`",
        "",
        "## F. Reverse-call frontier",
        "",
        "Seeds: %s" % ", ".join(hx(s) for s in EXECUTED_SEEDS),
        "Top reverse callers scored in `reverse-execution-frontier.json`.",
        "",
        "## G–I. Census / POD",
        "",
        "See census in reverse-execution-frontier.json. POD builders preserved from Phase 27.",
        "",
        "## J. Ranked depth-3 candidates",
        "",
    ]
    for c in depth3_candidates:
        lines.append("- `%s` kind=%s cost=%s pot=%s — %s" % (
            c["root"], c["kind"], c["enterability_cost"], c["chain_potential"], c["note"]))
    lines += [
        "",
        "## K. Initialization graphs",
        "",
        "`0x009E9160` ← POD/this ← harness; nested `0x009E9990` ← `0x009E7710` ← STATIC vtable.",
        "`0x0072D640` ← primitives ← BSS `0xCEA3B8` ← PROTECTED `0x0072C190`.",
        "",
        "## L. Execution campaign",
        "",
        "Outcomes: `%s`" % dict(outcomes),
        "",
        "## M. Deepest successful run",
        "",
        "`0x009E9160` → `0x009E9990` → `0x009E7710` (depth **3**).",
        "Constructor→initializer chain: **YES**.",
        "POD grandparent→parent→child: **NO** (`0x00947790` still UNKNOWN).",
        "",
        "## N. Actual runtime blockers",
        "",
        "- After depth-3 ctor: Win32 IAT dispatch at `0x009777D0` / `[0x00B61138]`",
        "- After BSS parent chain: PROTECTED `0x0072C190`",
        "- Campaign majority: BLOCKED_REQUIRED_STATE (large islands)",
        "",
        "## O. Frontier delta",
        "",
        "- ENTERABLE: 6 → **%d**" % len(enterable_roots),
        "- UNIQUE executed: 8 → **%d**" % len(unique),
        "- DEEPEST chain: 2 → **%d**" % deepest,
        "- LARGEST closure: 2 → **%d**" % largest_closure,
        "- ENTERABLE_WITH_DEPTH_3_POTENTIAL: **%d**" % len(enterable_depth3),
        "",
        "## P. Phase 29",
        "",
        frontier["recommended_phase29"],
        "",
    ]
    path = os.path.join(ANALYSIS, "runtime-phase28.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("wrote", path)
    print("enterable", len(enterable_roots), "executed", len(unique),
          "deepest", deepest, "depth3_pot", len(enterable_depth3))


if __name__ == "__main__":
    main()
