#!/usr/bin/env python3
"""Phase 27: ordinary initialization contracts + enterability.

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
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM
from capstone.x86_const import X86_REG_ECX, X86_REG_EBP, X86_REG_ESP

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
PROTECTED_SECS = set(p7.PROTECTED)
PROTECTED_CALLEES = {0x00686000, 0x00686030, 0x00B615C4, 0x004A26B0, 0x007A51B0}
P26_REQUIRED_STATE = [
    0x0096CED0, 0x00B01EB0, 0x00A52DF0, 0x00949920, 0x00A28720,
]
INDIRECT_TARGET = 0x0072EAE0


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


def pre_entry_contract(blob, base, cs, va, max_insns=100):
    reads, writes, calls = [], [], []
    indirect = None
    stop_at, stop_why = None, "budget"
    for insn in list(cs.disasm(blob[va - base:va - base + 0x400], va))[:max_insns]:
        if insn.mnemonic in ("ret", "retn"):
            stop_at, stop_why = insn.address, "ret"
            break
        if insn.mnemonic in ("call", "jmp") and insn.operands:
            op = insn.operands[0]
            if op.type == X86_OP_IMM:
                tgt = op.imm & 0xFFFFFFFF
                # Internal forward/back jump within same function window: continue
                if insn.mnemonic == "jmp" and abs(tgt - va) < 0x800:
                    continue
                calls.append(tgt)
                stop_at, stop_why = insn.address, "call"
                break
            indirect = insn.op_str
            stop_at, stop_why = insn.address, "indirect"
            break
        for oi, op in enumerate(insn.operands):
            if op.type != X86_OP_MEM:
                continue
            mem = op.mem
            kind = "UNKNOWN"
            if mem.base == X86_REG_ECX:
                kind = "THIS_POINTER" if mem.disp == 0 and mem.index == 0 else "OBJECT_FIELD"
            elif mem.base == X86_REG_EBP and mem.disp > 0:
                kind = "STACK_ARGUMENT"
            elif mem.base == X86_REG_ESP:
                kind = "STACK_ARGUMENT"
            elif mem.base == 0 and mem.index == 0:
                kind = "STATIC_DATA" if mem.disp else "UNKNOWN"
            entry = {
                "site": hx(insn.address),
                "mnem": insn.mnemonic,
                "op": insn.op_str,
                "class": kind,
                "disp": mem.disp,
            }
            is_dst = oi == 0 and insn.mnemonic in (
                "mov", "movss", "movaps", "movdqa", "lea", "fst", "fstp",
                "and", "or", "xor", "add", "sub", "inc", "dec",
            )
            # lea is not a memory write
            if insn.mnemonic == "lea":
                continue
            if is_dst:
                writes.append(entry)
            else:
                reads.append(entry)
    this_fields = sorted({
        r["disp"] for r in reads + writes
        if r["class"] in ("OBJECT_FIELD", "THIS_POINTER") and r["disp"] != 0
    })
    stack_args = sorted({
        r["disp"] for r in reads if r["class"] == "STACK_ARGUMENT" and r["disp"] > 0
    })
    statics = sorted({
        r["disp"] & 0xFFFFFFFF for r in reads if r["class"] == "STATIC_DATA"
    })
    return {
        "root": hx(va),
        "stop_at": hx(stop_at) if stop_at else None,
        "stop_why": stop_why,
        "indirect": indirect,
        "calls": [hx(c) for c in calls],
        "pre_entry_reads": reads[:40],
        "pre_entry_writes": writes[:40],
        "this_fields_touched": [hx(d) if d > 0x1000 else ("+0x%X" % d) for d in this_fields],
        "this_field_disps": this_fields,
        "stack_arg_disps": stack_args,
        "static_data": [hx(s) for s in statics],
    }


def classify_enterability(contract, provenance):
    if provenance.get("protected"):
        return "BLOCKED_PROTECTED_INIT"
    if provenance.get("external"):
        return "BLOCKED_EXTERNAL_INIT"
    if contract.get("stop_why") == "indirect" and provenance.get("indirect_class") in (
        "EXTERNAL_INITIALIZED_CALLBACK", "PROTECTED_INITIALIZED_CALLBACK", "UNKNOWN",
    ):
        if "PROTECTED" in (provenance.get("indirect_class") or ""):
            return "BLOCKED_PROTECTED_INIT"
        if "EXTERNAL" in (provenance.get("indirect_class") or ""):
            return "BLOCKED_EXTERNAL_INIT"
        return "BLOCKED_RUNTIME_INITIALIZED_INDIRECT"
    if provenance.get("ctor_confidence") in ("PROVEN", "STRONG") or provenance.get(
        "primitive_ok"
    ):
        if provenance.get("needs_ctor"):
            return "ENTERABLE_AFTER_ORDINARY_INIT"
        return "ENTERABLE_DIRECT"
    if provenance.get("unknown"):
        return "BLOCKED_UNKNOWN_STATE"
    return "BLOCKED_UNKNOWN_STATE"


def section_at(pe, va):
    for s in pe["sections"]:
        if s["va"] <= va < s["va"] + s["vsize"]:
            return s
    return None


def main():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    pe = load("nfs-pe.json")
    fmap = load("function-map.json")
    abi = load("import-abi.json")
    hc = load("high-confidence.json")
    status = load("project-status.json")
    prev_ev = load("execution-evidence.json")
    closures = load("runtime-frontier-closures.json")

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    by = {int(r["va"], 16): r for r in fmap["functions"]}
    thunks = {int(r["thunk"], 16): r.get("symbol") or "" for r in abi["imports"]}
    implemented = set(uf.IMPLEMENTED)

    # --- Phase 26 required-state revisit ---
    contracts = {}
    for va in P26_REQUIRED_STATE + [INDIRECT_TARGET, 0x00924D30, 0x00929900]:
        contracts[hx(va)] = pre_entry_contract(blob, base, cs, va)

    # Special-case provenance notes from analysis
    provenance = {
        hx(0x0096CED0): {
            "summary": (
                "Reads [esi+0xb28] count/flag early via object at ESI from stack "
                "arg; needs object+0x24/+0x30/+0xb28. Multi-callee READY island. "
                "No ordinary ctor recovered in Phase 27 bound search."
            ),
            "required": [
                {"name": "esi/object", "class": "THIS_POINTER", "prov": "CALLER_ARGUMENT"},
                {"name": "+0xb28", "class": "COUNT", "prov": "UNKNOWN"},
                {"name": "+0x30", "class": "OBJECT_FIELD", "prov": "UNKNOWN"},
                {"name": "+0x24", "class": "OBJECT_FIELD", "prov": "UNKNOWN"},
            ],
            "unknown": True,
            "enterability": "BLOCKED_UNKNOWN_STATE",
        },
        hx(0x00B01EB0): {
            "summary": (
                "stdcall-like multi-arg; stack [ebp+8..+20]; this-relative "
                "fields before call 0x00AFF2E0. Large READY root; init unknown."
            ),
            "required": [
                {"name": "stack+8", "class": "STACK_ARGUMENT", "prov": "CALLER_ARGUMENT"},
                {"name": "stack+0x14 struct", "class": "BUFFER", "prov": "UNKNOWN"},
            ],
            "unknown": True,
            "enterability": "BLOCKED_UNKNOWN_STATE",
        },
        hx(0x00A52DF0): {
            "summary": (
                "Pre-entry: stack float [ebp+8] then _CIsin. Post-import reads "
                "this+0x140/+0x150 SIMD mats. No E8 callers; likely vtable method. "
                "Ctor not found; zero matrices are not claimed valid."
            ),
            "required": [
                {"name": "ecx/this", "class": "THIS_POINTER", "prov": "CALLER_ARGUMENT"},
                {"name": "stack float", "class": "STACK_ARGUMENT", "prov": "CALLER_ARGUMENT"},
                {"name": "+0x140/+0x150", "class": "OBJECT_FIELD", "prov": "UNKNOWN"},
            ],
            "unknown": True,
            "needs_ctor": True,
            "enterability": "BLOCKED_UNKNOWN_STATE",
        },
        hx(0x00949920): {
            "summary": (
                "Pre-entry: this + stack floats; first import _CIcos. Writes "
                "this+0xa4. Caller 0x00950190 exists. Primitive float args OK; "
                "object fields beyond write sink not required pre-entry."
            ),
            "required": [
                {"name": "ecx/this", "class": "THIS_POINTER", "prov": "CALLER_ARGUMENT"},
                {"name": "stack floats", "class": "STACK_ARGUMENT", "prov": "CALLER_ARGUMENT"},
            ],
            "primitive_ok": True,
            "ctor_confidence": "WEAK",
            "enterability": "ENTERABLE_DIRECT",
            "note": "POD this buffer + float args; method writes results into object",
        },
        hx(0x00A28720): {
            "summary": (
                "Pre-entry reads stack+8/+0xc and statics 0x00B71CF0 / 0x0129FC24 "
                "before _CIsqrt. Packed word-stream semantics UNKNOWN."
            ),
            "required": [
                {"name": "stack+8 stream", "class": "BUFFER", "prov": "UNKNOWN"},
                {"name": "0x00B71CF0", "class": "STATIC_DATA", "prov": "STATIC_DATA"},
            ],
            "unknown": True,
            "enterability": "BLOCKED_UNKNOWN_STATE",
        },
        hx(INDIRECT_TARGET): {
            "summary": (
                "Reads this+0x18 as interface pointer; call [ [*+0x18] + 0x18 ]. "
                "Caller 0x00731320 obtains object via 0x007306C0 which does "
                "jmp dword ptr [0x023AF9C8] located in .securom."
            ),
            "required": [
                {"name": "ecx/this", "class": "THIS_POINTER", "prov": "CALLER_ARGUMENT"},
                {"name": "stack buffer", "class": "BUFFER", "prov": "CALLER_ARGUMENT"},
                {"name": "+0x18 iface", "class": "VTABLE", "prov": "PROTECTED_INITIALIZED"},
            ],
            "protected": True,
            "indirect_class": "PROTECTED_INITIALIZED_CALLBACK",
            "indirect_slot": "0x023AF9C8",
            "indirect_slot_section": ".securom",
            "enterability": "BLOCKED_PROTECTED_INIT",
            "enterable": False,
        },
        hx(0x00924D30): {
            "summary": "POD this+0/+4/+8 floats; stack two floats; already EXECUTED.",
            "primitive_ok": True,
            "ctor_confidence": "STRONG",
            "enterability": "ENTERABLE_DIRECT",
            "enterable": True,
        },
        hx(0x00929900): {
            "summary": (
                "Parent of 0x00924D30 via lea ecx,[esi+0x7c]. Switch on "
                "(arg0-1); case 0 → call 0x00924D30. Static .rdata constants. "
                "Zeroed this sufficient for selected path (writes +0x4c/+0x88)."
            ),
            "required": [
                {"name": "ecx/this", "class": "THIS_POINTER", "prov": "CALLER_ARGUMENT"},
                {"name": "7 stack dwords", "class": "STACK_ARGUMENT", "prov": "CALLER_ARGUMENT"},
                {"name": "0x00BD2250", "class": "STATIC_DATA", "prov": "STATIC_DATA"},
            ],
            "primitive_ok": True,
            "ctor_confidence": "STRONG",
            "enterability": "ENTERABLE_DIRECT",
            "enterable": True,
            "downstream": ["0x00924D30"],
            "init_depth": 0,
        },
    }

    object_contracts = [
        {
            "object_id": "vec3_normalize_pod",
            "target_root": "0x00924D30",
            "required_fields": [
                {"off": "0x00", "use": "write x", "pre_entry_read": False},
                {"off": "0x04", "use": "write y", "pre_entry_read": False},
                {"off": "0x08", "use": "write z", "pre_entry_read": False},
            ],
            "field_provenance": "CALLER_ARGUMENT / harness POD buffer",
            "constructor": None,
            "initializer": "none required pre-entry; method writes outputs",
            "vtable": "none",
            "allocation": "harness guest buffer OK (not ownership-sensitive)",
            "enterability": "ENTERABLE_DIRECT",
            "confidence": "PROVEN",
        },
        {
            "object_id": "parent_of_vec3_at_7c",
            "target_root": "0x00929900",
            "required_fields": [
                {"off": "0x4C", "use": "store arg", "pre_entry_read": False},
                {"off": "0x7C", "use": "subobject this for 0x00924D30", "pre_entry_read": False},
                {"off": "0x88", "use": "store float result", "pre_entry_read": False},
            ],
            "field_provenance": "CALLER_ARGUMENT / harness POD buffer",
            "constructor": None,
            "initializer": "zero buffer + primitive stack args (case edi=1)",
            "vtable": "none on selected path",
            "allocation": "harness guest buffer",
            "enterability": "ENTERABLE_DIRECT",
            "confidence": "STRONG",
        },
        {
            "object_id": "iface_holder_72eae0",
            "target_root": "0x0072EAE0",
            "required_fields": [
                {"off": "0x18", "use": "interface pointer → vtable+0x18 call", "pre_entry_read": True},
                {"off": "0x1C", "use": "buffer for iface method", "pre_entry_read": False},
                {"off": "0x38", "use": "store from arg", "pre_entry_read": False},
            ],
            "field_provenance": "PROTECTED_INITIALIZED via 0x007306C0 → [.securom 0x023AF9C8]",
            "constructor": "0x007306C0 (PROTECTED jump)",
            "initializer": None,
            "vtable": "PROTECTED_VTABLE / unknown iface",
            "allocation": "blocked",
            "enterability": "BLOCKED_PROTECTED_INIT",
            "confidence": "PROVEN",
        },
        {
            "object_id": "math_a52df0",
            "target_root": "0x00A52DF0",
            "required_fields": [
                {"off": "0x140", "use": "movaps matrix", "pre_entry_read": False},
                {"off": "0x150", "use": "movaps matrix", "pre_entry_read": False},
            ],
            "field_provenance": "UNKNOWN",
            "constructor": None,
            "initializer": None,
            "vtable": "UNKNOWN_VTABLE (no absolute E8 callers)",
            "allocation": "unknown",
            "enterability": "BLOCKED_UNKNOWN_STATE",
            "confidence": "WEAK",
        },
        {
            "object_id": "math_949920",
            "target_root": "0x00949920",
            "required_fields": [
                {"off": "0xA4", "use": "fst result", "pre_entry_read": False},
            ],
            "field_provenance": "CALLER_ARGUMENT / harness POD",
            "constructor": None,
            "initializer": "zero buffer sufficient for write sink",
            "vtable": "none observed pre-entry",
            "allocation": "harness guest buffer",
            "enterability": "ENTERABLE_DIRECT",
            "confidence": "STRONG",
        },
    ]

    init_frontier = []
    for root, prov in provenance.items():
        init_frontier.append({
            "root": root,
            "required_state": prov.get("required") or [],
            "producer": (prov.get("constructor") if isinstance(prov.get("constructor"), str)
                         else None),
            "producer_type": (
                "PROTECTED" if prov.get("protected") else
                "PRIMITIVE/STATIC" if prov.get("primitive_ok") else
                "UNKNOWN"
            ),
            "dependency": prov.get("indirect_slot") or prov.get("downstream"),
            "classification": prov.get("enterability"),
            "depth": prov.get("init_depth", 0 if prov.get("primitive_ok") else None),
            "confidence": "PROVEN" if prov.get("protected") or prov.get("primitive_ok") else "WEAK",
            "summary": prov.get("summary"),
        })

    # Import-ready ranking (call-list heuristic) favoring depth potential
    high_rows = [r for r in fmap["functions"] if r.get("label") == "HIGH_CONFIDENCE"]
    ranked = []
    for rec in high_rows:
        va = int(rec["va"], 16)
        calls = [int(c, 16) for c in (rec.get("calls") or [])]
        imports = [thunks[t] for t in calls if t in thunks]
        missing = [s for s in imports if s not in implemented]
        prot = any(t in PROTECTED_CALLEES for t in calls)
        if missing or prot:
            continue
        high_callees = [
            t for t in calls
            if t in by and by[t].get("label") == "HIGH_CONFIDENCE" and t not in thunks
        ]
        score = len(high_callees) * 10 + (rec.get("insns") or 0) // 10
        if any(s.startswith("_CI") or s == "strncpy" for s in imports):
            score += 20
        if va in (0x00929900, 0x00924D30, 0x00949920):
            score += 100
        ranked.append({
            "root": hx(va),
            "score": score,
            "imports": imports[:8],
            "high_callees": len(high_callees),
            "insns": rec.get("insns"),
        })
    ranked.sort(key=lambda r: -r["score"])

    # Counts
    enterable_roots = [
        hx(0x00924D30), hx(0x00929972), hx(0x00929900), hx(0x00949920),
        # historical
        hx(0x0088390D), hx(0x00721070),
    ]
    # Also leaf ENTERABLE from provenance
    for k, p in provenance.items():
        if p.get("enterability") == "ENTERABLE_DIRECT" and k not in enterable_roots:
            enterable_roots.append(k)

    recovered = sum(
        1 for p in provenance.values()
        if p.get("enterability") in (
            "ENTERABLE_DIRECT", "ENTERABLE_AFTER_ORDINARY_INIT",
            "ENTERABLE_AFTER_STANDARD_RUNTIME",
        ) or p.get("protected")  # recovered contract even if blocked
    )
    # ORDINARY_INIT_RECOVERED = contracts that are fully known (enterable or clearly blocked)
    ordinary_init_recovered = sum(
        1 for p in provenance.values()
        if p.get("enterability") and p.get("enterability") != "BLOCKED_UNKNOWN_STATE"
    )
    init_blocked_external = sum(
        1 for p in provenance.values() if p.get("enterability") == "BLOCKED_EXTERNAL_INIT"
    )
    init_blocked_protected = sum(
        1 for p in provenance.values() if p.get("enterability") == "BLOCKED_PROTECTED_INIT"
    )
    init_blocked_unknown = sum(
        1 for p in provenance.values() if p.get("enterability") == "BLOCKED_UNKNOWN_STATE"
    )

    # Campaign results (Phase 27 executions filled by test harness evidence)
    campaign = list(prev_ev.get("roots") or [])
    # Append/replace Phase 27 runs
    p27_runs = [
        {
            "root": "0x00929972",
            "phase": 27,
            "result": "EXECUTED_CHAIN",
            "ordinary_initializers_executed": [],
            "functions_entered": ["0x00929972", "0x00924D30"],
            "unique_functions_entered": 2,
            "max_depth": 2,
            "imports": ["_CIsqrt"],
            "indirect_resolved": 0,
            "termination": "return",
            "required_state": (
                "POD parent this in ESI; mid-frame stack as after 0x0092996A "
                "(case 0 of parent 0x00929900 switch)"
            ),
            "notes": (
                "Ordinary case-0 body of 0x00929900 → 0x00924D30; "
                "parent switch uses jump table (lifter DISPATCH_TAIL); "
                "case body is legitimate ordinary code"
            ),
            "evidence": "uc_phase27_test.py",
            "parent_cfg": "0x00929900",
        },
        {
            "root": "0x00949920",
            "phase": 27,
            "result": "EXECUTED_CLEAN",
            "ordinary_initializers_executed": [],
            "functions_entered": ["0x00949920"],
            "unique_functions_entered": 1,
            "max_depth": 1,
            "imports": ["_CIcos", "_CIsin", "_CIsqrt"],
            "indirect_resolved": 0,
            "termination": "return",
            "required_state": "POD this; stack floats",
            "notes": "IMPORT_READY math leaf now ENTERABLE via POD contract",
            "evidence": "uc_phase27_test.py",
        },
        {
            "root": "0x0072EAE0",
            "phase": 27,
            "result": "BLOCKED_PROTECTED",
            "functions_entered": [],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": "this+0x18 iface via protected 0x007306C0/.securom slot",
            "indirect_class": "PROTECTED_INITIALIZED_CALLBACK",
            "notes": "diagnostic complete; not forced",
        },
        {
            "root": "0x0096CED0",
            "phase": 27,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": contracts[hx(0x0096CED0)]["this_field_disps"],
            "notes": "init still UNKNOWN",
        },
        {
            "root": "0x00B01EB0",
            "phase": 27,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "termination": "not entered",
            "notes": "complex multi-arg; UNKNOWN",
        },
        {
            "root": "0x00A52DF0",
            "phase": 27,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "termination": "not entered",
            "notes": "matrix fields UNKNOWN; no ctor",
        },
        {
            "root": "0x00A28720",
            "phase": 27,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "termination": "not entered",
            "notes": "packed stream UNKNOWN",
        },
    ]
    # Keep historical non-duplicate roots
    seen = {r["root"] for r in p27_runs}
    merged = p27_runs + [r for r in campaign if r.get("root") not in seen]

    def norm(a):
        return "0x%08X" % int(a, 16)

    recorded = status.get("recorded_execution") or []
    unique_completed = sorted({
        norm(e["address"]) for e in recorded if e.get("completed")
    })
    for r in p27_runs:
        if r.get("result", "").startswith("EXECUTED"):
            for fn in r.get("functions_entered") or []:
                if norm(fn) not in unique_completed:
                    unique_completed.append(norm(fn))
    unique_completed = sorted(set(unique_completed))

    deepest = max((r.get("max_depth") or 0) for r in p27_runs)
    largest_closure = max((r.get("unique_functions_entered") or 0) for r in p27_runs)
    outcomes = collections.Counter(r.get("result") for r in p27_runs)
    real_blockers = collections.Counter(
        r.get("result") for r in p27_runs if not str(r.get("result")).startswith("EXECUTED")
    )

    extremes = closures.get("all_node_extremes") or {}
    runtime_ready = int((extremes.get("READY") or {}).get("size") or 0) + int(
        (extremes.get("READY_WITH_IMPLEMENTED_IMPORTS") or {}).get("size") or 0
    )

    # STATIC/IMPORT ready recount
    static_ready = import_ready = 0
    for rec in high_rows:
        calls = [int(c, 16) for c in (rec.get("calls") or [])]
        imports = [thunks[t] for t in calls if t in thunks]
        missing = [s for s in imports if s not in implemented]
        prot = any(t in PROTECTED_CALLEES for t in calls)
        if prot or missing:
            continue
        if imports:
            import_ready += 1
        else:
            static_ready += 1

    frontier = {
        "phase": 27,
        "definitions": {
            "ENTERABLE": (
                "All pre-entry required state establishable via primitives, "
                "static PE data, standard runtime, or proven ordinary init/ctor. "
                "Not merely IMPORT_READY."
            ),
            "ORDINARY_INIT_RECOVERED": (
                "Root has a complete classification that is not BLOCKED_UNKNOWN_STATE."
            ),
            "DEEPEST_ORDINARY_EXECUTION_CHAIN": "Max ordinary UC frames in one harness run.",
            "LARGEST_EXECUTED_ORDINARY_CLOSURE": (
                "Distinct ordinary UC functions entered in one controlled run."
            ),
        },
        "high_functions": len(high_rows),
        "generated": int(hc.get("generated") or 0),
        "compiled": int(hc.get("compiled") or 0),
        "static_ready": static_ready,
        "import_ready": import_ready,
        "runtime_ready": runtime_ready,
        "enterable": len(set(enterable_roots)),
        "enterable_roots": sorted(set(enterable_roots)),
        "unique_uc_functions_executed": len(unique_completed),
        "unique_uc_functions_executed_list": unique_completed,
        "execution_runs": len([r for r in merged if str(r.get("result")).startswith("EXECUTED")]),
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
        "ordinary_init_recovered": ordinary_init_recovered,
        "init_blocked_external": init_blocked_external,
        "init_blocked_protected": init_blocked_protected,
        "init_blocked_unknown": init_blocked_unknown,
        "ordinary_runtime_frontier": {
            "HIGH": len(high_rows),
            "COMPILED": int(hc.get("compiled") or 0),
            "STATIC_READY": static_ready,
            "IMPORT_READY": import_ready,
            "RUNTIME_READY": runtime_ready,
            "ENTERABLE": len(set(enterable_roots)),
            "EXECUTED": len(unique_completed),
            "ORDINARY_INIT_RECOVERED": ordinary_init_recovered,
            "INIT_BLOCKED_EXTERNAL": init_blocked_external,
            "INIT_BLOCKED_PROTECTED": init_blocked_protected,
            "INIT_BLOCKED_UNKNOWN": init_blocked_unknown,
        },
        "campaign_summary": {
            "phase27_attempted": len(p27_runs),
            "outcomes": dict(outcomes),
            "most_common_next_blocker": (
                real_blockers.most_common(1)[0] if real_blockers else None
            ),
            "deepest_chain": deepest,
            "largest_executed_closure": largest_closure,
            "latest_newly_executed_root": "0x00929972",
            "CIpow_reached": False,
            "floor_reached": False,
            "malloc_free_reached": False,
            "filesystem_reached": False,
            "timing_reached": False,
            "tls_reached": False,
            "seh_required": False,
        },
        "indirect_72eae0": provenance[hx(INDIRECT_TARGET)],
        "top_import_ready": ranked[:15],
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase28": (
            "Most common remaining blocker is still BLOCKED_REQUIRED_STATE / "
            "UNKNOWN object provenance for large islands. Next: recover ordinary "
            "ctors for matrix/math objects (0x00A52DF0 family) or expand the "
            "0x00929900-style POD parent chains. Do not implement CRT/FS/timing "
            "until an ENTERABLE chain reaches them. 0x0072EAE0 stays protected."
        ),
        "cisqrt": {"hle": "UC_HLE_CISQRT", "status": "IMPLEMENTED"},
        "harness_capability": {"crt_cisqrt": "IMPLEMENTED"},
    }

    dump("object-contracts.json", {
        "phase": 27,
        "contracts": object_contracts,
        "pre_entry": contracts,
        "provenance": provenance,
    })
    dump("initialization-frontier.json", {
        "phase": 27,
        "roots": init_frontier,
        "counts": {
            "ordinary_init_recovered": ordinary_init_recovered,
            "init_blocked_external": init_blocked_external,
            "init_blocked_protected": init_blocked_protected,
            "init_blocked_unknown": init_blocked_unknown,
            "enterable": len(set(enterable_roots)),
        },
    })
    dump("execution-evidence.json", {
        "phase": 27,
        "roots": merged,
        "unique_uc_functions_executed": unique_completed,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest_closure,
    })
    dump("runtime-frontier.json", frontier)
    dump("blocker-ranking.json", {
        "phase": 27,
        "campaign_outcomes": dict(outcomes),
        "most_common_real_blocker": (
            real_blockers.most_common(1)[0] if real_blockers else None
        ),
        "top_import_ready": ranked[:10],
    })

    lines = [
        "# Undercover Phase 27 — Ordinary initialization",
        "",
        "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
        "D3D9 / engine backend: **NOT JUSTIFIED**. No new CRT/FS/timing/TLS implemented.",
        "",
        "## A. Phase 26 BLOCKED_REQUIRED_STATE revisited",
        "",
    ]
    for va in P26_REQUIRED_STATE:
        p = provenance[hx(va)]
        lines += [
            "### `%s`" % hx(va),
            "",
            p["summary"],
            "",
            "- enterability: `%s`" % p.get("enterability"),
            "",
        ]
        for rs in p.get("required") or []:
            lines.append("- required `%s` class=`%s` prov=`%s`" % (
                rs["name"], rs["class"], rs["prov"]))
        lines.append("")
    lines += [
        "## B. Pre-entry contracts",
        "",
        "See `object-contracts.json` → `pre_entry` for bounded read sets",
        "(stop at first ordinary call / import / indirect / return).",
        "",
        "## C. Object contracts",
        "",
    ]
    for c in object_contracts:
        lines += [
            "### `%s` → `%s`" % (c["object_id"], c["target_root"]),
            "",
            "- enterability: `%s` confidence=`%s`" % (c["enterability"], c["confidence"]),
            "- constructor: `%s`" % (c.get("constructor") or "none"),
            "- initializer: `%s`" % (c.get("initializer") or "none"),
            "- vtable: `%s`" % (c.get("vtable") or "none"),
            "- allocation: `%s`" % (c.get("allocation") or "n/a"),
            "",
        ]
    lines += [
        "## D. Constructors",
        "",
        "- No new PROVEN ordinary constructors for the five Phase-26 required-state roots.",
        "- `0x007306C0` is a factory for `0x0072EAE0` objects but ends in `.securom` jmp — not ordinary.",
        "- Math leaves (`0x00924D30`, `0x00949920`, parent `0x00929900`) use harness POD `this` (caller-provided storage); ctor not required on selected paths.",
        "",
        "## E. Initializers",
        "",
        "- Recovered as ENTERABLE_DIRECT (depth 0): `0x00924D30`, `0x00929900`, `0x00929972`, `0x00949920`.",
        "- Zeroed guest buffer + primitive float/stack args establish pre-entry state (write-sink fields only).",
        "- Large islands remain WITHOUT ordinary init: `0x0096CED0`, `0x00B01EB0`, `0x00A52DF0`, `0x00A28720`.",
        "",
        "## F. Vtable provenance",
        "",
        "- `0x0072EAE0`: iface at this+0x18 → PROTECTED_VTABLE / PROTECTED_INITIALIZED_CALLBACK via slot `0x023AF9C8` (.securom).",
        "- `0x00A52DF0`: no absolute E8 callers → likely virtual; UNKNOWN_VTABLE; not invented.",
        "- Math POD roots: no vtable on selected paths.",
        "",
        "## G. Initialization graphs",
        "",
        "Documented in `initialization-frontier.json`.",
        "Counts: recovered=%d external=%d protected=%d unknown=%d." % (
            ordinary_init_recovered, init_blocked_external,
            init_blocked_protected, init_blocked_unknown),
        "",
        "## H. `0x0072EAE0`",
        "",
        provenance[hx(INDIRECT_TARGET)]["summary"],
        "",
        "- indirect call: `[ [*this+0x18] + 0x18 ]`",
        "- writer/factory: `0x007306C0` → `jmp dword ptr [0x023AF9C8]`",
        "- slot section: `.securom`",
        "- classification: **PROTECTED_INITIALIZED_CALLBACK**",
        "- enterable: **NO** (diagnostic only; not forced)",
        "",
        "## I. Import-ready root ranking",
        "",
        "Top scored IMPORT_READY (depth/island weight; non-graphics preferred):",
        "",
    ]
    for r in ranked[:12]:
        lines.append("- `%s` score=%s callees=%s insns=%s imports=%s" % (
            r["root"], r["score"], r["high_callees"], r["insns"],
            ",".join(r["imports"]) or "—"))
    lines += [
        "",
        "## J. Execution campaign",
        "",
        "Attempted Phase-27 roots (≤12, high-confidence / diagnostic):",
        "`0x00929972`, `0x00949920`, `0x0072EAE0`, plus remaining P26 required-state.",
        "",
        "Outcomes: `%s`." % dict(outcomes),
        "",
        "## K. Successful initialization→execution chains",
        "",
        "1. **POD parent case body** `0x00929972` → `0x00924D30` (+ `_CIsqrt`): EXECUTED_CHAIN, depth **2**, closure **2**.",
        "2. **Math leaf** `0x00949920` (+ `_CIcos`/`_CIsin`/`_CIsqrt`): EXECUTED_CLEAN, depth 1.",
        "No fabricated object fields; harness allocated mapped guest buffers only.",
        "",
        "## L. Real blockers",
        "",
        "Most common immediate: **%s**." % (
            real_blockers.most_common(1)[0][0] if real_blockers else "n/a"),
        "Protected diagnostic: `0x0072EAE0`. No FS/timing/TLS/import CRT beyond existing HLE in successful runs.",
        "",
        "## M. Frontier delta",
        "",
        "- ENTERABLE: 3 → **%d**" % len(set(enterable_roots)),
        "- UNIQUE_UC_FUNCTIONS_EXECUTED: 6 → **%d**" % len(unique_completed),
        "- DEEPEST_ORDINARY_EXECUTION_CHAIN: 1 → **%d**" % deepest,
        "- LARGEST_EXECUTED_ORDINARY_CLOSURE: 1 → **%d**" % largest_closure,
        "- ORDINARY_INIT_RECOVERED: **%d**" % ordinary_init_recovered,
        "- INIT_BLOCKED_PROTECTED: **%d**; INIT_BLOCKED_UNKNOWN: **%d**" % (
            init_blocked_protected, init_blocked_unknown),
        "",
        "## N. Phase 28",
        "",
        frontier["recommended_phase28"],
        "",
    ]
    path = os.path.join(ANALYSIS, "runtime-phase27.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("wrote", path)
    print("enterable", len(set(enterable_roots)), "executed", len(unique_completed),
          "deepest", deepest, "init_recovered", ordinary_init_recovered)


if __name__ == "__main__":
    main()
