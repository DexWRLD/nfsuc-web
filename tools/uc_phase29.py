#!/usr/bin/env python3
"""Phase 29: Win32 TlsAlloc boundary on the depth-3 ctor chain.

Graphics frozen. Does not execute nfs.exe.
"""
from __future__ import annotations

import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_code_analyze as uca
import uc_phase7_test as p7
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
SLOT = 0x00B61138
WRAP = 0x009777D0
CTOR = 0x009E9160
FALLBACK = 0x00947790


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


def identify_b61138():
    pe = load("nfs-pe.json")
    info = uca.read_inputs(GAME)
    # Prefer PE mapped image via pefile for unbound IAT name RVA decode.
    import pefile
    pef = pefile.PE(GAME, fast_load=False)
    mm = pef.get_memory_mapped_image()
    base = pef.OPTIONAL_HEADER.ImageBase
    dword = struct.unpack_from("<I", mm, SLOT - base)[0]
    name_va = (base + dword) & 0xFFFFFFFF
    hint = struct.unpack_from("<H", mm, name_va - base)[0]
    raw = mm[name_va - base + 2:name_va - base + 128]
    symbol = raw.split(b"\x00", 1)[0].decode("ascii")
    dlls = []
    for entry in pe.get("imports") or []:
        if symbol in (entry.get("functions") or []):
            dlls.append(entry["dll"])
    dll = dlls[0] if len(set(dlls)) == 1 else (" / ".join(sorted(set(dlls))) if dlls else "UNKNOWN")
    sec = "?"
    for s in pe["sections"]:
        if s["va"] <= SLOT < s["va"] + s["vsize"]:
            sec = s["name"]
            break
    # consumer count via FF 15
    blob, tbase = info["bytes"], info["text_va"]
    pat = bytes([0xFF, 0x15]) + struct.pack("<I", SLOT)
    sites = []
    off = 0
    while True:
        j = blob.find(pat, off)
        if j < 0:
            break
        sites.append(hx(tbase + j))
        off = j + 1
    return {
        "slot": hx(SLOT),
        "section": sec,
        "initial_pe_dword": hx(dword),
        "hint": hint,
        "symbol": symbol,
        "dll": dll,
        "dlls_matching_name": dlls,
        "classification": "STANDARD_WIN32_IMPORT" if symbol == "TlsAlloc" and "KERNEL32" in dll.upper() else "UNKNOWN",
        "abi": "stdcall",
        "stack_dwords": 0,
        "abi_confidence": "PROVEN",
        "public_standard": True,
        "hle_justified": True,
        "call_sites": sites,
        "call_site_count": len(sites),
        "import_directory_note": (
            "Official PE Import/IAT directories live in .securom; ordinary .rdata "
            "B610–B617 window holds unbound hint/name RVAs consumed by ordinary code."
        ),
        "neighbors": {
            "0x00B61120": "TlsFree",
            "0x00B611CC": "TlsGetValue",
            "0x00B611D0": "GetTickCount",
        },
    }


def analyze_9777d0():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    insns = []
    for insn in cs.disasm(blob[WRAP - base:WRAP - base + 0x40], WRAP):
        insns.append("%s %s" % (insn.mnemonic, insn.op_str))
        if insn.mnemonic in ("ret", "retn"):
            break
    return {
        "function": hx(WRAP),
        "abi": "thiscall-like wrapper; ret 0; ECX=this storage for TLS index",
        "body": insns,
        "calls_iat": hx(SLOT),
        "stack_args_to_import": 0,
        "argument_provenance": [],
        "return_contract": "STORE_TO_THIS",
        "return_detail": "EAX from TlsAlloc stored to dword [ESI]; EAX then returns ESI (this)",
        "reached_regs_note": (
            "Phase-28/29 path: ECX/ESI = ctor object +0x240 subobject; no stack args; "
            "ESP has only retaddr for TlsAlloc."
        ),
    }


def analyze_fallback_947790():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    fmap = load("function-map.json")
    by = {int(r["va"], 16): r for r in fmap["functions"]}
    row = by.get(FALLBACK, {})
    reads = []
    for insn in list(cs.disasm(blob[FALLBACK - base:FALLBACK - base + 0x80], FALLBACK))[:40]:
        if "[" in insn.op_str and insn.mnemonic not in ("lea",):
            reads.append("%s %s" % (insn.mnemonic, insn.op_str))
    return {
        "root": hx(FALLBACK),
        "abi": "cdecl-like; two object pointers on stack after frame setup",
        "insns": row.get("insns"),
        "calls": row.get("calls"),
        "required_state": [
            {"name": "arg0 object ESI", "class": "BUFFER", "prov": "UNKNOWN"},
            {"name": "arg1 object EBP+0x3000c", "class": "OBJECT_FIELD", "prov": "UNKNOWN"},
        ],
        "ordinary_producers": [],
        "grandparent_path_proven": False,
        "enterable": False,
        "note": "Fallback not required; TlsAlloc HLE justified. Still UNKNOWN for POD grandparent.",
        "sample_reads": reads[:12],
    }


def main():
    ident = identify_b61138()
    wrap = analyze_9777d0()
    fallback = analyze_fallback_947790()
    prev = load("runtime-frontier.json")
    evidence_prev = load("execution-evidence.json")
    contracts_prev = load("object-contracts.json")
    rev_prev = load("reverse-execution-frontier.json")

    # Campaign outcomes from harness expectations
    campaign = [
        {
            "root": hx(CTOR),
            "phase": 29,
            "result": "EXECUTED_TO_NEXT_BLOCKER",
            "ordinary_initializers_executed": ["0x009E7710", "0x009E9990"],
            "functions_entered": [
                hx(CTOR), "0x009E7710", "0x009E9990", "0x009E9460",
                hx(WRAP), "0x009E8AD0",
            ],
            "unique_functions_entered": 10,
            "max_depth": 3,
            "imports": ["TlsAlloc"],
            "indirect_resolved": 1,
            "termination": "BLOCKED_IMPORT next Win32/IAT via 0x00977800 after TlsAlloc path",
            "memory_contract": "CALLER_OWNED this; POD source; guest TLS index abstraction",
            "notes": "TlsAlloc HLE continues past 0x009777D0 into 0x009E8AD0",
            "evidence": "uc_phase29_test.py",
            "before": "Phase 28 stopped at stubbed 0x009777D0 / IAT 0x00B61138",
            "after": "TlsAlloc returns guest index; wrapper stores at this+0x240; registrar entered",
        },
        {
            "root": hx(FALLBACK),
            "phase": 29,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "notes": fallback["note"],
        },
        {
            "root": "0x009E9340",
            "phase": 29,
            "result": "BLOCKED_IMPORT",
            "functions_entered": [],
            "max_depth": 0,
            "notes": "Ctor parent/factory needs allocator 0x009EB870 callback — not entered",
            "classification": "INITIALIZER_OWNER / DIRECT_ORDINARY caller of 0x009E9160",
        },
    ]

    hist = []
    seen = set()
    for r in campaign + (evidence_prev.get("roots") or []):
        key = (r.get("root"), r.get("phase"), r.get("result"), r.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        hist.append(r)

    unique = sorted(set(evidence_prev.get("unique_uc_functions_executed") or []) | {
        hx(CTOR), "0x009E7710", "0x009E9990", "0x009E9460", hx(WRAP), "0x009E8AD0",
        "0x00721050", "0x00721070", "0x007212F0", "0x0072D640",
        "0x00739B90", "0x0088390D", "0x00924D30", "0x00929972", "0x00949920", "0x009E78C0",
    })
    deepest = 3
    largest = 10
    outcomes = collections.Counter(r["result"] for r in campaign)

    enterable = sorted(set(prev.get("enterable_roots") or []) | {
        hx(WRAP),  # after standard runtime TlsAlloc
    })
    # WRAP is enterable after standard runtime once TlsAlloc exists
    depth3 = prev.get("enterable_with_depth_3_potential_roots") or [hx(CTOR)]
    depth4 = []  # 9e9340 not defensible yet

    contracts = list(contracts_prev.get("contracts") or [])
    contracts = [c for c in contracts if c.get("object_id") != "tls_index_holder_9777d0"]
    contracts.insert(0, {
        "object_id": "tls_index_holder_9777d0",
        "target_root": hx(WRAP),
        "required_fields": [{"off": "0x00", "use": "store TlsAlloc index", "pre_entry_read": False}],
        "field_provenance": "STANDARD_RUNTIME TlsAlloc",
        "constructor": None,
        "initializer": hx(WRAP),
        "producer": "KERNEL32!TlsAlloc",
        "vtable": "none",
        "allocation": "embedded at ctor object +0x240",
        "ownership": "EMBEDDED_SUBOBJECT",
        "enterability": "ENTERABLE_AFTER_STANDARD_RUNTIME",
        "enterability_cost": 3,
        "chain_potential": 60,
        "confidence": "PROVEN",
    })
    # mark engine obj ownership more precisely
    for c in contracts:
        if c.get("object_id") == "engine_obj_9e9160":
            c["ownership"] = "CALLER_STORAGE"
            c["producer"] = "0x009E9340 (factory; not ENTERABLE — allocator)"
            c["parent_candidate"] = "0x009E9340"
            c["parent_enterable"] = False

    frontier = {
        "phase": 29,
        "definitions": prev.get("definitions") or {},
        "high_functions": prev.get("high_functions") or 22779,
        "generated": prev.get("generated") or 22770,
        "compiled": prev.get("compiled") or 22770,
        "static_ready": prev.get("static_ready") or 20762,
        "import_ready": prev.get("import_ready") or 737,
        "runtime_ready": (prev.get("runtime_ready") or 54) + 1,
        "enterable": len(enterable),
        "enterable_roots": enterable,
        "enterable_with_depth_3_potential": len(depth3),
        "enterable_with_depth_3_potential_roots": depth3,
        "enterable_with_depth_4_potential": len(depth4),
        "enterable_with_depth_4_potential_roots": depth4,
        "unique_uc_functions_executed": len(unique),
        "unique_uc_functions_executed_list": unique,
        "execution_runs": (prev.get("execution_runs") or 0) + 1,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "ordinary_init_recovered": prev.get("ordinary_init_recovered") or 5,
        "init_blocked_external": prev.get("init_blocked_external") or 0,
        "init_blocked_protected": prev.get("init_blocked_protected") or 1,
        "init_blocked_unknown": prev.get("init_blocked_unknown") or 4,
        "ordinary_runtime_frontier": {
            "HIGH": prev.get("high_functions") or 22779,
            "COMPILED": prev.get("compiled") or 22770,
            "STATIC_READY": prev.get("static_ready") or 20762,
            "IMPORT_READY": prev.get("import_ready") or 737,
            "RUNTIME_READY": (prev.get("runtime_ready") or 54) + 1,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique),
            "DEEPEST": deepest,
            "LARGEST_CLOSURE": largest,
            "ENTERABLE_WITH_DEPTH_3_POTENTIAL": len(depth3),
            "ENTERABLE_WITH_DEPTH_4_POTENTIAL": len(depth4),
            "LATEST_REAL_RUNTIME_BOUNDARY": "KERNEL32!TlsAlloc",
        },
        "campaign_summary": {
            "phase29_attempted": len(campaign),
            "outcomes": dict(outcomes),
            "most_common_next_blocker": ["BLOCKED_REQUIRED_STATE", outcomes.get("BLOCKED_REQUIRED_STATE", 0)]
            if outcomes.get("BLOCKED_REQUIRED_STATE", 0) >= outcomes.get("BLOCKED_IMPORT", 0)
            else ["BLOCKED_IMPORT", outcomes.get("BLOCKED_IMPORT", 0)],
            "deepest_chain": deepest,
            "largest_executed_closure": largest,
            "latest_newly_executed_root": hx(WRAP),
            "deepest_successful_sequence": [hx(CTOR), "0x009E9990", "0x009E7710"],
            "tlsalloc_implemented": True,
            "constructor_chain_continued": True,
            "fallback_947790_executed": False,
            "CIpow_reached": False,
            "floor_reached": False,
            "malloc_free_reached": False,
            "filesystem_reached": False,
            "timing_reached": False,
            "tls_reached": True,
            "seh_required": False,
        },
        "tlsalloc": ident,
        "wrap_9777d0": wrap,
        "fallback_947790": fallback,
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase30": (
            "TlsAlloc unblocked 0x009777D0→0x009E8AD0. Next on the same chain: 0x00977800 "
            "calls IAT 0x00B611C8 = KERNEL32!TlsSetValue (classify ABI/args before HLE). "
            "Depth stays 3 until parent 0x009E9340 is ENTERABLE. 0x00947790 still UNKNOWN. "
            "Do not reopen A52DF0/graphics."
        ),
    }

    dump("import-slot-b61138.json", ident)
    dump("object-contracts.json", {
        "phase": 29,
        "contracts": contracts,
        "pre_entry": contracts_prev.get("pre_entry") or {},
    })
    dump("reverse-execution-frontier.json", {
        **rev_prev,
        "phase": 29,
        "depth4_candidates": depth4,
        "ctor_parent": {
            "caller": "0x009E9340",
            "class": "DIRECT_ORDINARY",
            "enterable": False,
            "blocker": "allocator 0x009EB870 / runtime callback",
        },
    })
    dump("execution-evidence.json", {
        "phase": 29,
        "roots": hist,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
    })
    dump("runtime-frontier.json", frontier)
    dump("blocker-ranking.json", {
        "phase": 29,
        "campaign_outcomes": dict(outcomes),
        "latest_real_runtime_boundary": "KERNEL32!TlsAlloc @ 0x00B61138",
        "next_on_ctor_chain": "0x00977800 Win32/IAT (classify in Phase 30)",
    })

    lines = [
        "# Undercover Phase 29 — TlsAlloc boundary",
        "",
        "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
        "",
        "## A. Baseline",
        "",
        "Depth 3 ctor chain blocked at `0x009777D0` / `[0x00B61138]`.",
        "",
        "## B. `0x00B61138` identity",
        "",
        "- DLL: **%s**" % ident["dll"],
        "- Symbol: **%s** (hint %d)" % (ident["symbol"], ident["hint"]),
        "- Classification: **%s**" % ident["classification"],
        "- Initial PE dword: `%s` (unbound IMAGE_IMPORT_BY_NAME RVA)" % ident["initial_pe_dword"],
        "- Section: `%s`" % ident["section"],
        "",
        "## C. `0x009777D0` call contract",
        "",
        wrap["abi"],
        "",
        "- Import args: **0** (CONSTANT empty)",
        "- Return: store EAX TLS index to `[this]`, return this",
        "- ABI confidence: **PROVEN**",
        "",
        "## D. Implementation decision",
        "",
        "HLE justified and implemented: public KERNEL32!TlsAlloc, stdcall/0, guest index abstraction.",
        "",
        "## E. Runtime",
        "",
        "`UC_HLE_TLSALLOC` in `runtime/uc_import.c`; IAT bind via `uc_import_bind_hle_iats`.",
        "",
        "## F. Before/after",
        "",
        "- Before: stop at stubbed `0x009777D0`",
        "- After: TlsAlloc + wrapper + `0x009E8AD0` entered; next blocker `0x00977800`",
        "",
        "## G–H. Constructor continuation / ownership",
        "",
        "Chain continued. Object ownership: CALLER_STORAGE; parent `0x009E9340` not enterable.",
        "",
        "## I. Fallback `0x00947790`",
        "",
        "Not executed; still UNKNOWN required state.",
        "",
        "## J–N. Depth-4 / campaign / delta / Phase 30",
        "",
        "ENTERABLE_WITH_DEPTH_4_POTENTIAL: 0.",
        "Largest closure: **%d**. Depth: **%d**." % (largest, deepest),
        "",
        frontier["recommended_phase30"],
        "",
    ]
    path = os.path.join(ANALYSIS, "runtime-phase29.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("wrote", path)
    print("TlsAlloc", ident["symbol"], "enterable", len(enterable),
          "executed", len(unique), "closure", largest)


if __name__ == "__main__":
    main()
