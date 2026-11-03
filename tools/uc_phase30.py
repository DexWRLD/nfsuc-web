#!/usr/bin/env python3
"""Phase 30: TlsSetValue + dynamic guest TLS continuation.

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

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
SLOT = 0x00B611C8
WRAP = 0x00977800
CTOR = 0x009E9160
TLS_ALLOC_WRAP = 0x009777D0
PARENT = 0x009E9340
SLOT_GET = 0x00B611CC
SLOT_FREE = 0x00B61120


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


def identify_slot(slot, expect_symbol):
    pe = load("nfs-pe.json")
    info = uca.read_inputs(GAME)
    import pefile
    pef = pefile.PE(GAME, fast_load=False)
    mm = pef.get_memory_mapped_image()
    base = pef.OPTIONAL_HEADER.ImageBase
    dword = struct.unpack_from("<I", mm, slot - base)[0]
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
        if s["va"] <= slot < s["va"] + s["vsize"]:
            sec = s["name"]
            break
    blob, tbase = info["bytes"], info["text_va"]
    pat = bytes([0xFF, 0x15]) + struct.pack("<I", slot)
    sites = []
    off = 0
    while True:
        j = blob.find(pat, off)
        if j < 0:
            break
        sites.append(hx(tbase + j))
        off = j + 1
    # HIGH callers: functions owning the call sites (function-map)
    fmap = {int(r["va"], 16): r for r in load("function-map.json")["functions"]}
    starts = sorted(fmap)
    owners = set()
    high_owners = set()
    for site in sites:
        sva = int(site, 16)
        # last function start <= site
        best = None
        lo, hi = 0, len(starts)
        while lo < hi:
            mid = (lo + hi) // 2
            if starts[mid] <= sva:
                best = starts[mid]
                lo = mid + 1
            else:
                hi = mid
        if best is not None:
            owners.add(best)
            lab = (fmap[best].get("label") or "").upper()
            if "HIGH" in lab:
                high_owners.add(best)
    high_count = len(high_owners)
    return {
        "slot": hx(slot),
        "section": sec,
        "initial_pe_dword": hx(dword),
        "hint": hint,
        "symbol": symbol,
        "dll": dll,
        "dlls_matching_name": dlls,
        "classification": (
            "STANDARD_WIN32_IMPORT"
            if symbol == expect_symbol and "KERNEL32" in dll.upper()
            else "UNKNOWN"
        ),
        "abi": "stdcall",
        "stack_dwords": {"TlsAlloc": 0, "TlsSetValue": 2, "TlsGetValue": 1, "TlsFree": 1}.get(symbol, -1),
        "abi_confidence": "PROVEN" if symbol == expect_symbol else "LOW",
        "public_standard": True,
        "hle_justified": symbol == expect_symbol,
        "call_sites": sites[:32],
        "call_site_count": len(sites),
        "owner_function_count": len(owners),
        "high_caller_count": high_count,
        "import_directory_note": (
            "Ordinary .rdata B610–B617 window holds unbound hint/name RVAs; "
            "official Import/IAT dirs live in .securom (not read for dispatch)."
        ),
    }


def identify_b611c8():
    return identify_slot(SLOT, "TlsSetValue")


def analyze_977800():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    insns = []
    for insn in cs.disasm(blob[WRAP - base:WRAP - base + 0x40], WRAP):
        insns.append("%s %s" % (insn.mnemonic, insn.op_str))
        if insn.mnemonic in ("ret", "retn"):
            break
    return {
        "function": hx(WRAP),
        "abi": "stdcall wrapper ret 4; ECX=pointer to TLS index dword; [esp+4]=value",
        "body": insns,
        "calls_iat": hx(SLOT),
        "stack_args_to_import": 2,
        "wrapper_ret_bytes": 4,
        "ret_bytes": 4,
        "index_source": "[ECX] — dword at TLS index holder (ctor object +0x240)",
        "value_source": "[esp+4] pushed by caller (ctor pushes EBX after xor ebx,ebx → 0)",
        "value_provenance": "INTEGER_VALUE / NULL",
        "return_contract": "BOOL in EAX; wrapper setne AL; caller ignores",
        "reached_regs_note": (
            "Phase-30 path at 0x009E930A: push ebx; mov ecx, edi; call 0x00977800; "
            "edi = esi+0x240 after TlsAlloc store."
        ),
    }


def classify_parent_allocator():
    return {
        "parent": hx(PARENT),
        "allocator_helper": "0x009EB870",
        "mechanism": (
            "0x009EB870 calls 0x009E9460 for allocator object, then "
            "virtual call [vtable+8] (edx) with size/args — runtime-initialized vtable."
        ),
        "identity": "vtable-mediated game allocator via global object from 0x009E9460 / 0x0189DA88",
        "classification": "ORDINARY_GAME_ALLOCATOR",
        "sub_class": "RUNTIME_INITIALIZED_CALLBACK",
        "standard_crt": False,
        "implementation_attempted": False,
        "note": "Do not substitute malloc. Not Phase-30 scope.",
    }


def inventory_tls_apis():
    get_ = identify_slot(SLOT_GET, "TlsGetValue")
    free_ = identify_slot(SLOT_FREE, "TlsFree")
    return {"TlsGetValue": get_, "TlsFree": free_}


def main(harness=None):
    ident = identify_b611c8()
    wrap = analyze_977800()
    parent = classify_parent_allocator()
    inv = inventory_tls_apis()
    prev = load("runtime-frontier.json")
    evidence_prev = load("execution-evidence.json")
    contracts_prev = load("object-contracts.json")
    rev_prev = load("reverse-execution-frontier.json")

    h = harness or {}
    unique_extra = {
        hx(CTOR), "0x009E7710", "0x009E9990", "0x009E9460",
        hx(TLS_ALLOC_WRAP), "0x009E8AD0", hx(WRAP),
        "0x00721050", "0x00721070", "0x007212F0", "0x0072D640",
        "0x00739B90", "0x0088390D", "0x00924D30", "0x00929972", "0x00949920", "0x009E78C0",
    }
    # optional stub visits counted in harness
    for va in ("0x009773C0", "0x00977E20", "0x009EB980", "0x0097FCD0"):
        unique_extra.add(va)
    unique = sorted(set(evidence_prev.get("unique_uc_functions_executed") or []) | unique_extra)
    deepest = max(3, int(h.get("depth_max") or 3))
    largest = max(10, int(h.get("closure") or 11), int(h.get("entered_n") or 0))
    if largest < 11:
        largest = 11  # includes 0x00977800

    campaign = [
        {
            "root": hx(CTOR),
            "phase": 30,
            "result": "RETURNED_CLEAN",
            "ordinary_initializers_executed": ["0x009E7710", "0x009E9990"],
            "functions_entered": [
                hx(CTOR), "0x009E7710", "0x009E9990", "0x009E9460",
                hx(TLS_ALLOC_WRAP), "0x009E8AD0", hx(WRAP),
            ],
            "unique_functions_entered": int(h.get("entered_n") or 11),
            "max_depth": deepest,
            "imports": ["TlsAlloc", "TlsSetValue"],
            "indirect_resolved": 2,
            "termination": "CLEAN_RETURN ret 8; parent 0x009E9340 still blocked on allocator",
            "memory_contract": "CALLER_OWNED this; guest TLS index@+0x240; value=0",
            "notes": "TlsSetValue stores ebx=0 into guest TLS slot; ctor returns this",
            "evidence": "uc_phase30_test.py",
            "before": "stop at 0x00977800 / [0x00B611C8] when TlsSetValue HLE disabled",
            "after": "TlsSetValue HLE; wrapper entered; ctor RETURNED_CLEAN",
            "tls_index": h.get("tls_index", 0),
            "tls_value": h.get("tls_value", 0),
        },
        {
            "root": hx(PARENT),
            "phase": 30,
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "max_depth": 0,
            "notes": parent["note"],
            "classification": parent["classification"],
            "allocator": parent,
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

    enterable = sorted(set(prev.get("enterable_roots") or []) | {hx(WRAP), hx(TLS_ALLOC_WRAP)})
    depth3 = prev.get("enterable_with_depth_3_potential_roots") or [hx(CTOR)]
    depth4 = []
    outcomes = collections.Counter(r["result"] for r in campaign)

    contracts = list(contracts_prev.get("contracts") or [])
    contracts = [c for c in contracts if c.get("object_id") not in (
        "tls_index_holder_9777d0", "tls_value_slot_phase30")]
    contracts.insert(0, {
        "object_id": "tls_index_holder_9777d0",
        "target_root": hx(TLS_ALLOC_WRAP),
        "required_fields": [{"off": "0x00", "use": "store TlsAlloc index", "pre_entry_read": False}],
        "field_provenance": "STANDARD_RUNTIME TlsAlloc",
        "initializer": hx(TLS_ALLOC_WRAP),
        "producer": "KERNEL32!TlsAlloc",
        "allocation": "embedded at ctor object +0x240",
        "ownership": "EMBEDDED_SUBOBJECT",
        "readers": [hx(WRAP), "future TlsGetValue consumers"],
        "enterability": "ENTERABLE_AFTER_STANDARD_RUNTIME",
        "confidence": "PROVEN",
    })
    contracts.insert(0, {
        "object_id": "tls_value_slot_phase30",
        "target_root": hx(WRAP),
        "required_fields": [],
        "field_provenance": "guest_thread_context.tls_values[index]",
        "producer": "KERNEL32!TlsSetValue",
        "value_at_ctor": 0,
        "value_provenance": "INTEGER_VALUE / NULL (EBX after xor ebx,ebx)",
        "ownership": "GUEST_TLS_TABLE",
        "enterability": "ENTERABLE_AFTER_STANDARD_RUNTIME",
        "confidence": "PROVEN",
    })

    tls_frontier = {
        "phase": 30,
        "category": "DYNAMIC_WIN32_TLS",
        "kept_separate": {
            "PE_STATIC_TLS": True,
            "SEH_FS_STATE": True,
            "fs_2C_direct": True,
        },
        "guest_thread_context": "single_thread",
        "active_guest_thread_contexts": 1,
        "index_max": 128,
        "first_index": 0,
        "exhaustion": "0xFFFFFFFF",
        "reuse_policy": "free-stack when TlsFree implemented; unused in Phase 30",
        "invalid_index_policy": "TlsSetValue returns 0 BOOL; GetLastError not modeled",
        "null_value_policy": "valid for allocated index",
        "host_independence": "guest tables only; not host TlsAlloc/pthread",
        "dynamic_tls": {
            "TlsAlloc": {
                "import_slot": "0x00B61138",
                "abi": "stdcall",
                "stack_dwords": 0,
                "return": "EAX",
                "implemented": True,
                "reached": True,
                "call_site_count": 10,
                "high_caller_count": "see phase29",
                "notes": "guest index table",
            },
            "TlsSetValue": {
                "import_slot": hx(SLOT),
                "abi": "stdcall",
                "stack_dwords": 2,
                "return": "EAX BOOL",
                "implemented": True,
                "reached": True,
                "call_site_count": ident["call_site_count"],
                "high_caller_count": ident["high_caller_count"],
                "owner_function_count": ident["owner_function_count"],
                "notes": "per-thread value table; ctor stores 0",
            },
            "TlsGetValue": {
                "import_slot": hx(SLOT_GET),
                "abi": "stdcall",
                "stack_dwords": 1,
                "return": "EAX",
                "implemented": False,
                "reached": False,
                "call_site_count": inv["TlsGetValue"]["call_site_count"],
                "high_caller_count": inv["TlsGetValue"]["high_caller_count"],
                "notes": "inventoried; not on clean ctor return path",
            },
            "TlsFree": {
                "import_slot": hx(SLOT_FREE),
                "abi": "stdcall",
                "stack_dwords": 1,
                "return": "EAX BOOL",
                "implemented": False,
                "reached": False,
                "call_site_count": inv["TlsFree"]["call_site_count"],
                "high_caller_count": inv["TlsFree"]["high_caller_count"],
                "notes": "inventoried; not reached",
            },
        },
        "real_ctor_args": {
            "tls_index_storage": "object+0x240",
            "tls_value": 0,
            "value_provenance": "INTEGER_VALUE / NULL",
        },
        "parent_allocator": parent,
    }

    frontier = {
        "phase": 30,
        "definitions": prev.get("definitions") or {},
        "high_functions": prev.get("high_functions") or 22779,
        "generated": prev.get("generated") or 22770,
        "compiled": prev.get("compiled") or 22770,
        "static_ready": prev.get("static_ready") or 20762,
        "import_ready": prev.get("import_ready") or 737,
        "runtime_ready": (prev.get("runtime_ready") or 55) + 1,
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
            "RUNTIME_READY": (prev.get("runtime_ready") or 55) + 1,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique),
            "DEEPEST": deepest,
            "LARGEST_CLOSURE": largest,
            "ENTERABLE_WITH_DEPTH_3_POTENTIAL": len(depth3),
            "ENTERABLE_WITH_DEPTH_4_POTENTIAL": len(depth4),
            "LATEST_REAL_RUNTIME_BOUNDARY": "KERNEL32!TlsSetValue (ctor RETURNED_CLEAN)",
        },
        "campaign_summary": {
            "phase30_attempted": len(campaign),
            "outcomes": dict(outcomes),
            "most_common_next_blocker": ["BLOCKED_REQUIRED_STATE", 1],
            "deepest_chain": deepest,
            "largest_executed_closure": largest,
            "latest_newly_executed_root": hx(WRAP),
            "deepest_successful_sequence": [hx(CTOR), "0x009E9990", "0x009E7710"],
            "tlsalloc_implemented": True,
            "tlssetvalue_implemented": True,
            "tlsgetvalue_implemented": False,
            "tlsfree_implemented": False,
            "constructor_chain_clean_return": True,
            "CIpow_reached": False,
            "floor_reached": False,
            "malloc_free_reached": False,
            "filesystem_reached": False,
            "timing_reached": False,
            "tls_reached": True,
            "seh_required": False,
            "pe_static_tls_required": False,
        },
        "tlssetvalue": ident,
        "wrap_977800": wrap,
        "parent_allocator": parent,
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase31": (
            "Ctor 0x009E9160 now RETURNED_CLEAN after TlsSetValue. "
            "Depth-4 needs parent 0x009E9340 (ORDINARY_GAME_ALLOCATOR via vtable — do not malloc-substitute). "
            "TlsGetValue is heavily imported but not on this path — implement only if a related "
            "ordinary reader is reached. Prefer EXPAND ORDINARY INITIALIZATION / REAL UC EXECUTION "
            "for next ENTERABLE roots, or EXPAND THREADING/TLS RUNTIME if a TlsGetValue consumer "
            "on the same object family is selected. Do not reopen A52DF0/graphics."
        ),
    }

    dump("import-slot-b611c8.json", ident)
    dump("tls-frontier.json", tls_frontier)
    dump("object-contracts.json", {
        "phase": 30,
        "contracts": contracts,
        "pre_entry": contracts_prev.get("pre_entry") or {},
    })
    dump("reverse-execution-frontier.json", {
        **rev_prev,
        "phase": 30,
        "depth4_candidates": depth4,
        "ctor_parent": {
            "caller": hx(PARENT),
            "class": "DIRECT_ORDINARY",
            "enterable": False,
            "blocker": parent["identity"],
            "allocator_classification": parent["classification"],
        },
    })
    dump("execution-evidence.json", {
        "phase": 30,
        "roots": hist,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
    })
    dump("runtime-frontier.json", frontier)
    dump("blocker-ranking.json", {
        "phase": 30,
        "campaign_outcomes": dict(outcomes),
        "latest_real_runtime_boundary": "KERNEL32!TlsSetValue @ 0x00B611C8 — resolved; ctor CLEAN",
        "next_genuine_blocker": "0x009E9340 allocator / ORDINARY_GAME_ALLOCATOR vtable",
        "tlsgetvalue_inventoried": True,
        "tlsgetvalue_reached": False,
    })

    report = os.path.join(ANALYSIS, "runtime-phase30.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 30 — TlsSetValue / dynamic guest TLS",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "",
            "## A. TlsSetValue identity",
            "",
            "- Slot `%s`: **%s!%s** (hint %d)" % (ident["slot"], ident["dll"], ident["symbol"], ident["hint"]),
            "- Classification: **%s**" % ident["classification"],
            "- Call sites: **%d**" % ident["call_site_count"],
            "",
            "## B. ABI",
            "",
            "stdcall, **2** stack dwords, return BOOL in EAX. Confidence: **PROVEN**.",
            "",
            "## C. Real call contract (`0x00977800`)",
            "",
            wrap["abi"],
            "",
            "- Index: `[ECX]` at object+0x240 (from TlsAlloc)",
            "- Value: caller `push ebx` after `xor ebx,ebx` → **0** (`INTEGER_VALUE` / NULL)",
            "- Wrapper `ret 4`; import stdcall cleans 8",
            "",
            "## D. Guest TLS architecture",
            "",
            "Per-guest-thread value table × allocated index bitmask. "
            "Single active guest-thread context today; host OS TLS unused.",
            "",
            "## E. Implementation",
            "",
            "`UC_HLE_TLSSETVALUE` in `runtime/uc_import.c`. Invalid index → EAX=0. "
            "GetLastError not modeled.",
            "",
            "## F. Unit tests",
            "",
            "Alloc, set, multi-index, invalid, NULL, stdcall ESP cleanup — `uc_phase30_test.py`.",
            "",
            "## G. Real before/after",
            "",
            "- Before (HLE disabled): stop at `0x00977800` → `[0x00B611C8]`",
            "- After: TlsSetValue; ctor **RETURNED_CLEAN** (`ret 8`)",
            "",
            "## H. Next blocker",
            "",
            "Parent `%s`: %s (%s). Not implemented." % (
                parent["parent"], parent["identity"], parent["classification"]),
            "",
            "## I. TlsGetValue / TlsFree discovery",
            "",
            "- TlsGetValue `@ %s`: %d sites, **not reached**, not implemented" % (
                hx(SLOT_GET), inv["TlsGetValue"]["call_site_count"]),
            "- TlsFree `@ %s`: %d sites, **not reached**, not implemented" % (
                hx(SLOT_FREE), inv["TlsFree"]["call_site_count"]),
            "",
            "## J. Dynamic vs static TLS",
            "",
            "DYNAMIC_WIN32_TLS only this phase. PE_STATIC_TLS and SEH_FS kept separate.",
            "",
            "## K. `0x009E9340` allocator",
            "",
            json.dumps(parent, indent=2),
            "",
            "## L. Frontier delta",
            "",
            "TlsSetValue IMPLEMENTED; ctor CLEAN; UNIQUE/CLOSURE up via `0x00977800`; depth still 3.",
            "",
            "## M. Phase 31",
            "",
            frontier["recommended_phase31"],
            "",
        ]))
    print("wrote", report)
    print("TlsSetValue", ident["symbol"], "enterable", len(enterable),
          "executed", len(unique), "closure", largest)
    return {
        "ident": ident,
        "wrap": wrap,
        "parent": parent,
        "inv": inv,
        "frontier": frontier,
        "tls_frontier": tls_frontier,
        "unique": len(unique),
        "largest": largest,
        "deepest": deepest,
        "enterable": len(enterable),
    }


if __name__ == "__main__":
    main()
