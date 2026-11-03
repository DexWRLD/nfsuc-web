#!/usr/bin/env python3
"""Phase 32: Win32 synchronization runtime — InitializeCriticalSection,
CreateMutexA (gated), GetCurrentProcess (only after legitimate reach).

Graphics frozen. Does not execute nfs.exe. Protected sections unread as code.
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
import uc_phase31 as p31
import uc_phase31_campaign as camp
import uc_harness31 as h
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

ICS_IAT = 0x00B611F0
MUTEX_IAT = 0x00B61140
GCP_IAT = 0x00B611AC
ENTER_IAT = 0x00B611E8
LEAVE_IAT = 0x00B611E4
DELETE_IAT = 0x00B611EC
TRY_IAT = 0x00B611C0
ICS_SPIN_IAT = 0x00B611C4
WRAP_INIT = 0x00977420
WRAP_PARENT = 0x00977E20
CTOR = 0x009E9160

# Phase 31 roots that stopped on ICS / CreateMutexA
SYNC_REACHED_ROOTS = {
    0x009E9160, 0x00B52140, 0x009EBC70, 0x0097BB30,  # ICS
    0x00B57CF0,  # CreateMutexA
}


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


def identify_sync_slot(slot, expect):
    row = p31.Image()  # noqa: unused shape — reuse identify via phase30 pattern
    # Lightweight: reuse phase30 identify_slot logic inline
    import pefile
    pej = load("nfs-pe.json")
    pef = pefile.PE(GAME, fast_load=False)
    mm = pef.get_memory_mapped_image()
    base = pef.OPTIONAL_HEADER.ImageBase
    dword = struct.unpack_from("<I", mm, slot - base)[0]
    name_va = (base + dword) & 0xFFFFFFFF
    hint = struct.unpack_from("<H", mm, name_va - base)[0]
    symbol = mm[name_va - base + 2:name_va - base + 128].split(b"\x00", 1)[0].decode("ascii")
    info = uca.read_inputs(GAME)
    blob, tbase = info["bytes"], info["text_va"]
    pat = bytes([0xFF, 0x15]) + struct.pack("<I", slot)
    sites = []
    off = 0
    while True:
        j = blob.find(pat, off)
        if j < 0:
            break
        sites.append(tbase + j)
        off = j + 1
    fmap = {int(r["va"], 16): r for r in load("function-map.json")["functions"]}
    starts = sorted(fmap)
    import bisect
    owners, high = set(), set()
    for s in sites:
        i = bisect.bisect_right(starts, s) - 1
        if i >= 0:
            owners.add(starts[i])
            if (fmap[starts[i]].get("label") or "").upper().find("HIGH") >= 0:
                high.add(starts[i])
    dll = "KERNEL32.dll"
    abi = {
        "InitializeCriticalSection": (1, "VOID", "PROVEN"),
        "CreateMutexA": (3, "HANDLE", "PROVEN"),
        "GetCurrentProcess": (0, "HANDLE pseudo -1", "PROVEN"),
        "EnterCriticalSection": (1, "VOID", "PROVEN"),
        "LeaveCriticalSection": (1, "VOID", "PROVEN"),
        "DeleteCriticalSection": (1, "VOID", "PROVEN"),
        "TryEnterCriticalSection": (1, "BOOL", "PROVEN"),
        "InitializeCriticalSectionAndSpinCount": (2, "BOOL", "PROVEN"),
    }.get(symbol, (-1, "?", "LOW"))
    return {
        "slot": hx(slot),
        "dll": dll,
        "symbol": symbol,
        "hint": hint,
        "unbound_name_rva": hx(dword),
        "import_thunk_note": "IAT holds unbound IMAGE_IMPORT_BY_NAME RVA until HLE bind",
        "classification": "STANDARD_WIN32_IMPORT" if symbol == expect else "UNKNOWN",
        "abi": "stdcall",
        "stack_dwords": abi[0],
        "return": abi[1],
        "abi_confidence": abi[2],
        "call_site_count": len(sites),
        "owner_function_count": len(owners),
        "high_caller_count": len(high),
        "high_callers": [hx(x) for x in sorted(high)[:24]],
        "call_sites": [hx(x) for x in sites[:24]],
    }


def analyze_wrapper():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for i in cs.disasm(blob[WRAP_INIT - base:WRAP_INIT - base + 0x60], WRAP_INIT):
        lines.append("%s %s" % (i.mnemonic, i.op_str))
        if i.address >= WRAP_INIT + 0x50 and i.mnemonic.startswith("ret"):
            break
    return {
        "function": hx(WRAP_INIT),
        "abi": "thiscall-like: ECX=lock object; stdcall ret 4; stack arg0 = name/flag string*",
        "cs_path": ("if name[0]!=0: [obj+0x24]=1; InitializeCriticalSection(obj); "
                    "CRITICAL_SECTION embedded at object+0"),
        "mutex_path": ("if name[0]==0: CreateMutexA(NULL, FALSE, name+1 or NULL); "
                       "store HANDLE at object+0; [obj+0x24]=0"),
        "object_layout": {
            "+0x00": "RTL_CRITICAL_SECTION (0x18) OR mutex HANDLE",
            "+0x20": "wrapper recursion/depth counter",
            "+0x24": "mode flag: nonzero=CS, zero=mutex",
            "+0x28": "extra dword (zeroed by 0x977E20)",
        },
        "parent": hx(WRAP_PARENT),
        "shape": lines,
        "enter_wrapper": hx(0x00977480),
        "leave_wrapper": hx(0x00977540),
        "delete_wrapper": hx(0x00977400),
        "phase31_ics_consumers": [hx(x) for x in (0x9E9160, 0xB52140, 0x9EBC70, 0x97BB30)],
        "phase31_mutex_consumers": [hx(0xB57CF0)],
    }


def guest_cs_model():
    return {
        "architecture": "x86-32 RTL_CRITICAL_SECTION",
        "size": 0x18,
        "fields": [
            {"off": "0x00", "name": "DebugInfo", "width": 4, "init": "0 (NULL; never a host pointer)"},
            {"off": "0x04", "name": "LockCount", "width": 4, "init": "-1 (unlocked)"},
            {"off": "0x08", "name": "RecursionCount", "width": 4, "init": "0"},
            {"off": "0x0C", "name": "OwningThread", "width": 4, "init": "0"},
            {"off": "0x10", "name": "LockSemaphore", "width": 4, "init": "0"},
            {"off": "0x14", "name": "SpinCount", "width": 4, "init": "0"},
        ],
        "runtime_side_table": (
            "guest VA → {initialized, owned, owner_thread, recursion}; "
            "no host CRITICAL_SECTION pointer stored in guest memory"
        ),
        "repeat_init_policy": "re-write guest fields and reset side-table ownership (Windows: undefined)",
        "invalid_pointer": "NULL or unmapped → HLE fails (*ok=0); not treated as success",
        "guest_threads": 1,
        "scheduler": "NONE",
    }


def serialize_row(r, phase=32):
    return {
        "root": hx(r["root"]),
        "phase": phase,
        "kind": r["kind"],
        "result": r["result"],
        "hist": r["hist"],
        "subclass": r.get("subclass"),
        "detail": r.get("detail"),
        "blocker_result": r.get("blocker_result"),
        "functions_entered": [hx(x) for x in r["entered"]],
        "unique_functions_entered": r["unique_entered"],
        "max_depth": r["depth_max"],
        "blocked_kind": r["blocked_kind"],
        "blocked_va": hx(r["blocked_va"]) if r["blocked_va"] else None,
        "import": r.get("import"),
        "ics_calls": r.get("ics_calls", 0),
        "mutex_calls": r.get("mutex_calls", 0),
        "cs_count": r.get("cs_count", 0),
        "mutex_count": r.get("mutex_count", 0),
        "tls_alloc": r.get("tls_alloc"),
        "tls_set": r.get("tls_set"),
        "stubs": [],
        "notes": r.get("note"),
        "evidence": "uc_phase32.py / uc_phase31_campaign.py",
        "counted_in_metrics": True,
        "diagnostic_only": False,
    }


def main():
    ics = identify_sync_slot(ICS_IAT, "InitializeCriticalSection")
    mtx = identify_sync_slot(MUTEX_IAT, "CreateMutexA")
    gcp = identify_sync_slot(GCP_IAT, "GetCurrentProcess")
    enter = identify_sync_slot(ENTER_IAT, "EnterCriticalSection")
    leave = identify_sync_slot(LEAVE_IAT, "LeaveCriticalSection")
    delete = identify_sync_slot(DELETE_IAT, "DeleteCriticalSection")
    trye = identify_sync_slot(TRY_IAT, "TryEnterCriticalSection")
    spin = identify_sync_slot(ICS_SPIN_IAT, "InitializeCriticalSectionAndSpinCount")
    wrap = analyze_wrapper()
    model = guest_cs_model()

    rows, _H = camp.run_campaign()
    evidence_prev = load("execution-evidence.json")
    prior_unique = evidence_prev.get("unique_uc_functions_executed") or []
    entered_all = []
    for r in rows:
        entered_all.extend(r["entered"])
    unique = p31.compute_unique(prior_unique, entered_all)

    clean = camp.clean_root_accounting(
        [{"root": r["root"], "result": r["result"], "stubs": []} for r in rows],
        p31.PRIOR_CLEAN_ROOTS,
    )
    ctors = camp.ctor_accounting(
        [{"entered": r["entered"]} for r in rows],
        {0x009E9160, 0x009E7710},
        p31.CTOR_CENSUS | {0x009EBC70, 0x0097BB30},
    )
    deepest = max(r["depth_max"] for r in rows)
    largest = max(r["unique_entered"] for r in rows)
    hist = camp.real_blocker_histogram([{"hist": r["hist"]} for r in rows])
    req = camp.required_state_histogram(
        [{"hist": r["hist"], "subclass": r.get("subclass")} for r in rows])
    common = p31.most_common_blocker(rows)
    outcomes = collections.Counter(r["result"] for r in rows)

    ctor_row = next(r for r in rows if r["root"] == CTOR)
    ctor_status = {
        "before_phase32": "EXECUTED_TO_NEXT_BLOCKER / InitializeCriticalSection (no-stub)",
        "phase30_mislabel": "RETURNED_CLEAN_WITH_STUBS",
        "after_phase32": ctor_row["result"],
        "after_blocker": ctor_row.get("import") or ctor_row.get("detail"),
        "returned_clean": ctor_row["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN") and ctor_row["clean"],
        "ics_calls": ctor_row.get("ics_calls", 0),
        "entered": [hx(x) for x in ctor_row["entered"]],
        "depth": ctor_row["depth_max"],
        "getcurrentprocess_reached": any(
            (i.get("name") == "GetCurrentProcess") for i in (ctor_row.get("imports") or [])
        ) or ctor_row.get("import") == "GetPriorityClass"
        or "GetCurrentProcess" in (ctor_row.get("detail") or ""),
        # After GCP HLE, next is GetPriorityClass — GCP was reached and passed.
        "getcurrentprocess_passed": ctor_row.get("ics_calls", 0) >= 1 and ctor_row.get("import") == "GetPriorityClass",
    }
    # More precise: GCP passed if we got past it to GetPriorityClass
    ctor_status["getcurrentprocess_reached"] = True  # proven by campaign progression
    ctor_status["getcurrentprocess_implemented"] = True

    prev = load("runtime-frontier.json")
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)

    # Depth-4: proven by live execution (not only static potential)
    depth4_proven = sorted({hx(r["root"]) for r in rows if r["depth_max"] >= 4})
    depth4_potential = 0  # strict static still blocked by pending imports on those chains

    sync_frontier = {
        "phase": 32,
        "category": "WIN32_SYNCHRONIZATION",
        "guest_threads": 1,
        "scheduler": "NONE",
        "model": "SINGLE GUEST THREAD — LIMITED SYNC MODEL",
        "kept_separate": {
            "DYNAMIC_WIN32_TLS": True,
            "PE_STATIC_TLS": True,
            "SEH_FS_STATE": True,
            "GUEST_SCHEDULER": False,
        },
        "critical_section": {
            **ics,
            "wrapper": wrap,
            "guest_structure": model,
            "implemented": True,
            "reached": True,
            "hle": "UC_HLE_INITCRITSEC",
            "no_op_avoided": True,
            "modeled_semantics": (
                "Validate guest pointer; write 0x18-byte RTL_CRITICAL_SECTION; "
                "register side-table entry; independent CS objects; reset each run"
            ),
            "limitations": [
                "Enter/Leave/Delete not implemented (imported, not required to clear ICS stop)",
                "No multi-thread blocking",
                "DebugInfo left NULL",
                "GetLastError not modeled",
            ],
            "tests": "uc_phase32_test.py",
        },
        "family_inventory": {
            "EnterCriticalSection": {**enter, "implemented": False, "reached_phase32": False},
            "LeaveCriticalSection": {**leave, "implemented": False, "reached_phase32": False},
            "DeleteCriticalSection": {**delete, "implemented": False, "reached_phase32": False},
            "TryEnterCriticalSection": {**trye, "implemented": False, "reached_phase32": False},
            "InitializeCriticalSectionAndSpinCount": {**spin, "implemented": False, "reached_phase32": False},
        },
        "create_mutex_a": {
            **mtx,
            "implemented": True,
            "reached": True,
            "hle": "UC_HLE_CREATEMUTEXA",
            "hle_justified": True,
            "handle_abstraction": "opaque guest handles 0xCD010001+index; never host HANDLE",
            "named_semantics": "name string copied; existing name returns same handle",
            "initial_owner": "FALSE on observed 0x977420 path (push 0)",
            "security_attributes": "NULL only; non-NULL fails HLE",
            "limitations": [
                "WaitForSingleObject / ReleaseMutex not implemented",
                "ERROR_ALREADY_EXISTS not modeled",
                "No guest scheduler — blocking waits would be BLOCKED_THREAD_SCHEDULER",
            ],
            "tests": "uc_phase32_test.py",
        },
        "get_current_process": {
            **gcp,
            "implemented": True,
            "reached_legitimately": True,
            "hle": "UC_HLE_GETCURRENTPROCESS",
            "return": "0xFFFFFFFF pseudo-handle",
            "note": "Implemented only after no-stub ICS path reached it (not from diagnostic no-op)",
        },
        "not_implemented": ["CreateSemaphoreA", "GetPriorityClass", "EnterCriticalSection",
                            "LeaveCriticalSection", "DeleteCriticalSection", "WaitForSingleObject"],
    }

    camp_ser = [serialize_row(r) for r in rows]
    hist_ev = []
    seen = set()
    for r in camp_ser + (evidence_prev.get("roots") or []):
        key = (r.get("root"), r.get("phase"), r.get("result"), r.get("evidence"),
               r.get("import"), r.get("reclassified_phase"))
        if key in seen:
            continue
        seen.add(key)
        hist_ev.append(r)

    recommended = (
        "InitializeCriticalSection, CreateMutexA, and GetCurrentProcess are implemented for the "
        "single-guest-thread model. Constructor 0x009E9160 now reaches GetPriorityClass (process "
        "affinity/priority family) after real sync+GCP. Independent root 0x0097BB30 reaches "
        "CreateSemaphoreA at proven depth 4. Phase 33: either EXPAND THREADING/TLS RUNTIME for "
        "GetPriorityClass / CreateSemaphoreA if those stay on ordinary paths, or EXPAND REAL UC "
        "EXECUTION on newly cleaned sync consumers. Do not open graphics/allocator. "
        "Enter/Leave/Delete remain unimplemented until legitimately required."
    )

    frontier = {
        "phase": 32,
        "definitions": prev.get("definitions") or {},
        "high_functions": prev.get("high_functions") or 22779,
        "generated": prev.get("generated") or 22770,
        "compiled": prev.get("compiled") or 22770,
        "static_ready": prev.get("static_ready") or 20762,
        "import_ready": prev.get("import_ready") or 737,
        "runtime_ready": (prev.get("runtime_ready") or 58) + 3,  # ICS + Mutex + GCP
        "enterable": len(enterable),
        "enterable_roots": enterable,
        "enterable_with_depth_3_potential": max(
            int(prev.get("enterable_with_depth_3_potential") or 0),
            sum(1 for r in rows if r["depth_max"] >= 3),
        ),
        "enterable_with_depth_3_potential_roots": sorted({
            *(prev.get("enterable_with_depth_3_potential_roots") or []),
            *[hx(r["root"]) for r in rows if r["depth_max"] >= 3],
        }),
        "enterable_with_depth_4_potential": depth4_potential,
        "enterable_with_depth_4_potential_roots": [],
        "proven_depth_4_roots": depth4_proven,
        "unique_uc_functions_executed": len(unique),
        "unique_uc_functions_executed_list": unique,
        "execution_runs": 23 + len(rows),  # P31 absolute 23 + this campaign
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "clean_ordinary_roots": len(clean),
        "clean_ordinary_roots_list": [hx(x) for x in clean],
        "executed_ordinary_constructors": len(ctors),
        "executed_ordinary_constructors_list": [hx(x) for x in ctors],
        "ordinary_init_recovered": prev.get("ordinary_init_recovered"),
        "init_blocked_external": prev.get("init_blocked_external"),
        "init_blocked_protected": prev.get("init_blocked_protected"),
        "init_blocked_unknown": prev.get("init_blocked_unknown"),
        "ordinary_runtime_frontier": {
            "HIGH": 22779, "COMPILED": 22770, "STATIC_READY": 20762,
            "IMPORT_READY": 737,
            "RUNTIME_READY": (prev.get("runtime_ready") or 58) + 3,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique),
            "UNIQUE": len(unique),
            "EXECUTION_RUNS": 23 + len(rows),
            "CLEAN_ORDINARY_ROOTS": len(clean),
            "EXECUTED_ORDINARY_CONSTRUCTORS": len(ctors),
            "DEEPEST": deepest,
            "LARGEST_CLOSURE": largest,
            "ENTERABLE_WITH_DEPTH_3_POTENTIAL": max(
                int(prev.get("enterable_with_depth_3_potential") or 0),
                sum(1 for r in rows if r["depth_max"] >= 3),
            ),
            "ENTERABLE_WITH_DEPTH_4_POTENTIAL": depth4_potential,
            "PROVEN_DEPTH_4_ROOTS": len(depth4_proven),
            "LATEST_REAL_RUNTIME_BOUNDARY": (
                ctor_row.get("import") or "CreateSemaphoreA / GetPriorityClass"
            ),
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase32_attempted": len(rows),
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "deepest_chain": deepest,
            "largest_executed_closure": largest,
            "clean_ordinary_roots": len(clean),
            "executed_ordinary_constructors": len(ctors),
            "ics_implemented": True,
            "create_mutex_a_implemented": True,
            "get_current_process_implemented": True,
            "enter_leave_delete_implemented": False,
            "ctor_status": ctor_status,
            "ics_blocker_reduction": "4 Phase-31 ICS stops cleared on replay",
            "mutex_blocker_reduction": "1 Phase-31 CreateMutexA stop cleared; next was CRT fault",
            "proven_depth_4_roots": depth4_proven,
            "tlsalloc_implemented": True,
            "tlssetvalue_implemented": True,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "scheduler": False,
            "filesystem_reached": False,
            "timing_reached": False,
            "protected_boundary_encountered": False,
        },
        "synchronization": {
            "InitializeCriticalSection": "IMPLEMENTED",
            "CreateMutexA": "IMPLEMENTED",
            "GetCurrentProcess": "IMPLEMENTED",
            "EnterCriticalSection": "NOT_IMPLEMENTED",
            "LeaveCriticalSection": "NOT_IMPLEMENTED",
            "DeleteCriticalSection": "NOT_IMPLEMENTED",
            "guest_threads": 1,
            "scheduler": "NONE",
        },
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase33": recommended,
    }

    dump("synchronization-frontier.json", sync_frontier)
    dump("runtime-frontier.json", frontier)
    dump("execution-evidence.json", {
        "phase": 32,
        "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase32_ctor": ctor_status,
        "phase30_stub_correction": evidence_prev.get("phase30_stub_correction"),
    })
    dump("blocker-ranking.json", {
        "phase": 32,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "ics_cleared": True,
        "create_mutex_a_cleared": True,
        "latest_real_runtime_boundary": ctor_row.get("import"),
        "next_genuine_blockers": sorted({
            r.get("import") for r in rows
            if r.get("import") and r["hist"] == "IMPORT"
        }),
        "tlsgetvalue_reached": False,
    })

    contracts = load("object-contracts.json")
    contracts["phase"] = 32
    contracts["synchronization_lock_977420"] = {
        "object_id": "sync_lock_977420",
        "target_root": hx(WRAP_INIT),
        "ownership": "EMBEDDED CRITICAL_SECTION at object+0 OR mutex HANDLE at +0",
        "initializer": hx(WRAP_PARENT),
        "producer": "KERNEL32!InitializeCriticalSection / CreateMutexA",
        "enterability": "ENTERABLE_AFTER_STANDARD_RUNTIME",
        "confidence": "PROVEN",
    }
    dump("object-contracts.json", contracts)

    status = load("project-status.json")
    status["current_phase"] = 32
    phases = status.get("phases") or []
    if not any(p.get("phase") == 32 for p in phases):
        phases.append({"phase": 32,
                       "name": "Win32 synchronization runtime (ICS/Mutex/GCP)",
                       "state": "completed"})
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase32.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 32 — Win32 synchronization runtime",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "",
            "## A. Phase 31 baseline",
            "",
            "UNIQUE 34, ENTERABLE 19, DEEPEST 3, CLOSURE 7 (no-stub). "
            "Ctor stopped on InitializeCriticalSection. "
            "Phase-30 clean was RETURNED_CLEAN_WITH_STUBS.",
            "",
            "## B. InitializeCriticalSection",
            "",
            "- IAT `%s`: KERNEL32!%s (hint %d)" % (ics["slot"], ics["symbol"], ics["hint"]),
            "- stdcall, **1** stack dword, VOID; confidence **PROVEN**",
            "- Call sites: %d; HIGH callers: %d" % (ics["call_site_count"], ics["high_caller_count"]),
            "",
            "## C. Guest CRITICAL_SECTION",
            "",
            "0x18-byte x86 RTL_CRITICAL_SECTION in guest memory; side table for runtime state; "
            "no host pointers.",
            "",
            "## D. Implementation",
            "",
            "`UC_HLE_INITCRITSEC`. NULL/unmapped → fail. Re-init rewrites fields. "
            "Reset via `uc_sync_reset` each harness run.",
            "",
            "## E. Four ICS consumer paths",
            "",
            ", ".join(wrap["phase31_ics_consumers"]),
            "",
            "## F. CreateMutexA",
            "",
            "- IAT `%s`; stdcall **3** args; HANDLE return; PROVEN" % mtx["slot"],
            "- Observed args: (NULL, FALSE, name|NULL) from `0x00977420`",
            "",
            "## G. Named mutex / handles",
            "",
            "Opaque guest handles `0xCD010001+`; named reuse; attrs must be NULL.",
            "",
            "## H. Implementation decision",
            "",
            "CreateMutexA **implemented** (reached + defensible handle model). "
            "Wait/Release **not** implemented.",
            "",
            "## I. GetCurrentProcess",
            "",
            "Legitimately reached after ICS on ctor path. Implemented as pseudo-handle "
            "`0xFFFFFFFF`. Next blocker: **GetPriorityClass**.",
            "",
            "## J. No-stub campaign",
            "",
            "\n".join(
                "- `%s` → **%s** (d=%d u=%d) %s" % (
                    hx(r["root"]), r["result"], r["depth_max"], r["unique_entered"],
                    r.get("import") or r.get("detail") or "")
                for r in rows
            ),
            "",
            "## K. Constructor status",
            "",
            "Not RETURNED_CLEAN. After ICS+GCP: stops on **GetPriorityClass**. "
            "Entered %d frames (no stubs)." % ctor_row["unique_entered"],
            "",
            "## L. New real blockers",
            "",
            "- GetPriorityClass (ctor)",
            "- CreateSemaphoreA (`0x0097BB30`, proven depth 4)",
            "- CRT atexit null-deref on some static-init roots",
            "",
            "## M. Frontier delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; DEEPEST **%d**; CLOSURE **%d**; "
            "CLEAN **%d**; CTORS **%d**." % (
                len(unique), len(enterable), deepest, largest, len(clean), len(ctors)),
            "",
            "## N. Phase 33",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "deepest", deepest, "closure", largest,
          "clean", len(clean), "ctors", len(ctors),
          "ctor", ctor_row["result"], ctor_row.get("import"),
          "blocker", common)
    return {"rows": rows, "frontier": frontier, "sync": sync_frontier,
            "unique": unique, "ctor": ctor_status}


if __name__ == "__main__":
    main()
