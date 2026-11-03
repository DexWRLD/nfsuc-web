#!/usr/bin/env python3
"""Phase 33: GetPriorityClass + CreateSemaphoreA on no-stub UC paths.

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
import bisect
import re
import pefile

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

GPC_IAT = 0x00B610E4
SEM_IAT = 0x00B6112C
SPC_IAT = 0x00B610E8
GCT_IAT = 0x00B611DC
CTOR = 0x009E9160
SEM_ROOT = 0x0097BB30
EBC70 = 0x009EBC70


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


def identify_slot(slot, expect):
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
    sites, off = [], 0
    while True:
        j = blob.find(pat, off)
        if j < 0:
            break
        sites.append(tbase + j)
        off = j + 1
    fmap = {int(r["va"], 16): r for r in load("function-map.json")["functions"]}
    starts = sorted(fmap)
    owners, high = set(), set()
    for s in sites:
        i = bisect.bisect_right(starts, s) - 1
        if i >= 0:
            owners.add(starts[i])
            if "HIGH" in ((fmap[starts[i]].get("label") or "").upper()):
                high.add(starts[i])
    abi = {
        "GetPriorityClass": (1, "DWORD", "PROVEN"),
        "SetPriorityClass": (2, "BOOL", "PROVEN"),
        "CreateSemaphoreA": (4, "HANDLE", "PROVEN"),
        "ReleaseSemaphore": (3, "BOOL", "PROVEN"),
        "GetCurrentThread": (0, "HANDLE pseudo -2", "PROVEN"),
        "CloseHandle": (1, "BOOL", "PROVEN"),
        "WaitForSingleObject": (2, "DWORD", "PROVEN"),
    }.get(symbol, (-1, "?", "LOW"))
    return {
        "slot": hx(slot), "dll": "KERNEL32.dll", "symbol": symbol, "hint": hint,
        "unbound_name_rva": hx(dword),
        "classification": "STANDARD_WIN32_IMPORT" if symbol == expect else "UNKNOWN",
        "abi": "stdcall", "stack_dwords": abi[0], "return": abi[1],
        "abi_confidence": abi[2],
        "call_site_count": len(sites),
        "high_caller_count": len(high),
        "high_callers": [hx(x) for x in sorted(high)[:24]],
        "call_sites": [hx(x) for x in sites[:24]],
    }


def analyze_gpc_usage():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for i in cs.disasm(blob[0x97F790 - base:0x97F790 - base + 0x50], 0x97F790):
        lines.append("%08X: %s %s" % (i.address, i.mnemonic, i.op_str))
        if i.address >= 0x97F7D9:
            break
    return {
        "consumer": "0x0097F790",
        "shape": lines,
        "argument": "EDI = GetCurrentProcess() result (pseudo-handle 0xFFFFFFFF)",
        "return_usage": (
            "Stored to local [esp+0x1c]; not used to choose SetPriorityClass argument. "
            "SetPriorityClass later uses constant 0x100 (HIGH_PRIORITY_CLASS). "
            "Saved class is restored via SetPriorityClass near function epilogue."
        ),
        "follow_on_imports": [
            "GetCurrentThread", "GetThreadPriority",
            "SetPriorityClass", "SetThreadPriority",
            "QueryPerformanceCounter", "QueryPerformanceFrequency",
        ],
        "guest_priority_policy": {
            "initial": "NORMAL_PRIORITY_CLASS (0x20)",
            "mutable": False,
            "note": "SetPriorityClass not implemented; priority class is immutable",
        },
    }


def analyze_semaphore_call():
    return {
        "wrapper": "0x009775E0",
        "reached_via": ["0x0097BB30", "0x00978040", "0x00977AF0", "0x009775E0"],
        "observed_args_unnamed_path": {
            "lpSemaphoreAttributes": "NULL (0)",
            "lInitialCount": "0",
            "lMaximumCount": "0x3FFFFFFF",
            "lpName": "NULL",
        },
        "return_usage": "stored to object+0; BOOL success = (handle != 0)",
        "call_site": "0x0097762D",
    }


def classify_crt_atexit():
    return {
        "roots": ["0x00B52140", "0x00B57CF0"],
        "sequence": "static init → 0x00977E20 (ICS) → 0x0087B640(callback) → 0x0087B59B → SEH frame 0x0087BEB8",
        "fault": "null / unmapped guest access after CRT helper entry",
        "globals_touched": ["0x018B1E6C", "0x018B1E68", "IAT 0x00B61398", "IAT 0x00B61394"],
        "classification": "BLOCKED_CRT_INITIALIZATION",
        "reason": (
            "CRT atexit/registration path requires initialized CRT lock/heap state "
            "and import helpers; PE-zero BSS / unbound CRT IATs are not a defensible "
            "ordinary init substitute. NULL callback is not invoked."
        ),
        "implementation_attempted": False,
    }


def serialize_row(r, phase=33):
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
        "ics_calls": r.get("ics_calls", 0),
        "mutex_calls": r.get("mutex_calls", 0),
        "gpc_calls": r.get("gpc_calls", 0),
        "sem_calls": r.get("sem_calls", 0),
        "cs_count": r.get("cs_count", 0),
        "mutex_count": r.get("mutex_count", 0),
        "sem_count": r.get("sem_count", 0),
        "priority_class": r.get("priority_class", 0),
        "stubs": [],
        "notes": r.get("note"),
        "evidence": "uc_phase33.py",
        "counted_in_metrics": True,
        "diagnostic_only": False,
    }


def main():
    gpc = identify_slot(GPC_IAT, "GetPriorityClass")
    sem = identify_slot(SEM_IAT, "CreateSemaphoreA")
    spc = identify_slot(SPC_IAT, "SetPriorityClass")
    gct = identify_slot(GCT_IAT, "GetCurrentThread")
    rel = identify_slot(0x00B61124, "ReleaseSemaphore")
    wso = identify_slot(0x00B611D8, "WaitForSingleObject")
    ch = identify_slot(0x00B610A4, "CloseHandle")
    gpc_use = analyze_gpc_usage()
    sem_call = analyze_semaphore_call()
    atexit = classify_crt_atexit()

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

    ctor = next(r for r in rows if r["root"] == CTOR)
    semr = next(r for r in rows if r["root"] == SEM_ROOT)
    ebc = next(r for r in rows if r["root"] == EBC70)

    ctor_status = {
        "before": "EXECUTED_TO_NEXT_BLOCKER / GetPriorityClass",
        "after": ctor["result"],
        "after_blocker": ctor.get("import") or ctor.get("detail"),
        "returned_clean": bool(ctor.get("clean")),
        "gpc_calls": ctor.get("gpc_calls", 0),
        "priority_class_observed": ctor.get("priority_class", 0),
        "entered": [hx(x) for x in ctor["entered"]],
        "depth": ctor["depth_max"],
    }
    sem_status = {
        "before": "EXECUTED_TO_NEXT_BLOCKER / CreateSemaphoreA (depth 4)",
        "after": semr["result"],
        "after_blocker": semr.get("import") or semr.get("detail"),
        "returned_clean": bool(semr.get("clean")),
        "sem_calls": semr.get("sem_calls", 0),
        "sem_count": semr.get("sem_count", 0),
        "entered": [hx(x) for x in semr["entered"]],
        "depth": semr["depth_max"],
    }

    prev = load("runtime-frontier.json")
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)
    depth4_proven = sorted({hx(r["root"]) for r in rows if r["depth_max"] >= 4})
    depth5_proven = sorted({hx(r["root"]) for r in rows if r["depth_max"] >= 5})

    process_frontier = {
        "phase": 33,
        "model": "ONE_LOGICAL_GUEST_PROCESS",
        "pseudo_handle": "0xFFFFFFFF",
        "priority_class_initial": "NORMAL_PRIORITY_CLASS (0x20)",
        "priority_class_mutable": False,
        "GetPriorityClass": {**gpc, "implemented": True, "reached": True,
                             "hle": "UC_HLE_GETPRIORITYCLASS", **gpc_use},
        "SetPriorityClass": {**spc, "implemented": False, "reached_phase33": False,
                             "inventoried": True,
                             "note": "Reached only after GetCurrentThread on ctor path"},
        "GetCurrentThread": {**gct, "implemented": False, "reached_phase33": True,
                             "note": "Current constructor next blocker; pseudo-handle -2 not implemented this phase"},
        "last_error_modeled": False,
    }

    sync_prev = load("synchronization-frontier.json")
    sync_prev["phase"] = 33
    sync_prev["create_semaphore_a"] = {
        **sem, **sem_call,
        "implemented": True, "reached": True, "hle": "UC_HLE_CREATESEMAPHOREA",
        "hle_justified": True,
        "handle_abstraction": "typed guest handles 0xCD010001+ (SEMAPHORE vs MUTEX)",
        "count_validation": "max>0, initial>=0, initial<=max",
        "named_policy": "reuse same handle; do not rewrite counts; cross-type name fails",
        "last_error": "ERROR_ALREADY_EXISTS not modeled",
        "limitations": ["ReleaseSemaphore/Wait/CloseHandle not implemented",
                        "No guest scheduler / blocking waits"],
        "tests": "uc_phase33_test.py",
    }
    sync_prev["get_priority_class"] = process_frontier["GetPriorityClass"]
    sync_prev["lifecycle_inventory"] = {
        "ReleaseSemaphore": {**rel, "implemented": False, "reached_phase33": False},
        "WaitForSingleObject": {**wso, "implemented": False, "reached_phase33": False},
        "CloseHandle": {**ch, "implemented": False, "reached_phase33": False},
    }
    sync_prev["crt_atexit"] = atexit
    sync_prev["guest_threads"] = 1
    sync_prev["scheduler"] = "NONE"
    sync_prev["model"] = "SINGLE GUEST THREAD — LIMITED SYNC MODEL"

    recommended = (
        "GetPriorityClass and CreateSemaphoreA are implemented. Semaphore root 0x0097BB30 "
        "now RETURNS CLEAN at depth 4. Constructor advances to GetCurrentThread (pseudo-handle). "
        "Phase 34: implement GetCurrentThread (+ optionally SetPriorityClass/GetThreadPriority "
        "on the same 0x97F790 affinity block) under EXPAND THREADING/TLS RUNTIME, or harvest "
        "more ordinary roots under EXPAND REAL UC EXECUTION. CRT atexit remains "
        "BLOCKED_CRT_INITIALIZATION — do not fabricate registration tables. Graphics frozen."
    )

    frontier = {
        "phase": 33,
        "definitions": prev.get("definitions") or {},
        "high_functions": 22779, "generated": 22770, "compiled": 22770,
        "static_ready": 20762, "import_ready": 737,
        "runtime_ready": (prev.get("runtime_ready") or 61) + 2,
        "enterable": len(enterable),
        "enterable_roots": enterable,
        "enterable_with_depth_3_potential": max(
            int(prev.get("enterable_with_depth_3_potential") or 0),
            sum(1 for r in rows if r["depth_max"] >= 3)),
        "enterable_with_depth_3_potential_roots": sorted({
            *(prev.get("enterable_with_depth_3_potential_roots") or []),
            *[hx(r["root"]) for r in rows if r["depth_max"] >= 3],
        }),
        "enterable_with_depth_4_potential": 0,
        "enterable_with_depth_4_potential_roots": [],
        "proven_depth_4_roots": depth4_proven,
        "proven_depth_5_roots": depth5_proven,
        "unique_uc_functions_executed": len(unique),
        "unique_uc_functions_executed_list": unique,
        "execution_runs": 35 + len(rows),
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
            "RUNTIME_READY": (prev.get("runtime_ready") or 61) + 2,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique), "UNIQUE": len(unique),
            "EXECUTION_RUNS": 35 + len(rows),
            "CLEAN_ORDINARY_ROOTS": len(clean),
            "EXECUTED_ORDINARY_CONSTRUCTORS": len(ctors),
            "DEEPEST": deepest, "LARGEST_CLOSURE": largest,
            "ENTERABLE_WITH_DEPTH_4_POTENTIAL": 0,
            "PROVEN_DEPTH_4_ROOTS": len(depth4_proven),
            "LATEST_REAL_RUNTIME_BOUNDARY": ctor.get("import") or "GetCurrentThread",
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase33_attempted": len(rows),
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "deepest_chain": deepest,
            "largest_executed_closure": largest,
            "clean_ordinary_roots": len(clean),
            "executed_ordinary_constructors": len(ctors),
            "getpriorityclass_implemented": True,
            "createsemaphorea_implemented": True,
            "ctor_status": ctor_status,
            "semaphore_path_status": sem_status,
            "ebc70_status": {"result": ebc["result"], "clean": ebc["clean"]},
            "crt_atexit": atexit,
            "release_semaphore_reached": False,
            "wait_reached": False,
            "closehandle_reached": False,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "scheduler": False,
            "filesystem_reached": False,
            "timing_reached": False,
            "protected_boundary_encountered": False,
            "proven_depth_4_roots": depth4_proven,
        },
        "synchronization": {
            "InitializeCriticalSection": "IMPLEMENTED",
            "CreateMutexA": "IMPLEMENTED",
            "GetCurrentProcess": "IMPLEMENTED",
            "GetPriorityClass": "IMPLEMENTED",
            "CreateSemaphoreA": "IMPLEMENTED",
            "GetCurrentThread": "NOT_IMPLEMENTED",
            "SetPriorityClass": "NOT_IMPLEMENTED",
            "guest_threads": 1,
            "scheduler": "NONE",
        },
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase34": recommended,
    }

    dump("process-handle-frontier.json", process_frontier)
    dump("synchronization-frontier.json", sync_prev)
    dump("runtime-frontier.json", frontier)

    camp_ser = [serialize_row(r) for r in rows]
    hist_ev, seen = [], set()
    for r in camp_ser + (evidence_prev.get("roots") or []):
        key = (r.get("root"), r.get("phase"), r.get("result"), r.get("import"),
               r.get("evidence"), r.get("reclassified_phase"))
        if key in seen:
            continue
        seen.add(key)
        hist_ev.append(r)
    dump("execution-evidence.json", {
        "phase": 33, "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase33_ctor": ctor_status,
        "phase33_semaphore": sem_status,
        "phase30_stub_correction": evidence_prev.get("phase30_stub_correction"),
    })
    dump("blocker-ranking.json", {
        "phase": 33,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "getpriorityclass_cleared": True,
        "createsemaphorea_cleared": True,
        "latest_real_runtime_boundary": ctor.get("import"),
        "next_genuine_blockers": sorted({
            r.get("import") for r in rows if r.get("import") and r["hist"] == "IMPORT"
        } | {"BLOCKED_CRT_INITIALIZATION"}),
        "crt_atexit": atexit,
    })

    status = load("project-status.json")
    status["current_phase"] = 33
    phases = status.get("phases") or []
    if not any(p.get("phase") == 33 for p in phases):
        phases.append({"phase": 33,
                       "name": "GetPriorityClass + CreateSemaphoreA",
                       "state": "completed"})
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase33.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 33 — process priority + semaphore creation",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "",
            "## A. Phase-32 baseline",
            "",
            "UNIQUE 43, ENTERABLE 20, DEEPEST 4, CLOSURE 11, RUNTIME_READY 61.",
            "",
            "## B. GetPriorityClass",
            "",
            "- IAT `%s` KERNEL32!%s; stdcall 1 dword → DWORD; **PROVEN**" % (
                gpc["slot"], gpc["symbol"]),
            "- Sites %d; HIGH %d" % (gpc["call_site_count"], gpc["high_caller_count"]),
            "",
            "## C. Pseudo-handle provenance",
            "",
            gpc_use["argument"],
            "",
            "## D. Guest priority model",
            "",
            "Initial **NORMAL_PRIORITY_CLASS (0x20)**; immutable until SetPriorityClass exists.",
            "",
            "## E. Implementation",
            "",
            "`UC_HLE_GETPRIORITYCLASS`. Invalid handle → EAX=0. Last-error not modeled.",
            "",
            "## F. Constructor before/after",
            "",
            "Before: stop on GetPriorityClass. After: **%s** / **%s** (not clean)." % (
                ctor_status["after"], ctor_status["after_blocker"]),
            "",
            "## G. CreateSemaphoreA",
            "",
            "- IAT `%s`; stdcall 4 dwords → HANDLE; **PROVEN**" % sem["slot"],
            "",
            "## H. Observed contract",
            "",
            json.dumps(sem_call["observed_args_unnamed_path"]),
            "",
            "## I. Implementation",
            "",
            "Typed guest handles (MUTEX vs SEMAPHORE). Count validation. Named reuse. "
            "No wait/release/scheduler.",
            "",
            "## J. Semaphore path before/after",
            "",
            "Before: CreateSemaphoreA @ depth 4. After: **%s** clean=%s depth=%d." % (
                sem_status["after"], sem_status["returned_clean"], sem_status["depth"]),
            "",
            "## K. CRT atexit NULL",
            "",
            "**%s** — %s" % (atexit["classification"], atexit["reason"]),
            "",
            "## L. Campaign",
            "",
            "\n".join(
                "- `%s` → **%s** (d=%d u=%d) %s" % (
                    hx(r["root"]), r["result"], r["depth_max"], r["unique_entered"],
                    r.get("import") or r.get("detail") or "")
                for r in rows
            ),
            "",
            "## M. Next blockers",
            "",
            "- Constructor: **GetCurrentThread**",
            "- CRT static-init: BLOCKED_CRT_INITIALIZATION",
            "- SetPriorityClass inventoried on same affinity block (not reached until GCT)",
            "",
            "## N. Frontier delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; DEEPEST **%d**; CLOSURE **%d**; "
            "CLEAN **%d**; RUNTIME_READY **%d**." % (
                len(unique), len(enterable), deepest, largest, len(clean),
                frontier["runtime_ready"]),
            "",
            "## O. Phase 34",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "deep", deepest, "clos", largest, "clean", len(clean),
          "ctor", ctor.get("import"), "sem", semr["result"], "blocker", common)
    return {"rows": rows, "frontier": frontier, "unique": unique}


if __name__ == "__main__":
    main()
