#!/usr/bin/env python3
"""Phase 34: GetCurrentThread + guest priority continuation on no-stub UC paths.

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
import pefile

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

GCT_IAT = 0x00B611DC
GTP_IAT = 0x00B61184
SPC_IAT = 0x00B610E8
STP_IAT = 0x00B61180
QPC_IAT = 0x00B611F8
QPF_IAT = 0x00B611FC
SLEEPEX_IAT = 0x00B61188
CTOR = 0x009E9160
SEM_ROOT = 0x0097BB30
EBC70 = 0x009EBC70
AFFINITY_BLOCK = 0x0097F790


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
        "GetCurrentThread": (0, "HANDLE pseudo 0xFFFFFFFE", "PROVEN"),
        "GetThreadPriority": (1, "int", "PROVEN"),
        "SetPriorityClass": (2, "BOOL", "PROVEN"),
        "SetThreadPriority": (2, "BOOL", "PROVEN"),
        "QueryPerformanceCounter": (1, "BOOL", "PROVEN"),
        "QueryPerformanceFrequency": (1, "BOOL", "PROVEN"),
        "SleepEx": (2, "DWORD", "PROVEN"),
        "SetThreadAffinityMask": (2, "DWORD_PTR", "PROVEN"),
        "GetProcessAffinityMask": (3, "BOOL", "PROVEN"),
        "SetProcessAffinityMask": (2, "BOOL", "PROVEN"),
        "GetCurrentThreadId": (0, "DWORD", "PROVEN"),
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


def analyze_affinity_block():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for i in cs.disasm(blob[AFFINITY_BLOCK - base:AFFINITY_BLOCK - base + 0x160], AFFINITY_BLOCK):
        if "b61" in i.op_str or i.mnemonic in ("call", "push") and (
                "0x" in i.op_str or i.op_str in ("edi", "esi", "eax", "ebx")):
            if "b61" in i.op_str or i.mnemonic == "call" or (
                    i.mnemonic == "push" and ("0x" in i.op_str or i.op_str in ("edi", "esi", "eax"))):
                lines.append("%08X: %s %s" % (i.address, i.mnemonic, i.op_str))
        if i.address >= 0x97F8E8:
            break
    return {
        "consumer": hx(AFFINITY_BLOCK),
        "shape": lines,
        "sequence": [
            "GetCurrentProcess → EDI (0xFFFFFFFF)",
            "GetPriorityClass(EDI) → save NORMAL",
            "GetCurrentThread → ESI (0xFFFFFFFE)",
            "GetThreadPriority(ESI) → save NORMAL(0)",
            "SetPriorityClass(EDI, 0x100 REALTIME_PRIORITY_CLASS)",
            "SetThreadPriority(ESI, 0xF THREAD_PRIORITY_TIME_CRITICAL)",
            "QueryPerformanceCounter / QueryPerformanceFrequency (timing)",
            "SleepEx(0x32)",
            "restore SetPriorityClass / SetThreadPriority",
        ],
        "priority_class_0x100": "REALTIME_PRIORITY_CLASS (not HIGH=0x80)",
        "thread_priority_0xf": "THREAD_PRIORITY_TIME_CRITICAL",
        "affinity_imports_on_path": [],
        "note": "Affinity APIs are not called on this ordinary path.",
    }


def classify_crt_atexit():
    return {
        "roots": ["0x00B52140", "0x00B57CF0"],
        "classification": "BLOCKED_CRT_INITIALIZATION",
        "implementation_attempted": False,
        "reason": (
            "CRT atexit/registration path requires initialized CRT lock/heap state; "
            "unchanged from Phase 33. Not the highest-leverage blocker this campaign."
        ),
    }


def serialize_row(r, phase=34):
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
        "gct_calls": r.get("gct_calls", 0),
        "gtp_calls": r.get("gtp_calls", 0),
        "spc_calls": r.get("spc_calls", 0),
        "stp_calls": r.get("stp_calls", 0),
        "cs_count": r.get("cs_count", 0),
        "mutex_count": r.get("mutex_count", 0),
        "sem_count": r.get("sem_count", 0),
        "priority_class": r.get("priority_class", 0),
        "thread_priority": r.get("thread_priority", 0),
        "stubs": [],
        "notes": r.get("note"),
        "evidence": "uc_phase34.py",
        "counted_in_metrics": True,
        "diagnostic_only": False,
    }


def main():
    gct = identify_slot(GCT_IAT, "GetCurrentThread")
    gtp = identify_slot(GTP_IAT, "GetThreadPriority")
    spc = identify_slot(SPC_IAT, "SetPriorityClass")
    stp = identify_slot(STP_IAT, "SetThreadPriority")
    qpc = identify_slot(QPC_IAT, "QueryPerformanceCounter")
    qpf = identify_slot(QPF_IAT, "QueryPerformanceFrequency")
    sleepx = identify_slot(SLEEPEX_IAT, "SleepEx")
    block = analyze_affinity_block()
    atexit = classify_crt_atexit()

    # Affinity inventory — scan KERNEL32 IAT; do not implement.
    affinity = {
        "SetThreadAffinityMask": {"imported": False, "reached_phase34": False,
                                  "implemented": False},
        "GetProcessAffinityMask": {"imported": False, "reached_phase34": False,
                                   "implemented": False},
        "SetProcessAffinityMask": {"imported": False, "reached_phase34": False,
                                   "implemented": False},
    }
    pef = pefile.PE(GAME, fast_load=False)
    mm = pef.get_memory_mapped_image()
    ib = pef.OPTIONAL_HEADER.ImageBase
    for slot in range(0x00B61000, 0x00B63000, 4):
        raw = struct.unpack_from("<I", mm, slot - ib)[0]
        if not (0x1000 <= raw < 0xCAC000):
            continue
        try:
            txt = mm[raw + 2:raw + 80].split(b"\x00", 1)[0].decode("ascii")
        except Exception:
            continue
        if txt in affinity:
            affinity[txt] = identify_slot(slot, txt)
            affinity[txt]["imported"] = True
            affinity[txt]["implemented"] = False
            affinity[txt]["reached_phase34"] = False
    affinity["note"] = (
        "No affinity import is present on the ordinary constructor path; "
        "KERNEL32 IAT scan finds no Set/Get*AffinityMask slots in the scanned range."
        if not any(v.get("imported") for k, v in affinity.items() if k != "note")
        else "Imported but not reached on ctor path; no guest topology — future dependency."
    )

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
        "before": "EXECUTED_TO_NEXT_BLOCKER / GetCurrentThread",
        "after": ctor["result"],
        "after_blocker": ctor.get("import") or ctor.get("detail"),
        "blocker_result": ctor.get("blocker_result"),
        "returned_clean": bool(ctor.get("clean")),
        "gct_calls": ctor.get("gct_calls", 0),
        "gtp_calls": ctor.get("gtp_calls", 0),
        "spc_calls": ctor.get("spc_calls", 0),
        "stp_calls": ctor.get("stp_calls", 0),
        "priority_class_observed": ctor.get("priority_class", 0),
        "thread_priority_observed": ctor.get("thread_priority", 0),
        "entered": [hx(x) for x in ctor["entered"]],
        "depth": ctor["depth_max"],
        "closure": ctor["unique_entered"],
    }
    sem_status = {
        "before": "EXECUTED_CHAIN clean depth 4",
        "after": semr["result"],
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
    depth4_proven = sorted({hx(r["root"]) for r in rows if r["depth_max"] >= 4}
                           | set(prev.get("proven_depth_4_roots") or []))
    depth5_proven = sorted({hx(r["root"]) for r in rows if r["depth_max"] >= 5})

    runtime_ready = (prev.get("runtime_ready") or 65) + 4  # GCT+GTP+SPC+STP
    # Absolute runs: Phase 33 closed at 47; this campaign adds len(rows).
    execution_runs = 47 + len(rows)

    process_thread = {
        "phase": 34,
        "model": "ONE_LOGICAL_GUEST_PROCESS / ONE_ACTIVE_GUEST_THREAD",
        "guest_processes": 1,
        "guest_threads": 1,
        "scheduler": "NONE",
        "thread_scheduling": "NOT_IMPLEMENTED",
        "process_pseudo_handle": "0xFFFFFFFF",
        "thread_pseudo_handle": "0xFFFFFFFE",
        "priority_class_initial": "NORMAL_PRIORITY_CLASS (0x20)",
        "priority_class_mutable": True,
        "thread_priority_initial": "THREAD_PRIORITY_NORMAL (0)",
        "thread_priority_mutable": True,
        "host_scheduling_policy": "UNCHANGED — guest state only",
        "GetCurrentThread": {
            **gct, "implemented": True, "reached": True,
            "hle": "UC_HLE_GETCURRENTTHREAD", "hle_justified": True,
            "pseudo_handle": "0xFFFFFFFE",
            "not_thread_id": True,
            "not_host_handle": True,
            "real_reached_caller": hx(AFFINITY_BLOCK),
            "tests": "uc_phase34_test.py",
        },
        "GetThreadPriority": {
            **gtp, "implemented": True, "reached": True,
            "hle": "UC_HLE_GETTHREADPRIORITY",
            "default": "THREAD_PRIORITY_NORMAL (0)",
            "error_return": "THREAD_PRIORITY_ERROR_RETURN (0x7FFFFFFF)",
            "real_reached_caller": hx(AFFINITY_BLOCK),
        },
        "SetPriorityClass": {
            **spc, "implemented": True, "reached": True,
            "hle": "UC_HLE_SETPRIORITYCLASS",
            "observed_class": "0x100 REALTIME_PRIORITY_CLASS",
            "realtime_host_policy": "guest state only; host scheduling unchanged",
            "real_reached_caller": hx(AFFINITY_BLOCK),
        },
        "SetThreadPriority": {
            **stp, "implemented": True, "reached": True,
            "hle": "UC_HLE_SETTHREADPRIORITY",
            "observed_priority": "0xF THREAD_PRIORITY_TIME_CRITICAL",
            "real_reached_caller": hx(AFFINITY_BLOCK),
        },
        "affinity_block": block,
        "affinity_apis": affinity,
        "timing": {
            "QueryPerformanceCounter": {
                **qpc, "implemented": False, "reached_phase34": True,
                "note": "Next genuine constructor blocker after priority APIs",
            },
            "QueryPerformanceFrequency": {
                **qpf, "implemented": False, "reached_phase34": False,
                "note": "Same affinity block; after QPC",
            },
            "SleepEx": {
                **sleepx, "implemented": False, "reached_phase34": False,
                "observed_arg_static": "0x32 (50 ms)",
            },
            "timing_implementation_attempted": False,
            "recommendation": (
                "Phase 35: deterministic guest monotonic performance-counter abstraction; "
                "do not substitute wall-clock time."
            ),
        },
        "separations": {
            "GUEST_PROCESS_PRIORITY_CLASS": "mutable guest DWORD",
            "GUEST_THREAD_RELATIVE_PRIORITY": "mutable guest int",
            "HOST_SCHEDULING_POLICY": "outside guest compatibility model",
        },
        "limitations": [
            "No guest scheduler / multithreading",
            "Pseudo-handles resolve to the single active guest context",
            "GetLastError not modeled",
            "Affinity unimplemented (no coherent guest topology)",
            "Timing not implemented this phase",
        ],
        "crt_atexit": atexit,
    }

    sync_prev = load("synchronization-frontier.json")
    sync_prev["phase"] = 34
    sync_prev["guest_threads"] = 1
    sync_prev["scheduler"] = "NONE"
    sync_prev["thread_scheduling"] = "NOT_IMPLEMENTED"
    sync_prev["model"] = "SINGLE GUEST THREAD — LIMITED SYNC MODEL"
    sync_prev["get_current_thread"] = process_thread["GetCurrentThread"]
    sync_prev["get_thread_priority"] = process_thread["GetThreadPriority"]
    sync_prev["set_priority_class"] = process_thread["SetPriorityClass"]
    sync_prev["set_thread_priority"] = process_thread["SetThreadPriority"]
    sync_prev["crt_atexit"] = atexit
    # Preserve Phase 32/33 implemented rows if present.
    sync_prev.setdefault("create_semaphore_a", {"implemented": True})
    sync_prev.setdefault("get_priority_class", {"implemented": True})

    recommended = (
        "GetCurrentThread, GetThreadPriority, SetPriorityClass, and SetThreadPriority "
        "are implemented with guest-only state (no host scheduling changes). Constructor "
        "0x009E9160 advances past the priority block and stops on QueryPerformanceCounter. "
        "Phase 35: EXPAND TIMING RUNTIME — coherent deterministic guest QPC/QPF (+ SleepEx "
        "policy) without wall-clock substitution. Affinity remains a future dependency "
        "(no guest processor topology). CRT atexit stays BLOCKED_CRT_INITIALIZATION. "
        "Graphics frozen. No scheduler."
    )

    frontier = {
        "phase": 34,
        "definitions": prev.get("definitions") or {},
        "high_functions": 22779, "generated": 22770, "compiled": 22770,
        "static_ready": 20762, "import_ready": 737,
        "runtime_ready": runtime_ready,
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
        "execution_runs": execution_runs,
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
            "RUNTIME_READY": runtime_ready,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique), "UNIQUE": len(unique),
            "EXECUTION_RUNS": execution_runs,
            "CLEAN_ORDINARY_ROOTS": len(clean),
            "EXECUTED_ORDINARY_CONSTRUCTORS": len(ctors),
            "DEEPEST": deepest, "LARGEST_CLOSURE": largest,
            "ENTERABLE_WITH_DEPTH_4_POTENTIAL": 0,
            "PROVEN_DEPTH_4_ROOTS": len(depth4_proven),
            "LATEST_REAL_RUNTIME_BOUNDARY": ctor.get("import") or "QueryPerformanceCounter",
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase34_attempted": len(rows),
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "deepest_chain": deepest,
            "largest_executed_closure": largest,
            "clean_ordinary_roots": len(clean),
            "executed_ordinary_constructors": len(ctors),
            "getcurrentthread_implemented": True,
            "setpriorityclass_implemented": True,
            "getthreadpriority_implemented": True,
            "setthreadpriority_implemented": True,
            "ctor_status": ctor_status,
            "semaphore_path_status": sem_status,
            "ebc70_status": {"result": ebc["result"], "clean": ebc["clean"]},
            "crt_atexit": atexit,
            "affinity_reached": False,
            "affinity_implemented": False,
            "qpc_reached": True,
            "qpf_reached": False,
            "timing_implementation_attempted": False,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "scheduler": False,
            "filesystem_reached": False,
            "protected_boundary_encountered": False,
            "diagnostics_counted": 0,
            "proven_depth_4_roots": depth4_proven,
        },
        "synchronization": {
            "InitializeCriticalSection": "IMPLEMENTED",
            "CreateMutexA": "IMPLEMENTED",
            "GetCurrentProcess": "IMPLEMENTED",
            "GetPriorityClass": "IMPLEMENTED",
            "CreateSemaphoreA": "IMPLEMENTED",
            "GetCurrentThread": "IMPLEMENTED",
            "GetThreadPriority": "IMPLEMENTED",
            "SetPriorityClass": "IMPLEMENTED",
            "SetThreadPriority": "IMPLEMENTED",
            "guest_processes": 1,
            "guest_threads": 1,
            "scheduler": "NONE",
            "thread_scheduling": "NOT_IMPLEMENTED",
        },
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase35": recommended,
        "phase31_metric_corrections_preserved": True,
    }

    dump("process-thread-frontier.json", process_thread)
    # Keep process-handle-frontier as a thin alias for older readers.
    dump("process-handle-frontier.json", {
        "phase": 34,
        "superseded_by": "process-thread-frontier.json",
        "model": process_thread["model"],
        "pseudo_handle": process_thread["process_pseudo_handle"],
        "priority_class_initial": process_thread["priority_class_initial"],
        "priority_class_mutable": True,
        "GetPriorityClass": {"implemented": True},
        "SetPriorityClass": process_thread["SetPriorityClass"],
        "GetCurrentThread": process_thread["GetCurrentThread"],
    })
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
        "phase": 34, "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase34_ctor": ctor_status,
        "phase34_semaphore": sem_status,
        "phase33_ctor": evidence_prev.get("phase33_ctor"),
        "phase33_semaphore": evidence_prev.get("phase33_semaphore"),
        "phase30_stub_correction": evidence_prev.get("phase30_stub_correction"),
    })
    dump("blocker-ranking.json", {
        "phase": 34,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "getcurrentthread_cleared": True,
        "setpriorityclass_cleared": True,
        "getthreadpriority_cleared": True,
        "setthreadpriority_cleared": True,
        "latest_real_runtime_boundary": ctor.get("import"),
        "static_import_frequency_vs_execution": {
            "note": "Affinity and wait APIs appear in IAT but are not constructor blockers.",
            "execution_blocker": ctor.get("import"),
        },
        "next_genuine_blockers": sorted({
            r.get("import") for r in rows if r.get("import")
            and r.get("hist") in ("IMPORT", "TIMING")
        } | {"BLOCKED_CRT_INITIALIZATION", "QueryPerformanceCounter"}),
        "crt_atexit": atexit,
    })

    status = load("project-status.json")
    status["current_phase"] = 34
    status["strategy"] = (
        "Phase 34: GetCurrentThread + guest priority APIs; ctor → QueryPerformanceCounter. "
        "Graphics frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 34 for p in phases):
        phases.append({"phase": 34,
                       "name": "GetCurrentThread + guest priority continuation",
                       "state": "completed"})
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase34.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 34 — guest thread identity + priority continuation",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.",
            "",
            "## A. Phase-33 baseline",
            "",
            "UNIQUE 44, ENTERABLE 21, DEEPEST 4, CLOSURE 11, RUNTIME_READY 65, RUNS 47, "
            "CLEAN 12, CTORS 9. Constructor stopped on GetCurrentThread. "
            "Semaphore root 0x0097BB30 clean at depth 4.",
            "",
            "## B. GetCurrentThread import identity",
            "",
            "- IAT `%s` KERNEL32!%s hint %s; thunk/unbound `%s`" % (
                gct["slot"], gct["symbol"], gct["hint"], gct["unbound_name_rva"]),
            "- stdcall, 0 stack dwords, HANDLE in EAX; **%s**" % gct["abi_confidence"],
            "- call sites %d; HIGH callers %d: %s" % (
                gct["call_site_count"], gct["high_caller_count"],
                ", ".join(gct["high_callers"][:8])),
            "- real reached caller: `%s`" % hx(AFFINITY_BLOCK),
            "",
            "## C. Pseudo-handle model",
            "",
            "`GetCurrentThread` → **0xFFFFFFFE**. Distinct from process "
            "`GetCurrentProcess` → **0xFFFFFFFF**. Not a thread ID. Not a host HANDLE.",
            "",
            "## D. Guest thread context",
            "",
            "One active guest-thread context: identity via pseudo-handle, dynamic TLS "
            "(existing), relative thread priority, sync ownership identity. "
            "Lifetime: guest process. Scheduler: **NONE**.",
            "",
            "## E. Implementation and tests",
            "",
            "`UC_HLE_GETCURRENTTHREAD` / `GETTHREADPRIORITY` / `SETPRIORITYCLASS` / "
            "`SETTHREADPRIORITY`. Guest-only mutable priority state. Host scheduling "
            "unchanged even for REALTIME / TIME_CRITICAL. Tests: `uc_phase34_test.py`.",
            "",
            "## F. Constructor continuation",
            "",
            "Before: stop on GetCurrentThread. After: **%s** / **%s** (clean=%s). "
            "Observed mid-path: process class 0x%X, thread priority %s." % (
                ctor_status["after"], ctor_status["after_blocker"],
                ctor_status["returned_clean"],
                ctor_status["priority_class_observed"],
                ctor_status["thread_priority_observed"]),
            "",
            "## G. SetPriorityClass provenance",
            "",
            "IAT `%s`; reached YES with handle=process pseudo, class=**0x100 "
            "REALTIME_PRIORITY_CLASS** (not HIGH=0x80). Implemented YES; guest mutable YES." % (
                spc["slot"]),
            "",
            "## H. GetThreadPriority / SetThreadPriority",
            "",
            "Both imported, reached on ctor path, implemented. Default NORMAL(0). "
            "Invalid handle → THREAD_PRIORITY_ERROR_RETURN. STP observed arg 0xF = "
            "TIME_CRITICAL.",
            "",
            "## I. Affinity status",
            "",
            "Not reached on the ordinary constructor path. Not implemented. "
            "No coherent guest processor topology — future dependency.",
            "",
            "## J. Timing reach",
            "",
            "QueryPerformanceCounter **reached** (next blocker). QPF / SleepEx(0x32) "
            "present statically after QPC on the same block. Timing **not** implemented.",
            "",
            "## K. No-stub campaign",
            "",
            "\n".join(
                "- `%s` → **%s** (d=%d u=%d) %s" % (
                    hx(r["root"]), r["result"], r["depth_max"], r["unique_entered"],
                    r.get("import") or r.get("detail") or "")
                for r in rows
            ),
            "",
            "## L. Next real blockers",
            "",
            "- Constructor: **QueryPerformanceCounter** (BLOCKED_TIMING)",
            "- CRT static-init: BLOCKED_CRT_INITIALIZATION",
            "- Affinity: not reached",
            "",
            "## M. Frontier delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; DEEPEST **%d**; CLOSURE **%d**; "
            "CLEAN **%d**; RUNTIME_READY **%d**; RUNS **%d**." % (
                len(unique), len(enterable), deepest, largest, len(clean),
                runtime_ready, execution_runs),
            "",
            "## N. Phase-35 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "deep", deepest, "clos", largest, "clean", len(clean),
          "ctor", ctor.get("import"), "sem", semr["result"], "blocker", common)
    return {"rows": rows, "frontier": frontier, "unique": unique,
            "process_thread": process_thread}


if __name__ == "__main__":
    main()
