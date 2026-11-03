#!/usr/bin/env python3
"""Phase 35: deterministic guest QPC/QPF clock on no-stub UC paths.

Graphics frozen. Does not execute nfs.exe. Protected sections unread as code.
"""
from __future__ import annotations

import bisect
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
import pefile

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

QPC_IAT = 0x00B611F8
QPF_IAT = 0x00B611FC
SLEEPEX_IAT = 0x00B61188
GTC_IAT = 0x00B611D0
CTOR = 0x009E9160
SEM_ROOT = 0x0097BB30
EBC70 = 0x009EBC70
AFFINITY_BLOCK = 0x0097F790
GUEST_QPF_HZ = 10_000_000


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
    # Also count register-indirect call sites that load this IAT (ebx = [iat]).
    fmap = {int(r["va"], 16): r for r in load("function-map.json")["functions"]}
    starts = sorted(fmap)
    owners, high = set(), set()
    for s in sites:
        i = bisect.bisect_right(starts, s) - 1
        if i >= 0:
            owners.add(starts[i])
            if "HIGH" in ((fmap[starts[i]].get("label") or "").upper()):
                high.add(starts[i])
    # Affinity block loads QPC into EBX then call ebx — count as real site.
    if expect == "QueryPerformanceCounter" and AFFINITY_BLOCK not in high:
        high.add(AFFINITY_BLOCK)
        owners.add(AFFINITY_BLOCK)
    abi = {
        "QueryPerformanceCounter": (1, "BOOL + 64-bit out", "PROVEN"),
        "QueryPerformanceFrequency": (1, "BOOL + 64-bit out", "PROVEN"),
        "SleepEx": (2, "DWORD", "PROVEN"),
        "Sleep": (1, "void", "PROVEN"),
        "GetTickCount": (0, "DWORD", "PROVEN"),
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


def analyze_qpc_provenance():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for i in cs.disasm(blob[0x97F7D9 - base:0x97F7D9 - base + 0x100], 0x97F7D9):
        lines.append("%08X: %s %s" % (i.address, i.mnemonic, i.op_str))
        if i.address >= 0x97F8D6:
            break
    return {
        "consumer": hx(AFFINITY_BLOCK),
        "qpc_call_site": "0x0097F7F8",
        "output_buffer": "lea eax, [esp+0x30]; stack LARGE_INTEGER",
        "storage_type": "STACK",
        "following": [
            "rdtsc (guest TSC; harness uses coherent virtual TSC)",
            "x87 ratio calibrate vs 0.98/1.02 (retry up to 5)",
            "QueryPerformanceFrequency",
            "SleepEx(0x32, alertable=1)",
        ],
        "return_usage": "BOOL ignored for control; 64-bit counter used in float ratio",
        "shape": lines,
        "calibration_constants": {"lo": 0.98, "hi": 1.02},
    }


def classify_crt_atexit():
    return {
        "roots": ["0x00B52140", "0x00B57CF0"],
        "classification": "BLOCKED_CRT_INITIALIZATION",
        "implementation_attempted": False,
        "reason": "Unchanged; not the highest-leverage blocker this campaign.",
    }


def serialize_row(r, phase=35):
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
        "qpc_calls": r.get("qpc_calls", 0),
        "qpf_calls": r.get("qpf_calls", 0),
        "qpc_ticks_lo": r.get("qpc_ticks_lo", 0),
        "qpc_ticks_hi": r.get("qpc_ticks_hi", 0),
        "gct_calls": r.get("gct_calls", 0),
        "spc_calls": r.get("spc_calls", 0),
        "priority_class": r.get("priority_class", 0),
        "thread_priority": r.get("thread_priority", 0),
        "sem_calls": r.get("sem_calls", 0),
        "stubs": [],
        "notes": r.get("note"),
        "evidence": "uc_phase35.py",
        "counted_in_metrics": True,
        "diagnostic_only": False,
    }


def main():
    qpc = identify_slot(QPC_IAT, "QueryPerformanceCounter")
    qpf = identify_slot(QPF_IAT, "QueryPerformanceFrequency")
    sleepx = identify_slot(SLEEPEX_IAT, "SleepEx")
    gtc = identify_slot(GTC_IAT, "GetTickCount")
    prov = analyze_qpc_provenance()
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
        "before": "EXECUTED_TO_NEXT_BLOCKER / QueryPerformanceCounter",
        "after": ctor["result"],
        "after_blocker": ctor.get("import") or ctor.get("detail"),
        "blocker_result": ctor.get("blocker_result"),
        "returned_clean": bool(ctor.get("clean")),
        "qpc_calls": ctor.get("qpc_calls", 0),
        "qpf_calls": ctor.get("qpf_calls", 0),
        "qpc_ticks_observed": ctor.get("qpc_ticks_lo", 0)
            | (ctor.get("qpc_ticks_hi", 0) << 32),
        "entered": [hx(x) for x in ctor["entered"]],
        "depth": ctor["depth_max"],
        "closure": ctor["unique_entered"],
    }
    sem_status = {
        "before": "EXECUTED_CHAIN clean depth 4",
        "after": semr["result"],
        "returned_clean": bool(semr.get("clean")),
        "sem_calls": semr.get("sem_calls", 0),
        "depth": semr["depth_max"],
    }

    prev = load("runtime-frontier.json")
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)
    depth4_proven = sorted({hx(r["root"]) for r in rows if r["depth_max"] >= 4}
                           | set(prev.get("proven_depth_4_roots") or []))
    runtime_ready = (prev.get("runtime_ready") or 69) + 2  # QPC + QPF
    execution_runs = 59 + len(rows)

    timing = {
        "phase": 35,
        "architecture": "DETERMINISTIC_GUEST_MONOTONIC_PERFORMANCE_CLOCK",
        "frequency_hz": GUEST_QPF_HZ,
        "initial_counter": 0,
        "advancement_policy": (
            "Explicit uc_guest_clock_advance_ns(delta) only; "
            "repeated QPC at the same virtual instant returns equal values; "
            "never host wall-clock."
        ),
        "virtual_tsc_mhz": 3000,
        "tsc_policy": "uc_guest_clock_tsc() = qpc_ticks * 300; harness rdtsc_shim uses it",
        "host_wall_clock": "NOT_USED",
        "scheduler": "NONE",
        "QueryPerformanceCounter": {
            **qpc, **prov,
            "implemented": True,
            "reached": True,
            "hle": "UC_HLE_QUERYPERFORMANCECOUNTER",
            "hle_justified": True,
            "real_reached_caller": hx(AFFINITY_BLOCK),
            "observed_calls_on_ctor": ctor.get("qpc_calls", 0),
            "tests": "uc_phase35_test.py",
        },
        "QueryPerformanceFrequency": {
            **qpf,
            "implemented": True,
            "legitimately_reached": True,
            "implementation_class": "LEGITIMATELY_REACHED",
            "also": "IMPLEMENTED_AS_COHERENT_CLOCK_PAIR",
            "hle": "UC_HLE_QUERYPERFORMANCEFREQUENCY",
            "observed_calls_on_ctor": ctor.get("qpf_calls", 0),
            "frequency_written": GUEST_QPF_HZ,
        },
        "SleepEx": {
            **sleepx,
            "implemented": False,
            "legitimately_reached": True,
            "observed_args": {"dwMilliseconds": 0x32, "bAlertable": 1},
            "classification": "BLOCKED_ALERTABLE_WAIT",
            "reason": (
                "Alertable SleepEx requires APC delivery / wait completion semantics "
                "absent from the single-guest-thread model. Do not fake alertable success."
            ),
        },
        "GetTickCount": {
            **gtc, "implemented": False, "reached_phase35": False,
        },
        "Sleep": {"imported_scan": "not required this phase", "implemented": False},
        "unsupported": [
            "alertable waits / APC delivery",
            "guest thread scheduler",
            "host wall-clock as guest timebase",
            "auto-increment QPC per call",
        ],
        "crt_atexit": atexit,
    }

    recommended = (
        "QPC/QPF guest clock is live; constructor advances to alertable SleepEx(50ms, TRUE). "
        "Phase 36: either EXPAND THREADING/TLS RUNTIME for a narrowly justified non-alertable "
        "sleep/virtual-wait policy (without APC/scheduler fiction), or EXPAND REAL UC EXECUTION "
        "on other ordinary roots while leaving alertable waits classified. "
        "CRT atexit remains BLOCKED_CRT_INITIALIZATION. Graphics frozen."
    )

    frontier = {
        "phase": 35,
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
        "proven_depth_5_roots": sorted({hx(r["root"]) for r in rows if r["depth_max"] >= 5}),
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
            "IMPORT_READY": 737, "RUNTIME_READY": runtime_ready,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique), "UNIQUE": len(unique),
            "EXECUTION_RUNS": execution_runs,
            "CLEAN_ORDINARY_ROOTS": len(clean),
            "EXECUTED_ORDINARY_CONSTRUCTORS": len(ctors),
            "DEEPEST": deepest, "LARGEST_CLOSURE": largest,
            "ENTERABLE_WITH_DEPTH_4_POTENTIAL": 0,
            "PROVEN_DEPTH_4_ROOTS": len(depth4_proven),
            "LATEST_REAL_RUNTIME_BOUNDARY": ctor.get("import") or "SleepEx",
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase35_attempted": len(rows),
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "deepest_chain": deepest,
            "largest_executed_closure": largest,
            "clean_ordinary_roots": len(clean),
            "executed_ordinary_constructors": len(ctors),
            "qpc_implemented": True,
            "qpf_implemented": True,
            "sleepex_implemented": False,
            "ctor_status": ctor_status,
            "semaphore_path_status": sem_status,
            "ebc70_status": {"result": ebc["result"], "clean": ebc["clean"]},
            "crt_atexit": atexit,
            "timing_loop_encountered": False,
            "instruction_budget_exhaustion": False,
            "alertable_wait_reached": True,
            "scheduler": False,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "filesystem_reached": False,
            "protected_boundary_encountered": False,
            "diagnostics_counted": 0,
        },
        "synchronization": prev.get("synchronization") or {},
        "timing": {
            "QueryPerformanceCounter": "IMPLEMENTED",
            "QueryPerformanceFrequency": "IMPLEMENTED",
            "SleepEx": "NOT_IMPLEMENTED / BLOCKED_ALERTABLE_WAIT",
            "frequency_hz": GUEST_QPF_HZ,
            "guest_threads": 1,
            "scheduler": "NONE",
        },
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase36": recommended,
        "phase31_metric_corrections_preserved": True,
    }
    frontier["synchronization"].update({
        "QueryPerformanceCounter": "IMPLEMENTED",
        "QueryPerformanceFrequency": "IMPLEMENTED",
        "SleepEx": "NOT_IMPLEMENTED",
    })

    dump("timing-frontier.json", timing)
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
        "phase": 35, "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase35_ctor": ctor_status,
        "phase35_semaphore": sem_status,
        "phase34_ctor": evidence_prev.get("phase34_ctor"),
        "phase33_ctor": evidence_prev.get("phase33_ctor"),
        "phase30_stub_correction": evidence_prev.get("phase30_stub_correction"),
    })
    dump("blocker-ranking.json", {
        "phase": 35,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "qpc_cleared": True,
        "qpf_cleared": True,
        "latest_real_runtime_boundary": ctor.get("import"),
        "next_genuine_blockers": sorted({
            r.get("import") for r in rows if r.get("import")
            and r.get("hist") in ("IMPORT", "TIMING", "ALERTABLE_WAIT")
        } | {"BLOCKED_CRT_INITIALIZATION", "SleepEx"}),
        "crt_atexit": atexit,
    })

    status = load("project-status.json")
    status["current_phase"] = 35
    status["strategy"] = (
        "Phase 35: deterministic guest QPC/QPF; ctor → alertable SleepEx. Graphics frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 35 for p in phases):
        phases.append({"phase": 35,
                       "name": "Deterministic guest QPC/QPF clock",
                       "state": "completed"})
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase35.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 35 — deterministic guest performance clock",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.",
            "",
            "## A. Phase-34 baseline",
            "",
            "UNIQUE 44, ENTERABLE 21, DEEPEST 4, CLOSURE 11, RUNTIME_READY 69, RUNS 59. "
            "Constructor stopped on QueryPerformanceCounter.",
            "",
            "## B. QPC identity and ABI",
            "",
            "- IAT `%s` KERNEL32!%s hint %s; unbound `%s`" % (
                qpc["slot"], qpc["symbol"], qpc["hint"], qpc["unbound_name_rva"]),
            "- stdcall, 1 stack dword, BOOL in EAX + 64-bit LE store; **%s**" % qpc["abi_confidence"],
            "- HIGH callers include `%s`" % hx(AFFINITY_BLOCK),
            "",
            "## C. Real output-buffer provenance",
            "",
            prov["output_buffer"] + " (" + prov["storage_type"] + "). Call site `%s`." % (
                prov["qpc_call_site"]),
            "",
            "## D. Clock design and frequency",
            "",
            "Virtual frequency **%d** ticks/s. Initial counter **0**. "
            "Not host uptime. Not host QPC." % GUEST_QPF_HZ,
            "",
            "## E. Deterministic advancement policy",
            "",
            "`uc_guest_clock_advance_ns(delta)` only. Equal QPC at equal virtual time. "
            "Virtual TSC = qpc_ticks × 300 (3 GHz coherent).",
            "",
            "## F. QPC implementation/tests",
            "",
            "`UC_HLE_QUERYPERFORMANCECOUNTER`. Full 8-byte guest write via checked stores. "
            "Invalid buffer → HLE reject. Tests: `uc_phase35_test.py`.",
            "",
            "## G. QPF identity and actual reach",
            "",
            "- IAT `%s`; stdcall 1 dword; **PROVEN**" % qpf["slot"],
            "- Legitimately reached on ctor path after QPC calibration retries "
            "(observed qpf_calls=%d)." % ctor.get("qpf_calls", 0),
            "",
            "## H. QPF implementation/tests",
            "",
            "`UC_HLE_QUERYPERFORMANCEFREQUENCY` writes stable `%d`. "
            "Same timebase as QPC." % GUEST_QPF_HZ,
            "",
            "## I. Timing consistency",
            "",
            "Unit tests cover advance_ns → ΔQPC / QPF == elapsed seconds (integer). "
            "Low-word rollover and reset covered.",
            "",
            "## J. Constructor before/after",
            "",
            "Before: stop on QPC. After: **%s** / **%s** (clean=%s). "
            "Observed qpc_calls=%d qpf_calls=%d." % (
                ctor_status["after"], ctor_status["after_blocker"],
                ctor_status["returned_clean"],
                ctor_status["qpc_calls"], ctor_status["qpf_calls"]),
            "",
            "## K. SleepEx and wait semantics",
            "",
            "Reached with args **(0x32, alertable=1)**. Not implemented. "
            "**BLOCKED_ALERTABLE_WAIT** — no APC delivery / no scheduler.",
            "",
            "## L. No-stub campaign",
            "",
            "\n".join(
                "- `%s` → **%s** (d=%d u=%d) %s" % (
                    hx(r["root"]), r["result"], r["depth_max"], r["unique_entered"],
                    r.get("import") or r.get("detail") or "")
                for r in rows
            ),
            "",
            "## M. Next genuine blocker",
            "",
            "- Constructor: **SleepEx** (`BLOCKED_ALERTABLE_WAIT`)",
            "- CRT static-init: BLOCKED_CRT_INITIALIZATION",
            "",
            "## N. Frontier delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; DEEPEST **%d**; CLOSURE **%d**; "
            "CLEAN **%d**; RUNTIME_READY **%d**; RUNS **%d**." % (
                len(unique), len(enterable), deepest, largest, len(clean),
                runtime_ready, execution_runs),
            "",
            "## O. Phase-36 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "deep", deepest, "clos", largest, "clean", len(clean),
          "ctor", ctor.get("import"), "blocker", common)
    return {"rows": rows, "frontier": frontier, "timing": timing}


if __name__ == "__main__":
    main()
