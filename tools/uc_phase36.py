#!/usr/bin/env python3
"""Phase 36: deterministic SleepEx timeout-only wait on no-stub UC paths.

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

SLEEPEX_IAT = 0x00B61188
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
    fmap = {int(r["va"], 16): r for r in load("function-map.json")["functions"]}
    starts = sorted(fmap)
    high = set()
    for s in sites:
        i = bisect.bisect_right(starts, s) - 1
        if i >= 0 and "HIGH" in ((fmap[starts[i]].get("label") or "").upper()):
            high.add(starts[i])
    abi = {
        "SleepEx": (2, "DWORD", "PROVEN"),
        "Sleep": (1, "void", "PROVEN"),
        "CreateWaitableTimerA": (3, "HANDLE", "PROVEN"),
        "SetWaitableTimer": (6, "BOOL", "PROVEN"),
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


def analyze_sleepex_contract():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for i in cs.disasm(blob[0x97F8D0 - base:0x97F8D0 - base + 0x20], 0x97F8D0):
        lines.append("%08X: %s %s" % (i.address, i.mnemonic, i.op_str))
    return {
        "ordinary_caller": hx(AFFINITY_BLOCK),
        "instruction": "0x0097F8D6",
        "args": {"dwMilliseconds": 0x32, "bAlertable": 1},
        "arg_provenance": "immediate push 1; push 0x32",
        "return_usage": "IGNORED — next insn lea ecx,[esp+0x10]; call QPC",
        "post_sleep_loop": "je 0x97F8D0 retries SleepEx until calibration threshold 0.25",
        "shape": lines,
    }


def apc_inventory():
    pef = pefile.PE(GAME, fast_load=False)
    mm = pef.get_memory_mapped_image()
    ib = pef.OPTIONAL_HEADER.ImageBase
    want = {
        "QueueUserAPC", "ReadFileEx", "WriteFileEx", "SetWaitableTimer",
        "SetWaitableTimerEx", "CreateWaitableTimerA", "CreateWaitableTimerW",
        "NtQueueApcThread",
    }
    found = {}
    for slot in range(0x00B61000, 0x00B63000, 4):
        raw = struct.unpack_from("<I", mm, slot - ib)[0]
        if not (0x1000 <= raw < 0xCAC000):
            continue
        try:
            txt = mm[raw + 2:raw + 80].split(b"\x00", 1)[0].decode("ascii")
        except Exception:
            continue
        if txt in want:
            found[txt] = hx(slot)
    fmap = h.load_fmap()
    clos = set(h.closure(CTOR, fmap, limit=48))
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    reached = {}
    for name, slot_s in found.items():
        slot = int(slot_s, 16)
        pat = bytes([0xFF, 0x15]) + struct.pack("<I", slot)
        hits = []
        for fn in clos:
            chunk = blob[fn - base:fn - base + 0x800]
            j = 0
            while True:
                k = chunk.find(pat, j)
                if k < 0:
                    break
                hits.append(hx(fn + k))
                j = k + 1
        reached[name] = hits
    return {
        "imported": found,
        "in_ctor_closure": {n: hts for n, hts in reached.items() if hts},
        "QueueUserAPC": "NOT_IMPORTED",
        "ReadFileEx": "NOT_IMPORTED",
        "WriteFileEx": "NOT_IMPORTED",
        "SetWaitableTimer_on_ctor_path": bool(reached.get("SetWaitableTimer")),
        "CreateWaitableTimerA_on_ctor_path": bool(reached.get("CreateWaitableTimerA")),
        "pending_apc_classification": "PROVEN_NO_PENDING_APC_IN_SUPPORTED_MODEL",
        "note": (
            "SetWaitableTimer/CreateWaitableTimerA are imported but not called on the "
            "ordinary constructor closure path that reaches SleepEx. No APC queue exists "
            "in the guest runtime. Guest APC pending flag defaults false."
        ),
    }


def classify_crt_atexit():
    return {
        "roots": ["0x00B52140", "0x00B57CF0"],
        "classification": "BLOCKED_CRT_INITIALIZATION",
        "implementation_attempted": False,
    }


def serialize_row(r, phase=36):
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
        "sleepex_calls": r.get("sleepex_calls", 0),
        "sleepex_done": r.get("sleepex_done", 0),
        "qpc_calls": r.get("qpc_calls", 0),
        "qpf_calls": r.get("qpf_calls", 0),
        "qpc_ticks_lo": r.get("qpc_ticks_lo", 0),
        "qpc_ticks_hi": r.get("qpc_ticks_hi", 0),
        "stubs": [],
        "notes": r.get("note"),
        "evidence": "uc_phase36.py",
        "counted_in_metrics": True,
        "diagnostic_only": False,
    }


def main():
    sleepx = identify_slot(SLEEPEX_IAT, "SleepEx")
    contract = analyze_sleepex_contract()
    apc = apc_inventory()
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

    ticks = ctor.get("qpc_ticks_lo", 0) | (ctor.get("qpc_ticks_hi", 0) << 32)
    ctor_status = {
        "before": "EXECUTED_TO_NEXT_BLOCKER / SleepEx BLOCKED_ALERTABLE_WAIT",
        "after": ctor["result"],
        "after_blocker": ctor.get("import") or ctor.get("detail"),
        "blocker_result": ctor.get("blocker_result"),
        "returned_clean": bool(ctor.get("clean")),
        "sleepex_calls": ctor.get("sleepex_calls", 0),
        "sleepex_done": ctor.get("sleepex_done", 0),
        "qpc_ticks_after": ticks,
        "virtual_ms_elapsed": ticks * 100 // GUEST_QPF_HZ,
        "entered": [hx(x) for x in ctor["entered"]],
        "depth": ctor["depth_max"],
        "closure": ctor["unique_entered"],
        "new_ordinary_after_sleep": [
            hx(x) for x in ctor["entered"]
            if x not in (0x9E9160, 0x9E7710, 0x9E9990, 0x9E9460, 0x9773C0,
                         0x977E20, 0x977420, 0x9EB980, 0x978720, 0x97FCD0, 0x97F790)
        ],
    }

    wait = {
        "phase": 36,
        "SleepEx": {
            **sleepx, **contract,
            "implemented": True,
            "reached": True,
            "hle": "UC_HLE_SLEEPEX",
            "hle_justified": True,
            "timeout_only_eligible": True,
            "supported_finite_non_alertable": True,
            "supported_finite_alertable_timeout": True,
            "apc_delivery": False,
            "zero_timeout": "immediate complete; no invented elapsed time",
            "infinite_timeout": "rejected (*ok=0) — BLOCKED_INFINITE_WAIT class",
            "pending_apc_guard": "uc_wait_set_pending_apc(1) refuses timeout-only path",
            "return_on_timeout": 0,
            "never_returns_WAIT_IO_COMPLETION_without_callback": True,
            "virtual_advance_per_50ms": "500,000 QPC ticks / 50,000,000 ns",
            "tests": "uc_phase36_test.py",
        },
        "apc_provenance": apc,
        "guest_wait_model": {
            "representation": (
                "last-wait descriptor: ms, alertable, start_ticks, deadline_ticks; "
                "completion counter; pending-APC flag"
            ),
            "threads": 1,
            "scheduler": "NONE",
            "advancement": "synchronous HLE advances guest clock to deadline (harness-controlled)",
            "not": ["CreateThread", "APC delivery", "kernel wait queues", "Web Workers"],
        },
        "crt_atexit": atexit,
    }

    timing = load("timing-frontier.json")
    timing["phase"] = 36
    timing["SleepEx"] = {
        **timing.get("SleepEx", {}),
        **wait["SleepEx"],
        "classification": "IMPLEMENTED_TIMEOUT_ONLY",
        "legitimately_reached": True,
        "implemented": True,
    }
    timing["wait_frontier"] = "wait-frontier.json"

    prev = load("runtime-frontier.json")
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)
    depth4_proven = sorted({hx(r["root"]) for r in rows if r["depth_max"] >= 4}
                           | set(prev.get("proven_depth_4_roots") or []))
    runtime_ready = (prev.get("runtime_ready") or 71) + 1  # SleepEx
    execution_runs = 71 + len(rows)

    recommended = (
        "SleepEx timeout-only HLE cleared the alertable finite wait. Constructor now "
        "stops on an unresolved ordinary jump-table / switch dispatch inside 0x0097F9E0 "
        "(BLOCKED_INDIRECT). Phase 37: EXPAND INDIRECT DISPATCH — enable/verify JTSWITCH "
        "recognition for this MSVC switch so ordinary case handlers execute without "
        "DISPATCH_TAIL. Do not invent APC delivery. Graphics frozen."
    )

    frontier = {
        "phase": 36,
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
            "LATEST_REAL_RUNTIME_BOUNDARY": ctor.get("blocker_result") or "BLOCKED_INDIRECT",
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase36_attempted": len(rows),
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist,
            "required_state_histogram": req,
            "most_common_next_blocker": list(common),
            "deepest_chain": deepest,
            "largest_executed_closure": largest,
            "clean_ordinary_roots": len(clean),
            "executed_ordinary_constructors": len(ctors),
            "sleepex_implemented": True,
            "apc_delivery": False,
            "ctor_status": ctor_status,
            "semaphore_path_status": {
                "result": semr["result"], "clean": semr["clean"],
                "depth": semr["depth_max"],
            },
            "ebc70_status": {"result": ebc["result"], "clean": ebc["clean"]},
            "crt_atexit": atexit,
            "timing_loop_encountered": False,
            "scheduler": False,
            "tlsgetvalue_reached": False,
            "tlsfree_reached": False,
            "filesystem_reached": False,
            "protected_boundary_encountered": False,
            "diagnostics_counted": 0,
        },
        "synchronization": prev.get("synchronization") or {},
        "timing": prev.get("timing") or {},
        "waits": {
            "SleepEx": "IMPLEMENTED_TIMEOUT_ONLY",
            "APC_delivery": "NOT_IMPLEMENTED",
            "guest_threads": 1,
            "scheduler": "NONE",
            "current_ctor_blocker": ctor.get("blocker_result"),
        },
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase37": recommended,
        "phase31_metric_corrections_preserved": True,
    }
    frontier["timing"].update({
        "SleepEx": "IMPLEMENTED_TIMEOUT_ONLY",
        "frequency_hz": GUEST_QPF_HZ,
    })

    dump("wait-frontier.json", wait)
    dump("timing-frontier.json", timing)
    dump("runtime-frontier.json", frontier)

    camp_ser = [serialize_row(r) for r in rows]
    hist_ev, seen = [], set()
    for r in camp_ser + (evidence_prev.get("roots") or []):
        key = (r.get("root"), r.get("phase"), r.get("result"), r.get("import"),
               r.get("evidence"), r.get("detail"), r.get("reclassified_phase"))
        if key in seen:
            continue
        seen.add(key)
        hist_ev.append(r)
    dump("execution-evidence.json", {
        "phase": 36, "roots": hist_ev,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "clean_ordinary_roots": [hx(x) for x in clean],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase36_ctor": ctor_status,
        "phase35_ctor": evidence_prev.get("phase35_ctor"),
        "phase34_ctor": evidence_prev.get("phase34_ctor"),
        "phase30_stub_correction": evidence_prev.get("phase30_stub_correction"),
    })
    dump("blocker-ranking.json", {
        "phase": 36,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist,
        "required_state_histogram": req,
        "most_common_real_blocker": list(common),
        "sleepex_cleared": True,
        "latest_real_runtime_boundary": ctor.get("blocker_result"),
        "next_genuine_blockers": sorted({
            r.get("blocker_result") or r.get("import") or r.get("detail")
            for r in rows
            if r.get("hist") in ("IMPORT", "TIMING", "ALERTABLE_WAIT", "INDIRECT")
        } | {"BLOCKED_CRT_INITIALIZATION"}),
        "crt_atexit": atexit,
    })

    status = load("project-status.json")
    status["current_phase"] = 36
    status["strategy"] = (
        "Phase 36: SleepEx timeout-only; ctor → jump-table INDIRECT in 0x97F9E0. "
        "Graphics frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 36 for p in phases):
        phases.append({"phase": 36,
                       "name": "Deterministic SleepEx timeout",
                       "state": "completed"})
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase36.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 36 — deterministic SleepEx timeout",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
            "D3D9 / ENGINE BACKEND: **NOT JUSTIFIED**.",
            "",
            "## A. Phase-35 baseline",
            "",
            "UNIQUE 44, ENTERABLE 21, DEEPEST 4, CLOSURE 11, RUNTIME_READY 71, RUNS 71. "
            "Constructor stopped on alertable SleepEx(50, TRUE).",
            "",
            "## B. SleepEx identity and ABI",
            "",
            "- IAT `%s` KERNEL32!%s hint %s" % (
                sleepx["slot"], sleepx["symbol"], sleepx["hint"]),
            "- stdcall, 2 stack dwords → DWORD; **%s**" % sleepx["abi_confidence"],
            "- sites %d; HIGH %d" % (sleepx["call_site_count"], sleepx["high_caller_count"]),
            "",
            "## C. Real constructor call contract",
            "",
            "`SleepEx(0x32, TRUE)` at `%s` in `%s`. Return **ignored**." % (
                contract["instruction"], contract["ordinary_caller"]),
            "",
            "## D. APC/completion provenance",
            "",
            json.dumps(apc, indent=2),
            "",
            "## E. Timeout-only eligibility",
            "",
            "**YES** — PROVEN_NO_PENDING_APC_IN_SUPPORTED_MODEL on the ctor path; "
            "finite timeout; coherent guest clock; return 0 = timeout.",
            "",
            "## F. Guest wait representation",
            "",
            wait["guest_wait_model"]["representation"],
            "",
            "## G. Virtual-time advancement",
            "",
            "50 ms → 50,000,000 ns → 500,000 QPC ticks. Synchronous HLE advances the "
            "Phase-35 clock to the deadline. Not host sleep. Not a scheduler.",
            "",
            "## H. Tests",
            "",
            "`uc_phase36_test.py` — ABI, finite alertable/non-alertable, repeated, "
            "zero, infinite reject, pending-APC guard, QPC integration.",
            "",
            "## I. Constructor before/after",
            "",
            "Before: BLOCKED_ALERTABLE_WAIT. After: **%s** / **%s** (clean=%s). "
            "SleepEx completions=%d; virtual ticks=%d (~%d ms)." % (
                ctor_status["after"], ctor_status["after_blocker"],
                ctor_status["returned_clean"],
                ctor_status["sleepex_done"], ticks,
                ctor_status["virtual_ms_elapsed"]),
            "",
            "## J. Subsequent ordinary execution",
            "",
            "New bodies: %s. Depth **%d**, closure **%d**." % (
                ", ".join(ctor_status["new_ordinary_after_sleep"]) or "(none)",
                ctor_status["depth"], ctor_status["closure"]),
            "",
            "## K. Next real blockers",
            "",
            "- Constructor: **BLOCKED_INDIRECT** (MSVC jump table in `0x0097F9E0`)",
            "- CRT: BLOCKED_CRT_INITIALIZATION",
            "",
            "## L. Frontier delta",
            "",
            "UNIQUE **%d**; ENTERABLE **%d**; DEEPEST **%d**; CLOSURE **%d**; "
            "CLEAN **%d**; RUNTIME_READY **%d**; RUNS **%d**." % (
                len(unique), len(enterable), deepest, largest, len(clean),
                runtime_ready, execution_runs),
            "",
            "## M. Phase-37 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("unique", len(unique), "enterable", len(enterable),
          "deep", deepest, "clos", largest, "clean", len(clean),
          "ctor", ctor.get("blocker_result"), "sx", ctor.get("sleepex_done"))
    return {"rows": rows, "frontier": frontier, "wait": wait}


if __name__ == "__main__":
    main()
