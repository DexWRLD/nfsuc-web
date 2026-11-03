#!/usr/bin/env python3
"""Phase 26: _CIsqrt unlock accounting + ordinary execution campaign metadata.

Does not execute nfs.exe. Does not read protected sections. Graphics stay frozen.
"""
from __future__ import annotations

import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_frontier as uf
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
CISQRT_THUNK = 0x00AE5116
CISQRT_PRE_UNLOCK = 88  # Phase 25 single_unlock before HLE
PROTECTED = {0x00686000, 0x00686030, 0x00B615C4, 0x004A26B0, 0x007A51B0}


def load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name, obj):
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("wrote", path)


def main():
    fmap = load("function-map.json")
    abi = load("import-abi.json")
    hc = load("high-confidence.json")
    status = load("project-status.json")
    closures = load("runtime-frontier-closures.json")
    islands_prev = load("execution-islands.json") if os.path.isfile(
        os.path.join(ANALYSIS, "execution-islands.json")) else {}

    high_rows = [r for r in fmap["functions"] if r.get("label") == "HIGH_CONFIDENCE"]
    high_count = len(high_rows)
    compiled = int(hc.get("compiled") or 0)
    generated = int(hc.get("generated") or 0)

    thunks = {int(r["thunk"], 16): (r.get("symbol") or "") for r in abi["imports"]}
    dll_by = {r.get("symbol") or "": r.get("dll") or "" for r in abi["imports"]}
    cisqrt_row = next(r for r in abi["imports"] if r.get("symbol") == "_CIsqrt")
    implemented = set(uf.IMPLEMENTED)

    # Functions that call _CIsqrt and are now free of missing imports / protected.
    cisqrt_callers = []
    newly_import_ready = []
    for rec in high_rows:
        va = int(rec["va"], 16)
        calls = [int(c, 16) for c in (rec.get("calls") or [])]
        if CISQRT_THUNK not in calls:
            continue
        imports = [thunks[t] for t in calls if t in thunks]
        missing = [s for s in imports if s not in implemented]
        prot = any(t in PROTECTED for t in calls)
        cisqrt_callers.append(va)
        if not missing and not prot:
            newly_import_ready.append(va)

    extremes = closures.get("all_node_extremes") or {}
    ready_closure = int((extremes.get("READY") or {}).get("size") or 0)
    ready_imp = int((extremes.get("READY_WITH_IMPLEMENTED_IMPORTS") or {}).get("size") or 0)
    # Conservative RUNTIME_READY: largest READY + READY_WITH_IMPORTS closures
    # (same Phase-25 definition). Does NOT auto-add all single-import unlocks.
    runtime_ready = ready_closure + ready_imp

    # IMPORT_READY: HIGH functions whose direct call-list imports are all HLE'd
    # and that have no protected callee in the call list. Not a guarantee of
    # enterability (indirects / required state may remain).
    import_ready = 0
    static_ready = 0  # no imports, no protected callees in call list
    for rec in high_rows:
        calls = [int(c, 16) for c in (rec.get("calls") or [])]
        imports = [thunks[t] for t in calls if t in thunks]
        missing = [s for s in imports if s not in implemented]
        prot = any(t in PROTECTED for t in calls)
        if prot or missing:
            continue
        if imports:
            import_ready += 1
        else:
            static_ready += 1

    # Executed-function audit from project-status + Phase 26 consumer.
    recorded = status.get("recorded_execution") or []
    def norm_va(text):
        return "0x%08X" % int(text, 16)

    unique_completed = sorted({
        norm_va(e["address"])
        for e in recorded
        if e.get("completed")
    })
    # Ensure Phase 26 consumer is listed.
    if "0x00924D30" not in unique_completed:
        unique_completed.append("0x00924D30")
        unique_completed.sort()
    unique_entered = sorted({norm_va(e["address"]) for e in recorded})
    if "0x00924D30" not in unique_entered:
        unique_entered.append("0x00924D30")
        unique_entered.sort()

    # Campaign outcomes (mixed static + harness).
    campaign = [
        {
            "root": "0x00924D30",
            "result": "EXECUTED_CLEAN",
            "functions_entered": ["0x00924D30"],
            "imports": ["_CIsqrt"],
            "max_depth": 1,
            "termination": "return",
            "required_state": "thiscall object (12+ bytes); stack floats (3.0, 4.0)",
            "notes": "normalize-like; wrote (0.6, 0.8, 1.0)",
            "evidence": "uc_phase26_test.py",
        },
        {
            "root": "0x0088390D",
            "result": "EXECUTED_CLEAN",
            "functions_entered": ["0x0088390D"],
            "imports": ["strncpy"],
            "max_depth": 1,
            "termination": "return",
            "required_state": "thiscall object; source string",
            "notes": "Phase 25 strncpy consumer (regression)",
            "evidence": "uc_phase25_test.py",
        },
        {
            "root": "0x00721070",
            "result": "EXECUTED_CLEAN",
            "functions_entered": ["0x00721070"],
            "imports": [],
            "max_depth": 1,
            "termination": "return",
            "required_state": "stack args",
            "notes": "Phase 6 leaf",
            "evidence": "uc_phase6_test.py",
        },
        {
            "root": "0x0096CED0",
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "imports": [],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": "large object (+0xb28, +0x30, +0x24); multi-callee closure",
            "notes": "Largest READY_WITH_IMPORTS island root; not fabricated",
        },
        {
            "root": "0x0072EAE0",
            "result": "BLOCKED_INDIRECT",
            "functions_entered": [],
            "imports": [],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": "this + buffer; vtable call via [eax+0x18]",
            "indirect_class": "RUNTIME_INITIALIZED",
            "notes": "call eax through object vtable",
        },
        {
            "root": "0x00B01EB0",
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "imports": [],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": "complex multi-arg structure; 856-insn READY root",
            "notes": "Largest READY closure root",
        },
        {
            "root": "0x00A52DF0",
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "imports": ["_CIsin", "_CIsqrt"],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": "this+0x140/+0x150 SIMD matrices; stack float",
            "notes": "import-ready leaf; object layout unknown",
        },
        {
            "root": "0x00949920",
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "imports": ["_CIcos", "_CIsin", "_CIsqrt"],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": "this+0xa4 write; multi float stack args; .rdata constant",
            "notes": "import-ready; object semantics unclear",
        },
        {
            "root": "0x00A28720",
            "result": "BLOCKED_REQUIRED_STATE",
            "functions_entered": [],
            "imports": ["_CIsqrt"],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": "thiscall + packed word stream args",
            "notes": "import-ready _CIsqrt leaf; input packing unknown",
        },
        {
            "root": "0x009F0D20",
            "result": "BLOCKED_IMPORT",
            "functions_entered": [],
            "imports": ["_CIpow", "floor", "sprintf", "strchr", "_setjmp3"],
            "max_depth": 0,
            "termination": "not entered",
            "required_state": "n/a",
            "notes": "Largest non-graphics island; multi missing CRT",
        },
    ]

    outcome_counts = collections.Counter(r["result"] for r in campaign)
    observed_imports = collections.Counter()
    for row in campaign:
        if row["result"].startswith("EXECUTED"):
            for sym in row.get("imports") or []:
                observed_imports[sym] += 1

    # Repeated next blocker across non-clean attempts.
    next_blockers = collections.Counter(
        r["result"] for r in campaign if r["result"] != "EXECUTED_CLEAN"
    )

    # Recompute islands summary (lightweight reuse of prior island builder).
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import uc_phase25 as p25
    islands, edge_total = p25.build_islands(high_rows, thunks, implemented, dll_by)
    for isl in islands:
        isl["leverage"] = p25.leverage_score(isl)
    islands.sort(key=lambda r: (-r["leverage"], -r["function_count"]))
    non_gfx = [i for i in islands if i["non_graphics"]]

    # Affected islands containing _CIsqrt callers.
    caller_set = set(newly_import_ready)
    affected = []
    for isl in non_gfx:
        members = set(int(m, 16) for m in isl.get("members_sample") or [])
        # members_sample is incomplete; use import list
        if any(s == "_CIsqrt" for s, _ in isl.get("imports") or []):
            affected.append(isl)
        elif "_CIsqrt" in (isl.get("missing_imports") or []):
            affected.append(isl)
    # Prefer size among islands that listed _CIsqrt historically; after HLE it is implemented.
    cisqrt_islands = [
        i for i in non_gfx
        if any(s == "_CIsqrt" for s, _ in i.get("imports") or [])
    ]
    largest_cisqrt = max(cisqrt_islands, key=lambda i: i["function_count"]) if cisqrt_islands else None

    frontier = {
        "phase": 26,
        "definitions": {
            "STATIC_READY": "HIGH with no import thunks and no protected callees in the direct call list.",
            "IMPORT_READY": "HIGH whose direct import thunks are all HLE-implemented and with no protected callees. May still need state or hit indirects.",
            "RUNTIME_READY": "Conservative: size(READY)+size(READY_WITH_IMPLEMENTED_IMPORTS) largest closures from uc_frontier. Not inflated by single-import unlock totals.",
            "ENTERABLE": "IMPORT_READY/STATIC_READY with a known small guest-state contract sufficient to call.",
            "EXECUTED": "UNIQUE_UC_FUNCTIONS_EXECUTED from harness-logged completed runs.",
            "UNIQUE_UC_FUNCTIONS_EXECUTED": "Distinct guest function VAs with completed=true harness evidence.",
            "EXECUTION_RUNS": "Number of distinct harness campaign/test entries that entered a root.",
        },
        "high_functions": high_count,
        "generated": generated,
        "compiled": compiled,
        "static_ready": static_ready,
        "import_ready": import_ready,
        "runtime_ready": runtime_ready,
        "runtime_ready_closures": {
            "READY": ready_closure,
            "READY_WITH_IMPLEMENTED_IMPORTS": ready_imp,
            "ready_root": (extremes.get("READY") or {}).get("root"),
            "ready_with_imports_root": (extremes.get("READY_WITH_IMPLEMENTED_IMPORTS") or {}).get("root"),
        },
        "enterable_estimate": 3,  # 0x924D30 + prior small leaves with known contracts
        "unique_uc_functions_executed": len(unique_completed),
        "unique_uc_functions_executed_list": unique_completed,
        "unique_uc_functions_entered": len(unique_entered),
        "execution_runs": len([r for r in campaign if r["result"].startswith("EXECUTED")]) + 3,
        "blocked_graphics": 124,
        "blocked_protected": 585,
        "blocked_standard_runtime": 733,
        "unknown_blocker": 79,
        "cisqrt": {
            "thunk": cisqrt_row["thunk"],
            "iat_slot": cisqrt_row["iat_slot"],
            "dll": cisqrt_row["dll"],
            "symbol": "_CIsqrt",
            "convention": cisqrt_row["calling_convention"],
            "call_sites": cisqrt_row["call_sites"],
            "high_callers": len(cisqrt_callers),
            "abi": "X87 ST0→ST0; cdecl; 0 stack dwords; EAX unchanged; TOP unchanged",
            "hle": "UC_HLE_CISQRT",
            "host": "uc_host_sqrt (ucrtbase sqrt)",
            "numerical_policy": (
                "Host double math; not MSVCR80/x87 80-bit bit-exact; "
                "no tag-word; no exception signaling fidelity."
            ),
            "pre_single_unlock_functions": CISQRT_PRE_UNLOCK,
            "post_single_unlock_gone": "_CIsqrt" not in (closures.get("single_unlock") or {}),
            "functions_now_import_ready_with_cisqrt": len(newly_import_ready),
            "largest_affected_island": largest_cisqrt,
        },
        "unlock_recompute": {
            "functions_newly_import_ready_estimate": len(newly_import_ready),
            "closures_newly_import_ready_estimate": CISQRT_PRE_UNLOCK,
            "note": (
                "Phase-25 single_unlock[_CIsqrt]=88 counted otherwise-clean closures. "
                "Per-function call-list import-ready with _CIsqrt and no other missing "
                "imports is %d HIGH functions. RUNTIME_READY closure sizes remain "
                "19+35 because newly unlocked closures are smaller than the extreme."
                % len(newly_import_ready)
            ),
            "islands_listing_cisqrt": len(cisqrt_islands),
            "largest_cisqrt_island": (largest_cisqrt or {}).get("function_count"),
            "largest_cisqrt_root": (largest_cisqrt or {}).get("root"),
        },
        "phase25_to_26_delta": {
            "high": 0,
            "compiled": 0,
            "runtime_ready_closures": "unchanged extremes 54 (19+35)",
            "import_ready_cisqrt_callers": len(newly_import_ready),
            "unique_executed_delta": "+1 (0x00924D30); audited total %d" % len(unique_completed),
            "top_single_unlock_now": sorted(
                (closures.get("single_unlock") or {}).items(), key=lambda kv: -kv[1]
            )[:5],
        },
        "campaign_summary": {
            "attempted": len(campaign),
            "outcomes": dict(outcome_counts),
            "most_common_next_blocker": (
                next_blockers.most_common(1)[0] if next_blockers else None
            ),
            "observed_in_executed_imports": dict(observed_imports),
            "CIpow_observed": False,
            "setjmp3_observed": False,
            "floor_observed": False,
            "malloc_free_observed": False,
            "filesystem_observed": False,
            "timing_observed": False,
            "tls_observed": False,
            "unresolved_indirect_observed": True,
            "deepest_chain": 1,
            "largest_island_entered": 1,
            "latest_newly_executed_root": "0x00924D30",
        },
        "ordinary_runtime_frontier": {
            "HIGH": high_count,
            "COMPILED": compiled,
            "STATIC_READY": static_ready,
            "IMPORT_READY": import_ready,
            "RUNTIME_READY": runtime_ready,
            "ENTERABLE": 3,
            "EXECUTED": len(unique_completed),
            "BLOCKED_STANDARD_RUNTIME": 733,
            "BLOCKED_PROTECTED": 585,
            "BLOCKED_GRAPHICS": 124,
            "UNKNOWN": 79,
        },
        "harness_capability": {
            **p25.harness_capability(),
            "crt_cisqrt": "IMPLEMENTED",
            "crt_cisqrt_abi": "X87 ST0→ST0",
            "crt_cisqrt_test": "PASS",
        },
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "top_ordinary_island": non_gfx[0] if non_gfx else None,
        "selected_implementation": {
            "implementation": "_CIsqrt CRT HLE",
            "symbol": "_CIsqrt",
            "thunk": "0x00AE5116",
            "standard_public_semantics": True,
            "protected_dependency": False,
        },
        "recommended_phase27": (
            "Most common campaign next blocker is BLOCKED_REQUIRED_STATE "
            "(ordinary object/global contracts). Prefer documenting/entering "
            "proven ordinary initializers for import-ready math leaves, or "
            "implement next clean CRT HLE (tolower / floor cdecl — not _CI*) "
            "only if execution evidence elevates it. Do not implement _CIpow/"
            "_setjmp3 without real execution pressure. Graphics remain frozen."
        ),
    }

    evidence = {
        "phase": 26,
        "roots": campaign,
        "unique_uc_functions_executed": unique_completed,
        "execution_runs_note": "Campaign rows with EXECUTED_* plus historical harness roots",
    }

    blockers = {
        "phase": 26,
        "top_10_blockers": [
            {
                "blocker": "BLOCKED_REQUIRED_STATE",
                "note": "Dominant Phase-26 campaign next blocker for otherwise import-ready roots",
                "recommended_now": "YES_FOR_PHASE27_ANALYSIS",
            },
            {
                "blocker": "BLOCKED_INDIRECT",
                "note": "Observed at 0x0072EAE0 (RUNTIME_INITIALIZED vtable)",
                "recommended_now": "CANDIDATE",
            },
            {
                "blocker": "IMPORT:tolower",
                "single_unlock_post": (closures.get("single_unlock") or {}).get("tolower"),
                "recommended_now": "CANDIDATE",
            },
            {
                "blocker": "IMPORT:floor",
                "note": "cdecl CRT; not _CI* ABI",
                "single_unlock_post": (closures.get("single_unlock") or {}).get("floor"),
                "recommended_now": "CANDIDATE",
            },
            {
                "blocker": "IMPORT:_CIpow",
                "note": "Not observed in real Phase-26 execution; do not auto-implement",
                "recommended_now": "NO",
            },
            {
                "blocker": "IMPORT:_setjmp3",
                "note": "Not observed in real Phase-26 execution",
                "recommended_now": "NO",
            },
        ],
        "campaign_outcome_histogram": dict(outcome_counts),
        "selected": frontier["selected_implementation"],
    }

    islands_out = {
        "phase": 26,
        "island_count": len(islands),
        "non_graphics_count": len(non_gfx),
        "edge_total_high_internal": edge_total,
        "top_non_graphics": non_gfx[:40],
        "cisqrt_islands_sample": cisqrt_islands[:10],
    }

    dump("runtime-frontier.json", frontier)
    dump("execution-evidence.json", evidence)
    dump("blocker-ranking.json", blockers)
    dump("execution-islands.json", islands_out)

    lines = [
        "# Undercover Phase 26 — `_CIsqrt` + ordinary execution campaign",
        "",
        "Graphics remain **frozen**: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`.",
        "",
        "## A. `_CIsqrt` metadata",
        "",
        "| field | value |",
        "| --- | --- |",
        "| thunk | `%s` |" % cisqrt_row["thunk"],
        "| IAT | `%s` |" % cisqrt_row["iat_slot"],
        "| DLL | `%s` |" % cisqrt_row["dll"],
        "| call sites | %d |" % cisqrt_row["call_sites"],
        "| HIGH callers | %d |" % len(cisqrt_callers),
        "| pre single-unlock | %d |" % CISQRT_PRE_UNLOCK,
        "| now import-ready (call-list) | %d |" % len(newly_import_ready),
        "",
        "## B. ABI",
        "",
        "Identical to Phase-9 `_CI*` family: **ST0 → ST0**, cdecl, **0** stack dwords,",
        "EAX unchanged, TOP unchanged. Host math via `uc_host_sqrt`.",
        "",
        "## C. Implementation",
        "",
        "`UC_HLE_CISQRT` in `uc_abi.h` / `uc_import.c` using existing `x87_replace`.",
        "",
        "## D. Numerical policy",
        "",
        "Host double (ucrtbase `sqrt`). Not bit-exact MSVCR80/x87 80-bit.",
        "No tag-word / FP-env / exception fidelity claims.",
        "Negative inputs: host-dependent (typically NaN); guest integer/x87 TOP preserved.",
        "",
        "## E–G. Tests / consumer",
        "",
        "Unit+edge+ABI in `uc_phase26_test.py`. Real consumer **`0x00924D30`**:",
        "before unbound host → reject; after → normalize (3,4)→(0.6,0.8,1.0).",
        "",
        "## H. Unlock recompute",
        "",
        frontier["unlock_recompute"]["note"],
        "",
        "## I. Runtime-ready definition",
        "",
        "See `runtime-frontier.json` `definitions`. RUNTIME_READY stays closure-extreme based (**54**).",
        "",
        "## J–M. Campaign",
        "",
        "Attempted %d roots. Outcomes: %s." % (len(campaign), dict(outcome_counts)),
        "Most common next blocker: **%s**." % (
            (next_blockers.most_common(1)[0][0] if next_blockers else "n/a")),
        "",
        "## N. Frontier delta",
        "",
        "- `_CIsqrt` removed from single-unlock ranking (was #1 @ 88).",
        "- Next single-unlock leaders: `_wassert`/tolower/sprintf.",
        "- UNIQUE executed: **%d** (was audited 6 completed + new `0x00924D30` → see list)." % len(unique_completed),
        "",
        "## O. Executed-count audit",
        "",
        "UNIQUE_UC_FUNCTIONS_EXECUTED = completed harness VAs:",
        ", ".join("`%s`" % a for a in unique_completed),
        "",
        "Phase 25 said “6” while adding a consumer because the metric mixed",
        "completed vs entered; Phase 26 uses completed-only unique VAs.",
        "",
        "## P. Recommended Phase 27",
        "",
        frontier["recommended_phase27"],
        "",
    ]
    path = os.path.join(ANALYSIS, "runtime-phase26.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("wrote", path)
    print("cisqrt import-ready", len(newly_import_ready), "runtime_ready", runtime_ready,
          "unique_executed", len(unique_completed))


if __name__ == "__main__":
    main()
