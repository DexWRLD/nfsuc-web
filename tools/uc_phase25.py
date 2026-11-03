#!/usr/bin/env python3
"""Phase 25: ordinary (non-graphics) Undercover runtime frontier ranking.

Reads the function map, import ABI, prior runtime-frontier snapshot, and
high-confidence compile counts. Does not execute the game, does not read
protected sections, and does not reopen the frozen graphics backend path.
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
PROTECTED_CALLEES = {
    0x00686000, 0x00686030, 0x00B615C4, 0x004A26B0, 0x007A51B0,
}
GRAPHICS_THUNKS = set()  # filled from import-abi d3d*
SUBMIT = 0x007A51B0


def load_json(name):
    path = os.path.join(ANALYSIS, name)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def hex_u(va):
    return "0x%08X" % (va & 0xFFFFFFFF)


def classify_fn_blockers(imports, callees, thunk_to_sym, implemented):
    tags = set()
    missing = []
    for va in callees:
        if va in PROTECTED_CALLEES or va == SUBMIT:
            tags.add("BLOCKED_PROTECTED")
            if va == SUBMIT:
                tags.add("BLOCKED_GRAPHICS")
                tags.add("BLOCKED_PROTECTED_GRAPHICS")
        sym = thunk_to_sym.get(va)
        if not sym:
            continue
        kind = uf.classify_symbol("", sym) if False else None
        # Prefer dll-aware classification via cached row later.
        if sym not in implemented:
            missing.append(sym)
    for sym in missing:
        kind = uf.classify_symbol("MSVCR80.dll", sym)
        if kind == "GRAPHICS_BOUNDARY":
            tags.add("BLOCKED_GRAPHICS")
        elif kind == "MEMORY_BOUNDARY":
            tags.add("BLOCKED_MEMORY")
        elif kind == "FILESYSTEM_BOUNDARY":
            tags.add("BLOCKED_FILESYSTEM")
        elif kind == "TIMING_BOUNDARY":
            tags.add("BLOCKED_TIMING")
        elif kind == "THREAD_BOUNDARY":
            tags.add("BLOCKED_THREADING")
        elif kind == "KNOWN_IMPORT_MISSING_HLE":
            tags.add("BLOCKED_IMPORT")
        elif kind == "UNKNOWN_RUNTIME_DEPENDENCY":
            tags.add("BLOCKED_EXTERNAL")
        else:
            tags.add("BLOCKED_IMPORT")
    if not tags and not missing:
        tags.add("RUNTIME_READY")
    elif missing and not (tags & {
        "BLOCKED_PROTECTED", "BLOCKED_GRAPHICS", "BLOCKED_PROTECTED_GRAPHICS",
        "BLOCKED_MEMORY", "BLOCKED_FILESYSTEM", "BLOCKED_TIMING",
        "BLOCKED_THREADING", "BLOCKED_EXTERNAL",
    }):
        tags.add("BLOCKED_IMPORT")
    return sorted(tags), missing


def build_islands(high_rows, thunks, implemented, dll_by_sym):
    """Undirected components over HIGH call edges (non-thunk callees)."""
    high = {int(r["va"], 16): r for r in high_rows}
    parent = {va: va for va in high}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    edges = 0
    for va, rec in high.items():
        for cstr in rec.get("calls") or []:
            tgt = int(cstr, 16)
            if tgt in thunks:
                continue
            if tgt in high:
                union(va, tgt)
                edges += 1

    comps = collections.defaultdict(list)
    for va in high:
        comps[find(va)].append(va)

    islands = []
    for root, members in comps.items():
        members = sorted(members)
        imports = collections.Counter()
        indirect = 0
        protected = 0
        graphics = 0
        tls = 0
        blockers = collections.Counter()
        enterable = False
        for va in members:
            rec = high[va]
            for cstr in rec.get("calls") or []:
                tgt = int(cstr, 16)
                if tgt in thunks:
                    sym = thunks[tgt]
                    imports[sym] += 1
                    dll = dll_by_sym.get(sym, "")
                    kind = uf.classify_symbol(dll, sym)
                    if kind == "GRAPHICS_BOUNDARY":
                        graphics += 1
                    if sym not in implemented:
                        if kind == "GRAPHICS_BOUNDARY":
                            blockers["BLOCKED_GRAPHICS"] += 1
                        elif kind == "MEMORY_BOUNDARY":
                            blockers["BLOCKED_MEMORY"] += 1
                        elif kind == "FILESYSTEM_BOUNDARY":
                            blockers["BLOCKED_FILESYSTEM"] += 1
                        elif kind == "TIMING_BOUNDARY":
                            blockers["BLOCKED_TIMING"] += 1
                        elif kind == "THREAD_BOUNDARY":
                            blockers["BLOCKED_THREADING"] += 1
                        elif kind == "KNOWN_IMPORT_MISSING_HLE":
                            blockers["BLOCKED_IMPORT"] += 1
                        else:
                            blockers["BLOCKED_EXTERNAL"] += 1
                elif tgt in PROTECTED_CALLEES:
                    protected += 1
                    blockers["BLOCKED_PROTECTED"] += 1
                    if tgt == SUBMIT:
                        graphics += 1
                        blockers["BLOCKED_GRAPHICS"] += 1
                        blockers["BLOCKED_PROTECTED_GRAPHICS"] += 1
            # Heuristic: MSVC TLS / SEH markers are not in call lists; count
            # reasons text when present.
            reasons = " ".join(rec.get("reasons") or []).lower()
            if "tls" in reasons:
                tls += 1
                blockers["BLOCKED_TLS"] += 1
        missing = sorted(s for s in imports if s not in implemented)
        if not missing and protected == 0 and graphics == 0:
            enterable = True
            blockers["RUNTIME_READY"] += 1
        islands.append({
            "root": hex_u(members[0]),
            "representative": hex_u(members[0]),
            "function_count": len(members),
            "edge_count": 0,  # filled below approximately
            "imports": imports.most_common(12),
            "missing_imports": missing[:16],
            "indirect_calls": indirect,
            "protected_deps": protected,
            "graphics_deps": graphics,
            "tls_members": tls,
            "blockers": dict(blockers),
            "enterable": enterable,
            "executed_member": False,
            "members_sample": [hex_u(v) for v in members[:8]],
            "non_graphics": graphics == 0 and SUBMIT not in {
                int(c, 16) for m in members for c in (high[m].get("calls") or [])
            },
        })

    # Approximate internal edge counts per component.
    root_of = {va: find(va) for va in high}
    edge_by_root = collections.Counter()
    for va, rec in high.items():
        r = root_of[va]
        for cstr in rec.get("calls") or []:
            tgt = int(cstr, 16)
            if tgt in high and root_of[tgt] == r:
                edge_by_root[r] += 1
    by_rep = {find(int(i["root"], 16)): i for i in islands}
    for r, n in edge_by_root.items():
        if r in by_rep:
            by_rep[r]["edge_count"] = n
    return islands, edges


def leverage_score(island):
    n = island["function_count"]
    e = island["edge_count"]
    miss = len(island["missing_imports"])
    prot = island["protected_deps"]
    gfx = island["graphics_deps"]
    score = n * 2 + e
    score -= miss * 40
    score -= prot * 200
    score -= gfx * 250
    if island["enterable"]:
        score += 80
    if island["non_graphics"]:
        score += 50
    # Prefer known CRT-only gaps over opaque externals.
    blockers = island["blockers"]
    if blockers.get("BLOCKED_IMPORT") and not blockers.get("BLOCKED_EXTERNAL"):
        score += 30
    if blockers.get("BLOCKED_EXTERNAL"):
        score -= 40
    return score


def harness_capability():
    return {
        "mapped_ordinary_sections": "IMPLEMENTED",
        "guest_stack": "IMPLEMENTED",
        "direct_uc_calls": "IMPLEMENTED",
        "nested_uc_calls": "IMPLEMENTED",
        "imports_hle": "PARTIAL",
        "x87": "PARTIAL",
        "simd": "PARTIAL",
        "atomics": "PARTIAL",
        "memory_validation": "IMPLEMENTED",
        "indirect_dispatch": "PARTIAL",
        "tls": "STUB",
        "filesystem": "MISSING",
        "threads": "MISSING",
        "timing": "MISSING",
        "seh": "STUB",
        "notes": (
            "Native UC harness maps ordinary PE sections and runs lifted HIGH "
            "functions with import HLE for CRT mem/string and a few x87 helpers. "
            "NFSU2 win32/fileio/thread helpers exist in the broader tree but are "
            "not wired as the Undercover native UC import path. Atomics suffice "
            "for single-thread controlled execution."
        ),
        "atomic_correctness": "SUFFICIENT_FOR_SINGLE_THREAD",
    }


def main():
    fmap = load_json("function-map.json")
    abi = load_json("import-abi.json")
    hc = load_json("high-confidence.json")
    # Closure snapshot from uc_frontier.py (post-strncpy when re-run in Phase 25).
    closures_path = os.path.join(ANALYSIS, "runtime-frontier-closures.json")
    if os.path.isfile(closures_path):
        frontier_prev = load_json("runtime-frontier-closures.json")
    else:
        frontier_prev = load_json("runtime-frontier.json")
    # Pre-Phase-25 single-unlock for strncpy (measured before HLE landed).
    strncpy_unlock_pre = 90

    high_rows = [r for r in fmap["functions"] if r.get("label") == "HIGH_CONFIDENCE"]
    high_count = len(high_rows)
    generated = int(hc.get("generated") or 0)
    compiled = int(hc.get("compiled") or 0)

    thunks = {}
    dll_by_sym = {}
    for row in abi["imports"]:
        sym = row["symbol"] or ("ordinal_%s" % row["ordinal"])
        thunks[int(row["thunk"], 16)] = sym
        dll_by_sym[sym] = row.get("dll") or ""
        if "d3d" in (row.get("dll") or "").lower() or (sym or "").lower().startswith("d3d"):
            GRAPHICS_THUNKS.add(int(row["thunk"], 16))

    implemented = set(uf.IMPLEMENTED)
    islands, edge_total = build_islands(high_rows, thunks, implemented, dll_by_sym)
    for isl in islands:
        isl["leverage"] = leverage_score(isl)
    islands.sort(key=lambda r: (-r["leverage"], -r["function_count"]))

    non_gfx = [i for i in islands if i["non_graphics"]]
    ready_islands = [i for i in islands if i["enterable"] and i["non_graphics"]]

    # Function-level blocker histogram (call-list based; conservative).
    fn_hist = collections.Counter()
    blocked_graphics = blocked_protected = blocked_std = unknown = 0
    runtime_ready_est = 0
    for rec in high_rows:
        va = int(rec["va"], 16)
        imports = []
        protected = False
        graphics = False
        for cstr in rec.get("calls") or []:
            tgt = int(cstr, 16)
            if tgt in thunks:
                imports.append(thunks[tgt])
            if tgt in PROTECTED_CALLEES:
                protected = True
                if tgt == SUBMIT:
                    graphics = True
        missing = [s for s in imports if s not in implemented]
        tags = set()
        if protected:
            tags.add("BLOCKED_PROTECTED")
            blocked_protected += 1
        if graphics:
            tags.add("BLOCKED_GRAPHICS")
            blocked_graphics += 1
        for sym in missing:
            kind = uf.classify_symbol(dll_by_sym.get(sym, ""), sym)
            if kind == "GRAPHICS_BOUNDARY":
                tags.add("BLOCKED_GRAPHICS")
                graphics = True
            elif kind in ("MEMORY_BOUNDARY", "FILESYSTEM_BOUNDARY", "TIMING_BOUNDARY",
                          "THREAD_BOUNDARY", "KNOWN_IMPORT_MISSING_HLE"):
                tags.add("BLOCKED_STANDARD_RUNTIME")
            elif kind == "UNKNOWN_RUNTIME_DEPENDENCY":
                tags.add("UNKNOWN")
            else:
                tags.add("BLOCKED_IMPORT")
        if graphics and "BLOCKED_GRAPHICS" not in tags:
            tags.add("BLOCKED_GRAPHICS")
        if not tags and not missing:
            tags.add("RUNTIME_READY")
            runtime_ready_est += 1
        elif missing and "BLOCKED_PROTECTED" not in tags and "BLOCKED_GRAPHICS" not in tags:
            tags.add("BLOCKED_STANDARD_RUNTIME")
            blocked_std += 1
        if "UNKNOWN" in tags:
            unknown += 1
        for t in tags:
            fn_hist[t] += 1

    # Import frontier with post-strncpy ranking.
    unlock = frontier_prev.get("single_unlock") or {}
    import_rows = []
    for row in abi["imports"]:
        sym = row["symbol"] or ("ordinal_%s" % row["ordinal"])
        status = "IMPLEMENTED_HLE" if sym in implemented else (
            "KNOWN_ABI_UNIMPLEMENTED" if row.get("calling_convention") in (
                "cdecl", "stdcall", "thiscall", "fastcall") and uf.classify_symbol(
                row.get("dll") or "", sym) in (
                "KNOWN_IMPORT_MISSING_HLE", "MEMORY_BOUNDARY", "FILESYSTEM_BOUNDARY",
                "TIMING_BOUNDARY", "THREAD_BOUNDARY", "READY_WITH_IMPLEMENTED_IMPORTS")
            else ("UNKNOWN_ABI" if row.get("calling_convention") == "unknown"
                  else "CONVENTION_KNOWN_NO_HLE")
        )
        pre = unlock.get(sym, 0)
        if sym == "strncpy":
            pre = strncpy_unlock_pre
        import_rows.append({
            "symbol": sym,
            "dll": row.get("dll"),
            "convention": row.get("calling_convention"),
            "call_sites": row.get("call_sites"),
            "status": status,
            "single_unlock_functions_pre_phase25": pre,
            "single_unlock_functions_post": unlock.get(sym, 0) if sym != "strncpy" else 0,
        })
    import_rows.sort(key=lambda r: (
        0 if r["status"] == "IMPLEMENTED_HLE" else 1,
        -int(r["single_unlock_functions_post"] or r["single_unlock_functions_pre_phase25"] or 0),
        -int(r["call_sites"] or 0),
    ))

    top_missing = [r for r in import_rows if r["status"] != "IMPLEMENTED_HLE"]
    top_missing.sort(key=lambda r: -int(r.get("single_unlock_functions_post")
                                        or r["single_unlock_functions_pre_phase25"] or 0))

    # CRT / alloc / FS / timing / threading / TLS / SEH summaries from imports.
    def frontier_bucket(predicate):
        rows = [r for r in abi["imports"] if predicate(r)]
        return {
            "imports": [
                {
                    "symbol": r["symbol"],
                    "call_sites": r["call_sites"],
                    "convention": r["calling_convention"],
                    "implemented": (r["symbol"] or "") in implemented,
                }
                for r in sorted(rows, key=lambda x: -int(x.get("call_sites") or 0))
            ],
            "total_call_sites": sum(int(r.get("call_sites") or 0) for r in rows),
            "unimplemented": sum(
                1 for r in rows if (r["symbol"] or "") not in implemented
            ),
        }

    crt = frontier_bucket(lambda r: (r.get("dll") or "").upper().startswith("MSVCR")
                          or (r.get("symbol") or "") in uf.SIMPLE_CDECL
                          or (r.get("symbol") or "") in implemented)
    alloc = frontier_bucket(lambda r: (r.get("symbol") or "") in (
        "malloc", "free", "_aligned_malloc", "_aligned_free", "calloc", "realloc"))
    filesystem = frontier_bucket(
        lambda r: uf.classify_symbol(r.get("dll") or "", r.get("symbol") or "")
        == "FILESYSTEM_BOUNDARY")
    timing = frontier_bucket(
        lambda r: uf.classify_symbol(r.get("dll") or "", r.get("symbol") or "")
        == "TIMING_BOUNDARY"
        or (r.get("symbol") or "") in (
            "QueryPerformanceCounter", "QueryPerformanceFrequency",
            "timeGetTime", "GetTickCount", "Sleep"))
    threading = frontier_bucket(
        lambda r: uf.classify_symbol(r.get("dll") or "", r.get("symbol") or "")
        == "THREAD_BOUNDARY"
        or (r.get("symbol") or "") in (
            "CreateThread", "WaitForSingleObject", "EnterCriticalSection",
            "LeaveCriticalSection", "InitializeCriticalSection",
            "TlsAlloc", "TlsGetValue", "TlsSetValue", "InterlockedIncrement",
            "InterlockedDecrement", "InterlockedCompareExchange"))

    # Blocker ranking for top 10.
    blocker_impact = collections.Counter()
    for isl in non_gfx:
        for b, n in isl["blockers"].items():
            if b == "RUNTIME_READY":
                continue
            blocker_impact[b] += isl["function_count"]
    # Also weight missing imports as named blockers.
    for isl in non_gfx:
        for sym in isl["missing_imports"][:3]:
            blocker_impact["IMPORT:" + sym] += isl["function_count"]

    top_blockers = []
    for name, affected_fns in blocker_impact.most_common(10):
        affected_islands = sum(
            1 for i in non_gfx
            if name in i["blockers"]
            or (name.startswith("IMPORT:") and name[7:] in i["missing_imports"])
        )
        largest = max(
            (i for i in non_gfx
             if name in i["blockers"]
             or (name.startswith("IMPORT:") and name[7:] in i["missing_imports"])),
            key=lambda i: i["function_count"],
            default=None,
        )
        recommend = "NO"
        if name == "IMPORT:strncpy" or (
            name == "BLOCKED_IMPORT" and any(
                "strncpy" in i["missing_imports"] for i in non_gfx[:20]
            )
        ):
            recommend = "YES"  # already implementing this phase
        elif name.startswith("IMPORT:") and name[7:] in uf.SIMPLE_CDECL:
            recommend = "CANDIDATE"
        top_blockers.append({
            "blocker": name,
            "affected_high_functions": affected_fns,
            "affected_components": affected_islands,
            "largest_component_unlocked": (largest or {}).get("function_count"),
            "largest_component_root": (largest or {}).get("root"),
            "implementation_difficulty": "LOW" if name.startswith("IMPORT:") and name[7:] in (
                set(uf.SIMPLE_CDECL) | {"strncpy"} | implemented
            ) else "MEDIUM",
            "correctness_risk": "LOW" if name.startswith("IMPORT:") else "MEDIUM",
            "protected_dependency_risk": "YES" if "PROTECTED" in name or "GRAPHICS" in name else "NO",
            "recommended_now": recommend if name != "IMPORT:strncpy" else "DONE_PHASE25",
        })

    top_islands = []
    for isl in non_gfx[:10]:
        top_islands.append({
            "root": isl["root"],
            "function_count": isl["function_count"],
            "edge_count": isl["edge_count"],
            "imports": isl["imports"][:8],
            "missing_imports": isl["missing_imports"][:8],
            "indirects": isl["indirect_calls"],
            "initialization": "UNKNOWN",
            "subsystem_guess": (
                "CRT/string" if any(s in ("strncpy", "strlen", "strcmp", "sprintf")
                                    for s, _ in isl["imports"]) else
                "filesystem" if any(
                    uf.classify_symbol(dll_by_sym.get(s, ""), s) == "FILESYSTEM_BOUNDARY"
                    for s, _ in isl["imports"]) else
                "ordinary"
            ),
            "exact_blockers": sorted(isl["blockers"]),
            "estimated_runtime_work": (
                "import HLE only" if isl["missing_imports"] and not isl["protected_deps"]
                else ("enterable" if isl["enterable"] else "multi-blocker")
            ),
            "leverage": isl["leverage"],
        })

    selected = {
        "implementation": "strncpy CRT HLE",
        "symbol": "strncpy",
        "thunk": "0x0087B6A0",
        "why": (
            "Highest single-missing-import unlock in prior frontier "
            "(90 HIGH functions / 66 closures / 244 call sites); cdecl; "
            "standard public CRT semantics; no protected behavior."
        ),
        "standard_public_semantics": True,
        "protected_dependency": False,
    }

    # Phase 25 delta: pre-measured strncpy single-missing-import unlock.
    newly_ready_fns = strncpy_unlock_pre
    extremes = frontier_prev.get("all_node_extremes") or {}
    ready_closure = int((extremes.get("READY") or {}).get("size") or 0)
    ready_imports_closure = int(
        (extremes.get("READY_WITH_IMPLEMENTED_IMPORTS") or {}).get("size") or 0)
    # Prefer closure-based ready sizes over per-function call-list heuristics.
    runtime_ready_closure = ready_closure + ready_imports_closure
    frontier = {
        "phase": 25,
        "high_functions": high_count,
        "generated": generated,
        "compiled": compiled,
        "runtime_ready_estimate": runtime_ready_closure,
        "runtime_ready_note": (
            "RUNTIME_READY uses largest READY + READY_WITH_IMPLEMENTED_IMPORTS "
            "closure sizes from uc_frontier (not compilation). Per-function "
            "call-list heuristic was %d (overcounts leaves)." % runtime_ready_est
        ),
        "executed": 6,
        "executed_note": (
            "Harness-logged only: prior phases 5 recorded + Phase 25 consumer "
            "0x0088390D. COMPILED is not EXECUTED."
        ),
        "blocked_graphics": blocked_graphics,
        "blocked_protected": blocked_protected,
        "blocked_standard_runtime": blocked_std,
        "unknown_blocker": unknown,
        "execution_islands": len(islands),
        "non_graphics_islands": len(non_gfx),
        "largest_non_graphics_island": non_gfx[0] if non_gfx else None,
        "largest_runtime_ready_island": {
            "root": (extremes.get("READY_WITH_IMPLEMENTED_IMPORTS") or {}).get("root")
                    or (extremes.get("READY") or {}).get("root"),
            "function_count": runtime_ready_closure,
            "ready_closure": ready_closure,
            "ready_with_imports_closure": ready_imports_closure,
        },
        "blocker_histogram_functions": dict(fn_hist),
        "import_frontier": {
            "total_thunks": len(abi["imports"]),
            "implemented_hle": sum(1 for r in import_rows if r["status"] == "IMPLEMENTED_HLE"),
            "convention_unknown": sum(
                1 for r in abi["imports"] if r.get("calling_convention") == "unknown"
            ),
            "top_missing_by_prior_unlock": top_missing[:12],
        },
        "crt_frontier": crt,
        "allocation_frontier": alloc,
        "filesystem_frontier": filesystem,
        "timing_frontier": timing,
        "threading_frontier": threading,
        "tls_frontier": {
            "status": "STUB",
            "note": (
                "Prior phases observed substantial fs:[0x2C]/TLS traffic; "
                "no fabricated TLS init this phase. Not the selected unlock."
            ),
        },
        "seh_frontier": {
            "status": "STUB",
            "note": (
                "Ordinary fs:[0] bookkeeping appears in .text; full exception "
                "delivery/unwind is not implemented. Not selected this phase."
            ),
        },
        "indirect_call_frontier": frontier_prev.get("indirect_kinds") or {},
        "ordinary_initialization_frontier": {
            "note": "Prefer enterable non-graphics islands as harness roots.",
            "top_enterable": [
                {"root": i["root"], "functions": i["function_count"]}
                for i in ready_islands[:8]
            ],
        },
        "harness_capability": harness_capability(),
        "selected_implementation": selected,
        "phase25_delta": {
            "newly_runtime_ready_functions_estimate": newly_ready_fns,
            "newly_runtime_ready_note": (
                "Prior single_unlock[strncpy]=%d HIGH functions in otherwise-clean closures."
                % newly_ready_fns
            ),
            "consumer_under_test": "0x0088390D",
        },
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "ordinary_runtime_frontier": {
            "HIGH": high_count,
            "COMPILED": compiled,
            "RUNTIME_READY_EST": runtime_ready_closure,
            "EXECUTED": 6,
            "BLOCKED_STANDARD_RUNTIME": blocked_std,
            "BLOCKED_PROTECTED": blocked_protected,
            "BLOCKED_GRAPHICS": blocked_graphics,
            "UNKNOWN": unknown,
        },
        "top_ordinary_island": top_islands[0] if top_islands else None,
    }

    # Compact island dump (top 40 non-graphics only).
    islands_out = {
        "phase": 25,
        "island_count": len(islands),
        "non_graphics_count": len(non_gfx),
        "edge_total_high_internal": edge_total,
        "top_non_graphics": non_gfx[:40],
    }
    blockers_out = {
        "phase": 25,
        "top_10_blockers": top_blockers,
        "top_10_execution_islands": top_islands,
        "histogram_functions": dict(fn_hist),
        "selected": selected,
    }

    def dump(name, obj):
        path = os.path.join(ANALYSIS, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, indent=2)
            fh.write("\n")
        print("wrote", path)

    dump("runtime-frontier.json", frontier)
    dump("execution-islands.json", islands_out)
    dump("blocker-ranking.json", blockers_out)

    # Human report
    lines = [
        "# Undercover Phase 25 — Ordinary runtime frontier",
        "",
        "Graphics investigation remains **frozen**. "
        "`FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`. "
        "No analysis of `0x007A51B0` / protected submit backend.",
        "",
        "## Counts",
        "",
        "| metric | value |",
        "| --- | ---: |",
        "| HIGH functions | %d |" % high_count,
        "| Generated | %d |" % generated,
        "| Compiled | %d |" % compiled,
        "| RUNTIME_READY (READY + READY_WITH_IMPORTS closures) | %d |" % runtime_ready_closure,
        "| EXECUTED (harness-logged) | 6 |",
        "| BLOCKED_GRAPHICS (call-list) | %d |" % blocked_graphics,
        "| BLOCKED_PROTECTED (call-list) | %d |" % blocked_protected,
        "| BLOCKED_STANDARD_RUNTIME | %d |" % blocked_std,
        "| UNKNOWN | %d |" % unknown,
        "| Execution islands | %d |" % len(islands),
        "| Non-graphics islands | %d |" % len(non_gfx),
        "",
        "## Selected implementation",
        "",
        "**`strncpy` CRT HLE** (`0x0087B6A0`, cdecl, 3 stack dwords).",
        "",
        selected["why"],
        "",
        "Standard/public semantics: YES. Protected dependency: NO.",
        "",
        "## Top blockers (non-graphics weighted)",
        "",
    ]
    for row in top_blockers:
        lines.append(
            "- `%s` — ~%d HIGH fns / %d components; largest %s @ %s; recommend %s"
            % (
                row["blocker"],
                row["affected_high_functions"],
                row["affected_components"],
                row["largest_component_unlocked"],
                row["largest_component_root"],
                row["recommended_now"],
            )
        )
    lines += ["", "## Top non-graphics execution islands", ""]
    for row in top_islands:
        lines.append(
            "- root `%s` — %d fns, missing %s, blockers %s"
            % (
                row["root"],
                row["function_count"],
                ", ".join(row["missing_imports"]) or "none",
                ", ".join(row["exact_blockers"]) or "none",
            )
        )
    lines += [
        "",
        "## Import frontier",
        "",
        "Total thunks: %d. Implemented HLE: %d. Next unlock candidates after strncpy:"
        % (len(abi["imports"]), sum(1 for r in import_rows if r["status"] == "IMPLEMENTED_HLE")),
        "",
    ]
    for row in top_missing[:8]:
        lines.append(
            "- `%s` sites=%s prior_single_unlock=%s (%s)"
            % (row["symbol"], row["call_sites"], row["single_unlock_functions_pre_phase25"], row["status"])
        )
    lines += [
        "",
        "## Frontiers (summary)",
        "",
        "- **CRT**: continue string/math helpers with known cdecl; next after strncpy likely `_CIsqrt` / `tolower` / `sprintf` (format risk).",
        "- **Allocation**: `malloc`/`free` present as MEMORY_BOUNDARY — do not substitute for protected helpers.",
        "- **Filesystem**: CRT/Win32 file imports exist; leverage lower than strncpy this phase.",
        "- **Timing / threading / TLS / SEH**: present as stubs or missing on UC import path; not selected.",
        "- **Indirect calls**: still a major whole-program limiter (see prior frontier kinds).",
        "",
        "## Harness capability",
        "",
    ]
    for k, v in harness_capability().items():
        if k == "notes":
            continue
        lines.append("- %s: **%s**" % (k, v))
    lines += [
        "",
        harness_capability()["notes"],
        "",
        "## Dashboard fields",
        "",
        "- `ORDINARY_RUNTIME_FRONTIER`: see `runtime-frontier.json`",
        "- `TOP ORDINARY ISLAND`: see `execution-islands.json`",
        "- Graphics badges stay frozen (FIRST FRAME blocked / D3D9 not justified / engine backend not justified).",
        "",
        "## Recommended Phase 26",
        "",
        "Re-measure single-missing-import unlock after strncpy; pick the next "
        "**known-ABI CRT** helper with clean closures (likely `_CIsqrt` or another "
        "SIMPLE_CDECL string helper), or expand ordinary initialization roots "
        "that are now enterable. Do not reopen protected graphics.",
        "",
    ]
    path = os.path.join(ANALYSIS, "runtime-phase25.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("wrote", path)
    print("HIGH", high_count, "islands", len(islands), "non_gfx", len(non_gfx),
          "strncpy_unlock_est", newly_ready_fns)


if __name__ == "__main__":
    main()
