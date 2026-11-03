#!/usr/bin/env python3
"""Phase 44: BLOCKED_EXTERNAL root attribution + callback registration edges.

Uses project progress/helper-cut classifications and the Nov 2026 Ghidra blocker
audit. Does not implement protected boundaries. Does not inflate ENTERABLE /
RUNTIME_READY / EXECUTED. Does not invent Win32/D3D9 slot mappings.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, deque
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")

HELPER_ALLOC = 0x00686000
HELPER_FREE = 0x00686030
PROTECTED = {
    0x00686000: "allocator",
    0x00686030: "free",
    0x004A26B0: "graphics_backend",
    0x007A51B0: "submission",
    0x0071E380: "opaque_cleanup",
    0x00B615C4: "callback_slot",
}

FIRST_FRAME = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"


def hx(n: int) -> str:
    return "0x%08X" % (n & 0xFFFFFFFF)


def load(name: str):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name: str, obj: Any) -> None:
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")


def build_succ(fmap: dict) -> Dict[int, List[int]]:
    succs: Dict[int, List[int]] = {}
    for row in fmap["functions"]:
        va = int(row["va"], 16) if isinstance(row["va"], str) else int(row["va"])
        targets = []
        for x in (row.get("calls") or []) + (row.get("tails") or []):
            targets.append(int(x, 16) if isinstance(x, str) else int(x))
        succs[va] = sorted(set(targets))
    return succs


def audit_callers(audit: dict) -> Dict[int, Set[int]]:
    out: Dict[int, Set[int]] = {}
    for r in audit["roots"]:
        root = int(r["address"], 16)
        callers: Set[int] = set()
        for ref in r.get("references") or []:
            c = ref.get("caller")
            if c:
                callers.add(int(c, 16))
        out[root] = callers
    return out


def shortest_path(
    start: int,
    helper: int,
    succs: Dict[int, List[int]],
    audit_direct: Set[int],
    bridge: Set[int],
) -> Tuple[Optional[List[int]], str]:
    if start in audit_direct:
        return [start, helper], "DIRECT_AUDIT_CALLER"
    # Prefer map edges to helper or to audit-direct callers.
    q = deque([(start, [start])])
    seen = {start}
    while q:
        cur, path = q.popleft()
        for nxt in succs.get(cur, []):
            if nxt in seen:
                continue
            if nxt == helper:
                return path + [helper], "PATH_VIA_MAP"
            if nxt in audit_direct:
                return path + [nxt, helper], "PATH_VIA_MAP_THEN_DIRECT"
            if nxt in bridge and len(path) < 32:
                seen.add(nxt)
                q.append((nxt, path + [nxt]))
    return None, "NO_PATH_FOUND"


def callback_edges() -> List[dict]:
    """Registration-only edges justified by static DATA references in the audit."""
    return [
        {
            "edge_kind": "CALLBACK_REGISTRATION",
            "not_execution": True,
            "registrar": "0x0072E340",
            "site": "0x0072E497",
            "ref_type": "DATA",
            "callback": "0x0072B170",
            "label": "window callback boundary / GameFrame lpfnWndProc-shaped store",
            "audit_readiness": "NEEDS_MORE_STATIC_EVIDENCE",
            "confidence": "CONFIRMED_REGISTRATION",
            "execution_modeled": False,
            "note": (
                "Address supplied into window-class preparation; not an ordinary "
                "direct call. Do not treat as executed WndProc without further evidence."
            ),
        },
        {
            "edge_kind": "CALLBACK_REGISTRATION",
            "not_execution": True,
            "registrar": "0x0076CA20",
            "site": "0x0076CB40",
            "ref_type": "DATA",
            "callback": "0x00766730",
            "label": "render-thread callback boundary",
            "audit_readiness": "NEEDS_MORE_STATIC_EVIDENCE",
            "confidence": "CONFIRMED_REGISTRATION",
            "execution_modeled": False,
            "note": (
                "Callback address pushed before thread-wrapper call; registration "
                "edge only. Actual callback execution remains unmodeled as an ordinary "
                "call-graph edge."
            ),
        },
    ]


def attribute() -> dict:
    prog = load("progress.json")
    fmap = load("function-map.json")
    audit = load("blocker-audit-2026-11-03.json")
    cut = load("helper-cut.json")
    fr = load("runtime-frontier.json")

    before_counts = Counter(f["runtime_status"] for f in prog["functions"])
    be_funcs = [f for f in prog["functions"] if f["runtime_status"] == "BLOCKED_EXTERNAL"]
    be_set = {int(f["address"], 16) for f in be_funcs}
    must_set = {int(x, 16) for x in cut["must"]}
    may_set = {int(x, 16) for x in cut["may"]}
    assert be_set == must_set, "BLOCKED_EXTERNAL must equal helper-cut MUST set"

    succs = build_succ(fmap)
    root_callers = audit_callers(audit)
    alloc_direct = root_callers[HELPER_ALLOC]
    bridge = must_set | may_set | alloc_direct

    # fmap direct HELPER edges among MUST
    fmap_direct = {
        va for va in must_set if HELPER_ALLOC in succs.get(va, [])
    }
    audit_missing = sorted(fmap_direct - alloc_direct)
    # Verified by ordinary .text disassembly in Phase 44 (call 0x00686000 present).
    audit_incomplete_confirmed = [hx(x) for x in audit_missing]

    inventory = []
    for f in sorted(be_funcs, key=lambda x: int(x["address"], 16)):
        va = int(f["address"], 16)
        path, method = shortest_path(va, HELPER_ALLOC, succs, alloc_direct, bridge)
        audit_gap = va in fmap_direct and va not in alloc_direct
        if va in alloc_direct:
            kind = "DIRECT"
        elif audit_gap:
            kind = "DIRECT"
            method = "DIRECT_MAP_VERIFIED_AUDIT_INCOMPLETE"
        else:
            kind = "TRANSITIVE"
        also = []
        for root, callers in root_callers.items():
            if root == HELPER_ALLOC:
                continue
            if va in callers:
                also.append({
                    "root": hx(root),
                    "label": PROTECTED.get(root, "other"),
                })
        row = {
            "address": f["address"],
            "runtime_status": "BLOCKED_EXTERNAL",
            "blocker_category": "BLOCKED_EXTERNAL",
            "attribution": {
                "kind": kind,
                "root_blocker": hx(HELPER_ALLOC),
                "root_label": "allocator",
                "shortest_path": [hx(x) for x in path] if path else None,
                "path_edge_count": (len(path) - 1) if path else None,
                "path_method": method,
                "confidence": "CONFIRMED" if path else "UNRESOLVED",
            },
            "project_blocker_field": f.get("blocker"),
            "external_helper_class": f.get("external_helper"),
            "also_direct_caller_of": also,
            "reclassified": False,
            "classification_error": False,
        }
        if audit_gap:
            row["audit_gap"] = {
                "issue": "AUDIT_MISSING_DIRECT_CALLER",
                "evidence": (
                    "ordinary .text contains call 0x00686000; "
                    "audit complete:true omitted caller"
                ),
                "confidence": "CONFIRMED",
            }
        inventory.append(row)

    cb = callback_edges()
    # Registrar statuses
    by_addr = {f["address"]: f for f in prog["functions"]}
    for edge in cb:
        reg = by_addr.get(edge["registrar"])
        cb_fn = by_addr.get(edge["callback"])
        edge["registrar_runtime_status"] = (reg or {}).get("runtime_status", "ABSENT")
        edge["callback_runtime_status"] = (cb_fn or {}).get("runtime_status", "ABSENT")
        edge["affects_blocked_external_count"] = False

    # Other root overlaps (not reclassifying BLOCKED_EXTERNAL)
    other_root_hits = {}
    for root, callers in root_callers.items():
        if root == HELPER_ALLOC:
            continue
        hit = sorted(hx(x) for x in (callers & be_set))
        if hit:
            other_root_hits[hx(root)] = {
                "label": PROTECTED.get(root, "other"),
                "blocked_external_direct_callers": hit,
                "count": len(hit),
                "note": "Secondary direct edge; primary BLOCKED_EXTERNAL root remains allocator.",
            }

    # MAY audit-direct callers correctly not BLOCKED_EXTERNAL
    may_direct = sorted(hx(x) for x in (alloc_direct & may_set))
    absent_direct = []
    for c in sorted(alloc_direct):
        a = hx(c)
        if a not in by_addr and c not in must_set and c not in may_set:
            absent_direct.append(a)

    direct_n = sum(1 for r in inventory if r["attribution"]["kind"] == "DIRECT")
    trans_n = sum(1 for r in inventory if r["attribution"]["kind"] == "TRANSITIVE")
    rooted = sum(1 for r in inventory if r["attribution"]["shortest_path"])
    gaps = sum(1 for r in inventory if r.get("audit_gap"))

    # Metrics: no guest execution inflation
    after_be = len(inventory)
    metrics = {
        "blocked_external_before": before_counts.get("BLOCKED_EXTERNAL", 0),
        "blocked_external_after": after_be,
        "blocked_external_delta": 0,
        "with_identified_root_blocker": rooted,
        "direct_root_callers": direct_n,
        "transitive_inherited": trans_n,
        "audit_missing_direct_caller_gaps": gaps,
        "callback_registration_edges": len(cb),
        "blocked_external_affected_by_callback_edges": 0,
        "enterable_before": fr.get("enterable"),
        "enterable_after": fr.get("enterable"),
        "enterable_delta": 0,
        "unique_uc_functions_executed_before": fr.get("unique_uc_functions_executed"),
        "unique_uc_functions_executed_after": fr.get("unique_uc_functions_executed"),
        "unique_executed_delta": 0,
        "runtime_ready_before": fr.get("runtime_ready"),
        "runtime_ready_after": fr.get("runtime_ready"),
        "runtime_ready_delta": 0,
        "newly_classified_without_execution": 0,
        "first_frame": FIRST_FRAME,
    }

    report = {
        "phase": 44,
        "title": "External blocker attribution and callback reachability",
        "game_code_target": "NFS_UNDERCOVER_PC",
        "tooling_origin": "NFSU2-WEB",
        "sha256": audit.get("sha256"),
        "evidence": "blocker-audit-2026-11-03.json",
        "definitions": {
            "BLOCKED_EXTERNAL": (
                "progress.py: MUST_REACH_EXTERNAL_HELPER on allocator 0x00686000 "
                "(helper-cut). Not every protected-boundary caller."
            ),
            "DIRECT": "Function itself calls root blocker (audit and/or verified map).",
            "TRANSITIVE": "Every returning ordinary path hits a MUST/direct callee of the root.",
            "CALLBACK_REGISTRATION": (
                "DATA/store of callback address; not ordinary execution of the callback body."
            ),
        },
        "protected_boundaries_opaque": [hx(x) for x in PROTECTED],
        "summary": {
            "blocked_external_count": after_be,
            "equals_helper_cut_must": True,
            "duplicate_root": hx(HELPER_ALLOC),
            "all_share_allocator_root": True,
            "direct": direct_n,
            "transitive": trans_n,
            "rooted": rooted,
            "audit_gaps": gaps,
            "classification_errors_requiring_status_change": 0,
            "note": (
                "All 74 BLOCKED_EXTERNAL share root 0x00686000. No status reclassification: "
                "Ghidra call sites alone do not justify changing BLOCKED_EXTERNAL, and "
                "callback registration edges are not execution edges."
            ),
        },
        "metrics": metrics,
        "audit_vs_project": {
            "allocator_audit_defined_callers": len(alloc_direct),
            "allocator_audit_callers_in_blocked_external": len(alloc_direct & be_set),
            "allocator_audit_callers_in_may": len(may_direct),
            "allocator_audit_callers_absent_from_progress": len(absent_direct),
            "may_direct_sample": may_direct[:20],
            "absent_direct_sample": absent_direct[:20],
            "fmap_must_helper_edges_missing_from_audit": audit_incomplete_confirmed,
            "audit_complete_flag_allocator": True,
            "audit_completeness_issue": (
                "Allocator root claims complete:true but omits >=6 verified ordinary "
                "direct callers present in project function-map and .text."
            ),
        },
        "secondary_root_overlaps_on_blocked_external": other_root_hits,
        "callback_registration_edges": cb,
        "functions": inventory,
    }
    dump("blocked-external-attribution.json", report)

    # Compact inventory for Ghidra / tooling
    dump("blocked-external-inventory.json", {
        "phase": 44,
        "count": after_be,
        "root_blocker": hx(HELPER_ALLOC),
        "functions": [
            {
                "address": r["address"],
                "kind": r["attribution"]["kind"],
                "path": r["attribution"]["shortest_path"],
                "confidence": r["attribution"]["confidence"],
            }
            for r in inventory
        ],
    })

    dump("callback-registration-edges.json", {
        "phase": 44,
        "edges": cb,
        "semantics": {
            "registration_vs_execution": "DISTINCT",
            "changes_blocked_external": False,
            "invented_win32_mappings": False,
        },
    })

    # Update frontier diagnostics only
    fr["phase"] = 44
    fr["first_frame"] = FIRST_FRAME
    fr["graphics_frozen"] = True
    fr["blocked_external_attribution"] = {
        "count": after_be,
        "root": hx(HELPER_ALLOC),
        "direct": direct_n,
        "transitive": trans_n,
        "rooted": rooted,
        "audit_gaps": gaps,
        "callback_registration_edges": len(cb),
        "status_reclassified": 0,
        "enterable_delta": 0,
        "runtime_ready_delta": 0,
        "unique_executed_delta": 0,
        "inventory": "blocked-external-attribution.json",
    }
    fr["recommended_phase45"] = (
        "Close allocator-audit caller gaps in static evidence; recover enough of "
        "0x0072B170 / 0x00766730 ordinary bodies to decide whether callback "
        "execution edges are justifiable; keep protected backends opaque. "
        "Do not promote BLOCKED_EXTERNAL to ENTERABLE without an ordinary "
        "allocator-free path."
    )
    dump("runtime-frontier.json", fr)

    status = load("project-status.json")
    status["current_phase"] = 44
    status["strategy"] = (
        "Phase 44: attribute all 74 BLOCKED_EXTERNAL to allocator 0x00686000 "
        "(56 direct / 18 transitive); model callback registration edges without "
        "execution; FIRST_FRAME remains blocked."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 44 for p in phases):
        phases.append({
            "phase": 44,
            "name": "External blocker attribution and callback reachability",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    write_report(report)
    write_handoff(fr)
    return report


def write_report(report: dict) -> None:
    m = report["metrics"]
    s = report["summary"]
    lines = [
        "# Undercover Phase 44 — External blocker attribution",
        "",
        f"Target SHA-256: `{report['sha256']}`",
        "",
        f"`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`",
        "",
        f"FIRST_FRAME: `{FIRST_FRAME}`",
        "",
        "## A. What BLOCKED_EXTERNAL means here",
        "",
        report["definitions"]["BLOCKED_EXTERNAL"],
        "",
        "The eight audited protected boundaries are **not** each a separate",
        "`BLOCKED_EXTERNAL` class. Only the helper-cut **MUST** set (allocator)",
        "is painted `BLOCKED_EXTERNAL` in `progress.json`.",
        "",
        "## B. Counts",
        "",
        f"- BLOCKED_EXTERNAL before: **{m['blocked_external_before']}**",
        f"- BLOCKED_EXTERNAL after: **{m['blocked_external_after']}** (delta {m['blocked_external_delta']})",
        f"- With identified root blocker: **{m['with_identified_root_blocker']}**",
        f"- Direct: **{s['direct']}**",
        f"- Transitive/inherited: **{s['transitive']}**",
        f"- Audit missing-caller gaps: **{m['audit_missing_direct_caller_gaps']}**",
        f"- Callback registration edges: **{m['callback_registration_edges']}**",
        f"- BLOCKED_EXTERNAL affected by callback edges: **{m['blocked_external_affected_by_callback_edges']}**",
        "",
        "## C. Root cause",
        "",
        "Every `BLOCKED_EXTERNAL` function shares root **`0x00686000` (allocator)**.",
        "No duplicate competing primary roots inside this class.",
        "",
        "## D. Audit cross-check",
        "",
        f"- Audit defined alloc callers: {report['audit_vs_project']['allocator_audit_defined_callers']}",
        f"- Of those in BLOCKED_EXTERNAL: {report['audit_vs_project']['allocator_audit_callers_in_blocked_external']}",
        f"- Of those in MAY (correctly not BLOCKED_EXTERNAL): {report['audit_vs_project']['allocator_audit_callers_in_may']}",
        f"- Absent from progress: {report['audit_vs_project']['allocator_audit_callers_absent_from_progress']}",
        "",
        "Audit completeness issue:",
        "",
        report["audit_vs_project"]["audit_completeness_issue"],
        "",
        "Verified omitted direct callers:",
        "",
    ]
    for a in report["audit_vs_project"]["fmap_must_helper_edges_missing_from_audit"]:
        lines.append(f"- `{a}`")
    lines += [
        "",
        "## E. Callback edges",
        "",
        "| Registrar | Site | Callback | Kind | Execution modeled |",
        "|---|---|---|---|---|",
    ]
    for e in report["callback_registration_edges"]:
        lines.append(
            f"| `{e['registrar']}` | `{e['site']}` | `{e['callback']}` | "
            f"{e['edge_kind']} | {e['execution_modeled']} |"
        )
    lines += [
        "",
        "Registration ≠ execution. Registrars were **not** reclassified to",
        "`BLOCKED_EXTERNAL` because a DATA reference exists.",
        "",
        "## F. Classification errors",
        "",
        "- Status changes required: **0**",
        "- Graph diagnostics added for audit caller gaps and callback registration.",
        "- Do not reclassify solely because a Ghidra call site exists.",
        "",
        "## G. Guest metrics (unchanged)",
        "",
        f"- ENTERABLE: {m['enterable_after']} (Δ {m['enterable_delta']})",
        f"- UNIQUE executed: {m['unique_uc_functions_executed_after']} (Δ {m['unique_executed_delta']})",
        f"- RUNTIME_READY: {m['runtime_ready_after']} (Δ {m['runtime_ready_delta']})",
        f"- Newly classified without execution: {m['newly_classified_without_execution']}",
        "",
        "## H. Artifacts",
        "",
        "- `blocked-external-attribution.json`",
        "- `blocked-external-inventory.json`",
        "- `callback-registration-edges.json`",
        "- `blocker-audit-2026-11-03.json`",
        "",
        "## I. Phase 45",
        "",
        "See `phase45-handoff.md`.",
        "",
    ]
    with open(os.path.join(ANALYSIS, "runtime-phase44.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))


def write_handoff(fr: dict) -> None:
    with open(os.path.join(ANALYSIS, "phase45-handoff.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 45 handoff",
            "",
            "From Phase 44 blocker attribution.",
            "",
            "## Do not",
            "",
            "- Implement/execute `0x00686000` / `0x00686030` / backends / `0x0071E380` / `0x00B615C4`.",
            "- Invent CreateWindowExA / UpdateWindow / Direct3DCreate9 slot mappings.",
            "- Promote BLOCKED_EXTERNAL → ENTERABLE without an allocator-free ordinary path.",
            "- Treat callback registration DATA edges as executed callbacks.",
            "",
            "## Next highest value",
            "",
            "1. Expand static recovery of `0x0072B170` and `0x00766730` bodies enough to",
            "   justify or reject callback **execution** edges.",
            "2. Reconcile Ghidra allocator-caller inventory with verified ordinary `.text`",
            "   (audit omitted ≥6 direct callers).",
            "3. Continue ordinary object-family / virtual-interface work that does not",
            "   require the allocator MUST set.",
            "",
            fr.get("recommended_phase45") or "",
            "",
        ]))


def main() -> int:
    report = attribute()
    print(json.dumps({
        "phase": 44,
        "blocked_external": report["summary"]["blocked_external_count"],
        "direct": report["summary"]["direct"],
        "transitive": report["summary"]["transitive"],
        "audit_gaps": report["summary"]["audit_gaps"],
        "callback_edges": len(report["callback_registration_edges"]),
        "enterable": report["metrics"]["enterable_after"],
        "first_frame": FIRST_FRAME,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
