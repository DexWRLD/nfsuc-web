"""Build the Undercover status dashboard from analysis JSON.

Reads function-map.json, high-confidence.json, runtime-frontier.json,
import-abi.json, helper-cut.json, and project-status.json. Writes
progress.json, progress.svg, and progress.html. Does not read the game,
protected sections, or generated C, and does not change classifications.
"""

import html
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_frontier as uf

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
PROTECTED = ("Stext", "Sitext", "Srdata", "Sdata", "Sidata", ".securom")


def load_angr_cached():
    """Read cached angr/oracle metadata. Never runs angr."""
    path = os.path.join(ANALYSIS, "angr", "summary.json")
    gfx_path = os.path.join(ANALYSIS, "angr", "graphics-phase21.json")
    p22_path = os.path.join(ANALYSIS, "angr", "renderer-phase22.json")
    p23_path = os.path.join(ANALYSIS, "angr", "renderer-phase23.json")
    out = {
        "status": "NOT RUN",
        "version": None,
        "present_control": "NOT RUN",
        "clear_control": "NOT RUN",
        "overlap": None,
        "boundary_disagreements": None,
        "device_to_renderer": None,
        "draw_consensus": None,
        "renderer_list": None,
        "backend_handoff": None,
        "raw_device_draw": None,
        "durable_device_alias": None,
        "frame_root": None,
        "graphics_boundary": None,
        "vector_insertion": None,
        "element_plus04": None,
        "iface_publication": None,
        "vtable_class": None,
        "method_148_terminus": None,
        "method_14c_terminus": None,
        "method_154_terminus": None,
        "post_init_seam": None,
        "d3d9": None,
        "engine_backend_adapter": None,
        "first_frame": None,
        "engine_frontend": None,
        "submit_backend": None,
        "visible_submit_contract": None,
        "raw_d3d9_resource_traffic": None,
        "frame_correlation": None,
        "graphics_architecture": None,
        "safe_runtime_seam": None,
    }
    if os.path.isfile(path):
        try:
            s = json.load(open(path, encoding="utf-8"))
            if s.get("angr_available") and s.get("cfg_ok"):
                out["status"] = "AVAILABLE"
            elif s.get("angr_available"):
                out["status"] = "AVAILABLE"
            else:
                out["status"] = "NOT RUN"
            out["version"] = s.get("angr_version")
            pc = s.get("present_control") or ""
            cc = s.get("clear_control") or ""
            out["present_control"] = pc.replace("ANGR_PRESENT_CONTROL_", "") or "NOT RUN"
            out["clear_control"] = cc.replace("ANGR_CLEAR_CONTROL_", "") or "NOT RUN"
        except Exception:
            pass
    if os.path.isfile(gfx_path):
        try:
            g = json.load(open(gfx_path, encoding="utf-8"))
            dash = g.get("dashboard") or {}
            out["device_to_renderer"] = dash.get("DEVICE_TO_RENDERER") or (g.get("relationship") or {}).get("CONSENSUS")
            out["draw_consensus"] = dash.get("DRAW_CONSENSUS")
            out["boundary_disagreements"] = dash.get("BOUNDARY_DISAGREEMENTS")
            out["overlap"] = dash.get("FUNCTION_OVERLAP")
            if dash.get("ANGR"):
                out["status"] = dash.get("ANGR")
            if dash.get("PRESENT_CONTROL"):
                out["present_control"] = dash.get("PRESENT_CONTROL")
            if dash.get("CLEAR_CONTROL"):
                out["clear_control"] = dash.get("CLEAR_CONTROL")
            if dash.get("ANGR_VERSION"):
                out["version"] = dash.get("ANGR_VERSION")
        except Exception:
            pass
    if os.path.isfile(p22_path):
        try:
            g = json.load(open(p22_path, encoding="utf-8"))
            dash = g.get("dashboard") or {}
            out["renderer_list"] = dash.get("RENDERER_LIST")
            out["backend_handoff"] = dash.get("BACKEND_HANDOFF")
            out["raw_device_draw"] = dash.get("RAW_DEVICE_DRAW")
            out["durable_device_alias"] = dash.get("DURABLE_DEVICE_ALIAS")
            out["frame_root"] = dash.get("FRAME_ROOT")
            out["graphics_boundary"] = dash.get("GRAPHICS_BOUNDARY")
            if dash.get("ANGR"):
                out["status"] = dash.get("ANGR")
            if dash.get("DRAW_CODE"):
                out["draw_consensus"] = dash.get("DRAW_CONSENSUS") or out["draw_consensus"] or "ENGINE_COM_DRAW"
        except Exception:
            pass
    if os.path.isfile(p23_path):
        try:
            g = json.load(open(p23_path, encoding="utf-8"))
            dash = g.get("dashboard") or {}
            out["vector_insertion"] = dash.get("VECTOR_INSERTION")
            out["element_plus04"] = dash.get("ELEMENT_PLUS04")
            out["iface_publication"] = dash.get("INTERFACE_PUBLICATION")
            out["vtable_class"] = dash.get("VTABLE")
            out["method_148_terminus"] = dash.get("METHOD_148_TERMINUS")
            out["method_14c_terminus"] = dash.get("METHOD_14C_TERMINUS")
            out["method_154_terminus"] = dash.get("METHOD_154_TERMINUS")
            out["raw_device_draw"] = dash.get("RAW_DEVICE_DRAW") or out["raw_device_draw"]
            out["graphics_boundary"] = dash.get("GRAPHICS_BOUNDARY") or out["graphics_boundary"]
            out["post_init_seam"] = dash.get("POST_INIT_SEAM")
            out["d3d9"] = dash.get("D3D9")
            out["engine_backend_adapter"] = dash.get("ENGINE_BACKEND_ADAPTER")
            out["first_frame"] = dash.get("FIRST_FRAME")
            if dash.get("ENGINE_GFX_IFACE_00"):
                out["renderer_list"] = dash.get("ENGINE_GFX_IFACE_00")
        except Exception:
            pass
    # Prefer phase23-raw dashboard when present
    p23_raw = os.path.join(ANALYSIS, "phase23-raw.json")
    if os.path.isfile(p23_raw):
        try:
            g = json.load(open(p23_raw, encoding="utf-8"))
            dash = g.get("dashboard") or {}
            for k_src, k_dst in (
                ("VECTOR_INSERTION", "vector_insertion"),
                ("ELEMENT_PLUS04", "element_plus04"),
                ("INTERFACE_PUBLICATION", "iface_publication"),
                ("VTABLE", "vtable_class"),
                ("METHOD_148_TERMINUS", "method_148_terminus"),
                ("METHOD_14C_TERMINUS", "method_14c_terminus"),
                ("METHOD_154_TERMINUS", "method_154_terminus"),
                ("RAW_DEVICE_DRAW", "raw_device_draw"),
                ("GRAPHICS_BOUNDARY", "graphics_boundary"),
                ("POST_INIT_SEAM", "post_init_seam"),
                ("D3D9", "d3d9"),
                ("ENGINE_BACKEND_ADAPTER", "engine_backend_adapter"),
                ("FIRST_FRAME", "first_frame"),
            ):
                if dash.get(k_src) is not None:
                    out[k_dst] = dash.get(k_src)
        except Exception:
            pass
    p24_raw = os.path.join(ANALYSIS, "phase24-raw.json")
    if os.path.isfile(p24_raw):
        try:
            g = json.load(open(p24_raw, encoding="utf-8"))
            dash = g.get("dashboard") or {}
            for k_src, k_dst in (
                ("ENGINE_FRONTEND", "engine_frontend"),
                ("SUBMIT_BACKEND", "submit_backend"),
                ("VISIBLE_SUBMIT_CONTRACT", "visible_submit_contract"),
                ("RAW_D3D9_RESOURCE_TRAFFIC", "raw_d3d9_resource_traffic"),
                ("FRAME_CORRELATION", "frame_correlation"),
                ("GRAPHICS_ARCHITECTURE", "graphics_architecture"),
                ("SAFE_RUNTIME_SEAM", "safe_runtime_seam"),
                ("FIRST_FRAME", "first_frame"),
                ("D3D9", "d3d9"),
                ("ENGINE_BACKEND_ADAPTER", "engine_backend_adapter"),
                ("GRAPHICS_BOUNDARY", "graphics_boundary"),
            ):
                if dash.get(k_src) is not None:
                    out[k_dst] = dash.get(k_src)
        except Exception:
            pass
    return out

TRANSLATION_COLOR = {
    "COMPILED": "#3fb950",
    "GENERATED_NOT_COMPILED": "#d29922",
    "DISCOVERED_NOT_GENERATED": "#6e7681",
    "BOUNDARY_PROBLEM": "#f0883e",
    "REJECTED_DATA": "#f85149",
    "UNKNOWN": "#484f58",
}
RUNTIME_COLOR = {
    "EXECUTED": "#56d364",
    "READY": "#2ea043",
    "RUNTIME_READY_NOT_EXECUTED": "#39c5cf",
    "BLOCKED_INITIALIZATION": "#d29922",
    "BLOCKED_INDIRECT": "#db6d28",
    "BLOCKED_IMPORT": "#e3b341",
    "BLOCKED_EXTERNAL": "#f85149",
    "PROTECTED_BOUNDARY": "#ff7b72",
    "UNKNOWN": "#484f58",
}
RUNTIME_RANK = {name: i for i, name in enumerate((
    "EXECUTED", "BLOCKED_EXTERNAL", "RUNTIME_READY_NOT_EXECUTED",
    "PROTECTED_BOUNDARY", "BLOCKED_INDIRECT", "BLOCKED_IMPORT",
    "BLOCKED_INITIALIZATION", "UNKNOWN",
))}
FRONTIER_STATUS = {
    "PROTECTED_BOUNDARY": "PROTECTED_BOUNDARY",
    "UNRESOLVED_INDIRECT_CALL": "BLOCKED_INDIRECT",
    "RESOLVABLE_INDIRECT_CALL": "BLOCKED_INDIRECT",
    "READY": "RUNTIME_READY_NOT_EXECUTED",
    "READY_WITH_IMPLEMENTED_IMPORTS": "RUNTIME_READY_NOT_EXECUTED",
    "KNOWN_IMPORT_MISSING_HLE": "BLOCKED_IMPORT",
    "UNKNOWN_IMPORT_ABI": "BLOCKED_IMPORT",
    "TIMING_BOUNDARY": "BLOCKED_IMPORT",
    "FILESYSTEM_BOUNDARY": "BLOCKED_IMPORT",
    "MEMORY_BOUNDARY": "BLOCKED_IMPORT",
    "NETWORK_BOUNDARY": "BLOCKED_IMPORT",
    "TLS_BOUNDARY": "BLOCKED_IMPORT",
}
BG = "#0d1117"
PANEL = "#161b22"
LINE = "#30363d"
TEXT = "#e6edf3"
MUTED = "#8b949e"
WIDTH = 1080


def load_json(name):
    path = os.path.join(ANALYSIS, name)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def hex_addr(text):
    return int(text, 16)


def worst_ratio(row, side):
    area = sum(row)
    return max(max((side * side * item) / (area * area), (area * area) / (side * side * item)) for item in row)


def place_row(row, x, y, w, h):
    thickness = sum(row) / min(w, h)
    offset = 0.0
    placed = []
    for area in row:
        length = area / thickness
        if w >= h:
            placed.append((x, y + offset, thickness, length))
        else:
            placed.append((x + offset, y, length, thickness))
        offset += length
    if w >= h:
        return placed, (x + thickness, y, w - thickness, h)
    return placed, (x, y + thickness, w, h - thickness)


def squarify(weights, x, y, w, h):
    """Squarified layout. Weights stay in the order they are given."""
    total = sum(weights)
    if total <= 0 or w <= 0 or h <= 0:
        return [(x, y, w, h) for _ in weights]
    areas = [weight * w * h / total for weight in weights]
    rects = []
    row = []
    while areas:
        side = min(w, h)
        if side <= 0:
            break
        if not row or worst_ratio(row + [areas[0]], side) <= worst_ratio(row, side):
            row.append(areas.pop(0))
            continue
        placed, (x, y, w, h) = place_row(row, x, y, w, h)
        rects.extend(placed)
        row = []
    if row:
        placed, _ = place_row(row, x, y, w, h)
        rects.extend(placed)
    while len(rects) < len(weights):
        rects.append((x, y, 0, 0))
    return rects


def snap(rect):
    x, y, w, h = rect
    return int(round(x)), int(round(y)), max(0, int(round(w))), max(0, int(round(h)))


def cell_boxes(count, x, y, w, h):
    if count <= 0 or w <= 0 or h <= 0:
        return []
    cols = max(1, int(round(math.sqrt(count * max(w, 1) / max(h, 1)))))
    cols = min(cols, count)
    rows = (count + cols - 1) // cols
    boxes = []
    index = 0
    for row in range(rows):
        cols_here = min(cols, count - index)
        for col in range(cols_here):
            left = x + (col * w) // cols_here
            right = x + ((col + 1) * w) // cols_here
            top = y + (row * h) // rows
            bottom = y + ((row + 1) * h) // rows
            if right - left > 1 and bottom - top > 1:
                boxes.append((left, top, right - left - 1, bottom - top - 1))
            else:
                boxes.append((left, top, max(1, right - left), max(1, bottom - top)))
            index += 1
    return boxes


def better(current, proposed):
    if proposed is None:
        return current
    if current is None or RUNTIME_RANK[proposed] < RUNTIME_RANK[current]:
        return proposed
    return current


def load_frontier_pair():
    """Closure frontier (uc_frontier) plus Phase-25 ordinary frontier summary."""
    closures_path = os.path.join(ANALYSIS, "runtime-frontier-closures.json")
    ordinary_path = os.path.join(ANALYSIS, "runtime-frontier.json")
    closures = {}
    ordinary = {}
    if os.path.isfile(closures_path):
        closures = json.load(open(closures_path, encoding="utf-8"))
    raw = json.load(open(ordinary_path, encoding="utf-8")) if os.path.isfile(ordinary_path) else {}
    if raw.get("all_node_extremes"):
        # Still the classic closure document.
        closures = raw
    elif raw.get("ordinary_runtime_frontier") or raw.get("phase") == 25:
        ordinary = raw
        if not closures and os.path.isfile(closures_path):
            closures = json.load(open(closures_path, encoding="utf-8"))
    else:
        closures = raw
    return closures, ordinary


def build():
    function_map = load_json("function-map.json")
    compiled = load_json("high-confidence.json")
    frontier, ordinary = load_frontier_pair()
    abi = load_json("import-abi.json")
    status = load_json("project-status.json")
    pe = load_json("nfs-pe.json")
    helper_path = os.path.join(ANALYSIS, "helper-cut.json")
    helper = json.load(open(helper_path, encoding="utf-8")) if os.path.isfile(helper_path) else None

    thunks = {}
    for row in abi["imports"]:
        thunks[hex_addr(row["thunk"])] = row
    protected_spans = []
    for sec in pe["sections"]:
        if sec["name"] in PROTECTED:
            protected_spans.append((sec["va"], sec["end"], sec["name"]))

    failed = {hex_addr(item) for item in compiled["failed_functions"]}
    compiler_failed = {hex_addr(item) for item in compiled["compiler_failed_functions"]}
    rows = sorted(function_map["functions"], key=lambda row: hex_addr(row["va"]))
    reachable_high = [
        row for row in rows
        if row["label"] == "HIGH_CONFIDENCE" and row.get("reachable")
    ]
    demoted_compiled = set()
    if function_map.get("phase4_high_confidence") == compiled["attempted"]:
        gap = compiled["attempted"] - compiled["generated"]
        extra = function_map["phase4_high_confidence"] - gap - len(reachable_high)
        rejected_extra = [
            hex_addr(row["va"]) for row in rows
            if row["label"] == "REJECTED_DATA_LIKE" and hex_addr(row["va"]) not in failed
            and row.get("reachable")
        ]
        if extra == len(rejected_extra):
            demoted_compiled = set(rejected_extra)

    recorded = {hex_addr(item["address"]): item for item in status["recorded_execution"]}
    helper_class = {}
    if helper:
        for addr in helper["must"]:
            helper_class[hex_addr(addr)] = "MUST_REACH_EXTERNAL_HELPER"
        for addr in helper["may"]:
            helper_class[hex_addr(addr)] = "MAY_REACH_EXTERNAL_HELPER"

    frontier_hit = {}
    blocks = dict(frontier.get("all_node_extremes") or {})
    if "only_indirect" in frontier:
        blocks["only_indirect"] = frontier["only_indirect"]
    for key, rec in blocks.items():
        if not isinstance(rec, dict):
            continue
        label = rec.get("label") or key
        mapped = FRONTIER_STATUS.get(label)
        for addr in rec.get("functions") or []:
            va = hex_addr(addr)
            frontier_hit.setdefault(va, [])
            frontier_hit[va].append((mapped, label))

    functions = []
    for row in rows:
        va = hex_addr(row["va"])
        label = row["label"]
        calls = [hex_addr(item) for item in (row.get("calls") or [])]
        tails = [hex_addr(item) for item in (row.get("tails") or [])]
        targets = calls + tails
        if va in compiler_failed:
            translation = "GENERATED_NOT_COMPILED"
        elif va in failed:
            translation = "BOUNDARY_PROBLEM"
        elif label == "REJECTED_DATA_LIKE":
            translation = "REJECTED_DATA"
        elif label == "HIGH_CONFIDENCE" and row.get("reachable"):
            translation = "COMPILED"
        elif label in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE", "LOW_CONFIDENCE"):
            translation = "DISCOVERED_NOT_GENERATED"
        else:
            translation = "UNKNOWN"
        generated = translation in ("COMPILED", "GENERATED_NOT_COMPILED") or va in demoted_compiled
        compiled_ok = translation == "COMPILED" or va in demoted_compiled

        runtime = None
        blocker = None
        record = recorded.get(va)
        if record and record.get("completed"):
            runtime = "EXECUTED"
        dependence = helper_class.get(va)
        if dependence == "MUST_REACH_EXTERNAL_HELPER":
            runtime = better(runtime, "BLOCKED_EXTERNAL")
            blocker = blocker or "0x00686000"
        for mapped, source in frontier_hit.get(va, []):
            if mapped:
                runtime = better(runtime, mapped)
                blocker = blocker or source
            elif blocker is None:
                blocker = source
        import_names = []
        protected_edge = False
        for target in targets:
            if target in thunks:
                meta = thunks[target]
                name = meta.get("symbol") or "ordinal"
                kind = uf.classify_symbol(meta.get("dll"), meta.get("symbol"))
                if kind != "READY_WITH_IMPLEMENTED_IMPORTS":
                    import_names.append(name)
            for lo, hi, name in protected_spans:
                if lo <= target < hi:
                    protected_edge = True
                    blocker = blocker or name
        if import_names:
            runtime = better(runtime, "BLOCKED_IMPORT")
            blocker = blocker or import_names[0]
        if protected_edge:
            runtime = better(runtime, "PROTECTED_BOUNDARY")
        if runtime is None:
            runtime = "UNKNOWN"
        if dependence is None and va in helper_class:
            dependence = helper_class[va]
        if dependence is None and helper and row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable"):
            dependence = "NO_PATH_TO_EXTERNAL_HELPER"

        item = {
            "address": "0x%08X" % va,
            "confidence": label,
            "reachable": bool(row.get("reachable")),
            "generated": bool(generated),
            "compiled": bool(compiled_ok) and translation != "BOUNDARY_PROBLEM",
            "translation_status": translation,
            "runtime_status": runtime,
            "external_helper": dependence if dependence else "UNKNOWN",
        }
        if record:
            item["recorded_execution"] = True
            item["completed"] = bool(record.get("completed"))
            item["first_observed_phase"] = record.get("phase")
        if blocker:
            item["blocker"] = blocker
        if import_names:
            item["unimplemented_imports"] = sorted(set(import_names))
        item["direct_callees"] = len(targets)
        functions.append(item)

    def count(field, value):
        return sum(1 for item in functions if item[field] == value)

    translation_counts = {name: count("translation_status", name) for name in TRANSLATION_COLOR}
    runtime_counts = {name: count("runtime_status", name) for name in RUNTIME_COLOR}
    helper_summary = None
    if helper:
        helper_summary = {
            "must": helper["must_count"],
            "may": helper["may_count"],
            "independent": helper["independent_count"],
            "direct_functions": helper["direct_functions"],
            "direct_sites": helper["direct_sites"],
            "reachable_high": helper["reachable_high"],
        }
    map_counts = function_map.get("counts") or {}
    cfg_complete = 0
    for name in ("RET_REACHED", "MULTIPLE_RETURNS", "TAIL_TRANSFER", "CFG_COMPLETE"):
        cfg_complete += (function_map.get("termination_counts") or {}).get(name, 0)
    discovery = {
        "candidates": len(functions),
        "high": map_counts.get("HIGH_CONFIDENCE", translation_counts["COMPILED"]),
        "medium": map_counts.get("MEDIUM_CONFIDENCE", 0),
        "low": map_counts.get("LOW_CONFIDENCE", 0),
        "rejected": map_counts.get("REJECTED_DATA_LIKE", translation_counts["REJECTED_DATA"]),
        "cfg_complete": cfg_complete,
        "cfg_budget_exceeded": function_map.get("cfg_budget_exceeded", 0),
        "translation_success": compiled["generated"],
        "compilation_success": compiled["compiled"],
        "covered_bytes": function_map.get("covered_bytes"),
        "text_size": function_map.get("text_size"),
    }
    model = {
        "project": {
            "name": "nfsuc-web",
            "current_phase": status["current_phase"],
            "strategy": status["strategy"],
        },
        "discovery": discovery,
        "translation": {
            "label": "High-confidence function compilation",
            "attempted": compiled["attempted"],
            "generated": compiled["generated"],
            "compiled": compiled["compiled"],
            "compiler_failures": compiled["compiler_failures"],
            "map_cells": len(functions),
            "map_compiled_cells": translation_counts["COMPILED"],
            "counts": translation_counts,
            "note": (
                "The badge is the current high-confidence.json compile record. "
                "Green cells are discovery-enrolled HIGH functions that generated and compiled. "
                "Map 'reachable' means discovery enrollment, not proven call-graph reachability."
            ),
        },
        "runtime": {
            "recorded_completed": sum(1 for item in functions if item.get("completed")),
            "recorded_entries": sum(1 for item in status["recorded_execution"]),
            "recorded_without_map_cell": sorted(
                item["address"] for item in status["recorded_execution"]
                if item["address"].upper() not in {row["address"].upper() for row in functions}),
            "unlogged_entries": "UNKNOWN",
            "counts": runtime_counts,
            "ready_closure": ((frontier.get("all_node_extremes") or {}).get("READY") or {}).get("size"),
            "ready_with_imports_closure": ((frontier.get("all_node_extremes") or {}).get(
                "READY_WITH_IMPLEMENTED_IMPORTS") or {}).get("size"),
            "note": (
                "A compiled function is not a function that has run. "
                "DISCOVERED_HIGH != CALL_GRAPH_REACHABLE != RUNTIME_ENTERABLE."
            ),
        },
        "ordinary_runtime_frontier": ordinary.get("ordinary_runtime_frontier") or {},
        "top_ordinary_island": ordinary.get("top_ordinary_island") or {},
        "campaign_summary": ordinary.get("campaign_summary") or {},
        "cisqrt": ordinary.get("cisqrt") or {},
        "harness_capability": ordinary.get("harness_capability") or {},
        "tls_frontier": (
            json.load(open(os.path.join(ANALYSIS, "tls-frontier.json"), encoding="utf-8"))
            if os.path.isfile(os.path.join(ANALYSIS, "tls-frontier.json")) else {}
        ),
        "sync_frontier": (
            json.load(open(os.path.join(ANALYSIS, "synchronization-frontier.json"), encoding="utf-8"))
            if os.path.isfile(os.path.join(ANALYSIS, "synchronization-frontier.json")) else {}
        ),
        "process_frontier": (
            json.load(open(os.path.join(ANALYSIS, "process-handle-frontier.json"), encoding="utf-8"))
            if os.path.isfile(os.path.join(ANALYSIS, "process-handle-frontier.json")) else {}
        ),
        "process_thread_frontier": (
            json.load(open(os.path.join(ANALYSIS, "process-thread-frontier.json"), encoding="utf-8"))
            if os.path.isfile(os.path.join(ANALYSIS, "process-thread-frontier.json")) else {}
        ),
        "initialization": status["initialization"],
        "boundaries": status["boundaries"],
        "helper_cut": helper_summary if helper_summary else "UNKNOWN",
        "graphics": status["graphics"],
        "first_frame_estimate": status["first_frame_estimate"],
        "phases": status["phases"],
        "milestones": status["milestones"],
        "history": [
            {
                "source": "function-map.json",
                "phase4_high_confidence": function_map.get("phase4_high_confidence"),
            },
            {
                "source": "high-confidence.json",
                "attempted": compiled["attempted"],
                "generated": compiled["generated"],
                "compiled": compiled["compiled"],
                "compiler_failures": compiled["compiler_failures"],
            },
            {
                "source": "runtime-frontier-closures.json",
                "largest_ready_closure": ((frontier.get("all_node_extremes") or {}).get("READY") or {}).get("size"),
                "largest_ready_with_imports": ((frontier.get("all_node_extremes") or {}).get(
                    "READY_WITH_IMPLEMENTED_IMPORTS") or {}).get("size"),
            },
        ],
        "functions": functions,
    }
    return model


def groups_for(functions, field):
    buckets = {}
    for item in functions:
        va = hex_addr(item["address"])
        base = va & ~0xFFFFF
        buckets.setdefault(base, []).append(item)
    groups = []
    for base in sorted(buckets):
        items = buckets[base]
        if field == "translation_status":
            done = sum(1 for item in items if item["translation_status"] == "COMPILED")
            label = "compiled"
        else:
            done = sum(1 for item in items if item["runtime_status"] in (
                "EXECUTED", "RUNTIME_READY_NOT_EXECUTED"))
            label = "recorded or ready"
        groups.append({
            "name": "0x%03Xxxxxx" % (base >> 20),
            "range": "0x%08X..0x%08X" % (base, base + 0xFFFFF),
            "items": items,
            "done": done,
            "total": len(items),
            "caption": label,
        })
    return groups


def draw_map(parts, title, groups, field, colors, x, y, w, h, detailed):
    parts.append('<text x="%d" y="%d" fill="%s" font-size="15" font-family="Segoe UI, sans-serif">%s</text>'
                 % (x, y + 16, TEXT, html.escape(title)))
    body_y = y + 24
    body_h = h - 24
    rects = squarify([group["total"] for group in groups], x, body_y, w, body_h)
    for group, rect in zip(groups, rects):
        gx, gy, gw, gh = snap(rect)
        if gw <= 0 or gh <= 0:
            continue
        parts.append('<rect x="%d" y="%d" width="%d" height="%d" fill="%s" stroke="%s" stroke-width="1"/>'
                     % (gx, gy, gw, gh, PANEL, LINE))
        header = 0
        if gh > 36 and gw > 80:
            header = 14
            percent = (100.0 * group["done"] / group["total"]) if group["total"] else 0
            caption = "%s %d/%d %.0f%%" % (group["name"], group["done"], group["total"], percent)
            if len(caption) * 6 > gw - 8:
                caption = "%s %.0f%%" % (group["name"], percent)
            parts.append('<text x="%d" y="%d" fill="%s" font-size="10" font-family="Segoe UI, sans-serif">%s</text>'
                         % (gx + 4, gy + 11, MUTED, html.escape(caption)))
        boxes = cell_boxes(group["total"], gx + 2, gy + header + 2, max(0, gw - 4), max(0, gh - header - 4))
        for item, box in zip(group["items"], boxes):
            cx, cy, cw, ch = box
            color = colors[item[field]]
            tip = tooltip(item) if detailed else (
                "%s | %s | %s" % (item["address"], item["translation_status"], item["runtime_status"]))
            parts.append(
                '<rect x="%d" y="%d" width="%d" height="%d" fill="%s" data-addr="%s"><title>%s</title></rect>'
                % (cx, cy, cw, ch, color, item["address"], html.escape(tip)))
    return y + h


def tooltip(item):
    lines = [
        "Address: %s" % item["address"],
        "Confidence: %s" % item["confidence"],
        "Generated: %s" % ("yes" if item["generated"] else "no"),
        "Compiled: %s" % ("yes" if item["compiled"] else "no"),
        "Recorded execution: %s" % ("yes" if item.get("recorded_execution") else "not listed"),
        "External-helper dependency: %s" % item["external_helper"],
        "Translation: %s" % item["translation_status"],
        "Runtime: %s" % item["runtime_status"],
    ]
    if item.get("first_observed_phase"):
        lines.append("First observed phase: %s" % item["first_observed_phase"])
    if item.get("completed") is not None:
        lines.append("Completed: %s" % ("yes" if item["completed"] else "no"))
    if item.get("blocker"):
        lines.append("Blocker: %s" % item["blocker"])
    lines.append("Direct callees: %d" % item["direct_callees"])
    if item.get("unimplemented_imports"):
        lines.append("Unimplemented imports: %s" % ", ".join(item["unimplemented_imports"]))
    return "\n".join(lines)


def legend(parts, x, y, colors):
    cursor = x
    for name, color in colors.items():
        parts.append('<rect x="%d" y="%d" width="10" height="10" fill="%s"/>' % (cursor, y, color))
        parts.append('<text x="%d" y="%d" fill="%s" font-size="10" font-family="Segoe UI, sans-serif">%s</text>'
                     % (cursor + 14, y + 9, MUTED, html.escape(name)))
        cursor += 14 + 7 * len(name) + 10
    return y + 18


def _ordinary_frontier_badge(model):
    orf = model.get("ordinary_runtime_frontier") or {}
    if not orf:
        return "UNMEASURED"
    return "H%d C%d I%d R%d E%d" % (
        int(orf.get("HIGH") or 0),
        int(orf.get("COMPILED") or 0),
        int(orf.get("IMPORT_READY") or orf.get("RUNTIME_READY_EST") or 0),
        int(orf.get("RUNTIME_READY") or orf.get("RUNTIME_READY_EST") or 0),
        int(orf.get("EXECUTED") or 0),
    )


def _real_uc_execution_badge(model):
    orf = model.get("ordinary_runtime_frontier") or {}
    camp = model.get("campaign_summary") or {}
    if not orf and not camp:
        return "UNMEASURED"
    nxt = camp.get("most_common_next_blocker")
    if isinstance(nxt, (list, tuple)) and nxt:
        nxt = nxt[0]
    return "enter=%s uniq=%s clean=%s ctors=%s deep=%s clos=%s d4=%s blk=%s" % (
        orf.get("ENTERABLE") or "?",
        orf.get("UNIQUE") or orf.get("EXECUTED") or "?",
        orf.get("CLEAN_ORDINARY_ROOTS") or "?",
        orf.get("EXECUTED_ORDINARY_CONSTRUCTORS") or "?",
        camp.get("deepest_chain") or orf.get("DEEPEST") or "?",
        camp.get("largest_executed_closure") or orf.get("LARGEST_CLOSURE") or "?",
        orf.get("ENTERABLE_WITH_DEPTH_4_POTENTIAL") or "?",
        nxt or "?",
    )


def _real_execution_html_table(model):
    orf = model.get("ordinary_runtime_frontier") or {}
    camp = model.get("campaign_summary") or {}
    nxt = camp.get("most_common_next_blocker")
    if isinstance(nxt, (list, tuple)) and nxt:
        nxt = "%s ×%s" % (nxt[0], nxt[1] if len(nxt) > 1 else "?")
    return html_table(("Metric", "Value"), [
        ("ENTERABLE", orf.get("ENTERABLE") or "?"),
        ("UNIQUE EXECUTED", orf.get("UNIQUE") or orf.get("EXECUTED") or "?"),
        ("CLEAN ROOTS", orf.get("CLEAN_ORDINARY_ROOTS") or "?"),
        ("EXECUTED CTORS", orf.get("EXECUTED_ORDINARY_CONSTRUCTORS") or "?"),
        ("DEEPEST CHAIN", camp.get("deepest_chain") or orf.get("DEEPEST") or "?"),
        ("LARGEST CLOSURE", camp.get("largest_executed_closure") or orf.get("LARGEST_CLOSURE") or "?"),
        ("DEPTH-4 CANDIDATES", orf.get("ENTERABLE_WITH_DEPTH_4_POTENTIAL") or "?"),
        ("MOST COMMON REAL BLOCKER", nxt or "?"),
    ])


def _ordinary_init_badge(model):
    orf = model.get("ordinary_runtime_frontier") or {}
    if not orf:
        return "UNMEASURED"
    return "rec=%s ext=%s prot=%s unk=%s d3=%s" % (
        orf.get("ORDINARY_INIT_RECOVERED") or "?",
        orf.get("INIT_BLOCKED_EXTERNAL") or "?",
        orf.get("INIT_BLOCKED_PROTECTED") or "?",
        orf.get("INIT_BLOCKED_UNKNOWN") or "?",
        orf.get("ENTERABLE_WITH_DEPTH_3_POTENTIAL") or "?",
    )


def _cisqrt_badge(model):
    cis = model.get("cisqrt") or {}
    hc = model.get("harness_capability") or {}
    if cis.get("hle") == "UC_HLE_CISQRT" or hc.get("crt_cisqrt") == "IMPLEMENTED":
        return "IMPLEMENTED ST0→ST0 PASS"
    return "UNKNOWN"


def _tls_badge(model):
    tls = model.get("tls_frontier") or {}
    dyn = tls.get("dynamic_tls") or {}
    if not dyn:
        return "UNMEASURED"
    def st(name):
        row = dyn.get(name) or {}
        if row.get("implemented"):
            return "IMPLEMENTED"
        if row.get("reached"):
            return "REACHED"
        return "NOT_REACHED" if name in dyn else "PENDING"
    return "Alloc=%s Set=%s Get=%s Free=%s thr=%s" % (
        st("TlsAlloc"), st("TlsSetValue"), st("TlsGetValue"), st("TlsFree"),
        tls.get("active_guest_thread_contexts") or "?",
    )


def _sync_badge(model):
    sync = model.get("sync_frontier") or {}
    if not sync:
        return "UNMEASURED"
    fam = sync.get("family_inventory") or {}

    def st_row(row):
        if not row:
            return "PENDING"
        if row.get("implemented"):
            return "IMPLEMENTED"
        if row.get("reached") or row.get("reached_legitimately") or row.get("reached_phase32"):
            return "REACHED"
        return "NOT_IMPL"

    return "ICS=%s Mutex=%s Sem=%s GCP=%s GCT=%s GPC=%s thr=%s sched=%s" % (
        st_row(sync.get("critical_section")),
        st_row(sync.get("create_mutex_a")),
        st_row(sync.get("create_semaphore_a")),
        st_row(sync.get("get_current_process")),
        st_row(sync.get("get_current_thread")),
        st_row(sync.get("get_priority_class")),
        sync.get("guest_threads") or "?",
        sync.get("scheduler") or "NONE",
    )


def _guest_process_badge(model):
    pt = model.get("process_thread_frontier") or model.get("process_frontier") or {}
    if not pt:
        return "UNMEASURED"
    return "proc=%s class=%s mutable=%s" % (
        pt.get("guest_processes") or 1,
        (pt.get("priority_class_initial") or "?").split()[0],
        "YES" if pt.get("priority_class_mutable") else "NO",
    )


def _guest_thread_badge(model):
    pt = model.get("process_thread_frontier") or {}
    sync = model.get("sync_frontier") or {}
    thr = pt.get("guest_threads") or sync.get("guest_threads") or 1
    return "thr=%s GCT=%s sched=%s" % (
        thr,
        "IMPL" if (pt.get("GetCurrentThread") or {}).get("implemented") else "PEND",
        pt.get("scheduler") or sync.get("scheduler") or "NONE",
    )


def _sync_html_table(model):
    sync = model.get("sync_frontier") or {}
    fam = sync.get("family_inventory") or {}
    def impl(row):
        if not row:
            return "PENDING"
        return "IMPLEMENTED" if row.get("implemented") else "NOT_IMPLEMENTED"
    proc = model.get("process_frontier") or {}
    rows = [
        ("InitializeCriticalSection", impl(sync.get("critical_section"))),
        ("CreateMutexA", impl(sync.get("create_mutex_a"))),
        ("CreateSemaphoreA", impl(sync.get("create_semaphore_a"))),
        ("GetCurrentProcess", impl(sync.get("get_current_process"))),
        ("GetPriorityClass", impl(sync.get("get_priority_class") or proc.get("GetPriorityClass"))),
        ("GetCurrentThread", impl(sync.get("get_current_thread"))),
        ("Get/SetThreadPriority", impl(sync.get("get_thread_priority"))),
        ("SetPriorityClass", impl(sync.get("set_priority_class"))),
        ("Enter/Leave/Delete", "NOT_IMPLEMENTED"),
        ("Guest processes", "1"),
        ("Guest threads", "%s" % (sync.get("guest_threads") or 1)),
        ("Scheduler", sync.get("scheduler") or "NONE"),
        ("Thread scheduling", sync.get("thread_scheduling") or "NOT_IMPLEMENTED"),
        ("Process model", proc.get("model") or "ONE_LOGICAL_GUEST_PROCESS"),
        ("Model", sync.get("model") or "SINGLE GUEST THREAD — LIMITED SYNC MODEL"),
    ]
    return html_table(("Item", "Status"), rows)


def _tls_html_table(model):
    tls = model.get("tls_frontier") or {}
    dyn = tls.get("dynamic_tls") or {}
    rows = [
        ("TlsAlloc", "IMPLEMENTED" if (dyn.get("TlsAlloc") or {}).get("implemented") else "PENDING"),
        ("TlsSetValue", "IMPLEMENTED" if (dyn.get("TlsSetValue") or {}).get("implemented") else "PENDING"),
        ("TlsGetValue", (
            "IMPLEMENTED" if (dyn.get("TlsGetValue") or {}).get("implemented")
            else ("NOT_REACHED" if dyn.get("TlsGetValue") else "PENDING"))),
        ("TlsFree", (
            "IMPLEMENTED" if (dyn.get("TlsFree") or {}).get("implemented")
            else ("NOT_REACHED" if dyn.get("TlsFree") else "PENDING"))),
        ("Guest thread contexts", "%s currently (no general threading)" % (
            tls.get("active_guest_thread_contexts") or 1)),
        ("Category", tls.get("category") or "DYNAMIC_WIN32_TLS"),
    ]
    return html_table(("Item", "Status"), rows)


def _top_island_badge(model):
    top = model.get("top_ordinary_island") or {}
    if not top:
        return "UNMEASURED"
    blockers = top.get("exact_blockers") or []
    primary = blockers[0] if blockers else "none"
    return "%s fn=%s %s" % (top.get("root") or "?", top.get("function_count") or "?", primary)


def badge_row(parts, badges, y):
    x = 16
    row_y = y
    for label, value in badges:
        text = "%s  %s" % (label, value)
        width = 16 + int(6.6 * len(text))
        if x + width > WIDTH - 16:
            x = 16
            row_y += 28
        parts.append('<rect x="%d" y="%d" width="%d" height="22" rx="4" fill="%s" stroke="%s"/>'
                     % (x, row_y, width, PANEL, LINE))
        parts.append('<text x="%d" y="%d" fill="%s" font-size="11" font-family="Segoe UI, sans-serif">%s</text>'
                     % (x + 8, row_y + 15, TEXT, html.escape(text)))
        x += width + 8
    return row_y + 30


def render_svg(model, detailed=False):
    functions = model["functions"]
    translation = groups_for(functions, "translation_status")
    runtime = groups_for(functions, "runtime_status")
    trans = model["translation"]
    run = model["runtime"]
    cut = model["helper_cut"]
    cut_text = "UNKNOWN" if cut == "UNKNOWN" else "%d must / %d may / %d independent" % (
        cut["must"], cut["may"], cut["independent"])
    disc = model.get("discovery") or {}
    gfx = model.get("graphics") or {}
    static_factory = gfx.get("static_factory_frontier") or (
        "REACHABLE" if gfx.get("reachable_from_high_graph") == "YES" else "NOT REACHABLE"
    )
    runtime_factory = gfx.get("runtime_factory_frontier") or (
        "ENTERABLE" if gfx.get("enterable_now") == "YES" else "NOT ENTERABLE"
    )
    frontier_ready = "YES" if gfx.get("factory_frontier_ready") else "NO"
    pre_cb = gfx.get("pre_factory_callback") or "UNRESOLVED"
    d3d_impl = "YES" if gfx.get("direct3d9_implemented") else "NO"
    factory_init = gfx.get("factory_initialization") or "EXTERNAL/PROTECTED BLOCKED"
    post_init = gfx.get("post_init_graphics_frontier") or "UNKNOWN"
    device_code = gfx.get("device_code") or gfx.get("device_pointer") or "UNKNOWN"
    device_pub = gfx.get("device_publication") or "UNKNOWN"
    present_code = gfx.get("present_code") or "UNKNOWN"
    present_rt = gfx.get("present_runtime") or "UNKNOWN"
    draw_code = gfx.get("draw_code") or "UNKNOWN"
    reset_rec = gfx.get("reset_recovery") or "UNKNOWN"
    seam = gfx.get("post_init_seam") or "UNKNOWN"
    d3d_just = "JUSTIFIED" if gfx.get("d3d9_implementation_justified") else "NOT JUSTIFIED"
    first_clear = gfx.get("first_clear") or "UNKNOWN"
    first_draw = gfx.get("first_draw") or "UNKNOWN"
    first_present = gfx.get("first_present") or "UNKNOWN"
    angr_meta = load_angr_cached()
    angr_badge = angr_meta.get("status") or gfx.get("angr") or "NOT RUN"
    badges = [
        ("Functions compiled", "%d/%d" % (trans["compiled"], trans["attempted"])),
        ("Compiler failures", str(trans["compiler_failures"])),
        ("Recorded entries", str(run["recorded_entries"])),
        ("Phase", str(model["project"]["current_phase"])),
        ("External boundary", "0x00686000"),
        ("Helper cut", cut_text),
        ("HIGH", str(disc.get("high", "?"))),
        ("MEDIUM", str(disc.get("medium", "?"))),
        ("CFG-complete", str(disc.get("cfg_complete", "?"))),
        ("CFG-budget", str(disc.get("cfg_budget_exceeded", "?"))),
        ("FACTORY INITIALIZATION", factory_init),
        ("DEVICE CODE", device_code),
        ("DEVICE PUBLICATION", device_pub),
        ("PRESENT CODE", present_code),
        ("PRESENT RUNTIME", present_rt),
        ("DRAW CODE", draw_code),
        ("RESET/RECOVERY", reset_rec),
        ("POST-INIT SEAM", seam),
        ("D3D9 IMPLEMENTATION", d3d_just),
        ("POST-INIT GRAPHICS FRONTIER", post_init),
        ("FIRST CLEAR", first_clear),
        ("FIRST DRAW", first_draw),
        ("FIRST PRESENT", first_present),
        ("ANGR", angr_badge),
        ("ANGR PRESENT CONTROL", angr_meta.get("present_control") or gfx.get("angr_present_control") or "NOT RUN"),
        ("ANGR CLEAR CONTROL", angr_meta.get("clear_control") or gfx.get("angr_clear_control") or "NOT RUN"),
        ("DEVICE→RENDERER", gfx.get("device_to_renderer") or "UNKNOWN"),
        ("DRAW CONSENSUS", gfx.get("draw_consensus") or "UNKNOWN"),
        ("RENDERER", gfx.get("renderer_classification") or "PROVEN ENGINE OBJECT"),
        ("RENDERER LIST", angr_meta.get("renderer_list") or gfx.get("renderer_list") or "UNKNOWN"),
        ("ENGINE DRAW", gfx.get("engine_draw") or "FOUND"),
        ("BACKEND HANDOFF", angr_meta.get("backend_handoff") or gfx.get("backend_handoff") or "UNKNOWN"),
        ("RAW DEVICE DRAW", angr_meta.get("raw_device_draw") or gfx.get("raw_device_draw") or "UNKNOWN"),
        ("DURABLE DEVICE ALIAS", angr_meta.get("durable_device_alias") or gfx.get("durable_device_alias") or "UNKNOWN"),
        ("FRAME ROOT", angr_meta.get("frame_root") or gfx.get("frame_root") or "UNKNOWN"),
        ("GRAPHICS BOUNDARY", angr_meta.get("graphics_boundary") or gfx.get("graphics_boundary") or "UNKNOWN"),
        ("RENDERER VECTOR", "MAPPED"),
        ("VECTOR INSERTION", angr_meta.get("vector_insertion") or "UNKNOWN"),
        ("ELEMENT +0x04", angr_meta.get("element_plus04") or "UNKNOWN"),
        ("IFACE PUBLICATION", angr_meta.get("iface_publication") or "UNKNOWN"),
        ("VTABLE", angr_meta.get("vtable_class") or "UNKNOWN"),
        ("METHOD +148", angr_meta.get("method_148_terminus") or "UNKNOWN"),
        ("METHOD +14C", angr_meta.get("method_14c_terminus") or "UNKNOWN"),
        ("METHOD +154", angr_meta.get("method_154_terminus") or "UNKNOWN"),
        ("P23 SEAM", angr_meta.get("post_init_seam") or seam),
        ("P23 D3D9", angr_meta.get("d3d9") or d3d_just),
        ("P23 BACKEND ADAPTER", angr_meta.get("engine_backend_adapter") or "UNKNOWN"),
        ("FIRST FRAME", "BLOCKED — PROTECTED BACKEND"),
        ("D3D9", "NOT JUSTIFIED"),
        ("ENGINE BACKEND", "NOT JUSTIFIED"),
        ("ENGINE FRONTEND", angr_meta.get("engine_frontend") or "UNKNOWN"),
        ("SUBMIT BACKEND", angr_meta.get("submit_backend") or "UNKNOWN"),
        ("VISIBLE SUBMIT CONTRACT", angr_meta.get("visible_submit_contract") or "UNKNOWN"),
        ("RAW D3D9 RESOURCE TRAFFIC", angr_meta.get("raw_d3d9_resource_traffic") or "UNKNOWN"),
        ("FRAME CORRELATION", angr_meta.get("frame_correlation") or "UNKNOWN"),
        ("GRAPHICS ARCHITECTURE", angr_meta.get("graphics_architecture") or "UNKNOWN"),
        ("SAFE RUNTIME SEAM", angr_meta.get("safe_runtime_seam") or "UNKNOWN"),
        ("STATIC FACTORY", static_factory),
        ("FACTORY FRONTIER READY", frontier_ready),
        ("DIRECT3D9 IMPLEMENTED", d3d_impl),
        ("Runtime factory frontier", runtime_factory),
        ("ORDINARY RUNTIME FRONTIER", _ordinary_frontier_badge(model)),
        ("TOP ORDINARY ISLAND", _top_island_badge(model)),
        ("REAL UC EXECUTION", _real_uc_execution_badge(model)),
        ("ORDINARY INITIALIZATION", _ordinary_init_badge(model)),
        ("CRT _CIsqrt", _cisqrt_badge(model)),
        ("DYNAMIC WIN32 TLS", _tls_badge(model)),
        ("WIN32 SYNCHRONIZATION", _sync_badge(model)),
        ("GUEST PROCESS", _guest_process_badge(model)),
        ("GUEST THREAD", _guest_thread_badge(model)),
    ]
    parts = []
    y = badge_row(parts, badges, 14)
    y = draw_map(parts, "Function translation", translation, "translation_status",
                 TRANSLATION_COLOR, 16, y + 8, WIDTH - 32, 360, detailed)
    y = legend(parts, 16, y + 8, TRANSLATION_COLOR)
    parts.append('<text x="16" y="%d" fill="%s" font-size="11" font-family="Segoe UI, sans-serif">%s</text>'
                 % (y + 16, MUTED, html.escape(
                     "High-confidence function compilation %d/%d. This is not project completion."
                     % (trans["compiled"], trans["attempted"]))))
    y = draw_map(parts, "Runtime reachability", runtime, "runtime_status",
                 RUNTIME_COLOR, 16, y + 28, WIDTH - 32, 360, detailed)
    y = legend(parts, 16, y + 8, RUNTIME_COLOR)
    parts.append('<text x="16" y="%d" fill="%s" font-size="11" font-family="Segoe UI, sans-serif">%s</text>'
                 % (y + 16, MUTED, html.escape(run["note"] + " Unlogged entries: UNKNOWN.")))
    height = y + 36
    body = "\n".join(parts)
    svg = "\n".join([
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">' % (
            WIDTH, height, WIDTH, height),
        '<rect width="%d" height="%d" fill="%s"/>' % (WIDTH, height, BG),
        body,
        "</svg>",
        "",
    ])
    return svg


def html_table(headers, rows):
    head = "".join("<th>%s</th>" % html.escape(item) for item in headers)
    body = []
    for row in rows:
        body.append("<tr>" + "".join("<td>%s</td>" % html.escape(str(cell)) for cell in row) + "</tr>")
    return "<table><tr>%s</tr>%s</table>" % (head, "".join(body))


def render_html(model, svg):
    trans = model["translation"]
    run = model["runtime"]
    graphics = model["graphics"]
    estimate = model["first_frame_estimate"]
    cut = model["helper_cut"]
    disc = model.get("discovery") or {}
    angr_meta = load_angr_cached()
    boundary = model["boundaries"]["0x00686000"]
    unknown_b = model["boundaries"]["0x0055FF30"]
    init_rows = []
    for item in model["initialization"]:
        init_rows.append((
            item["address"], item["status"],
            item.get("writer") or "UNKNOWN",
            item.get("value") or "",
        ))
    phase_pills = " ".join(
        '<span class="pill %s">%d %s</span>' % (item["state"], item["phase"], html.escape(item["name"]))
        for item in model["phases"])
    mile_rows = [(item["name"], item["state"]) for item in model["milestones"]]
    history_rows = []
    for point in model["history"]:
        history_rows.append((point["source"], ", ".join(
            "%s=%s" % (key, value) for key, value in point.items() if key != "source")))
    cut_line = "UNKNOWN" if cut == "UNKNOWN" else (
        "MUST %d, MAY %d, independent %d, CFG-direct functions %d, CFG-direct sites %d"
        % (cut["must"], cut["may"], cut["independent"], cut["direct_functions"], cut["direct_sites"]))
    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Undercover status</title>
<style>
body { margin: 0; background: #0d1117; color: #e6edf3; font: 14px/1.45 "Segoe UI", sans-serif; }
main { max-width: 1120px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 8px; }
h2 { font-size: 16px; margin: 28px 0 8px; }
p, li { color: #c9d1d9; }
.note { color: #8b949e; }
svg { width: 100%%; height: auto; background: #0d1117; }
table { border-collapse: collapse; width: 100%%; margin: 8px 0 16px; }
th, td { border: 1px solid #30363d; padding: 4px 8px; text-align: left; vertical-align: top; }
th { color: #8b949e; font-weight: 600; }
.pill { display: inline-block; margin: 0 6px 6px 0; padding: 3px 8px; border: 1px solid #30363d; border-radius: 999px; background: #161b22; }
.completed { color: #3fb950; }
.current { color: #d29922; }
#tip { position: fixed; display: none; max-width: 360px; padding: 8px 10px; background: #161b22; border: 1px solid #30363d; white-space: pre-wrap; font: 12px/1.4 ui-monospace, monospace; pointer-events: none; z-index: 2; }
</style>
</head>
<body>
<main>
<h1>Undercover status</h1>
<p class="note">Generated by <code>python tools/progress.py</code>. Cells are real functions from the function map. Translation and runtime are separate pictures.</p>
%s
<h2>Discovery quality</h2>
%s
<h2>Initialization</h2>
%s
<h2>External boundary</h2>
<p><code>0x00686000</code> %s. Direct call sites %d. High-confidence span sites %d. Reachable high-confidence span sites %d. Not implemented, not substituted, not lifted, not executed.</p>
<p>Control-flow cut: %s.</p>
<p><code>0x0055FF30</code> %s. This is not a protected classification.</p>
<h2>Current frontier</h2>
<p>Current blocker: <code>0x00686000</code>, %s.</p>
<p>Strategy: %s</p>
<p>FACTORY INITIALIZATION: %s. DEVICE CODE: %s. DEVICE PUBLICATION: %s.</p>
<p>PRESENT CODE: %s. PRESENT RUNTIME: %s. DRAW CODE: %s. RESET/RECOVERY: %s.</p>
<p>POST-INIT SEAM: %s. D3D9 IMPLEMENTATION: %s. POST-INIT GRAPHICS FRONTIER: %s.</p>
<p>FIRST CLEAR: %s. FIRST DRAW: %s. FIRST PRESENT: %s.</p>
<p>ANGR: %s. ANGR VERSION: %s. PRESENT CONTROL: %s. CLEAR CONTROL: %s.</p>
<p>DEVICE→RENDERER: %s. DRAW CONSENSUS: %s. Boundary disagreements (cached): %s.</p>
<p>RENDERER LIST: %s. BACKEND HANDOFF: %s. RAW DEVICE DRAW: %s. DURABLE DEVICE ALIAS: %s.</p>
<p>FRAME ROOT: %s. GRAPHICS BOUNDARY: %s.</p>
<p>RENDERER VECTOR: MAPPED. VECTOR INSERTION: %s. ELEMENT +0x04: %s. IFACE PUBLICATION: %s. VTABLE: %s.</p>
<p>METHOD +148: %s. METHOD +14C: %s. METHOD +154: %s. FIRST FRAME: <strong>BLOCKED — PROTECTED BACKEND</strong>.</p>
<p>D3D9: <strong>NOT JUSTIFIED</strong>. ENGINE BACKEND: <strong>NOT JUSTIFIED</strong>. Graphics investigation frozen after Phase 24.</p>
<p>ENGINE FRONTEND: %s. SUBMIT BACKEND: %s. VISIBLE SUBMIT CONTRACT: %s. RAW D3D9 RESOURCE TRAFFIC: %s.</p>
<p>FRAME CORRELATION: %s. GRAPHICS ARCHITECTURE: %s. SAFE RUNTIME SEAM: %s.</p>
<p>STATIC FACTORY: %s. FACTORY FRONTIER READY: %s. DIRECT3D9 IMPLEMENTED: %s.</p>
<h2>Ordinary runtime frontier</h2>
%s
<h2>Top ordinary island</h2>
%s
<h2>Real UC execution</h2>
%s
<h2>Ordinary initialization</h2>
%s
<h2>Dynamic Win32 TLS</h2>
%s
<p>Guest-managed indices/values only. Not host TLS. Not a general threading runtime.</p>
<h2>Win32 synchronization</h2>
%s
<p>SINGLE GUEST THREAD — LIMITED SYNC MODEL. No guest scheduler.</p>
<p>CRT <code>_CIsqrt</code>: %s. ABI: X87 ST0→ST0.</p>
<p>Independent of <code>0x00686000</code>: %s. Discovery-enrolled on HIGH graph: %s. Runtime enterable now: %s. Call <code>%s</code> in <code>%s</code> (%s).</p>
<p>Active objective: %s</p>
<p>%s</p>
<p>First-frame estimate: frozen — <code>FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND</code>. Former estimate (%s / %s–%s) is historical only. %s</p>
<p>Recorded runs with no function-map cell: %s. Other entered functions whose tests do not record an address stay UNKNOWN.</p>
<h2>Phases</h2>
<p>%s</p>
<p class="note">Completed means the phase's scoped objective was finished, not that a subsystem is finished.</p>
<h2>Milestones</h2>
%s
<h2>History from analysis files</h2>
%s
<p class="note">Points without a structured source are omitted. Unlogged execution stays UNKNOWN.</p>
</main>
<div id="tip"></div>
<script>
const tip = document.getElementById("tip");
document.querySelectorAll("rect[data-addr]").forEach(function (node) {
  node.addEventListener("mousemove", function (event) {
    const title = node.querySelector("title");
    tip.textContent = title ? title.textContent : node.getAttribute("data-addr");
    tip.style.display = "block";
    tip.style.left = (event.clientX + 14) + "px";
    tip.style.top = (event.clientY + 14) + "px";
  });
  node.addEventListener("mouseleave", function () { tip.style.display = "none"; });
});
</script>
</body>
</html>
""" % (
        svg.replace('<?xml version="1.0" encoding="UTF-8"?>\n', '', 1),
        html_table(("Metric", "Value"), [
            ("Function candidates", disc.get("candidates")),
            ("HIGH", disc.get("high")),
            ("MEDIUM", disc.get("medium")),
            ("LOW", disc.get("low")),
            ("REJECTED", disc.get("rejected")),
            ("CFG-complete functions", disc.get("cfg_complete")),
            ("CFG-budget exceeded", disc.get("cfg_budget_exceeded")),
            ("Translation success", disc.get("translation_success")),
            ("Compilation success", disc.get("compilation_success")),
        ]),
        html_table(("Address", "Status", "Writer", "Value"), init_rows),
        html.escape(boundary["status"]),
        boundary["direct_call_sites"],
        boundary["high_confidence_span_sites"],
        boundary["reachable_high_span_sites"],
        html.escape(cut_line),
        html.escape(unknown_b["status"]),
        html.escape(boundary["status"]),
        html.escape(model["project"]["strategy"]),
        html.escape(graphics.get("factory_initialization") or "EXTERNAL/PROTECTED BLOCKED"),
        html.escape(graphics.get("device_code") or graphics.get("device_pointer") or "UNKNOWN"),
        html.escape(graphics.get("device_publication") or "UNKNOWN"),
        html.escape(graphics.get("present_code") or "UNKNOWN"),
        html.escape(graphics.get("present_runtime") or "UNKNOWN"),
        html.escape(graphics.get("draw_code") or "UNKNOWN"),
        html.escape(graphics.get("reset_recovery") or "UNKNOWN"),
        html.escape(graphics.get("post_init_seam") or "UNKNOWN"),
        "JUSTIFIED" if graphics.get("d3d9_implementation_justified") else "NOT JUSTIFIED",
        html.escape(graphics.get("post_init_graphics_frontier") or "UNKNOWN"),
        html.escape(graphics.get("first_clear") or "UNKNOWN"),
        html.escape(graphics.get("first_draw") or "UNKNOWN"),
        html.escape(graphics.get("first_present") or "UNKNOWN"),
        html.escape(angr_meta.get("status") or graphics.get("angr") or "NOT RUN"),
        html.escape(str(angr_meta.get("version") or graphics.get("angr_version") or "n/a")),
        html.escape(str(angr_meta.get("present_control") or graphics.get("angr_present_control") or "NOT RUN")),
        html.escape(str(angr_meta.get("clear_control") or graphics.get("angr_clear_control") or "NOT RUN")),
        html.escape(str(angr_meta.get("device_to_renderer") or graphics.get("device_to_renderer") or "UNKNOWN")),
        html.escape(str(angr_meta.get("draw_consensus") or graphics.get("draw_consensus") or "UNKNOWN")),
        html.escape(str(angr_meta.get("boundary_disagreements") if angr_meta.get("boundary_disagreements") is not None else "n/a")),
        html.escape(str(angr_meta.get("renderer_list") or graphics.get("renderer_list") or "UNKNOWN")),
        html.escape(str(angr_meta.get("backend_handoff") or graphics.get("backend_handoff") or "UNKNOWN")),
        html.escape(str(angr_meta.get("raw_device_draw") or graphics.get("raw_device_draw") or "UNKNOWN")),
        html.escape(str(angr_meta.get("durable_device_alias") or graphics.get("durable_device_alias") or "UNKNOWN")),
        html.escape(str(angr_meta.get("frame_root") or graphics.get("frame_root") or "UNKNOWN")),
        html.escape(str(angr_meta.get("graphics_boundary") or graphics.get("graphics_boundary") or "UNKNOWN")),
        html.escape(str(angr_meta.get("vector_insertion") or "UNKNOWN")),
        html.escape(str(angr_meta.get("element_plus04") or "UNKNOWN")),
        html.escape(str(angr_meta.get("iface_publication") or "UNKNOWN")),
        html.escape(str(angr_meta.get("vtable_class") or "UNKNOWN")),
        html.escape(str(angr_meta.get("method_148_terminus") or "UNKNOWN")),
        html.escape(str(angr_meta.get("method_14c_terminus") or "UNKNOWN")),
        html.escape(str(angr_meta.get("method_154_terminus") or "UNKNOWN")),
        html.escape(str(angr_meta.get("engine_frontend") or "UNKNOWN")),
        html.escape(str(angr_meta.get("submit_backend") or "UNKNOWN")),
        html.escape(str(angr_meta.get("visible_submit_contract") or "UNKNOWN")),
        html.escape(str(angr_meta.get("raw_d3d9_resource_traffic") or "UNKNOWN")),
        html.escape(str(angr_meta.get("frame_correlation") or "UNKNOWN")),
        html.escape(str(angr_meta.get("graphics_architecture") or "UNKNOWN")),
        html.escape(str(angr_meta.get("safe_runtime_seam") or "UNKNOWN")),
        html.escape(graphics.get("static_factory_frontier") or graphics.get("frontier") or "UNKNOWN"),
        "YES" if graphics.get("factory_frontier_ready") else "NO",
        "YES" if graphics.get("direct3d9_implemented") else "NO",
        html_table(("Metric", "Value"), [
            (k, v) for k, v in (model.get("ordinary_runtime_frontier") or {
                "status": "UNMEASURED"}).items()
        ]),
        html_table(("Field", "Value"), [
            ("root", (model.get("top_ordinary_island") or {}).get("root") or "UNMEASURED"),
            ("functions", (model.get("top_ordinary_island") or {}).get("function_count") or "?"),
            ("status", "enterable" if (model.get("top_ordinary_island") or {}).get("estimated_runtime_work") == "enterable"
             else ((model.get("top_ordinary_island") or {}).get("estimated_runtime_work") or "?")),
            ("primary blocker", ((model.get("top_ordinary_island") or {}).get("exact_blockers") or ["none"])[0]),
            ("next blocker", (
                ((model.get("top_ordinary_island") or {}).get("exact_blockers") or ["none", "none"]) + ["none"]
            )[1] if len((model.get("top_ordinary_island") or {}).get("exact_blockers") or []) > 1
            else ((model.get("top_ordinary_island") or {}).get("missing_imports") or ["none"])[0]
                 if (model.get("top_ordinary_island") or {}).get("missing_imports") else "none"),
            ("missing imports", ", ".join((model.get("top_ordinary_island") or {}).get("missing_imports") or []) or "none"),
        ]),
        _real_execution_html_table(model),
        html_table(("Metric", "Value"), [
            ("recovered", (model.get("ordinary_runtime_frontier") or {}).get("ORDINARY_INIT_RECOVERED") or "?"),
            ("external", (model.get("ordinary_runtime_frontier") or {}).get("INIT_BLOCKED_EXTERNAL") or "?"),
            ("protected", (model.get("ordinary_runtime_frontier") or {}).get("INIT_BLOCKED_PROTECTED") or "?"),
            ("unknown", (model.get("ordinary_runtime_frontier") or {}).get("INIT_BLOCKED_UNKNOWN") or "?"),
            ("depth-3 potential", (model.get("ordinary_runtime_frontier") or {}).get("ENTERABLE_WITH_DEPTH_3_POTENTIAL") or "?"),
        ]),
        _tls_html_table(model),
        _sync_html_table(model),
        html.escape(_cisqrt_badge(model)),
        html.escape(graphics["independent_of_0x00686000"]),
        html.escape(graphics["reachable_from_high_graph"]),
        html.escape(graphics["enterable_now"]),
        html.escape(graphics["call"]),
        html.escape(graphics["function"]),
        html.escape(graphics["confidence"]),
        html.escape(graphics.get("active_objective") or "Expand ordinary CPU/runtime islands; graphics frozen"),
        html.escape("; ".join(graphics.get("blockers") or []) or "No blocker list."),
        estimate["best_case_phase"],
        estimate["likely_low"],
        estimate["likely_high"],
        html.escape(estimate["uncertainty"]),
        html.escape(", ".join(model["runtime"]["recorded_without_map_cell"]) or "none"),
        phase_pills,
        html_table(("Milestone", "State"), mile_rows),
        html_table(("Source", "Values"), history_rows),
    )
    return page


def dump(model):
    public = dict(model)
    return json.dumps(public, indent=2) + "\n"


def _hex_rgb(color):
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))


def render_png(model):
    """Raster twin of the SVG for GitHub README embedding.

    GitHub often skips large multi-thousand-element SVGs in README files.
    """
    from PIL import Image, ImageDraw, ImageFont

    functions = model["functions"]
    translation = groups_for(functions, "translation_status")
    runtime = groups_for(functions, "runtime_status")
    trans = model["translation"]
    run = model["runtime"]
    cut = model["helper_cut"]
    cut_text = "UNKNOWN" if cut == "UNKNOWN" else "%d must / %d may / %d independent" % (
        cut["must"], cut["may"], cut["independent"])
    disc = model.get("discovery") or {}
    gfx = model.get("graphics") or {}
    static_factory = gfx.get("static_factory_frontier") or (
        "REACHABLE" if gfx.get("reachable_from_high_graph") == "YES" else "NOT REACHABLE"
    )
    runtime_factory = gfx.get("runtime_factory_frontier") or (
        "ENTERABLE" if gfx.get("enterable_now") == "YES" else "NOT ENTERABLE"
    )
    frontier_ready = "YES" if gfx.get("factory_frontier_ready") else "NO"
    pre_cb = gfx.get("pre_factory_callback") or "UNRESOLVED"
    d3d_impl = "YES" if gfx.get("direct3d9_implemented") else "NO"
    factory_init = gfx.get("factory_initialization") or "EXTERNAL/PROTECTED BLOCKED"
    post_init = gfx.get("post_init_graphics_frontier") or "UNKNOWN"
    device_code = gfx.get("device_code") or gfx.get("device_pointer") or "UNKNOWN"
    device_pub = gfx.get("device_publication") or "UNKNOWN"
    present_code = gfx.get("present_code") or "UNKNOWN"
    present_rt = gfx.get("present_runtime") or "UNKNOWN"
    draw_code = gfx.get("draw_code") or "UNKNOWN"
    reset_rec = gfx.get("reset_recovery") or "UNKNOWN"
    seam = gfx.get("post_init_seam") or "UNKNOWN"
    d3d_just = "JUSTIFIED" if gfx.get("d3d9_implementation_justified") else "NOT JUSTIFIED"
    first_clear = gfx.get("first_clear") or "UNKNOWN"
    first_draw = gfx.get("first_draw") or "UNKNOWN"
    first_present = gfx.get("first_present") or "UNKNOWN"
    angr_meta = load_angr_cached()
    angr_badge = angr_meta.get("status") or gfx.get("angr") or "NOT RUN"
    badges = [
        ("Functions compiled", "%d/%d" % (trans["compiled"], trans["attempted"])),
        ("Compiler failures", str(trans["compiler_failures"])),
        ("Recorded entries", str(run["recorded_entries"])),
        ("Phase", str(model["project"]["current_phase"])),
        ("External boundary", "0x00686000"),
        ("Helper cut", cut_text),
        ("HIGH", str(disc.get("high", "?"))),
        ("MEDIUM", str(disc.get("medium", "?"))),
        ("CFG-complete", str(disc.get("cfg_complete", "?"))),
        ("CFG-budget", str(disc.get("cfg_budget_exceeded", "?"))),
        ("FACTORY INITIALIZATION", factory_init),
        ("DEVICE CODE", device_code),
        ("DEVICE PUBLICATION", device_pub),
        ("PRESENT CODE", present_code),
        ("PRESENT RUNTIME", present_rt),
        ("DRAW CODE", draw_code),
        ("RESET/RECOVERY", reset_rec),
        ("POST-INIT SEAM", seam),
        ("D3D9 IMPLEMENTATION", d3d_just),
        ("POST-INIT GRAPHICS FRONTIER", post_init),
        ("FIRST CLEAR", first_clear),
        ("FIRST DRAW", first_draw),
        ("FIRST PRESENT", first_present),
        ("ANGR", angr_badge),
        ("ANGR PRESENT CONTROL", angr_meta.get("present_control") or gfx.get("angr_present_control") or "NOT RUN"),
        ("ANGR CLEAR CONTROL", angr_meta.get("clear_control") or gfx.get("angr_clear_control") or "NOT RUN"),
        ("DEVICE→RENDERER", gfx.get("device_to_renderer") or "UNKNOWN"),
        ("DRAW CONSENSUS", gfx.get("draw_consensus") or "UNKNOWN"),
        ("RENDERER", gfx.get("renderer_classification") or "PROVEN ENGINE OBJECT"),
        ("RENDERER LIST", angr_meta.get("renderer_list") or gfx.get("renderer_list") or "UNKNOWN"),
        ("ENGINE DRAW", gfx.get("engine_draw") or "FOUND"),
        ("BACKEND HANDOFF", angr_meta.get("backend_handoff") or gfx.get("backend_handoff") or "UNKNOWN"),
        ("RAW DEVICE DRAW", angr_meta.get("raw_device_draw") or gfx.get("raw_device_draw") or "UNKNOWN"),
        ("DURABLE DEVICE ALIAS", angr_meta.get("durable_device_alias") or gfx.get("durable_device_alias") or "UNKNOWN"),
        ("FRAME ROOT", angr_meta.get("frame_root") or gfx.get("frame_root") or "UNKNOWN"),
        ("GRAPHICS BOUNDARY", angr_meta.get("graphics_boundary") or gfx.get("graphics_boundary") or "UNKNOWN"),
        ("RENDERER VECTOR", "MAPPED"),
        ("VECTOR INSERTION", angr_meta.get("vector_insertion") or "UNKNOWN"),
        ("ELEMENT +0x04", angr_meta.get("element_plus04") or "UNKNOWN"),
        ("IFACE PUBLICATION", angr_meta.get("iface_publication") or "UNKNOWN"),
        ("VTABLE", angr_meta.get("vtable_class") or "UNKNOWN"),
        ("METHOD +148", angr_meta.get("method_148_terminus") or "UNKNOWN"),
        ("METHOD +14C", angr_meta.get("method_14c_terminus") or "UNKNOWN"),
        ("METHOD +154", angr_meta.get("method_154_terminus") or "UNKNOWN"),
        ("P23 SEAM", angr_meta.get("post_init_seam") or seam),
        ("P23 D3D9", angr_meta.get("d3d9") or d3d_just),
        ("P23 BACKEND ADAPTER", angr_meta.get("engine_backend_adapter") or "UNKNOWN"),
        ("FIRST FRAME", "BLOCKED — PROTECTED BACKEND"),
        ("D3D9", "NOT JUSTIFIED"),
        ("ENGINE BACKEND", "NOT JUSTIFIED"),
        ("ENGINE FRONTEND", angr_meta.get("engine_frontend") or "UNKNOWN"),
        ("SUBMIT BACKEND", angr_meta.get("submit_backend") or "UNKNOWN"),
        ("VISIBLE SUBMIT CONTRACT", angr_meta.get("visible_submit_contract") or "UNKNOWN"),
        ("RAW D3D9 RESOURCE TRAFFIC", angr_meta.get("raw_d3d9_resource_traffic") or "UNKNOWN"),
        ("FRAME CORRELATION", angr_meta.get("frame_correlation") or "UNKNOWN"),
        ("GRAPHICS ARCHITECTURE", angr_meta.get("graphics_architecture") or "UNKNOWN"),
        ("SAFE RUNTIME SEAM", angr_meta.get("safe_runtime_seam") or "UNKNOWN"),
        ("STATIC FACTORY", static_factory),
        ("FACTORY FRONTIER READY", frontier_ready),
        ("DIRECT3D9 IMPLEMENTED", d3d_impl),
        ("Runtime factory frontier", runtime_factory),
        ("ORDINARY RUNTIME FRONTIER", _ordinary_frontier_badge(model)),
        ("TOP ORDINARY ISLAND", _top_island_badge(model)),
        ("REAL UC EXECUTION", _real_uc_execution_badge(model)),
        ("ORDINARY INITIALIZATION", _ordinary_init_badge(model)),
        ("CRT _CIsqrt", _cisqrt_badge(model)),
        ("DYNAMIC WIN32 TLS", _tls_badge(model)),
        ("WIN32 SYNCHRONIZATION", _sync_badge(model)),
        ("GUEST PROCESS", _guest_process_badge(model)),
        ("GUEST THREAD", _guest_thread_badge(model)),
    ]

    # Measure height with the same geometry as the SVG.
    class Measure(list):
        pass

    measure = Measure()
    y = badge_row(measure, badges, 14)
    y = draw_map(measure, "Function translation", translation, "translation_status",
                 TRANSLATION_COLOR, 16, y + 8, WIDTH - 32, 360, False)
    y = legend(measure, 16, y + 8, TRANSLATION_COLOR)
    y += 16
    y = draw_map(measure, "Runtime reachability", runtime, "runtime_status",
                 RUNTIME_COLOR, 16, y + 28, WIDTH - 32, 360, False)
    y = legend(measure, 16, y + 8, RUNTIME_COLOR)
    height = y + 36

    image = Image.new("RGB", (WIDTH, height), _hex_rgb(BG))
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.truetype("segoeui.ttf", 12)
        font_sm = ImageFont.truetype("segoeui.ttf", 10)
        font_title = ImageFont.truetype("segoeui.ttf", 15)
    except OSError:
        font = ImageFont.load_default()
        font_sm = font
        font_title = font

    def paint_map(title, groups, field, colors, x, top, w, h):
        draw.text((x, top + 2), title, fill=_hex_rgb(TEXT), font=font_title)
        body_y = top + 24
        body_h = h - 24
        rects = squarify([group["total"] for group in groups], x, body_y, w, body_h)
        for group, rect in zip(groups, rects):
            gx, gy, gw, gh = snap(rect)
            if gw <= 0 or gh <= 0:
                continue
            draw.rectangle([gx, gy, gx + gw - 1, gy + gh - 1], fill=_hex_rgb(PANEL), outline=_hex_rgb(LINE))
            header = 0
            if gh > 36 and gw > 80:
                header = 14
                percent = (100.0 * group["done"] / group["total"]) if group["total"] else 0
                caption = "%s %d/%d %.0f%%" % (group["name"], group["done"], group["total"], percent)
                if len(caption) * 6 > gw - 8:
                    caption = "%s %.0f%%" % (group["name"], percent)
                draw.text((gx + 4, gy + 2), caption, fill=_hex_rgb(MUTED), font=font_sm)
            boxes = cell_boxes(group["total"], gx + 2, gy + header + 2, max(0, gw - 4), max(0, gh - header - 4))
            for item, box in zip(group["items"], boxes):
                cx, cy, cw, ch = box
                color = _hex_rgb(colors[item[field]])
                if cw <= 1 or ch <= 1:
                    draw.point((cx, cy), fill=color)
                else:
                    draw.rectangle([cx, cy, cx + cw - 1, cy + ch - 1], fill=color)
        return top + h

    def paint_legend(x, top, colors):
        cursor = x
        for name, color in colors.items():
            draw.rectangle([cursor, top, cursor + 9, top + 9], fill=_hex_rgb(color))
            draw.text((cursor + 14, top - 1), name, fill=_hex_rgb(MUTED), font=font_sm)
            cursor += 14 + 7 * len(name) + 10
        return top + 18

    # Badges
    x = 16
    row_y = 14
    for label, value in badges:
        text = "%s  %s" % (label, value)
        width = 16 + int(6.6 * len(text))
        if x + width > WIDTH - 16:
            x = 16
            row_y += 28
        draw.rounded_rectangle([x, row_y, x + width, row_y + 22], radius=4,
                               fill=_hex_rgb(PANEL), outline=_hex_rgb(LINE))
        draw.text((x + 8, row_y + 4), text, fill=_hex_rgb(TEXT), font=font)
        x += width + 8
    y = row_y + 30
    y = paint_map("Function translation", translation, "translation_status",
                  TRANSLATION_COLOR, 16, y + 8, WIDTH - 32, 360)
    y = paint_legend(16, y + 8, TRANSLATION_COLOR)
    note = "High-confidence function compilation %d/%d. This is not project completion." % (
        trans["compiled"], trans["attempted"])
    draw.text((16, y + 4), note, fill=_hex_rgb(MUTED), font=font_sm)
    y += 16
    y = paint_map("Runtime reachability", runtime, "runtime_status",
                  RUNTIME_COLOR, 16, y + 28, WIDTH - 32, 360)
    y = paint_legend(16, y + 8, RUNTIME_COLOR)
    draw.text((16, y + 4), run["note"] + " Unlogged entries: UNKNOWN.",
              fill=_hex_rgb(MUTED), font=font_sm)

    from io import BytesIO
    buf = BytesIO()
    image.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def write_outputs(directory, model, svg, page, png=None):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, "progress.json"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump(model))
    with open(os.path.join(directory, "progress.svg"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(svg)
    with open(os.path.join(directory, "progress.html"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(page)
    if png is not None:
        with open(os.path.join(directory, "progress.png"), "wb") as handle:
            handle.write(png)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    directory = ANALYSIS
    if argv:
        directory = argv[0]
    model = build()
    svg = render_svg(model, detailed=False)
    page = render_html(model, render_svg(model, detailed=True))
    png = render_png(model)
    write_outputs(directory, model, svg, page, png)
    trans = model["translation"]
    print("cells %d compiled-record %d/%d compiler-failures %d recorded-entries %d"
          % (trans["map_cells"], trans["compiled"], trans["attempted"],
             trans["compiler_failures"], model["runtime"]["recorded_entries"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
