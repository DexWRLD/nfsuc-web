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


def build():
    function_map = load_json("function-map.json")
    compiled = load_json("high-confidence.json")
    frontier = load_json("runtime-frontier.json")
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
    model = {
        "project": {
            "name": "nfsuc-web",
            "current_phase": status["current_phase"],
            "strategy": status["strategy"],
        },
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
                "The badge is the Phase 5 compile record in high-confidence.json. "
                "Green cells are the current reachable high-confidence functions. "
                "The map does not say which compiled function was later removed from that set."
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
            "ready_closure": frontier["all_node_extremes"]["READY"]["size"],
            "ready_with_imports_closure": frontier["all_node_extremes"]["READY_WITH_IMPLEMENTED_IMPORTS"]["size"],
            "note": "A compiled function is not a function that has run.",
        },
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
                "source": "runtime-frontier.json",
                "largest_ready_closure": frontier["all_node_extremes"]["READY"]["size"],
                "largest_ready_with_imports": frontier["all_node_extremes"]["READY_WITH_IMPLEMENTED_IMPORTS"]["size"],
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
    badges = [
        ("Functions compiled", "%d/%d" % (trans["compiled"], trans["attempted"])),
        ("Compiler failures", str(trans["compiler_failures"])),
        ("Recorded entries", str(run["recorded_entries"])),
        ("Phase", str(model["project"]["current_phase"])),
        ("External boundary", "0x00686000"),
        ("Helper cut", cut_text),
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
<h2>Initialization</h2>
%s
<h2>External boundary</h2>
<p><code>0x00686000</code> %s. Direct call sites %d. High-confidence span sites %d. Reachable high-confidence span sites %d. Not implemented, not substituted, not lifted, not executed.</p>
<p>Control-flow cut: %s.</p>
<p><code>0x0055FF30</code> %s. This is not a protected classification.</p>
<h2>Current frontier</h2>
<p>Current blocker: <code>0x00686000</code>, %s.</p>
<p>Strategy: %s</p>
<p>Direct3DCreate9 independent of <code>0x00686000</code>: %s. Reachable from the high-confidence graph: %s. Enterable now: %s. Call <code>%s</code> in <code>%s</code> (%s).</p>
<p>First-frame estimate, marked as an estimate: best case phase %d, likely %d–%d. %s</p>
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
        html_table(("Address", "Status", "Writer", "Value"), init_rows),
        html.escape(boundary["status"]),
        boundary["direct_call_sites"],
        boundary["high_confidence_span_sites"],
        boundary["reachable_high_span_sites"],
        html.escape(cut_line),
        html.escape(unknown_b["status"]),
        html.escape(boundary["status"]),
        html.escape(model["project"]["strategy"]),
        html.escape(graphics["independent_of_0x00686000"]),
        html.escape(graphics["reachable_from_high_graph"]),
        html.escape(graphics["enterable_now"]),
        html.escape(graphics["call"]),
        html.escape(graphics["function"]),
        html.escape(graphics["confidence"]),
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


def write_outputs(directory, model, svg, page):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, "progress.json"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump(model))
    with open(os.path.join(directory, "progress.svg"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(svg)
    with open(os.path.join(directory, "progress.html"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(page)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    directory = ANALYSIS
    if argv:
        directory = argv[0]
    model = build()
    svg = render_svg(model, detailed=False)
    page = render_html(model, render_svg(model, detailed=True))
    write_outputs(directory, model, svg, page)
    trans = model["translation"]
    print("cells %d compiled-record %d/%d compiler-failures %d recorded-entries %d"
          % (trans["map_cells"], trans["compiled"], trans["attempted"],
             trans["compiler_failures"], model["runtime"]["recorded_entries"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
