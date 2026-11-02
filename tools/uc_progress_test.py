"""Checks for the progress dashboard. Uses committed analysis JSON only."""

import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import progress


def expect(cond, text):
    if not cond:
        sys.exit(text)


def main():
    first = progress.build()
    second = progress.build()
    expect(progress.dump(first) == progress.dump(second), "json drift")
    svg_a = progress.render_svg(first, detailed=False)
    svg_b = progress.render_svg(second, detailed=False)
    expect(svg_a == svg_b, "svg drift")
    page_a = progress.render_html(first, progress.render_svg(first, detailed=True))
    page_b = progress.render_html(second, progress.render_svg(second, detailed=True))
    expect(page_a == page_b, "html drift")

    function_map = progress.load_json("function-map.json")
    compiled = progress.load_json("high-confidence.json")
    functions = first["functions"]
    expect(len(functions) == len(function_map["functions"]), "function count")
    addresses = [item["address"] for item in functions]
    expect(len(addresses) == len(set(addresses)), "unique addresses")
    expect(addresses == sorted(addresses, key=lambda item: int(item, 16)), "sort")
    reachable_high = sum(
        1 for row in function_map["functions"]
        if row["label"] == "HIGH_CONFIDENCE" and row.get("reachable"))
    expect(first["translation"]["counts"]["COMPILED"] == reachable_high, "compiled cells")
    expect(first["translation"]["compiled"] == compiled["compiled"], "compile record")
    expect(first["translation"]["generated"] == compiled["generated"], "generated record")
    expect(first["translation"]["compiler_failures"] == compiled["compiler_failures"], "compiler failures")
    expect(first["translation"]["compiler_failures"] == 0, "compiler failure value")
    completed = [item for item in functions if item.get("completed")]
    expect(first["runtime"]["counts"]["EXECUTED"] == len(completed), "executed cells")
    expect(first["runtime"]["unlogged_entries"] == "UNKNOWN", "unlogged stays unknown")
    by_addr = {item["address"]: item for item in functions}
    expect(by_addr["0x0072E340"]["external_helper"] == "UNKNOWN", "medium stays unknown")
    expect(by_addr["0x0072E340"]["translation_status"] == "DISCOVERED_NOT_GENERATED", "medium not compiled")
    expect(by_addr["0x00830380"]["runtime_status"] == "BLOCKED_EXTERNAL", "must caller")
    expect(by_addr["0x00830380"]["external_helper"] == "MUST_REACH_EXTERNAL_HELPER", "must label")
    expect(first["helper_cut"]["must"] == 11, "must count")
    expect(first["helper_cut"]["may"] == 31, "may count")
    expect(first["helper_cut"]["independent"] == 6456, "independent count")
    expect(first["boundaries"]["0x0055FF30"]["status"] == "UNKNOWN", "unknown helper")
    expect("PROTECTED" not in first["boundaries"]["0x0055FF30"]["status"], "unknown is not protected")
    expect(first["graphics"]["independent_of_0x00686000"] == "YES", "d3d independence")
    expect(first["graphics"]["enterable_now"] == "NO", "d3d not enterable")

    svg_cells = svg_a.count("data-addr=")
    expect(svg_cells == 2 * len(functions), "svg cells")
    root = ET.fromstring(svg_a)
    seen = set()
    for node in root.iter():
        if node.tag.endswith("rect") and node.get("data-addr"):
            seen.add(node.get("data-addr"))
    expect(seen == set(addresses), "svg addresses")
    blob = svg_a + page_a + progress.dump(first)
    for banned in ("e8f63f2fae", "MZ", "This program cannot be run"):
        expect(banned not in blob, "embedded content " + banned)

    png_a = progress.render_png(first)
    png_b = progress.render_png(second)
    expect(png_a == png_b, "png drift")
    expect(png_a[:8] == b"\x89PNG\r\n\x1a\n", "png signature")

    left = tempfile.mkdtemp(prefix="uc-progress-")
    right = tempfile.mkdtemp(prefix="uc-progress-")
    progress.main([left])
    progress.main([right])
    for name in ("progress.json", "progress.svg", "progress.html", "progress.png"):
        mode = "rb" if name.endswith(".png") else "r"
        encoding = None if name.endswith(".png") else "utf-8"
        with open(os.path.join(left, name), mode, encoding=encoding) as handle:
            a = handle.read()
        with open(os.path.join(right, name), mode, encoding=encoding) as handle:
            b = handle.read()
        expect(a == b, "file drift " + name)
        if name.endswith(".json"):
            json.loads(a)
        if name.endswith(".svg"):
            ET.fromstring(a)
        if name.endswith(".png"):
            expect(a[:8] == b"\x89PNG\r\n\x1a\n", "written png")
    print("progress dashboard ok", len(functions), first["runtime"]["counts"]["EXECUTED"])


if __name__ == "__main__":
    main()
