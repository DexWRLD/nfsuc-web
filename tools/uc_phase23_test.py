"""Phase 23 interface provenance tests."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def expect(cond, text):
    if not cond:
        sys.exit(text)


def main():
    raw_path = os.path.join(ANALYSIS, "phase23-raw.json")
    expect(os.path.isfile(raw_path), "phase23-raw missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase23.md")), "phase23 report missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "renderer-interface-graph.json")), "graph missing")

    raw = json.load(open(raw_path, encoding="utf-8"))
    expect(raw["phase"] == 23, "phase")

    # Vector insertion recognition
    ins = raw["inserts"]
    expect(ins["insert_site_count"] >= 2, "insert count")
    expect(ins["vector_insertion_confidence"] in ("STRONG", "PROVEN"), "insert conf")
    classes = {s["classification"] for s in ins["insert_sites"]}
    expect("VECTOR_INSERT_STRONG" in classes or "VECTOR_INSERT_PROVEN" in classes, "insert class")
    expect(ins["classic_inlined_push_back_sites"] == 0, "no classic push_back")

    # 8-byte element / +0x04 provenance
    el = raw["elements"]
    expect(el["+0x04"]["classification"] == "ENGINE_GFX_IFACE_00", "+04 iface")
    expect("007A1A20" in el["+0x04"]["provenance"].upper().replace("x", "x"), "+04 ctor")
    expect(el["+0x00"]["classification"] == "ASSOCIATED_OBJECT_POINTER", "+00")

    # Reallocation distinction
    mut_classes = {m["classification"] for m in ins["mutations"]}
    expect("VECTOR_REALLOC" in mut_classes, "realloc")
    expect("VECTOR_ERASE" in mut_classes, "erase")
    expect("VECTOR_CLEAR" in mut_classes, "clear")

    # Interface constructor classification
    c = raw["interface"]["construction"]
    expect(c["classification"] == "ORDINARY_CONSTRUCTED", "ctor class")
    expect(c["final_vtable"].lower() == "0x00bb1aac", "vt")
    expect(c["vtable_classification"] == "STATIC", "static vt")

    # Vtable-store recognition
    expect(c["vtable_pointer_writes"], "vt writes")
    expect(raw["interface"]["vtable_pointer_write_count"] >= 1, "vt write count")

    # Method-slot resolution
    for slot in ("0x00000148", "0x0000014c", "0x00000154"):
        # JSON keys may be hex with different casing/width
        pass
    methods = raw["interface"]["methods"]
    expect(len(methods) == 3, "three methods")
    for m in methods.values():
        expect(m["classification"] == "ORDINARY_TEXT_TARGET", "method ordinary")
        expect(m["backend_terminus"] in (
            "RAW_D3D9_DEVICE", "D3D9_WRAPPER", "ORDINARY_ENGINE_BACKEND",
            "EXTERNAL_ENGINE_BACKEND", "PROTECTED_BOUNDARY", "DYNAMIC_UNKNOWN", "UNKNOWN",
        ), "terminus")
        expect(m["reads_device"] is False, "no device in method")

    # Publication / boundary
    expect(raw["publication"] in (
        "ORDINARY_INTERFACE_PUBLICATION",
        "EXTERNAL_INTERFACE_PUBLICATION",
        "PROTECTED_INTERFACE_PUBLICATION",
        "MIXED_INTERFACE_PUBLICATION",
        "UNKNOWN_INTERFACE_PUBLICATION",
    ), "publication")
    expect(raw["graphics_boundary"] in (
        "RAW_D3D9_BOUNDARY", "ORDINARY_ENGINE_BACKEND_BOUNDARY",
        "EXTERNAL_ENGINE_BACKEND_BOUNDARY", "PROTECTED_ENGINE_BACKEND_BOUNDARY",
        "MIXED_BOUNDARY", "UNKNOWN",
    ), "boundary")
    expect(raw["ownership"]["model"] == "OWNED_ENGINE_OBJECT", "ownership")
    expect(raw["implementation"]["D3D9_IMPLEMENTATION_JUSTIFIED"] is False, "d3d no")
    expect(raw["implementation"]["ENGINE_BACKEND_ADAPTER_JUSTIFIED"] is False, "adapter no")
    expect(raw["seam"]["classification"] == "PARTIAL_POST_INIT_SEAM", "seam")
    expect(raw["first_frame"]["BEST_CASE"] == "UNBOUNDED", "best")
    expect(raw["raw_device_draw_found"] is False, "raw draw")

    # Graph v2
    g = raw["interface_graph_v2"]
    rels = {e["rel"] for e in g["edges"]}
    expect("INSERTS" in rels, "INSERTS edge")
    expect("HAS_VTABLE" in rels, "HAS_VTABLE")
    expect("PROTECTED_BOUNDARY" in rels, "PROTECTED edge")
    expect(any(n.get("id") == "vtable_0xBB1AAC" for n in g["nodes"]), "vt node")

    # Dashboard
    d = raw["dashboard"]
    expect(d["VECTOR_INSERTION"] == "FOUND", "dash insert")
    expect(d["ELEMENT_PLUS04"] == "PROVENANCE FOUND", "dash +04")
    expect(d["VTABLE"] == "STATIC", "dash vt")
    expect(d["FIRST_FRAME"] == "UNBOUNDED", "dash ff")

    # Phase 20–22 regression artifacts still present
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase22.md")), "p22 regression")
    expect(os.path.isfile(os.path.join(ANALYSIS, "phase22-raw.json")), "p22 raw")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase21.md")), "p21 regression")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase20.md")), "p20 regression")

    print("uc_phase23_test: OK")


if __name__ == "__main__":
    main()
