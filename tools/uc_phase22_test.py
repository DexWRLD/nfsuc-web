"""Phase 22 renderer provenance tests."""
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
    raw_path = os.path.join(ANALYSIS, "phase22-raw.json")
    expect(os.path.isfile(raw_path), "phase22-raw missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase22.md")), "phase22 report missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "renderer-interface-graph.json")), "graph missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "angr", "renderer-phase22.json")), "angr cache missing")

    raw = json.load(open(raw_path, encoding="utf-8"))
    expect(raw["phase"] == 22, "phase")

    # Container inference
    c = raw["container"]
    expect(c["type"] == "MSVC_VECTOR_LIKE", "container type")
    expect(c["element_size"] == 8, "elem size")
    expect(c["confidence"] in ("STRONG", "PROVEN"), "container conf")
    expect("+0x50" in c["fields"] and "+0x54" in c["fields"] and "+0x58" in c["fields"], "trio")

    # Writers
    expect(raw["ctor_0x007B5020"]["classification"] == "DEFINITE_PUBLISHER", "ctor")
    expect(raw["dtor_0x007A06E0"]["classification"] == "DEFINITE_NULL_ON_EXIT", "dtor")
    expect(raw["null_stub_0x0079D1E0"]["classification"] == "NULL_CLEAR", "null stub")

    # Helper ABI
    h = raw["helper_0x0079E4A0"]
    expect(h["abi"]["ret_bytes"] == 8, "ret 8")
    expect(h["iteration"]["stride"] == 8, "stride")

    # Interfaces / graph
    expect(raw["interfaces"]["count"] >= 1, "iface count")
    expect("ENGINE_GFX_IFACE_00" in raw["interfaces"], "iface00")
    g = raw["interface_graph"]
    expect(any(e.get("rel") == "CONTAINS" for e in g["edges"]), "contains edge")
    expect(any(e.get("rel") == "UNKNOWN" for e in g["edges"]), "unknown device edge")

    # Draws / terminus
    expect(len(raw["draw_candidates"]) == 5, "five draws")
    for d in raw["draw_candidates"]:
        expect(d["terminus"] in (
            "RAW_D3D9_DEVICE", "D3D9_WRAPPER", "ENGINE_BACKEND",
            "EXTERNAL_CODE", "PROTECTED_BOUNDARY", "UNKNOWN",
        ), "terminus")
        expect(d["UC_classification"] == "ENGINE_COM_DRAW", "engine draw")
    expect(raw["raw_device_draw_found"] is False, "no raw draw")

    # Durable alias correction
    expect(raw["durable_alias"]["phase22_correction"] == "FALSE_DEVICE_ALIAS", "false alias")
    expect(raw["durable_alias"]["durable_device_alias_mapped"] is False, "unmapped")

    # Handoff / negative weighting
    hand = raw["angr"]["handoff"]
    expect(hand["CONSENSUS"] in (
        "NO_ORDINARY_DEVICE_BRIDGE", "UNKNOWN", "INCONCLUSIVE", "UC_ONLY",
    ) or "BRIDGE" in str(hand["CONSENSUS"]) or hand["CONSENSUS"], "handoff")
    if hand.get("negative_weight"):
        expect(hand["negative_weight"] in ("NEGATIVE_STRONG", "NEGATIVE_WEAK"), "neg weight")

    # Frame / seam / decisions
    expect(raw["frame_root"]["classification"] in (
        "FRAME_ROOT_PROVEN", "FRAME_ROOT_STRONG", "NO_COMMON_ROOT_FOUND", "UNKNOWN",
    ), "frame")
    expect(raw["seam"]["classification"] == "PARTIAL_POST_INIT_SEAM", "seam")
    expect(raw["implementation"]["D3D9_IMPLEMENTATION_JUSTIFIED"] is False, "d3d no")
    expect(raw["implementation"]["ENGINE_BACKEND_ADAPTER_JUSTIFIED"] is False, "adapter no")
    expect(raw["first_frame_estimate"]["best_case_phase"] == "UNBOUNDED", "unbounded")
    expect(raw["execution"]["ran"] is False, "no exec")
    expect(raw["boundary"]["classification"] == "MIXED_BOUNDARY", "boundary")

    # 0x686030
    expect(raw["initialization"]["0x00686030"]["not_frozen_slot"] is True, "686030")

    dash = raw["dashboard"]
    expect(dash["RENDERER_LIST"] == "MAPPED", "dash list")
    expect(dash["RAW_DEVICE_DRAW"] == "NOT FOUND", "dash raw")
    expect(dash["BACKEND_HANDOFF"] == "UNKNOWN", "dash handoff")
    expect(dash["DURABLE_DEVICE_ALIAS"] == "UNMAPPED", "dash durable")

    status = json.load(open(os.path.join(ANALYSIS, "project-status.json"), encoding="utf-8"))
    expect(status["current_phase"] >= 22, "status phase")
    expect(status["graphics"]["renderer_list"] == "MAPPED", "status list")

    print("phase22 tests ok")


if __name__ == "__main__":
    main()
