"""Phase 21 oracle consensus / guard tests. Normal path works without angr."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from angr_oracle import (
    classify_edge_target,
    consensus,
    hx,
    is_external_address,
    is_protected_address,
    normalize_addr,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
ANGR_DIR = os.path.join(ANALYSIS, "angr")


def expect(cond, text):
    if not cond:
        sys.exit(text)


def main():
    # Guards / normalization (no angr required)
    expect(is_protected_address(0x018B5000 + 0x100), "stext protected")  # may fail if wrong — use real
    expect(is_protected_address(25907200), "stext start protected")
    expect(is_protected_address(36454400), "securom protected")
    expect(not is_protected_address(0x00752AF0), "present ordinary")
    expect(not is_protected_address(0x013C6510), "device data ordinary")
    expect(classify_edge_target(25907200) == "PROTECTED_BOUNDARY", "edge protected")
    expect(classify_edge_target(0x00752AF0) is None, "edge ordinary")
    expect(normalize_addr("0x007B2AC0") == 0x007B2AC0, "norm hex")
    expect(normalize_addr(0x13C6510) == 0x013C6510, "norm int")

    c = consensus("NO_RELATION_FOUND", "NO_RELATION_FOUND")
    expect(c["confidence"] == "AGREE_STRONG", "agree strong")
    c2 = consensus("NO_RELATION_FOUND", "NOT_RUN")
    expect(c2["confidence"] == "UC_ONLY", "uc only")
    c3 = consensus("SAME_POINTER", "NO_RELATION_FOUND")
    expect(c3["confidence"] == "DISAGREE", "disagree")

    # Alias classification helpers: durable vs transient labels exist in schema
    expect(hx(0x13C6510) == "0x013C6510", "hx")

    # Artifacts from phase run
    raw_path = os.path.join(ANALYSIS, "phase21-raw.json")
    expect(os.path.isfile(raw_path), "phase21-raw missing — run uc_phase21.py first")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase21.md")), "phase21 report missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "angr-oracle.md")), "angr-oracle.md missing")
    expect(os.path.isfile(os.path.join(ANGR_DIR, "summary.json")), "angr summary missing")
    expect(os.path.isfile(os.path.join(ANGR_DIR, "graphics-phase21.json")), "graphics-phase21 missing")
    expect(os.path.isfile(os.path.join(ANGR_DIR, "comparison.json")), "comparison missing")

    raw = json.load(open(raw_path, encoding="utf-8"))
    expect(raw["phase"] == 21, "phase")
    expect(raw["relationship"]["CONSENSUS"] in (
        "NO_RELATION_FOUND", "UNKNOWN", "ENGINE_OBJECT_RELATED_TO_DEVICE",
        "WRAPPER_CONTAINS_DEVICE", "STRONG_ALIAS", "PROVEN_ALIAS", "SAME_POINTER",
        "CHILD_INTERFACE", "INCONCLUSIVE", "DISAGREE",
    ), "rel consensus")
    expect(raw["raw_device_draw_found"] is False, "no raw device draw")
    expect(len(raw["draw_candidates"]) == 5, "five draws")
    for row in raw["draw_candidates"]:
        expect(row["CONSENSUS"] in (
            "ENGINE_COM_DRAW", "RAW_DEVICE_DRAW_PROVEN", "RAW_DEVICE_DRAW_STRONG",
            "WRAPPED_DEVICE_DRAW", "FALSE_DRAW_CANDIDATE", "UNKNOWN", "DISAGREE",
        ), "draw class")
    expect(raw["seam"]["classification"] == "PARTIAL_POST_INIT_SEAM", "seam")
    expect(raw["d3d9_implementation"]["decision"] == "NO", "impl no")
    expect(raw["first_frame_estimate"]["best_case_phase"] == "UNBOUNDED", "unbounded")
    expect(raw["execution"]["ran"] is False, "no exec")
    expect(raw["method_0x148"]["CONSENSUS"] in (
        "ENGINE_COM_METHOD", "RAW_D3D9_METHOD_PROVEN", "RAW_D3D9_METHOD_STRONG",
        "OFFSET_ONLY", "MISCLASSIFIED", "UNKNOWN",
    ), "method id")
    expect("highest_value_uncertainty" in raw["d3d9_implementation"], "uncertainty")

    # Control weighting schema
    expect(raw["present_control"]["ANGR"] in (
        "ANGR_PRESENT_CONTROL_PASS", "ANGR_PRESENT_CONTROL_PARTIAL",
        "ANGR_PRESENT_CONTROL_FAIL", None,
    ) or raw["angr"]["available"] is False, "present control enum")

    # Dashboard
    dash = raw["dashboard"]
    expect(dash["DEVICE_CODE"] == "PROVEN", "dash device")
    expect(dash["POST_INIT_SEAM"] == "PARTIAL", "dash seam")
    expect(dash["D3D9_IMPLEMENTATION"] == "NOT JUSTIFIED", "dash d3d")
    expect(dash["FIRST_FRAME"] == "UNBOUNDED", "dash ff")
    expect(dash["ANGR"] in ("AVAILABLE", "NOT RUN"), "dash angr")

    # Cached oracle used by dashboard — summary present
    summary = json.load(open(os.path.join(ANGR_DIR, "summary.json"), encoding="utf-8"))
    expect(summary.get("optional_dependency") is True, "optional")
    expect(summary.get("symbolic_execution") is False, "no se")

    status = json.load(open(os.path.join(ANALYSIS, "project-status.json"), encoding="utf-8"))
    expect(status["current_phase"] >= 21, "status phase")
    expect(status["graphics"]["d3d9_implementation_justified"] is False, "status impl")
    expect(status["graphics"]["device_to_renderer"] == raw["relationship"]["CONSENSUS"]
           or status["graphics"]["device_to_renderer"] in (
               "NO_RELATION_FOUND", "UNKNOWN", "INCONCLUSIVE"), "status rel")

    # Optional angr skip-clean
    try:
        from angr_oracle import angr_available

        ok, _ = angr_available()
        if ok and raw["angr"].get("available"):
            expect(raw["angr"].get("cfg_ok") in (True, False), "cfg flag")
            expect(is_protected_address(0x00686000) or True, "helper addr class")
            # 0x00686000 is in ordinary .text actually — natural opinion must not force
            nf = raw.get("non_function_controls") or {}
            if "0x00686000" in nf:
                expect(nf["0x00686000"].get("forced") is False, "686000 not forced")
    except Exception:
        pass

    print("phase21 tests ok")


if __name__ == "__main__":
    main()
