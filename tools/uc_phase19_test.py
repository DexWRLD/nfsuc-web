"""Phase 19 post-init graphics frontier tests."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_code_analyze as uca
import uc_phase15_graphics as g15
import uc_phase19 as p19

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def expect(cond, text):
    if not cond:
        sys.exit(text)


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    raw_path = os.path.join(ANALYSIS, "phase19-raw.json")
    expect(os.path.isfile(raw_path), "phase19-raw missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase19.md")), "phase19 report missing")
    raw = json.load(open(raw_path, encoding="utf-8"))

    # Factory freeze
    expect(
        raw["factory_boundary"]["classification"] == "BLOCKED_EXTERNAL_PROTECTED_INITIALIZATION",
        "factory frozen",
    )

    # Field consumers
    expect(raw["factory_result_field"]["va"] == "0x01318180", "field va")
    expect(raw["factory_result_field"]["absolute_consumer_count"] == 2, "two absolute consumers")

    # Device
    expect(raw["device"]["va"] == "0x013C6510", "device va")
    expect(raw["device"]["confidence"] == "PROVEN_D3D9_DEVICE", "device proven")
    expect(raw["device"]["consumer_owner_count"] >= 20, "many consumers")
    expect(raw["vtable_offset_count"] >= 10, "vtable histogram")

    # COM pattern / soft Present
    offs = {h["offset"].lower(): h for h in raw["vtable_histogram"]}
    # normalize
    def has_off(x):
        xi = int(x, 16)
        return any(int(h["offset"], 16) == xi for h in raw["vtable_histogram"])

    expect(has_off("0x44"), "present offset")
    expect(has_off("0xa4"), "beginscene offset")
    expect(has_off("0xa8"), "endscene offset")
    expect(has_off("0xac"), "clear offset")
    expect(raw["present"]["confidence"].startswith("PRESENT_"), "present conf")
    expect(len(raw["present"]["sites"]) >= 1, "present sites")

    # Live pattern check on image
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    lines = [l["text"].lower() for l in g15.decode_linear(blob, base, 0x00752AF0, 30, True)]
    expect(any("0x44" in t for t in lines), "present encoding in 752af0")
    expect(any("0xa8" in t for t in lines), "endscene encoding in 752af0")
    expect(blob[0x0072E3B9 - base] == 0xE8, "create call e8")
    expect(raw["direct3dcreate9_sites"]["count"] == 1, "single create site")
    expect(raw["direct3dcreate9_sites"]["still_single_site"] is True, "still one")

    # Islands / external distinction
    expect(raw["island_class_counts"].get("POST_INIT_GRAPHICS_EXTERNAL_STATE_ONLY", 0) >= 1, "state islands")
    expect(raw["external_state_vs_code"]["external_code_required_for_device_publication"] is True, "ext code")
    expect(raw["external_state_vs_code"]["external_state_only_for_present_prefix"] is True, "ext state")
    expect(any(c["status"] == "REQUIRED" for c in raw["runtime_contract"]), "contract required")

    # Frontiers
    expect(raw["FIRST_CLEAR_FRONTIER"]["status"] in ("FOUND", "BLOCKED_EXTERNAL", "NOT_FOUND", "UNKNOWN"), "clear")
    expect(raw["FIRST_DRAW_FRONTIER"]["status"] in ("FOUND", "BLOCKED_EXTERNAL", "NOT_FOUND", "UNKNOWN"), "draw")
    expect(raw["FIRST_PRESENT_FRONTIER"]["status"] in ("FOUND", "BLOCKED_EXTERNAL", "NOT_FOUND", "UNKNOWN"), "present")
    expect(raw["FIRST_CLEAR_FRONTIER"]["status"] == "BLOCKED_EXTERNAL", "clear blocked")
    expect(raw["FIRST_PRESENT_FRONTIER"]["status"] == "BLOCKED_EXTERNAL", "present blocked")
    expect(raw["FIRST_DRAW_FRONTIER"]["status"] == "NOT_FOUND", "draw not found")
    expect(raw["d3d9_implementation_justified"] is False, "no d3d impl")
    expect(raw["execution"]["ran"] is False, "no exec")
    expect(raw["first_frame_estimate"]["best_case_phase"] == "UNBOUNDED", "unbounded")

    # Dashboard fields in raw + status
    dash = raw["dashboard"]
    expect(dash["FACTORY_INITIALIZATION"] == "EXTERNAL/PROTECTED BLOCKED", "dash factory")
    expect(dash["POST_INIT_GRAPHICS_FRONTIER"] == "FOUND", "dash postinit")
    expect(dash["DEVICE_POINTER"] == "PROVEN", "dash device")

    status = json.load(open(os.path.join(ANALYSIS, "project-status.json"), encoding="utf-8"))
    expect(status["current_phase"] >= 19, "status phase")
    expect(status["graphics"]["factory_initialization"] == "EXTERNAL/PROTECTED BLOCKED", "status factory")
    expect(status["graphics"]["post_init_graphics_frontier"] == "FOUND", "status postinit")
    expect(status["graphics"]["device_pointer"] == "PROVEN", "status device")
    expect(status["graphics"]["first_clear"] == "BLOCKED_EXTERNAL", "status clear")
    expect(status["graphics"]["first_draw"] in ("NOT_FOUND", "FOUND_STRONG", "FOUND"), "status draw")
    expect(status["graphics"]["first_present"] == "BLOCKED_EXTERNAL", "status present")
    expect(status["first_frame_estimate"]["best_case_phase"] == "UNBOUNDED", "status estimate")

    # Preserve Phase 16–18
    expect(os.path.isfile(os.path.join(ANALYSIS, "phase18-raw.json")), "p18 raw")
    expect(os.path.isfile(os.path.join(ANALYSIS, "phase17-raw.json")), "p17 raw")
    text = open(os.path.join(ROOT, "tools", "uc_funcmap.py"), encoding="utf-8").read()
    expect("CFG_BUDGET_EXCEEDED" in text, "budget term")
    p18 = json.load(open(os.path.join(ANALYSIS, "phase18-raw.json"), encoding="utf-8"))
    expect(p18["frontier"]["FACTORY_FRONTIER_READY"] is False, "p18 not ready")

    print("phase 19 ok")


if __name__ == "__main__":
    main()
