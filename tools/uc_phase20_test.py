"""Phase 20 device lifecycle / seam tests."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_code_analyze as uca
import uc_phase15_graphics as g15

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def expect(cond, text):
    if not cond:
        sys.exit(text)


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    raw_path = os.path.join(ANALYSIS, "phase20-raw.json")
    expect(os.path.isfile(raw_path), "phase20-raw missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase20.md")), "phase20 report missing")
    raw = json.load(open(raw_path, encoding="utf-8"))

    # Out-param provenance
    pub = raw["device"]["publication"]
    expect(pub["class"] == "DEFINITE_DEVICE_PUBLICATION", "pub class")
    expect("0x007252B6" in str(pub["instructions"]), "outparam1")
    expect(raw["createdevice"]["out_param_proof"] is True, "outparam proof")
    expect(raw["createdevice"]["confidence"] == "CREATEDEVICE_STRONG_CANDIDATE", "cd conf")
    expect(raw["createdevice"]["vtable_offset"] == "0x40", "cd off")

    # Helper / callback
    expect(raw["helper_relationship"]["before_device_publication"] is True, "helper before")
    expect(raw["callback_relationship"]["mandatory_for_in_game_publication"] is True, "cb yes")
    expect(raw["callback_relationship"]["mandatory_for_present_prefix"] is False, "cb present no")

    # Lifecycle / reset / recovery
    expect(raw["reset"]["confidence"] == "RESET_NOT_FOUND", "reset")
    expect(raw["recovery"]["found"] is False, "recovery")
    expect(raw["republication"]["found"] is False, "repub")

    # Present / clear / draw
    expect(raw["PRESENT_CODE_FRONTIER"]["status"] == "FOUND", "present code")
    expect(raw["PRESENT_RUNTIME_FRONTIER"]["status"] == "BLOCKED_EXTERNAL_DEVICE_STATE", "present rt")
    expect(raw["clear"]["confidence"] == "CLEAR_PROVEN", "clear")
    expect(raw["FIRST_DRAW_FRONTIER"]["status"] == "FOUND_STRONG", "draw frontier")
    expect(raw["draw"]["count"] >= 1, "draw candidates")

    # Alias / wrapper structures exist
    expect("count" in raw["aliases"], "aliases")
    expect(isinstance(raw["wrappers"], list), "wrappers")

    # Contract / seam
    expect(any(c["class"] == "D3D_DEVICE_STATE" for c in raw["runtime_contract"]), "contract")
    expect(raw["seam"]["classification"] == "PARTIAL_POST_INIT_SEAM", "seam")
    expect(raw["seam"]["requires_reproducing_protected_semantics"] is False, "seam safe")
    expect(raw["d3d9_implementation"]["decision"] == "NO", "impl no")
    expect(raw["first_frame_estimate"]["best_case_phase"] == "UNBOUNDED", "unbounded")
    expect(raw["execution"]["ran"] is False, "no exec")

    # Live image checks
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    expect(blob[0x007252B6 - base:0x007252B6 - base + 5] == bytes.fromhex("6810653c01"), "push device")
    lines = [l["text"].lower() for l in g15.decode_linear(blob, base, 0x007297D0, 80, False)]
    expect(any("0x686000" in t for t in lines), "helper in caller")
    expect(any("0x725200" in t for t in lines), "pub in caller")
    # helper appears before first 725200 in listing order
    hi = next(i for i, t in enumerate(lines) if "0x686000" in t)
    pi = next(i for i, t in enumerate(lines) if "0x725200" in t)
    expect(hi < pi, "helper before pub in listing")

    # Dashboard + status
    dash = raw["dashboard"]
    expect(dash["DEVICE_CODE"] == "PROVEN", "dash device code")
    expect(dash["DEVICE_PUBLICATION"] == "EXTERNAL/BLOCKED", "dash pub")
    expect(dash["PRESENT_CODE"] == "FOUND", "dash present code")
    expect(dash["PRESENT_RUNTIME"] == "BLOCKED", "dash present rt")
    expect(dash["DRAW_CODE"] == "FOUND", "dash draw")
    expect(dash["POST_INIT_SEAM"] == "PARTIAL", "dash seam")
    expect(dash["D3D9_IMPLEMENTATION"] == "NOT JUSTIFIED", "dash impl")

    status = json.load(open(os.path.join(ANALYSIS, "project-status.json"), encoding="utf-8"))
    expect(status["current_phase"] == 20, "phase")
    expect(status["graphics"]["device_publication"] == "EXTERNAL/BLOCKED", "status pub")
    expect(status["graphics"]["present_code"] == "FOUND", "status present code")
    expect(status["graphics"]["present_runtime"] == "BLOCKED", "status present rt")
    expect(status["graphics"]["draw_code"] == "FOUND", "status draw")
    expect(status["graphics"]["post_init_seam"] == "PARTIAL", "status seam")
    expect(status["graphics"]["d3d9_implementation_justified"] is False, "status impl")
    expect(status["first_frame_estimate"]["best_case_phase"] == "UNBOUNDED", "status est")

    # Regressions 16-19
    expect(os.path.isfile(os.path.join(ANALYSIS, "phase19-raw.json")), "p19")
    expect(os.path.isfile(os.path.join(ANALYSIS, "phase18-raw.json")), "p18")
    text = open(os.path.join(ROOT, "tools", "uc_funcmap.py"), encoding="utf-8").read()
    expect("CFG_BUDGET_EXCEEDED" in text, "budget")

    print("phase 20 ok")


if __name__ == "__main__":
    main()
