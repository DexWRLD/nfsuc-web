"""Phase 17 factory-frontier provenance tests.

Ordinary analysis only. Does not execute graphics code or synthesize state.
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_code_analyze as uca
import uc_funcmap as fm
import uc_initprov as ip
import uc_phase7_test as p7
import uc_phase17 as p17

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def expect(cond, text):
    if not cond:
        sys.exit(text)


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    raw_path = os.path.join(ANALYSIS, "phase17-raw.json")
    expect(os.path.isfile(raw_path), "phase17-raw missing")
    raw = json.load(open(raw_path, encoding="utf-8"))

    # Flag writer provenance
    fw = raw["flag_writer"]
    expect(fw["va"] == "0x00722D60", "writer va")
    expect(fw["map"]["label"] == "HIGH_CONFIDENCE", "writer high")
    expect(fw["map"]["reachable"] is True, "writer enrolled")
    expect(fw["e8_e9_sites"] == [], "no e8")
    expect(fw["text_immediate_refs"] == [], "no imm refs")
    expect(fw["invocation_path"] == "NONE", "no invocation")
    expect("enrollment" in raw["terminology"]["reachable_in_function_map"].lower()
           or "enrolled" in raw["terminology"]["reachable_in_function_map"].lower(),
           "terminology")

    # XCHG detection on image
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    expect(blob[0x00722D66 - base:0x00722D66 - base + 10] == bytes.fromhex("b801000000b91c1e3101"), "set1 imm")
    expect(blob[0x00722D70 - base] == 0x87, "xchg1")
    expect(blob[0x0072996D - base:0x0072996D - base + 5] == bytes.fromhex("b802000000"), "set2 imm")
    expect(blob[0x00B4F990 - base:0x00B4F990 - base + 8] == bytes.fromhex("33c0b91c1e310187"), "clear0")
    expect(raw["xchg"]["models_old_in_register"] is True, "xchg old")
    expect(raw["xchg"]["models_new_in_memory"] is True, "xchg new")
    expect(all(not s["is_lock"] for s in raw["xchg"]["sites"]), "no lock")

    # Slots
    starts, _ = fm.mark_starts(blob, base)
    for slot, value in p17.SLOTS.items():
        meta = raw["slots"][p17.hx(slot)]
        expect(starts[value - base] == 0, "slot off boundary " + hex(value))
        expect(meta["final_class"] == "RUNTIME_REPLACEMENT_REQUIRED", "slot class " + hex(slot))
        expect(meta["writers_absolute"] == [], "no slot writers " + hex(slot))
        expect(meta["alternatives"]["slot_is_iat"] is False, "not iat " + hex(slot))

    # Object / TLS
    expect(raw["object"]["key_field_roles"]["0x00000010"]["role"] == "WRITTEN_BY_FACTORY_PATH", "field +10")
    expect(raw["tls"]["writes"] == [], "no tls writes")
    expect(raw["tls"]["required_on_create_prefix"] is False, "tls not on create")
    expect(raw["tls"]["required_on_outer"] is True, "tls on outer")

    # Pre-factory path
    pre = raw["pre_factory"]
    expect(pre["reached_create_site"] is True, "reach site")
    expect(len(pre["indirects"]) == 3, "three call esi")
    expect(all(i["slot"] == "0x00B615C4" for i in pre["indirects"]), "esi slot")
    targets = [c["target"] for c in pre["calls_before"]]
    expect("0x0087A79C" in targets, "d3d thunk")
    expect(raw["create_helper_cut"] == "NO_PATH", "create independent")

    # FACTORY_FRONTIER_READY
    expect(raw["frontier"]["FACTORY_FRONTIER_READY"] is False, "not ready")
    expect(raw["frontier"]["create_high_reachable"] is True, "create high")
    expect(raw["frontier"]["indirect_ok"] is False, "indirect fail")
    expect(raw["execution"]["ran"] is False, "no exec")

    status = json.load(open(os.path.join(ANALYSIS, "project-status.json"), encoding="utf-8"))
    expect(status["current_phase"] == 17, "status phase")
    expect(status["graphics"]["reachable_from_high_graph"] == "YES", "static reachable")
    expect(status["graphics"]["enterable_now"] == "NO", "not enterable")
    expect(status["graphics"].get("factory_frontier_ready") is False, "frontier ready flag")

    # Preserve Phase 16 discovery regressions lightly
    text = open(os.path.join(ROOT, "tools", "uc_funcmap.py"), encoding="utf-8").read()
    expect("for _ in range(24):" not in text, "no 24 walk")
    expect("CFG_BUDGET_EXCEEDED" in text, "budget term")

    print("phase 17 ok")


if __name__ == "__main__":
    main()
