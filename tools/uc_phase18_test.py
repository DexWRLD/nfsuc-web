"""Phase 18 callback-table provenance tests.

Ordinary analysis only. Does not execute graphics code or patch .rdata.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_code_analyze as uca
import uc_funcmap as fm
import uc_phase18 as p18

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def expect(cond, text):
    if not cond:
        sys.exit(text)


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    raw_path = os.path.join(ANALYSIS, "phase18-raw.json")
    expect(os.path.isfile(raw_path), "phase18-raw missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "callback-table-map.json")), "table map missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase18.md")), "phase18 report missing")
    raw = json.load(open(raw_path, encoding="utf-8"))

    # Terminology
    term = raw["terminology"]
    expect("enrollment" in term["map_reachable_field"].lower(), "map reachable term")
    expect("DISCOVERED_HIGH" in term, "discovered term")
    expect("CALL_GRAPH_REACHABLE" in term, "call-graph term")

    # Table-boundary inference
    home = raw["table"]["containing_run"]
    expect(home is not None, "home run")
    expect(home["lo"] == "0x00B61528", "home lo")
    expect(home["hi"] == "0x00B615E4", "home hi")
    expect(home["n"] == 48, "home n")
    expect(raw["table"]["all_three_in_same_run"] is False, "three slots not one run")
    expect(len(raw["table"]["pointer_dense_runs"]) >= 3, "multiple runs")

    # Slot classification / invalid initial targets
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    starts, _ = fm.mark_starts(blob, base)
    for slot, value in p18.SLOTS.items():
        meta = raw["slots"][p18.hx(slot)]
        expect(starts[value - base] == 0, "slot off boundary " + hex(value))
        expect(meta["final_class"] == "RUNTIME_REPLACEMENT_REQUIRED", "runtime class")
        expect(meta["in_ordinary_named_iat"] is False, "not named iat " + hex(slot))
        expect(meta["in_pe_import_firstthunk"] is None, "not pe firstthunk " + hex(slot))
        expect(
            meta["initial_interpretation"]["class"]
            == "DELIBERATELY_INVALID_SENTINEL_OR_PLACEHOLDER",
            "placeholder " + hex(slot),
        )

    # Consumers / ABI grouping
    b615 = raw["slots"]["0x00B615C4"]
    expect(b615["consumer_count"] == 3, "three consumers")
    abi = raw["three_call"]["abi_inference"]
    expect(abi["stack_args_each"] == 4, "four args")
    expect(abi["caller_cleans"] is False, "callee cleans")
    expect(len(abi["observed_imm_args"]) == 3, "three calls")
    expect(abi["observed_imm_args"][0]["stdcall_args"]["code"] == "0x3A", "code1")
    expect(abi["observed_imm_args"][1]["stdcall_args"]["code"] == "0x34", "code2")
    expect(abi["observed_imm_args"][2]["stdcall_args"]["code"] == "0x32", "code3")
    expect(abi["observed_imm_args"][2]["stdcall_args"]["size"] == 0x18, "size3")

    # Alias / bulk / shadow
    expect(raw["alias_writers"]["definite"] == [], "no definite writers")
    expect(raw["bulk_copies"] == [], "no bulk overlap")
    expect(raw["shadow_table"]["found"] is False, "no shadow")

    # PE import / memory protection
    pe = raw["pe_import_binding"]
    expect(pe["import_directory_section"] == ".securom", "import in securom")
    expect(pe["iat_directory_section"] == ".securom", "iat in securom")
    expect(pe["descriptors_overlap_ordinary_B610_B617"] == [], "no ordinary descriptor overlap")
    expect(raw["memory_protection"]["evidence_linking_to_table"] is False, "no vp link")
    expect(raw["memory_protection"]["ordinary_text_refs_to_virtualprotect_iat"] == 0, "no vp imm")

    # Publication / frontier
    pub = raw["publishers"]["publication"]
    expect(pub["class"] == "EXTERNAL_PROTECTED_INITIALIZATION", "pub class")
    expect(pub["needs_protected_external"] is True, "needs protected")
    expect(pub["call_graph_reachable"] is False, "pub not reachable")
    expect(raw["frontier"]["FACTORY_FRONTIER_READY"] is False, "not ready")
    expect(raw["frontier"]["PRE_FACTORY_CALLBACK"] == "UNRESOLVED", "callback unresolved")
    expect(raw["frontier"]["STATIC_FACTORY"] == "REACHABLE", "static reachable")
    expect(raw["frontier"]["DIRECT3D9_IMPLEMENTED"] is False, "no d3d")
    expect(raw["execution"]["ran"] is False, "no exec")

    # Flag=1
    expect(raw["flag_set1"]["indirect"]["indirect_candidate"] == "NONE_OBSERVED", "flag indirect")
    expect(raw["flag_set1"]["indirect"]["ordinary_section_dword_hits"] == [], "flag dword")
    expect(raw["flag_set1"]["status"]["call_graph_reachable"] is False, "flag not cg")

    # Status / dashboard fields
    status = json.load(open(os.path.join(ANALYSIS, "project-status.json"), encoding="utf-8"))
    expect(status["current_phase"] >= 18, "status phase")
    expect(status["graphics"]["factory_frontier_ready"] is False, "frontier flag")
    expect(status["graphics"]["pre_factory_callback"] == "UNRESOLVED", "pre-cb")
    expect(status["graphics"]["direct3d9_implemented"] is False, "d3d status")
    expect(status["graphics"]["static_factory_frontier"] == "REACHABLE", "static")
    expect(status["graphics"]["callback_publication"] == "EXTERNAL_PROTECTED_INITIALIZATION",
           "pub status")

    # Preserve Phase 16/17 regressions lightly
    expect(os.path.isfile(os.path.join(ANALYSIS, "phase17-raw.json")), "phase17 raw")
    p17 = json.load(open(os.path.join(ANALYSIS, "phase17-raw.json"), encoding="utf-8"))
    expect(p17["frontier"]["FACTORY_FRONTIER_READY"] is False, "p17 not ready")
    text = open(os.path.join(ROOT, "tools", "uc_funcmap.py"), encoding="utf-8").read()
    expect("for _ in range(24):" not in text, "no 24 walk")
    expect("CFG_BUDGET_EXCEEDED" in text, "budget term")

    # Live create listing still has three call esi
    off = 0x0072E340 - base
    chunk = blob[off:off + 0x40]
    expect(chunk.count(b"\xFF\xD6") == 3, "three call esi encodings")

    print("phase 18 ok")


if __name__ == "__main__":
    main()
