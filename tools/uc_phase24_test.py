"""Phase 24 opaque graphics contract tests."""
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
    raw_path = os.path.join(ANALYSIS, "phase24-raw.json")
    expect(os.path.isfile(raw_path), "phase24-raw missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "runtime-phase24.md")), "report missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "phase24-opaque-contracts.json")), "contracts missing")
    expect(os.path.isfile(os.path.join(ANALYSIS, "renderer-interface-graph.json")), "graph missing")

    raw = json.load(open(raw_path, encoding="utf-8"))
    expect(raw["phase"] == 24, "phase")
    expect(raw["policy"] == "NO_PROTECTED_BODY_RECOVERY", "policy")

    # Opaque-call descriptors
    ids = {d["id"] for d in raw["descriptors"]}
    expect("PROTECTED_GFX_CALL_00" in ids, "desc00")
    expect("PROTECTED_GFX_CALL_01" in ids, "desc01")
    expect(raw["submit"]["caller_count"] >= 50, "many submit callers")
    expect(raw["insert"]["caller_count"] == 2, "two insert callers")

    # Call-shape clustering
    expect(len(raw["shapes"]) >= 1, "shapes")
    expect(all(s["id"].startswith("SUBMIT_SHAPE_") for s in raw["shapes"]), "shape ids")

    # Argument / method contracts
    for name in ("METHOD_148", "METHOD_14C", "METHOD_154"):
        m = raw["methods"][name]
        expect(m["stops_at"]["target"].lower() == "0x007a51b0", "stops opaque %s" % name)
        expect(m["input_completeness"] in (
            "COMPLETE_VISIBLE_CONTRACT", "PARTIAL_VISIBLE_CONTRACT",
            "MINIMAL_VISIBLE_CONTRACT", "UNKNOWN_CONTRACT",
        ), "input")
        expect(m["output_completeness"] in (
            "RETURN_ONLY", "ORDINARY_STATE_VISIBLE", "NO_VISIBLE_OUTPUT", "UNKNOWN_OUTPUT",
        ), "output")
        expect("boundary_args" in m and m["boundary_args"], "args")

    # Temp records
    expect(raw["methods"]["METHOD_148"]["record"]["size"] == 8, "rec148")
    expect(raw["methods"]["METHOD_154"]["record"]["size"] == 4, "rec154")

    # Queue pattern classification — must not claim proven ring without evidence
    q = raw["queue"]
    expect(q["candidates"], "queue cand")
    expect("QUEUE" in q["queue_confidence"].upper() or "DESCRIPTOR" in q["queue_confidence"].upper(), "q conf")

    # Shared-state / return / architecture
    expect(raw["frame"]["classification"] in (
        "FRAME_ROOT_PROVEN", "FRAME_ROOT_STRONG", "FRAME_STATE_CORRELATION",
        "NO_COMMON_ROOT_FOUND", "UNKNOWN",
    ), "frame")
    expect(raw["architecture"] == "ORDINARY_FRONTEND_PROTECTED_BACKEND", "arch")
    expect(raw["safe_seam"] in (
        "STANDARD_D3D9_SEAM", "POST_BACKEND_PRESENT_SEAM",
        "NO_MEANINGFUL_RENDER_SEAM", "UNKNOWN",
    ), "seam")
    expect(raw["first_frame"] == "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND", "ff")
    expect(raw["implementation"]["D3D9_IMPLEMENTATION_JUSTIFIED"] is False, "d3d")
    expect(raw["implementation"]["ENGINE_BACKEND_ADAPTER_JUSTIFIED"] is False, "adapter")
    expect(raw["protected_analysis_further_needed"] is False, "no more protected")

    # Graph: opaque node has no speculative outgoing to device as PROVEN
    g = raw["interface_graph_v3"]
    expect(any(n.get("id") == "PROTECTED_GFX_CALL_00" for n in g["nodes"]), "opaque node")
    bad = [
        e for e in g["edges"]
        if e.get("from") == "PROTECTED_GFX_CALL_00"
        and e.get("to") == "proven_d3d_device"
        and e.get("confidence") == "PROVEN"
    ]
    expect(not bad, "no proven edge from opaque to device")

    # Dashboard
    d = raw["dashboard"]
    expect(d["SUBMIT_BACKEND"] == "PROTECTED", "dash backend")
    expect(d["FIRST_FRAME"] == "BLOCKED", "dash ff")
    expect(d["ENGINE_FRONTEND"] == "ORDINARY", "dash front")

    # Regressions
    for p in ("runtime-phase23.md", "phase23-raw.json", "runtime-phase22.md", "runtime-phase21.md", "runtime-phase20.md"):
        expect(os.path.isfile(os.path.join(ANALYSIS, p)), "regression " + p)

    # Ensure opaque contracts JSON does not embed giant protected dumps
    contracts = open(os.path.join(ANALYSIS, "phase24-opaque-contracts.json"), encoding="utf-8").read()
    expect("ENCRYPTED_BYTES" not in contracts, "no encrypted bytes marker")
    expect(len(contracts) < 2_000_000, "contracts file size bound")

    print("uc_phase24_test: OK")


if __name__ == "__main__":
    main()
