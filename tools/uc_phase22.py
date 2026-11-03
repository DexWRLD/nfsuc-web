"""Phase 22: renderer COM container provenance and backend handoff search.

Ordinary sections only. Does not execute nfs.exe, fabricate devices/renderers,
cross protected boundaries, or implement D3D9. angr remains optional/targeted.
UC analyzer remains recompilation authority.
"""
from __future__ import annotations

import bisect
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_code_analyze as uca
import uc_phase15_graphics as g15
import uc_phase7_test as p7
from angr_oracle import AngrOracle, angr_available, hx, normalize_addr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
ANGR_DIR = os.path.join(ANALYSIS, "angr")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

DEVICE = 0x013C6510
RENDERER = 0x017AA798
HELPER = 0x0079E4A0
CTOR = 0x007B5020
DTOR = 0x007A06E0
NULL_STUB = 0x0079D1E0
VEC_INIT = 0x007A45B0
PRESENT = 0x00752AF0

# Phase 20/21 Draw candidates (re-validated)
DRAW_CANDS = [
    {"owner": 0x007B2AC0, "call": 0x007B2AE7, "offset": 0x148, "soft": "DrawPrimitive-shaped"},
    {"owner": 0x007B36A0, "call": 0x007B39D3, "offset": 0x148, "soft": "DrawPrimitive-shaped"},
    {"owner": 0x007A1400, "call": 0x007A14FD, "offset": 0x14C, "soft": "DrawIndexedPrimitive-shaped"},
    {"owner": 0x007B2930, "call": 0x007B29F7, "offset": 0x14C, "soft": "DrawIndexedPrimitive-shaped",
     "note": "Phase20 call site 0x7B29E7 was +0x1E4; true +0x14C call is via jmp to 0x7B29F7"},
    {"owner": 0x007B1850, "call": 0x007B1C78, "offset": 0x154, "soft": "DrawIndexedPrimitiveUP-shaped",
     "note": "Phase20 owner 0x7B17C0 was prior function; draw body starts 0x7B1850"},
]


def load_map():
    data = json.load(open(os.path.join(ANALYSIS, "function-map.json"), encoding="utf-8"))
    by = {int(r["va"], 16): r for r in data["functions"]}
    return data, by, sorted(by)


def owner_of(vas, by, eip):
    i = bisect.bisect_right(vas, eip) - 1
    if i < 0:
        return None, {}
    return vas[i], by.get(vas[i], {})


def analyze_helper(blob, base, by):
    lines = g15.decode_linear(blob, base, HELPER, 120, True)
    listing = [{"va": hx(l["va"]), "text": l["text"]} for l in lines]
    # Observed body: vector walk begin..end stride 8, iface at [elem+4]
    # Early unconditional jmp 0x48fcd6 is anomalous (target looks non-functional);
    # continuation at 0x79E4AF matches empty-check + iteration (flags from sub).
    return {
        "entry": hx(HELPER),
        "uc_label": by.get(HELPER, {}).get("label"),
        "abi": {
            "form": "thiscall + 2 stack bytes/bools (ret 8)",
            "ecx": "renderer object (saved EBX)",
            "stack_args": [
                {"slot": "[esp+0x18] after setup", "role": "bool filter A (gate VT+0x70)"},
                {"slot": "[esp+0x1C]", "role": "bool filter B (gate VT+0x1DC)"},
            ],
            "return": "EAX = selected COM iface pointer, or NULL",
            "ret_bytes": 8,
        },
        "fields_read": ["+0x50 begin", "+0x54 end"],
        "anomalous_jmp": {
            "va": "0x0079E4AA",
            "target": "0x0048FCD6",
            "note": (
                "Unconditional jmp to a site that does not decode as a coherent empty-check stub. "
                "Functional iteration body follows at 0x0079E4AF (jne/empty/ret). "
                "Treat 0x48FCD6 as unresolved/anomaly; do not follow."
            ),
            "class": "UNKNOWN_ANOMALY",
        },
        "iteration": {
            "begin": "[renderer+0x50] -> EBP",
            "end": "[renderer+0x54]",
            "stride": 8,
            "element_iface": "[EBP+4] -> ESI",
            "select": "keeps EDI as best candidate via VT+0x58 float compare",
            "filters": ["VT+0x70 (bool)", "VT+0x1DC (bool)"],
        },
        "indirect_calls": [
            {"offset": "0x70", "role": "predicate/filter"},
            {"offset": "0x1DC", "role": "predicate/filter"},
            {"offset": "0x58", "role": "float metric / priority"},
        ],
        "listing_head": listing[:50],
        "ANGR": None,
    }


def analyze_container():
    return {
        "fields": {
            "+0x50": "begin pointer",
            "+0x54": "end pointer",
            "+0x58": "end_of_storage / capacity pointer",
        },
        "type": "MSVC_VECTOR_LIKE",
        "confidence": "STRONG",
        "evidence": [
            "0x007A45B0 with ECX=&renderer+0x50 zeros [0],[4],[8] (begin/end/capacity)",
            "0x0079E4A0 / 0x007A1400 iterate EBP from begin to end with add EBP, 8",
            "0x007B18ED / 0x007A099F: sub end,begin; sar 3 => element count (size 8)",
            "0x007A06E0 destructor frees (end-begin) bytes via heap helper after sar/scale",
            "0x007A077A clear: mov [esi+0x54], ecx with ecx=[esi+0x50] (end=begin)",
        ],
        "bounds_representation": "begin/end pointers (not pointer/count)",
        "element_size": 8,
        "element_layout": {
            "+0x00": "UNKNOWN (metadata / paired pointer)",
            "+0x04": "COM/interface pointer (engine graphics iface)",
            "confidence": "STRONG for +0x04 iface; +0x00 UNKNOWN",
        },
    }


def analyze_ctor(blob, base, by):
    lines = g15.decode_linear(blob, base, CTOR, 120, False)
    events = []
    for l in lines:
        t = l["text"].lower()
        if any(x in t for x in ["17aa798", "0x50", "7a45b0", "686030", "call ", "bb19", "lea eax"]):
            events.append({"va": hx(l["va"]), "text": l["text"]})
        if l["va"] > 0x007B5200:
            break
    return {
        "entry": hx(CTOR),
        "role": "RENDERER_CONSTRUCTOR_PUBLISHER",
        "classification": "DEFINITE_PUBLISHER",
        "publishes": {
            "global": hx(RENDERER),
            "value": "this (ESI); via lea eax,[edi-0x44] where edi=esi+0x44",
            "sites": ["0x007B506B", "0x007B5072(null fallback)"],
        },
        "same_vtables_as_dtor_object": ["0xBB1964", "0xBB195C", "0xBB1944", "0xBB1924", "0xBB191C"],
        "container_init": {"call": hx(VEC_INIT), "ecx": "lea ecx,[esi+0x50]", "push": "0x0A capacity hint?"},
        "events": events[:40],
        "uc_label": by.get(CTOR, {}).get("label"),
    }


def analyze_dtor(blob, base, by):
    return {
        "entry": hx(DTOR),
        "role": "RENDERER_DESTRUCTOR_CLEANUP",
        "classification": "DEFINITE_NULL_ON_EXIT",
        "publishes": {
            "global": hx(RENDERER),
            "value": "EBP which remains 0 after xor ebp,ebp",
            "site": "0x007A09BB",
            "means": "NULL clear, not live-object publish",
        },
        "list_ops": [
            "reads +0x50/+0x54; on non-empty frees buffer (sar 3 * 8)",
            "clear-style end=begin at 0x007A077A early in body",
        ],
        "calls_0x686030": True,
        "note": "Phase 21 listed this as DEFINITE_PUBLISHER; corrected to destructor/null.",
        "uc_label": by.get(DTOR, {}).get("label"),
    }


def analyze_null_stub(blob, base, by):
    return {
        "entry": hx(NULL_STUB),
        "role": "RENDERER_GLOBAL_NULL_STUB",
        "classification": "NULL_CLEAR",
        "body": "mov dword ptr [0x017AA798], 0; ret",
        "note": (
            "Standalone function after int3 padding. Phase 21 owner-attributed it to 0x0079D150; "
            "0x0079D150 is a different buffer helper that returns before the stub."
        ),
        "uc_label": by.get(NULL_STUB, {}).get("label"),
        "prior_fn_0x79d150": {
            "role": "unrelated buffer grow/shrink helper (not renderer null)",
            "classification": "NOT_RENDERER_SHUTDOWN",
        },
    }


def lifecycle():
    return {
        "CREATE/INIT": {"fn": hx(CTOR), "confidence": "PROVEN"},
        "PUBLISH": {"global": hx(RENDERER), "fn": hx(CTOR), "confidence": "PROVEN"},
        "USE": {"helper": hx(HELPER), "draw_owners": [hx(c["owner"]) for c in DRAW_CANDS], "confidence": "PROVEN"},
        "DRAW": {"confidence": "PROVEN", "kind": "ENGINE_COM_DRAW"},
        "SHUTDOWN/REPLACE": {"fn": hx(DTOR), "confidence": "STRONG"},
        "NULL": {"fns": [hx(NULL_STUB), hx(DTOR) + " epilogue"], "confidence": "PROVEN"},
    }


def interface_inventory():
    """Dynamic list-element COM; no static vtable recovered this phase."""
    offsets = sorted({
        0x28, 0x30, 0x34, 0x58, 0x60, 0x68, 0x70, 0xBC,
        0x128, 0x148, 0x14C, 0x154, 0x1DC, 0x1E4,
    })
    return {
        "ENGINE_GFX_IFACE_00": {
            "source": "renderer vector element [elem+4]",
            "vtable_address": "RUNTIME_ONLY",
            "mapped_section": None,
            "ordinary_targets": "UNRESOLVED (indirect)",
            "observed_method_offsets": [hx(o) for o in offsets],
            "clusters": {
                "draw_like": ["0x00000148", "0x0000014C", "0x00000154"],
                "predicate_filter": ["0x00000070", "0x000001DC"],
                "metric_float": ["0x00000058"],
                "other": ["0x00000028", "0x00000030", "0x00000034", "0x00000060", "0x00000068", "0x000000BC", "0x00000128", "0x000001E4"],
            },
            "note": "No static vtable in ordinary sections recovered; cannot enumerate code targets.",
        },
        "count": 1,
        "vtables_recovered_static": 0,
        "ordinary_vtable_methods": 0,
    }


def analyze_draws(blob, base, by, vas):
    rows = []
    for c in DRAW_CANDS:
        owner = c["owner"]
        lines = g15.decode_linear(blob, base, owner, 200, False)
        uses_helper = any("0x79e4a0" in l["text"].lower() for l in lines)
        uses_vec = any("+ 0x50]" in l["text"].lower() or "+0x50]" in l["text"].lower() for l in lines)
        uses_ren = any("0x17aa798" in l["text"].lower() for l in lines)
        # Search DEVICE in owner span
        next_va = None
        i = bisect.bisect_right(vas, owner)
        end = vas[i] if i < len(vas) else owner + 0x2000
        device_in_fn = False
        for kind, eip, text, conf in g15.refs_of(blob, base, DEVICE):
            if owner <= eip < end:
                device_in_fn = True
                break
        terminus = "ENGINE_BACKEND"
        if device_in_fn:
            terminus = "RAW_D3D9_DEVICE"
        # No static impl target
        impl = "INDIRECT_COM"
        rows.append({
            "owner": hx(owner),
            "call": hx(c["call"]),
            "offset": hx(c["offset"]),
            "soft": c["soft"],
            "interface": "ENGINE_GFX_IFACE_00",
            "provenance": (
                "HELPER_0x79E4A0" if uses_helper else
                "DIRECT_VECTOR_WALK" if uses_vec else
                "RENDERER_RELATED"
            ),
            "uses_renderer_global": uses_ren,
            "uses_helper": uses_helper,
            "implementation_target": impl,
            "terminus": terminus if not device_in_fn else terminus,
            "device_in_owner": device_in_fn,
            "UC_classification": "ENGINE_COM_DRAW",
            "note": c.get("note"),
        })
        # Fix terminus label when no device
        if not device_in_fn:
            rows[-1]["terminus"] = "ENGINE_BACKEND"
    return rows


def durable_alias_correction(blob, base, by, vas):
    """Phase 21 durable this+0x1B0 was a false device alias."""
    # 0x7253F1 stores EAX after call 0x71D300, not DEVICE
    return {
        "site": "0x007253F1",
        "owner": "0x00725200",
        "field": "graphics_object+0x1B0",
        "phase21_claim": "durable DEVICE field store",
        "phase22_correction": "FALSE_DEVICE_ALIAS",
        "actual_value": "return of call 0x0071D300 (capability/feature index; compared to 3)",
        "evidence": [
            "DEVICE used earlier for SetRenderState VT+0xE4; EAX clobbered by call 0x71D300",
            "cmp eax, 3; mov [esi+0x1B0], eax; set flag [esi+0x1B4]",
        ],
        "writer": "0x00725200",
        "readers": "not exhaustively enumerated; field is status/index shaped",
        "relationship_to_renderer": "NO_RELATION_FOUND",
        "durable_device_alias_mapped": False,
    }


def handoff_candidates(draw_rows):
    # Ranked: helper itself, direct vector draw, ctor — none reach DEVICE in ordinary helpers
    cands = [
        {
            "fn": hx(HELPER),
            "score": 40,
            "why": "selects ENGINE_GFX_IFACE_00 for Draw owners",
            "negatives": ["no DEVICE read", "dynamic COM return"],
            "UC": "ENGINE_LIST_SELECT",
            "device_bridge": False,
        },
        {
            "fn": "0x007A1400",
            "score": 35,
            "why": "direct vector walk + VT+0x14C",
            "negatives": ["no DEVICE read in owner"],
            "UC": "ENGINE_COM_DRAW",
            "device_bridge": False,
        },
        {
            "fn": "0x007B2AC0",
            "score": 35,
            "why": "helper + VT+0x148",
            "negatives": ["no DEVICE read in owner"],
            "UC": "ENGINE_COM_DRAW",
            "device_bridge": False,
        },
        {
            "fn": "0x007A4860",
            "score": 15,
            "why": "called with selected iface on Draw path",
            "negatives": ["no DEVICE read"],
            "UC": "ENGINE_WRAPPER",
            "device_bridge": False,
        },
    ]
    strongest = cands[0]
    return cands, strongest


def classify_686030(by):
    row = by.get(0x00686030, {})
    return {
        "va": "0x00686030",
        "uc_label": row.get("label"),
        "insns": row.get("insns"),
        "reachable": row.get("reachable"),
        "relationship_to_0x686000": "NEARBY_SIBLING_ADDRESS_ONLY",
        "classification": "UNKNOWN_NON_ORDINARY_BODY",
        "note": (
            "MEDIUM_CONFIDENCE with non-coherent decode at entry (similar failure mode to "
            "0x00686000). Called from renderer destructor 0x007A06E0. Not treated as "
            "equivalent to frozen 0x00686000; not followed; EXTERNAL_STATE risk."
        ),
        "not_frozen_slot": True,
    }


def build_graph(draw_rows, iface):
    nodes = [
        {"id": "renderer", "va": hx(RENDERER)},
        {"id": "container", "fields": "+0x50/+0x54/+0x58"},
        {"id": "ENGINE_GFX_IFACE_00", "kind": "engine_com"},
        {"id": "proven_d3d_device", "va": hx(DEVICE)},
        {"id": "present", "va": hx(PRESENT)},
        {"id": "external_protected", "kind": "boundary"},
    ]
    edges = [
        {"from": "renderer", "to": "container", "rel": "CONTAINS"},
        {"from": hx(CTOR), "to": "renderer", "rel": "PUBLISHES"},
        {"from": hx(DTOR), "to": "renderer", "rel": "PUBLISHES", "note": "NULL"},
        {"from": hx(NULL_STUB), "to": "renderer", "rel": "PUBLISHES", "note": "NULL"},
        {"from": "container", "to": "ENGINE_GFX_IFACE_00", "rel": "RETURNS", "via": hx(HELPER)},
        {"from": "ENGINE_GFX_IFACE_00", "to": "ENGINE_GFX_IFACE_00", "rel": "CALLS", "note": "draw-like VT"},
        {"from": "proven_d3d_device", "to": "present", "rel": "CALLS", "note": "EndScene/Present"},
        {"from": "ENGINE_GFX_IFACE_00", "to": "proven_d3d_device", "rel": "UNKNOWN"},
        {"from": hx(DTOR), "to": "external_protected", "rel": "CALLS", "note": "0x00686030 unresolved"},
    ]
    for d in draw_rows:
        edges.append({"from": d["owner"], "to": "ENGINE_GFX_IFACE_00", "rel": "CALLS", "offset": d["offset"]})
    return {"nodes": nodes, "edges": edges}


def run_angr(game, helper_rec, draw_rows, strongest):
    ok, ver = angr_available()
    out = {
        "available": ok,
        "version": ver,
        "targets": {},
        "handoff": {"UC_ANALYZER": strongest["UC"], "ANGR": "NOT_RUN", "CONSENSUS": "UC_ONLY",
                    "negative_weight": None},
    }
    if not ok:
        return out
    try:
        oracle = AngrOracle(game)
    except Exception as exc:
        out["error"] = str(exc)[:200]
        return out

    for addr in (HELPER, CTOR, DTOR, 0x007B2AC0, 0x007A1400, PRESENT):
        try:
            rec = oracle.analyze_function(addr, decompile=True)
            excerpt = rec.get("pseudocode") or ""
            out["targets"][hx(addr)] = {
                "angr_function": rec.get("angr_function"),
                "size": rec.get("size"),
                "blocks": rec.get("block_count"),
                "immediate_hits": rec.get("immediate_hits"),
                "mentions_device": "13c6510" in excerpt.lower(),
                "mentions_renderer": "17aa798" in excerpt.lower(),
                "sha": rec.get("pseudocode_sha"),
                "excerpt_head": (excerpt[:1200] if excerpt else None),
            }
        except Exception as exc:
            out["targets"][hx(addr)] = {"error": str(exc)[:200]}

    # Handoff negative on helper / draw
    h = out["targets"].get(hx(HELPER)) or {}
    d = out["targets"].get("0x007B2AC0") or {}
    coherent = bool(h.get("angr_function") or d.get("angr_function"))
    mentions_ren = bool(d.get("mentions_renderer") or h.get("immediate_hits"))
    mentions_dev = bool(h.get("mentions_device") or d.get("mentions_device"))
    if coherent and mentions_ren and not mentions_dev:
        neg = "NEGATIVE_STRONG"
        angr_res = "NO_DEVICE_BRIDGE_IN_DRAW_SELECT"
    elif coherent and not mentions_dev:
        neg = "NEGATIVE_WEAK"
        angr_res = "NO_DEVICE_SEEN"
    else:
        neg = "NEGATIVE_WEAK"
        angr_res = "INCONCLUSIVE"
    out["handoff"] = {
        "UC_ANALYZER": "NO_ORDINARY_DEVICE_BRIDGE",
        "ANGR": angr_res,
        "CONSENSUS": "NO_ORDINARY_DEVICE_BRIDGE",
        "confidence": "AGREE" if neg == "NEGATIVE_STRONG" else "UC_ONLY",
        "negative_weight": neg,
    }
    helper_rec["ANGR"] = out["targets"].get(hx(HELPER))
    return out


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    print("phase22 loading", file=sys.stderr)
    os.makedirs(ANGR_DIR, exist_ok=True)

    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    image = p7.read_sections(game)
    data, by, vas = load_map()

    helper = analyze_helper(blob, base, by)
    container = analyze_container()
    ctor = analyze_ctor(blob, base, by)
    dtor = analyze_dtor(blob, base, by)
    nullstub = analyze_null_stub(blob, base, by)
    life = lifecycle()
    iface = interface_inventory()
    draws = analyze_draws(blob, base, by, vas)
    durable = durable_alias_correction(blob, base, by, vas)
    cands, strongest = handoff_candidates(draws)
    helper_686030 = classify_686030(by)

    print("phase22 angr", file=sys.stderr)
    angr = run_angr(game, helper, draws, strongest)

    graph = build_graph(draws, iface)

    raw_device_draw = any(d["terminus"] == "RAW_D3D9_DEVICE" for d in draws)
    frame_root = {
        "classification": "NO_COMMON_ROOT_FOUND",
        "note": (
            "Present/EndScene proven on DEVICE at 0x00752AF0; ENGINE_COM_DRAW uses renderer "
            "list without a shared ordinary caller proven this phase."
        ),
        "ordering": {
            "BeginScene→engine Draw→EndScene→Present": "UNKNOWN",
            "EndScene→Present on DEVICE prefix": "PROVEN_DIRECT",
        },
    }

    boundary = {
        "classification": "MIXED_BOUNDARY",
        "detail": (
            "RAW_D3D9_BOUNDARY for Present/Clear/EndScene on 0x013C6510; "
            "ENGINE_BACKEND_BOUNDARY for Draw via ENGINE_GFX_IFACE_00. "
            "No ordinary bridge between them proven."
        ),
    }

    seam = {
        "classification": "PARTIAL_POST_INIT_SEAM",
        "rationale": (
            "Unchanged: host DEVICE still legitimizes Present/Clear. Engine Draw path mapped "
            "to a vector of dynamic COM ifaces, but without a backend→device handoff the seam "
            "is not CLEAN."
        ),
    }

    impl = {
        "D3D9_IMPLEMENTATION_JUSTIFIED": False,
        "ENGINE_BACKEND_ADAPTER_JUSTIFIED": False,
        "reason": (
            "ENGINE_COM_DRAW terminates at dynamic ENGINE_GFX_IFACE_00 with no ordinary "
            "implementation targets and no DEVICE bridge. Adapter would require inventing "
            "iface semantics."
        ),
        "highest_value_uncertainty": (
            "Static identity / constructors of objects stored in renderer vector elements "
            "([elem+4] COM): where they are inserted, which concrete vtables they use, and "
            "whether those method bodies eventually read 0x013C6510."
        ),
    }

    contracts = {
        "MINIMUM_FIRST_DRAW_CONTRACT": {
            "fabricated": False,
            "items": [
                {"item": "renderer at 0x017AA798", "class": "EXTERNAL_INITIALIZED"},
                {"item": "non-empty vector +0x50..+0x54 of ENGINE_GFX_IFACE_00", "class": "UNKNOWN"},
                {"item": "backend behind iface methods", "class": "UNKNOWN"},
            ],
            "blocked_by": "list element publication + iface implementation provenance",
        },
        "MINIMUM_FIRST_PRESENT_CONTRACT": {
            "fabricated": False,
            "items": [
                {"item": "IDirect3DDevice9* at 0x013C6510", "class": "D3D_DEVICE_STATE"},
                {"item": "0x00752AF0", "class": "ORDINARY_CODE"},
            ],
            "blocked_by": "live device publication EXTERNAL/BLOCKED for in-game path",
        },
    }

    init_deps = {
        "root": hx(CTOR),
        "dependencies": {
            "DEVICE_STATE": "NOT_REQUIRED_IN_CTOR_BODY",
            "FACTORY_STATE": "UNKNOWN",
            "0x00686000": "NOT_DIRECT",
            "0x00686030": "DTOR_ONLY_UNRESOLVED",
            "0x00B615C4": "UNKNOWN",
            "ordinary_code": "YES",
            "allocator": "0x007A45B0 -> call 0x006CA7C0 (body unresolved/non-coherent at entry)",
        },
        "0x00686030": helper_686030,
    }

    estimate = {"best_case_phase": "UNBOUNDED", "likely_range": "UNBOUNDED"}

    dashboard = {
        "RENDERER": "PROVEN ENGINE OBJECT",
        "RENDERER_LIST": "MAPPED",
        "ENGINE_DRAW": "FOUND",
        "BACKEND_HANDOFF": "UNKNOWN",
        "RAW_DEVICE_DRAW": "NOT FOUND",
        "DURABLE_DEVICE_ALIAS": "UNMAPPED",
        "FRAME_ROOT": "UNKNOWN",
        "GRAPHICS_BOUNDARY": "MIXED",
        "POST_INIT_SEAM": "PARTIAL",
        "D3D9_IMPLEMENTATION": "NOT JUSTIFIED",
        "ENGINE_BACKEND_ADAPTER": "NOT JUSTIFIED",
        "FIRST_FRAME": "UNBOUNDED",
        "ANGR": "AVAILABLE" if angr.get("available") else "NOT RUN",
        "DEVICE_CODE": "PROVEN",
        "DEVICE_PUBLICATION": "EXTERNAL/BLOCKED",
        "PRESENT_CODE": "FOUND",
        "DRAW_CODE": "FOUND_STRONG",
    }

    out = {
        "phase": 22,
        "helper_0x0079E4A0": helper,
        "container": container,
        "ctor_0x007B5020": ctor,
        "dtor_0x007A06E0": dtor,
        "null_stub_0x0079D1E0": nullstub,
        "lifecycle": life,
        "interfaces": iface,
        "draw_candidates": draws,
        "raw_device_draw_found": raw_device_draw,
        "durable_alias": durable,
        "handoff_candidates": cands,
        "strongest_handoff": strongest,
        "angr": angr,
        "interface_graph": graph,
        "frame_root": frame_root,
        "boundary": boundary,
        "seam": seam,
        "implementation": impl,
        "contracts": contracts,
        "initialization": init_deps,
        "first_frame_estimate": estimate,
        "resource_evidence": {
            "found": False,
            "note": "No VB/IB/texture/shader object linkage proven from list-element methods this phase.",
        },
        "execution": {"ran": False},
        "dashboard": dashboard,
        "recommended_phase23": "EXPAND_RENDERER_STATE_PROVENANCE",
        "angr_quality": {
            "materially_helped": bool(angr.get("available")),
            "strongest_finding": (
                angr.get("handoff", {}).get("ANGR")
                if angr.get("available") else "angr unavailable"
            ),
            "negative_weight": (angr.get("handoff") or {}).get("negative_weight"),
        },
    }

    path = os.path.join(ANALYSIS, "phase22-raw.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")

    with open(os.path.join(ANGR_DIR, "renderer-phase22.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({
            "helper": helper,
            "container": container,
            "draws": draws,
            "handoff": angr.get("handoff"),
            "angr_targets": angr.get("targets"),
            "dashboard": dashboard,
        }, fh, indent=2)
        fh.write("\n")

    with open(os.path.join(ANALYSIS, "renderer-interface-graph.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(graph, fh, indent=2)
        fh.write("\n")

    # project-status
    status = json.load(open(os.path.join(ANALYSIS, "project-status.json"), encoding="utf-8"))
    status["current_phase"] = 22
    status["strategy"] = (
        "Phase 22: renderer 0x017AA798 holds an MSVC-like vector at +0x50/+0x54/+0x58 of "
        "8-byte elements; [elem+4] is ENGINE_GFX_IFACE_00 (dynamic COM). Helper 0x0079E4A0 "
        "selects from that list. Draw remains ENGINE_COM_DRAW terminating at ENGINE_BACKEND "
        "with no ordinary DEVICE bridge. Phase21 durable +0x1B0 corrected as false alias. "
        "PARTIAL seam; D3D9/adapter NOT justified; first-frame UNBOUNDED."
    )
    status["graphics"].update({
        "renderer_classification": "PROVEN_ENGINE_OBJECT",
        "renderer_list": "MAPPED",
        "engine_draw": "FOUND",
        "backend_handoff": "UNKNOWN",
        "raw_device_draw": "NOT FOUND",
        "durable_device_alias": "UNMAPPED",
        "frame_root": "UNKNOWN",
        "graphics_boundary": "MIXED",
        "draw_code": "FOUND_STRONG",
        "post_init_seam": "PARTIAL",
        "d3d9_implementation_justified": False,
        "engine_backend_adapter_justified": False,
        "active_objective": (
            "Recover constructors/vtables of renderer vector element COM objects; find insert sites"
        ),
        "blockers": [
            "In-game DEVICE publication EXTERNAL/BLOCKED",
            "ENGINE_GFX_IFACE_00 vtables runtime-only; no ordinary method bodies mapped",
            "No DEVICE bridge from engine Draw path",
            "List element publishers not fully mapped",
            "D3D9 / engine-backend adapter not justified",
        ],
    })
    status["first_frame_estimate"] = {
        "best_case_phase": "UNBOUNDED",
        "likely_low": "UNBOUNDED",
        "likely_high": "UNBOUNDED",
        "is_estimate": True,
        "uncertainty": "Engine Draw mapped to dynamic COM list without backend→device handoff.",
    }
    for ph in status["phases"]:
        if ph["phase"] == 21:
            ph["state"] = "completed"
        if ph["phase"] == 22:
            ph["state"] = "current"
            break
    else:
        status["phases"].append({
            "phase": 22,
            "name": "Renderer COM container and backend handoff",
            "state": "current",
        })
    for m in status["milestones"]:
        if m["name"] == "DRAW CODE":
            m["state"] = "FOUND_STRONG"
        if m["name"] == "POST-INIT SEAM":
            m["state"] = "PARTIAL"
        if m["name"] == "D3D9 IMPLEMENTATION":
            m["state"] = "NOT JUSTIFIED"
        if m["name"] == "FIRST FRAME":
            m["state"] = "UNBOUNDED"
    # ensure renderer milestones reflected in graphics only
    with open(os.path.join(ANALYSIS, "project-status.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(status, fh, indent=2)
        fh.write("\n")

    print("container", container["type"], "raw_draw", raw_device_draw, file=sys.stderr)
    print("handoff", (angr.get("handoff") or {}).get("CONSENSUS"), "seam", seam["classification"], file=sys.stderr)
    print("wrote", path, file=sys.stderr)


if __name__ == "__main__":
    main()
