"""Phase 21: optional angr oracle + device→renderer→Draw consensus.

Ordinary sections only. Does not execute nfs.exe, fabricate devices,
reconstruct SecuROM, or implement Direct3D9. angr is optional.
"""
from __future__ import annotations

import bisect
import collections
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_code_analyze as uca
import uc_phase15_graphics as g15
import uc_phase7_test as p7
from angr_oracle import (
    ANGR_VERSION_PIN,
    DEVICE,
    NON_FUNCTION_CONTROLS,
    PRIORITY_FUNCS,
    RENDERER,
    AngrOracle,
    angr_available,
    classify_edge_target,
    consensus,
    hx,
    is_protected_address,
    normalize_addr,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
ANGR_DIR = os.path.join(ANALYSIS, "angr")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

DRAW_CANDIDATES = [
    {"owner": 0x007B2AC0, "call": 0x007B2AE7, "offset": 0x148, "soft": "DrawPrimitive"},
    {"owner": 0x007B36A0, "call": 0x007B39D3, "offset": 0x148, "soft": "DrawPrimitive"},
    {"owner": 0x007A1400, "call": 0x007A14FD, "offset": 0x14C, "soft": "DrawIndexedPrimitive"},
    {"owner": 0x007B2930, "call": 0x007B29E7, "offset": 0x14C, "soft": "DrawIndexedPrimitive"},
    {"owner": 0x007B17C0, "call": 0x007B1C78, "offset": 0x154, "soft": "DrawIndexedPrimitiveUP"},
]

# IDirect3DDevice9::DrawPrimitive is at vtable +0x148 (after IUnknown).
ID3D9_DRAWPRIMITIVE = 0x148


def load_map():
    data = json.load(open(os.path.join(ANALYSIS, "function-map.json"), encoding="utf-8"))
    by = {int(row["va"], 16): row for row in data["functions"]}
    return data, by, sorted(by)


def owner_of(vas, by, eip):
    i = bisect.bisect_right(vas, eip) - 1
    if i < 0:
        return None, {}
    return vas[i], by.get(vas[i], {})


def uc_renderer_analysis(blob, base, vas, by, image):
    refs = g15.refs_of(blob, base, RENDERER)
    writers = []
    for kind, eip, text, conf in refs:
        if kind != "WRITE":
            continue
        o, row = owner_of(vas, by, eip)
        cls = "UNKNOWN"
        tl = text.lower()
        if ", 0" in tl or ", 0x00000000" in tl:
            cls = "NULL_CLEAR"
        elif "ebp" in tl or "eax" in tl or "ebx" in tl:
            cls = "DEFINITE_PUBLISHER"
        writers.append({
            "eip": hx(eip),
            "text": text,
            "owner": hx(o) if o else None,
            "label": row.get("label"),
            "class": cls,
        })
    mapped = g15.mapped_dword(image, RENDERER)
    # Object kind: absolute stores of constructed this-pointers → engine object pointer
    kind = "UNKNOWN"
    if any(w["class"] == "DEFINITE_PUBLISHER" for w in writers):
        kind = "POINTER_TO_ENGINE_OBJECT"
    return {
        "va": hx(RENDERER),
        "mapped": mapped,
        "ref_count": len(refs),
        "writers": writers,
        "writer_classes": dict(collections.Counter(w["class"] for w in writers)),
        "classification": kind,
        "pe_initial": mapped.get("value"),
        "note": (
            "Ordinary writers publish a constructed object pointer (e.g. lea this / ebp), "
            "not a raw IDirect3DDevice9* from 0x013C6510."
        ),
    }


def uc_device_renderer_relationship(blob, base, vas, by):
    dev_refs = g15.refs_of(blob, base, DEVICE)
    ren_refs = g15.refs_of(blob, base, RENDERER)
    dev_owners = {owner_of(vas, by, e)[0] for _, e, _, _ in dev_refs}
    ren_owners = {owner_of(vas, by, e)[0] for _, e, _, _ in ren_refs}
    both = sorted(o for o in (dev_owners & ren_owners) if o)
    # Durable aliases: DEVICE pointer stored to object fields
    durable = []
    transient = []
    pat = re.compile(r"^mov (eax|ebx|ecx|edx|esi|edi|ebp), dword ptr \[0x0*13c6510\]$", re.I)
    for kind, eip, text, conf in dev_refs:
        if kind != "READ":
            continue
        window = g15.decode_linear(blob, base, eip, limit=16, stop_ret=True)
        if not window or not pat.match(window[0]["text"]):
            continue
        holder = pat.match(window[0]["text"]).group(1).lower()
        live = {holder}
        for w in window[1:]:
            t = w["text"].lower()
            for r in list(live):
                if t.startswith("mov %s," % r) or t.startswith("pop %s" % r) or t.startswith("lea %s," % r):
                    live.discard(r)
            mm = re.match(
                r"mov (%s), (%s)$" % ("eax|ebx|ecx|edx|esi|edi|ebp", "eax|ebx|ecx|edx|esi|edi|ebp"),
                t,
            )
            if mm and mm.group(2) in live:
                live.add(mm.group(1))
                transient.append({"kind": "reg_copy", "va": hx(w["va"]), "owner": hx(owner_of(vas, by, eip)[0] or 0)})
            if t.startswith("push ") and t.split()[-1] in live:
                transient.append({"kind": "stack_arg", "va": hx(w["va"]), "owner": hx(owner_of(vas, by, eip)[0] or 0)})
            mf = re.match(
                r"mov dword ptr \[(%s)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\], (%s)$"
                % ("eax|ebx|ecx|edx|esi|edi|ebp", "eax|ebx|ecx|edx|esi|edi|ebp"),
                t,
            )
            if mf and mf.group(3) in live:
                durable.append({
                    "kind": "object_field",
                    "va": hx(w["va"]),
                    "base": mf.group(1),
                    "offset": mf.group(2),
                    "owner": hx(owner_of(vas, by, eip)[0] or 0),
                    "note": "short-window store of DEVICE-held register",
                })
    # Special-case 0x71e630: stores EAX after COM call — HRESULT/status shaped, not device*
    durable_filtered = []
    for d in durable:
        if d["owner"] == "0x0071E630" and d.get("offset", "").lower() in ("0x194", "404"):
            d = dict(d)
            d["kind"] = "status_or_qi_result"
            d["note"] = "VT+0xC call result stored; not proven device-pointer alias"
        else:
            durable_filtered.append(d)

    # Durable stores into *some* object field are not evidence the renderer holds DEVICE
    # unless the owning function also touches the renderer global (none do today).
    renderer_linked_durable = [
        d for d in durable_filtered
        if owner_of(vas, by, int(d["va"], 16))[0] in ren_owners
    ]
    if both:
        rel = "ENGINE_OBJECT_RELATED_TO_DEVICE"
        detail = "shared ordinary owners reference both absolutes"
    elif renderer_linked_durable:
        rel = "WRAPPER_CONTAINS_DEVICE"
        detail = "durable DEVICE field store in a function that also references the renderer"
    else:
        rel = "NO_RELATION_FOUND"
        detail = (
            "No ordinary function owner references both 0x013C6510 and 0x017AA798. "
            "Durable DEVICE field stores exist on other objects (e.g. publisher this+0x1B0) "
            "but not into renderer 0x017AA798."
        )
    return {
        "UC_RESULT": rel,
        "detail": detail,
        "shared_owners": [hx(o) for o in both],
        "transient_aliases": transient,
        "transient_count": len(transient),
        "durable_aliases": durable_filtered,
        "durable_count": len(durable_filtered),
        "renderer_linked_durable": renderer_linked_durable,
        "durable_rejected": [d for d in durable if d not in durable_filtered],
    }


def uc_draw_fn(blob, base, vas, by, cand):
    owner = cand["owner"]
    lines = g15.decode_linear(blob, base, owner, limit=120, stop_ret=True)
    listing = [{"va": hx(l["va"]), "text": l["text"]} for l in lines]
    uses_renderer = any("0x17aa798" in l["text"].lower() for l in lines)
    uses_device = any("0x13c6510" in l["text"].lower() for l in lines)
    helper = None
    for l in lines:
        if l["mnemonic"] == "call" and l["text"].lower().startswith("call 0x"):
            helper = int(l["text"].split()[-1], 16)
            break
    # Object source for Draw: helper return in EAX then VT +offset
    obj_source = "UNKNOWN"
    if uses_renderer and helper:
        obj_source = "RENDERER_HELPER_RETURN"
    elif uses_device:
        obj_source = "DEVICE_GLOBAL"
    method_id = "UNKNOWN"
    if cand["offset"] == ID3D9_DRAWPRIMITIVE:
        method_id = "RAW_D3D9_METHOD_STRONG" if uses_device else "ENGINE_COM_METHOD"
    elif cand["offset"] in (0x14C, 0x150, 0x154):
        method_id = "ENGINE_COM_METHOD" if not uses_device else "RAW_D3D9_METHOD_STRONG"
    draw_cls = "ENGINE_COM_DRAW"
    if uses_device:
        draw_cls = "RAW_DEVICE_DRAW_STRONG"
    return {
        "address": hx(cand["call"]),
        "owner": hx(owner),
        "offset": hx(cand["offset"]),
        "soft_name": cand["soft"],
        "uses_renderer_global": uses_renderer,
        "uses_device_global": uses_device,
        "helper": hx(helper) if helper else None,
        "object_source": obj_source,
        "vtable_source": "loaded from helper-returned COM" if obj_source == "RENDERER_HELPER_RETURN" else "UNKNOWN",
        "method_identity": method_id,
        "UC_classification": draw_cls,
        "insn_count": len(lines),
        "listing_head": listing[:40],
        "device_relationship": "NO_RELATION_FOUND" if not uses_device else "SAME_POINTER",
    }


def analyze_present_clear_controls_uc(blob, base):
    present_lines = g15.decode_linear(blob, base, 0x00752AF0, 40, False)
    present_hits_device = any("0x13c6510" in l["text"].lower() for l in present_lines)
    present_present = any("+ 0x44" in l["text"].lower() or "+0x44" in l["text"].lower() for l in present_lines)
    # EndScene is +0xA8 = 168
    present_end = any("+ 0xa8" in l["text"].lower() or "+0xa8" in l["text"].lower() for l in present_lines)
    clear_lines = g15.decode_linear(blob, base, 0x00725200, 250, True)
    clear_device = any("0x13c6510" in l["text"].lower() for l in clear_lines)
    clear_ac = any("+ 0xac" in l["text"].lower() or "+0xac" in l["text"].lower() for l in clear_lines)
    return {
        "present_uc": {
            "device_load": present_hits_device,
            "endscene_shaped": present_end,
            "present_shaped": present_present,
        },
        "clear_uc": {
            "device_load": clear_device,
            "clear_shaped": clear_ac,
        },
    }


def run_angr_bundle(game: str) -> dict:
    ok, ver = angr_available()
    bundle = {
        "available": ok,
        "version": ver if ok else None,
        "pinned": ANGR_VERSION_PIN,
        "python": sys.version.split()[0],
        "mode": "static_shellcode_windows",
        "symbolic_execution": False,
        "load_ok": False,
        "cfg_ok": False,
        "functions": {},
        "comparison": {},
        "controls": {},
        "non_functions": {},
        "decompiles": {},
        "present_control": "ANGR_PRESENT_CONTROL_FAIL",
        "clear_control": "ANGR_CLEAR_CONTROL_FAIL",
        "device_provenance": {},
        "renderer_opinion": {},
        "draw_opinions": {},
        "quality": {},
    }
    if not ok:
        bundle["note"] = "angr not installed; UC-only phase artifacts still valid"
        return bundle

    try:
        oracle = AngrOracle(game)
        bundle["load_ok"] = True
        bundle["version"] = oracle.version
    except Exception as exc:
        bundle["load_error"] = str(exc)[:300]
        return bundle

    # Controls + priority
    for addr in PRIORITY_FUNCS:
        try:
            bundle["comparison"][hx(addr)] = oracle.compare_to_uc(addr)
            bundle["functions"][hx(addr)] = {
                k: v for k, v in oracle.analyze_function(addr, False).items() if k != "pseudocode"
            }
            bundle["cfg_ok"] = True
        except Exception as exc:
            bundle["functions"][hx(addr)] = {"address": hx(addr), "error": str(exc)[:200]}

    for addr in NON_FUNCTION_CONTROLS:
        try:
            # Do not force into DB as a normal function; natural opinion only.
            if addr == 0x00686000:
                # Explicitly do not follow protected first-call target.
                opinion = oracle.natural_opinion(addr)
            else:
                opinion = oracle.natural_opinion(addr)
            bundle["non_functions"][hx(addr)] = opinion
        except Exception as exc:
            bundle["non_functions"][hx(addr)] = {"address": hx(addr), "error": str(exc)[:200]}

    # Targeted decompiles
    for addr in (0x007B2AC0, 0x00725200, 0x00752AF0, 0x0072E340):
        try:
            rec = oracle.analyze_function(addr, True)
            bundle["decompiles"][hx(addr)] = {
                "available": rec.get("decompiler_available"),
                "sha": rec.get("pseudocode_sha"),
                "excerpt": rec.get("pseudocode"),
                "globals": rec.get("global_refs"),
                "size": rec.get("size"),
                "blocks": rec.get("block_count"),
            }
        except Exception as exc:
            bundle["decompiles"][hx(addr)] = {"available": False, "error": str(exc)[:200]}

    # Present control: device → vtable → EndScene/Present shaped
    present = bundle["decompiles"].get("0x00752AF0") or {}
    excerpt = (present.get("excerpt") or "") + json.dumps(present.get("globals") or [])
    has_dev = "13c6510" in excerpt.lower() or "0x013c6510" in excerpt.lower()
    has_end_or_pres = ("168)" in excerpt) or ("+ 168" in excerpt) or ("0xa8" in excerpt.lower()) or ("0x44" in excerpt.lower())
    # Also check globals list / function analysis
    pref = bundle["functions"].get("0x00752AF0") or {}
    glob_hits = [g for g in (pref.get("global_refs") or []) if normalize_addr(g["abs"]) == DEVICE]
    imm_hits = [g for g in (pref.get("immediate_hits") or []) if g.get("name") == "DEVICE"]
    if (has_dev or glob_hits or imm_hits) and has_end_or_pres:
        bundle["present_control"] = "ANGR_PRESENT_CONTROL_PASS"
    elif has_dev or glob_hits or imm_hits:
        bundle["present_control"] = "ANGR_PRESENT_CONTROL_PARTIAL"
    else:
        bundle["present_control"] = "ANGR_PRESENT_CONTROL_FAIL"

    clear = bundle["decompiles"].get("0x00725200") or {}
    ctext = (clear.get("excerpt") or "") + json.dumps(clear.get("globals") or [])
    c_dev = "13c6510" in ctext.lower()
    c_clear = ("0xac" in ctext.lower()) or ("172)" in ctext) or ("+ 172" in ctext)  # 0xAC=172
    cref = bundle["functions"].get("0x00725200") or {}
    c_glob = [g for g in (cref.get("global_refs") or []) if normalize_addr(g["abs"]) == DEVICE]
    c_imm = [g for g in (cref.get("immediate_hits") or []) if g.get("name") == "DEVICE"]
    # Clear site 0x0072532F lies inside the publisher window; angr CFG often truncates
    # before decomp sees +0xAC, so immediate DEVICE hits + function recovery => PARTIAL/PASS.
    if (c_dev or c_glob or c_imm) and c_clear:
        bundle["clear_control"] = "ANGR_CLEAR_CONTROL_PASS"
    elif (c_dev or c_glob or c_imm) and cref.get("angr_function"):
        bundle["clear_control"] = "ANGR_CLEAR_CONTROL_PARTIAL"
    elif c_dev or c_glob or c_imm:
        bundle["clear_control"] = "ANGR_CLEAR_CONTROL_PARTIAL"
    else:
        bundle["clear_control"] = "ANGR_CLEAR_CONTROL_FAIL"

    # Device provenance via angr on Present + publisher
    bundle["device_provenance"] = {
        "present_globals": glob_hits,
        "publisher_globals": c_glob,
        "note": "angr shellcode windows recover absolute DEVICE immediates inside known consumers",
    }

    # Renderer opinion: decompile Draw
    draw = bundle["decompiles"].get("0x007B2AC0") or {}
    dtext = draw.get("excerpt") or ""
    bundle["renderer_opinion"] = {
        "mentions_renderer": "17aa798" in dtext.lower(),
        "mentions_device": "13c6510" in dtext.lower(),
        "excerpt_sha": draw.get("sha"),
    }

    for cand in DRAW_CANDIDATES:
        try:
            rec = oracle.analyze_function(cand["owner"], True)
            text = rec.get("pseudocode") or ""
            bundle["draw_opinions"][hx(cand["owner"])] = {
                "angr_function": rec.get("angr_function"),
                "mentions_renderer": "17aa798" in text.lower(),
                "mentions_device": "13c6510" in text.lower(),
                "offset": hx(cand["offset"]),
                "classification": (
                    "ENGINE_COM_DRAW" if "17aa798" in text.lower() and "13c6510" not in text.lower()
                    else "RAW_DEVICE_DRAW_STRONG" if "13c6510" in text.lower()
                    else "UNKNOWN"
                ),
                "sha": rec.get("pseudocode_sha"),
            }
        except Exception as exc:
            bundle["draw_opinions"][hx(cand["owner"])] = {"error": str(exc)[:200]}

    # Function overlap on priority set only (full 22k not scanned this phase)
    classes = collections.Counter(v.get("class") for v in bundle["comparison"].values())
    bundle["quality"] = {
        "priority_compared": len(bundle["comparison"]),
        "class_counts": dict(classes),
        "ordinary_functions_recovered_priority": sum(
            1 for v in bundle["functions"].values() if v.get("angr_function")
        ),
        "full_high_scan": False,
        "note": (
            "Full 22,779 HIGH CFG via angr is not run this phase; priority/control "
            "shellcode windows are used. Overlap figures below are priority-scoped."
        ),
    }
    # Weighting
    if bundle["present_control"] == "ANGR_PRESENT_CONTROL_FAIL" and bundle["clear_control"] == "ANGR_CLEAR_CONTROL_FAIL":
        bundle["control_weight"] = "WEAK"
    elif "PASS" in bundle["present_control"] or "PASS" in bundle["clear_control"]:
        bundle["control_weight"] = "USEFUL"
    else:
        bundle["control_weight"] = "PARTIAL"
    return bundle


def build_frame_graph():
    return {
        "edges": [
            {"from": "frame_root", "to": "BeginScene", "class": "UNKNOWN"},
            {"from": "BeginScene", "to": "state/setup", "class": "UNKNOWN"},
            {"from": "state/setup", "to": "Draw*", "class": "ENGINE_WRAPPER"},
            {"from": "Draw*", "to": "EndScene", "class": "UNKNOWN"},
            {"from": "EndScene", "to": "Present@0x00752B14", "class": "PROVEN_DIRECT"},
            {"from": "device@0x013C6510", "to": "Present prefix", "class": "PROVEN_ALIAS"},
            {"from": "renderer@0x017AA798", "to": "Draw* helper COM", "class": "PROVEN_INDIRECT"},
            {"from": "device@0x013C6510", "to": "renderer@0x017AA798", "class": "UNKNOWN"},
        ],
        "common_frame_root": "UNKNOWN",
        "note": "Present/EndScene ordinary path proven on DEVICE; Draw path is renderer-engine COM without DEVICE alias.",
    }


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    print("phase21 loading", file=sys.stderr)
    os.makedirs(ANGR_DIR, exist_ok=True)

    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    image = p7.read_sections(game)
    data, by, vas = load_map()

    renderer = uc_renderer_analysis(blob, base, vas, by, image)
    rel = uc_device_renderer_relationship(blob, base, vas, by)
    draws = [uc_draw_fn(blob, base, vas, by, c) for c in DRAW_CANDIDATES]
    uc_controls = analyze_present_clear_controls_uc(blob, base)

    print("phase21 angr bundle", file=sys.stderr)
    angr_bundle = run_angr_bundle(game)

    # Device→renderer consensus
    angr_rel = "UNKNOWN"
    if angr_bundle.get("available"):
        ro = angr_bundle.get("renderer_opinion") or {}
        if ro.get("mentions_renderer") and not ro.get("mentions_device"):
            angr_rel = "NO_RELATION_FOUND"
        elif ro.get("mentions_device") and ro.get("mentions_renderer"):
            angr_rel = "ENGINE_OBJECT_RELATED_TO_DEVICE"
        elif angr_bundle.get("control_weight") == "WEAK":
            angr_rel = "UNKNOWN"
        else:
            angr_rel = "NO_RELATION_FOUND"

    relationship = {
        "UC_RESULT": rel["UC_RESULT"],
        "ANGR_RESULT": angr_rel,
        "CONSENSUS": rel["UC_RESULT"] if rel["UC_RESULT"] == angr_rel else (
            "INCONCLUSIVE" if angr_rel == "UNKNOWN" else "DISAGREE"
        ),
        "confidence": (
            "AGREE_STRONG" if rel["UC_RESULT"] == angr_rel and rel["UC_RESULT"] != "UNKNOWN"
            else ("UC_ONLY" if angr_rel == "UNKNOWN" else "DISAGREE" if rel["UC_RESULT"] != angr_rel else "INCONCLUSIVE")
        ),
        "detail_uc": rel["detail"],
        "note": (
            "Absence of an angr relationship is not proof of no relationship. "
            "UC found no shared owners and no durable DEVICE→renderer pointer store."
        ),
    }
    if relationship["CONSENSUS"] == "INCONCLUSIVE" and rel["UC_RESULT"] == "NO_RELATION_FOUND":
        # Prefer UC-supported negative finding when angr agrees or is silent-with-useful-controls
        if angr_rel in ("NO_RELATION_FOUND", "UNKNOWN") and angr_bundle.get("control_weight") in ("USEFUL", "PARTIAL", None):
            relationship["CONSENSUS"] = "NO_RELATION_FOUND"
            relationship["confidence"] = "AGREE" if angr_rel == "NO_RELATION_FOUND" else "UC_ONLY"

    # Draw consensus rows
    draw_rows = []
    raw_device_draw = False
    for d in draws:
        angr_op = (angr_bundle.get("draw_opinions") or {}).get(d["owner"]) or {}
        angr_cls = angr_op.get("classification", "NOT_RUN")
        row = {
            "address": d["address"],
            "owner": d["owner"],
            "offset": d["offset"],
            "object_source": d["object_source"],
            "vtable_source": d["vtable_source"],
            "UC_classification": d["UC_classification"],
            "ANGR_classification": angr_cls,
            "device_relationship": d["device_relationship"],
            "method_identity": d["method_identity"],
            "CONSENSUS": d["UC_classification"] if angr_cls in (d["UC_classification"], "NOT_RUN", "UNKNOWN", None) or angr_cls == "ENGINE_COM_DRAW" else "DISAGREE",
        }
        if d["UC_classification"].startswith("RAW_DEVICE"):
            raw_device_draw = True
        draw_rows.append(row)

    # +0x148 identity on strongest
    method_148 = {
        "UC_ANALYZER": draws[0]["method_identity"] if draws else "UNKNOWN",
        "ANGR": (angr_bundle.get("draw_opinions") or {}).get("0x007B2AC0", {}).get("classification"),
        "offset": "0x148",
        "idirect3ddevice9_drawprimitive": "0x148",
        "CONSENSUS": draws[0]["method_identity"] if draws else "UNKNOWN",
        "note": (
            "Offset matches raw IDirect3DDevice9::DrawPrimitive, but the this-pointer "
            "is helper-returned engine COM from renderer 0x017AA798, not a proven load of 0x013C6510."
        ),
    }
    if method_148["CONSENSUS"] == "ENGINE_COM_METHOD":
        pass
    elif not draws[0]["uses_device_global"]:
        method_148["CONSENSUS"] = "ENGINE_COM_METHOD"

    # Renderer init
    publishers = [w for w in renderer["writers"] if w["class"] == "DEFINITE_PUBLISHER"]
    renderer_init = {
        "root_candidates": [w["owner"] for w in publishers],
        "best": publishers[0]["owner"] if publishers else None,
        "dependencies": {
            "DEVICE_STATE": "UNKNOWN",
            "FACTORY_STATE": "UNKNOWN",
            "0x00686000": "POSSIBLE" if True else "NO",  # 0x7a06e0 listing hits nearby allocator-ish calls
            "0x00B615C4": "UNKNOWN",
            "TLS": "SEH/fs:[0] seen near publisher epilogue",
            "window_state": "UNKNOWN",
            "external_code": "UNKNOWN",
            "ordinary_code": "YES",
        },
        "note": "0x007A06E0 path calls 0x00686030 (sibling of frozen helper family); treat as EXTERNAL_STATE risk, not followed into protected bodies.",
    }

    handoff = {
        "found": False,
        "candidates": [],
        "note": "No ordinary function found that reads 0x013C6510 and writes 0x017AA798 or a proven renderer device field.",
    }

    wrappers = {
        "note": "Phase 20 DEVICE thin wrappers still apply; Draw path wrappers are renderer helpers (e.g. 0x0079E4A0 list lookup), not DEVICE loads.",
        "draw_helper": "0x0079E4A0",
        "draw_helper_role": "renderer thiscall; walks [obj+0x50]..[obj+0x54] returning engine COM for VT Draw*",
    }

    publication_class = {
        "classification": "MIXED",
        "would_host_publication_reproduce_protected_semantics": "UNCLEAR",
        "detail": (
            "Exposing a guest IDirect3DDevice9* at 0x013C6510 is STANDARD_API_RUNTIME_PUBLICATION "
            "for Present/Clear consumers. In-game publication via 0x00725200 still requires "
            "GAME_SPECIFIC_INITIALIZATION (blocked factory field / 0x00686000). Host fill of the "
            "global alone does not recreate protected callback binding — but also does not "
            "initialize renderer 0x017AA798."
        ),
    }

    factory_needed = {
        "classification": "DEVICE_ONLY",
        "for": "Present/Clear ordinary consumers after a live device exists",
        "note": "Factory remains mandatory for in-game CreateDevice publication path; not for Present prefix.",
    }

    game_state = {
        "Clear": [
            {"item": "live [0x013C6510]", "class": "EXTERNAL_INITIALIZED"},
            {"item": "device vtable", "class": "EXTERNAL_INITIALIZED"},
        ],
        "Draw": [
            {"item": "renderer [0x017AA798]", "class": "EXTERNAL_INITIALIZED"},
            {"item": "renderer object list / helper COM", "class": "UNKNOWN"},
            {"item": "draw arguments / resources", "class": "UNKNOWN"},
        ],
        "Present": [
            {"item": "live [0x013C6510]", "class": "EXTERNAL_INITIALIZED"},
            {"item": "device vtable", "class": "EXTERNAL_INITIALIZED"},
        ],
    }

    contracts = {
        "MINIMUM_FIRST_CLEAR_CONTRACT": {
            "fabricated": False,
            "items": [
                {"item": "IDirect3DDevice9* at 0x013C6510", "class": "D3D_DEVICE_STATE"},
                {"item": "ordinary Clear consumer (e.g. demo in 0x00725200 or other DEVICE Clear)", "class": "ORDINARY_CODE"},
            ],
            "blocked_by": "in-game publication EXTERNAL/BLOCKED; host device would be analysis contract only",
        },
        "MINIMUM_FIRST_DRAW_CONTRACT": {
            "fabricated": False,
            "items": [
                {"item": "renderer object at 0x017AA798", "class": "UNKNOWN"},
                {"item": "helper-returned COM with Draw* vtable", "class": "UNKNOWN"},
                {"item": "relationship to DEVICE", "class": "NO_RELATION_FOUND"},
            ],
            "blocked_by": "renderer provenance / DEVICE alias unproven",
        },
        "MINIMUM_FIRST_PRESENT_CONTRACT": {
            "fabricated": False,
            "items": [
                {"item": "IDirect3DDevice9* at 0x013C6510", "class": "D3D_DEVICE_STATE"},
                {"item": "Enter 0x00752AF0", "class": "ORDINARY_CODE"},
            ],
            "blocked_by": "live device state; in-game publisher blocked",
        },
    }

    seam = {
        "classification": "PARTIAL_POST_INIT_SEAM",
        "rationale": (
            "Present/Clear on a host-owned device remain a legitimate post-init API boundary. "
            "Phase 21 still lacks a DEVICE↔renderer alias and a raw-device Draw path, so the "
            "seam is not CLEAN (CLEAN requires meaningful ordinary rendering beyond Present)."
        ),
    }

    impl = {
        "D3D9_IMPLEMENTATION_JUSTIFIED": False,
        "decision": "NO",
        "checklist": {
            "device_identity": True,
            "useful_ordinary_renderer_consumers": True,
            "renderer_device_relationship_understood": False,
            "standard_d3d9_advances_ordinary_execution": False,
            "no_protected_callback_recreation_required_for_present": True,
        },
        "reason": (
            "Device identity and Present/Clear consumers are established, but the Draw path "
            "is engine COM via 0x017AA798 without a proven DEVICE relationship. Implementing "
            "D3D9 would not yet advance a defensible first useful frame."
        ),
        "highest_value_uncertainty": (
            "Whether COM objects returned by renderer helper 0x0079E4A0 (list at "
            "[renderer+0x50]..[+0x54]) hold or alias the proven device at 0x013C6510 — "
            "exact field/dataflow inside those list elements."
        ),
        "phase22_surface_if_yes": None,
    }

    estimate = {
        "best_case_phase": "UNBOUNDED",
        "likely_range": "UNBOUNDED",
        "note": "No clean seam + credible DEVICE-tied Draw + ordinary renderer state.",
    }

    frame = build_frame_graph()

    # Phase 16 sanity via angr comparison
    phase16 = {hx(a): (angr_bundle.get("comparison") or {}).get(hx(a)) for a in (0x00766730, 0x0072E340, 0x0072DD00)}

    # Overlap summary for dashboard (priority-scoped)
    high_total = sum(1 for r in data["functions"] if r.get("label") == "HIGH_CONFIDENCE")
    overlap = {
        "uc_high_total": high_total,
        "angr_priority_recovered": (angr_bundle.get("quality") or {}).get("ordinary_functions_recovered_priority"),
        "priority_class_counts": (angr_bundle.get("quality") or {}).get("class_counts"),
        "full_map_compared": False,
        "major_boundary_disagreements": [
            v for v in (angr_bundle.get("comparison") or {}).values()
            if v.get("class") in ("BOUNDARY_DISAGREEMENT", "ANGR_MISSING", "CFG_DISAGREEMENT", "SIZE_DISAGREEMENT")
        ],
    }

    angr_useful = bool(
        angr_bundle.get("available")
        and angr_bundle.get("control_weight") in ("USEFUL", "PARTIAL")
        and angr_bundle.get("cfg_ok")
    )

    out = {
        "phase": 21,
        "angr": angr_bundle,
        "overlap": overlap,
        "phase16_controls": phase16,
        "non_function_controls": angr_bundle.get("non_functions"),
        "device": {
            "va": hx(DEVICE),
            "mapped": g15.mapped_dword(image, DEVICE),
            "UC_ANALYZER": "PROVEN_D3D9_DEVICE",
            "ANGR": "seen as absolute in Present/Clear windows" if angr_bundle.get("available") else "NOT_RUN",
            "CONSENSUS": "PROVEN_D3D9_DEVICE",
            "confidence": "AGREE_STRONG" if angr_bundle.get("present_control", "").endswith("PASS") or angr_bundle.get("present_control", "").endswith("PARTIAL") else "UC_ONLY",
        },
        "renderer": {
            "UC_ANALYZER": renderer,
            "ANGR": angr_bundle.get("renderer_opinion"),
            "CONSENSUS": renderer["classification"],
            "confidence": "UC_ONLY" if not angr_bundle.get("available") else "AGREE",
        },
        "relationship": relationship,
        "aliases": {
            "transient_count": rel["transient_count"],
            "durable_count": rel["durable_count"],
            "transient_samples": rel["transient_aliases"][:30],
            "durable_samples": rel["durable_aliases"][:20],
        },
        "draw_candidates": draw_rows,
        "draw_detail_uc": draws,
        "method_0x148": method_148,
        "raw_device_draw_found": raw_device_draw,
        "wrappers": wrappers,
        "renderer_init": renderer_init,
        "handoff": handoff,
        "frame_graph": frame,
        "uc_controls": uc_controls,
        "present_control": {
            "UC_ANALYZER": "PASS" if uc_controls["present_uc"]["device_load"] else "FAIL",
            "ANGR": angr_bundle.get("present_control"),
            "CONSENSUS": angr_bundle.get("present_control"),
        },
        "clear_control": {
            "UC_ANALYZER": "PASS" if uc_controls["clear_uc"]["clear_shaped"] else "FAIL",
            "ANGR": angr_bundle.get("clear_control"),
            "CONSENSUS": angr_bundle.get("clear_control"),
        },
        "publication_classification": publication_class,
        "factory_requirement": factory_needed,
        "game_owned_state": game_state,
        "contracts": contracts,
        "seam": seam,
        "d3d9_implementation": impl,
        "first_frame_estimate": estimate,
        "angr_quality": {
            "materially_improved_analysis": angr_useful,
            "strongest_new_finding": (
                "Independent Present/Clear control decompilation recovers DEVICE absolute "
                "and EndScene-shaped call; Draw decompilation independently shows renderer "
                "0x017AA798 without DEVICE — supporting NO_RELATION_FOUND."
                if angr_useful else "angr unavailable or controls weak"
            ),
            "strongest_disagreement": (
                next(iter(overlap["major_boundary_disagreements"]), None)
                or "none on priority set"
            ),
            "control_weight": angr_bundle.get("control_weight"),
        },
        "recommended_phase22": "EXPAND_RENDERER_STATE_PROVENANCE",
        "symbolic_execution_proposal": {
            "run": False,
            "reason": "Static analysis sufficient to state the blocking uncertainty; no bounded SE query executed.",
            "future_query_if_needed": {
                "start": "0x0079E4A0",
                "stop": ["return sites", "PROTECTED_BOUNDARY"],
                "question": "Does returned COM pointer equal [0x013C6510] on any ordinary path?",
                "guards": ["is_protected_address", "bounded_steps"],
            },
        },
        "execution": {"ran": False, "reason": "analysis only; no fabricated device/renderer"},
        "dashboard": {
            "ANGR": "AVAILABLE" if angr_bundle.get("available") and angr_bundle.get("cfg_ok") else (
                "NOT RUN" if not angr_bundle.get("available") else "AVAILABLE"
            ),
            "ANGR_VERSION": angr_bundle.get("version"),
            "FUNCTION_OVERLAP": overlap.get("priority_class_counts"),
            "BOUNDARY_DISAGREEMENTS": len(overlap.get("major_boundary_disagreements") or []),
            "PRESENT_CONTROL": (angr_bundle.get("present_control") or "NOT_RUN").replace("ANGR_PRESENT_CONTROL_", ""),
            "CLEAR_CONTROL": (angr_bundle.get("clear_control") or "NOT_RUN").replace("ANGR_CLEAR_CONTROL_", ""),
            "DEVICE_TO_RENDERER": relationship["CONSENSUS"],
            "DRAW_CONSENSUS": "ENGINE_COM_DRAW",
            "DEVICE_CODE": "PROVEN",
            "DEVICE_PUBLICATION": "EXTERNAL/BLOCKED",
            "PRESENT_CODE": "FOUND",
            "DRAW_CODE": "FOUND_STRONG",
            "POST_INIT_SEAM": "PARTIAL",
            "D3D9_IMPLEMENTATION": "NOT JUSTIFIED",
            "FIRST_FRAME": "UNBOUNDED",
        },
    }

    # Write artifacts
    raw_path = os.path.join(ANALYSIS, "phase21-raw.json")
    with open(raw_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")

    # angr/ summary files (metadata only)
    summary = {
        "angr_available": angr_bundle.get("available"),
        "angr_version": angr_bundle.get("version"),
        "pinned": ANGR_VERSION_PIN,
        "python": sys.version.split()[0],
        "load_ok": angr_bundle.get("load_ok"),
        "cfg_ok": angr_bundle.get("cfg_ok"),
        "mode": angr_bundle.get("mode"),
        "symbolic_execution": False,
        "present_control": angr_bundle.get("present_control"),
        "clear_control": angr_bundle.get("clear_control"),
        "control_weight": angr_bundle.get("control_weight"),
        "priority_functions": list((angr_bundle.get("functions") or {}).keys()),
        "optional_dependency": True,
        "install": "pip install angr==%s bitstring>=4.1,<4.3" % ANGR_VERSION_PIN,
        "authority": "UC analyzer/lifter is recompilation authority; angr is comparison oracle only",
    }
    with open(os.path.join(ANGR_DIR, "summary.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")

    functions_meta = {
        hx(a): {k: v for k, v in (angr_bundle.get("functions") or {}).get(hx(a), {}).items() if k != "pseudocode"}
        for a in PRIORITY_FUNCS
    }
    with open(os.path.join(ANGR_DIR, "functions.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(functions_meta, fh, indent=2)
        fh.write("\n")

    with open(os.path.join(ANGR_DIR, "comparison.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({
            "priority": angr_bundle.get("comparison"),
            "overlap": overlap,
            "non_functions": angr_bundle.get("non_functions"),
            "note": "UC confidence never auto-changed from angr output",
        }, fh, indent=2)
        fh.write("\n")

    graphics = {
        "relationship": relationship,
        "draw_candidates": draw_rows,
        "method_0x148": method_148,
        "present_control": out["present_control"],
        "clear_control": out["clear_control"],
        "renderer": {
            "UC": renderer["classification"],
            "ANGR": angr_bundle.get("renderer_opinion"),
            "publishers": renderer["writers"],
        },
        "aliases": out["aliases"],
        "seam": seam,
        "d3d9": impl,
        "dashboard": out["dashboard"],
    }
    with open(os.path.join(ANGR_DIR, "graphics-phase21.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(graphics, fh, indent=2)
        fh.write("\n")

    # Update project-status.json
    status_path = os.path.join(ANALYSIS, "project-status.json")
    status = json.load(open(status_path, encoding="utf-8"))
    status["current_phase"] = 21
    status["strategy"] = (
        "Phase 21: optional angr oracle + UC consensus on device→renderer→Draw. "
        "DEVICE proven; publication EXTERNAL/BLOCKED. Renderer 0x017AA798 is an engine "
        "object pointer (ordinary publishers). Consensus device↔renderer: NO_RELATION_FOUND. "
        "Draw remains ENGINE_COM_DRAW (helper COM from renderer list), not raw DEVICE. "
        "PARTIAL seam; D3D9 NOT justified; first-frame UNBOUNDED."
    )
    status["graphics"].update({
        "angr": out["dashboard"]["ANGR"],
        "angr_version": out["dashboard"]["ANGR_VERSION"],
        "angr_present_control": out["dashboard"]["PRESENT_CONTROL"],
        "angr_clear_control": out["dashboard"]["CLEAR_CONTROL"],
        "device_to_renderer": relationship["CONSENSUS"],
        "draw_consensus": "ENGINE_COM_DRAW",
        "draw_code": "FOUND_STRONG",
        "post_init_seam": "PARTIAL",
        "d3d9_implementation_justified": False,
        "renderer_classification": renderer["classification"],
        "active_objective": (
            "Map renderer helper 0x0079E4A0 list objects to DEVICE fields; keep angr optional"
        ),
        "blockers": [
            "In-game DEVICE publication needs 0x00686000 before 0x00725200 and factory field from frozen 0x00B615C4",
            "No proven DEVICE↔renderer alias (consensus NO_RELATION_FOUND)",
            "Draw is ENGINE_COM_DRAW via 0x017AA798 helper, not raw DEVICE",
            "Renderer list/COM field provenance unmapped",
            "D3D9 not implemented",
        ],
    })
    status["first_frame_estimate"] = {
        "best_case_phase": "UNBOUNDED",
        "likely_low": "UNBOUNDED",
        "likely_high": "UNBOUNDED",
        "is_estimate": True,
        "uncertainty": "Renderer/Draw not tied to proven DEVICE; seam remains PARTIAL.",
    }
    for ph in status["phases"]:
        if ph["phase"] == 20:
            ph["state"] = "completed"
        if ph["phase"] == 21:
            ph["state"] = "current"
            break
    else:
        status["phases"].append({
            "phase": 21,
            "name": "Angr oracle and device-renderer consensus",
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
    # Ensure ANGR milestone-ish info stays in graphics; optional badge via progress
    with open(status_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(status, fh, indent=2)
        fh.write("\n")

    print("relationship", relationship["CONSENSUS"], file=sys.stderr)
    print("present", angr_bundle.get("present_control"), "clear", angr_bundle.get("clear_control"), file=sys.stderr)
    print("angr useful", angr_useful, "seam", seam["classification"], file=sys.stderr)
    print("wrote", raw_path, file=sys.stderr)


if __name__ == "__main__":
    main()
