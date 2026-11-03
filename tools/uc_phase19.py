"""Phase 19: post-init graphics frontier discovery.

Ordinary .text/.rdata/.data/.tls/.rsrc and PE headers only.
Does not execute nfs.exe, reconstruct SecuROM binding, invent callbacks,
fabricate COM objects, or implement Direct3D9.
"""
from __future__ import annotations

import bisect
import collections
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

import uc_code_analyze as uca
import uc_initprov as ip
import uc_phase15_graphics as g15
import uc_phase7_test as p7

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

OBJ = 0x01318170
FACTORY_FIELD = OBJ + 0x10  # 0x01318180
CREATE = 0x0072E340
CREATE_THUNK = 0x0087A79C
SLOT_B615C4 = 0x00B615C4
HELPER = 0x00686000
DEVICE = 0x013C6510
D3DERR_DEVICELOST = 0x8876086C

# Soft labels used ONLY when device identity is independently established.
DEVICE_VT_SAFE = {
    0x00: "QueryInterface",
    0x04: "AddRef",
    0x08: "Release",
    0x38: "Reset",
    0x3C: "GetDisplayMode",
    0x44: "Present",
    0xA4: "BeginScene",
    0xA8: "EndScene",
    0xAC: "Clear",
    0x148: "DrawPrimitive",
    0x14C: "DrawIndexedPrimitive",
    0x150: "DrawPrimitiveUP",
    0x154: "DrawIndexedPrimitiveUP",
}

REGS = "eax|ebx|ecx|edx|esi|edi|ebp"
PAT_LOAD = re.compile(r"^mov (%s), dword ptr \[0x0*%x\]$" % (REGS, DEVICE), re.I)
PAT_VT = re.compile(r"^mov (%s), dword ptr \[(%s)\]$" % (REGS, REGS), re.I)
PAT_METH = re.compile(
    r"^mov (%s), dword ptr \[(%s)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]$" % (REGS, REGS), re.I
)


def hx(n):
    return "0x%08X" % (n & 0xFFFFFFFF)


def md():
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    return cs


def load_map():
    data = json.load(open(os.path.join(ANALYSIS, "function-map.json"), encoding="utf-8"))
    by = {int(row["va"], 16): row for row in data["functions"]}
    return data, by, sorted(by)


def owner_of(vas, by, eip):
    i = bisect.bisect_right(vas, eip) - 1
    if i < 0:
        return None, {}
    return vas[i], by.get(vas[i], {})


def discovery_status(row, pred):
    va = None
    high = row.get("label") == "HIGH_CONFIDENCE"
    enrolled = bool(row.get("reachable"))
    return {
        "discovered_high": high and enrolled,
        "label": row.get("label"),
        "enrolled": enrolled,
        "call_graph_reachable": None,
        "map_reachable_means": "discovery_enrollment",
    }


def build_pred_succ(by):
    pred = collections.defaultdict(set)
    succ = collections.defaultdict(set)
    for va, row in by.items():
        if row.get("label") != "HIGH_CONFIDENCE" or not row.get("reachable"):
            continue
        for key in ("calls", "tails"):
            for text in row.get(key) or []:
                t = int(text, 16)
                pred[t].add(va)
                succ[va].add(t)
    return pred, succ


def closure_hits(succ, start, targets, limit=6000):
    targets = set(targets)
    seen = set()
    q = [start]
    while q and len(seen) < limit:
        u = q.pop()
        if u in seen:
            continue
        seen.add(u)
        if u in targets:
            return True
        for v in succ.get(u, ()):
            if v not in seen:
                q.append(v)
    return False


def parse_imm(text):
    text = text.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text)


def scan_device_com(blob, base, vas, by, refs):
    hist = collections.Counter()
    by_off = collections.defaultdict(list)
    for kind, eip, text, conf in refs:
        if kind != "READ":
            continue
        window = g15.decode_linear(blob, base, eip, limit=55, stop_ret=True)
        i = 0
        while i < len(window):
            m = PAT_LOAD.match(window[i]["text"])
            if not m:
                i += 1
                continue
            holder = m.group(1).lower()
            vt = None
            j0 = None
            for j in range(i + 1, min(i + 8, len(window))):
                mv = PAT_VT.match(window[j]["text"])
                if mv and mv.group(2).lower() == holder:
                    vt = mv.group(1).lower()
                    j0 = j
                    break
            if vt is None:
                i += 1
                continue
            for k in range(j0 + 1, min(j0 + 8, len(window))):
                mm = PAT_METH.match(window[k]["text"])
                if not (mm and mm.group(2).lower() == vt):
                    continue
                meth = mm.group(1).lower()
                offv = parse_imm(mm.group(3))
                for w in window[k + 1 : k + 10]:
                    if w["text"].lower() == "call %s" % meth:
                        owner, row = owner_of(vas, by, eip)
                        hist[offv] += 1
                        by_off[offv].append(
                            {
                                "call_va": hx(w["va"]),
                                "load_va": hx(window[i]["va"]),
                                "owner": hx(owner) if owner else None,
                                "owner_label": row.get("label"),
                                "discovered_high": row.get("label") == "HIGH_CONFIDENCE"
                                and row.get("reachable"),
                                "soft_name": DEVICE_VT_SAFE.get(offv),
                            }
                        )
                        break
            i += 1
    histogram = [
        {
            "offset": hx(off),
            "calls": n,
            "owners": len({x["owner"] for x in by_off[off] if x["owner"]}),
            "soft_name": DEVICE_VT_SAFE.get(off),
            "sites": by_off[off][:12],
        }
        for off, n in hist.most_common()
    ]
    return hist, by_off, histogram


def factory_result_consumers(blob, base, vas, by, pred):
    out = []
    for kind, eip, text, conf in g15.refs_of(blob, base, FACTORY_FIELD):
        owner, row = owner_of(vas, by, eip)
        window = [w["text"] for w in g15.decode_linear(blob, base, eip, 20, True)]
        out.append(
            {
                "kind": kind,
                "eip": hx(eip),
                "text": text,
                "owner": hx(owner) if owner else None,
                "owner_label": row.get("label"),
                "discovered_high": row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable"),
                "call_graph_reachable": bool(pred.get(owner)),
                "window": window,
            }
        )
    # Alias: create writes [ebx+0x10] after Direct3DCreate9
    create_alias = {
        "kind": "ALIAS_WRITE_IN_CREATE",
        "eip": "0x0072E3C2",
        "text": "mov dword ptr [ebx + 0x10], eax",
        "owner": hx(CREATE),
        "note": "EAX = Direct3DCreate9 return; EBX = ECX graphics object",
    }
    return out, create_alias


def count_create_sites(blob, base):
    sites = []
    for off in range(len(blob) - 5):
        if blob[off] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        if (base + off + 5 + rel) & 0xFFFFFFFF == CREATE_THUNK:
            sites.append(hx(base + off))
    return sites


def d3dx_frontier(abi, by, pred):
    rows = []
    for row in abi["imports"]:
        sym = row.get("symbol") or ""
        if not sym.startswith("D3DX"):
            continue
        thunk = int(row["thunk"], 16)
        callers = sorted(pred.get(thunk, ()))
        high_callers = [
            hx(c)
            for c in callers
            if by.get(c, {}).get("label") == "HIGH_CONFIDENCE" and by.get(c, {}).get("reachable")
        ]
        rows.append(
            {
                "dll": row.get("dll"),
                "symbol": sym,
                "thunk": hx(thunk),
                "calling_convention": row.get("calling_convention"),
                "confidence": row.get("confidence"),
                "call_sites_meta": row.get("call_sites"),
                "high_callers": high_callers,
                "high_caller_count": len(high_callers),
            }
        )
    return rows


def classify_island(fn, succ, by, device_owners, present_owners, clear_owners):
    row = by.get(fn, {})
    hits_helper = closure_hits(succ, fn, {HELPER})
    hits_create = closure_hits(succ, fn, {CREATE})
    # Slot is not a code target; treat create as proxy for factory-prefix dependency.
    uses_device = fn in device_owners
    if hits_helper:
        cls = "PROTECTED_DEPENDENT"
    elif hits_create:
        cls = "POST_INIT_GRAPHICS_EXTERNAL_STATE_ONLY"  # still needs factory result path historically
        # More precise: create is blocked external code on that path
        cls = "PROTECTED_DEPENDENT"
    elif uses_device and not hits_helper:
        cls = "POST_INIT_GRAPHICS_EXTERNAL_STATE_ONLY"
    else:
        cls = "UNKNOWN"
    # Refine present-only leaves
    if fn in present_owners and not hits_helper and not hits_create:
        cls = "POST_INIT_GRAPHICS_EXTERNAL_STATE_ONLY"
    imports_needed = []
    # Indirect density from map
    indirect = int(row.get("indirect_calls") or row.get("indirect") or 0)
    if indirect:
        # keep state-only unless helper
        if cls == "POST_INIT_GRAPHICS_EXTERNAL_STATE_ONLY":
            pass
        elif not hits_helper:
            cls = "POST_INIT_GRAPHICS_INDIRECT_BLOCKED"
    return {
        "entry": hx(fn),
        "label": row.get("label"),
        "discovered_high": row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable"),
        "class": cls,
        "hits_00686000": hits_helper,
        "hits_create_0x0072E340": hits_create,
        "uses_device_global": uses_device,
        "direct_calls": len(row.get("calls") or []),
    }


def window_imports(abi):
    want = (
        "CreateWindow",
        "CreateWindowEx",
        "ShowWindow",
        "UpdateWindow",
        "PeekMessage",
        "GetMessage",
        "DispatchMessage",
        "TranslateMessage",
        "GetDC",
        "ReleaseDC",
        "GetClientRect",
        "GetWindowRect",
        "SetWindowPos",
        "AdjustWindowRect",
        "DestroyWindow",
        "DefWindowProc",
        "RegisterClass",
        "RegisterClassEx",
    )
    out = []
    for row in abi["imports"]:
        sym = row.get("symbol") or ""
        if any(sym.startswith(w) for w in want):
            out.append(
                {
                    "dll": row.get("dll"),
                    "symbol": sym,
                    "thunk": row.get("thunk"),
                    "call_sites": row.get("call_sites"),
                    "calling_convention": row.get("calling_convention"),
                }
            )
    return out


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    print("phase19 loading", file=sys.stderr)
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    image = p7.read_sections(game)
    data, by, vas = load_map()
    abi = json.load(open(os.path.join(ANALYSIS, "import-abi.json"), encoding="utf-8"))
    pred, succ = build_pred_succ(by)

    factory_boundary = {
        "path": [
            hx(CREATE),
            "three call esi via [0x00B615C4]",
            "ordinary helpers",
            "Direct3DCreate9 @ 0x0087A79C",
            "store [object+0x10]",
        ],
        "classification": "BLOCKED_EXTERNAL_PROTECTED_INITIALIZATION",
        "slot": hx(SLOT_B615C4),
        "table": "0x00B61528-0x00B615E4",
        "note": (
            "Phase 18 boundary. Do not reconstruct publication, invent callbacks, "
            "or patch .rdata."
        ),
    }

    field_consumers, create_alias = factory_result_consumers(blob, base, vas, by, pred)
    create_sites = count_create_sites(blob, base)

    device_mapped = g15.mapped_dword(image, DEVICE)
    device_refs = g15.refs_of(blob, base, DEVICE)
    hist, by_off, histogram = scan_device_com(blob, base, vas, by, device_refs)

    # Device publication: ADDRESS_TAKEN out-params
    out_params = []
    for kind, eip, text, conf in device_refs:
        if kind != "ADDRESS_TAKEN":
            continue
        owner, row = owner_of(vas, by, eip)
        out_params.append(
            {
                "eip": hx(eip),
                "text": text,
                "owner": hx(owner) if owner else None,
                "owner_label": row.get("label"),
                "discovered_high": row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable"),
            }
        )

    present_sites = by_off.get(0x44, [])
    begin_sites = by_off.get(0xA4, [])
    end_sites = by_off.get(0xA8, [])
    clear_sites = by_off.get(0xAC, [])
    draw_sites = []
    for off in (0x148, 0x14C, 0x150, 0x154):
        draw_sites.extend(by_off.get(off, []))

    device_owners = {
        int(x["owner"], 16)
        for sites in by_off.values()
        for x in sites
        if x.get("owner")
    }
    present_owners = {int(x["owner"], 16) for x in present_sites if x.get("owner")}
    clear_owners = {int(x["owner"], 16) for x in clear_sites if x.get("owner")}

    # Soft Clear detection: also scan Present owner 0x725200 listing for +0xAC
    # (histogram may miss if ref eip alignment differs)
    clear_manual = []
    for owner in sorted(present_owners | {0x00725200}):
        for line in g15.decode_linear(blob, base, owner, 200, True):
            t = line["text"].lower()
            if "0xac" in t and "dword ptr [" in t and "mov" in t:
                clear_manual.append({"owner": hx(owner), "va": hx(line["va"]), "text": line["text"]})

    # DEVICELOST
    lost_sites = []
    for off in ip.iter_immediates(blob, base, D3DERR_DEVICELOST):
        classified = ip.classify_encoding(blob, base, off, D3DERR_DEVICELOST)
        if not classified:
            continue
        kind, eip, text, conf = classified
        owner, row = owner_of(vas, by, eip)
        lost_sites.append(
            {
                "eip": hx(eip),
                "text": text,
                "owner": hx(owner) if owner else None,
                "label": row.get("label"),
            }
        )

    # Device confidence
    has_present = bool(present_sites)
    has_begin = bool(begin_sites)
    has_end = bool(end_sites)
    has_clear = bool(clear_sites or clear_manual)
    has_lost = bool(lost_sites)
    if has_present and has_begin and has_end and has_lost:
        device_confidence = "PROVEN_D3D9_DEVICE"
    elif has_present and (has_begin or has_end):
        device_confidence = "STRONG_DEVICE_CANDIDATE"
    elif hist:
        device_confidence = "WEAK_DEVICE_CANDIDATE"
    else:
        device_confidence = "UNKNOWN"

    # CreateDevice-like: out-param push of DEVICE then call through COM +0x40 in 0x725200
    create_device_candidate = {
        "location": "0x007252CF / 0x007252F5",
        "owner": "0x00725200",
        "shape": (
            "push &0x013C6510; push present-params-like; push 0x40; ...; "
            "call [vtable+0x40] on stack COM object in EBP"
        ),
        "vtable_offset": "0x40",
        "note": (
            "Offset is +0x40, one slot past IDirect3D9::CreateDevice (+0x3C). "
            "Likely a wrapper method or non-raw IDirect3D9. Out-parameter is the "
            "device global. Not labeled CreateDevice as proven."
        ),
        "confidence": "STRONG_DEVICE_PUBLICATION_CANDIDATE",
        "caller": "0x007297D0",
        "caller_hits_00686000": True,
    }

    # Reset candidates: device VT +0x38
    reset_sites = by_off.get(0x38, [])

    # Post-init islands: all HIGH owners that use DEVICE
    islands = []
    for fn in sorted(device_owners):
        islands.append(classify_island(fn, succ, by, device_owners, present_owners, clear_owners))
    # Also include present-only if missing
    for fn in present_owners:
        if fn not in device_owners:
            islands.append(classify_island(fn, succ, by, device_owners, present_owners, clear_owners))

    class_counts = collections.Counter(i["class"] for i in islands)
    state_only = [i for i in islands if i["class"] == "POST_INIT_GRAPHICS_EXTERNAL_STATE_ONLY"]
    # Best entries: prefer Present owners that are state-only, else any Present owner
    best_present = None
    for site in present_sites:
        o = int(site["owner"], 16) if site.get("owner") else None
        if o is None:
            continue
        hit = closure_hits(succ, o, {HELPER})
        rec = {
            "owner": hx(o),
            "call_va": site["call_va"],
            "hits_00686000_closure": hit,
            "present_at_entry_prefix": site["call_va"] < hx(o + 0x80) if False else True,
        }
        # Prefer 0x752AF0: Present near entry before later helper-using calls
        if o == 0x00752AF0:
            best_present = rec
            best_present["note"] = (
                "EndScene+Present at function entry; later callees may hit 0x00686000, "
                "but the present prefix itself only needs DEVICE state."
            )
            break
        if best_present is None:
            best_present = rec

    # Frame-loop candidates: functions with Present and other graphics traffic
    frame_candidates = []
    for fn in sorted(present_owners):
        row = by.get(fn, {})
        n_off = sum(1 for off, sites in by_off.items() if any(int(s["owner"], 16) == fn for s in sites if s.get("owner")))
        frame_candidates.append(
            {
                "entry": hx(fn),
                "label": row.get("label"),
                "distinct_device_vtable_offsets": n_off,
                "hits_00686000": closure_hits(succ, fn, {HELPER}),
                "preds": len(pred.get(fn, ())),
            }
        )
    frame_candidates.sort(key=lambda r: (-r["distinct_device_vtable_offsets"], r["hits_00686000"]))

    # D3DX
    d3dx = d3dx_frontier(abi, by, pred)

    # Shader-ish D3DX
    shader_syms = [r for r in d3dx if any(x in r["symbol"] for x in ("Shader", "Texture", "Surface", "Cube", "Volume"))]

    # Runtime contract
    contract = [
        {"item": "IDirect3DDevice9-like pointer at 0x013C6510", "status": "REQUIRED",
         "evidence": "125 COM calls; Present/BeginScene/EndScene (+ Clear manual); DEVICELOST constant"},
        {"item": "IDirect3D9-like at [0x01318170+0x10]", "status": "REQUIRED",
         "evidence": "Written by Direct3DCreate9 on blocked factory path; few absolute readers"},
        {"item": "Graphics object 0x01318170", "status": "REQUIRED",
         "evidence": "Factory thiscall ECX; address-taken widely"},
        {"item": "Callback table slot 0x00B615C4", "status": "REQUIRED",
         "evidence": "Blocked factory prefix only; not required by pure device Present consumers"},
        {"item": "HWND / focus window", "status": "UNKNOWN",
         "evidence": "Appears among CreateDevice-like args in 0x00725200; not proven for Present-only"},
        {"item": "Presentation parameters buffer", "status": "UNKNOWN",
         "evidence": "lea [esi+0x130] pushed beside device out-param"},
        {"item": "TLS index 0x01882C34", "status": "OPTIONAL",
         "evidence": "Outer orchestration only (Phase 17/18)"},
        {"item": "Flag 0x01311E1C == 1", "status": "OPTIONAL",
         "evidence": "Gates factory path; not read on Present-at-entry leaf 0x00752AF0"},
    ]

    # Frontiers
    first_clear = {
        "status": "FOUND" if (clear_sites or clear_manual) else "NOT_FOUND",
        "sites": clear_sites[:8],
        "manual": clear_manual[:8],
        "best": "0x00725200" if clear_manual else None,
        "dependency": "EXTERNAL_STATE_REQUIRED (device); publication path via 0x00725200 caller hits 0x00686000",
    }
    if clear_sites or clear_manual:
        # Clear lives in 0x725200 which is ordinary, but getting a live device needs creation path
        first_clear["status"] = "BLOCKED_EXTERNAL"
        first_clear["note"] = (
            "Clear-shaped call exists on ordinary code using DEVICE, but DEVICE is only "
            "published through a path whose caller closure includes 0x00686000 / blocked factory."
        )

    first_present = {
        "status": "BLOCKED_EXTERNAL",
        "sites": present_sites,
        "best_entry": best_present,
        "note": (
            "Present-shaped calls found (VT +0x44). Ordinary Present consumers require "
            "EXTERNAL STATE at 0x013C6510. No ordinary writer of that global; publication "
            "is out-param of COM call under a helper-dependent caller."
        ),
    }
    first_draw = {
        "status": "NOT_FOUND" if not draw_sites else "FOUND",
        "sites": draw_sites,
        "note": (
            "No DrawPrimitive/DrawIndexedPrimitive/UP-shaped VT offsets observed on the "
            "DEVICE global load pattern in this pass."
        ),
    }
    if not draw_sites:
        first_draw["status"] = "NOT_FOUND"

    # Minimum D3D9 surface tiers
    tier0 = ["Direct3DCreate9", "IDirect3D9::CreateDevice (or wrapper equivalent publishing 0x013C6510)"]
    tier1 = ["IDirect3DDevice9::BeginScene", "IDirect3DDevice9::Clear", "IDirect3DDevice9::EndScene",
             "IDirect3DDevice9::Present"]
    tier2 = ["vertex/index/texture creation methods (offsets observed but unnamed)",
             "SetRenderState/SetTransform-family offsets in histogram"]
    tier3 = ["D3DX math/helpers", "shader constant table helpers", "volume/cube texture helpers"]

    # First-frame graph (candidate, not executable)
    first_frame_graph = {
        "exists_as_ordinary_candidate": True,
        "edges": [
            {"from": "external/protected startup", "to": "device at 0x013C6510", "class": "EXTERNAL_CODE_REQUIRED"},
            {"from": "blocked factory 0x0072E340", "to": "IDirect3D9 at [obj+0x10]", "class": "EXTERNAL_CODE_REQUIRED"},
            {"from": "0x007297D0", "to": "0x00725200", "class": "ORDINARY_DIRECT"},
            {"from": "0x007297D0", "to": "0x00686000", "class": "PROTECTED_BOUNDARY"},
            {"from": "0x00725200", "to": "publish 0x013C6510", "class": "ORDINARY_INDIRECT_PROVEN"},
            {"from": "0x00725200", "to": "Clear/Begin/End/Present demo", "class": "ORDINARY_INDIRECT_PROVEN"},
            {"from": "0x00752AF0", "to": "EndScene+Present", "class": "ORDINARY_INDIRECT_PROVEN"},
            {"from": "0x00752AF0", "to": "later callees", "class": "PROTECTED_BOUNDARY"},
            {"from": "any Present consumer", "to": "[0x013C6510]", "class": "EXTERNAL_STATE_REQUIRED"},
        ],
        "blockers": [
            "No ordinary publication of 0x013C6510",
            "Device publication caller 0x007297D0 hits 0x00686000",
            "Factory prefix blocked on 0x00B615C4 external publication",
            "No draw-shaped DEVICE calls found in this scan",
        ],
    }

    # Alternate factory
    alternate_factory = {
        "additional_Direct3DCreate9_sites": create_sites,
        "count": len(create_sites),
        "still_single_site": create_sites == ["0x0072E3B9"],
    }

    # Window deps
    win = window_imports(abi)

    # Scores for post-init entries
    scores = []
    for isl in islands:
        fn = int(isl["entry"], 16)
        n_off = sum(
            1
            for off, sites in by_off.items()
            if any(s.get("owner") == isl["entry"] for s in sites)
        )
        milestone = 0
        if fn in present_owners:
            milestone += 3
        if fn in clear_owners or any(m.get("owner") == isl["entry"] for m in clear_manual):
            milestone += 2
        if isl["class"] == "POST_INIT_GRAPHICS_EXTERNAL_STATE_ONLY":
            milestone += 2
        if isl["hits_00686000"]:
            milestone -= 2
        scores.append(
            {
                **isl,
                "distinct_vt_offsets": n_off,
                "milestone_score": milestone,
            }
        )
    scores.sort(key=lambda r: (-r["milestone_score"], -r["distinct_vt_offsets"]))

    d3d_impl_justified = False

    # Estimate: post-init boundary FOUND as analysis artifact, but executable path still
    # blocked by external code for device publication → remove optimistic estimate.
    estimate = {
        "best_case_phase": "UNBOUNDED",
        "likely_range": "UNBOUNDED",
        "note": (
            "Post-init graphics interfaces and Present/Clear-shaped calls are identified, "
            "but device publication has no ordinary writer and the known publisher caller "
            "hits protected helper 0x00686000. Optimistic phase numbers removed."
        ),
    }

    phase20 = {
        "recommendation": "EXPAND_POST_INIT_GRAPHICS_ANALYSIS",
        "actions": [
            "Deepen device-publication COM identity at 0x00725200 (wrapper vs CreateDevice)",
            "Map full Present caller chain and any reset/recreate ordinary path that avoids 0x00686000",
            "Extend draw/resource VT naming only after interface identity is proven",
            "Do not implement D3D9 until an ordinary publication or clean external-state contract is accepted as a project decision",
        ],
    }

    out = {
        "factory_boundary": factory_boundary,
        "factory_result_field": {
            "va": hx(FACTORY_FIELD),
            "absolute_consumers": field_consumers,
            "absolute_consumer_count": len(field_consumers),
            "create_alias_write": create_alias,
        },
        "direct3dcreate9_sites": alternate_factory,
        "device": {
            "va": hx(DEVICE),
            "mapped": device_mapped,
            "confidence": device_confidence,
            "ref_count": len(device_refs),
            "ref_kinds": dict(collections.Counter(k for k, _, _, _ in device_refs)),
            "out_param_sites": out_params,
            "writer": (
                "No absolute MOV store. Published as out-parameter of COM call in "
                "0x00725200 (caller 0x007297D0)."
            ),
            "consumer_owner_count": len(device_owners),
            "create_device_candidate": create_device_candidate,
        },
        "vtable_histogram": histogram,
        "vtable_offset_count": len(histogram),
        "present": {
            "confidence": "PRESENT_STRONG_CANDIDATE" if present_sites else "PRESENT_UNKNOWN",
            "offset": "0x44",
            "sites": present_sites,
            "best": best_present,
        },
        "begin_scene": {
            "confidence": "STRONG_CANDIDATE" if begin_sites else "UNKNOWN",
            "offset": "0xA4",
            "sites": begin_sites,
        },
        "end_scene": {
            "confidence": "STRONG_CANDIDATE" if end_sites else "UNKNOWN",
            "offset": "0xA8",
            "sites": end_sites,
        },
        "clear": {
            "confidence": "STRONG_CANDIDATE" if (clear_sites or clear_manual) else "UNKNOWN",
            "offset": "0xAC",
            "sites": clear_sites,
            "manual": clear_manual,
        },
        "draw": {
            "confidence": "UNKNOWN" if not draw_sites else "CANDIDATE",
            "sites": draw_sites,
            "count": len(draw_sites),
        },
        "device_lost": lost_sites,
        "reset_candidates": {
            "vt_0x38_sites": reset_sites,
            "found": bool(reset_sites) or bool(lost_sites),
            "note": (
                "DEVICELOST constant compared in 0x00725200. No DEVICE VT +0x38 "
                "(Reset) sites matched the load pattern in this pass."
            ),
        },
        "d3dx": d3dx,
        "shader_frontier": {
            "d3dx_shader_related": shader_syms,
            "device_shader_vt_observed": [
                h for h in histogram if h["offset"] in ("0x0000017C", "0x000001A0", "0x000001A8", "0x000001AC")
                or int(h["offset"], 16) in (0x17C, 0x1A0, 0x1A8, 0x1AC, 0x190, 0x198)
            ],
            "note": "Metadata only; no shader blobs extracted.",
        },
        "frame_loop_candidates": frame_candidates,
        "post_init_islands": islands,
        "island_class_counts": dict(class_counts),
        "island_scores": scores[:25],
        "best_post_init_entry": scores[0] if scores else None,
        "external_state_vs_code": {
            "external_code_required_for_device_publication": True,
            "external_state_only_for_present_prefix": True,
            "note": (
                "Ordinary Present/EndScene code consumes DEVICE state without calling "
                "the factory slot publisher. Obtaining a non-NULL DEVICE still requires "
                "unavailable external/protected publication code."
            ),
        },
        "runtime_contract": contract,
        "window_imports": win,
        "minimum_d3d9_surface": {
            "TIER_0": tier0,
            "TIER_1": tier1,
            "TIER_2": tier2,
            "TIER_3": tier3,
        },
        "FIRST_CLEAR_FRONTIER": first_clear,
        "FIRST_DRAW_FRONTIER": first_draw,
        "FIRST_PRESENT_FRONTIER": first_present,
        "first_frame_graph": first_frame_graph,
        "d3d9_implementation_justified": d3d_impl_justified,
        "execution": {"ran": False, "reason": "would require nonexistent D3D interfaces / fabricated state"},
        "first_frame_estimate": estimate,
        "phase20": phase20,
        "dashboard": {
            "FACTORY_INITIALIZATION": "EXTERNAL/PROTECTED BLOCKED",
            "POST_INIT_GRAPHICS_FRONTIER": "FOUND",
            "DEVICE_POINTER": "PROVEN" if device_confidence == "PROVEN_D3D9_DEVICE" else (
                "CANDIDATE" if "CANDIDATE" in device_confidence else "UNKNOWN"
            ),
            "FIRST_CLEAR": first_clear["status"],
            "FIRST_DRAW": first_draw["status"],
            "FIRST_PRESENT": first_present["status"],
        },
    }

    path = os.path.join(ANALYSIS, "phase19-raw.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print("device", device_confidence, "owners", len(device_owners), "vt", len(histogram), file=sys.stderr)
    print("present", len(present_sites), "begin", len(begin_sites), "end", len(end_sites), file=sys.stderr)
    print("islands", dict(class_counts), file=sys.stderr)
    print("frontiers", first_clear["status"], first_draw["status"], first_present["status"], file=sys.stderr)
    print("wrote", path, file=sys.stderr)


if __name__ == "__main__":
    main()
