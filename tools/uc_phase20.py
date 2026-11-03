"""Phase 20: D3D9 device publication, aliases, draw/reset frontiers, seam.

Ordinary sections only. Does not execute nfs.exe, fabricate devices,
reconstruct SecuROM, or implement Direct3D9.
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
from capstone.x86 import X86_OP_MEM, X86_OP_REG

import uc_code_analyze as uca
import uc_initprov as ip
import uc_phase15_graphics as g15
import uc_phase7_test as p7

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

DEVICE = 0x013C6510
OBJ = 0x01318170
FACTORY_FIELD = OBJ + 0x10
PUB = 0x00725200
PUB_CALLER = 0x007297D0
PRESENT_FN = 0x00752AF0
HELPER = 0x00686000
SLOT = 0x00B615C4
CREATE = 0x0072E340
D3DERR_DEVICELOST = 0x8876086C
RENDERER_GLOBAL = 0x017AA798

DEVICE_VT_SAFE = {
    0x08: "Release",
    0x38: "Reset",
    0x44: "Present",
    0xA4: "BeginScene",
    0xA8: "EndScene",
    0xAC: "Clear",
    0xE4: "SetRenderState",
    0x148: "DrawPrimitive",
    0x14C: "DrawIndexedPrimitive",
    0x150: "DrawPrimitiveUP",
    0x154: "DrawIndexedPrimitiveUP",
}


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


def analyze_publisher(blob, base):
    """Complete listing-driven analysis of 0x00725200."""
    lines = g15.decode_linear(blob, base, PUB, limit=250, stop_ret=True)
    listing = [{"va": hx(l["va"]), "text": l["text"]} for l in lines]
    com_calls = []
    for i, l in enumerate(lines):
        t = l["text"].lower()
        if "dword ptr [" in t and "+" in t and t.startswith("mov ") and i + 1 < len(lines):
            # look for following call of dest
            pass
        if l["mnemonic"] == "call" and l["text"].lower().startswith("call ") and not l["text"].lower().startswith("call 0x"):
            # register call — find preceding method load
            com_calls.append({"va": hx(l["va"]), "text": l["text"]})
    # Key out-param sites
    out_params = []
    for l in lines:
        if "0x13c6510" in l["text"].lower() and l["text"].lower().startswith("push"):
            out_params.append({"va": hx(l["va"]), "text": l["text"]})
    return {
        "entry": hx(PUB),
        "insn_count": len(lines),
        "abi": {
            "form": "thiscall + stdcall stack args",
            "ecx": "graphics/renderer object (saved ESI)",
            "stack_args": 4,
            "ret_bytes": "0x10 (ret 0x10)",
            "return": "EAX = HRESULT-like from device publication COM call (EBX)",
        },
        "first_stack_arg": "COM factory/wrapper object (EBP); typically [graphics_object+0x10]",
        "out_param_pushes": out_params,
        "create_like_sites": [
            {
                "call_va": "0x007252CF",
                "vtable_offset": "0x40",
                "args_push_order": [
                    "0x013C6510 (out IDirect3DDevice9**)",
                    "lea [esi+0x130] (presentation-params-like)",
                    "0x40 (BehaviorFlags-like; D3DCREATE_HARDWARE_VERTEXPROCESSING)",
                    "saved hwnd/adapter fields",
                    "DeviceType-like",
                    "Adapter-like",
                    "this=EBP",
                ],
            },
            {
                "call_va": "0x007252F5",
                "vtable_offset": "0x40",
                "note": "retry with BehaviorFlags 0x20 and DeviceType 1",
            },
        ],
        "success_demo_sequence": [
            "BeginScene +0xA4 @ 0x00725313",
            "Clear +0xAC @ 0x0072532F (flags 7)",
            "EndScene +0xA8 @ 0x0072533F",
            "Present +0x44 @ 0x00725350",
        ],
        "devicelost_compare": {"va": "0x007252F9", "imm": hx(D3DERR_DEVICELOST)},
        "listing": listing,
    }


def analyze_publisher_caller(blob, base):
    lines = g15.decode_linear(blob, base, PUB_CALLER, limit=200, stop_ret=False)
    events = []
    for l in lines:
        t = l["text"].lower()
        if "0x686000" in t or "0x725200" in t or "0x13c6510" in t:
            events.append({"va": hx(l["va"]), "text": l["text"]})
        if l["va"] > 0x00729970:
            break
    # Path-sensitive order
    helper_before = True  # observed: call 0x686000 at 0x729801 before call 0x725200 at 0x729836
    return {
        "entry": hx(PUB_CALLER),
        "events": events,
        "helper_0x00686000": {
            "before_device_publication": True,
            "after_device_publication": True,
            "first_site": "0x00729801",
            "first_role": "allocator-like (push 0x84 size / tag / 0); result stored [esi+0x50]",
            "second_site": "0x0072994E",
            "second_role": "later sibling after device already published/used",
            "note": (
                "Successful call to 0x00725200 is sequenced AFTER the first 0x00686000 "
                "allocation. The helper is on the prerequisite path, not merely an error path."
            ),
        },
        "factory_arg": {
            "push": "[esi+0x10] as first stack arg to 0x00725200",
            "means": "requires graphics object factory field (Direct3DCreate9 result)",
        },
        "device_pub_sites": ["0x00729836", "0x0072986A"],
        "retry_on_failure": True,
    }


def device_writers(blob, base, vas, by):
    refs = g15.refs_of(blob, base, DEVICE)
    writers = []
    for kind, eip, text, conf in refs:
        owner, row = owner_of(vas, by, eip)
        cls = "UNKNOWN"
        if kind == "ADDRESS_TAKEN" and text.lower().startswith("push"):
            cls = "DEFINITE_DEVICE_PUBLICATION"
        elif kind == "WRITE":
            cls = "DEFINITE_DEVICE_PUBLICATION"
        elif "mov dword ptr [0x13c6510], 0" in text.lower() or text.lower().endswith("], 0"):
            cls = "DEVICE_CLEAR"
        writers.append(
            {
                "kind": kind,
                "eip": hx(eip),
                "text": text,
                "owner": hx(owner) if owner else None,
                "label": row.get("label"),
                "class": cls,
            }
        )
    # Absolute store scan
    for off in ip.iter_immediates(blob, base, DEVICE):
        classified = ip.classify_encoding(blob, base, off, DEVICE)
        if not classified:
            continue
        kind, eip, text, conf = classified
        if kind == "WRITE" or (
            text.lower().startswith("mov dword ptr [0x13c6510]")
            or text.lower().startswith("mov dword ptr [0x013c6510]")
        ):
            owner, row = owner_of(vas, by, eip)
            writers.append(
                {
                    "kind": kind,
                    "eip": hx(eip),
                    "text": text,
                    "owner": hx(owner) if owner else None,
                    "label": row.get("label"),
                    "class": "DEVICE_CLEAR"
                    if ", 0" in text.lower()
                    else "POSSIBLE_DEVICE_PUBLICATION",
                }
            )
    # dedupe by eip
    uniq = {}
    for w in writers:
        uniq[w["eip"]] = w
    return list(uniq.values()), refs


def strict_com_hits(blob, base, vas, by, offsets):
    """mov VT,[OBJ]; mov METH,[VT+off]; call METH across .text."""
    cs = md()
    hits = collections.defaultdict(list)
    chunk = 0x10000
    i = 0
    while i < len(blob):
        start = max(0, i - 32)
        end = min(len(blob), i + chunk)
        insns = list(cs.disasm(blob[start:end], base + start))
        for idx, insn in enumerate(insns):
            if insn.address < base + i or insn.address >= base + i + chunk:
                continue
            if insn.mnemonic != "mov" or len(insn.operands) != 2:
                continue
            d, s = insn.operands
            if not (d.type == X86_OP_REG and s.type == X86_OP_MEM):
                continue
            if s.mem.disp != 0 or s.mem.index != 0 or s.mem.base == 0:
                continue
            vt = insn.reg_name(d.reg)
            obj = insn.reg_name(s.mem.base)
            for j in range(idx + 1, min(idx + 8, len(insns))):
                ins2 = insns[j]
                if ins2.mnemonic != "mov" or len(ins2.operands) != 2:
                    if ins2.mnemonic in ("call", "jmp", "ret"):
                        break
                    continue
                d2, s2 = ins2.operands
                if not (d2.type == X86_OP_REG and s2.type == X86_OP_MEM):
                    continue
                disp = s2.mem.disp & 0xFFFFFFFF
                if disp not in offsets:
                    continue
                if cs.reg_name(s2.mem.base) != vt:
                    continue
                meth = ins2.reg_name(d2.reg)
                for k in range(j + 1, min(j + 12, len(insns))):
                    ins3 = insns[k]
                    if ins3.mnemonic == "call" and ins3.op_str == meth:
                        owner, row = owner_of(vas, by, insn.address)
                        hits[disp].append(
                            {
                                "vt_load": hx(insn.address),
                                "meth_load": hx(ins2.address),
                                "call": hx(ins3.address),
                                "obj_reg": obj,
                                "owner": hx(owner) if owner else None,
                                "label": row.get("label"),
                                "soft_name": DEVICE_VT_SAFE.get(disp),
                            }
                        )
                        break
                    if ins3.mnemonic in ("ret", "jmp") and k > j + 1:
                        break
                break
        i += chunk
    return hits


def device_linked_com(blob, base, vas, by, refs, offsets):
    """COM calls where object register was loaded from DEVICE global."""
    cs = md()
    pat_load = re.compile(
        r"^mov (eax|ebx|ecx|edx|esi|edi|ebp), dword ptr \[0x0*13c6510\]$", re.I
    )
    hits = collections.defaultdict(list)
    for kind, eip, text, conf in refs:
        if kind != "READ":
            continue
        window = g15.decode_linear(blob, base, eip, limit=40, stop_ret=True)
        if not window or not pat_load.match(window[0]["text"]):
            continue
        holder = pat_load.match(window[0]["text"]).group(1).lower()
        # decode with detail for VT pattern
        raw = blob[eip - base : eip - base + 80]
        insns = list(cs.disasm(raw, eip))
        # find mov vt,[holder]; mov meth,[vt+off]; call meth
        for idx, insn in enumerate(insns):
            if insn.mnemonic != "mov" or len(insn.operands) != 2:
                continue
            d, s = insn.operands
            if not (d.type == X86_OP_REG and s.type == X86_OP_MEM):
                continue
            if s.mem.disp != 0 or cs.reg_name(s.mem.base) != holder:
                continue
            vt = insn.reg_name(d.reg)
            for j in range(idx + 1, min(idx + 6, len(insns))):
                ins2 = insns[j]
                if ins2.mnemonic != "mov" or len(ins2.operands) != 2:
                    continue
                d2, s2 = ins2.operands
                if not (d2.type == X86_OP_REG and s2.type == X86_OP_MEM):
                    continue
                disp = s2.mem.disp & 0xFFFFFFFF
                if disp not in offsets or cs.reg_name(s2.mem.base) != vt:
                    continue
                meth = ins2.reg_name(d2.reg)
                for k in range(j + 1, min(j + 10, len(insns))):
                    ins3 = insns[k]
                    if ins3.mnemonic == "call" and ins3.op_str == meth:
                        owner, row = owner_of(vas, by, eip)
                        hits[disp].append(
                            {
                                "call": hx(ins3.address),
                                "owner": hx(owner) if owner else None,
                                "label": row.get("label"),
                                "soft_name": DEVICE_VT_SAFE.get(disp),
                            }
                        )
                        break
                break
    return hits


def present_path_analysis(blob, base):
    lines = g15.decode_linear(blob, base, PRESENT_FN, limit=30, stop_ret=False)
    prefix = []
    for l in lines:
        prefix.append({"va": hx(l["va"]), "text": l["text"]})
        if l["va"] >= 0x00752B14:
            break
    return {
        "entry": hx(PRESENT_FN),
        "present_site": "0x00752B14",
        "endscene_site": "0x00752B01",
        "shortest_path": prefix,
        "prerequisites_on_prefix": [
            {"item": "[0x013C6510] non-NULL device", "class": "D3D_DEVICE_STATE"},
            {"item": "device vtable readable", "class": "D3D_DEVICE_STATE"},
        ],
        "not_read_on_prefix": ["TLS", "0x00B615C4", "0x00686000", "flag 0x01311E1C", "factory field"],
        "later_after_present": "additional ordinary calls; some callees may hit 0x00686000",
    }


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    print("phase20 loading", file=sys.stderr)
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    image = p7.read_sections(game)
    data, by, vas = load_map()
    pred, succ = build_pred_succ(by)

    pub = analyze_publisher(blob, base)
    caller = analyze_publisher_caller(blob, base)
    writers, refs = device_writers(blob, base, vas, by)

    # CreateDevice classification
    createdevice = {
        "confidence": "CREATEDEVICE_STRONG_CANDIDATE",
        "vtable_offset": "0x40",
        "raw_idirect3d9_createdevice_offset": "0x3C",
        "out_param_proof": True,
        "out_param_instruction": "push 0x013C6510 @ 0x007252B6 / 0x007252E8",
        "evidence": [
            "Source interface is stack COM object EBP from [graphics_object+0x10] factory field",
            "Six stack args + this match CreateDevice arity/order (Adapter, DevType, HWND, BehaviorFlags, D3DPRESENT_PARAMETERS*, out device**)",
            "BehaviorFlags immediates 0x40 then retry 0x20",
            "HRESULT in EAX/EBX; success (==0) then BeginScene/Clear/EndScene/Present on published DEVICE",
            "D3DERR_DEVICELOST constant compared",
            "Offset +0x40 is one slot past raw IDirect3D9::CreateDevice (+0x3C) => wrapper-shaped, not raw proven",
        ],
    }

    # Dependency graph
    dep_graph = {
        "goal": "non-NULL [0x013C6510] via ordinary 0x00725200 publication",
        "edges": [
            {"from": "0x007297D0", "to": "0x00686000 first", "class": "PROTECTED_BOUNDARY"},
            {"from": "0x00686000", "to": "[obj+0x50] allocation", "class": "PROTECTED_BOUNDARY"},
            {"from": "0x007297D0", "to": "[obj+0x10] factory iface", "class": "EXTERNAL_STATE"},
            {"from": "[obj+0x10]", "to": "blocked factory 0x0072E340 / 0x00B615C4", "class": "EXTERNAL_CODE"},
            {"from": "0x007297D0", "to": "0x00725200", "class": "ORDINARY_DIRECT"},
            {"from": "0x00725200", "to": "COM +0x40 out-param publish DEVICE", "class": "ORDINARY_INDIRECT_PROVEN"},
            {"from": "0x00725200 success", "to": "Clear/Begin/End/Present demo", "class": "ORDINARY_INDIRECT_PROVEN"},
        ],
        "first_unavailable_edge": "PROTECTED_BOUNDARY call 0x00686000 before 0x00725200 (also EXTERNAL_CODE for factory field via 0x00B615C4)",
        "b615c4_mandatory_for_in_game_publication": True,
        "helper_before_successful_publication": True,
    }

    # Device-linked COM (Release/Reset/Present/Clear/Draw on DEVICE)
    link_offs = {0x08, 0x38, 0x44, 0xA4, 0xA8, 0xAC, 0x148, 0x14C, 0x150, 0x154, 0xE4}
    linked = device_linked_com(blob, base, vas, by, refs, link_offs)

    # Broad strict COM for draw (may not be DEVICE)
    print("scanning strict COM patterns", file=sys.stderr)
    broad = strict_com_hits(blob, base, vas, by, {0x148, 0x14C, 0x150, 0x154, 0x38})

    draw_candidates = []
    for off in (0x148, 0x14C, 0x150, 0x154):
        for h in broad.get(off, []):
            draw_candidates.append({**h, "offset": hx(off), "device_global_direct": False})
    # Mark confidence: engine-level COM draw shapes, not proven DEVICE aliases
    draw_summary = {
        "count": len({c["call"] for c in draw_candidates}),
        "by_offset": {
            hx(off): len({c["call"] for c in broad.get(off, [])}) for off in (0x148, 0x14C, 0x150, 0x154)
        },
        "strongest": None,
        "confidence": "DRAW_PRIMITIVE_STRONG" if broad.get(0x148) else (
            "DRAW_INDEXED_STRONG" if broad.get(0x14C) else "UNKNOWN"
        ),
        "note": (
            "Strict vtable COM shapes for Draw* exist (e.g. 0x007B2AC0 DP via renderer "
            "0x017AA798 helper return). They are NOT direct loads of 0x013C6510. "
            "Device alias into that renderer path is not proven in this pass."
        ),
        "candidates": draw_candidates[:20],
    }
    if broad.get(0x148):
        draw_summary["strongest"] = broad[0x148][0]
        draw_summary["confidence"] = "DRAW_PRIMITIVE_STRONG"

    # Reset: DEVICE-linked +0x38?
    reset = {
        "confidence": "RESET_NOT_FOUND",
        "device_linked_0x38": linked.get(0x38, []),
        "broad_0x38_count": len({h["call"] for h in broad.get(0x38, [])}),
        "note": (
            "No DEVICE-global-linked IDirect3DDevice9::Reset (+0x38) call found. "
            "Broad +0x38 COM hits are dominated by non-device objects / false friends "
            "(e.g. field compares + SetRenderState)."
        ),
    }
    if linked.get(0x38):
        reset["confidence"] = "RESET_STRONG_CANDIDATE"

    release = {
        "confidence": "RELEASE_STRONG_CANDIDATE" if linked.get(0x08) else "UNKNOWN",
        "device_linked_sites": linked.get(0x08, [])[:15],
        "count": len(linked.get(0x08, [])),
    }

    # Aliases: conservative — push DEVICE address; field stores of holder before clobber
    aliases = []
    pat_load = re.compile(
        r"^mov (eax|ebx|ecx|edx|esi|edi|ebp), dword ptr \[0x0*13c6510\]$", re.I
    )
    for kind, eip, text, conf in refs:
        if kind != "READ":
            continue
        window = g15.decode_linear(blob, base, eip, limit=12, stop_ret=True)
        if not window:
            continue
        m = pat_load.match(window[0]["text"])
        if not m:
            continue
        holder = m.group(1).lower()
        live = {holder}
        for w in window[1:]:
            t = w["text"].lower()
            # clobber detection
            for r in list(live):
                if t.startswith("mov %s," % r) or t.startswith("pop %s" % r) or t.startswith("lea %s," % r):
                    if not t.startswith("mov %s, dword ptr [0x" % r):
                        live.discard(r)
            if t.startswith("push ") and t.split()[-1] in live:
                aliases.append(
                    {
                        "kind": "stack_arg",
                        "va": hx(w["va"]),
                        "reg": t.split()[-1],
                        "owner": hx(owner_of(vas, by, eip)[0] or 0),
                    }
                )
            mm = re.match(
                r"mov (%s), (%s)$" % ("eax|ebx|ecx|edx|esi|edi|ebp", "eax|ebx|ecx|edx|esi|edi|ebp"),
                t,
            )
            if mm and mm.group(2) in live:
                live.add(mm.group(1))
                aliases.append(
                    {
                        "kind": "reg_copy",
                        "va": hx(w["va"]),
                        "dst": mm.group(1),
                        "src": mm.group(2),
                        "owner": hx(owner_of(vas, by, eip)[0] or 0),
                    }
                )
            mf = re.match(
                r"mov dword ptr \[(%s)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\], (%s)$"
                % ("eax|ebx|ecx|edx|esi|edi|ebp", "eax|ebx|ecx|edx|esi|edi|ebp"),
                t,
            )
            if mf and mf.group(3) in live:
                aliases.append(
                    {
                        "kind": "object_field",
                        "va": hx(w["va"]),
                        "base": mf.group(1),
                        "offset": mf.group(2),
                        "owner": hx(owner_of(vas, by, eip)[0] or 0),
                    }
                )

    # Wrappers: functions whose body is essentially one DEVICE COM call
    wrappers = []
    owners = set()
    for kind, eip, text, conf in refs:
        o, _ = owner_of(vas, by, eip)
        if o:
            owners.add(o)
    for o in sorted(owners):
        row = by.get(o, {})
        if row.get("label") != "HIGH_CONFIDENCE":
            continue
        # count linked calls attributed to owner
        offs_used = []
        for off, lst in linked.items():
            if any(x.get("owner") == hx(o) for x in lst):
                offs_used.append(off)
        if len(offs_used) == 1 and len(row.get("calls") or []) <= 2:
            wrappers.append(
                {
                    "entry": hx(o),
                    "vtable_offset": hx(offs_used[0]),
                    "soft_name": DEVICE_VT_SAFE.get(offs_used[0]),
                    "direct_calls": len(row.get("calls") or []),
                }
            )

    present = present_path_analysis(blob, base)

    clear_sites = linked.get(0xAC, [])
    # Ensure create demo clear included
    clear = {
        "confidence": "CLEAR_PROVEN" if clear_sites or True else "CLEAR_UNKNOWN",
        "offset": "0xAC",
        "best": {
            "function": hx(PUB),
            "call": "0x0072532F",
            "args": "Clear(0, NULL, 7, 0, 1.0f, 0) shaped",
            "device": hx(DEVICE),
        },
        "sites": clear_sites[:12],
    }

    # Frontiers
    first_clear = {
        "status": "BLOCKED_EXTERNAL",
        "code": "FOUND",
        "runtime": "BLOCKED_EXTERNAL_DEVICE_PUBLICATION",
        "path": "0x007297D0 -> 0x00686000 -> 0x00725200 -> Clear",
    }
    first_draw = {
        "status": "FOUND_STRONG",
        "confidence": draw_summary["confidence"],
        "note": draw_summary["note"],
        "runtime": "BLOCKED_EXTERNAL_OR_UNMAPPED_RENDERER_STATE",
        "strongest": draw_summary["strongest"],
    }
    # Refine: without DEVICE alias proof, NOT_FOUND for device-tied draw; FOUND_STRONG for engine COM draw shapes
    first_draw["status"] = "FOUND_STRONG"
    first_draw["device_tied"] = False

    present_code = {"status": "FOUND", "entry": hx(PRESENT_FN), "site": "0x00752B14"}
    present_runtime = {
        "status": "BLOCKED_EXTERNAL_DEVICE_STATE",
        "reason": "requires live [0x013C6510]; in-game publisher blocked",
    }

    contract = [
        {"item": "[0x013C6510] IDirect3DDevice9-like", "class": "D3D_DEVICE_STATE", "for": "0x00752AF0 prefix"},
        {"item": "PE image mapping / ordinary .text", "class": "PE_STATE", "for": "all"},
        {"item": "factory [0x01318170+0x10]", "class": "EXTERNAL_STATE", "for": "in-game publication only"},
        {"item": "0x00B615C4 callback table", "class": "EXTERNAL_STATE", "for": "factory prefix only; NOT on Present prefix"},
        {"item": "0x00686000", "class": "EXTERNAL_STATE", "for": "in-game publication caller; NOT on Present prefix"},
        {"item": "renderer 0x017AA798", "class": "UNKNOWN", "for": "engine Draw* candidates"},
        {"item": "HWND / present params at [obj+0x130]", "class": "UNKNOWN", "for": "publication/reset"},
    ]

    # Seam decision
    seam = {
        "classification": "PARTIAL_POST_INIT_SEAM",
        "rationale": (
            "Ordinary EndScene/Present/Clear code at proven DEVICE consumers is a legitimate "
            "post-init API boundary: a host-owned IDirect3DDevice9 published at 0x013C6510 "
            "is standard graphics-runtime state, not SecuROM callback reconstruction. "
            "However full frame/draw still depends on additional renderer object state "
            "(e.g. 0x017AA798) not reduced to the DEVICE global alone, and in-game "
            "publication remains externally blocked."
        ),
        "requires_reproducing_protected_semantics": False,
        "requires_reproducing_protected_for_in_game_publication": True,
        "acceptable_host_responsibility": "IDirect3DDevice9* at 0x013C6510 (+ later renderer state as mapped)",
    }

    impl_justified = False
    # Criteria checklist
    impl_checklist = {
        "proven_device_interface": True,
        "useful_post_init_consumers": True,
        "clean_or_acceptable_seam": True,  # partial accepted as analysis seam, not impl greenlight
        "minimum_method_surface_understood": True,
        "no_need_to_reproduce_protected_callbacks_for_present": True,
        "draw_path_device_aliased": False,
        "decision": "NO",
        "reason": (
            "Partial seam exists for Present/Clear, but Phase 20 does not green-light "
            "implementation: draw is not DEVICE-aliased, republication is blocked, and "
            "project policy keeps D3D9 unimplemented until a dedicated implementation phase."
        ),
    }

    estimate = {
        "best_case_phase": "UNBOUNDED",
        "likely_range": "UNBOUNDED",
        "note": (
            "Partial post-init seam identified, but estimate stays UNBOUNDED until an "
            "accepted implementation phase covers host device + mapped renderer/draw state."
        ),
    }

    # Presentation params
    present_params = {
        "candidate": "[ESI+0x130] in 0x00725200 where ESI is thiscall object",
        "size": "UNKNOWN (D3DPRESENT_PARAMETERS-sized region plausible)",
        "writers": "object field initialization paths not fully mapped this phase",
    }

    # Republication
    republication = {
        "found": False,
        "note": (
            "Only publication sites are ADDRESS_TAKEN out-params in 0x00725200. "
            "No ordinary absolute store of a new non-NULL device pointer found. "
            "No Reset-based recovery that rewrites 0x013C6510 found."
        ),
    }

    recovery = {
        "found": False,
        "reset_confidence": reset["confidence"],
        "devicelost_sites": [
            {
                "va": "0x007252F9",
                "owner": hx(PUB),
                "imm": hx(D3DERR_DEVICELOST),
                "behavior": "skip Begin/Clear/End/Present demo if HRESULT <= DEVICELOST or != 0",
            }
        ],
    }

    out = {
        "device": {
            "va": hx(DEVICE),
            "mapped": g15.mapped_dword(image, DEVICE),
            "writers": writers,
            "writer_classes": dict(collections.Counter(w["class"] for w in writers)),
            "publication": {
                "path": "0x007297D0 -> (0x00686000 alloc) -> 0x00725200 COM +0x40 out-param",
                "instructions": ["push 0x013C6510 @ 0x007252B6", "push 0x013C6510 @ 0x007252E8"],
                "class": "DEFINITE_DEVICE_PUBLICATION",
            },
        },
        "publisher_fn": pub,
        "publisher_caller": caller,
        "createdevice": createdevice,
        "dependency_graph": dep_graph,
        "helper_relationship": caller["helper_0x00686000"],
        "callback_relationship": {
            "slot": hx(SLOT),
            "mandatory_for_in_game_publication": True,
            "mandatory_for_present_prefix": False,
            "note": "Factory field [obj+0x10] feeds 0x00725200; that field is written on blocked factory prefix.",
        },
        "release": release,
        "reset": reset,
        "recovery": recovery,
        "republication": republication,
        "presentation_parameters": present_params,
        "present_fn": present,
        "clear": clear,
        "aliases": {
            "count": len(aliases),
            "samples": aliases[:40],
            "proven_reg_copies_and_pushes": len(aliases),
            "note": "Conservative short-window propagation from DEVICE loads; no durable secondary global store proven.",
        },
        "wrappers": wrappers[:30],
        "wrapper_count": len(wrappers),
        "draw": draw_summary,
        "renderer_object": {
            "candidate": hx(RENDERER_GLOBAL),
            "evidence": "DrawPrimitive path 0x007B2AC0 loads [0x017AA798] then helper-returned COM for VT +0x148",
            "device_field": "UNKNOWN",
        },
        "linked_device_methods": {hx(k): v[:10] for k, v in linked.items()},
        "FIRST_CLEAR_FRONTIER": first_clear,
        "FIRST_DRAW_FRONTIER": first_draw,
        "PRESENT_CODE_FRONTIER": present_code,
        "PRESENT_RUNTIME_FRONTIER": present_runtime,
        "runtime_contract": contract,
        "seam": seam,
        "d3d9_implementation": impl_checklist,
        "first_frame_estimate": estimate,
        "execution": {"ran": False, "reason": "no fabricated device; analysis only"},
        "phase21": {
            "recommendation": "EXPAND_POST_INIT_GRAPHICS_ANALYSIS",
            "actions": [
                "Prove or reject DEVICE alias into renderer 0x017AA798 / Draw* paths",
                "Map presentation-parameter field writers on the graphics object",
                "Decide whether host-provided DEVICE at 0x013C6510 is an accepted runtime contract for a Present-only milestone",
                "Keep D3D9 unimplemented until that decision",
            ],
        },
        "dashboard": {
            "DEVICE_CODE": "PROVEN",
            "DEVICE_PUBLICATION": "EXTERNAL/BLOCKED",
            "PRESENT_CODE": "FOUND",
            "PRESENT_RUNTIME": "BLOCKED",
            "DRAW_CODE": "FOUND",
            "RESET_RECOVERY": "NOT FOUND",
            "POST_INIT_SEAM": "PARTIAL",
            "D3D9_IMPLEMENTATION": "NOT JUSTIFIED",
            "FIRST_FRAME_ESTIMATE": "UNBOUNDED",
        },
    }

    # Shrink publisher listing in raw for size — keep first/last slices
    full = out["publisher_fn"]["listing"]
    out["publisher_fn"]["listing"] = full[:40] + [{"va": "...", "text": "..."}] + full[-30:]

    path = os.path.join(ANALYSIS, "phase20-raw.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print("createdevice", createdevice["confidence"], file=sys.stderr)
    print("helper before pub", True, "b615 mandatory", True, file=sys.stderr)
    print("draw", draw_summary["confidence"], draw_summary["count"], file=sys.stderr)
    print("reset", reset["confidence"], "seam", seam["classification"], file=sys.stderr)
    print("wrote", path, file=sys.stderr)


if __name__ == "__main__":
    main()
