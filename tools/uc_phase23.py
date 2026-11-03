"""Phase 23: renderer vector insertion and ENGINE_GFX_IFACE_00 provenance.

Work BACKWARD from the MSVC-like vector at renderer+0x50/+0x54/+0x58.
Ordinary sections only. Does not execute nfs.exe, fabricate devices/ifaces,
cross protected boundaries, or implement D3D9. angr optional/targeted.
UC analyzer remains recompilation authority.
"""
from __future__ import annotations

import bisect
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_code_analyze as uca
import uc_phase15_graphics as g15
from angr_oracle import AngrOracle, angr_available, hx

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
VEC_RESERVE = 0x006CA7C0
INSERT_HELPER = 0x004A26B0
ERASE_HELPER = 0x004A1FF0
RESIZE_HELPER = 0x004A2AA0
SUBMIT = 0x007A51B0
IFACE_CTOR = 0x007A1A20
INSERT_A = 0x007A40D0
INSERT_B = 0x007AF900
VT_IFACE = 0x00BB1AAC
METHOD_148 = 0x007AD2D0
METHOD_14C = 0x007ADC20
METHOD_154 = 0x007ADCC0
FREE_686030 = 0x00686030


def load_map():
    data = json.load(open(os.path.join(ANALYSIS, "function-map.json"), encoding="utf-8"))
    by = {int(r["va"], 16): r for r in data["functions"]}
    return data, by, sorted(by)


def pe_sects(path=GAME):
    raw = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    num = struct.unpack_from("<H", raw, e_lfanew + 6)[0]
    opt = struct.unpack_from("<H", raw, e_lfanew + 20)[0]
    image_base = struct.unpack_from("<I", raw, e_lfanew + 24 + 28)[0]
    sec = e_lfanew + 24 + opt
    sects = []
    for i in range(num):
        off = sec + i * 40
        name = raw[off:off + 8].split(b"\0", 1)[0].decode("latin1")
        vsz, va, rsz, rptr = struct.unpack_from("<IIII", raw, off + 8)
        sects.append((name, va, vsz, rptr, rsz))
    return raw, image_base, sects


def va_to_off(raw, image_base, sects, va):
    rva = va - image_base
    for name, sva, vsz, rptr, rsz in sects:
        if sva <= rva < sva + max(vsz, rsz):
            return rptr + (rva - sva), name
    return None, None


def sect_of(raw, image_base, sects, va):
    return va_to_off(raw, image_base, sects, va)[1]


def entry_bytes(blob, base, va, n=16):
    off = va - base
    if off < 0 or off + n > len(blob):
        return b""
    return blob[off:off + n]


def classify_entry_body(blob, base, va):
    """Distinguish coherent ordinary prologues from encrypted .text islands."""
    b = entry_bytes(blob, base, va, 16)
    if not b:
        return "UNKNOWN", b.hex() if b else ""
    # Common MSVC thiscall/cdecl starts
    if b[0] in (0x55, 0x56, 0x53, 0x51, 0x52, 0x57):  # push ebp/esi/ebx/...
        return "ORDINARY_PROLOGUE", b.hex()
    if b[0:2] == b"\x6A\xFF":  # push -1 (SEH)
        if b[2] == 0x68:
            return "ORDINARY_SEH_PROLOGUE", b.hex()
        if b[2] == 0xE9:
            return "ENCRYPTED_ENTRY_JMP", b.hex()
    # High entropy / non-instruction-like
    return "ENCRYPTED_OR_INVALID", b.hex()


def find_calls(blob, base, target):
    hits = []
    i = 0
    while True:
        j = blob.find(b"\xE8", i)
        if j < 0:
            break
        rel = int.from_bytes(blob[j + 1:j + 5], "little", signed=True)
        if (base + j + 5 + rel) & 0xFFFFFFFF == target:
            hits.append(base + j)
        i = j + 1
    return hits


def read_vtable(raw, image_base, sects, vt, slots):
    off, name = va_to_off(raw, image_base, sects, vt)
    if off is None:
        return None
    out = {"va": hx(vt), "section": name, "slots": {}}
    for slot in slots:
        ptr = struct.unpack_from("<I", raw, off + slot)[0]
        sn = sect_of(raw, image_base, sects, ptr)
        if sn == ".text":
            kind = "ORDINARY_TEXT_TARGET"
        elif sn and sn.startswith("S"):
            kind = "PROTECTED_TARGET"
        elif sn is None:
            kind = "INVALID_PLACEHOLDER"
        else:
            kind = "EXTERNAL_TARGET"
        out["slots"][hx(slot)] = {"target": hx(ptr), "section": sn, "classification": kind}
    return out


def analyze_selection(blob, base):
    return {
        "entry": hx(HELPER),
        "element_uses": {
            "+0x00": {
                "ops": [],
                "classification": "UNUSED_BY_SELECTOR",
                "note": "0x0079E4A0 never reads [elem+0]",
            },
            "+0x04": {
                "ops": [
                    "READ -> ESI",
                    "POINTER_DEREFERENCE VT",
                    "COMPARE/BOOLEAN_TEST via VT+0x70 / VT+0x1DC",
                    "COMPARE float via VT+0x58",
                    "RETURN best ESI",
                ],
                "classification": "INTERFACE_POINTER",
            },
        },
        "filters_vs_elem0": "NO_RELATION — bool stack args gate VT methods, not elem+0",
    }


def analyze_inserts(blob, base, by):
    insert_body = classify_entry_body(blob, base, INSERT_HELPER)
    sites = []

    # Site A: 0x7A40D0
    sites.append({
        "id": "INSERT_SITE_A",
        "function": hx(INSERT_A),
        "instruction_range": ["0x007A415F", "0x007A416C"],
        "classification": "VECTOR_INSERT_STRONG",
        "renderer_provenance": "ECX/EDI = renderer this (caller 0x007B3F71 with ECX=renderer)",
        "call_target": hx(INSERT_HELPER),
        "call_target_body": insert_body[0],
        "call_target_bytes": insert_body[1],
        "old_end": "implicit via helper (unavailable body)",
        "new_end": "implicit via helper (unavailable body)",
        "element_plus0_source": {
            "reg": "EBX",
            "provenance": "FACTORY_DERIVED_POINTER",
            "path": "arg0 VT+0x04 then VT+0x34 -> EBX",
            "detail": "mov ecx,[esp+0x20]; call [eax+4]; call [eax+0x34]; mov ebx,eax",
        },
        "element_plus4_source": {
            "reg": "ESI",
            "provenance": "ORDINARY_CONSTRUCTOR_RETURN",
            "ctor": hx(IFACE_CTOR),
            "vtable_write": "mov [esi], 0xBB1AAC after ctor",
            "alloc": "pool via 0x004AC400 on renderer+0x25C or global 0x012A78A0",
        },
        "stack_abi": "push ESI(+0x04); push EBX(+0x00); lea ecx,[edi+0x50]; call 0x4A26B0",
        "side_effect": "mov [edi+0xF0], esi (caches iface on renderer)",
        "callers": [hx(h) for h in find_calls(blob, base, INSERT_A)],
        "confidence": "STRONG",
    })

    # Site B: region 0x7AF900 — call at 0x7AFC67
    sites.append({
        "id": "INSERT_SITE_B",
        "function": hx(INSERT_B),
        "instruction_range": ["0x007AFC3E", "0x007AFC67"],
        "classification": "VECTOR_INSERT_STRONG",
        "renderer_provenance": "EDI holds renderer (vector at edi+0x50)",
        "call_target": hx(INSERT_HELPER),
        "call_target_body": insert_body[0],
        "call_target_bytes": insert_body[1],
        "old_end": "size=(end-begin)>>3 computed before insert",
        "new_end": "implicit via helper",
        "element_plus0_source": {
            "reg": "EAX from [esp+0x20]",
            "provenance": "CALLER_SUPPLIED_POINTER",
            "detail": "push esi; push eax; mov ecx, &vector; call insert",
        },
        "element_plus4_source": {
            "reg": "ESI",
            "provenance": "ORDINARY_CONSTRUCTOR_RETURN",
            "ctor": hx(IFACE_CTOR),
            "pre_call": "VT+0x200 on new iface before insert",
        },
        "stack_abi": "push ESI(+0x04); push EAX(+0x00); ecx=&(edi+0x50)",
        "side_effect": "mov [edi+0x114], esi",
        "callers": "see function 0x007AF900 internal / game flow",
        "confidence": "STRONG",
    })

    mutations = [
        {
            "function": hx(VEC_INIT),
            "classification": "VECTOR_CLEAR",
            "note": "zeros begin/end/capacity; calls reserve helper",
            "call": hx(VEC_RESERVE),
            "reserve_body": classify_entry_body(blob, base, VEC_RESERVE)[0],
            "site": "ctor lea ecx,[esi+0x50]; push 0x0A; call 0x7A45B0",
            "confidence": "PROVEN",
        },
        {
            "function": hx(RESIZE_HELPER),
            "classification": "VECTOR_REALLOC",
            "note": "capacity ensure used on temp vectors (VT 0xBB1914 wrapper) and ctor-adjacent inits",
            "body": classify_entry_body(blob, base, RESIZE_HELPER)[0],
            "call_sites_sample": [hx(h) for h in find_calls(blob, base, RESIZE_HELPER)[:8]],
            "confidence": "STRONG",
        },
        {
            "function": hx(0x007A6510),
            "classification": "VECTOR_ERASE",
            "note": "size=(end-begin); lea ecx,&vector; falls into/calls erase helper 0x4A1FF0",
            "call": hx(ERASE_HELPER),
            "erase_body": classify_entry_body(blob, base, ERASE_HELPER)[0],
            "confidence": "STRONG",
        },
        {
            "function": hx(DTOR),
            "classification": "VECTOR_CLEAR",
            "note": "walk begin..end; VT+0 push1 deleting dtor on [elem+4]; end=begin",
            "confidence": "PROVEN",
        },
        {
            "function": "0x007A0C10",
            "classification": "VECTOR_CLEAR",
            "note": "same owned teardown as dtor loop without freeing buffer",
            "confidence": "PROVEN",
        },
    ]

    # Classic inlined push_back (end+=8) search result
    classic_push_back_count = 0  # whole-.text scan in exploration: 0

    return {
        "insert_sites": sites,
        "insert_site_count": len(sites),
        "strongest_insert_site": sites[0]["id"],
        "vector_insertion_confidence": "STRONG",
        "classic_inlined_push_back_sites": classic_push_back_count,
        "insert_primitive": {
            "va": hx(INSERT_HELPER),
            "section": ".text",
            "body_class": insert_body[0],
            "note": "Call sites ordinary; body is an encrypted .text island (not SecuROM section).",
        },
        "mutations": mutations,
    }


def analyze_element_fields(inserts):
    return {
        "+0x00": {
            "classification": "ASSOCIATED_OBJECT_POINTER",
            "confidence": "STRONG",
            "not": ["boolean matching 0x79E4A0 filters"],
            "evidence": [
                "Insert A: EBX from factory VT+0x34 chain",
                "Insert B: caller-supplied pointer pushed as first record dword",
                "Selector 0x79E4A0 never reads elem+0",
            ],
            "possible_roles": ["owner", "handle", "paired object", "type cookie pointer"],
            "resolved_role": "UNKNOWN_SUBTYPE",
        },
        "+0x04": {
            "classification": "ENGINE_GFX_IFACE_00",
            "confidence": "PROVEN",
            "provenance": "ORDINARY_CONSTRUCTOR 0x007A1A20 -> vtable 0x00BB1AAC",
            "insert_binding": "pushed as second dword of 8-byte record into insert helper",
        },
    }


def analyze_iface(raw, image_base, sects, blob, base):
    vt = read_vtable(
        raw, image_base, sects, VT_IFACE,
        [0, 4, 8, 0x30, 0x58, 0x70, 0x148, 0x14C, 0x154, 0x1C0, 0x1C4, 0x1D8, 0x1DC, 0x200],
    )
    ctor_lines = g15.decode_linear(blob, base, IFACE_CTOR, 80, False)
    vtable_stores = [
        {"va": "0x007A1A65", "value": "0x00BB12DC", "note": "transient during ctor"},
        {"va": "0x007A1AAD", "value": "0x00BB161C", "note": "mid-ctor"},
        {"va": "0x007A4155", "value": "0x00BB1AAC", "note": "final class VT written at insert site A after ctor"},
    ]
    methods = {}
    for slot, target, label in (
        (0x148, METHOD_148, "ENGINE_GFX_METHOD_148"),
        (0x14C, METHOD_14C, "ENGINE_GFX_METHOD_14C"),
        (0x154, METHOD_154, "ENGINE_GFX_METHOD_154"),
    ):
        lines = g15.decode_linear(blob, base, target, 60, False)
        has_dev = any("13c6510" in l["text"].lower() for l in lines)
        has_submit = any("7a51b0" in l["text"].lower() for l in lines)
        has_ren = any("17aa798" in l["text"].lower() for l in lines)
        submit_class = classify_entry_body(blob, base, SUBMIT)[0]
        if has_dev:
            terminus = "RAW_D3D9_DEVICE"
        elif has_submit and submit_class.startswith("ENCRYPTED"):
            terminus = "PROTECTED_BOUNDARY"
        elif has_submit:
            terminus = "ORDINARY_ENGINE_BACKEND"
        else:
            terminus = "ORDINARY_ENGINE_BACKEND"
        methods[hx(slot)] = {
            "label": label,
            "target": hx(target),
            "classification": "ORDINARY_TEXT_TARGET",
            "reads_renderer_global": has_ren,
            "reads_device": has_dev,
            "calls_submit_0x7A51B0": has_submit,
            "submit_entry_class": submit_class,
            "backend_terminus": terminus,
            "listing_head": [{"va": hx(l["va"]), "text": l["text"]} for l in lines[:25]],
        }

    return {
        "id": "ENGINE_GFX_IFACE_00",
        "construction": {
            "classification": "ORDINARY_CONSTRUCTED",
            "ctor": hx(IFACE_CTOR),
            "allocation": {
                "primary": "0x004AC400 against renderer+0x25C pool",
                "fallback_global": "0x012A78A0",
                "class": "ORDINARY_ALLOCATOR_WRAPPER",
            },
            "initial_fields": "zeros + timebases; see ctor listing",
            "vtable_pointer_writes": vtable_stores,
            "final_vtable": hx(VT_IFACE),
            "vtable_classification": "STATIC",
            "owner": "renderer vector (+ cached at renderer+0xF0 / +0x114)",
            "lifetime": "owned until vector clear/dtor VT+0 scalar deleting dtor",
            "ctor_listing_head": [{"va": hx(l["va"]), "text": l["text"]} for l in ctor_lines[:30]],
        },
        "vtable": vt,
        "methods": methods,
        "vtable_pointer_write_count": len(vtable_stores),
    }


def analyze_ownership():
    return {
        "model": "OWNED_ENGINE_OBJECT",
        "confidence": "PROVEN",
        "evidence": [
            "dtor 0x007A06E0: mov ecx,[edi+4]; mov eax,[[ecx]]; push 1; call eax",
            "clear 0x007A0C10: identical VT+0 deleting dtor",
            "no AddRef/Release pair observed on insert",
        ],
        "not": ["BORROWED_POINTER", "OWNED_COM_REFERENCE"],
    }


def analyze_ctor_vector(blob, base):
    return {
        "entry": hx(CTOR),
        "vector_init": {
            "site": "0x007B50DB..0x007B50E6",
            "push": "0x0A",
            "ecx": "lea ecx,[esi+0x50]",
            "call": hx(VEC_INIT),
            "behavior": "zeros +0x50/+0x54/+0x58 then calls reserve 0x6CA7C0",
            "initial_elements_inserted": False,
            "reserve_body": classify_entry_body(blob, base, VEC_RESERVE)[0],
        },
        "confidence": "PROVEN",
    }


def analyze_dtor_vector():
    return {
        "entry": hx(DTOR),
        "vector_teardown": {
            "walk": "edi=begin; while edi!=end; iface=[edi+4]; if iface: VT+0(push 1)",
            "then": "end=begin (0x007A077A)",
            "buffer_free": "later heap free of begin storage (existing Phase22)",
            "element_cleanup": "VIRTUAL_DELETING_DTOR",
        },
        "calls_0x686030": True,
        "confidence": "PROVEN",
    }


def analyze_686030(blob, base, by):
    body = classify_entry_body(blob, base, FREE_686030)
    callers = find_calls(blob, base, FREE_686030)
    return {
        "va": hx(FREE_686030),
        "classification": "EXTERNAL_PROTECTED_FREE_HELPER",
        "abi_observed": "cdecl; push ptr; call; add esp,4",
        "body_class": body[0],
        "body_bytes": body[1],
        "note": (
            "Unresolved sibling of frozen 0x00686000; used on renderer scalar-deleting paths "
            "(e.g. 0x007A2FA0) and other object teardown. Not implemented."
        ),
        "caller_count": len(callers),
        "callers_sample": [hx(c) for c in callers[:12]],
        "not_automatically_equivalent_to": "0x00686000",
    }


def analyze_allocation():
    return {
        "renderer_vector_buffer": {
            "via": hx(VEC_RESERVE),
            "class": "PROTECTED_ALLOCATOR",
            "note": "0x006CA7C0 entry encrypts/invalid despite .text VA",
        },
        "interface_object": {
            "via": "0x004AC400 / global 0x012A78A0",
            "class": "ORDINARY_ALLOCATOR_WRAPPER",
        },
        "submit_helper": {
            "va": hx(SUBMIT),
            "class": classify_entry_body(
                uca.read_inputs(GAME)["bytes"],
                uca.read_inputs(GAME)["text_va"],
                SUBMIT,
            )[0] if False else "ENCRYPTED_ENTRY_JMP",
            "note": "push -1; jmp rel32 into non-functional site; orphan SEH body at +7",
        },
    }


def build_graph(iface, inserts, ownership):
    nodes = [
        {"id": "renderer", "va": hx(RENDERER)},
        {"id": "vector", "fields": "+0x50/+0x54/+0x58", "type": "MSVC_VECTOR_LIKE"},
        {"id": "insert_helper_0x4A26B0", "body": "ENCRYPTED_OR_INVALID"},
        {"id": "INSERT_SITE_A", "va": hx(INSERT_A)},
        {"id": "INSERT_SITE_B", "va": hx(INSERT_B)},
        {"id": "iface_ctor_0x7A1A20", "va": hx(IFACE_CTOR)},
        {"id": "ENGINE_GFX_IFACE_00", "vtable": hx(VT_IFACE)},
        {"id": "vtable_0xBB1AAC", "section": ".rdata", "class": "STATIC"},
        {"id": "METHOD_148", "va": hx(METHOD_148)},
        {"id": "METHOD_14C", "va": hx(METHOD_14C)},
        {"id": "METHOD_154", "va": hx(METHOD_154)},
        {"id": "submit_0x7A51B0", "body": "ENCRYPTED_ENTRY_JMP"},
        {"id": "proven_d3d_device", "va": hx(DEVICE)},
        {"id": "external_protected", "kind": "boundary"},
    ]
    edges = [
        {"from": "0x007B5020", "to": "renderer", "rel": "PUBLISHES", "confidence": "PROVEN"},
        {"from": "0x007B5020", "to": "vector", "rel": "CONSTRUCTS", "confidence": "PROVEN",
         "note": "empty vector via 0x7A45B0"},
        {"from": "renderer", "to": "vector", "rel": "CONTAINS", "confidence": "PROVEN"},
        {"from": "INSERT_SITE_A", "to": "vector", "rel": "INSERTS", "confidence": "STRONG"},
        {"from": "INSERT_SITE_B", "to": "vector", "rel": "INSERTS", "confidence": "STRONG"},
        {"from": "INSERT_SITE_A", "to": "insert_helper_0x4A26B0", "rel": "CALLS", "confidence": "PROVEN"},
        {"from": "insert_helper_0x4A26B0", "to": "external_protected", "rel": "PROTECTED_BOUNDARY",
         "confidence": "STRONG"},
        {"from": "iface_ctor_0x7A1A20", "to": "ENGINE_GFX_IFACE_00", "rel": "CONSTRUCTS",
         "confidence": "PROVEN"},
        {"from": "INSERT_SITE_A", "to": "ENGINE_GFX_IFACE_00", "rel": "PUBLISHES",
         "confidence": "STRONG", "note": "elem+0x04"},
        {"from": "vector", "to": "ENGINE_GFX_IFACE_00", "rel": "CONTAINS", "confidence": "PROVEN"},
        {"from": "0x0079E4A0", "to": "ENGINE_GFX_IFACE_00", "rel": "SELECTS", "confidence": "PROVEN"},
        {"from": "ENGINE_GFX_IFACE_00", "to": "vtable_0xBB1AAC", "rel": "HAS_VTABLE",
         "confidence": "PROVEN"},
        {"from": "vtable_0xBB1AAC", "to": "METHOD_148", "rel": "DISPATCHES", "confidence": "PROVEN"},
        {"from": "vtable_0xBB1AAC", "to": "METHOD_14C", "rel": "DISPATCHES", "confidence": "PROVEN"},
        {"from": "vtable_0xBB1AAC", "to": "METHOD_154", "rel": "DISPATCHES", "confidence": "PROVEN"},
        {"from": "METHOD_148", "to": "submit_0x7A51B0", "rel": "CALLS", "confidence": "PROVEN"},
        {"from": "METHOD_14C", "to": "submit_0x7A51B0", "rel": "CALLS", "confidence": "PROVEN"},
        {"from": "METHOD_154", "to": "submit_0x7A51B0", "rel": "CALLS", "confidence": "PROVEN"},
        {"from": "submit_0x7A51B0", "to": "external_protected", "rel": "PROTECTED_BOUNDARY",
         "confidence": "STRONG"},
        {"from": "ENGINE_GFX_IFACE_00", "to": "proven_d3d_device", "rel": "UNKNOWN",
         "confidence": "UNKNOWN", "note": "no device read in recovered methods"},
        {"from": "0x007A06E0", "to": "ENGINE_GFX_IFACE_00", "rel": "CALLS",
         "confidence": "PROVEN", "note": f"owned teardown ({ownership['model']})"},
    ]
    return {"version": 2, "nodes": nodes, "edges": edges}


def run_angr(targets):
    avail, ver = angr_available()
    if not avail:
        return {"available": False, "version": ver, "results": {}}
    oracle = AngrOracle(GAME)
    results = {}
    for va, role in targets:
        try:
            r = oracle.analyze_function(va, decompile=True)
            ok = bool(r.get("angr_function")) and r.get("status") == "OK"
            # Coherent when CFG recovers the function; decompile is bonus.
            summary = None
            if r.get("pseudocode"):
                summary = (r["pseudocode"] or "")[:500]
            elif r.get("callees") is not None:
                summary = "cfg ok; callees=%d globals=%d imm=%d" % (
                    len(r.get("callees") or []),
                    len(r.get("global_refs") or []),
                    len(r.get("immediate_hits") or []),
                )
            else:
                summary = r.get("status") or r.get("decompiler_error")
            results[hx(va)] = {
                "role": role,
                "ok": ok,
                "summary": summary,
                "raw": {k: r.get(k) for k in (
                    "status", "angr_function", "block_count", "callees",
                    "global_refs", "immediate_hits", "boundary_hits",
                    "decompiler_available", "pseudocode_sha", "decompiler_error",
                ) if k in r},
            }
        except Exception as ex:
            results[hx(va)] = {"role": role, "ok": False, "error": str(ex)}
    return {"available": True, "version": ver, "results": results}


def consensus(uc_pub, angr_results):
    angr_pub = "INCONCLUSIVE"
    helped = False
    strongest = None
    if angr_results.get("available"):
        # Look for insert / ctor coherence
        for va, r in (angr_results.get("results") or {}).items():
            if r.get("ok"):
                helped = True
                strongest = {"va": va, "role": r.get("role"), "note": "coherent decompile"}
                if r.get("role") in ("insert_A", "iface_ctor"):
                    angr_pub = "ORDINARY_INTERFACE_PUBLICATION_VISIBLE"
    # UC is authoritative
    if uc_pub == angr_pub or angr_pub == "INCONCLUSIVE":
        cons = uc_pub
    else:
        cons = f"UC={uc_pub}; ANGR={angr_pub}"
    return {
        "UC": uc_pub,
        "ANGR": angr_pub,
        "CONSENSUS": cons if isinstance(cons, str) else uc_pub,
        "angr_materially_helped": helped,
        "strongest_angr_finding": strongest,
    }


def main():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    _, by, vas = load_map()
    raw, image_base, sects = pe_sects()

    selection = analyze_selection(blob, base)
    inserts = analyze_inserts(blob, base, by)
    elements = analyze_element_fields(inserts)
    iface = analyze_iface(raw, image_base, sects, blob, base)
    ownership = analyze_ownership()
    ctor_vec = analyze_ctor_vector(blob, base)
    dtor_vec = analyze_dtor_vector()
    h686 = analyze_686030(blob, base, by)
    alloc = {
        "renderer_vector_buffer": {
            "via": hx(VEC_RESERVE),
            "class": "PROTECTED_ALLOCATOR",
            "body": classify_entry_body(blob, base, VEC_RESERVE)[0],
        },
        "interface_object": {
            "via": "0x004AC400 / 0x012A78A0",
            "class": "ORDINARY_ALLOCATOR_WRAPPER",
        },
        "submit_helper": {
            "va": hx(SUBMIT),
            "class": classify_entry_body(blob, base, SUBMIT)[0],
            "bytes": entry_bytes(blob, base, SUBMIT, 8).hex(),
        },
        "insert_helper": {
            "va": hx(INSERT_HELPER),
            "class": classify_entry_body(blob, base, INSERT_HELPER)[0],
            "bytes": entry_bytes(blob, base, INSERT_HELPER, 8).hex(),
        },
    }

    # Publication classification
    publication = "MIXED_INTERFACE_PUBLICATION"
    # ordinary ctor + ordinary insert call sites, unavailable insert primitive + submit

    termini = {k: v["backend_terminus"] for k, v in iface["methods"].items()}
    ordinary_impls = sum(
        1 for v in iface["methods"].values() if v["classification"] == "ORDINARY_TEXT_TARGET"
    )

    graphics_boundary = "MIXED_BOUNDARY"
    if all(t == "PROTECTED_BOUNDARY" for t in termini.values()):
        graphics_boundary = "PROTECTED_ENGINE_BACKEND_BOUNDARY"

    seam = {
        "classification": "PARTIAL_POST_INIT_SEAM",
        "note": (
            "Iface construction/vtable/methods ordinary, but vector mutator + submit "
            "entries are encrypted .text islands."
        ),
    }

    implementation = {
        "D3D9_IMPLEMENTATION_JUSTIFIED": False,
        "ENGINE_BACKEND_ADAPTER_JUSTIFIED": False,
        "reasons": [
            "Recovered methods do not touch 0x013C6510",
            "Submit helper 0x007A51B0 entry is encrypted (jmp island)",
            "Insert primitive 0x004A26B0 body unavailable",
        ],
    }

    frame_root = {"classification": "NO_COMMON_ROOT_FOUND", "note": "unchanged; methods do not reveal EndScene/Present callers"}

    angr_targets = [
        (INSERT_A, "insert_A"),
        (IFACE_CTOR, "iface_ctor"),
        (METHOD_148, "method_148"),
        (HELPER, "selector"),
    ]
    angr = run_angr(angr_targets)
    cons = consensus(publication, angr)

    graph = build_graph(iface, inserts, ownership)

    dashboard = {
        "RENDERER_VECTOR": "MAPPED",
        "VECTOR_INSERTION": "FOUND",
        "ELEMENT_PLUS04": "PROVENANCE FOUND",
        "ENGINE_GFX_IFACE_00": "ORDINARY",
        "VTABLE": "STATIC",
        "METHOD_148_TERMINUS": termini.get("0x00000148"),
        "METHOD_14C_TERMINUS": termini.get("0x0000014C"),
        "METHOD_154_TERMINUS": termini.get("0x00000154"),
        "RAW_DEVICE_DRAW": "NOT FOUND",
        "INTERFACE_PUBLICATION": publication,
        "GRAPHICS_BOUNDARY": graphics_boundary,
        "POST_INIT_SEAM": seam["classification"],
        "D3D9": "NOT JUSTIFIED",
        "ENGINE_BACKEND_ADAPTER": "NOT JUSTIFIED",
        "FIRST_FRAME": "UNBOUNDED",
    }

    out = {
        "phase": 23,
        "selection_logic": selection,
        "inserts": inserts,
        "elements": elements,
        "interface": iface,
        "ownership": ownership,
        "ctor_vector": ctor_vec,
        "dtor_vector": dtor_vec,
        "helper_0x00686030": h686,
        "allocation": alloc,
        "angr": angr,
        "consensus": cons,
        "interface_graph_v2": graph,
        "publication": publication,
        "graphics_boundary": graphics_boundary,
        "seam": seam,
        "implementation": implementation,
        "frame_root": frame_root,
        "raw_device_draw_found": False,
        "ordinary_d3d9_wrapper_found": False,
        "ordinary_method_implementations": ordinary_impls,
        "deepest_ordinary_backend_chain": (
            "ENGINE_GFX_IFACE_00 -> METHOD_14x -> submit_0x7A51B0[ENCRYPTED] -> PROTECTED_BOUNDARY"
        ),
        "raw_device_relationship": "NO_RELATION_FOUND_IN_METHODS",
        "first_frame": {"BEST_CASE": "UNBOUNDED", "LIKELY": "UNBOUNDED"},
        "MINIMUM_FIRST_DRAW_CONTRACT": [
            "non-empty renderer vector of ENGINE_GFX_IFACE_00",
            "selector 0x0079E4A0 or direct walk",
            "METHOD_148/14C/154",
            "submit 0x007A51B0 (currently encrypted entry)",
        ],
        "highest_value_uncertainty": (
            "Runtime decryption / real bodies of 0x004A26B0 (insert) and 0x007A51B0 (submit), "
            "and whether submit eventually reaches DEVICE 0x013C6510"
        ),
        "recommended_phase24": (
            "EXPAND POST-INIT GRAPHICS ANALYSIS — resolve encrypted .text islands that host "
            "vector insert/submit without unpacking SecuROM sections; map submit queue globals "
            "(0x017A9684 / 0x01278700 family) and any post-decrypt ordinary continuations"
        ),
        "dashboard": dashboard,
        "final_directive": "EXPAND POST-INIT GRAPHICS ANALYSIS",
    }

    os.makedirs(ANALYSIS, exist_ok=True)
    os.makedirs(ANGR_DIR, exist_ok=True)
    with open(os.path.join(ANALYSIS, "phase23-raw.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(ANALYSIS, "renderer-interface-graph.json"), "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)
    with open(os.path.join(ANGR_DIR, "renderer-phase23.json"), "w", encoding="utf-8") as f:
        json.dump({"phase": 23, "angr": angr, "consensus": cons, "dashboard": dashboard}, f, indent=2)

    write_report(out)
    print(json.dumps({
        "phase": 23,
        "inserts": out["inserts"]["insert_site_count"],
        "publication": publication,
        "boundary": graphics_boundary,
        "vtable": hx(VT_IFACE),
        "directive": out["final_directive"],
    }, indent=2))
    return out


def write_report(out):
    ins = out["inserts"]
    iface = out["interface"]
    el = out["elements"]
    lines = []
    a = lines.append
    a("# Runtime Phase 23 — Renderer Vector Insertion & Interface Provenance\n")
    a("Primary direction: Draw consumer ← vector element ← insertion ← iface construction ← vtable ← methods.\n")
    a("## A. Vector insertion sites\n")
    a(f"- Count: **{ins['insert_site_count']}** (confidence **{ins['vector_insertion_confidence']}**)")
    a(f"- Strongest: **{ins['strongest_insert_site']}**")
    a(f"- Classic inlined `end+=8` push_back sites in ordinary .text: **{ins['classic_inlined_push_back_sites']}**")
    a(f"- Insert primitive `0x004A26B0`: body **{ins['insert_primitive']['body_class']}** (encrypted .text island)\n")
    for s in ins["insert_sites"]:
        a(f"### {s['id']} — `{s['function']}` ({s['classification']})")
        a(f"- Range: {s['instruction_range']}")
        a(f"- Renderer: {s['renderer_provenance']}")
        a(f"- +0x00: {s['element_plus0_source']}")
        a(f"- +0x04: {s['element_plus4_source']}")
        a(f"- ABI: `{s['stack_abi']}`\n")
    a("## B. Vector mutation routines\n")
    for m in ins["mutations"]:
        a(f"- `{m['function']}` — **{m['classification']}** — {m.get('note','')}")
    a("\n## C. Element +0x00\n")
    a(f"- Classification: **{el['+0x00']['classification']}** ({el['+0x00']['confidence']})")
    a(f"- Not a boolean for `0x0079E4A0` filters.")
    a(f"- Role subtype: {el['+0x00']['resolved_role']}\n")
    a("## D. Element +0x04\n")
    a(f"- **{el['+0x04']['classification']}** — {el['+0x04']['provenance']}\n")
    a("## E. Insertion callers\n")
    a("- Site A caller: `0x007B3F71` (renderer method path in `0x007B36A0` band)")
    a("- Site B: internal to `0x007AF900`\n")
    a("## F–H. Interface instances / constructors / lifecycle\n")
    c = iface["construction"]
    a(f"- Construction: **{c['classification']}** via `{c['ctor']}`")
    a(f"- Final vtable: `{c['final_vtable']}` (**{c['vtable_classification']}**)")
    a(f"- Allocation: {c['allocation']}")
    a(f"- Ownership: **{out['ownership']['model']}**\n")
    a("## I–J. Vtable publication\n")
    a(f"- Static table `{c['final_vtable']}` in `.rdata`")
    a(f"- Vtable pointer writes observed: {iface['vtable_pointer_write_count']}")
    a(f"- Classification: STATIC (not dynamic/import/protected table)\n")
    a("## K–M. Method slots / implementations / backend\n")
    for slot, m in iface["methods"].items():
        a(f"- `{slot}` `{m['label']}` → `{m['target']}` (**{m['classification']}**)")
        a(f"  - submit `0x7A51B0`: {m['calls_submit_0x7A51B0']} ({m['submit_entry_class']})")
        a(f"  - terminus: **{m['backend_terminus']}**")
    a(f"\nDeepest chain: `{out['deepest_ordinary_backend_chain']}`\n")
    a("## N. Raw-device relationship\n")
    a(f"- {out['raw_device_relationship']}")
    a(f"- Raw-device Draw: **NO**; ordinary D3D9 wrapper: **NO**\n")
    a("## O. Renderer ctor/dtor ownership\n")
    a(f"- Ctor vector: {out['ctor_vector']['vector_init']}")
    a(f"- Dtor vector: {out['dtor_vector']['vector_teardown']}\n")
    a("## P. `0x00686030`\n")
    a(f"- {out['helper_0x00686030']}\n")
    a("## Q. Allocation provenance\n")
    a(f"- {json.dumps(out['allocation'], indent=2)}\n")
    a("## R. angr consensus\n")
    a(f"- {out['consensus']}\n")
    a("## S. Interface graph v2\n")
    a("- Written to `analysis/undercover/renderer-interface-graph.json`\n")
    a("## T–V. Publication / boundary / seam\n")
    a(f"- INTERFACE_PUBLICATION: **{out['publication']}**")
    a(f"- GRAPHICS_BOUNDARY: **{out['graphics_boundary']}**")
    a(f"- POST_INIT_SEAM: **{out['seam']['classification']}**")
    a(f"- D3D9 justified: **{out['implementation']['D3D9_IMPLEMENTATION_JUSTIFIED']}**")
    a(f"- Engine backend adapter justified: **{out['implementation']['ENGINE_BACKEND_ADAPTER_JUSTIFIED']}**\n")
    a("## W. First-frame estimate\n")
    a(f"- BEST_CASE: **{out['first_frame']['BEST_CASE']}**")
    a(f"- LIKELY: **{out['first_frame']['LIKELY']}**\n")
    a("## X. Recommended Phase 24\n")
    a(out["recommended_phase24"])
    a("\n---\n")
    a(f"**{out['final_directive']}**\n")
    path = os.path.join(ANALYSIS, "runtime-phase23.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
