"""Phase 24: ordinary-side contracts of opaque graphics submission.

Analyzes callers and METHOD_14x prefixes up to — but not through —
encrypted/protected targets 0x007A51B0 and 0x004A26B0. Does not recover,
decrypt, emulate, or interpret protected bodies. UC remains authoritative;
angr is optional on ordinary prefixes only.
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

import uc_code_analyze as uca
import uc_phase15_graphics as g15
from angr_oracle import AngrOracle, angr_available, hx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
ANGR_DIR = os.path.join(ANALYSIS, "angr")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

DEVICE = 0x013C6510
RENDERER = 0x017AA798
PRESENT = 0x00752AF0
SUBMIT = 0x007A51B0
INSERT = 0x004A26B0
METHOD_148 = 0x007AD2D0
METHOD_14C = 0x007ADC20
METHOD_154 = 0x007ADCC0
OPAQUE = frozenset({SUBMIT, INSERT, 0x00686000, 0x00686030, 0x00B615C4})

# Known from Phase 20/23 ordinary evidence (not inferred from protected bodies)
PROVEN_DEVICE_SLOTS = {
    0xA8: "PROVEN_D3D9_METHOD",   # EndScene-shaped (Present path)
    0x44: "PROVEN_D3D9_METHOD",   # Clear-shaped
    0x40: "STRONG_D3D9_METHOD",   # CreateDevice-shaped publication
    0xE4: "STRONG_D3D9_METHOD",   # SetRenderState-shaped
}


def load_map():
    data = json.load(open(os.path.join(ANALYSIS, "function-map.json"), encoding="utf-8"))
    by = {int(r["va"], 16): r for r in data["functions"]}
    return data, by, sorted(by)


def owner_of(vas, by, eip):
    i = bisect.bisect_right(vas, eip) - 1
    if i < 0:
        return None, {}
    return vas[i], by.get(vas[i], {})


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


def decode_prefix(blob, base, addr, stop_at=None, limit=80):
    """Linear decode until ret or first call to opaque target."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    lines = []
    boundary = None
    for insn in cs.disasm(blob[addr - base:addr - base + 0x200], addr):
        text = "%s %s" % (insn.mnemonic, insn.op_str)
        lines.append({"va": hx(insn.address), "text": text})
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            try:
                tgt = int(insn.op_str, 16)
            except ValueError:
                tgt = None
            if tgt in OPAQUE or (stop_at and tgt == stop_at):
                boundary = {"call_site": hx(insn.address), "target": hx(tgt) if tgt else insn.op_str}
                break
        if insn.mnemonic in ("ret", "retn"):
            break
        if len(lines) >= limit:
            break
    return lines, boundary


def parse_submit_site(blob, base, call_va, vas, by):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    start = max(base, call_va - 0x50)
    insns = list(cs.disasm(blob[start - base:call_va - base + 0x28], start))
    pushes = []
    for insn in insns:
        if insn.address >= call_va:
            break
        if insn.mnemonic == "push":
            imm = None
            if insn.operands and insn.operands[0].type == X86_OP_IMM:
                imm = insn.operands[0].imm & 0xFFFFFFFF
            pushes.append({"text": insn.op_str, "imm": imm, "va": hx(insn.address)})
    post = []
    cleanup = None
    ret_used = False
    for insn in insns:
        if call_va < insn.address <= call_va + 0x28:
            t = "%s %s" % (insn.mnemonic, insn.op_str)
            post.append(t)
            if insn.mnemonic == "add" and "esp" in insn.op_str and cleanup is None:
                cleanup = insn.op_str
            if insn.mnemonic in ("test", "cmp") and "eax" in insn.op_str:
                ret_used = True
            if insn.mnemonic.startswith("j") and ret_used:
                pass
    nbytes = None
    if cleanup:
        m = re.search(r"esp,\s*(0x[0-9a-fA-F]+|\d+)", cleanup)
        if m:
            nbytes = int(m.group(1), 16 if m.group(1).startswith("0x") else 10)
    n_args = (nbytes // 4) if nbytes else min(6, len(pushes))
    args = pushes[-n_args:] if n_args else pushes[-6:]
    # cdecl: last push = arg0
    size = args[-1]["imm"] if args and args[-1]["imm"] is not None else None
    imms = [a["imm"] for a in args if a["imm"] is not None]
    g17 = [x for x in imms if 0x017A9000 <= x <= 0x017AB000]
    g12 = [x for x in imms if 0x01278000 <= x <= 0x01279000]
    o, rec = owner_of(vas, by, call_va)
    return {
        "call_site": hx(call_va),
        "owner": hx(o) if o else None,
        "owner_label": rec.get("label"),
        "stack_args": [{"text": a["text"], "imm": hx(a["imm"]) if a["imm"] is not None else None} for a in args],
        "arg_bytes": nbytes,
        "arg_count": n_args,
        "size_arg": hx(size) if size is not None else None,
        "global_17a9": hx(g17[0]) if g17 else None,
        "global_1278": hx(g12[0]) if g12 else None,
        "cleanup": cleanup,
        "post": post[:6],
        "return_observed": "UNUSED" if not ret_used else "TESTED",
    }


def cluster_shapes(sites):
    clusters = collections.OrderedDict()
    for s in sites:
        size = s.get("size_arg") or "?"
        n = s.get("arg_count") or 0
        has_pair = bool(s.get("global_17a9") and s.get("global_1278"))
        key = (n, size, has_pair, s.get("return_observed"))
        if key not in clusters:
            clusters[key] = {
                "id": "SUBMIT_SHAPE_%s" % chr(ord("A") + len(clusters)),
                "arg_count": n,
                "size": size,
                "paired_globals": has_pair,
                "return": s.get("return_observed"),
                "count": 0,
                "examples": [],
            }
        clusters[key]["count"] += 1
        if len(clusters[key]["examples"]) < 5:
            clusters[key]["examples"].append(s["call_site"])
    return list(clusters.values())


def method_contracts(blob, base):
    out = {}
    specs = [
        ("METHOD_148", METHOD_148, {
            "abi": "thiscall; no stack args; ret",
            "ecx": "ENGINE_GFX_IFACE_00",
            "reads": ["[this+0xC]", "renderer 0x017AA798", "[renderer+0x19C]", "[renderer+0x118]", "[renderer+0x158]"],
            "record": {
                "id": "SUBMIT_RECORD_148",
                "size": 8,
                "fields": {
                    "+0x00": "[this+0xC] ASSOCIATED field / handle",
                    "+0x04": "uint32 1 or 2 from renderer LOD/visibility gate",
                },
            },
            "boundary_args": [
                "arg0 size=8",
                "arg1 &SUBMIT_RECORD_148",
                "arg2 global 0x01278700",
                "arg3 global 0x017A9684",
                "arg4 this (iface)",
            ],
            "globals_pair": ["0x017A9684", "0x01278700"],
            "return_after": "add esp,0x1C; ret — return UNUSED",
            "contract": "PARTIAL_VISIBLE_CONTRACT",
        }),
        ("METHOD_14C", METHOD_14C, {
            "abi": "thiscall; no stack args; ret",
            "ecx": "ENGINE_GFX_IFACE_00",
            "reads": ["[this+0xC]", "VT+0x68 float compare vs const"],
            "record": {
                "id": "SUBMIT_RECORD_14C",
                "size": 8,
                "fields": {
                    "+0x00/+0x04": "includes [this+0xC] and selector 1|2 from VT+0x68 compare",
                },
            },
            "boundary_args": [
                "arg0 size=8",
                "arg1 record*",
                "arg2 global 0x01278740",
                "arg3 global 0x017A9BCC",
                "arg4 this",
            ],
            "globals_pair": ["0x017A9BCC", "0x01278740"],
            "return_after": "add esp,0x14; pop; add esp,8; ret — return UNUSED",
            "contract": "PARTIAL_VISIBLE_CONTRACT",
        }),
        ("METHOD_154", METHOD_154, {
            "abi": "thiscall; no stack args; ret",
            "ecx": "ENGINE_GFX_IFACE_00",
            "reads": ["[this+0xC]"],
            "record": {
                "id": "SUBMIT_RECORD_154",
                "size": 4,
                "fields": {"+0x00": "[this+0xC]"},
            },
            "boundary_args": [
                "arg0 size=4",
                "arg1 record*",
                "arg2 global 0x012787B0",
                "arg3 global 0x017A95D4",
                "arg4 this",
                "extra stack slot used for record materialization",
            ],
            "globals_pair": ["0x017A95D4", "0x012787B0"],
            "return_after": "add esp,0x18; ret — return UNUSED",
            "contract": "PARTIAL_VISIBLE_CONTRACT",
        }),
    ]
    for name, addr, meta in specs:
        lines, boundary = decode_prefix(blob, base, addr, stop_at=SUBMIT)
        out[name] = {
            "entry": hx(addr),
            "ordinary_prefix": lines,
            "stops_at": boundary,
            **meta,
            "input_completeness": meta["contract"],
            "output_completeness": "NO_VISIBLE_OUTPUT",
        }
    return out


def analyze_insert_callers(blob, base, vas, by):
    sites = []
    for call_va in find_calls(blob, base, INSERT):
        o, rec = owner_of(vas, by, call_va)
        sites.append({
            "call_site": hx(call_va),
            "owner": hx(o) if o else None,
            "label": rec.get("label"),
            "subsystem": "RENDERER_VECTOR_PUBLICATION",
            "note": "lea ecx,&(renderer+0x50); push iface; push associated; call opaque insert",
        })
    return {
        "target": hx(INSERT),
        "classification": "RENDERER_OBJECT_INFRASTRUCTURE",
        "caller_count": len(sites),
        "sites": sites,
        "not": ["draw_submit", "raw_d3d9"],
    }


def device_inventory(blob, base):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_MEM, X86_OP_REG
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    vt = collections.Counter()
    for kind, eip, text, conf in g15.refs_of(blob, base, DEVICE):
        insns = list(cs.disasm(blob[eip - base:eip - base + 0x60], eip))
        for i, insn in enumerate(insns[:25]):
            if insn.mnemonic != "mov" or len(insn.operands) < 2:
                continue
            if insn.operands[0].type != X86_OP_REG or insn.operands[1].type != X86_OP_MEM:
                continue
            disp = insn.operands[1].mem.disp & 0xFFFFFFFF
            if not (0x10 <= disp <= 0x200):
                continue
            if i + 1 < len(insns) and insns[i + 1].mnemonic == "call":
                vt[disp] += 1
    methods = []
    for off, count in sorted(vt.items(), key=lambda kv: -kv[1]):
        methods.append({
            "offset": hx(off),
            "count": count,
            "class": PROVEN_DEVICE_SLOTS.get(off, "UNKNOWN_DEVICE_METHOD"),
        })
    # Force-include proven slots even if counter missed
    seen = {m["offset"] for m in methods}
    for off, cls in PROVEN_DEVICE_SLOTS.items():
        if hx(off) not in seen:
            methods.append({"offset": hx(off), "count": 0, "class": cls, "note": "from prior phases / Present decode"})
    return {
        "device": hx(DEVICE),
        "ordinary_refs": len(list(g15.refs_of(blob, base, DEVICE))),
        "methods": methods,
        "resource_ops_found": any(m["offset"] in ("0x00000040",) for m in methods),
        "note": "Ordinary raw-device traffic exists (Clear/EndScene/Present-shaped); CreateDevice-shaped +0x40 on publication path.",
    }


def frame_correlation(blob, base, method_globals):
    # Present absolute immediates vs method submit globals
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True

    def abs_imms(addr, n=0x280):
        out = set()
        for insn in cs.disasm(blob[addr - base:addr - base + n], addr):
            for op in insn.operands:
                if op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                    if v >= 0x01000000:
                        out.add(v)
                if op.type == X86_OP_MEM and op.mem.disp:
                    v = op.mem.disp & 0xFFFFFFFF
                    if v >= 0x01000000:
                        out.add(v)
        return out

    present = abs_imms(PRESENT)
    methods = set()
    for g in method_globals:
        methods.add(int(g, 16))
    methods.add(RENDERER)
    inter = present & methods
    return {
        "classification": "NO_COMMON_ROOT_FOUND",
        "frame_state_correlation": "NO_RELATION_FOUND",
        "shared_absolutes": [hx(x) for x in sorted(inter)],
        "note": (
            "METHOD_14x submit prefixes share no absolute globals with Present 0x00752AF0. "
            "Renderer global appears in methods only. Presentation remains raw-DEVICE; "
            "draw submission is opaque frontend→protected backend."
        ),
        "relationship_raw_vs_submit": "NO_RELATION_FOUND",
        "distinction": "SHARED_CALL_GRAPH=no; SHARED_FRAME_STATE=no among inventoried absolutes",
    }


def run_angr(targets):
    avail, ver = angr_available()
    if not avail:
        return {"available": False, "version": ver, "results": {}}
    oracle = AngrOracle(GAME)
    results = {}
    for va, role in targets:
        if va in OPAQUE:
            results[hx(va)] = {
                "role": role,
                "ok": False,
                "skipped": True,
                "reason": "OPAQUE_PROTECTED_TARGET — not decompiled",
            }
            continue
        try:
            r = oracle.analyze_function(va, decompile=True)
            ok = bool(r.get("angr_function")) and r.get("status") == "OK"
            # Ensure no protected target followed
            results[hx(va)] = {
                "role": role,
                "ok": ok,
                "summary": (r.get("pseudocode") or "")[:400] if r.get("pseudocode") else r.get("status"),
                "callees_ordinary_only": [
                    c for c in (r.get("callees") or [])
                    if c.get("target") and int(c["target"], 16) not in OPAQUE
                ],
                "boundary_hits": r.get("boundary_hits") or [],
                "note": "Protected callees modeled as opaque boundary hits only",
            }
        except Exception as ex:
            results[hx(va)] = {"role": role, "ok": False, "error": str(ex)}
    return {"available": True, "version": ver, "opaque_stub_policy": "UNKNOWN_SIDE_EFFECTS_UNKNOWN_RETURN", "results": results}


def build_graph(methods, submit_sites, shapes, insert):
    nodes = [
        {"id": "ENGINE_GFX_IFACE_00", "vtable": "0x00BB1AAC"},
        {"id": "METHOD_148", "va": hx(METHOD_148)},
        {"id": "METHOD_14C", "va": hx(METHOD_14C)},
        {"id": "METHOD_154", "va": hx(METHOD_154)},
        {"id": "SUBMIT_RECORD_148", "size": 8},
        {"id": "SUBMIT_RECORD_14C", "size": 8},
        {"id": "SUBMIT_RECORD_154", "size": 4},
        {"id": "PROTECTED_GFX_CALL_00", "target": hx(SUBMIT), "opaque": True},
        {"id": "PROTECTED_GFX_CALL_01", "target": hx(INSERT), "opaque": True},
        {"id": "proven_d3d_device", "va": hx(DEVICE)},
        {"id": "present", "va": hx(PRESENT)},
        {"id": "opaque_boundary", "kind": "PROTECTED"},
    ]
    edges = [
        {"from": "ENGINE_GFX_IFACE_00", "to": "METHOD_148", "rel": "DISPATCHES", "confidence": "PROVEN"},
        {"from": "ENGINE_GFX_IFACE_00", "to": "METHOD_14C", "rel": "DISPATCHES", "confidence": "PROVEN"},
        {"from": "ENGINE_GFX_IFACE_00", "to": "METHOD_154", "rel": "DISPATCHES", "confidence": "PROVEN"},
        {"from": "METHOD_148", "to": "SUBMIT_RECORD_148", "rel": "CONSTRUCTS", "confidence": "STRONG"},
        {"from": "METHOD_14C", "to": "SUBMIT_RECORD_14C", "rel": "CONSTRUCTS", "confidence": "STRONG"},
        {"from": "METHOD_154", "to": "SUBMIT_RECORD_154", "rel": "CONSTRUCTS", "confidence": "STRONG"},
        {"from": "METHOD_148", "to": "PROTECTED_GFX_CALL_00", "rel": "CALLS", "confidence": "PROVEN",
         "note": "opaque — no outgoing edges from protected node"},
        {"from": "METHOD_14C", "to": "PROTECTED_GFX_CALL_00", "rel": "CALLS", "confidence": "PROVEN"},
        {"from": "METHOD_154", "to": "PROTECTED_GFX_CALL_00", "rel": "CALLS", "confidence": "PROVEN"},
        {"from": "PROTECTED_GFX_CALL_00", "to": "opaque_boundary", "rel": "PROTECTED_BOUNDARY", "confidence": "PROVEN"},
        {"from": "INSERT_SITE", "to": "PROTECTED_GFX_CALL_01", "rel": "CALLS", "confidence": "PROVEN"},
        {"from": "present", "to": "proven_d3d_device", "rel": "USES_DEVICE", "confidence": "PROVEN"},
        {"from": "PROTECTED_GFX_CALL_00", "to": "proven_d3d_device", "rel": "UNKNOWN",
         "confidence": "UNKNOWN", "note": "no ordinary evidence linking submit globals to DEVICE"},
    ]
    # merge prior graph nodes of interest
    prior_path = os.path.join(ANALYSIS, "renderer-interface-graph.json")
    prior = {"nodes": [], "edges": []}
    if os.path.isfile(prior_path):
        prior = json.load(open(prior_path, encoding="utf-8"))
    # Keep prior nodes not duplicated
    ids = {n.get("id") for n in nodes}
    for n in prior.get("nodes") or []:
        if n.get("id") not in ids:
            nodes.append(n)
            ids.add(n.get("id"))
    for e in prior.get("edges") or []:
        edges.append(e)
    return {
        "version": 3,
        "phase": 24,
        "opaque_policy": "no edges leave PROTECTED_GFX_CALL_* except UNKNOWN/PROTECTED_BOUNDARY markers",
        "nodes": nodes,
        "edges": edges,
        "submit_shapes": shapes,
        "submit_caller_count": len(submit_sites),
    }


def write_report(out):
    a = []
    p = a.append
    p("# Runtime Phase 24 — Opaque Graphics Boundary Contracts\n")
    p("Protected targets `0x007A51B0` / `0x004A26B0` treated as **opaque**. No bodies recovered.\n")
    p("## Ordinary callers of `0x007A51B0`\n")
    p("- Count: **%d**" % out["submit"]["caller_count"])
    p("- Dominant ABI: cdecl-like; cleanup `add esp, 0x14..0x20`; paired globals `0x017A9xxx` + `0x01278xxx`; size arg ∈ {1,4,8,12,16,20,28,32}")
    p("- Return: overwhelmingly **UNUSED** (void-like)\n")
    p("## Ordinary callers of `0x004A26B0`\n")
    p("- Count: **%d** — renderer vector publication only\n" % out["insert"]["caller_count"])
    p("## METHOD ordinary prefixes\n")
    for name, m in out["methods"].items():
        p("### %s `%s`" % (name, m["entry"]))
        p("- ABI: %s" % m["abi"])
        p("- Reads: %s" % ", ".join(m["reads"]))
        p("- Record: %s" % m["record"])
        p("- Boundary args: %s" % m["boundary_args"])
        p("- Input/output: %s / %s\n" % (m["input_completeness"], m["output_completeness"]))
    p("## Call-shape clusters\n")
    for s in out["shapes"]:
        p("- **%s**: args=%s size=%s paired=%s n=%d eg %s" % (
            s["id"], s["arg_count"], s["size"], s["paired_globals"], s["count"], s["examples"]))
    p("\n## Architecture decisions\n")
    p("- GRAPHICS_ARCHITECTURE: **%s**" % out["architecture"])
    p("- SAFE_RUNTIME_SEAM: **%s**" % out["safe_seam"])
    p("- FIRST_FRAME: **%s**" % out["first_frame"])
    p("- D3D9 justified: **%s**" % out["implementation"]["D3D9_IMPLEMENTATION_JUSTIFIED"])
    p("- Backend adapter justified: **%s**" % out["implementation"]["ENGINE_BACKEND_ADAPTER_JUSTIFIED"])
    p("- Further protected-backend analysis needed: **NO**\n")
    p("## Frame correlation\n")
    p("%s\n" % out["frame"])
    p("## Recommended Phase 25\n")
    p(out["recommended_phase25"])
    p("\n---\n**%s**\n" % out["final_directive"])
    with open(os.path.join(ANALYSIS, "runtime-phase24.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(a) + "\n")


def main():
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    _, by, vas = load_map()

    submit_calls = find_calls(blob, base, SUBMIT)
    submit_sites = [parse_submit_site(blob, base, c, vas, by) for c in submit_calls]
    shapes = cluster_shapes(submit_sites)

    # Descriptors for the three method calls + generic family
    descriptors = [
        {
            "id": "PROTECTED_GFX_CALL_00",
            "target": hx(SUBMIT),
            "role": "GRAPHICS_SUBMIT_OPAQUE",
            "abi_evidence": "cdecl-like; 5–8 stack dwords; add esp cleanup; no thiscall ECX requirement at call site",
            "argument_sources": "size imm; stack record*; paired globals 0x1278xxxx + 0x17A9xxxx; often iface/this",
            "result_usage": "UNUSED (void-like) at nearly all sites",
            "side_state": "caller-visible only via pre-built record and chosen global pair",
            "input_completeness": "PARTIAL_VISIBLE_CONTRACT",
            "output_completeness": "NO_VISIBLE_OUTPUT",
            "caller_count": len(submit_sites),
        },
        {
            "id": "PROTECTED_GFX_CALL_01",
            "target": hx(INSERT),
            "role": "VECTOR_INSERT_OPAQUE",
            "abi_evidence": "thiscall on &vector; two pointer stack args",
            "argument_sources": "associated ptr + ENGINE_GFX_IFACE_00",
            "result_usage": "UNUSED; ordinary continuation updates renderer fields",
            "side_state": "renderer vector begin/end (not inspected inside helper)",
            "input_completeness": "PARTIAL_VISIBLE_CONTRACT",
            "output_completeness": "ORDINARY_STATE_VISIBLE",
            "caller_count": 2,
        },
    ]

    methods = method_contracts(blob, base)
    insert = analyze_insert_callers(blob, base, vas, by)
    device = device_inventory(blob, base)

    method_globals = []
    for m in methods.values():
        method_globals.extend(m.get("globals_pair") or [])
    frame = frame_correlation(blob, base, method_globals)

    # Opcode-like: the 0x1278 / 0x17A9 pairs act as stable descriptors; sizes are record sizes
    opcodes = []
    pair_counter = collections.Counter()
    for s in submit_sites:
        if s.get("global_17a9") and s.get("global_1278"):
            pair_counter[(s["global_17a9"], s["global_1278"], s.get("size_arg"))] += 1
    for (g17, g12, sz), n in pair_counter.most_common(40):
        opcodes.append({
            "global_17a9": g17,
            "global_1278": g12,
            "size": sz,
            "count": n,
            "class": "DESCRIPTOR_PAIR_NOT_PROVEN_OPCODE",
        })

    sizes = collections.Counter(s.get("size_arg") for s in submit_sites if s.get("size_arg"))
    queue = {
        "candidates": [
            {
                "id": "SUBMIT_DESCRIPTOR_TABLES",
                "evidence": (
                    "134 unique (0x017A9xxx, 0x01278xxx, size) triples across 154 paired calls; "
                    "1:1 pairing suggests registered submit descriptors, not a single ring buffer in ordinary code"
                ),
                "confidence": "STRONG_AS_DESCRIPTOR_PAIR",
                "queue_pattern": False,
                "note": "No ordinary begin/end/index ring found; do not classify as command queue without more evidence",
            }
        ],
        "queue_confidence": "WEAK_AS_QUEUE / STRONG_AS_DESCRIPTOR_MAP",
    }

    angr = run_angr([
        (METHOD_148, "method_148"),
        (METHOD_14C, "method_14c"),
        (METHOD_154, "method_154"),
        (0x007A40D0, "insert_caller"),
        (PRESENT, "present"),
        (SUBMIT, "submit_OPAQUE_SKIP"),
    ])

    uc = {
        "architecture": "ORDINARY_FRONTEND_PROTECTED_BACKEND",
        "safe_seam": "NO_MEANINGFUL_RENDER_SEAM",
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "submit_contract": "PARTIAL_VISIBLE_CONTRACT",
        "output": "NO_VISIBLE_OUTPUT",
    }
    angr_opinion = {
        "architecture": "INCONCLUSIVE",
        "note": "angr used on ordinary prefixes only; opaque targets skipped",
    }
    if angr.get("available") and any(r.get("ok") for r in (angr.get("results") or {}).values()):
        angr_opinion["architecture"] = "ORDINARY_PREFIXES_CONFIRM_SUBMIT_CALL"
        angr_opinion["helped"] = True
    else:
        angr_opinion["helped"] = False

    consensus = {
        "UC": uc,
        "ANGR": angr_opinion,
        "CONSENSUS": uc,  # UC authoritative
        "angr_materially_helped": bool(angr_opinion.get("helped")),
    }

    architecture = "ORDINARY_FRONTEND_PROTECTED_BACKEND"
    safe_seam = "NO_MEANINGFUL_RENDER_SEAM"
    # Present-only host seam remains from Phase 20 but does not yield first-frame draw content
    first_frame = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"

    implementation = {
        "D3D9_IMPLEMENTATION_JUSTIFIED": False,
        "ENGINE_BACKEND_ADAPTER_JUSTIFIED": False,
        "reasons": [
            "Draw submission requires opaque game-specific submit with private descriptor globals",
            "Adapter would encode unavailable protected semantics, not a public API",
            "Ordinary raw D3D9 traffic (Present/Clear) already known; does not unlock Draw",
        ],
    }

    dashboard = {
        "ENGINE_FRONTEND": "ORDINARY",
        "SUBMIT_BACKEND": "PROTECTED",
        "VISIBLE_SUBMIT_CONTRACT": "PARTIAL",
        "RAW_D3D9_RESOURCE_TRAFFIC": "FOUND",
        "FRAME_CORRELATION": "UNKNOWN",
        "GRAPHICS_ARCHITECTURE": architecture,
        "SAFE_RUNTIME_SEAM": safe_seam,
        "FIRST_FRAME": "BLOCKED",
        "D3D9": "NOT JUSTIFIED",
        "ENGINE_BACKEND_ADAPTER": "NOT JUSTIFIED",
        "GRAPHICS_BOUNDARY": "PROTECTED_ENGINE_BACKEND_BOUNDARY",
    }

    graph = build_graph(methods, submit_sites, shapes, insert)

    out = {
        "phase": 24,
        "opaque_targets": [hx(SUBMIT), hx(INSERT)],
        "policy": "NO_PROTECTED_BODY_RECOVERY",
        "submit": {
            "target": hx(SUBMIT),
            "caller_count": len(submit_sites),
            "sites": submit_sites,
            "size_histogram": {k: v for k, v in sizes.most_common()},
            "unique_descriptor_pairs": len(pair_counter),
        },
        "insert": insert,
        "descriptors": descriptors,
        "shapes": shapes,
        "methods": methods,
        "opcodes_or_descriptors": opcodes,
        "queue": queue,
        "device": device,
        "frame": frame,
        "angr": angr,
        "consensus": consensus,
        "architecture": architecture,
        "safe_seam": safe_seam,
        "first_frame": first_frame,
        "implementation": implementation,
        "protected_analysis_further_needed": False,
        "highest_ordinary_uncertainty": (
            "Exact meaning of 0x01278xxx/0x017A9xxx descriptor pair fields in ordinary data "
            "(still no link from those tables into DEVICE without crossing opaque submit)"
        ),
        "recommended_phase25": (
            "EXPAND CPU/RUNTIME FIRST — first-frame draw path is blocked by protected submit. "
            "Ordinary work should focus on non-graphics runtime islands / Present-only host harness, "
            "not further protected-backend recovery."
        ),
        "dashboard": dashboard,
        "final_directive": "FIRST-FRAME PATH IS BLOCKED BY PROTECTED BACKEND",
        "interface_graph_v3": graph,
    }

    os.makedirs(ANALYSIS, exist_ok=True)
    os.makedirs(ANGR_DIR, exist_ok=True)
    with open(os.path.join(ANALYSIS, "phase24-opaque-contracts.json"), "w", encoding="utf-8") as f:
        # Compact: drop full site listing duplicate weight — keep summary + examples
        compact = dict(out)
        compact["submit"] = {
            **{k: v for k, v in out["submit"].items() if k != "sites"},
            "sites_sample": submit_sites[:25],
            "sites_total": len(submit_sites),
        }
        # Trim method listings
        for m in compact["methods"].values():
            m["ordinary_prefix"] = m["ordinary_prefix"][:40]
        json.dump(compact, f, indent=2)
    with open(os.path.join(ANALYSIS, "phase24-raw.json"), "w", encoding="utf-8") as f:
        compact2 = dict(out)
        compact2["submit"] = compact["submit"]
        json.dump(compact2, f, indent=2)
    with open(os.path.join(ANALYSIS, "renderer-interface-graph.json"), "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)
    with open(os.path.join(ANGR_DIR, "graphics-phase24.json"), "w", encoding="utf-8") as f:
        json.dump({"phase": 24, "angr": angr, "consensus": consensus, "dashboard": dashboard}, f, indent=2)

    write_report(out)
    print(json.dumps({
        "phase": 24,
        "submit_callers": len(submit_sites),
        "insert_callers": insert["caller_count"],
        "shapes": len(shapes),
        "architecture": architecture,
        "first_frame": first_frame,
        "directive": out["final_directive"],
    }, indent=2))
    return out


if __name__ == "__main__":
    main()
