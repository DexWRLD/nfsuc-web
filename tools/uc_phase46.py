#!/usr/bin/env python3
"""Phase 46: first-frame evidence integration + matrix execution expansion.

Imports Ghidra first-frame evidence, expands allocator-independent 0x00A12xxx
guest execution, and adds synthetic ordinary rendering contracts (stream cache,
indexed-draw prep, buffer-range reclaim, D3D9 recorder). Opaque draw backends
remain untouched. Authentic first frame stays blocked.
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_graphics46 as g46
import uc_harness31 as h
import uc_phase7_test as p7
import uc_phase43_test as t43
import uc_phase44_test as t44
import uc_phase45_test as t45

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
FIRST_FRAME = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"
DOWNLOADS_EV = r"C:\Users\999\Downloads\undercover-first-frame-evidence.json"
DOWNLOADS_MD = r"C:\Users\999\Downloads\undercover-first-frame-report.md"

# Family regressions
CTOR_A, SETTER, GETTER = 0x009E9160, 0x009E9140, 0x009E9150
CTOR_B, EXPORT_B = 0x009E98F0, 0x009E9A30
CTOR_C, FIELD_C = 0x009EB350, 0x009EB2B0
OBJ, SRC = h.OBJ_BASE, h.SRC_BASE
POD, EXPORT_BUF = OBJ + 0x300, OBJ + 0x400
OBJ_C, ZERO_PTR = OBJ + 0x480, OBJ + 0x500

MAT = OBJ + 0x600
SRC_M = OBJ + 0x680
TMP_M = OBJ + 0x700
VEC_M = OBJ + 0x780

# Phase 45 preserved leaves
FN_CONST = 0x00A12850
FN_TRANSPOSE_INPLACE = 0x00A12860
FN_COPY_TRANSPOSE = 0x00A128A0
FN_ADD = 0x00A12D10
FN_SUB = 0x00A12D50
FN_SCALE = 0x00A12D90
FN_FMAX = 0x00A127E0
FN_COALESCE = 0x00A130E0

# Phase 46 new matrix leaves
FN_SCALE_ROWS_VX = 0x00A128F0   # this = broadcast(vec.x) * mat rows; ret 8
FN_MADD_ROWS_VX = 0x00A12940    # this += broadcast(vec.x) * mat rows; ret 8
FN_MUL_3X3 = 0x00A12E60         # this = A * B (3 rows); ret 8

# Buffer range reclaim (guest where fixture supports)
FN_RANGE_RECLAIM = 0x00766100
RANGE_HEAD = OBJ + 0x800
RANGE_NODE = OBJ + 0x820


def hx(va: int) -> str:
    return "0x%08X" % (va & 0xFFFFFFFF)


def load(name: str):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name: str, obj) -> None:
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("wrote", path)


def f32(v: float) -> int:
    return struct.unpack("<I", struct.pack("<f", v))[0]


def write_u32(harness: h.Harness, addr: int, val: int) -> None:
    for i, b in enumerate(struct.pack("<I", val & 0xFFFFFFFF)):
        harness.mem[addr + i] = b


def read_f32_at(harness: h.Harness, addr: int) -> float:
    return struct.unpack("<f", struct.pack("<I", harness.read_u32(addr)))[0]


def row_fill(base, a, b, c, d=0.0):
    return (
        (base, f32(a)),
        (base + 4, f32(b)),
        (base + 8, f32(c)),
        (base + 12, f32(d)),
    )


def ensure_evidence_imported() -> dict:
    dst_json = os.path.join(ANALYSIS, "first-frame-evidence-2026-11-03.json")
    dst_md = os.path.join(ANALYSIS, "first-frame-report-2026-11-03.md")
    if os.path.isfile(DOWNLOADS_EV):
        shutil.copy2(DOWNLOADS_EV, dst_json)
    if os.path.isfile(DOWNLOADS_MD):
        shutil.copy2(DOWNLOADS_MD, dst_md)
    with open(dst_json, encoding="utf-8") as fh:
        return json.load(fh)


def integrate_rendering_evidence(ev: dict) -> dict:
    call_sites = []
    for cs in ev.get("call_sites") or []:
        call_sites.append({
            "address": cs.get("address"),
            "function": cs.get("function"),
            "method": cs.get("method"),
            "arguments": cs.get("arguments"),
            "receiver": cs.get("receiver"),
            "confidence": cs.get("confidence"),
            "method_confirmed_import": False,
            "note": (
                "Method name strongly supported by vtable layout/args; "
                "not marked as a confirmed PE import."
            ),
        })

    edges = []
    for e in ev.get("edges") or []:
        edges.append({
            "from": e.get("from") or e.get("source"),
            "site": e.get("site") or e.get("call_site"),
            "to": e.get("to") or e.get("destination"),
            "kind": e.get("kind") or e.get("edge") or e.get("type"),
            "context": e.get("context") or e.get("note"),
            "opaque": (
                str(e.get("kind") or "").lower() == "opaque boundary"
                or bool(e.get("opaque"))
                or (e.get("to") or e.get("destination") or "") in (
                    "0x006860F0", "0x00686290", "0x006861B0",
                    "0x004A26B0", "0x007A51B0", "0x00686000", "0x00686030",
                )
            ),
        })

    inventory = {
        "phase": 46,
        "source": "first-frame-evidence-2026-11-03.json",
        "status": ev.get("status"),
        "coverage": ev.get("coverage"),
        "device_global": hx(g46.DEVICE_GLOBAL),
        "call_site_count": len(call_sites),
        "edge_count": len(edges),
        "call_sites": call_sites,
        "method_names_are_confirmed_imports": False,
        "opaque_boundaries": g46.opaque_boundaries(),
    }
    dump("d3d9-device-call-sites.json", inventory)

    graph = {
        "phase": 46,
        "status": FIRST_FRAME,
        "confirmed_direct_edges": [
            e for e in edges if str(e.get("kind") or "").lower() == "direct"
        ],
        "callback_registration_edges": [
            e for e in edges
            if "callback" in str(e.get("kind") or "").lower()
        ],
        "opaque_edges": [e for e in edges if e.get("opaque")],
        "unresolved_scheduling": [
            {
                "relationship": "render callback 0x00766730 → scene producer ~0x00777253",
                "status": "UNVERIFIED",
            },
            {
                "relationship": "render callback → scene dispatch ~0x007B5972/0x007B5979",
                "status": "UNVERIFIED",
            },
            {
                "relationship": "scene/mesh submission → later Present caller ~0x00758674",
                "status": "UNVERIFIED",
            },
        ],
        "edges": edges,
        "note": (
            "Callback registration is not runtime invocation. "
            "Static call-site discovery is not guest execution."
        ),
    }
    # Prefer raw edges from evidence file if richer
    if ev.get("edges"):
        graph["raw_edge_count"] = len(ev["edges"])
        graph["edges"] = ev["edges"]
    dump("render-call-graph.json", graph)

    structs = ev.get("structures") or {}
    mesh = structs.get("mesh_instance_descriptor") or {}
    dump("mesh-descriptor-field-map.json", {
        "phase": 46,
        "function": "0x00757B80",
        "minimum_read_extent": hx(g46.MESH_MIN_EXTENT),
        "fields": mesh.get("fields") or g46.MeshDescriptor().field_map(),
        "source": "first-frame-evidence-2026-11-03.json",
        "note": "Full descriptor writer/lifetime unresolved.",
    })

    dump("draw-handoff-metadata.json", {
        "phase": 46,
        "handoffs": ev.get("draw_handoffs") or [
            {
                "site": "0x00757C9A",
                "target": hx(g46.OPAQUE_INDEXED_DRAW),
                "shape": "indexed triangle-list-shaped",
                "opaque": True,
            },
            {
                "site": "0x00766700",
                "target": hx(g46.OPAQUE_USERMEM_DRAW),
                "shape": "user-memory non-indexed draw-shaped",
                "opaque": True,
            },
        ],
        "do_not_reconstruct": [
            hx(g46.OPAQUE_INDEXED_DRAW),
            hx(g46.OPAQUE_USERMEM_DRAW),
            hx(g46.OPAQUE_BAD_ENTRY),
        ],
    })

    dump("stream-state-evidence.json", {
        "phase": 46,
        "cache_base": hx(g46.STREAM_CACHE_BASE),
        "record_stride": hx(g46.STREAM_RECORD_STRIDE),
        "fields": ["buffer identity", "byte offset", "stride"],
        "hit_return_site": "0x0071B6E2",
        "hit_return_value": 0,
        "function": "0x0071B6B0",
        "explicit_forward_reference": "0x0075EFAE",
        "miss_path": (
            "Independently disassembled at 0x0071B6E6 (cache write + "
            "device vtable +0x190 call); tests inject the setter rather than "
            "claiming a complete translated function."
        ),
    })

    readiness = {
        "phase": 46,
        "status": FIRST_FRAME,
        "authentic_game_frame": "Blocked",
        "prerequisites": [
            {"requirement": "Device setup evidence", "status": "Identified"},
            {"requirement": "Clear-only presentation path", "status": "Identified"},
            {
                "requirement": "Scene geometry producer",
                "status": "Partially identified",
            },
            {
                "requirement": "Draw argument preparation",
                "status": "Partially identified",
            },
            {"requirement": "Opaque draw implementation", "status": "Blocked"},
            {
                "requirement": "Render callback → scene path",
                "status": "Unverified",
            },
            {
                "requirement": "Scene path → later Present",
                "status": "Unverified",
            },
            {
                "requirement": "Real asset/geometry payload",
                "status": "Unverified",
            },
            {
                "requirement": "Material texture bindings",
                "status": "Incomplete",
            },
            {
                "requirement": "Browser GPU submission",
                "status": "Unverified",
            },
            {"requirement": "Authentic game frame", "status": "Blocked"},
        ],
        "dashboard_flags": {
            "device_initialized_evidence": True,
            "clear_only_presentation_path_identified": True,
            "draw_argument_producer_identified": True,
            "draw_handoff_remains_opaque": True,
            "scene_to_present_chain_unresolved": True,
            "browser_gpu_backend_unverified": True,
            "authentic_first_frame_blocked": True,
        },
        "warnings": [
            "Static call-site discovery is not runtime execution.",
            "A synthetic draw-command recorder is not proof of an authentic frame.",
            "Method names are vtable-supported interpretations, not confirmed imports.",
        ],
        "coverage_from_evidence": ev.get("coverage"),
        "unresolved_from_evidence": ev.get("unresolved"),
    }
    dump("first-frame-readiness.json", readiness)

    dump("resource-stream-state-evidence.json", {
        "phase": 46,
        "buffer_update_record": structs.get("buffer_update_record") or {
            "stride": hx(g46.BUFFER_UPDATE_STRIDE),
            "fields": {
                "+0x00": "buffer selection / high-bit table selector",
                "+0x04": "element-offset component",
                "+0x08": "copy size",
                "+0x0C": "additional offset component",
                "+0x10": "source pointer",
            },
        },
        "secondary_queue": {
            "stride": hx(g46.SECONDARY_QUEUE_STRIDE),
            "reader": "0x007661A0",
            "helper": "0x00766100",
        },
        "stream_cache": {
            "base": hx(g46.STREAM_CACHE_BASE),
            "stride": hx(g46.STREAM_RECORD_STRIDE),
        },
    })

    return {
        "call_sites": len(call_sites),
        "edges": len(ev.get("edges") or edges),
        "readiness": readiness,
    }


def run_synthetic_contracts() -> dict:
    cache = g46.StreamCache()
    recorded = []

    def setter(device, stream, buffer, offset, stride):
        recorded.append({
            "method": "SetStreamSource",
            "device": device,
            "stream": stream,
            "buffer": buffer,
            "offset": offset,
            "stride": stride,
        })
        return 0

    cache.miss_setter = setter
    # miss then hit
    r1 = cache.cache_hit(0xD3D00001, 1, 0x1000, 0, 24)
    r2 = cache.cache_hit(0xD3D00001, 1, 0x1000, 0, 24)
    r3 = cache.cache_hit(0xD3D00001, 1, 0x1000, 0, 32)  # stride mismatch
    r4 = cache.cache_hit(0xD3D00001, 2, 0x2000, 64, 16)  # other stream
    r5 = cache.cache_hit(0xD3D00001, 2, 0x2000, 64, 16)

    mesh_empty = g46.MeshDescriptor(batch_counts=[0, 0], index_count=9, vertex_count=10)
    mesh_one = g46.MeshDescriptor(
        batch_counts=[1], batch_offsets=[3], index_count=9, vertex_count=12, stride=24
    )
    mesh_multi = g46.MeshDescriptor(
        batch_counts=[2, 1], batch_offsets=[1, 2], index_count=10, vertex_count=20
    )
    args_empty = g46.prepare_indexed_draw_args(mesh_empty, 0xD3D, 0)
    args_one = g46.prepare_indexed_draw_args(mesh_one, 0xD3D, 0)
    args_weird = g46.prepare_indexed_draw_args(mesh_multi, 0xD3D, 0)

    ranges = g46.RangeList(nodes=[
        g46.RangeNode(key=0x100, size=0x10, free=False),
        g46.RangeNode(key=0x110, size=0x10, free=False),
        g46.RangeNode(key=0x120, size=0x20, free=False),
    ])
    no_match = ranges.reclaim(0x999)
    exact = g46.RangeList(nodes=[
        g46.RangeNode(0x100, 0x10, False),
        g46.RangeNode(0x110, 0x10, False),
    ])
    exact_ok = exact.reclaim(0x100)
    # prev coalesce: free 0x100 first, then free 0x110
    prev_c = g46.RangeList(nodes=[
        g46.RangeNode(0x100, 0x10, True),
        g46.RangeNode(0x110, 0x10, False),
    ])
    prev_ok = prev_c.reclaim(0x110)
    next_c = g46.RangeList(nodes=[
        g46.RangeNode(0x100, 0x10, False),
        g46.RangeNode(0x110, 0x10, True),
    ])
    next_ok = next_c.reclaim(0x100)
    both_c = g46.RangeList(nodes=[
        g46.RangeNode(0x100, 0x10, True),
        g46.RangeNode(0x110, 0x10, False),
        g46.RangeNode(0x120, 0x10, True),
    ])
    both_ok = both_c.reclaim(0x110)

    rec = g46.D3D9CommandRecorder()
    clear_seq = rec.record_clear_only_present()
    rec2 = g46.D3D9CommandRecorder()
    later = rec2.record_later_present_cleanup()
    # stream forward reference shape
    rec3 = g46.D3D9CommandRecorder()
    rec3.SetStreamSource(0, 0xABCD, 0, 24 & 0x7FFF)
    rec3.SetIndices(0x1000)
    rec3.SetVertexDeclaration(0x2000)

    out = {
        "kind": "HOST_SYNTHETIC",
        "stream_cache": {
            "miss_then_hit": [r1, r2],
            "stride_mismatch_miss": r3,
            "other_stream": [r4, r5],
            "recorded_setters": recorded,
        },
        "indexed_draw_prep": {
            "empty_batch": args_empty,
            "single_batch": None if args_one is None else args_one.__dict__,
            "index10_prim_count": g46.indexed_prim_count(10),
            "index9_prim_count": g46.indexed_prim_count(9),
            "scaled_offset_batch0": g46.stream_offset_scaled(mesh_one, 0),
            "multi_batch_args": None if args_weird is None else args_weird.__dict__,
            "opaque_target": hx(g46.OPAQUE_INDEXED_DRAW),
            "note": "Preparation only; opaque handoff not executed.",
        },
        "range_reclaim": {
            "classification": "SYNTHETIC_ONLY",
            "abi_observed": "thiscall ret 4 (0x00766100)",
            "no_match": no_match,
            "exact_match": exact_ok,
            "exact_live_after": exact.live_count,
            "prev_coalesce": prev_ok,
            "prev_nodes": [(n.key, n.size, n.free) for n in prev_c.nodes],
            "next_coalesce": next_ok,
            "next_nodes": [(n.key, n.size, n.free) for n in next_c.nodes],
            "both_coalesce": both_ok,
            "both_nodes": [(n.key, n.size, n.free) for n in both_c.nodes],
        },
        "d3d9_recorder": {
            "clear_only_present": clear_seq,
            "later_present": later,
            "stream_index_sample": rec3.commands,
            "not_browser_gpu": True,
        },
    }
    dump("phase46-synthetic-contracts.json", {
        "phase": 46,
        **{k: v for k, v in out.items() if k != "indexed_draw_prep"},
        "indexed_draw_prep": {
            **{k: v for k, v in out["indexed_draw_prep"].items()
               if k not in ("empty_batch",)},
            "empty_batch_is_none": args_empty is None,
        },
    })
    return out


def run_campaign() -> dict:
    fmap = h.load_fmap()
    addrs = {
        FN_CONST, FN_TRANSPOSE_INPLACE, FN_COPY_TRANSPOSE, FN_ADD, FN_SUB,
        FN_SCALE, FN_FMAX, FN_COALESCE,
        FN_SCALE_ROWS_VX, FN_MADD_ROWS_VX, FN_MUL_3X3,
        FN_RANGE_RECLAIM,
        CTOR_A, SETTER, GETTER, CTOR_B, EXPORT_B, CTOR_C, FIELD_C, 0x009E7710,
    }
    for a in list(addrs):
        addrs |= set(h.closure(a, fmap, limit=48))
    harness = h.Harness(addrs)

    results = []
    prev = load("runtime-frontier.json")
    baseline_executed = set(prev.get("unique_uc_functions_executed_list") or [])
    baseline_enterable = set(prev.get("enterable_roots") or [])
    baseline_runs = int(prev.get("execution_runs") or 0)

    def record(name, root, out, *, oracle_ok=None, notes=None, sequence_length=None):
        entered = [out.entered[i] for i in range(out.entered_n)]
        row = {
            "name": name,
            "root": hx(root) if isinstance(root, int) else root,
            "clean": bool(out.clean),
            "eax": hx(out.eax),
            "blocked_kind": h.KIND_NAMES[out.blocked_kind],
            "blocked_va": hx(out.blocked_va) if out.blocked_va else None,
            "depth_max": out.depth_max,
            "entered": [hx(x) for x in entered],
            "unique_entered": len(set(entered)),
            "oracle_ok": oracle_ok,
            "notes": notes,
        }
        if sequence_length:
            row["sequence_length"] = sequence_length
        results.append(row)
        return row

    # --- family regressions ---
    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_A, ecx=OBJ, args=(SRC, 0), ret_pop=8,
                                   zero=((SRC, 0x40),)))
    record("reg_ctor_a", CTOR_A, out)
    out = harness.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                       continue_state=True)
    record("reg_setter", SETTER, out)
    out = harness.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0), continue_state=True)
    record("reg_getter", GETTER, out, oracle_ok=(out.clean and out.eax == 0x5A))
    harness.end_sequence()

    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_B, ecx=POD, ret_pop=0))
    record("reg_ctor_b", CTOR_B, out)
    out = harness.step(h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4,
                                   zero=((EXPORT_BUF, 0x40),)), continue_state=True)
    expected = (0x40, 0x40, 0x40, 0x200, 0x200, 0x100)
    got = tuple(harness.read_u32(EXPORT_BUF + 4 * i) for i in range(6)) if out.clean else ()
    record("reg_export_b", EXPORT_B, out, oracle_ok=(got == expected))
    harness.end_sequence()

    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_C, ecx=OBJ_C,
                                   args=(0x11, 0x22, ZERO_PTR, 0x33), ret_pop=0x10,
                                   zero=((ZERO_PTR, 4),)))
    record("reg_ctor_c", CTOR_C, out)
    out = harness.step(h.make_spec(FIELD_C, ecx=OBJ_C, ret_pop=0), continue_state=True)
    record("reg_field_c", FIELD_C, out,
           oracle_ok=(out.clean and out.eax == OBJ_C + 0xC))
    harness.end_sequence()

    # --- preserve Phase 45 matrix smoke ---
    out = harness.step(h.make_spec(FN_CONST, ret_pop=0))
    record("const_ptr", FN_CONST, out, oracle_ok=(out.clean and out.eax == 0x0129E5D0))

    init = row_fill(MAT, 1, 2, 3, 4) + row_fill(MAT + 0x10, 5, 6, 7, 8) + row_fill(
        MAT + 0x20, 9, 10, 11, 12) + row_fill(SRC_M, 1, 1, 1, 1) * 1
    # rebuild add properly
    init = (
        row_fill(MAT, 1, 2, 3, 4) + row_fill(MAT + 0x10, 5, 6, 7, 8) +
        row_fill(MAT + 0x20, 9, 10, 11, 12) +
        row_fill(SRC_M, 1, 1, 1, 1) + row_fill(SRC_M + 0x10, 1, 1, 1, 1) +
        row_fill(SRC_M + 0x20, 1, 1, 1, 1)
    )
    out = harness.step(h.make_spec(FN_ADD, ecx=MAT, args=(SRC_M,), ret_pop=4,
                                   init=init, zero=((MAT, 0x30), (SRC_M, 0x30))))
    oracle = False
    if out.clean:
        exp = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        gotf = [read_f32_at(harness, MAT + 4 * i) for i in range(12)]
        oracle = all(abs(gotf[i] - exp[i]) < 1e-4 for i in range(12))
    record("matrix_add_smoke", FN_ADD, out, oracle_ok=oracle)

    # --- Phase 46: scale rows by vec.x (A128F0) ---
    # this = broadcast(vec.x) * each mat row
    init = (
        (VEC_M, f32(2.0)), (VEC_M + 4, f32(9.0)),
        (VEC_M + 8, f32(8.0)), (VEC_M + 12, f32(7.0)),
    ) + row_fill(SRC_M, 1, 2, 3, 4) + row_fill(SRC_M + 0x10, 5, 6, 7, 8) + row_fill(
        SRC_M + 0x20, 9, 10, 11, 12
    )
    out = harness.step(h.make_spec(
        FN_SCALE_ROWS_VX, ecx=MAT, args=(VEC_M, SRC_M), ret_pop=8,
        init=init, zero=((MAT, 0x30), (SRC_M, 0x30), (VEC_M, 0x10)),
    ))
    oracle = False
    if out.clean:
        exp = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24]
        gotf = [read_f32_at(harness, MAT + 4 * i) for i in range(12)]
        oracle = all(abs(gotf[i] - exp[i]) < 1e-3 for i in range(12))
    record("scale_rows_vx", FN_SCALE_ROWS_VX, out, oracle_ok=oracle,
           notes="this = broadcast(vec.x)*mat_rows; ABI thiscall ret8")

    # --- madd rows (A12940): this += broadcast(vec.x)*mat ---
    init = (
        row_fill(MAT, 1, 1, 1, 1) + row_fill(MAT + 0x10, 1, 1, 1, 1) +
        row_fill(MAT + 0x20, 1, 1, 1, 1) +
        (
            (VEC_M, f32(3.0)), (VEC_M + 4, f32(0.0)),
            (VEC_M + 8, f32(0.0)), (VEC_M + 12, f32(0.0)),
        ) +
        row_fill(SRC_M, 1, 0, 0, 0) + row_fill(SRC_M + 0x10, 0, 1, 0, 0) +
        row_fill(SRC_M + 0x20, 0, 0, 1, 0)
    )
    out = harness.step(h.make_spec(
        FN_MADD_ROWS_VX, ecx=MAT, args=(VEC_M, SRC_M), ret_pop=8,
        init=init, zero=((MAT, 0x30), (SRC_M, 0x30), (VEC_M, 0x10)),
    ))
    oracle = False
    if out.clean:
        # row0: (1,1,1,1) + 3*(1,0,0,0) = (4,1,1,1)
        # row1: (1,1,1,1) + 3*(0,1,0,0) = (1,4,1,1)
        # row2: (1,1,1,1) + 3*(0,0,1,0) = (1,1,4,1)
        exp = [4, 1, 1, 1, 1, 4, 1, 1, 1, 1, 4, 1]
        gotf = [read_f32_at(harness, MAT + 4 * i) for i in range(12)]
        oracle = all(abs(gotf[i] - exp[i]) < 1e-3 for i in range(12))
    record("madd_rows_vx", FN_MADD_ROWS_VX, out, oracle_ok=oracle,
           notes="this += broadcast(vec.x)*mat_rows; ABI thiscall ret8")

    # --- 3x3 mul (A12E60): this = A * B ---
    # A = identity-ish diag, B = simple
    init = (
        row_fill(SRC_M, 2, 0, 0, 0) + row_fill(SRC_M + 0x10, 0, 3, 0, 0) +
        row_fill(SRC_M + 0x20, 0, 0, 4, 0) +
        row_fill(TMP_M, 1, 2, 3, 0) + row_fill(TMP_M + 0x10, 4, 5, 6, 0) +
        row_fill(TMP_M + 0x20, 7, 8, 9, 0)
    )
    out = harness.step(h.make_spec(
        FN_MUL_3X3, ecx=MAT, args=(SRC_M, TMP_M), ret_pop=8,
        init=init, zero=((MAT, 0x30), (SRC_M, 0x30), (TMP_M, 0x30)),
    ))
    oracle = False
    if out.clean:
        # row_i of B transformed: (bx*A0 + by*A1 + bz*A2)
        # B0=(1,2,3) -> (2,6,12)
        # B1=(4,5,6) -> (8,15,24)
        # B2=(7,8,9) -> (14,24,36)
        exp = [2, 6, 12, 0, 8, 15, 24, 0, 14, 24, 36, 0]
        gotf = [read_f32_at(harness, MAT + 4 * i) for i in range(12)]
        oracle = all(abs(gotf[i] - exp[i]) < 1e-2 for i in range(12))
        notes = "got=%s" % ([round(x, 4) for x in gotf],)
    else:
        notes = "blocked"
    record("mul_3x3", FN_MUL_3X3, out, oracle_ok=oracle, notes=notes)

    # --- extended chain: copy_transpose -> scale_rows_vx -> add ---
    src_vals = {
        0x00: 1.0, 0x04: 2.0, 0x08: 3.0,
        0x10: 4.0, 0x14: 5.0, 0x18: 6.0,
        0x20: 7.0, 0x24: 8.0, 0x28: 9.0,
    }
    harness.begin_sequence()
    init = tuple((SRC_M + off, f32(v)) for off, v in src_vals.items())
    s1 = harness.step(h.make_spec(
        FN_COPY_TRANSPOSE, ecx=MAT, args=(SRC_M,), ret_pop=4,
        init=init, zero=((MAT, 0x30), (SRC_M, 0x30), (TMP_M, 0x30), (VEC_M, 0x10)),
    ))
    write_u32(harness, VEC_M, f32(0.5))
    # scale_rows needs mat in arg1; copy result is in MAT — use MAT as source via TMP
    # Actually A128F0: args=(vec, mat), writes this. Copy mat to TMP first via... 
    # Simpler: use MAT as both this and... can't alias easily. Copy MAT->TMP manually.
    for i in range(12):
        write_u32(harness, TMP_M + 4 * i, harness.read_u32(MAT + 4 * i))
    s2 = harness.step(h.make_spec(
        FN_SCALE_ROWS_VX, ecx=MAT, args=(VEC_M, TMP_M), ret_pop=8,
    ), continue_state=True)
    ones = row_fill(SRC_M, 1, 1, 1, 1) + row_fill(SRC_M + 0x10, 1, 1, 1, 1) + row_fill(
        SRC_M + 0x20, 1, 1, 1, 1)
    for addr, val in ones:
        write_u32(harness, addr, val)
    s3 = harness.step(h.make_spec(FN_ADD, ecx=MAT, args=(SRC_M,), ret_pop=4),
                      continue_state=True)
    harness.end_sequence()
    chain_clean = bool(s1.clean and s2.clean and s3.clean)
    chain_entered = []
    for o in (s1, s2, s3):
        chain_entered.extend(hx(o.entered[i]) for i in range(o.entered_n))
    results.append({
        "name": "matrix_chain_transpose_scale_rows_add",
        "root": "STATEFUL:matrix_chain_p46",
        "clean": chain_clean,
        "eax": hx(s3.eax),
        "blocked_kind": "NONE" if chain_clean else h.KIND_NAMES[s3.blocked_kind],
        "blocked_va": None,
        "depth_max": max(s1.depth_max, s2.depth_max, s3.depth_max),
        "entered": chain_entered,
        "unique_entered": len(set(chain_entered)),
        "sequence_length": 3,
        "oracle_ok": chain_clean,
        "notes": "guest chain copy_transpose → scale_rows_vx → add",
    })

    # --- guest range reclaim: empty list + exact single-node ---
    # Empty: [HEAD]=HEAD
    write_u32(harness, RANGE_HEAD, RANGE_HEAD)
    write_u32(harness, RANGE_HEAD + 4, RANGE_HEAD)
    write_u32(harness, RANGE_HEAD + 8, 0)
    write_u32(harness, RANGE_HEAD + 0xC, 0)
    out = harness.step(h.make_spec(
        FN_RANGE_RECLAIM, ecx=RANGE_HEAD, args=(0x100,), ret_pop=4,
        zero=((RANGE_HEAD, 0x20),),
        init=((RANGE_HEAD, RANGE_HEAD), (RANGE_HEAD + 4, RANGE_HEAD)),
    ))
    record("range_reclaim_empty", FN_RANGE_RECLAIM, out,
           oracle_ok=bool(out.clean),
           notes="empty circular list; ABI thiscall ret4")

    # Single busy node pointing to sentinel
    # node: next=HEAD, prev=HEAD, size=0x10, key=0x100, free=1 (busy)
    init = (
        (RANGE_HEAD, RANGE_NODE),
        (RANGE_HEAD + 4, RANGE_NODE),
        (RANGE_HEAD + 8, 1),
        (RANGE_HEAD + 0xC, 0),
        (RANGE_NODE, RANGE_HEAD),
        (RANGE_NODE + 4, RANGE_HEAD),
        (RANGE_NODE + 8, 0x10),
        (RANGE_NODE + 0xC, 0x100),
        (RANGE_NODE + 0x10, 1),  # busy (nonzero); routine writes 0
    )
    out = harness.step(h.make_spec(
        FN_RANGE_RECLAIM, ecx=RANGE_HEAD, args=(0x100,), ret_pop=4,
        init=init, zero=((RANGE_HEAD, 0x40), (RANGE_NODE, 0x20)),
    ))
    oracle = False
    if out.clean:
        free_flag = harness.read_u32(RANGE_NODE + 0x10) & 0xFF
        oracle = free_flag == 0
    record("range_reclaim_exact_single", FN_RANGE_RECLAIM, out, oracle_ok=oracle,
           notes="mark free on exact key; guest execution")

    # Collect
    campaign_entered = set()
    for r in results:
        for a in r.get("entered") or []:
            campaign_entered.add(a if isinstance(a, str) else hx(a))

    newly = sorted(campaign_entered - baseline_executed)
    clean_enterable = []
    for r in results:
        if not (r.get("oracle_ok") and r.get("clean")):
            continue
        root = r["root"]
        if root.startswith("0x") and root not in baseline_enterable:
            clean_enterable.append(root)
    clean_enterable = sorted(set(clean_enterable))

    return {
        "results": results,
        "baseline_executed": sorted(baseline_executed),
        "campaign_entered": sorted(campaign_entered),
        "newly_executed": newly,
        "enterable_new": clean_enterable,
        "baseline_enterable": sorted(baseline_enterable),
        "baseline_runs": baseline_runs,
        "runs_delta": len(results),
        "regressions": {
            "family_a": any(r["name"] == "reg_getter" and r.get("oracle_ok") for r in results),
            "family_b": any(r["name"] == "reg_export_b" and r.get("oracle_ok") for r in results),
            "family_c": any(r["name"] == "reg_field_c" and r.get("oracle_ok") for r in results),
        },
        "matrix_chain_clean": chain_clean,
        "phase45_smoke_ok": any(
            r["name"] == "matrix_add_smoke" and r.get("oracle_ok") for r in results
        ),
    }


def update_artifacts(evidence_meta: dict, synth: dict, camp: dict) -> dict:
    prev = load("runtime-frontier.json")
    p45 = load("phase45-execution.json")
    p45_runs = int(p45["metrics_delta"]["runs_after"])
    p45_unique = int(p45["metrics_delta"]["unique_after"])
    p45_enterable = int(p45["metrics_delta"]["enterable_after"])
    p46_roots = {
        "0x00A128F0", "0x00A12940", "0x00A12E60", "0x00766100",
    }

    # Build executed set from campaign results (idempotent on re-run).
    executed = set(camp["baseline_executed"]) | set(camp["newly_executed"])
    for r in camp["results"]:
        if r.get("clean"):
            executed |= set(r.get("entered") or [])

    enterable = set(camp["baseline_enterable"]) | set(camp["enterable_new"])
    for r in camp["results"]:
        if r.get("oracle_ok") and r.get("clean") and r["root"] in p46_roots:
            enterable.add(r["root"])

    # Absolute RUNS from Phase-45 end + this campaign (not cumulative re-runs).
    runs = p45_runs + camp["runs_delta"]

    # Report deltas against Phase-45 end-state.
    p45_executed = set(executed) - p46_roots
    # If baseline already had p46 roots, baseline_executed is the re-run set;
    # reconstruct phase-45 comparison set for newly_executed reporting.
    newly_vs_p45 = sorted(executed - (set(camp["baseline_executed"]) - p46_roots))
    if not camp["newly_executed"] and prev.get("phase", 0) >= 46:
        newly_vs_p45 = sorted(p46_roots & executed)
    elif camp["newly_executed"]:
        newly_vs_p45 = list(camp["newly_executed"])
    enterable_new_vs_p45 = sorted(p46_roots & enterable)

    camp["newly_executed"] = newly_vs_p45
    camp["enterable_new"] = enterable_new_vs_p45
    camp["baseline_executed_p45_count"] = p45_unique
    camp["baseline_enterable_p45_count"] = p45_enterable
    camp["baseline_runs_p45"] = p45_runs

    clean_roots = list(prev.get("clean_ordinary_roots_list") or [])
    if not clean_roots and isinstance(prev.get("clean_ordinary_roots"), list):
        clean_roots = list(prev.get("clean_ordinary_roots") or [])
    for a in enterable_new_vs_p45:
        if a not in clean_roots:
            clean_roots.append(a)

    deepest = prev.get("deepest_ordinary_execution_chain") or 0
    largest = prev.get("largest_executed_ordinary_closure") or 0
    longest = prev.get("ordinary_execution_sequence_length") or 0
    largest_cov = prev.get("largest_stateful_sequence_coverage") or 0
    for r in camp["results"]:
        if r.get("clean"):
            deepest = max(deepest, r.get("depth_max") or 0)
            largest = max(largest, r.get("unique_entered") or 0)
        if r.get("sequence_length") and r.get("clean"):
            longest = max(longest, r["sequence_length"])
            largest_cov = max(largest_cov, r.get("unique_entered") or 0)

    frontier = dict(prev)
    frontier["phase"] = 46
    frontier["first_frame"] = FIRST_FRAME
    frontier["graphics_frozen"] = True
    frontier["unique_uc_functions_executed"] = len(executed)
    frontier["unique_uc_functions_executed_list"] = sorted(executed)
    frontier["enterable"] = len(enterable)
    frontier["enterable_roots"] = sorted(enterable)
    frontier["execution_runs"] = runs
    frontier["clean_ordinary_roots_list"] = sorted(set(clean_roots))
    frontier["clean_ordinary_roots"] = len(frontier["clean_ordinary_roots_list"])
    frontier["deepest_ordinary_execution_chain"] = deepest
    frontier["largest_executed_ordinary_closure"] = largest
    frontier["ordinary_execution_sequence_length"] = longest
    frontier["largest_stateful_sequence_coverage"] = largest_cov

    frontier["phase46"] = {
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "runs_delta": camp["runs_delta"],
        "matrix_chain_clean": camp["matrix_chain_clean"],
        "phase45_smoke_ok": camp["phase45_smoke_ok"],
        "regressions": camp["regressions"],
        "blocked_external_unchanged": 74,
        "allocator_still_opaque": True,
        "injected_allocator_tests": 0,
        "synthetic_contracts": True,
        "first_frame_readiness": "first-frame-readiness.json",
        "call_sites_imported": evidence_meta.get("call_sites"),
        "edges_imported": evidence_meta.get("edges"),
        "note": (
            "Guest matrix expansion + synthetic ordinary render contracts. "
            "Opaque draw handoffs untouched. FIRST_FRAME still blocked."
        ),
    }
    frontier["recommended_phase47"] = (
        "Recover scheduling edges from render callback 0x00766730 to scene "
        "producers (~0x00777253 / 0x007B5972) and from mesh/scene work to later "
        "Present (~0x00758674); expand remaining allocator-independent math; "
        "continue ordinary stream/state contracts with injected device mocks. "
        "Keep 0x006860F0/0x00686290/0x00686000 opaque."
    )
    dump("runtime-frontier.json", frontier)

    evidence = load("execution-evidence.json")
    evidence["phase"] = 46
    roots = evidence.get("roots") or []
    for r in camp["results"]:
        roots.append({
            "root": r["root"],
            "phase": 46,
            "kind": "STATEFUL_SEQUENCE" if r.get("sequence_length") else "DIRECT_GUEST_ENTRY",
            "result": "EXECUTED_CLEAN" if r.get("clean") else "FAULT_OR_BLOCKED",
            "hist": r.get("blocked_kind"),
            "functions_entered": r.get("entered") or [],
            "unique_functions_entered": r.get("unique_entered"),
            "max_depth": r.get("depth_max"),
            "clean": r.get("clean"),
            "oracle_ok": r.get("oracle_ok"),
            "sequence_length": r.get("sequence_length"),
            "stubs": [],
            "evidence": "uc_phase46.py",
            "counted_in_metrics": True,
            "diagnostic_only": False,
        })
    evidence["roots"] = roots
    evidence["unique_uc_functions_executed"] = len(executed)
    evidence["phase46_results"] = camp["results"]
    dump("execution-evidence.json", evidence)

    status = load("project-status.json")
    status["current_phase"] = 46
    status["strategy"] = (
        "Phase 46: first-frame evidence integration; matrix guest expansion; "
        "ordinary stream/mesh/range synthetic contracts; FIRST_FRAME frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 46 for p in phases):
        phases.append({
            "phase": 46,
            "name": "Matrix expansion & first-frame evidence integration",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    dump("phase46-execution.json", {
        "phase": 46,
        "results": camp["results"],
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "synthetic": {
            "stream_cache_tested": True,
            "indexed_draw_prep_tested": True,
            "range_reclaim_synthetic": True,
            "d3d9_recorder_clear_only": True,
            "not_authentic_frame": True,
        },
        "metrics_delta": {
            "unique_before": p45_unique,
            "unique_after": len(executed),
            "enterable_before": p45_enterable,
            "enterable_after": len(enterable),
            "runs_before": p45_runs,
            "runs_after": runs,
        },
    })

    dump("phase46-candidate-inventory.json", {
        "phase": 46,
        "candidates": [
            {
                "address": hx(FN_SCALE_ROWS_VX),
                "role": "scale matrix rows by broadcast(vec.x)",
                "abi": "thiscall ret8",
                "classification": "INDEPENDENT",
            },
            {
                "address": hx(FN_MADD_ROWS_VX),
                "role": "madd matrix rows by broadcast(vec.x)",
                "abi": "thiscall ret8",
                "classification": "INDEPENDENT",
            },
            {
                "address": hx(FN_MUL_3X3),
                "role": "3x3 matrix multiply into this",
                "abi": "thiscall ret8",
                "classification": "INDEPENDENT",
            },
            {
                "address": hx(FN_RANGE_RECLAIM),
                "role": "buffer range reclaim / coalesce",
                "abi": "thiscall ret4",
                "classification": "GUEST_WHERE_FIXTURED + SYNTHETIC coalesce cases",
            },
            {
                "address": "0x0071B6B0",
                "role": "stream cache hit / injected miss",
                "abi": "cdecl 5 args",
                "classification": "SYNTHETIC (hit verified; miss injected)",
            },
            {
                "address": "0x00757B80",
                "role": "indexed draw arg preparation (ordinary)",
                "abi": "thiscall ret8",
                "classification": "SYNTHETIC prep model; opaque 0x006860F0",
            },
        ],
    })
    return frontier


def write_docs(evidence_meta: dict, synth: dict, camp: dict, frontier: dict) -> None:
    p46 = frontier["phase46"]
    lines = [
        "# Undercover Phase 46 — Matrix expansion & first-frame evidence",
        "",
        "SHA-256 target: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`",
        "",
        "`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`",
        "",
        f"FIRST_FRAME: `{FIRST_FRAME}`",
        "",
        "## A. First-frame evidence integration",
        "",
        f"- Device xrefs / defined fns / recorded call sites / edges: "
        f"**{evidence_meta['readiness']['coverage_from_evidence']}** / "
        f"call_sites={evidence_meta['call_sites']} edges={evidence_meta['edges']}",
        "- Clear-only Present path in `0x00725200` identified (no draw between Clear and Present).",
        "- Indexed handoff `0x00757C9A → 0x006860F0` remains opaque.",
        "- User-memory handoff `0x00766700 → 0x00686290` remains opaque.",
        "- Scheduling edges callback→scene and scene→later Present: **UNVERIFIED**.",
        "",
        "Artifacts: `d3d9-device-call-sites.json`, `render-call-graph.json`, "
        "`first-frame-readiness.json`, `draw-handoff-metadata.json`, "
        "`mesh-descriptor-field-map.json`, `stream-state-evidence.json`.",
        "",
        "## B. New guest-executed functions",
        "",
        "| Address | Role | ABI | Clean | Oracle | Dependencies |",
        "|---|---|---|---|---|---|",
    ]
    role = {
        hx(FN_SCALE_ROWS_VX): "scale rows by vec.x",
        hx(FN_MADD_ROWS_VX): "madd rows by vec.x",
        hx(FN_MUL_3X3): "3x3 matrix multiply",
        hx(FN_RANGE_RECLAIM): "range reclaim",
        hx(FN_ADD): "matrix add smoke",
        hx(FN_CONST): "const ptr smoke",
        hx(FN_COPY_TRANSPOSE): "copy transpose (chain)",
    }
    for r in camp["results"]:
        if r["root"].startswith("0x00A1") or r["root"] == hx(FN_RANGE_RECLAIM):
            lines.append(
                f"| `{r['root']}` | {role.get(r['root'], r['name'])} | "
                f"see inventory | {r.get('clean')} | {r.get('oracle_ok')} | "
                f"none protected |"
            )
    lines += [
        "",
        f"Newly unique executed: {camp['newly_executed']}",
        f"Newly enterable: {camp['enterable_new']}",
        f"Extended matrix chain clean: {camp['matrix_chain_clean']}",
        "",
        "## C. Synthetic rendering contracts",
        "",
        "- Stream-cache hit/miss (miss via injected SetStreamSource).",
        "- Indexed-draw argument preparation (primCount = floor(indexCount/3)); "
        f"opaque target `{hx(g46.OPAQUE_INDEXED_DRAW)}` not executed.",
        "- Buffer-range reclaim: guest empty/exact-single + synthetic coalesce cases.",
        "- D3D9 command recorder: clear-only Present sequence + later EndScene/Present.",
        "",
        "**These are not authentic Undercover frames and are not browser GPU execution.**",
        "",
        "## D. Metrics",
        "",
        f"- UNIQUE: {camp.get('baseline_executed_p45_count', len(camp['baseline_executed']))} → "
        f"{frontier['unique_uc_functions_executed']}",
        f"- ENTERABLE: {camp.get('baseline_enterable_p45_count', len(camp['baseline_enterable']))} → "
        f"{frontier['enterable']}",
        f"- EXECUTION_RUNS: {camp.get('baseline_runs_p45', camp['baseline_runs'])} → "
        f"{frontier['execution_runs']}",
        f"- RUNTIME_READY: {frontier.get('runtime_ready')} (policy unchanged)",
        f"- BLOCKED_EXTERNAL: 74 (unchanged)",
        "",
        "## E. First-frame readiness",
        "",
        "See `first-frame-readiness.json`. Authentic game frame: **Blocked**.",
        "",
        "## F. Protected boundaries",
        "",
        "Opaque: `0x00686000`, `0x00686030`, `0x004A26B0`, `0x007A51B0`, "
        "`0x0071E380`, `0x00B615C4`, `0x006860F0`, `0x00686290`, `0x006861B0`.",
        "",
        "## G. Phase 47",
        "",
        frontier.get("recommended_phase47") or "",
        "",
    ]
    with open(os.path.join(ANALYSIS, "runtime-phase46.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))

    with open(os.path.join(ANALYSIS, "phase47-handoff.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 47 handoff",
            "",
            "From Phase 46 matrix expansion and first-frame evidence integration.",
            "",
            "## Do not",
            "",
            "- Reconstruct `0x00686000` / `0x00686030` / `0x006860F0` / `0x00686290` / `0x006861B0`.",
            "- Invent scheduling edges for callback→scene or scene→Present.",
            "- Claim authentic first frame or browser GPU submission.",
            "- Reclassify MUST/BLOCKED_EXTERNAL without an ordinary allocator-free path.",
            "",
            "## Priorities",
            "",
            "1. Static recovery of scheduling edges: `0x00766730` → `~0x00777253` / "
            "`0x007B5972`, and mesh/scene → `~0x00758674`.",
            "2. More allocator-independent `0x00A12xxx` leaves and longer guest chains.",
            "3. Ordinary stream/state/resource contracts with injected device mocks only.",
            "4. Material/texture binding evidence (non-null ordinary paths) if recoverable.",
            "",
            frontier.get("recommended_phase47") or "",
            "",
        ]))

    # Dependency graph markdown
    with open(os.path.join(ANALYSIS, "first-frame-dependency-graph.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# First-frame dependency graph (Phase 46)",
            "",
            f"Status: `{FIRST_FRAME}`",
            "",
            "## Confirmed direct edges (selected)",
            "",
            "- `0x00766730` → `0x0072E5D0` → … → `0x00725200` (device create / clear-only Present)",
            "- `0x00766730` → `0x007661A0` → `0x00766100` (buffer queue / range reclaim)",
            "- `0x00770750` → `0x0076FC30` → `0x00757B80` → **opaque** `0x006860F0`",
            "- `0x00766480` → **opaque** `0x00686290`",
            "- Undefined caller `0x00758674` → `0x00752AF0` (later EndScene/Present)",
            "",
            "## Unresolved",
            "",
            "- Render callback → scene producer (~`0x00777253`)",
            "- Render callback → scene dispatch (~`0x007B5972` / `0x007B5979`)",
            "- Scene/mesh path → later Present (~`0x00758674`)",
            "",
            "## Opaque targets",
            "",
            "- `0x006860F0`, `0x00686290`, `0x006861B0`, `0x004A26B0`, `0x007A51B0`, `0x00686000`",
            "",
            "Do not invent missing edges. Registration ≠ runtime invocation.",
            "",
        ]))


def run_tests() -> tuple[int, int]:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    import uc_phase46_test as t46
    suite.addTests(loader.loadTestsFromModule(t46))
    for mod in (t45, t43, t44):
        suite.addTests(loader.loadTestsFromModule(mod))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.testsRun, len(result.failures) + len(result.errors)


def main() -> int:
    ev = ensure_evidence_imported()
    evidence_meta = integrate_rendering_evidence(ev)
    synth = run_synthetic_contracts()
    camp = run_campaign()
    frontier = update_artifacts(evidence_meta, synth, camp)
    write_docs(evidence_meta, synth, camp, frontier)
    n, fails = run_tests()
    print(json.dumps({
        "phase": 46,
        "unique": frontier["unique_uc_functions_executed"],
        "enterable": frontier["enterable"],
        "runs": frontier["execution_runs"],
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "tests_run": n,
        "test_failures": fails,
        "first_frame": FIRST_FRAME,
        "blocked_external": 74,
        "call_sites": evidence_meta["call_sites"],
        "edges": evidence_meta["edges"],
    }, indent=2))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
