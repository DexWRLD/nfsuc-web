#!/usr/bin/env python3
"""Phase 46 tests: first-frame evidence, synthetic contracts, matrix expansion."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_graphics46 as g
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def _load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class FirstFrameEvidence(unittest.TestCase):
    def test_evidence_imported(self):
        self.assertTrue(os.path.isfile(
            os.path.join(ANALYSIS, "first-frame-evidence-2026-11-03.json")))
        self.assertTrue(os.path.isfile(
            os.path.join(ANALYSIS, "first-frame-report-2026-11-03.md")))

    def test_evidence_status_and_hash(self):
        ev = _load("first-frame-evidence-2026-11-03.json")
        self.assertEqual(
            ev["status"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")
        self.assertEqual(
            ev["target"]["sha256"],
            "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd")
        self.assertEqual(ev["coverage"]["device_xrefs"], 142)
        self.assertEqual(len(ev["call_sites"]), 25)
        self.assertEqual(len(ev["edges"]), 28)

    def test_call_sites_not_confirmed_imports(self):
        inv = _load("d3d9-device-call-sites.json")
        self.assertFalse(inv["method_names_are_confirmed_imports"])
        self.assertEqual(inv["call_site_count"], 25)

    def test_readiness_blocked(self):
        ready = _load("first-frame-readiness.json")
        self.assertEqual(
            ready["status"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")
        self.assertEqual(ready["authentic_game_frame"], "Blocked")
        flags = ready["dashboard_flags"]
        self.assertTrue(flags["clear_only_presentation_path_identified"])
        self.assertTrue(flags["draw_handoff_remains_opaque"])
        self.assertTrue(flags["authentic_first_frame_blocked"])
        self.assertTrue(flags["browser_gpu_backend_unverified"])
        statuses = {p["requirement"]: p["status"] for p in ready["prerequisites"]}
        self.assertEqual(statuses["Opaque draw implementation"], "Blocked")
        self.assertEqual(statuses["Render callback → scene path"], "Unverified")
        self.assertEqual(statuses["Authentic game frame"], "Blocked")


class StreamCacheContracts(unittest.TestCase):
    def test_hit_and_component_mismatches(self):
        cache = g.StreamCache()
        calls = []
        cache.miss_setter = lambda d, s, b, o, st: calls.append((s, b, o, st)) or 0
        # Miss path returns injected setter result (0 here); distinguish via call count.
        n0 = len(calls)
        self.assertEqual(cache.cache_hit(1, 0, 0xA, 0, 24), 0)  # miss
        self.assertEqual(len(calls), n0 + 1)
        self.assertEqual(cache.cache_hit(1, 0, 0xA, 0, 24), 0)  # hit
        self.assertEqual(len(calls), n0 + 1)
        self.assertEqual(cache.cache_hit(1, 0, 0xB, 0, 24), 0)  # buffer mismatch
        self.assertEqual(cache.cache_hit(1, 0, 0xB, 8, 24), 0)  # offset mismatch
        self.assertEqual(cache.cache_hit(1, 0, 0xB, 8, 16), 0)  # stride mismatch
        self.assertEqual(cache.cache_hit(1, 3, 0xC, 0, 12), 0)  # other stream
        self.assertEqual(cache.cache_hit(1, 3, 0xC, 0, 12), 0)  # hit
        self.assertEqual(len(calls), n0 + 5)

    def test_hit_returns_zero_without_setter_side_effect(self):
        cache = g.StreamCache()
        cache.set_slot(1, 0x10, 0, 24)
        self.assertEqual(cache.cache_hit(0, 1, 0x10, 0, 24), 0)


class IndexedDrawPrep(unittest.TestCase):
    def test_prim_count_div3(self):
        self.assertEqual(g.indexed_prim_count(0), 0)
        self.assertEqual(g.indexed_prim_count(3), 1)
        self.assertEqual(g.indexed_prim_count(9), 3)
        self.assertEqual(g.indexed_prim_count(10), 3)
        self.assertEqual(g.indexed_prim_count(11), 3)
        self.assertEqual(g.indexed_prim_count(12), 4)

    def test_empty_batch_returns_none(self):
        mesh = g.MeshDescriptor(batch_counts=[0], index_count=9, vertex_count=5)
        self.assertIsNone(g.prepare_indexed_draw_args(mesh, 0xD3D, 0))

    def test_single_batch_args(self):
        mesh = g.MeshDescriptor(
            batch_counts=[1], batch_offsets=[2], index_count=9, vertex_count=15
        )
        args = g.prepare_indexed_draw_args(mesh, 0x0D3D0001, 0)
        self.assertIsNotNone(args)
        self.assertEqual(args.prim_type, 4)
        self.assertEqual(args.prim_count, 3)
        self.assertEqual(args.vertex_count, 15)
        self.assertEqual(args.flag, 1)
        self.assertEqual(args.opaque_target, g.OPAQUE_INDEXED_DRAW)
        self.assertEqual(g.stream_offset_scaled(mesh, 0), 2 << 6)

    def test_opaque_target_not_confused_with_allocator(self):
        self.assertNotEqual(g.OPAQUE_INDEXED_DRAW, 0x00686000)
        self.assertNotEqual(g.OPAQUE_USERMEM_DRAW, 0x00686000)


class RangeReclaimSynthetic(unittest.TestCase):
    def test_no_match(self):
        lst = g.RangeList(nodes=[g.RangeNode(1, 8, False)])
        self.assertFalse(lst.reclaim(99))
        self.assertEqual(lst.live_count, 1)

    def test_exact(self):
        lst = g.RangeList(nodes=[g.RangeNode(1, 8, False), g.RangeNode(2, 8, False)])
        self.assertTrue(lst.reclaim(1))
        self.assertTrue(lst.nodes[0].free)
        self.assertEqual(lst.live_count, 1)

    def test_prev_coalesce(self):
        lst = g.RangeList(nodes=[
            g.RangeNode(0x100, 0x10, True),
            g.RangeNode(0x110, 0x10, False),
        ])
        self.assertTrue(lst.reclaim(0x110))
        self.assertEqual(len(lst.nodes), 1)
        self.assertEqual(lst.nodes[0].key, 0x100)
        self.assertEqual(lst.nodes[0].size, 0x20)

    def test_next_coalesce(self):
        lst = g.RangeList(nodes=[
            g.RangeNode(0x100, 0x10, False),
            g.RangeNode(0x110, 0x10, True),
        ])
        self.assertTrue(lst.reclaim(0x100))
        self.assertEqual(len(lst.nodes), 1)
        self.assertEqual(lst.nodes[0].size, 0x20)

    def test_both_coalesce(self):
        lst = g.RangeList(nodes=[
            g.RangeNode(0x100, 0x10, True),
            g.RangeNode(0x110, 0x10, False),
            g.RangeNode(0x120, 0x10, True),
        ])
        self.assertTrue(lst.reclaim(0x110))
        self.assertEqual(len(lst.nodes), 1)
        self.assertEqual(lst.nodes[0].key, 0x100)
        self.assertEqual(lst.nodes[0].size, 0x30)


class D3D9Recorder(unittest.TestCase):
    def test_clear_only_sequence(self):
        rec = g.D3D9CommandRecorder()
        seq = rec.record_clear_only_present()
        methods = [c["method"] for c in seq]
        self.assertEqual(methods, ["BeginScene", "Clear", "EndScene", "Present"])
        clear = seq[1]
        self.assertEqual(clear["flags"], 7)
        self.assertEqual(clear["color"], 0)
        self.assertEqual(clear["z"], 1.0)
        self.assertEqual(clear["stencil"], 0)
        # No draw between Clear and Present
        self.assertNotIn("DrawIndexedPrimitive", methods)
        self.assertNotIn("DrawPrimitive", methods)

    def test_later_present(self):
        rec = g.D3D9CommandRecorder()
        seq = rec.record_later_present_cleanup()
        self.assertEqual([c["method"] for c in seq], ["EndScene", "Present"])


class Phase46ExecutionMetrics(unittest.TestCase):
    def test_frontier_phase46(self):
        fr = _load("runtime-frontier.json")
        self.assertGreaterEqual(fr["phase"], 46)
        self.assertEqual(
            fr["first_frame"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 75)
        self.assertGreaterEqual(fr["enterable"], 41)
        self.assertGreaterEqual(fr["execution_runs"], 282)
        self.assertEqual(fr["phase46"]["blocked_external_unchanged"], 74)
        self.assertTrue(fr["phase46"]["allocator_still_opaque"])

    def test_new_matrix_leaves(self):
        fr = _load("runtime-frontier.json")
        executed = set(fr["unique_uc_functions_executed_list"])
        for va in ("0x00A128F0", "0x00A12940", "0x00A12E60"):
            self.assertIn(va, executed)
        self.assertTrue(fr["phase46"]["matrix_chain_clean"])
        self.assertTrue(fr["phase46"]["phase45_smoke_ok"])

    def test_phase45_leaves_preserved(self):
        fr = _load("runtime-frontier.json")
        executed = set(fr["unique_uc_functions_executed_list"])
        for va in (
            "0x00A12850", "0x00A12860", "0x00A128A0",
            "0x00A12D10", "0x00A12D50", "0x00A12D90",
        ):
            self.assertIn(va, executed)

    def test_family_regressions(self):
        fr = _load("runtime-frontier.json")
        reg = fr["phase46"]["regressions"]
        self.assertTrue(reg["family_a"])
        self.assertTrue(reg["family_b"])
        self.assertTrue(reg["family_c"])

    def test_execution_evidence(self):
        ev = _load("phase46-execution.json")
        self.assertGreaterEqual(ev["metrics_delta"]["unique_after"],
                                ev["metrics_delta"]["unique_before"])
        self.assertTrue(ev["synthetic"]["not_authentic_frame"])

    def test_draw_handoff_opaque(self):
        meta = _load("draw-handoff-metadata.json")
        targets = meta.get("do_not_reconstruct") or []
        self.assertIn("0x006860F0", targets)
        self.assertIn("0x00686290", targets)


if __name__ == "__main__":
    unittest.main()
