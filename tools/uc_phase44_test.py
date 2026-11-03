#!/usr/bin/env python3
"""Phase 44 tests: BLOCKED_EXTERNAL attribution + callback registration semantics."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def _load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class Attribution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.attr = _load("blocked-external-attribution.json")
        cls.inv = _load("blocked-external-inventory.json")
        cls.cb = _load("callback-registration-edges.json")
        cls.fr = _load("runtime-frontier.json")
        cls.prog = _load("progress.json")
        cls.cut = _load("helper-cut.json")

    def test_count_matches_progress_and_must(self):
        be = [f for f in self.prog["functions"] if f["runtime_status"] == "BLOCKED_EXTERNAL"]
        self.assertEqual(len(be), 74)
        self.assertEqual(self.attr["summary"]["blocked_external_count"], 74)
        self.assertEqual(len(self.attr["functions"]), 74)
        self.assertEqual(set(self.cut["must"]), {f["address"] for f in be})

    def test_all_rooted_at_allocator(self):
        for f in self.attr["functions"]:
            self.assertEqual(f["attribution"]["root_blocker"], "0x00686000")
            self.assertIsNotNone(f["attribution"]["shortest_path"])
            self.assertEqual(f["attribution"]["shortest_path"][-1], "0x00686000")
            self.assertFalse(f["reclassified"])
            self.assertFalse(f["classification_error"])

    def test_direct_transitive_partition(self):
        kinds = {f["attribution"]["kind"] for f in self.attr["functions"]}
        self.assertEqual(kinds, {"DIRECT", "TRANSITIVE"})
        self.assertEqual(self.attr["summary"]["direct"] + self.attr["summary"]["transitive"], 74)
        self.assertGreaterEqual(self.attr["summary"]["direct"], 56)
        self.assertGreaterEqual(self.attr["summary"]["transitive"], 1)

    def test_audit_gaps_flagged(self):
        gaps = [f for f in self.attr["functions"] if f.get("audit_gap")]
        self.assertGreaterEqual(len(gaps), 6)
        for g in gaps:
            self.assertEqual(g["audit_gap"]["issue"], "AUDIT_MISSING_DIRECT_CALLER")
            self.assertEqual(g["attribution"]["kind"], "DIRECT")

    def test_no_metric_inflation(self):
        m = self.attr["metrics"]
        self.assertEqual(m["blocked_external_delta"], 0)
        self.assertEqual(m["enterable_delta"], 0)
        self.assertEqual(m["runtime_ready_delta"], 0)
        self.assertEqual(m["unique_executed_delta"], 0)
        self.assertEqual(m["newly_classified_without_execution"], 0)
        self.assertEqual(m["blocked_external_affected_by_callback_edges"], 0)
        self.assertEqual(
            m["first_frame"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")

    def test_callback_registration_not_execution(self):
        self.assertEqual(len(self.cb["edges"]), 2)
        by_cb = {e["callback"]: e for e in self.cb["edges"]}
        self.assertIn("0x0072B170", by_cb)
        self.assertIn("0x00766730", by_cb)
        e1 = by_cb["0x0072B170"]
        self.assertEqual(e1["registrar"], "0x0072E340")
        self.assertEqual(e1["site"], "0x0072E497")
        self.assertEqual(e1["edge_kind"], "CALLBACK_REGISTRATION")
        self.assertTrue(e1["not_execution"])
        self.assertFalse(e1["execution_modeled"])
        e2 = by_cb["0x00766730"]
        self.assertEqual(e2["registrar"], "0x0076CA20")
        self.assertEqual(e2["site"], "0x0076CB40")
        self.assertFalse(e2["affects_blocked_external_count"])

    def test_registrars_not_forced_blocked_external(self):
        by = {f["address"]: f for f in self.prog["functions"]}
        self.assertNotEqual(by["0x0072E340"]["runtime_status"], "BLOCKED_EXTERNAL")
        # 76CA20 may be UNKNOWN/MAY — must not become BLOCKED_EXTERNAL via DATA edge
        self.assertNotEqual(by.get("0x0076CA20", {}).get("runtime_status"), "BLOCKED_EXTERNAL")

    def test_frontier_phase44(self):
        self.assertGreaterEqual(self.fr["phase"], 44)
        att = self.fr["blocked_external_attribution"]
        self.assertEqual(att["count"], 74)
        self.assertEqual(att["root"], "0x00686000")
        self.assertEqual(att["status_reclassified"], 0)
        self.assertEqual(att["enterable_delta"], 0)
        self.assertEqual(
            self.fr["first_frame"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")

    def test_eight_boundaries_not_equated_to_blocked_external(self):
        # Protected backends are opaque but are NOT the 74-cell class by themselves.
        be = {f["address"] for f in self.attr["functions"]}
        for opaque in (
            "0x004A26B0", "0x007A51B0", "0x0071E380",
            "0x00B615C4", "0x0072B170", "0x00686030",
        ):
            self.assertNotIn(opaque, be)


class Phase43Regression(unittest.TestCase):
    def test_phase43_synthetic_still_present(self):
        fr = _load("runtime-frontier.json")
        gfx = fr.get("graphics_config_phase43") or {}
        self.assertTrue(gfx.get("synthetic_implemented"))
        self.assertFalse(gfx.get("first_frame_unblocked"))


if __name__ == "__main__":
    unittest.main()
