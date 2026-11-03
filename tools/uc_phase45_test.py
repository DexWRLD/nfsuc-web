#!/usr/bin/env python3
"""Phase 45 tests: helper-cut reconciliation + allocator-independent execution."""
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


class HelperCutReconciliation(unittest.TestCase):
    def test_blocked_external_equals_current_must(self):
        rec = _load("helper-cut-reconciliation.json")
        self.assertTrue(rec["dashboard_blocked_external"]["equals_current_must"])
        self.assertEqual(rec["dashboard_blocked_external"]["count"], 74)
        self.assertEqual(rec["current_helper_cut"]["must_count"], 74)
        self.assertEqual(rec["current_helper_cut"]["may_count"], 139)
        self.assertEqual(rec["current_helper_cut"]["independent_count"], 22394)

    def test_historical_phase14_not_confused(self):
        rec = _load("helper-cut-reconciliation.json")
        hist = rec["historical_phase14_helper_cut"]
        self.assertEqual(hist["must"], 11)
        self.assertNotEqual(hist["must"], rec["current_helper_cut"]["must_count"])


class Phase45Execution(unittest.TestCase):
    def test_frontier_advanced(self):
        fr = _load("runtime-frontier.json")
        self.assertGreaterEqual(fr["phase"], 45)
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 67)
        self.assertGreaterEqual(fr["enterable"], 33)
        self.assertGreaterEqual(fr["execution_runs"], 265)
        self.assertEqual(
            fr["first_frame"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")
        self.assertTrue(fr["phase45"]["allocator_still_opaque"])
        self.assertEqual(fr["phase45"]["blocked_external_unchanged"], 74)
        self.assertEqual(fr["phase45"]["injected_allocator_tests"], 0)

    def test_new_matrix_leaves_present(self):
        fr = _load("runtime-frontier.json")
        executed = set(fr["unique_uc_functions_executed_list"])
        for va in (
            "0x00A12850", "0x00A12860", "0x00A128A0",
            "0x00A12D10", "0x00A12D50", "0x00A12D90",
        ):
            self.assertIn(va, executed)
        # At least some newly enterable
        self.assertGreaterEqual(len(fr["phase45"]["enterable_new"]), 1)

    def test_matrix_chain(self):
        fr = _load("runtime-frontier.json")
        self.assertTrue(fr["phase45"]["matrix_chain_clean"])

    def test_family_regressions(self):
        fr = _load("runtime-frontier.json")
        reg = fr["phase45"]["regressions"]
        self.assertTrue(reg["family_a"])
        self.assertTrue(reg["family_b"])
        self.assertTrue(reg["family_c"])

    def test_candidate_inventory(self):
        inv = _load("phase45-candidate-inventory.json")
        self.assertGreaterEqual(len(inv["candidates"]), 6)
        addrs = {c["address"] for c in inv["candidates"]}
        self.assertIn("0x00A128A0", addrs)

    def test_execution_evidence(self):
        ev = _load("phase45-execution.json")
        self.assertGreaterEqual(ev["metrics_delta"]["unique_after"],
                                ev["metrics_delta"]["unique_before"])
        cleans = [r for r in ev["results"] if r.get("clean") and r["root"].startswith("0x00A1")]
        self.assertGreaterEqual(len(cleans), 4)


if __name__ == "__main__":
    unittest.main()
