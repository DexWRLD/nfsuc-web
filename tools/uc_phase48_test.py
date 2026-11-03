#!/usr/bin/env python3
"""Phase 48 tests."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase7_test as p7

ANALYSIS = os.path.join(p7.ROOT, "analysis", "undercover")


def _load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class Phase48(unittest.TestCase):
    def test_frontier(self):
        fr = _load("runtime-frontier.json")
        self.assertGreaterEqual(fr["phase"], 48)
        self.assertEqual(
            fr["first_frame"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 82)
        self.assertGreaterEqual(fr["enterable"], 48)
        self.assertEqual(fr["phase48"]["blocked_external_unchanged"], 74)
        self.assertEqual(
            fr["phase48"]["asset_distribution"], "FIXTURE_PIPELINE_HARDENED")

    def test_new_leaves(self):
        fr = _load("runtime-frontier.json")
        executed = set(fr["unique_uc_functions_executed_list"])
        self.assertIn("0x00A12800", executed)
        self.assertIn("0x00A12810", executed)

    def test_node_validation_recorded(self):
        fr = _load("runtime-frontier.json")
        self.assertTrue(fr["phase48"]["node_uc_assets_passed"])
        self.assertTrue(fr["phase48"]["frontend_build_passed"])

    def test_help_dir_noted(self):
        note = _load("stray-help-dir-note.json")
        self.assertTrue(note.get("exists"))
        self.assertEqual(note.get("action"), "left_untracked")

    def test_family_regressions(self):
        fr = _load("runtime-frontier.json")
        reg = fr["phase48"]["regressions"]
        self.assertTrue(reg["family_a"])
        self.assertTrue(reg["family_b"])
        self.assertTrue(reg["family_c"])

    def test_readiness(self):
        r = _load("asset-distribution-readiness.json")
        self.assertIn(
            r["asset_distribution_readiness"],
            ("FIXTURE_PIPELINE_HARDENED", "PRIVATE_LAN_FIXTURE_HOST_READY"),
        )
        self.assertFalse(r["clean_pc_ux"]["authentic_play_enabled"])


if __name__ == "__main__":
    unittest.main()
