#!/usr/bin/env python3
"""Phase 49 regression checks."""
from __future__ import annotations

import json
import os
import unittest

import uc_phase7_test as p7

ANALYSIS = os.path.join(p7.ROOT, "analysis", "undercover")
FIRST = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"


def _load(name: str):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class Phase49(unittest.TestCase):
    def test_frontier(self):
        fr = _load("runtime-frontier.json")
        self.assertEqual(fr["phase"], 49)
        self.assertEqual(fr["first_frame"], FIRST)
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 84)
        self.assertGreaterEqual(fr["enterable"], 50)
        self.assertEqual(fr["phase49"]["blocked_external_unchanged"], 74)
        self.assertTrue(fr["phase49"]["lan_server_tests_passed"])
        self.assertEqual(
            fr["phase49"]["lan_testing_readiness"], "PRIVATE_LAN_HTTPS_READY")

    def test_readiness(self):
        r = _load("asset-distribution-readiness.json")
        self.assertEqual(r["phase"], 49)
        self.assertEqual(
            r["asset_distribution_readiness"], "PRIVATE_LAN_FIXTURE_HOST_READY")
        self.assertEqual(r["lan_testing_readiness"], "PRIVATE_LAN_HTTPS_READY")
        self.assertEqual(r["first_frame"], FIRST)
        self.assertFalse(r["clean_pc_ux"]["authentic_play_enabled"])
        self.assertIn("BOOT", r["clean_pc_ux"]["boot_stages"])
        self.assertEqual(
            r["two_pc_validation"]["physical_second_pc"], "MANUAL_REQUIRED")

    def test_docs_exist(self):
        for name in ("runtime-phase49.md", "phase50-handoff.md", "lan-validation.json"):
            self.assertTrue(
                os.path.isfile(os.path.join(ANALYSIS, name)), name)

    def test_startup_script_exists(self):
        self.assertTrue(
            os.path.isfile(os.path.join(p7.ROOT, "Start-UndercoverLAN.ps1")))
        self.assertTrue(os.path.isfile(
            os.path.join(p7.ROOT, "web", "tools", "uc-lan-server.mjs")))
        self.assertTrue(os.path.isfile(
            os.path.join(p7.ROOT, "web", "docs", "uc-private-lan.md")))


class Phase49LanReadiness(unittest.TestCase):
    def test_opaque_backends_unchanged(self):
        # Documentation still cites FIRST_FRAME blocked status
        text = open(
            os.path.join(ANALYSIS, "runtime-phase49.md"), encoding="utf-8",
        ).read()
        self.assertIn(FIRST, text)
        self.assertIn("PRIVATE_LAN_HTTPS_READY", text)


if __name__ == "__main__":
    unittest.main()
