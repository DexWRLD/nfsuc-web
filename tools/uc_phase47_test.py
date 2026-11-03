#!/usr/bin/env python3
"""Phase 47 tests: asset readiness artifacts + guest expansion metrics."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
STATIC = os.path.join(ROOT, "web", "src", "static")


def _load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class AssetDistribution(unittest.TestCase):
    def test_manifest_and_fixtures_present(self):
        self.assertTrue(os.path.isfile(os.path.join(STATIC, "uc-asset-manifest.json")))
        self.assertTrue(os.path.isfile(
            os.path.join(STATIC, "uc-fixtures", "startup", "readme.txt")))
        self.assertTrue(os.path.isfile(
            os.path.join(STATIC, "uc-fixtures", "startup", "boot-marker.json")))

    def test_manifest_unauthorized_production(self):
        with open(os.path.join(STATIC, "uc-asset-manifest.json"), encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertEqual(m["game"], "NFS_UNDERCOVER_PC")
        self.assertFalse(m["source"]["productionAssetsAuthorized"])
        self.assertEqual(m["source"]["mode"], "fixtures")
        self.assertTrue(any(a.get("license") == "copyrighted-unavailable" for a in m["assets"]))

    def test_readiness_artifact(self):
        r = _load("asset-distribution-readiness.json")
        self.assertIn(
            r["asset_distribution_readiness"],
            (
                "FIXTURE_PIPELINE_READY",
                "FIXTURE_PIPELINE_HARDENED",
                "PRIVATE_LAN_FIXTURE_HOST_READY",
            ),
        )
        self.assertEqual(
            r["production_undercover_assets"],
            "UNAVAILABLE_PENDING_AUTHORIZED_SOURCE")
        self.assertIn(
            r["browser_renderer_readiness"],
            (
                "SYNTHETIC_CLEAR_SMOKE_ONLY",
                "SYNTHETIC_TEXTURE_AND_MESH_PREVIEW",
                "STARTUP_LOGO_AND_SYNTHETIC_TEXTURE_PREVIEW",
            ),
        )
        self.assertEqual(
            r["first_frame"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")
        self.assertFalse(r["clean_pc_ux"]["authentic_play_enabled"])


class Phase47Execution(unittest.TestCase):
    def test_frontier(self):
        fr = _load("runtime-frontier.json")
        self.assertGreaterEqual(fr["phase"], 47)
        self.assertEqual(
            fr["first_frame"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 79)
        self.assertGreaterEqual(fr["enterable"], 45)
        self.assertGreaterEqual(fr["execution_runs"], 297)
        self.assertEqual(fr["phase47"]["blocked_external_unchanged"], 74)
        self.assertTrue(fr["phase47"]["allocator_still_opaque"])
        self.assertEqual(
            fr["phase47"]["asset_distribution"], "FIXTURE_PIPELINE_READY")

    def test_new_leaves(self):
        fr = _load("runtime-frontier.json")
        executed = set(fr["unique_uc_functions_executed_list"])
        for va in ("0x00A129B0", "0x00A12A40", "0x00A12DE0"):
            self.assertIn(va, executed)
        self.assertTrue(fr["phase47"]["chain_clean"])
        self.assertTrue(fr["phase47"]["p46_smoke_ok"])

    def test_phase46_preserved(self):
        fr = _load("runtime-frontier.json")
        executed = set(fr["unique_uc_functions_executed_list"])
        for va in ("0x00A128F0", "0x00A12940", "0x00A12E60", "0x00766100"):
            self.assertIn(va, executed)

    def test_family_regressions(self):
        fr = _load("runtime-frontier.json")
        reg = fr["phase47"]["regressions"]
        self.assertTrue(reg["family_a"])
        self.assertTrue(reg["family_b"])
        self.assertTrue(reg["family_c"])

    def test_asset_pipeline_tests_recorded(self):
        fr = _load("runtime-frontier.json")
        self.assertTrue(fr["phase47"]["asset_pipeline_tests_passed"])
        self.assertIn(fr["phase47"]["asset_pipeline_runner"], ("node", "python-mirror"))


if __name__ == "__main__":
    unittest.main()
