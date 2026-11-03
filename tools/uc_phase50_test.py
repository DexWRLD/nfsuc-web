#!/usr/bin/env python3
"""Phase 50 regression checks."""
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


class Phase50(unittest.TestCase):
    def test_frontier(self):
        fr = _load("runtime-frontier.json")
        self.assertEqual(fr["phase"], 50)
        self.assertEqual(fr["first_frame"], FIRST)
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 84)
        self.assertEqual(fr["phase50"]["blocked_external_unchanged"], 74)
        self.assertTrue(fr["phase50"]["dxt1_decoder_tests_passed"])
        self.assertFalse(fr["phase50"]["authentic_texture_preview_verified"])
        self.assertEqual(
            fr["phase50"]["cube_texture_correction"],
            "0x007513E2_CreateCubeTexture",
        )

    def test_authentic_status(self):
        a = _load("authentic-texture-status.json")
        self.assertEqual(a["synthetic_texture_decoder"], "WORKING")
        self.assertEqual(a["synthetic_mesh_viewer"], "WORKING")
        self.assertFalse(a["authentic_texture_source_identified"])
        self.assertFalse(a["authentic_first_frame_ready"])
        self.assertEqual(a["first_frame"], FIRST)

    def test_docs(self):
        for name in (
            "runtime-phase50.md",
            "phase51-handoff.md",
            "cube-texture-correction.json",
            "undercover-asset-browser-report.md",
        ):
            self.assertTrue(os.path.isfile(os.path.join(ANALYSIS, name)), name)

    def test_fixtures(self):
        fix = os.path.join(
            p7.ROOT, "web", "src", "static", "uc-fixtures", "textures",
        )
        self.assertTrue(os.path.isfile(os.path.join(fix, "solid-red-4x4.dxt1")))
        self.assertTrue(os.path.isfile(
            os.path.join(fix, "solid-red-4x4.dxt1.provenance.json")))


if __name__ == "__main__":
    unittest.main()
