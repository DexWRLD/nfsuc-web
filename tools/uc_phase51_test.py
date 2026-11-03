#!/usr/bin/env python3
"""Phase 51 regression checks."""
from __future__ import annotations

import json
import os
import unittest

import uc_phase7_test as p7

ANALYSIS = os.path.join(p7.ROOT, "analysis", "undercover")
FIRST = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"
DIALOG_SHA = "6c30b18704f937bb7257b44598bc66097de2bbc806e007d8f72c2d19765408a7"


def _load(name: str):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class Phase51(unittest.TestCase):
    def test_frontier(self):
        fr = _load("runtime-frontier.json")
        self.assertGreaterEqual(fr["phase"], 51)
        self.assertEqual(fr["first_frame"], FIRST)
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 84)
        self.assertEqual(fr["phase51"]["blocked_external_unchanged"], 74)
        self.assertTrue(fr["phase51"]["startup_preview_tests_passed"])
        self.assertEqual(fr["phase51"]["authentic_startup_asset_preview"], "READY")
        self.assertEqual(fr["phase51"]["authentic_intro_video_preview"], "IDENTIFIED_NO_DECODER")
        self.assertFalse(fr["phase51"]["bun_logo_payload_verified"])
        self.assertFalse(fr["phase51"]["vp6_decoder_implemented"])
        self.assertFalse(fr["phase51"]["browser_game_renderer_ready"])

    def test_statuses_independent(self):
        s = _load("startup-preview-status.json")
        self.assertEqual(s["AUTHENTIC_STARTUP_ASSET_PREVIEW"], "READY")
        self.assertEqual(s["AUTHENTIC_INTRO_VIDEO_PREVIEW"], "IDENTIFIED_NO_DECODER")
        self.assertEqual(s["FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"], "BLOCKED")

    def test_inventory_verified_image(self):
        inv = _load("startup-asset-inventory.json")
        v = inv["verified_startup_image"]
        self.assertEqual(v["payload_sha256"], DIALOG_SHA)
        self.assertEqual(v["relative_path"], "dialoglogo128x128.jpg")
        self.assertEqual(v["source_byte_offset"], 0)
        self.assertTrue(v["independently_decodable"])
        self.assertFalse(inv["fng_files_on_disk"])

    def test_docs(self):
        for name in (
            "runtime-phase51.md",
            "phase52-handoff.md",
            "startup-asset-inventory.json",
            "startup-preview-status.json",
            "undercover-intro-startup-report.md",
        ):
            self.assertTrue(os.path.isfile(os.path.join(ANALYSIS, name)), name)

    def test_fixtures(self):
        fix = os.path.join(
            p7.ROOT, "web", "src", "static", "uc-fixtures", "startup",
        )
        self.assertTrue(os.path.isfile(os.path.join(fix, "synthetic-logo.png")))
        self.assertTrue(os.path.isfile(
            os.path.join(fix, "synthetic-logo.png.provenance.json")))
        # Must not ship the authentic JPEG in-repo.
        self.assertFalse(os.path.isfile(os.path.join(fix, "dialoglogo128x128.jpg")))


if __name__ == "__main__":
    unittest.main()
