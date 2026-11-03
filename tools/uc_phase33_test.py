#!/usr/bin/env python3
"""Phase 33 tests: GetPriorityClass + CreateSemaphoreA guest semantics."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase31_campaign as camp
import uc_harness31 as h

ANALYSIS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "analysis", "undercover")


class Metadata(unittest.TestCase):
    def test_frontiers(self):
        sync = json.load(open(os.path.join(ANALYSIS, "synchronization-frontier.json"),
                              encoding="utf-8"))
        proc = json.load(open(os.path.join(ANALYSIS, "process-handle-frontier.json"),
                              encoding="utf-8"))
        self.assertTrue(sync["create_semaphore_a"]["implemented"])
        self.assertTrue(proc["GetPriorityClass"]["implemented"])
        self.assertEqual(proc["priority_class_initial"], "NORMAL_PRIORITY_CLASS (0x20)")
        # Phase 33 left priority immutable; Phase 34 made it mutable via SetPriorityClass.
        self.assertIn("priority_class_mutable", proc)
        self.assertEqual(sync["crt_atexit"]["classification"], "BLOCKED_CRT_INITIALIZATION")
        self.assertFalse(sync["crt_atexit"]["implementation_attempted"])


class Classifier(unittest.TestCase):
    def test_gct_is_next_blocker_shape(self):
        view = {
            "blocked_kind": h.K_IMPORT, "blocked_va": 0x8A9F2E, "blocked_fn": 0x97F790,
            "depth_max": 3, "entered": [0x9E9160, 0x97F790], "clean": False, "fault_why": "",
        }
        res = camp.classify_outcome(0x9E9160, view, import_name="GetCurrentThread")
        res = camp.finalize_result(res, 3)
        self.assertEqual(res["result"], "EXECUTED_TO_NEXT_BLOCKER")


@unittest.skipUnless(os.environ.get("UC_PHASE33_LIVE") == "1", "set UC_PHASE33_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.H = camp.run_campaign()

    def test_ctor_past_gpc(self):
        row = next(r for r in self.rows if r["root"] == 0x9E9160)
        self.assertGreaterEqual(row["gpc_calls"], 1)
        self.assertNotEqual(row.get("import"), "GetPriorityClass")
        # Phase 33 stopped on GetCurrentThread; Phase 34 advances past priority APIs.
        self.assertIn(row.get("import"),
                      ("GetCurrentThread", "QueryPerformanceCounter",
                       "QueryPerformanceFrequency", "SleepEx"))
        self.assertFalse(row["clean"])

    def test_semaphore_path_clean(self):
        row = next(r for r in self.rows if r["root"] == 0x97BB30)
        self.assertGreaterEqual(row["sem_calls"], 1)
        self.assertGreaterEqual(row["sem_count"], 1)
        self.assertEqual(row["result"], "EXECUTED_CHAIN")
        self.assertTrue(row["clean"])
        self.assertGreaterEqual(row["depth_max"], 4)

    def test_ebc70_still_clean(self):
        row = next(r for r in self.rows if r["root"] == 0x9EBC70)
        self.assertEqual(row["result"], "EXECUTED_CHAIN")

    def test_no_diag_noop(self):
        for r in self.rows:
            self.assertEqual(r.get("stubs") or [], [])


if __name__ == "__main__":
    unittest.main()
