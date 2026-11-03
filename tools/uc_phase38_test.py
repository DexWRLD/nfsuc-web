#!/usr/bin/env python3
"""Phase 38 tests: constructor state + stateful post-constructor sequences.

Graphics frozen. Live via UC_PHASE38_LIVE=1.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_harness31 as h
import uc_phase31_campaign as camp
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")

CTOR = 0x009E9160
SETTER = 0x009E9140
GETTER = 0x009E9150
RTTI = 0x009E7780
POD = 0x009E9980
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE
OBJ_SIZE = 0x248
VT_MAIN = 0x00C30E68
VT_POD = 0x00C30F2C


class Metadata(unittest.TestCase):
    def test_frontiers(self):
        ctor = json.load(open(os.path.join(ANALYSIS, "constructor-state-frontier.json"),
                              encoding="utf-8"))
        post = json.load(open(os.path.join(ANALYSIS, "post-constructor-frontier.json"),
                              encoding="utf-8"))
        fr = json.load(open(os.path.join(ANALYSIS, "runtime-frontier.json"),
                            encoding="utf-8"))
        self.assertEqual(ctor["phase"], 38)
        self.assertTrue(ctor["clean_termination"])
        self.assertEqual(ctor["known_object_storage_extent"], "0x00000248")
        self.assertTrue(ctor["reproducible_by_rerunning_ctor"])
        self.assertGreaterEqual(ctor["initialized_nonzero_dwords"], 1)
        self.assertEqual(ctor["highlights"]["vtable_plus0"], "0x00C30E68")
        self.assertTrue(post["reset_between_runs_validated"])
        self.assertGreaterEqual(post["strongest_consumer"]["result"] and 1, 1)
        self.assertEqual(
            post["strongest_consumer"]["result"], "EXECUTED_STATEFUL_SEQUENCE")
        self.assertIn("ordinary_execution_sequence_length", fr)
        self.assertIn("largest_stateful_sequence_coverage", fr)
        self.assertGreaterEqual(fr["ordinary_execution_sequence_length"], 3)
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 48)


@unittest.skipUnless(os.environ.get("UC_PHASE38_LIVE") == "1", "set UC_PHASE38_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fmap = h.load_fmap()
        addrs = set(h.closure(CTOR, fmap, limit=48))
        for a in (SETTER, GETTER, RTTI, POD, CTOR, 0x97BB30, 0x9EBC70):
            addrs.add(a)
            addrs |= set(h.closure(a, fmap, limit=24))
        cls.H = h.Harness(addrs)

    def test_ctor_regression_clean(self):
        out = self.H.run(h.make_spec(
            CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),)))
        self.assertTrue(out.clean)
        self.assertEqual(self.H.read_u32(OBJ), VT_MAIN)
        self.assertEqual(self.H.read_u32(OBJ + 4), VT_POD)
        self.assertGreaterEqual(out.sleepex_done, 5)
        ticks = out.qpc_ticks_lo | (out.qpc_ticks_hi << 32)
        self.assertEqual(ticks, 2_500_000)

    def test_ctor_before_after_fields(self):
        self.H.begin_sequence()
        before = self.H.read_bytes(OBJ, OBJ_SIZE)
        self.assertTrue(all(b == 0 for b in before))
        out = self.H.step(h.make_spec(
            CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),)),
            continue_state=False)
        self.assertTrue(out.clean)
        self.assertEqual(self.H.read_u32(OBJ), VT_MAIN)
        self.assertNotEqual(self.H.read_u32(OBJ + 0x240), 0xFFFFFFFF)
        self.H.end_sequence()

    def test_stateful_setter_getter(self):
        self.H.begin_sequence()
        o1 = self.H.step(h.make_spec(
            CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),)),
            continue_state=False)
        self.assertTrue(o1.clean)
        o2 = self.H.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                         continue_state=True)
        self.assertTrue(o2.clean)
        self.assertEqual(self.H.read_u8(OBJ + 0xDC), 0x5A)
        o3 = self.H.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0),
                         continue_state=True)
        self.assertTrue(o3.clean)
        self.assertEqual(o3.eax & 0xFF, 0x5A)
        # Sequence length 3; nested depth must not be inflated by sequencing.
        self.assertGreaterEqual(o3.entered_n, o1.entered_n)
        self.assertLessEqual(o3.depth_max, 8)
        self.H.end_sequence()

    def test_object_pointer_consistency_pod(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(h.make_spec(
            CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),)),
            continue_state=False).clean)
        out = self.H.step(h.make_spec(POD, ecx=OBJ + 4, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax, 0x00C30F38)
        self.H.end_sequence()

    def test_reset_between_independent_runs(self):
        self.H.begin_sequence()
        self.H.step(h.make_spec(
            CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),)),
            continue_state=False)
        self.H.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                    continue_state=True)
        self.assertEqual(self.H.read_u8(OBJ + 0xDC), 0x5A)
        self.H.end_sequence()
        out = self.H.run(h.make_spec(
            CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),)))
        self.assertTrue(out.clean)
        self.assertEqual(self.H.read_u8(OBJ + 0xDC), 0)

    def test_rtti_leaf(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(h.make_spec(
            CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),)),
            continue_state=False).clean)
        out = self.H.step(h.make_spec(RTTI, ecx=OBJ, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax, 0x00C30DE4)
        self.H.end_sequence()

    def test_campaign_regressions(self):
        rows, _ = camp.run_campaign(harness=self.H)
        ctor = next(r for r in rows if r["root"] == CTOR)
        self.assertTrue(ctor["clean"])
        sem = next(r for r in rows if r["root"] == 0x97BB30)
        self.assertTrue(sem["clean"])
        ebc = next(r for r in rows if r["root"] == 0x9EBC70)
        self.assertTrue(ebc["clean"])
        for r in rows:
            self.assertEqual(r.get("stubs") or [], [])


if __name__ == "__main__":
    unittest.main()
