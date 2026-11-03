#!/usr/bin/env python3
"""Phase 40 tests: independent object families + real vs direct vtable dispatch.

Graphics frozen. Live via UC_PHASE40_LIVE=1.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_harness31 as h
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")

CTOR_A = 0x009E9160
SETTER = 0x009E9140
GETTER = 0x009E9150
CTOR_B = 0x009E98F0
COPY_B = 0x009E9990
RTTI_B = 0x009E9980
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE
POD = OBJ + 0x300
POD_DST = OBJ + 0x380
VT_POD = 0x00C30F2C
VT_MAIN = 0x00C30E68


class Metadata(unittest.TestCase):
    def test_frontiers_phase40(self):
        fr = json.load(open(os.path.join(
            ANALYSIS, "runtime-frontier.json"), encoding="utf-8"))
        fam = json.load(open(os.path.join(
            ANALYSIS, "object-family-frontier.json"), encoding="utf-8"))
        vt = json.load(open(os.path.join(
            ANALYSIS, "vtable-execution-frontier.json"), encoding="utf-8"))
        post = json.load(open(os.path.join(
            ANALYSIS, "post-constructor-frontier.json"), encoding="utf-8"))
        self.assertGreaterEqual(fr["phase"], 40)
        self.assertGreaterEqual(fam["phase"], 40)
        self.assertGreaterEqual(vt["phase"], 40)
        self.assertGreaterEqual(post["phase"], 40)
        self.assertIn("independent_object_families_executed", fr)
        self.assertIn("clean_independent_object_lifecycles", fr)
        self.assertIn("real_vtable_dispatches_executed", fr)
        self.assertGreaterEqual(fr["independent_object_families_executed"], 2)
        self.assertGreaterEqual(fr["clean_independent_object_lifecycles"], 2)
        self.assertEqual(fam["strongest_new_family"], "B_9E98F0_POD")
        self.assertTrue(vt["dispatch_infrastructure"]["sparse_uc_dtab"])
        self.assertFalse(
            vt["dispatch_infrastructure"]["counts_direct_entry_as_real_dispatch"])
        defs = fr.get("definitions") or {}
        self.assertIn("INDEPENDENT_OBJECT_FAMILIES_EXECUTED", defs)
        self.assertIn("REAL_VTABLE_DISPATCHES_EXECUTED", defs)

    def test_candidate_classification(self):
        fam = json.load(open(os.path.join(
            ANALYSIS, "object-family-frontier.json"), encoding="utf-8"))
        ranked = fam["ranked_constructor_candidates"]
        self.assertGreaterEqual(len(ranked), 10)
        top = next(r for r in ranked if r["va"] == "0x009E98F0")
        self.assertEqual(top["classification"], "PROVEN_ORDINARY_CONSTRUCTOR")
        self.assertEqual(top["ownership"], "CALLER_STORAGE")
        self.assertTrue(top["independent_of_9E9160"])
        b = next(f for f in fam["families"] if f["family_id"] == "B_9E98F0_POD")
        self.assertEqual(b["object_ownership"], "CALLER_STORAGE")
        self.assertEqual(b["extent"], "0x00000054")
        self.assertEqual(b["vtable"], ["0x00C30F2C"])

    def test_real_vs_direct_dispatch_metadata(self):
        vt = json.load(open(os.path.join(
            ANALYSIS, "vtable-execution-frontier.json"), encoding="utf-8"))
        self.assertIn("real_vtable_dispatches_executed", vt)
        # Direct guest entry of a vtable target must not alone count.
        self.assertIn("result", vt)
        if vt["real_vtable_dispatches_executed"] > 0:
            self.assertEqual(vt["result"]["status"], "EXECUTED_VTABLE_DISPATCH")
            self.assertEqual(vt["result"]["actual_virtual_caller"], "0x009E8E00")
            self.assertEqual(vt["result"]["slot"], 5)
            self.assertEqual(vt["result"]["resolved_target"], "0x009E8E00")


@unittest.skipUnless(os.environ.get("UC_PHASE40_LIVE") == "1", "set UC_PHASE40_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fmap = h.load_fmap()
        addrs = set()
        for a in (CTOR_A, SETTER, GETTER, CTOR_B, COPY_B, RTTI_B,
                  0x009E7710, 0x009E0880, 0x009E8E00, 0x009E8400, 0x009E7780):
            addrs.add(a)
            addrs |= set(h.closure(a, fmap, limit=48))
        cls.H = h.Harness(addrs)

    def _ctor_a(self):
        return h.make_spec(CTOR_A, ecx=OBJ, args=(SRC, 0), ret_pop=8,
                           zero=((SRC, 0x40),))

    def test_family_a_setter_getter_0x5a(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor_a(), continue_state=False).clean)
        self.assertTrue(self.H.step(
            h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
            continue_state=True).clean)
        out = self.H.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax & 0xFF, 0x5A)
        self.H.end_sequence()

    def test_family_b_independent_lifecycle(self):
        self.H.begin_sequence()
        out = self.H.step(h.make_spec(CTOR_B, ecx=POD, ret_pop=0),
                          continue_state=False)
        self.assertTrue(out.clean)
        self.assertEqual(self.H.read_u32(POD), VT_POD)
        self.assertEqual(out.eax, POD)
        out = self.H.step(h.make_spec(RTTI_B, ecx=POD, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax, 0x00C30F38)
        self.H.end_sequence()

    def test_family_b_copy_preserves_contract(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(
            h.make_spec(CTOR_B, ecx=POD, ret_pop=0), continue_state=False).clean)
        self.assertTrue(self.H.step(
            h.make_spec(COPY_B, ecx=POD_DST, args=(POD,), ret_pop=4),
            continue_state=True).clean)
        self.assertEqual(self.H.read_u32(POD_DST), VT_POD)
        self.assertEqual(self.H.read_u32(POD_DST + 0x2C),
                         self.H.read_u32(POD + 0x2C))
        out = self.H.step(h.make_spec(RTTI_B, ecx=POD_DST, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax, 0x00C30F38)
        self.H.end_sequence()

    def test_runtime_reset_independent(self):
        """Fresh ctor each sequence — no snapshot copy of prior final state."""
        self.H.begin_sequence()
        self.assertTrue(self.H.step(
            h.make_spec(CTOR_B, ecx=POD, ret_pop=0), continue_state=False).clean)
        vt1 = self.H.read_u32(POD)
        self.H.end_sequence()
        self.H.begin_sequence()
        self.assertEqual(self.H.read_u32(POD), 0)  # wiped by setup
        self.assertTrue(self.H.step(
            h.make_spec(CTOR_B, ecx=POD, ret_pop=0), continue_state=False).clean)
        self.assertEqual(self.H.read_u32(POD), vt1)
        self.H.end_sequence()

    def test_vtable_slot_resolution_family_a(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor_a(), continue_state=False).clean)
        vt = self.H.read_u32(OBJ)
        self.assertEqual(vt, VT_MAIN)
        self.assertEqual(self.H.read_u32(vt + 5 * 4), 0x009E8E00)
        self.assertEqual(self.H.read_u32(vt + 13 * 4), SETTER)
        self.assertEqual(self.H.read_u32(vt + 14 * 4), GETTER)
        self.H.end_sequence()

    def test_real_vtable_dispatch_increments_indirect(self):
        """Guest DISPATCH_CALL into slot5 must bump uc_indirect_enters."""
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor_a(), continue_state=False).clean)
        out = self.H.step(
            h.make_spec(0x009E8E00, ecx=OBJ, args=(OBJ,), ret_pop=4),
            continue_state=True)
        self.assertGreaterEqual(out.uc_indirect_enters, 1)
        # Continuation may fault; dispatch itself still happened.
        self.assertFalse(out.clean)
        self.H.end_sequence()

    def test_direct_entry_does_not_count_as_vtable_dispatch(self):
        """Invoking RTTI_B via harness root is DIRECT — uc_indirect_enters stays 0."""
        self.H.begin_sequence()
        self.assertTrue(self.H.step(
            h.make_spec(CTOR_B, ecx=POD, ret_pop=0), continue_state=False).clean)
        out = self.H.step(h.make_spec(RTTI_B, ecx=POD, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.uc_indirect_enters, 0)
        self.H.end_sequence()


if __name__ == "__main__":
    unittest.main()
