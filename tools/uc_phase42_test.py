#!/usr/bin/env python3
"""Phase 42 tests: Family C field contracts + typed virtual-call rejection.

Graphics frozen. Live via UC_PHASE42_LIVE=1.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_harness31 as h
import uc_phase7_test as p7
import uc_target_verify as tv

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")

CTOR_A = 0x009E9160
SETTER = 0x009E9140
GETTER = 0x009E9150
CTOR_B = 0x009E98F0
RTTI_B = 0x009E9980
EXPORT_B = 0x009E9A30
CTOR_C = 0x009EB350
RTTI_C = 0x009EB310
FIELD_C = 0x009EB2B0
CLEAR8_C = 0x009EB2D0
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE
POD = OBJ + 0x300
EXPORT_BUF = OBJ + 0x400
OBJ_C = OBJ + 0x480
ZERO_PTR = OBJ + 0x500
VT_C = 0x00C31180
VT_MAIN = 0x00C30E68


def _load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class Metadata(unittest.TestCase):
    def test_frontiers_phase42(self):
        fr = _load("runtime-frontier.json")
        fam = _load("object-family-frontier.json")
        vt = _load("vtable-execution-frontier.json")
        self.assertGreaterEqual(fr["phase"], 42)
        self.assertGreaterEqual(fr["nontrivial_object_lifecycles"], 3)
        self.assertGreaterEqual(fr["independent_object_families_executed"], 3)
        self.assertEqual(fr["clean_virtual_calls"], 0)
        self.assertEqual(fr["virtual_call_continuation_faults"], 1)
        self.assertTrue(fam.get("family_c_nontrivial"))
        c = next(f for f in fam["families"] if f["family_id"] == "C_9EB350")
        self.assertEqual(c["extent"], "0x0000001C")
        self.assertEqual(c["vtable"], "0x00C31180")
        self.assertEqual(c["strongest_nontrivial_consumer"]["va"], "0x009EB2B0")
        iface = vt["interface_provenance"]
        self.assertEqual(iface["receiver_classification"],
                         "SEPARATE_INTERFACE_ARGUMENT")
        self.assertFalse(iface["correct_provider_enterable"])
        self.assertTrue(iface["wrong_interface_evidence"][
            "missing_stack_argument_on_nested_self_call"])
        self.assertEqual(
            iface["wrong_interface_evidence"]["classification"],
            "WRONG_INTERFACE_TYPE")
        self.assertTrue(vt["dispatch_infrastructure"]["ok"])
        self.assertEqual(vt["dispatch_infrastructure"]["protected_registered"], [])
        self.assertFalse(vt.get("new_provider_dispatch_attempted"))

    def test_target_still_verified_or_unavailable(self):
        prov = _load("target-provenance.json")
        self.assertIn(prov["verification_status"], (
            "VERIFIED_UNDERCOVER_1_1_2_1",
            "TARGET_BINARY_NOT_AVAILABLE_FOR_REHASH",
        ))
        self.assertEqual(tv.EXPECTED_SHA256, (
            "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd"))


@unittest.skipUnless(os.environ.get("UC_PHASE42_LIVE") == "1", "set UC_PHASE42_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fmap = h.load_fmap()
        addrs = set()
        for a in (CTOR_A, SETTER, GETTER, CTOR_B, RTTI_B, EXPORT_B,
                  CTOR_C, RTTI_C, FIELD_C, CLEAR8_C, 0x009E8E00, 0x009E7710,
                  0x009E0880, 0x009E8400, 0x009E7780, 0x009EB770):
            addrs.add(a)
            addrs |= set(h.closure(a, fmap, limit=48))
        cls.H = h.Harness(addrs)

    def _ctor_a(self):
        return h.make_spec(CTOR_A, ecx=OBJ, args=(SRC, 0), ret_pop=8,
                           zero=((SRC, 0x40),))

    def _ctor_c(self):
        return h.make_spec(CTOR_C, ecx=OBJ_C, args=(0xAA, 0xBB, ZERO_PTR, 0xCC),
                           ret_pop=0x10)

    def test_family_a_0x5a(self):
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

    def test_family_b_export_dwords(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(
            h.make_spec(CTOR_B, ecx=POD, ret_pop=0), continue_state=False).clean)
        fields = [self.H.read_u32(POD + o)
                  for o in (0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C)]
        out = self.H.step(
            h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4),
            continue_state=True)
        self.assertTrue(out.clean)
        dest = [self.H.read_u32(EXPORT_BUF + o)
                for o in (0, 4, 8, 0xC, 0x10, 0x14)]
        self.assertEqual(dest, fields)
        self.assertEqual(dest, [0x40, 0x40, 0x40, 0x200, 0x200, 0x100])
        self.H.end_sequence()

    def test_family_c_layout_and_field_slot(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor_c(), continue_state=False).clean)
        self.assertEqual(self.H.read_u32(OBJ_C), VT_C)
        self.assertEqual(self.H.read_u32(OBJ_C + 0x10), 0xAA)
        self.assertEqual(self.H.read_u32(OBJ_C + 0x14), 0xBB)
        self.assertEqual(self.H.read_u32(OBJ_C + 0x18), 0xCC)
        self.assertEqual(self.H.read_u32(OBJ_C + 0xC), 0)
        out = self.H.step(h.make_spec(RTTI_C, ecx=OBJ_C, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax, 0x00C31168)
        out = self.H.step(h.make_spec(FIELD_C, ecx=OBJ_C, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax, OBJ_C + 0xC)
        self.assertEqual(self.H.read_u32(out.eax), 0)
        out = self.H.step(h.make_spec(CLEAR8_C, ecx=OBJ_C, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(self.H.read_u32(OBJ_C + 8), 0)
        self.H.end_sequence()

    def test_wrong_interface_rejected(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor_a(), continue_state=False).clean)
        self.assertEqual(self.H.read_u32(self.H.read_u32(OBJ) + 0x14), 0x009E8E00)
        out = self.H.step(
            h.make_spec(0x009E8E00, ecx=OBJ, args=(OBJ,), ret_pop=4),
            continue_state=True)
        self.assertGreaterEqual(out.uc_indirect_enters, 1)
        self.assertFalse(out.clean)
        self.assertTrue(out.fault_active)
        self.H.end_sequence()

    def test_family_c_slot3_wrong_without_interface(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor_c(), continue_state=False).clean)
        out = self.H.step(
            h.make_spec(0x009EB770, ecx=OBJ_C, args=(0, 0), ret_pop=8),
            continue_state=True)
        self.assertFalse(out.clean)
        self.H.end_sequence()


if __name__ == "__main__":
    unittest.main()
