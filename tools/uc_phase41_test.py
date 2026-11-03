#!/usr/bin/env python3
"""Phase 41 tests: target identity, Family B/C contracts, virtual continuation.

Graphics frozen. Live via UC_PHASE41_LIVE=1.
Fingerprint unit tests do not require the game install when metadata is present;
live hash re-verify is optional.
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
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE
POD = OBJ + 0x300
EXPORT_BUF = OBJ + 0x400
OBJ_C = OBJ + 0x480
ZERO_PTR = OBJ + 0x500
VT_POD = 0x00C30F2C
VT_C = 0x00C31180


def _load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class Metadata(unittest.TestCase):
    def test_target_provenance_metadata(self):
        prov = _load("target-provenance.json")
        self.assertEqual(prov["tooling_origin"], "NFSU2-WEB")
        self.assertEqual(prov["game_code_target"], "NFS_UNDERCOVER_PC")
        self.assertEqual(
            prov["expected"]["sha256"],
            "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd")
        self.assertEqual(prov["expected"]["image_base"], "0x00400000")
        self.assertEqual(prov["expected"]["entry_va"], "0x01FCA510")
        self.assertNotIn("input_path", prov)
        self.assertIn(prov["verification_status"], (
            "VERIFIED_UNDERCOVER_1_1_2_1",
            "TARGET_BINARY_NOT_AVAILABLE_FOR_REHASH",
        ))
        if prov["verification_status"] == "VERIFIED_UNDERCOVER_1_1_2_1":
            self.assertTrue(prov["sha256_match"])
            self.assertTrue(prov["ordinary_text_provenance"])
            self.assertTrue(all(s["ok"] for s in prov["ordinary_samples_checked"]))

    def test_expected_constants_stable(self):
        self.assertEqual(tv.EXPECTED_SHA256, (
            "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd"))
        self.assertEqual(tv.EXPECTED_IMAGE_BASE, 0x00400000)
        self.assertEqual(tv.EXPECTED_ENTRY_VA, 0x01FCA510)

    def test_frontier_metrics(self):
        fr = _load("runtime-frontier.json")
        fam = _load("object-family-frontier.json")
        vt = _load("vtable-execution-frontier.json")
        self.assertGreaterEqual(fr["phase"], 41)
        self.assertGreaterEqual(fr["independent_object_families_executed"], 3)
        self.assertGreaterEqual(fr["clean_independent_object_lifecycles"], 3)
        self.assertGreaterEqual(fr["nontrivial_object_lifecycles"], 2)
        self.assertEqual(fr["real_vtable_dispatches_executed"], 1)
        self.assertEqual(fr["clean_virtual_calls"], 0)
        self.assertEqual(fr["virtual_call_continuation_faults"], 1)
        self.assertIn("NONTRIVIAL_OBJECT_LIFECYCLES", fr["definitions"])
        b = next(f for f in fam["families"] if f["family_id"] == "B_9E98F0_POD")
        self.assertTrue(b["nontrivial"])
        self.assertEqual(b["strongest_nontrivial_consumer"]["va"], "0x009E9A30")
        self.assertEqual(
            vt["phase40_site"]["continuation_classification"],
            "INCORRECT_VTABLE_SLOT")
        self.assertTrue(vt["phase40_site"]["same_function_caller_target"])
        self.assertFalse(vt["phase40_site"]["clean_virtual_call"])

    def test_standalone_vs_embedded_classification(self):
        fam = _load("object-family-frontier.json")
        rows = fam.get("family_b_method_census") or []
        by = {r["va"]: r for r in rows}
        self.assertEqual(by["0x009E9A30"]["contract"], "STANDALONE_FAMILY_B")
        self.assertEqual(by["0x009E9CD0"]["contract"], "EMBEDDED_FAMILY_B")
        self.assertTrue(by["0x009E9A30"]["standalone_enterable"])
        self.assertFalse(by["0x009E9CD0"]["standalone_enterable"])


@unittest.skipUnless(os.environ.get("UC_PHASE41_LIVE") == "1", "set UC_PHASE41_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fmap = h.load_fmap()
        addrs = set()
        for a in (CTOR_A, SETTER, GETTER, CTOR_B, RTTI_B, EXPORT_B, CTOR_C, RTTI_C,
                  0x009E8E00, 0x009E7710, 0x009E0880, 0x009E8400, 0x009E7780):
            addrs.add(a)
            addrs |= set(h.closure(a, fmap, limit=48))
        cls.H = h.Harness(addrs)

    def _ctor_a(self):
        return h.make_spec(CTOR_A, ecx=OBJ, args=(SRC, 0), ret_pop=8,
                           zero=((SRC, 0x40),))

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

    def test_family_b_rtti_and_export(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(
            h.make_spec(CTOR_B, ecx=POD, ret_pop=0), continue_state=False).clean)
        self.assertEqual(self.H.read_u32(POD), VT_POD)
        out = self.H.step(h.make_spec(RTTI_B, ecx=POD, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax, 0x00C30F38)
        fields = [self.H.read_u32(POD + o) for o in (0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C)]
        out = self.H.step(
            h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4),
            continue_state=True)
        self.assertTrue(out.clean)
        dest = [self.H.read_u32(EXPORT_BUF + o) for o in (0, 4, 8, 0xC, 0x10, 0x14)]
        self.assertEqual(dest, fields)
        self.H.end_sequence()

    def test_family_c_rtti(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(
            h.make_spec(CTOR_C, ecx=OBJ_C, args=(0x11, 0x22, ZERO_PTR, 0x33),
                        ret_pop=0x10), continue_state=False).clean)
        self.assertEqual(self.H.read_u32(OBJ_C), VT_C)
        out = self.H.step(h.make_spec(RTTI_C, ecx=OBJ_C, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax, 0x00C31168)
        self.H.end_sequence()

    def test_vcall_continuation_fault_classified(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor_a(), continue_state=False).clean)
        vt = self.H.read_u32(OBJ)
        self.assertEqual(self.H.read_u32(vt + 0x14), 0x009E8E00)
        out = self.H.step(
            h.make_spec(0x009E8E00, ecx=OBJ, args=(OBJ,), ret_pop=4),
            continue_state=True)
        self.assertGreaterEqual(out.uc_indirect_enters, 1)
        self.assertFalse(out.clean)
        self.assertTrue(out.fault_active)
        self.H.end_sequence()

    def test_live_hash_if_input_present(self):
        path = tv.default_input_path()
        if not os.path.isfile(path):
            self.skipTest("Undercover input unavailable")
        result = tv.verify(path)
        self.assertEqual(result["verification_status"], "VERIFIED_UNDERCOVER_1_1_2_1")


if __name__ == "__main__":
    unittest.main()
