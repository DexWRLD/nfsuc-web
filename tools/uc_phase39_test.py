#!/usr/bin/env python3
"""Phase 39 tests: object methods + constructor-published globals.

Graphics frozen. Live via UC_PHASE39_LIVE=1.
"""
from __future__ import annotations

import json
import os
import struct
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
LIST_A = 0x009E8400
LIST_B = 0x009E8460
EMBED = 0x009E83D0
CB = 0x009E78C0
OBJ = h.OBJ_BASE
SRC = h.SRC_BASE
VT_MAIN = 0x00C30E68
G_D1A4 = 0x0189D1A4
G_D198 = 0x0189D198


class Metadata(unittest.TestCase):
    def test_frontiers(self):
        post = json.load(open(os.path.join(
            ANALYSIS, "post-constructor-frontier.json"), encoding="utf-8"))
        glob = json.load(open(os.path.join(
            ANALYSIS, "global-publication-frontier.json"), encoding="utf-8"))
        fr = json.load(open(os.path.join(
            ANALYSIS, "runtime-frontier.json"), encoding="utf-8"))
        self.assertEqual(post["phase"], 39)
        self.assertTrue(post["runtime_vtable_check"]["matches_static"])
        self.assertEqual(post["runtime_vtable_check"]["slot14"], "0x009E9150")
        self.assertGreaterEqual(post["clean_stateful_sequences"], 6)
        self.assertGreaterEqual(post["longest_sequence"], 3)
        g0 = glob["globals"][0]
        self.assertEqual(g0["address"], "0x0189D1A4")
        self.assertEqual(g0["classification"], "FUNCTION_POINTER")
        self.assertTrue(g0["matches_constructor_write"])
        self.assertEqual(g0["runtime_value"], "0x009E78C0")
        self.assertIn("clean_stateful_sequences", fr)
        self.assertIn("proven_post_constructor_consumers", fr)
        self.assertGreaterEqual(fr["ordinary_execution_sequence_length"], 5)
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 53)


@unittest.skipUnless(os.environ.get("UC_PHASE39_LIVE") == "1", "set UC_PHASE39_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fmap = h.load_fmap()
        addrs = set()
        for a in (CTOR, SETTER, GETTER, RTTI, POD, LIST_A, LIST_B, EMBED, CB,
                  0x009E81C0, 0x97BB30, 0x9EBC70):
            addrs.add(a)
            addrs |= set(h.closure(a, fmap, limit=48))
        cls.H = h.Harness(addrs)

    def _ctor(self):
        return h.make_spec(CTOR, ecx=OBJ, args=(SRC, 0), ret_pop=8, zero=((SRC, 0x40),))

    def test_setter_getter_returns_0x5a(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor(), continue_state=False).clean)
        self.assertTrue(self.H.step(
            h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
            continue_state=True).clean)
        out = self.H.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.assertEqual(out.eax & 0xFF, 0x5A)
        self.assertEqual(self.H.read_u8(OBJ + 0xDC), 0x5A)
        self.H.end_sequence()

    def test_runtime_vtable_slots(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor(), continue_state=False).clean)
        vt = self.H.read_u32(OBJ)
        self.assertEqual(vt, VT_MAIN)
        self.assertEqual(self.H.read_u32(vt + 13 * 4), SETTER)
        self.assertEqual(self.H.read_u32(vt + 14 * 4), GETTER)
        self.assertEqual(self.H.read_u32(vt + 2 * 4), RTTI)
        self.H.end_sequence()

    def test_global_publication_values(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor(), continue_state=False).clean)
        self.assertEqual(self.H.read_u32(G_D1A4), 0x009E78C0)
        self.assertEqual(self.H.read_u32(G_D198), 0x009E77D0)
        self.assertEqual(self.H.read_u32(0x0189DA84), 0)
        self.H.end_sequence()

    def test_published_callback_early_exit(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor(), continue_state=False).clean)
        out = self.H.step(
            h.make_spec(CB, ecx=0, args=(0, 0, 0), ret_pop=0),
            continue_state=True)
        self.assertTrue(out.clean)
        self.H.end_sequence()

    def test_embed_clear_early_exit(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor(), continue_state=False).clean)
        self.assertEqual(self.H.read_u32(OBJ + 0xE0), 0)
        out = self.H.step(h.make_spec(EMBED, ecx=OBJ, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        self.H.end_sequence()

    def test_mut_chain_length_vs_depth(self):
        self.H.begin_sequence()
        self.assertTrue(self.H.step(self._ctor(), continue_state=False).clean)
        self.H.step(h.make_spec(SETTER, ecx=OBJ, args=(0x11,), ret_pop=4),
                    continue_state=True)
        g = self.H.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0),
                        continue_state=True)
        self.assertEqual(g.eax & 0xFF, 0x11)
        self.H.step(h.make_spec(RTTI, ecx=OBJ, ret_pop=0), continue_state=True)
        out = self.H.step(h.make_spec(LIST_A, ecx=OBJ, ret_pop=0),
                          continue_state=True)
        self.assertTrue(out.clean)
        # 5 sequential entrypoints; nested depth must stay bounded (not 5+)
        self.assertLessEqual(out.depth_max, 8)
        self.assertGreaterEqual(out.entered_n, 18)
        self.H.end_sequence()

    def test_reset_isolation(self):
        self.H.begin_sequence()
        self.H.step(self._ctor(), continue_state=False)
        self.H.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                    continue_state=True)
        self.assertEqual(self.H.read_u8(OBJ + 0xDC), 0x5A)
        self.H.end_sequence()
        out = self.H.run(self._ctor())
        self.assertTrue(out.clean)
        self.assertEqual(self.H.read_u8(OBJ + 0xDC), 0)
        self.assertEqual(out.sleepex_done, 5)
        ticks = out.qpc_ticks_lo | (out.qpc_ticks_hi << 32)
        self.assertEqual(ticks, 2_500_000)

    def test_campaign_ctor_clean(self):
        rows, _ = camp.run_campaign(harness=self.H)
        ctor = next(r for r in rows if r["root"] == CTOR)
        self.assertTrue(ctor["clean"])
        for r in rows:
            self.assertEqual(r.get("stubs") or [], [])


if __name__ == "__main__":
    unittest.main()
