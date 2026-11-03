#!/usr/bin/env python3
"""Phase 37 tests: MSVC absolute dword jump-table + JTSWITCH harness.

Graphics frozen. Static/lifter tests need the game image for table bytes.
Live campaign via UC_PHASE37_LIVE=1.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
import uc_code_analyze as uca
import uc_phase7_test as p7
import uc_phase31_campaign as camp
import uc_harness31 as h
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_REG_EAX

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

SWITCH_FN = 0x0097F9E0
JMP_SITE = 0x0097F9F5
CASE3 = 0x0097FA08
TABLE = 0x0097FA40
DEFAULT = 0x0097FA3D
CTOR = 0x009E9160


def _info():
    return uca.read_inputs(GAME)


class StaticTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.info = _info()
        cls.blob, cls.base = cls.info["bytes"], cls.info["text_va"]

    def test_capstone_jmp_form(self):
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        off = JMP_SITE - self.base
        insn = next(cs.disasm(self.blob[off:off + 16], JMP_SITE))
        self.assertEqual(insn.mnemonic, "jmp")
        self.assertEqual(insn.bytes.hex(), "ff248540fa9700")
        op = insn.operands[0]
        self.assertEqual(op.type, X86_OP_MEM)
        m = op.mem
        self.assertEqual(m.base, 0)
        self.assertEqual(m.index, X86_REG_EAX)
        self.assertEqual(m.scale, 4)
        self.assertEqual(m.disp & 0xFFFFFFFF, TABLE)

    def test_table_entries(self):
        ents = [struct.unpack_from("<I", self.blob, TABLE - self.base + 4 * i)[0]
                for i in range(7)]
        expected = [
            0x0097FA38, 0x0097FA38, 0x0097F9FC, 0x0097FA08,
            0x0097FA14, 0x0097FA20, 0x0097FA2C,
        ]
        self.assertEqual(ents, expected)
        for t in ents:
            self.assertTrue(self.base <= t < self.base + len(self.blob))

    def test_case3_is_phase36_stop(self):
        raw = struct.unpack_from("<I", self.blob, TABLE - self.base + 4 * 3)[0]
        self.assertEqual(raw, CASE3)

    def test_invalid_selector_not_in_table(self):
        # Indices outside 0..6 are not table entries; bound check → default.
        self.assertEqual(DEFAULT, 0x0097FA3D)
        # Production recognition uses cmp eax,6 → n+1 == 7 entries only.
        os.environ["JTSWITCH"] = "1"
        lifter = lift.RawLifter(self.blob, self.base, comments=False)
        lifter.lift(SWITCH_FN)
        _reg, _base, ents = lifter.jtab[JMP_SITE]
        self.assertEqual(len(ents), 7)
        self.assertNotIn(7, range(len(ents))[7:])  # no 8th case


class LifterJtSwitch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.info = _info()

    def test_without_jtswitch_is_dispatch_tail(self):
        os.environ.pop("JTSWITCH", None)
        lifter = lift.RawLifter(self.info["bytes"], self.info["text_va"], comments=False)
        code, _ = lifter.lift(SWITCH_FN)
        self.assertFalse(lifter.jtab)
        self.assertIn("DISPATCH_TAIL", code)
        self.assertNotIn("switch (c->eax)", code)

    def test_with_jtswitch_emits_cases(self):
        os.environ["JTSWITCH"] = "1"
        lifter = lift.RawLifter(self.info["bytes"], self.info["text_va"], comments=False)
        code, _ = lifter.lift(SWITCH_FN)
        self.assertIn(JMP_SITE, lifter.jtab)
        reg, base, ents = lifter.jtab[JMP_SITE]
        self.assertEqual(base, TABLE)
        self.assertEqual(len(ents), 7)
        self.assertEqual(ents[3], CASE3)
        self.assertIn("switch (c->eax)", code)
        self.assertIn("case 3u:", code)
        self.assertIn("L_0097fa08", code)
        # Runtime-checked table entry (not a guessed goto alone).
        self.assertIn("MR32(0x97fa4cu)", code)  # table+4*3
        self.assertIn("== 0x97fa08u", code)

    def test_harness_enables_jtswitch(self):
        # Source-level contract: Harness.__init__ sets the env before lift.
        src = open(os.path.join(ROOT, "tools", "uc_harness31.py"), encoding="utf-8").read()
        self.assertIn('os.environ["JTSWITCH"] = "1"', src)


class Metadata(unittest.TestCase):
    def test_indirect_frontier(self):
        path = os.path.join(ANALYSIS, "indirect-dispatch-frontier.json")
        if not os.path.isfile(path):
            self.skipTest("run uc_phase37.py first")
        fr = json.load(open(path, encoding="utf-8"))
        self.assertEqual(fr["switch_classification"], "ABSOLUTE_DWORD_JUMP_TABLE")
        self.assertEqual(fr["proof"], "PROVEN_JUMP_TABLE")
        self.assertEqual(fr["table_base_va"], "0x0097FA40")
        self.assertEqual(fr["entry_count"], 7)
        self.assertEqual(fr["runtime_selected_index"], 3)
        self.assertEqual(fr["runtime_selected_target"], "0x0097FA08")
        self.assertTrue(fr["runtime_selected_valid"])
        self.assertTrue(fr["audit"]["hardcoded_production_bypass_avoided"])
        self.assertTrue(fr["audit"]["correction_generic"])


@unittest.skipUnless(os.environ.get("UC_PHASE37_LIVE") == "1", "set UC_PHASE37_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.H = camp.run_campaign()

    def test_switch_case3_executes(self):
        # Legitimate selector 3: absolute table case body at 0x97FA08.
        OB = h.OBJ_BASE
        spec = h.make_spec(SWITCH_FN, ecx=OB, args=(3,), ret_pop=4, zero=((OB, 0x40),))
        out = self.H.run(spec)
        self.assertTrue(out.clean)
        self.assertIn(SWITCH_FN, [
            out.entered[i] for i in range(out.entered_n)])

    def test_invalid_selector_defaults_clean(self):
        OB = h.OBJ_BASE
        # eax=7 fails ja → default ret; must not read past table.
        spec = h.make_spec(SWITCH_FN, ecx=OB, args=(7,), ret_pop=4, zero=((OB, 0x40),))
        out = self.H.run(spec)
        self.assertTrue(out.clean)

    def test_ctor_clean_after_jtswitch(self):
        row = next(r for r in self.rows if r["root"] == CTOR)
        self.assertTrue(row["clean"])
        self.assertIn(row["result"], ("EXECUTED_CLEAN", "EXECUTED_CHAIN"))
        self.assertIn(SWITCH_FN, row["entered"])
        self.assertGreaterEqual(row["sleepex_done"], 5)
        ticks = row["qpc_ticks_lo"] | (row["qpc_ticks_hi"] << 32)
        self.assertEqual(ticks, 2_500_000)
        self.assertGreaterEqual(row["depth_max"], 4)
        self.assertGreaterEqual(row["unique_entered"], 15)

    def test_semaphore_still_clean(self):
        row = next(r for r in self.rows if r["root"] == 0x97BB30)
        self.assertTrue(row["clean"])

    def test_ebc70_still_clean(self):
        row = next(r for r in self.rows if r["root"] == 0x9EBC70)
        self.assertTrue(row["clean"])

    def test_no_stubs(self):
        for r in self.rows:
            self.assertEqual(r.get("stubs") or [], [])


if __name__ == "__main__":
    unittest.main()
