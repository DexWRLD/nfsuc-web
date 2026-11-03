#!/usr/bin/env python3
"""Phase 31 tests: allocator provenance, ctor this-source, depth scoring,
required-state subclasses, clean-root / executed-ctor accounting.

Graphics frozen. Does not execute nfs.exe for pure unit tests. Optional live
campaign gated behind UC_PHASE31_LIVE=1.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase31 as p31
import uc_phase31_campaign as camp
import uc_harness31 as h


class FakeInsn:
    def __init__(self, mnemonic, op_str, operands=None, address=0):
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.operands = operands or []
        self.address = address


class Imm:
    def __init__(self, imm):
        from capstone.x86 import X86_OP_IMM
        self.type = X86_OP_IMM
        self.imm = imm


class AllocatorProvenance(unittest.TestCase):
    def test_protected_boundary_call(self):
        ev = {"writers": [{"site": "0x009E9414"}], "value_source": "PROTECTED_BOUNDARY_CALL"}
        self.assertEqual(p31.classify_allocator(ev), "PROTECTED_INITIALIZED_ALLOCATOR")

    def test_ordinary_path(self):
        ev = {"writers": [{"site": "x"}], "value_source": "ORDINARY_CONSTRUCTOR"}
        self.assertEqual(p31.classify_allocator(ev), "ORDINARY_INITIALIZABLE_ALLOCATOR")

    def test_standard_runtime(self):
        ev = {"writers": [{"site": "x"}], "value_source": "STANDARD_RUNTIME_API"}
        self.assertEqual(p31.classify_allocator(ev), "STANDARD_RUNTIME_INITIALIZABLE_ALLOCATOR")

    def test_external(self):
        ev = {"writers": [{"site": "x"}], "value_source": "EXTERNAL_BOUNDARY_CALL"}
        self.assertEqual(p31.classify_allocator(ev), "EXTERNAL_INITIALIZED_ALLOCATOR")

    def test_unknown_no_writers(self):
        self.assertEqual(p31.classify_allocator({"writers": [], "value_source": "X"}),
                         "UNKNOWN_RUNTIME_INITIALIZED_ALLOCATOR")

    def test_exactly_one_class(self):
        self.assertEqual(len(p31.CLASS_ALLOC), 5)

    def test_metadata_matches_classification(self):
        path = os.path.join(p31.ANALYSIS, "allocator-frontier.json")
        if not os.path.isfile(path):
            self.skipTest("allocator-frontier.json not yet written")
        data = p31.load("allocator-frontier.json")
        self.assertEqual(data["classification"], "PROTECTED_INITIALIZED_ALLOCATOR")
        self.assertEqual(data["ALLOCATOR_TARGET_RESOLVED"], "NO")
        self.assertEqual(data["ALLOCATOR_INIT_PATH_ORDINARY"], "NO")
        self.assertEqual(data["factory_9e9340_enterable"], "NO")
        self.assertTrue(data["stop_track_a"])
        self.assertFalse(data["implementation_attempted"])


class CtorThisSource(unittest.TestCase):
    def test_stack_storage(self):
        insns = [
            FakeInsn("lea", "ecx, [esp + 0x20]"),
            FakeInsn("call", "0x9e9160", [Imm(0x9E9160)]),
        ]
        self.assertEqual(p31.classify_this_source(insns, 1, {0x9EB870}), "STACK_STORAGE")

    def test_embedded_subobject(self):
        insns = [
            FakeInsn("lea", "ecx, [esi + 0x10]"),
            FakeInsn("call", "0x9e9160", [Imm(0x9E9160)]),
        ]
        self.assertEqual(p31.classify_this_source(insns, 1), "EMBEDDED_SUBOBJECT")

    def test_global_storage(self):
        insns = [
            FakeInsn("mov", "ecx, dword ptr [0x189da84]"),
            FakeInsn("call", "0x9e9160", [Imm(0x9E9160)]),
        ]
        self.assertEqual(p31.classify_this_source(insns, 1), "GLOBAL_STORAGE")

    def test_allocator_result(self):
        insns = [
            FakeInsn("call", "0x9eb870", [Imm(0x9EB870)]),
            FakeInsn("mov", "ecx, eax"),
            FakeInsn("call", "0x9e9160", [Imm(0x9E9160)]),
        ]
        self.assertEqual(
            p31.classify_this_source(insns, 2, {0x9EB870}), "ALLOCATOR_RESULT")

    def test_caller_argument_via_esi(self):
        # No write to esi before use → treated as CALLER_ARGUMENT at entry.
        insns = [
            FakeInsn("mov", "ecx, esi"),
            FakeInsn("call", "0x9e9160", [Imm(0x9E9160)]),
        ]
        self.assertEqual(p31.classify_this_source(insns, 1), "CALLER_ARGUMENT")


class DepthScoring(unittest.TestCase):
    def test_proven_depth_dominates(self):
        high = p31.score_candidate(proven_depth=3, enterable_descendants=1, chain_potential=10, cost=0)
        low = p31.score_candidate(proven_depth=0, enterable_descendants=8, chain_potential=80, cost=0)
        self.assertGreater(high, low)

    def test_strict_depth4_rejects_pending_import(self):
        d4, d5 = p31.depth_potential(
            frames_static=5, pending_imports=True, protected_before=False,
            unresolved_indirect=False, contract_defensible=True, unlifted_callees=False)
        self.assertFalse(d4)
        self.assertFalse(d5)

    def test_strict_depth4_accepts_clean_chain(self):
        d4, d5 = p31.depth_potential(
            frames_static=4, pending_imports=False, protected_before=False,
            unresolved_indirect=False, contract_defensible=True, unlifted_callees=False)
        self.assertTrue(d4)
        self.assertFalse(d5)

    def test_zero_depth4_acceptable_in_frontier(self):
        path = os.path.join(p31.ANALYSIS, "runtime-frontier.json")
        if not os.path.isfile(path):
            self.skipTest("runtime-frontier missing")
        fr = p31.load("runtime-frontier.json")
        # Phase 31 recorded zero strict depth-4 potential; later phases may
        # still report 0 under the same static rule even after proven depth-4 runs.
        self.assertGreaterEqual(int(fr.get("phase") or 0), 31)
        self.assertEqual(fr.get("enterable_with_depth_4_potential"), 0)


class RequiredStateSubclass(unittest.TestCase):
    def test_allocator_required_null_deref(self):
        view = {
            "blocked_kind": h.K_FAULT, "blocked_va": 0, "blocked_fn": 0x9EB870,
            "depth_max": 2, "entered": [0x9EB870, 0x9E9460], "clean": False,
            "fault_why": "unmapped guest access",
        }
        res = camp.classify_outcome(0x9EB870, view)
        self.assertEqual(res["subclass"], "ALLOCATOR_REQUIRED")
        self.assertEqual(res["hist"], "REQUIRED_STATE")

    def test_unknown_object_null_without_allocator(self):
        view = {
            "blocked_kind": h.K_FAULT, "blocked_va": 0, "blocked_fn": 0x1000,
            "depth_max": 1, "entered": [0x1000], "clean": False, "fault_why": "x",
        }
        res = camp.classify_outcome(0x1000, view)
        self.assertEqual(res["subclass"], "UNKNOWN_OBJECT")

    def test_import_finalize_to_next_blocker(self):
        view = {
            "blocked_kind": h.K_IMPORT, "blocked_va": 0x8A9EB4, "blocked_fn": 0x977420,
            "depth_max": 3, "entered": [1, 2, 3], "clean": False, "fault_why": "",
        }
        res = camp.classify_outcome(0x9E9160, view, import_name="InitializeCriticalSection")
        res = camp.finalize_result(res, 3)
        self.assertEqual(res["result"], "EXECUTED_TO_NEXT_BLOCKER")
        self.assertEqual(res["hist"], "IMPORT")
        self.assertEqual(res["blocker_result"], "BLOCKED_IMPORT")


class CleanRootAccounting(unittest.TestCase):
    def test_adds_clean_chain_without_stubs(self):
        rows = [
            {"root": 0x9E98F0, "result": "EXECUTED_CHAIN", "stubs": []},
            {"root": 0x9E9160, "result": "EXECUTED_TO_NEXT_BLOCKER", "stubs": []},
            {"root": 0xAAAA, "result": "EXECUTED_CLEAN", "stubs": [0x1]},
        ]
        got = camp.clean_root_accounting(rows, {0x949920})
        self.assertIn(0x9E98F0, got)
        self.assertIn(0x949920, got)
        self.assertNotIn(0x9E9160, got)
        self.assertNotIn(0xAAAA, got)

    def test_unique_excludes_stubs_until_real(self):
        prior = ["0x00949920", "0x009773C0", "0x0097FCD0"]
        entered = [0x009773C0, 0x009E98F0]
        uniq = p31.compute_unique(prior, entered)
        self.assertIn("0x009773C0", uniq)       # promoted: really entered
        self.assertNotIn("0x0097FCD0", uniq)    # still stub-only / never entered
        self.assertIn("0x009E98F0", uniq)


class ExecutedCtorAccounting(unittest.TestCase):
    def test_counts_entered_ctors_only(self):
        rows = [
            {"entered": [0x9E9160, 0x9E7710, 0x977420]},
            {"entered": [0x9E98F0, 0x9E7710]},
        ]
        got = camp.ctor_accounting(rows, {0x9E9160}, {0x9E9160, 0x9E7710, 0x9E98F0, 0x808770})
        self.assertEqual(set(got), {0x9E9160, 0x9E7710, 0x9E98F0})


@unittest.skipUnless(os.environ.get("UC_PHASE31_LIVE") == "1", "set UC_PHASE31_LIVE=1")
class LiveCampaign(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.H = camp.run_campaign()

    def test_allocator_negative_control(self):
        row = next(r for r in self.rows if r["root"] == 0x9EB870)
        self.assertEqual(row["subclass"], "ALLOCATOR_REQUIRED")

    def test_ctor_blocks_on_critical_section(self):
        """Phase 31 proved the no-stub ctor reaches ICS.

        After Phase 32+ HLE, ICS is implemented: require that the path still
        enters the sync wrapper chain and no longer stops on ICS itself.
        """
        row = next(r for r in self.rows if r["root"] == 0x9E9160)
        self.assertIn(0x00977420, row["entered"])
        self.assertGreaterEqual(row["depth_max"], 3)
        if row.get("ics_calls", 0) >= 1:
            self.assertNotEqual(row.get("import"), "InitializeCriticalSection")
            self.assertIn(row["result"], ("EXECUTED_TO_NEXT_BLOCKER", "EXECUTED_CHAIN",
                                          "EXECUTED_CLEAN"))
        else:
            self.assertEqual(row["import"], "InitializeCriticalSection")
            self.assertEqual(row["result"], "EXECUTED_TO_NEXT_BLOCKER")

    def test_clean_chains_exist(self):
        cleans = [r for r in self.rows if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")]
        self.assertGreaterEqual(len(cleans), 4)

    def test_diag_not_inflating(self):
        diag = camp.run_diagnostics(self.H)
        self.assertFalse(diag["counted_in_metrics"])
        self.assertEqual(diag["next_blocker_import"], "GetCurrentProcess")


if __name__ == "__main__":
    unittest.main()
