#!/usr/bin/env python3
"""Phase 36 tests: deterministic SleepEx timeout-only waits.

Graphics frozen. Pure unit tests need no game. Live campaign via UC_PHASE36_LIVE=1.
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase31_campaign as camp
import uc_harness31 as h
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")

HLE_SRC = r'''
#include "cpu.h"
#include "uc_abi.h"
#include <stdint.h>

uint8_t *g_mem;
int _fltused;
guest_fn_t g_dtab[DISPATCH_TEXT_SIZE];

void uc_guest_store8(uint32_t addr, uint8_t value) {
    if (addr < 0x03100000u) g_mem[addr] = value;
}
void uc_guest_store32(uint32_t addr, uint32_t value, int *ok) {
    if (addr + 3u >= 0x03100000u) { if (ok) *ok = 0; return; }
    g_mem[addr] = (uint8_t)value;
    g_mem[addr+1] = (uint8_t)(value >> 8);
    g_mem[addr+2] = (uint8_t)(value >> 16);
    g_mem[addr+3] = (uint8_t)(value >> 24);
    if (ok) *ok = 1;
}
static void zero_cpu(CPU *c) {
    uint8_t *p = (uint8_t *)c; unsigned i;
    for (i = 0; i < sizeof(CPU); i++) p[i] = 0;
}
static void push32(CPU *c, uint32_t v) {
    c->esp -= 4u; MR32(c->esp) = v;
}
static uint64_t rd64(uint32_t addr) {
    return ((uint64_t)MR32(addr + 4u) << 32) | MR32(addr);
}

static UcImport SX = {
    0x00B61188, 0x00B61188, "KERNEL32.dll", "SleepEx", -1,
    UC_ABI_STDCALL, 2, UC_HLE_SLEEPEX, UC_LOC_STACK, UC_LOC_EAX
};
static UcImport QPC = {
    0x00B611F8, 0x00B611F8, "KERNEL32.dll", "QueryPerformanceCounter", -1,
    UC_ABI_STDCALL, 1, UC_HLE_QUERYPERFORMANCECOUNTER, UC_LOC_STACK, UC_LOC_EAX
};
static UcImport QPF = {
    0x00B611FC, 0x00B611FC, "KERNEL32.dll", "QueryPerformanceFrequency", -1,
    UC_ABI_STDCALL, 1, UC_HLE_QUERYPERFORMANCEFREQUENCY, UC_LOC_STACK, UC_LOC_EAX
};

__declspec(dllexport) int uc_p36_hle_tests(uint8_t *mem, uint32_t mem_size) {
    CPU cpu, *c = &cpu;
    uint32_t esp0, ebx0, esi0, edi0, buf = 0x03004000u;
    uint64_t before, after, freq;
    int fails = 0;
    if (mem_size < 0x03100000u) return -1;
    g_mem = mem;
    zero_cpu(c);
    uc_guest_limit = 0x03100000u;
    uc_tls_reset();
    uc_sync_reset();
    uc_process_reset();
    uc_thread_reset();
    uc_guest_clock_reset();
    uc_wait_reset();

    esp0 = 0x0300F000u;
    c->esp = esp0; c->eip = 0x11111111u;
    c->ebx = 0xAABB0001u; c->esi = 0xAABB0002u; c->edi = 0xAABB0003u;
    ebx0 = c->ebx; esi0 = c->esi; edi0 = c->edi;

    /* SleepEx(50, FALSE) — 500000 ticks */
    push32(c, 0); push32(c, 50u); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &SX, 0)) fails += 1;
    if (c->eax != 0u) fails += 2;
    if (c->esp != esp0) fails += 4;
    if (c->eip != 0x00DEC0DEu) fails += 8;
    if (c->ebx != ebx0 || c->esi != esi0 || c->edi != edi0) fails += 16;
    if (uc_guest_clock_qpc() != 500000ull) fails += 32;

    /* SleepEx(50, TRUE) no pending APC */
    uc_guest_clock_reset(); uc_wait_reset();
    c->esp = esp0; push32(c, 1u); push32(c, 50u); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &SX, 0) || c->eax != 0u) fails += 64;
    if (uc_guest_clock_qpc() != 500000ull) fails += 128;
    if (uc_wait_sleepex_completions() != 1u) fails += 256;

    /* repeated: two 50ms → 100ms */
    c->esp = esp0; push32(c, 1u); push32(c, 50u); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &SX, 0)) fails += 512;
    if (uc_guest_clock_qpc() != 1000000ull) fails += 1024;
    if (uc_wait_sleepex_completions() != 2u) fails += 2048;

    /* zero timeout: no invented elapsed */
    before = uc_guest_clock_qpc();
    c->esp = esp0; push32(c, 0); push32(c, 0); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &SX, 0) || c->eax != 0u) fails += 4096;
    if (uc_guest_clock_qpc() != before) fails += 8192;

    /* infinite rejected */
    c->esp = esp0; push32(c, 0); push32(c, 0xFFFFFFFFu); push32(c, 0x00DEC0DEu);
    if (uc_import_invoke(c, &SX, 0)) fails += 16384;

    /* pending APC guard */
    uc_wait_set_pending_apc(1);
    c->esp = esp0; push32(c, 1u); push32(c, 50u); push32(c, 0x00DEC0DEu);
    if (uc_import_invoke(c, &SX, 0)) fails += 32768;
    uc_wait_set_pending_apc(0);

    /* QPC/QPF integration: 50ms sleep → Δ/freq = 0.05s exact in ticks */
    uc_guest_clock_reset(); uc_wait_reset();
    c->esp = esp0; push32(c, buf); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPC, 0)) fails += 65536;
    before = rd64(buf);
    c->esp = esp0; push32(c, 0); push32(c, 50u); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &SX, 0)) fails += 131072;
    c->esp = esp0; push32(c, buf); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPC, 0)) fails += 262144;
    after = rd64(buf);
    c->esp = esp0; push32(c, buf + 0x10u); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPF, 0)) fails += 524288;
    freq = rd64(buf + 0x10u);
    if (freq != 10000000ull) fails += 1048576;
    if (after - before != 500000ull) fails += 2097152;
    if ((after - before) * 1000ull / freq != 50ull) fails += 4194304;

    /* reset isolation */
    uc_guest_clock_reset(); uc_wait_reset();
    if (uc_guest_clock_qpc() != 0 || uc_wait_sleepex_completions() != 0) fails += 8388608;

    return fails;
}
'''


def build_hle_dll():
    work = tempfile.mkdtemp(prefix="uc-p36-")
    c_path = os.path.join(work, "p36_hle.c")
    with open(c_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(HLE_SRC)
    includes = ["-I", os.path.join(ROOT, "tests", "uc_host"),
                "-I", os.path.join(ROOT, "tests"),
                "-I", os.path.join(ROOT, "runtime")]
    common = [p7.clang(), "-c", "-std=c11", "-O0", "-ffreestanding", "-w"] + includes
    objs = []
    for src in (c_path, os.path.join(ROOT, "runtime", "uc_import.c")):
        obj = os.path.join(work, os.path.basename(src) + ".o")
        proc = subprocess.run(common + ["-o", obj, src], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr[:4000])
        objs.append(obj)
    dll = os.path.join(work, "uc_p36.dll")
    p7.link(objs, dll)
    return dll, work


class Metadata(unittest.TestCase):
    def test_frontiers(self):
        wait = json.load(open(os.path.join(ANALYSIS, "wait-frontier.json"), encoding="utf-8"))
        timing = json.load(open(os.path.join(ANALYSIS, "timing-frontier.json"), encoding="utf-8"))
        self.assertEqual(wait["phase"], 36)
        self.assertTrue(wait["SleepEx"]["implemented"])
        self.assertTrue(wait["SleepEx"]["timeout_only_eligible"])
        self.assertFalse(wait["SleepEx"]["apc_delivery"])
        self.assertEqual(
            wait["apc_provenance"]["pending_apc_classification"],
            "PROVEN_NO_PENDING_APC_IN_SUPPORTED_MODEL")
        self.assertTrue(timing["SleepEx"]["implemented"])
        self.assertEqual(wait["guest_wait_model"]["scheduler"], "NONE")


class Classifier(unittest.TestCase):
    def test_jump_table_is_indirect(self):
        view = {
            "blocked_kind": h.K_IMPORT, "blocked_va": 0x97FA08, "blocked_fn": 0x97F9E0,
            "depth_max": 4, "entered": [0x9E9160, 0x97F790, 0x97F9E0],
            "clean": False, "fault_why": "",
        }
        res = camp.classify_outcome(0x9E9160, view, import_name="\x10")
        res = camp.finalize_result(res, 4)
        self.assertEqual(res["result"], "EXECUTED_TO_NEXT_BLOCKER")
        self.assertEqual(res["blocker_result"], "BLOCKED_INDIRECT")


class HleSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll_path, cls.work = build_hle_dll()
        cls.lib = ctypes.CDLL(cls.dll_path)
        cls.lib.uc_p36_hle_tests.restype = ctypes.c_int
        cls.lib.uc_p36_hle_tests.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]

    def test_hle_suite(self):
        mem = (ctypes.c_uint8 * p7.MEM_SIZE)()
        rc = self.lib.uc_p36_hle_tests(
            ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE)
        self.assertEqual(rc, 0, "hle fail mask=0x%X" % (rc & 0xFFFFFFFF))


@unittest.skipUnless(os.environ.get("UC_PHASE36_LIVE") == "1", "set UC_PHASE36_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.H = camp.run_campaign()

    def test_ctor_past_sleepex(self):
        row = next(r for r in self.rows if r["root"] == 0x9E9160)
        self.assertGreaterEqual(row["sleepex_done"], 5)
        self.assertGreaterEqual(row["sleepex_calls"], 1)
        # Phase 36: past SleepEx to jump-table. Phase 37+: JTSWITCH → clean.
        self.assertIn(row["result"], (
            "EXECUTED_TO_NEXT_BLOCKER", "EXECUTED_CHAIN", "EXECUTED_CLEAN"))
        if row["result"] == "EXECUTED_TO_NEXT_BLOCKER":
            self.assertEqual(row.get("blocker_result"), "BLOCKED_INDIRECT")
            self.assertFalse(row["clean"])
        else:
            self.assertTrue(row["clean"])
        self.assertGreaterEqual(row["depth_max"], 4)
        self.assertGreaterEqual(row["unique_entered"], 12)
        ticks = row["qpc_ticks_lo"] | (row["qpc_ticks_hi"] << 32)
        self.assertEqual(ticks, row["sleepex_done"] * 500000)

    def test_semaphore_path_clean(self):
        row = next(r for r in self.rows if r["root"] == 0x97BB30)
        self.assertEqual(row["result"], "EXECUTED_CHAIN")
        self.assertTrue(row["clean"])

    def test_ebc70_still_clean(self):
        row = next(r for r in self.rows if r["root"] == 0x9EBC70)
        self.assertEqual(row["result"], "EXECUTED_CHAIN")

    def test_no_diag_noop(self):
        for r in self.rows:
            self.assertEqual(r.get("stubs") or [], [])


if __name__ == "__main__":
    unittest.main()
