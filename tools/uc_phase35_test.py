#!/usr/bin/env python3
"""Phase 35 tests: deterministic guest QPC/QPF clock.

Graphics frozen. Pure unit tests need no game. Live campaign via UC_PHASE35_LIVE=1.
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
    uint32_t lo = MR32(addr), hi = MR32(addr + 4u);
    return ((uint64_t)hi << 32) | lo;
}

static UcImport QPC = {
    0x00B611F8, 0x00B611F8, "KERNEL32.dll", "QueryPerformanceCounter", -1,
    UC_ABI_STDCALL, 1, UC_HLE_QUERYPERFORMANCECOUNTER, UC_LOC_STACK, UC_LOC_EAX
};
static UcImport QPF = {
    0x00B611FC, 0x00B611FC, "KERNEL32.dll", "QueryPerformanceFrequency", -1,
    UC_ABI_STDCALL, 1, UC_HLE_QUERYPERFORMANCEFREQUENCY, UC_LOC_STACK, UC_LOC_EAX
};

__declspec(dllexport) int uc_p35_hle_tests(uint8_t *mem, uint32_t mem_size) {
    CPU cpu, *c = &cpu;
    uint32_t esp0, ebx0, esi0, edi0, buf = 0x03004000u;
    uint64_t a, b, freq;
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

    esp0 = 0x0300F000u;
    c->esp = esp0; c->eip = 0x11111111u;
    c->ebx = 0xBEEF0001u; c->esi = 0xBEEF0002u; c->edi = 0xBEEF0003u;
    ebx0 = c->ebx; esi0 = c->esi; edi0 = c->edi;

    /* initial QPC == 0 */
    push32(c, buf); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPC, 0)) fails += 1;
    if (c->eax != 1u) fails += 2;
    if (rd64(buf) != 0) fails += 4;
    if (c->esp != esp0) fails += 8;
    if (c->eip != 0x00DEC0DEu) fails += 16;
    if (c->ebx != ebx0 || c->esi != esi0 || c->edi != edi0) fails += 32;

    /* repeated at same virtual time */
    c->esp = esp0; push32(c, buf); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPC, 0) || rd64(buf) != 0) fails += 64;

    /* QPF = 10_000_000 */
    c->esp = esp0; push32(c, buf + 0x10u); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPF, 0)) fails += 128;
    freq = rd64(buf + 0x10u);
    if (freq != 10000000ull) fails += 256;
    c->esp = esp0; push32(c, buf + 0x10u); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPF, 0) || rd64(buf + 0x10u) != freq) fails += 512;

    /* advance 1 second → +10_000_000 ticks */
    if (!uc_guest_clock_advance_ns(1000000000ull)) fails += 1024;
    c->esp = esp0; push32(c, buf); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPC, 0)) fails += 2048;
    a = rd64(buf);
    if (a != 10000000ull) fails += 4096;
    if (a < 0) fails += 8192; /* monotonic vs initial 0 */

    /* another second */
    if (!uc_guest_clock_advance_ns(1000000000ull)) fails += 16384;
    c->esp = esp0; push32(c, buf); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPC, 0)) fails += 32768;
    b = rd64(buf);
    if (b != 20000000ull) fails += 65536;
    if (b < a) fails += 131072;
    if ((b - a) / freq != 1ull) fails += 262144;

    /* 32-bit low-word rollover: advance to just past 2^32 ticks */
    uc_guest_clock_reset();
    /* 0x100000000 ticks * 100 ns = 0x6400000000 ns */
    if (!uc_guest_clock_advance_ns(0x6400000000ull)) fails += 524288;
    c->esp = esp0; push32(c, buf); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &QPC, 0)) fails += 1048576;
    a = rd64(buf);
    if ((uint32_t)a != 0u) fails += 2097152;
    if ((uint32_t)(a >> 32) != 1u) fails += 4194304;

    /* invalid pointer */
    c->esp = esp0; push32(c, 0xFFFFFFF0u); push32(c, 0x00DEC0DEu);
    if (uc_import_invoke(c, &QPC, 0)) fails += 8388608;

    /* reset */
    uc_guest_clock_reset();
    if (uc_guest_clock_qpc() != 0) fails += 16777216;
    if (uc_guest_clock_qpf() != 10000000ull) fails += 33554432;
    if (uc_guest_clock_tsc() != 0) fails += 67108864;

    return fails;
}
'''


def build_hle_dll():
    work = tempfile.mkdtemp(prefix="uc-p35-")
    c_path = os.path.join(work, "p35_hle.c")
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
    dll = os.path.join(work, "uc_p35.dll")
    p7.link(objs, dll)
    return dll, work


class Metadata(unittest.TestCase):
    def test_frontiers(self):
        timing = json.load(open(os.path.join(ANALYSIS, "timing-frontier.json"),
                                encoding="utf-8"))
        self.assertEqual(timing["phase"], 35)
        self.assertEqual(timing["frequency_hz"], 10_000_000)
        self.assertTrue(timing["QueryPerformanceCounter"]["implemented"])
        self.assertTrue(timing["QueryPerformanceFrequency"]["legitimately_reached"])
        self.assertTrue(timing["SleepEx"]["legitimately_reached"])
        self.assertFalse(timing["SleepEx"]["implemented"])
        self.assertEqual(timing["SleepEx"]["classification"], "BLOCKED_ALERTABLE_WAIT")
        self.assertEqual(timing["scheduler"], "NONE")


class Classifier(unittest.TestCase):
    def test_sleepex_alertable(self):
        view = {
            "blocked_kind": h.K_IMPORT, "blocked_va": 0x8AB180, "blocked_fn": 0x97F790,
            "depth_max": 3, "entered": [0x9E9160, 0x97F790], "clean": False, "fault_why": "",
        }
        res = camp.classify_outcome(0x9E9160, view, import_name="SleepEx")
        res = camp.finalize_result(res, 3)
        self.assertEqual(res["result"], "EXECUTED_TO_NEXT_BLOCKER")
        self.assertEqual(res["blocker_result"], "BLOCKED_ALERTABLE_WAIT")


class HleSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll_path, cls.work = build_hle_dll()
        cls.lib = ctypes.CDLL(cls.dll_path)
        cls.lib.uc_p35_hle_tests.restype = ctypes.c_int
        cls.lib.uc_p35_hle_tests.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]

    def test_hle_suite(self):
        mem = (ctypes.c_uint8 * p7.MEM_SIZE)()
        rc = self.lib.uc_p35_hle_tests(
            ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE)
        self.assertEqual(rc, 0, "hle fail mask=0x%X" % (rc & 0xFFFFFFFF))


@unittest.skipUnless(os.environ.get("UC_PHASE35_LIVE") == "1", "set UC_PHASE35_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.H = camp.run_campaign()

    def test_ctor_past_qpc_to_sleepex(self):
        row = next(r for r in self.rows if r["root"] == 0x9E9160)
        self.assertGreaterEqual(row["qpc_calls"], 1)
        self.assertGreaterEqual(row["qpf_calls"], 1)
        self.assertEqual(row.get("import"), "SleepEx")
        self.assertEqual(row["result"], "EXECUTED_TO_NEXT_BLOCKER")
        self.assertEqual(row.get("blocker_result"), "BLOCKED_ALERTABLE_WAIT")
        self.assertFalse(row["clean"])

    def test_semaphore_path_clean(self):
        row = next(r for r in self.rows if r["root"] == 0x97BB30)
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
