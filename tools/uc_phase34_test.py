#!/usr/bin/env python3
"""Phase 34 tests: GetCurrentThread pseudo-handle + guest priority semantics.

Graphics frozen. Pure unit tests need no game. Live campaign via UC_PHASE34_LIVE=1.
HLE semantics compile a tiny freestanding DLL against runtime/uc_import.c.
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
    uint8_t *p = (uint8_t *)c;
    unsigned i;
    for (i = 0; i < sizeof(CPU); i++) p[i] = 0;
}

static UcImport GCT = {
    0x00B611DC, 0x00B611DC, "KERNEL32.dll", "GetCurrentThread", -1,
    UC_ABI_STDCALL, 0, UC_HLE_GETCURRENTTHREAD, UC_LOC_NONE, UC_LOC_EAX
};
static UcImport GCP = {
    0x00B611AC, 0x00B611AC, "KERNEL32.dll", "GetCurrentProcess", -1,
    UC_ABI_STDCALL, 0, UC_HLE_GETCURRENTPROCESS, UC_LOC_NONE, UC_LOC_EAX
};
static UcImport GPC = {
    0x00B610E4, 0x00B610E4, "KERNEL32.dll", "GetPriorityClass", -1,
    UC_ABI_STDCALL, 1, UC_HLE_GETPRIORITYCLASS, UC_LOC_STACK, UC_LOC_EAX
};
static UcImport SPC = {
    0x00B610E8, 0x00B610E8, "KERNEL32.dll", "SetPriorityClass", -1,
    UC_ABI_STDCALL, 2, UC_HLE_SETPRIORITYCLASS, UC_LOC_STACK, UC_LOC_EAX
};
static UcImport GTP = {
    0x00B61184, 0x00B61184, "KERNEL32.dll", "GetThreadPriority", -1,
    UC_ABI_STDCALL, 1, UC_HLE_GETTHREADPRIORITY, UC_LOC_STACK, UC_LOC_EAX
};
static UcImport STP = {
    0x00B61180, 0x00B61180, "KERNEL32.dll", "SetThreadPriority", -1,
    UC_ABI_STDCALL, 2, UC_HLE_SETTHREADPRIORITY, UC_LOC_STACK, UC_LOC_EAX
};

static void push32(CPU *c, uint32_t v) {
    c->esp -= 4u;
    MR32(c->esp) = v;
}

__declspec(dllexport) int uc_p34_hle_tests(uint8_t *mem, uint32_t mem_size) {
    CPU cpu, *c = &cpu;
    uint32_t esp0, ebx0, esi0, edi0;
    int fails = 0;
    if (mem_size < 0x03100000u) return -1;
    g_mem = mem;
    zero_cpu(c);
    uc_tls_reset();
    uc_sync_reset();
    uc_process_reset();
    uc_thread_reset();

    /* --- GetCurrentThread pseudo-handle --- */
    esp0 = 0x0300F000u; c->esp = esp0; c->eip = 0x11111111u;
    c->ebx = 0xBEEF0001u; c->esi = 0xBEEF0002u; c->edi = 0xBEEF0003u;
    ebx0 = c->ebx; esi0 = c->esi; edi0 = c->edi;
    push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &GCT, 0)) fails += 100;
    if (c->eax != 0xFFFFFFFEu) fails += 1;
    if (c->esp != esp0) fails += 2;          /* stdcall 0 args */
    if (c->eip != 0x00DEC0DEu) fails += 4;
    if (c->ebx != ebx0 || c->esi != esi0 || c->edi != edi0) fails += 8;
    if (!uc_thread_pseudo_handle(c->eax)) fails += 16;
    if (uc_process_pseudo_handle(c->eax)) fails += 32;

    /* process vs thread distinction */
    c->esp = esp0; c->eip = 0x11111111u;
    push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &GCP, 0)) fails += 200;
    if (c->eax != 0xFFFFFFFFu) fails += 64;
    if (uc_thread_pseudo_handle(c->eax)) fails += 128;

    /* repeated GCT */
    c->esp = esp0; push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &GCT, 0) || c->eax != 0xFFFFFFFEu) fails += 256;

    /* priority consistency: GPC → SPC(REALTIME) → GPC */
    c->esp = esp0; push32(c, 0xFFFFFFFFu); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &GPC, 0) || c->eax != 0x20u) fails += 512;
    c->esp = esp0; push32(c, 0x100u); push32(c, 0xFFFFFFFFu); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &SPC, 0) || c->eax != 1u) fails += 1024;
    if (uc_process_priority_class() != 0x100u) fails += 2048;
    c->esp = esp0; push32(c, 0xFFFFFFFFu); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &GPC, 0) || c->eax != 0x100u) fails += 4096;

    /* invalid process handle / class */
    c->esp = esp0; push32(c, 0x100u); push32(c, 0x1234u); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &SPC, 0) || c->eax != 0u) fails += 8192;
    c->esp = esp0; push32(c, 0x99u); push32(c, 0xFFFFFFFFu); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &SPC, 0) || c->eax != 0u) fails += 16384;

    /* thread priority: GTP → STP(15) → GTP; invalid → ERROR_RETURN */
    uc_thread_reset();
    c->esp = esp0; push32(c, 0xFFFFFFFEu); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &GTP, 0) || (int32_t)c->eax != 0) fails += 32768;
    c->esp = esp0; push32(c, 0xFu); push32(c, 0xFFFFFFFEu); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &STP, 0) || c->eax != 1u) fails += 65536;
    if (uc_thread_priority() != 15) fails += 131072;
    c->esp = esp0; push32(c, 0xFFFFFFFEu); push32(c, 0x00DEC0DEu);
    if (!uc_import_invoke(c, &GTP, 0) || (int32_t)c->eax != 15) fails += 262144;
    c->esp = esp0; push32(c, 0xFFFFFFFFu); push32(c, 0x00DEC0DEu); /* process handle */
    if (!uc_import_invoke(c, &GTP, 0) || c->eax != 0x7FFFFFFFu) fails += 524288;

    /* reset restores defaults */
    uc_process_reset();
    uc_thread_reset();
    if (uc_process_priority_class() != 0x20u) fails += 1048576;
    if (uc_thread_priority() != 0) fails += 2097152;
    if (uc_active_guest_threads() != 1u) fails += 4194304;

    return fails;
}
'''


def build_hle_dll():
    work = tempfile.mkdtemp(prefix="uc-p34-")
    c_path = os.path.join(work, "p34_hle.c")
    with open(c_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(HLE_SRC)
    includes = ["-I", os.path.join(ROOT, "tests", "uc_host"),
                "-I", os.path.join(ROOT, "tests"),
                "-I", os.path.join(ROOT, "runtime")]
    common = [p7.clang(), "-c", "-std=c11", "-O0", "-ffreestanding", "-w"] + includes
    objs = []
    # Link only uc_import.c — guest store stubs live in HLE_SRC (no uc_image).
    for src in (c_path, os.path.join(ROOT, "runtime", "uc_import.c")):
        obj = os.path.join(work, os.path.basename(src) + ".o")
        proc = subprocess.run(common + ["-o", obj, src], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr[:4000])
        objs.append(obj)
    dll = os.path.join(work, "uc_p34.dll")
    p7.link(objs, dll)
    return dll, work


class Metadata(unittest.TestCase):
    def test_frontiers(self):
        pt = json.load(open(os.path.join(ANALYSIS, "process-thread-frontier.json"),
                            encoding="utf-8"))
        sync = json.load(open(os.path.join(ANALYSIS, "synchronization-frontier.json"),
                              encoding="utf-8"))
        self.assertEqual(pt["phase"], 34)
        self.assertTrue(pt["GetCurrentThread"]["implemented"])
        self.assertEqual(pt["thread_pseudo_handle"], "0xFFFFFFFE")
        self.assertEqual(pt["process_pseudo_handle"], "0xFFFFFFFF")
        self.assertTrue(pt["priority_class_mutable"])
        self.assertEqual(pt["scheduler"], "NONE")
        self.assertEqual(pt["guest_threads"], 1)
        self.assertEqual(pt["affinity_block"]["priority_class_0x100"],
                         "REALTIME_PRIORITY_CLASS (not HIGH=0x80)")
        self.assertTrue(pt["timing"]["QueryPerformanceCounter"]["reached_phase34"])
        self.assertFalse(pt["timing"]["timing_implementation_attempted"])
        self.assertEqual(sync["crt_atexit"]["classification"], "BLOCKED_CRT_INITIALIZATION")


class Classifier(unittest.TestCase):
    def test_qpc_is_timing_blocker(self):
        view = {
            "blocked_kind": h.K_IMPORT, "blocked_va": 0x8A9E84, "blocked_fn": 0x97F790,
            "depth_max": 3, "entered": [0x9E9160, 0x97F790], "clean": False, "fault_why": "",
        }
        res = camp.classify_outcome(0x9E9160, view, import_name="QueryPerformanceCounter")
        res = camp.finalize_result(res, 3)
        self.assertEqual(res["result"], "EXECUTED_TO_NEXT_BLOCKER")
        self.assertEqual(res["blocker_result"], "BLOCKED_TIMING")
        self.assertEqual(res["hist"], "TIMING")


class HleSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll_path, cls.work = build_hle_dll()
        cls.lib = ctypes.CDLL(cls.dll_path)
        cls.lib.uc_p34_hle_tests.restype = ctypes.c_int
        cls.lib.uc_p34_hle_tests.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]

    def test_hle_suite(self):
        mem = (ctypes.c_uint8 * p7.MEM_SIZE)()
        rc = self.lib.uc_p34_hle_tests(
            ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE)
        self.assertEqual(rc, 0, "hle fail mask=0x%X" % (rc & 0xFFFFFFFF))


@unittest.skipUnless(os.environ.get("UC_PHASE34_LIVE") == "1", "set UC_PHASE34_LIVE=1")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.H = camp.run_campaign()

    def test_ctor_past_gct_to_qpc(self):
        row = next(r for r in self.rows if r["root"] == 0x9E9160)
        self.assertGreaterEqual(row["gct_calls"], 1)
        self.assertGreaterEqual(row["gtp_calls"], 1)
        self.assertGreaterEqual(row["spc_calls"], 1)
        self.assertGreaterEqual(row["stp_calls"], 1)
        # Phase 34 stopped on QPC; Phase 35 advances past QPC/QPF.
        self.assertIn(row.get("import"),
                      ("QueryPerformanceCounter", "QueryPerformanceFrequency", "SleepEx"))
        self.assertEqual(row["result"], "EXECUTED_TO_NEXT_BLOCKER")
        self.assertFalse(row["clean"])
        # Priority/thread state may be mid-path or restored depending on stop point.
        self.assertIn(row["priority_class"], (0x20, 0x100))
        self.assertIn(row["thread_priority"], (0, 15))

    def test_semaphore_path_clean(self):
        row = next(r for r in self.rows if r["root"] == 0x97BB30)
        self.assertGreaterEqual(row["sem_calls"], 1)
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
