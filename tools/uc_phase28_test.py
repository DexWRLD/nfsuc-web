#!/usr/bin/env python3
"""Phase 28: reverse-call / ctor depth + ordinary execution.

Depth-3: 0x009E9160 → 0x009E9990 → 0x009E7710
Depth-2 BSS: 0x0072D640 → 0x00721050 / 0x007212F0 / 0x00721070 → protected
Does not start nfs.exe.
"""
import ctypes
import os
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
import uc_code_analyze as uca
import uc_phase7_test as p7
import uc_phase28 as p28

ROOT = p7.ROOT
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

CTOR = 0x009E9160
MID = 0x009E9990
BASE = 0x009E7710
HELPER_9460 = 0x009E9460
BSS = 0x0072D640
GET_TAB = 0x00721050
MIX = 0x007212F0
XOR = 0x00721070
PROT = 0x0072C190

CTOR_SET = {CTOR, MID, BASE, HELPER_9460}
BSS_SET = {BSS, GET_TAB, MIX, XOR}


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_analysis_unit():
    info = uca.read_inputs(GAME)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    pe = p28.load("nfs-pe.json")
    fmap = p28.load("function-map.json")
    by = {int(r["va"], 16): r for r in fmap["functions"]}
    pred = p28.build_pred_index(by)

    track = p28.analyze_a52(info["bytes"], info["text_va"], cs, pe, pred)
    expect(track["producer_classification"] == "NO_ORDINARY_INIT_PATH_FOUND", "track a stop")
    expect(track["enterable"] is False, "a52 not enterable")
    expect(len(track["e8_callers"]) == 0, "no e8")

    rev = p28.reverse_frontier(by, pred)
    expect(any(r["seed"] == "0x00721070" for r in rev), "reverse seed")
    expect(p28.enterability_cost("ordinary_ctor") < p28.enterability_cost("unknown"), "cost")
    expect(p28.enterability_cost("protected") >= 100, "blocked cost")
    expect(p28.chain_potential({"calls": ["0x1"] * 5, "insns": 100}, 1) > 50, "chain pot")

    census = p28.constructor_census(by, info["bytes"], info["text_va"], cs)
    expect(any(c["va"] == p28.hx(CTOR) for c in census["proven_constructors"]), "proven ctor")
    expect(any(c["class"] == "POD_BUILDER" for c in census["pod_builders"]), "pod")

    # caller contract propagation: 72d640 passes stack args into 7212f0/721070
    row = by[BSS]
    expect("0x00721070" in (row.get("calls") or []), "bss calls xor")
    print("phase28 analysis unit tests ok")


def instrument(code, addr):
    match = re.search(r"void (sub_[0-9a-f]+)\(CPU \*restrict c\) \{", code)
    if not match:
        sys.exit("no def %08x" % addr)
    name = match.group(1)
    code = code.replace(
        "void %s(CPU *restrict c) {" % name,
        "void %s_impl(CPU *restrict c) {\n"
        "    note_enter(0x%08xu);\n"
        "    if (abort_run) { POP32(c->eip); return; }\n"
        "    uc_fn_enter(0x%08xu, c);" % (name, addr, addr),
        1)

    def repl_ret(m):
        extra = m.group(1) or ""
        return ("depth_now--; uc_fn_leave(0x%08xu, c); "
                "POP32(c->eip);%s return;" % (addr, extra))

    code = re.sub(r"POP32\(c->eip\);( c->esp \+= \d+u;)? return;", repl_ret, code)

    def repl_call(m):
        target = int(m.group(1), 16)
        return "uc_direct(0x%08xu, c)" % target

    code = re.sub(r"sub_([0-9a-f]+)\(c\)", repl_call, code)
    code = re.sub(
        r"MR32\(([^;]*?)\) = \(([^;]*?)\);",
        r"uc_guest_store32(\1, (uint32_t)(\2), 0);",
        code)
    code = re.sub(
        r"MR8\(([^;]*?)\) = \(([^;]*?)\);",
        r"uc_guest_store8(\1, (uint8_t)(\2));",
        code)
    code = re.sub(
        r"MRF32\(([^;]*?)\) = ([^;]+);",
        r"uc_guest_storef32(\1, \2);",
        code)
    return name, code


def build_source(bodies):
    decls, switch = [], []
    for addr, name, _c in bodies:
        decls.append("void %s_impl(CPU *restrict c);" % name)
        switch.append("    case 0x%08xu: %s_impl(c); break;" % (addr, name))
    joined = "\n".join(c for _a, _n, c in bodies)
    return r'''
#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"
#include <stddef.h>

uint8_t *g_mem;
int _fltused;
guest_fn_t g_dtab[DISPATCH_TEXT_SIZE];
static int uc_hle_fail, uc_direct_fail, abort_run, blocked_kind;
static uint32_t blocked_va;
static uint32_t entered[16];
static int entered_n, depth_now, depth_max;

''' + "\n".join(decls) + r'''

void *memset(void *dst, int v, size_t n) {
    unsigned char *p = (unsigned char *)dst; while (n--) *p++ = (unsigned char)v; return dst;
}
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst; const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++; return dst;
}
static void zero_bytes(void *p, unsigned n) { memset(p, 0, n); }
static void uc_guest_storef32(uint32_t addr, float value) {
    uint32_t bits; zero_bytes(&bits, 4); *(float *)&bits = value;
    uc_guest_store32(addr, bits, 0);
}
static void note_visit(uint32_t fn) {
    int i;
    for (i = 0; i < entered_n; i++) if (entered[i] == fn) return;
    if (entered_n < 16) entered[entered_n++] = fn;
}
static void note_enter(uint32_t fn) {
    depth_now++;
    if (depth_now > depth_max) depth_max = depth_now;
    note_visit(fn);
}
static void note_block(uint32_t va, int kind) {
    if (!blocked_kind) { blocked_kind = kind; blocked_va = va; }
    abort_run = 1;
}
static void stub_ret(CPU *c) { POP32(c->eip); }
static void stub_ret4(CPU *c) { POP32(c->eip); c->esp += 4u; }
static void stub_ret8(CPU *c) { POP32(c->eip); c->esp += 8u; }
static void uc_direct(uint32_t target, CPU *c) {
    if (abort_run) { POP32(c->eip); return; }
    switch (target) {
''' + "\n".join(switch) + r'''
    /* Stubs: visit only — do not inflate ordinary nesting depth. */
    case 0x009773c0u: note_visit(0x009773c0u); stub_ret8(c); return;
    case 0x00977e20u: note_visit(0x00977e20u); stub_ret8(c); return;
    case 0x009eb980u: note_visit(0x009eb980u); stub_ret(c); return;
    case 0x0097fcd0u: note_visit(0x0097fcd0u); stub_ret8(c); return;
    case 0x009777d0u:
        note_visit(0x009777d0u);
        note_block(0x009777d0u, 1); /* IMPORT/IAT */
        stub_ret(c);
        return;
    case 0x00977800u: note_block(0x00977800u, 1); stub_ret4(c); return;
    case 0x009e8ad0u: note_visit(0x009e8ad0u); stub_ret(c); return;
    case 0x009e9000u: note_block(0x009e9000u, 2); stub_ret(c); return;
    case 0x00686030u: note_block(0x00686030u, 3); stub_ret(c); return;
    case 0x0072c190u:
        note_visit(0x0072c190u);
        note_block(0x0072c190u, 3); /* PROTECTED */
        stub_ret(c);
        return;
    default: uc_direct_fail = 1; note_block(target, 2); POP32(c->eip); return;
    }
}
''' + joined + r'''

void dispatch_indirect(CPU *c, uint32_t target) {
    (void)c;
    note_block(target, 1);
    /* leave ret addr; caller continues poorly — abort_run stops further work */
}
void dispatch_tail(CPU *c) { (void)c; }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    (void)c; (void)why; note_block(addr, 2);
}

typedef struct UcPhase28Out {
    uint32_t code, ctor_ok, bss_ok, entered_n, depth_max, closure;
    uint32_t blocked_kind, blocked_va;
    uint32_t has_ctor, has_mid, has_base;
} UcPhase28Out;

static int fail_line;
#define EXPECT(cond) do { if (!(cond)) { fail_line = __LINE__; return; } } while (0)
static void wr32(uint32_t a, uint32_t v) { uc_guest_store32(a, v, 0); }

static void run_ctor(UcPhase28Out *out) {
    CPU cpu, *c = &cpu;
    uint32_t S = 0x0300f000u;
    uint32_t obj = 0x03004000u;
    uint32_t src = 0x03004800u;
    int i;
    zero_bytes(c, sizeof *c);
    entered_n = depth_now = depth_max = 0;
    abort_run = blocked_kind = 0; blocked_va = 0;
    uc_hle_fail = uc_direct_fail = 0;
    for (i = 0; i < 0x300; i++) uc_guest_store8(obj + i, 0);
    for (i = 0; i < 0x40; i++) uc_guest_store8(src + i, 0);
    c->esp = S;
    c->ecx = obj;
    wr32(S, 0x00dec0deu);
    wr32(S + 4, src);
    wr32(S + 8, 0);
    sub_009e9160_impl(c);
    out->entered_n = (uint32_t)entered_n;
    out->depth_max = (uint32_t)depth_max;
    out->closure = (uint32_t)entered_n;
    out->blocked_kind = (uint32_t)blocked_kind;
    out->blocked_va = blocked_va;
    {
        int j, hc = 0, hm = 0, hb = 0;
        for (j = 0; j < entered_n; j++) {
            if (entered[j] == 0x009e9160u) hc = 1;
            if (entered[j] == 0x009e9990u) hm = 1;
            if (entered[j] == 0x009e7710u) hb = 1;
        }
        out->has_ctor = (uint32_t)hc;
        out->has_mid = (uint32_t)hm;
        out->has_base = (uint32_t)hb;
    }
    EXPECT(out->has_ctor && out->has_mid && out->has_base);
    EXPECT(depth_max >= 3);
    EXPECT(uc_access_fault.active == 0);
    out->ctor_ok = 1;
}

static void run_bss(UcPhase28Out *out) {
    CPU cpu, *c = &cpu;
    uint32_t S = 0x0300e000u;
    int i;
    zero_bytes(c, sizeof *c);
    entered_n = depth_now = depth_max = 0;
    abort_run = blocked_kind = 0; blocked_va = 0;
    uc_direct_fail = 0;
    c->esp = S;
    wr32(S, 0x00dec0deu);
    wr32(S + 4, 0x11111111u);
    wr32(S + 8, 0x22222222u);
    sub_0072d640_impl(c);
    out->entered_n = (uint32_t)entered_n;
    /* keep ctor depth_max if larger; record bss separately via closure field reuse */
    if ((uint32_t)depth_max > out->depth_max) out->depth_max = (uint32_t)depth_max;
    EXPECT(entered_n >= 4);
    EXPECT(depth_max >= 2);
    EXPECT(uc_access_fault.active == 0);
    out->bss_ok = 1;
    out->blocked_kind = (uint32_t)blocked_kind;
    out->blocked_va = blocked_va;
}

__declspec(dllexport) int uc_phase28_run(
    uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int nsections,
    UcPhase28Out *out) {
    int i; fail_line = 0; zero_bytes(out, sizeof *out);
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) if (uc_image_map(&sections[i])) return 2;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ|UC_MEM_WRITE)) return 3;
    if (uc_image_add_private("obj", 0x03004000u, 0x4000u, UC_MEM_READ|UC_MEM_WRITE)) return 4;
    run_ctor(out);
    if (fail_line) { out->code = (uint32_t)fail_line; return fail_line; }
    run_bss(out);
    out->code = (uint32_t)fail_line;
    return fail_line;
}
'''


class Out(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32), ("ctor_ok", ctypes.c_uint32),
        ("bss_ok", ctypes.c_uint32), ("entered_n", ctypes.c_uint32),
        ("depth_max", ctypes.c_uint32), ("closure", ctypes.c_uint32),
        ("blocked_kind", ctypes.c_uint32), ("blocked_va", ctypes.c_uint32),
        ("has_ctor", ctypes.c_uint32), ("has_mid", ctypes.c_uint32),
        ("has_base", ctypes.c_uint32),
    ]


def run_harness():
    info = uca.read_inputs(GAME)
    image = p7.read_sections(GAME)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    bodies = []
    for addr in (CTOR, MID, BASE, HELPER_9460, BSS, GET_TAB, MIX, XOR):
        code, _ = lifter.lift(addr)
        name, code = instrument(code, addr)
        bodies.append((addr, name, code))
    src = build_source(bodies)
    work = tempfile.mkdtemp(prefix="uc-phase28-")
    c_path = os.path.join(work, "phase28.c")
    with open(c_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(src)
    includes = ["-I", os.path.join(ROOT, "tests", "uc_host"),
                "-I", os.path.join(ROOT, "tests"),
                "-I", os.path.join(ROOT, "runtime")]
    common = [p7.clang(), "-c", "-std=c11", "-O0", "-ffreestanding", "-DUC_GUEST_CHECKED"] + includes
    objs = []
    for src_path in (c_path, os.path.join(ROOT, "runtime", "uc_import.c"),
                     os.path.join(ROOT, "runtime", "uc_image.c")):
        obj = os.path.join(work, os.path.basename(src_path) + ".o")
        proc = subprocess.run(common + ["-o", obj, src_path], capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            print(c_path)
            sys.exit(proc.returncode or 1)
        objs.append(obj)
    dll = os.path.join(work, "uc_phase28.dll")
    p7.link(objs, dll)
    lib = ctypes.CDLL(dll)
    mem = (ctypes.c_uint8 * p7.MEM_SIZE)()
    items, keep = [], []
    for sec in image["sections"]:
        if sec["name"] not in p7.ALLOWED and sec["name"] not in p7.PROTECTED:
            continue
        item = p7.Section()
        item.va, item.vsize, item.flags = sec["va"], sec["vsize"], sec["flags"]
        item.name = sec["name"].encode("ascii")
        if sec["raw"] is not None:
            buf = ctypes.create_string_buffer(sec["raw"])
            keep.append(buf)
            item.raw = ctypes.cast(buf, ctypes.c_void_p)
            item.raw_len = len(sec["raw"])
        items.append(item)
    out = Out()
    lib.uc_phase28_run.restype = ctypes.c_int
    rc = lib.uc_phase28_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        (p7.Section * len(items))(*items), len(items), ctypes.byref(out))
    for field, _t in Out._fields_:
        val = getattr(out, field)
        print(field, hex(val) if field.endswith("_va") else val)
    if rc != 0:
        lines = src.splitlines()
        print("failed", rc, lines[rc - 1] if 0 < rc <= len(lines) else "")
        print("work", work)
        sys.exit(1)
    expect(out.ctor_ok == 1, "ctor")
    expect(out.bss_ok == 1, "bss")
    expect(out.depth_max >= 3, "depth3")
    print("uc phase28 ctor-depth + bss tests passed")


def main():
    test_analysis_unit()
    run_harness()


if __name__ == "__main__":
    main()
