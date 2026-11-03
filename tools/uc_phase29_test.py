#!/usr/bin/env python3
"""Phase 29: TlsAlloc boundary + extended ordinary ctor chain.

Identifies KERNEL32!TlsAlloc at IAT 0x00B61138 via 0x009777D0.
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
import uc_phase29 as p29

ROOT = p7.ROOT
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

CTOR = 0x009E9160
MID = 0x009E9990
BASE = 0x009E7710
HELPER_9460 = 0x009E9460
TLS_WRAP = 0x009777D0
REG = 0x009E8AD0
SLOT = 0x00B61138


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_tlsalloc_identity():
    info = p29.identify_b61138()
    expect(info["symbol"] == "TlsAlloc", "symbol")
    expect(info["dll"] == "KERNEL32.dll", "dll")
    expect(info["classification"] == "STANDARD_WIN32_IMPORT", "class")
    expect(info["abi"] == "stdcall", "abi")
    expect(info["stack_dwords"] == 0, "nargs")
    expect(info["abi_confidence"] == "PROVEN", "conf")
    expect(info["hle_justified"] is True, "justified")
    wrap = p29.analyze_9777d0()
    expect(wrap["calls_iat"] == "0x00B61138", "call")
    expect(wrap["return_contract"] == "STORE_TO_THIS", "ret")
    print("TlsAlloc identity/ABI tests ok")


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
    code = re.sub(r"sub_([0-9a-f]+)\(c\)",
                  lambda m: "uc_direct(0x%08xu, c)" % int(m.group(1), 16), code)
    code = re.sub(
        r"MR32\(([^;]*?)\) = \(([^;]*?)\);",
        r"uc_guest_store32(\1, (uint32_t)(\2), 0);",
        code)
    code = re.sub(
        r"MR8\(([^;]*?)\) = \(([^;]*?)\);",
        r"uc_guest_store8(\1, (uint8_t)(\2));",
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
static int abort_run, blocked_kind;
static uint32_t blocked_va, tls_calls;
static uint32_t entered[24];
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
static void note_visit(uint32_t fn) {
    int i; for (i = 0; i < entered_n; i++) if (entered[i] == fn) return;
    if (entered_n < 24) entered[entered_n++] = fn;
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
    case 0x009773c0u: note_visit(0x009773c0u); stub_ret8(c); return;
    case 0x00977e20u: note_visit(0x00977e20u); stub_ret8(c); return;
    case 0x009eb980u: note_visit(0x009eb980u); stub_ret(c); return;
    case 0x0097fcd0u: note_visit(0x0097fcd0u); stub_ret8(c); return;
    case 0x00977800u: note_block(0x00977800u, 1); stub_ret4(c); return;
    case 0x009e9000u: note_block(0x009e9000u, 2); stub_ret(c); return;
    case 0x00686030u: note_block(0x00686030u, 3); stub_ret(c); return;
    default: note_block(target, 2); POP32(c->eip); return;
    }
}
void dispatch_indirect(CPU *c, uint32_t target) {
    const UcImport *imp = uc_import_find_dispatch_target(target);
    if (imp && imp->hle == UC_HLE_TLSALLOC) tls_calls++;
    if (imp && uc_import_invoke(c, imp, 0)) return;
    note_block(target ? target : 0x00B61138u, 1);
}
void dispatch_tail(CPU *c) { (void)c; }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    (void)c; (void)why; note_block(addr, 2);
}

''' + joined + r'''

typedef struct Out {
    uint32_t code, ok, entered_n, depth_max, closure;
    uint32_t tls_calls, tls_index, blocked_kind, blocked_va;
    uint32_t has_wrap, has_reg;
} Out;

static int fail_line;
#define EXPECT(cond) do { if (!(cond)) { fail_line = __LINE__; return; } } while (0)
static void wr32(uint32_t a, uint32_t v) { uc_guest_store32(a, v, 0); }

static void run_ctor(Out *out) {
    CPU cpu, *c = &cpu;
    uint32_t S = 0x0300f000u, obj = 0x03004000u, src = 0x03004800u;
    int i;
    zero_bytes(c, sizeof *c);
    entered_n = depth_now = depth_max = 0;
    abort_run = blocked_kind = 0; blocked_va = tls_calls = 0;
    for (i = 0; i < 0x300; i++) uc_guest_store8(obj + i, 0);
    for (i = 0; i < 0x40; i++) uc_guest_store8(src + i, 0);
    c->esp = S; c->ecx = obj;
    wr32(S, 0x00dec0deu); wr32(S + 4, src); wr32(S + 8, 0);
    sub_009e9160_impl(c);
    out->entered_n = (uint32_t)entered_n;
    out->depth_max = (uint32_t)depth_max;
    out->closure = (uint32_t)entered_n;
    out->tls_calls = tls_calls;
    out->tls_index = *(uint32_t *)uc_guest_ptr(obj + 0x240u, 4, 0);
    out->blocked_kind = (uint32_t)blocked_kind;
    out->blocked_va = blocked_va;
    {
        int j, hw = 0, hr = 0;
        for (j = 0; j < entered_n; j++) {
            if (entered[j] == 0x009777d0u) hw = 1;
            if (entered[j] == 0x009e8ad0u) hr = 1;
        }
        out->has_wrap = (uint32_t)hw;
        out->has_reg = (uint32_t)hr;
    }
    EXPECT(tls_calls >= 1);
    EXPECT(out->has_wrap);
    EXPECT(depth_max >= 3);
    EXPECT(entered_n > 4);
    /* 0x009E8AD0 writes ordinary .data callback slots; import fault must be clear. */
    EXPECT(uc_import_fault.active == 0);
    out->ok = 1;
}

__declspec(dllexport) int uc_phase29_run(
    uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int nsections, Out *out) {
    int i; fail_line = 0; zero_bytes(out, sizeof *out);
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) if (uc_image_map(&sections[i])) return 2;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ|UC_MEM_WRITE)) return 3;
    if (uc_image_add_private("obj", 0x03004000u, 0x4000u, UC_MEM_READ|UC_MEM_WRITE)) return 4;
    /* .rdata IAT may be read-only; unbound name RVA still resolves via
     * uc_import_find_dispatch_target. */
    (void)uc_import_bind_hle_iats();
    run_ctor(out);
    out->code = (uint32_t)fail_line;
    return fail_line;
}
'''


class Out(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32), ("ok", ctypes.c_uint32),
        ("entered_n", ctypes.c_uint32), ("depth_max", ctypes.c_uint32),
        ("closure", ctypes.c_uint32), ("tls_calls", ctypes.c_uint32),
        ("tls_index", ctypes.c_uint32), ("blocked_kind", ctypes.c_uint32),
        ("blocked_va", ctypes.c_uint32), ("has_wrap", ctypes.c_uint32),
        ("has_reg", ctypes.c_uint32),
    ]


def run_harness():
    info = uca.read_inputs(GAME)
    image = p7.read_sections(GAME)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    bodies = []
    for addr in (CTOR, MID, BASE, HELPER_9460, TLS_WRAP, REG):
        code, _ = lifter.lift(addr)
        name, code = instrument(code, addr)
        bodies.append((addr, name, code))
    src = build_source(bodies)
    work = tempfile.mkdtemp(prefix="uc-phase29-")
    c_path = os.path.join(work, "phase29.c")
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
    dll = os.path.join(work, "uc_phase29.dll")
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
    lib.uc_phase29_run.restype = ctypes.c_int
    rc = lib.uc_phase29_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        (p7.Section * len(items))(*items), len(items), ctypes.byref(out))
    for field, _t in Out._fields_:
        val = getattr(out, field)
        print(field, hex(val) if field.endswith("_va") or field == "tls_index" else val)
    if rc != 0:
        lines = src.splitlines()
        print("failed", rc, lines[rc - 1] if 0 < rc <= len(lines) else "")
        print("work", work)
        sys.exit(1)
    expect(out.ok == 1, "ok")
    expect(out.tls_calls >= 1, "tls")
    expect(out.depth_max >= 3, "depth")
    expect(out.closure > 4, "closure")
    print("uc phase29 TlsAlloc + ctor continuation passed")


def main():
    test_tlsalloc_identity()
    run_harness()


if __name__ == "__main__":
    main()
