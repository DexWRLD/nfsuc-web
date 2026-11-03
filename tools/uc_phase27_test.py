#!/usr/bin/env python3
"""Phase 27: enterability contracts + ordinary execution chains.

Chain: mid-parent case body 0x00929972 → 0x00924D30.
Leaf: 0x00949920 early path (ret 0xc).
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
import uc_phase27 as p27

ROOT = p7.ROOT
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
FRAG = 0x00929972  # case-0 body of 0x00929900
CHILD = 0x00924D30
MATH949 = 0x00949920
THUNKS = {0x00AE5110: "cos", 0x00AE5140: "sin", 0x00AE5116: "sqrt"}


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_pre_entry_analysis():
    info = uca.read_inputs(GAME)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    c72 = p27.pre_entry_contract(info["bytes"], info["text_va"], cs, 0x0072EAE0)
    expect(c72["stop_why"] == "indirect", "72eae0 indirect")
    expect(0x18 in c72["this_field_disps"], "72eae0 this+0x18")
    c924 = p27.pre_entry_contract(info["bytes"], info["text_va"], cs, CHILD)
    expect(c924["calls"] == ["0x00AE5116"], "924 calls sqrt")
    prot = p27.classify_enterability(c72, {
        "protected": True,
        "indirect_class": "PROTECTED_INITIALIZED_CALLBACK",
    })
    expect(prot == "BLOCKED_PROTECTED_INIT", "protected")
    direct = p27.classify_enterability(
        c924, {"primitive_ok": True, "ctor_confidence": "STRONG"})
    expect(direct == "ENTERABLE_DIRECT", "enterable")
    # ctor recognition: static ordinary vtable vs protected slot
    expect(p27.section_at(
        __import__("json").load(open("analysis/undercover/nfs-pe.json", encoding="utf-8")),
        0x023AF9C8)["name"] == ".securom", "securom slot")
    print("pre-entry / classification / vtable-slot tests ok")


def instrument(code, addr):
    match = re.search(r"void (sub_[0-9a-f]+)\(CPU \*restrict c\) \{", code)
    if not match:
        sys.exit("no def %08x" % addr)
    name = match.group(1)
    code = code.replace(
        "void %s(CPU *restrict c) {" % name,
        "void %s_impl(CPU *restrict c) {\n"
        "    note_enter(0x%08xu);\n"
        "    uc_fn_enter(0x%08xu, c);" % (name, addr, addr),
        1)

    def repl_ret(m):
        extra = m.group(1) or ""
        return ("depth_now--; uc_fn_leave(0x%08xu, c); "
                "POP32(c->eip);%s return;" % (addr, extra))

    code = re.sub(r"POP32\(c->eip\);( c->esp \+= \d+u;)? return;", repl_ret, code)

    def repl_call(m):
        target = int(m.group(1), 16)
        if target in THUNKS:
            return m.group(0)
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
    thunks = "\n".join(
        "void sub_%08x(CPU *c) { uc_thunk(c, 0x%08xu); }" % (t, t) for t in THUNKS)
    return r'''
#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"
#include <stddef.h>

uint8_t *g_mem;
int _fltused;
static int uc_hle_fail, uc_direct_fail;
static uint32_t uc_cos_calls, uc_sin_calls, uc_sqrt_calls;
static uint32_t entered[8];
static int entered_n, depth_now, depth_max;
static UcHostUnary saved_sin, saved_cos, saved_sqrt;

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
static void note_enter(uint32_t fn) {
    int i; depth_now++;
    if (depth_now > depth_max) depth_max = depth_now;
    for (i = 0; i < entered_n; i++) if (entered[i] == fn) return;
    if (entered_n < 8) entered[entered_n++] = fn;
}
static void uc_direct(uint32_t target, CPU *c) {
    switch (target) {
''' + "\n".join(switch) + r'''
    default: uc_direct_fail = 1; return;
    }
}
static void uc_thunk(CPU *c, uint32_t thunk) {
    const UcImport *imp = uc_import_find(thunk);
    if (!imp || !uc_import_invoke(c, imp, 0)) uc_hle_fail = 1;
    else {
        if (thunk == 0x00AE5110u) uc_cos_calls++;
        if (thunk == 0x00AE5140u) uc_sin_calls++;
        if (thunk == 0x00AE5116u) uc_sqrt_calls++;
    }
}
''' + thunks + "\n" + joined + r'''

void dispatch_indirect(CPU *c, uint32_t target) { (void)c; (void)target; uc_direct_fail = 1; }
void dispatch_tail(CPU *c) { (void)c; }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    (void)c; (void)addr; (void)why; uc_direct_fail = 1;
}

typedef struct UcPhase27Out {
    uint32_t code, chain_ok, math_ok, entered_n, depth_max;
    uint32_t entered0, entered1;
    uint32_t cos_calls, sin_calls, sqrt_calls;
    uint32_t out_x, out_y, out_z, field_a4;
} UcPhase27Out;

static int fail_line;
#define EXPECT(cond) do { if (!(cond)) { fail_line = __LINE__; return; } } while (0)
static void wr32(uint32_t a, uint32_t v) { uc_guest_store32(a, v, 0); }
static void wrf(uint32_t a, float v) {
    uint32_t b; zero_bytes(&b, 4); *(float *)&b = v; wr32(a, b);
}
static uint32_t rdf(uint32_t a) { return *(uint32_t *)uc_guest_ptr(a, 4, 0); }

static void run_chain(UcPhase27Out *out) {
    CPU cpu, *c = &cpu;
    uint32_t S = 0x0300f000u;
    uint32_t obj = 0x03004000u;
    int i;
    zero_bytes(c, sizeof *c);
    entered_n = depth_now = depth_max = 0;
    uc_hle_fail = uc_direct_fail = 0;
    uc_cos_calls = uc_sin_calls = uc_sqrt_calls = 0;
    for (i = 0; i < 0x100; i++) uc_guest_store8(obj + i, 0);
    /* Mid-parent frame after push ebx (see 0x0092996A):
       [S+0]=ebx [S+4]=edi [S+8]=esi [S+0xC .. +0x28)=locals
       [S+0x28]=ret [S+0x2C..)=args. esi register = parent object. */
    c->esi = obj;
    c->esp = S;
    wr32(S + 0x00, 0xb0b0b0b0u);
    wr32(S + 0x04, 0xd1d1d1d1u);
    wr32(S + 0x08, obj);
    wrf(S + 0x2c, 3.0f);
    wrf(S + 0x14, 4.0f); /* read after sub esp,8 as esp+0x14 → S+0xc; put 4.0 at S+0xc */
    wrf(S + 0x0c, 4.0f);
    wrf(S + 0x38, 1.0f);
    wrf(S + 0x3c, 0.0f);
    wr32(S + 0x28, 0x00dec0deu);
    sub_00929972_impl(c);
    out->sqrt_calls = uc_sqrt_calls;
    out->entered_n = (uint32_t)entered_n;
    out->depth_max = (uint32_t)depth_max;
    out->entered0 = entered_n > 0 ? entered[0] : 0;
    out->entered1 = entered_n > 1 ? entered[1] : 0;
    out->out_x = rdf(obj + 0x7c);
    out->out_y = rdf(obj + 0x80);
    out->out_z = rdf(obj + 0x84);
    EXPECT(uc_hle_fail == 0);
    EXPECT(uc_direct_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(uc_sqrt_calls >= 1);
    EXPECT(entered_n >= 2);
    EXPECT(depth_max >= 2);
    out->chain_ok = 1;
}

static void run_math949(UcPhase27Out *out) {
    CPU cpu, *c = &cpu;
    uint32_t esp = 0x0300e000u;
    uint32_t obj = 0x03005000u;
    int i;
    zero_bytes(c, sizeof *c);
    uc_hle_fail = uc_direct_fail = 0;
    for (i = 0; i < 0x100; i++) uc_guest_store8(obj + i, 0);
    c->esp = esp;
    c->ecx = obj;
    wr32(esp, 0x00dec0deu);
    wrf(esp + 4, 0.5f);
    wrf(esp + 8, 0.25f);
    wrf(esp + 12, 4.0f);
    sub_00949920_impl(c);
    out->field_a4 = rdf(obj + 0xa4);
    out->cos_calls = uc_cos_calls;
    out->sin_calls = uc_sin_calls;
    EXPECT(uc_hle_fail == 0);
    EXPECT(uc_direct_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(c->eip == 0x00dec0deu);
    EXPECT(c->esp == esp + 16); /* pop ret + ret 0xC arg cleanup */
    out->math_ok = 1;
}

__declspec(dllexport) void uc_phase27_bind(UcHostUnary s, UcHostUnary co, UcHostUnary sq) {
    saved_sin = uc_host_sin = s;
    saved_cos = uc_host_cos = co;
    saved_sqrt = uc_host_sqrt = sq;
}
__declspec(dllexport) int uc_phase27_run(
    uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int nsections,
    UcPhase27Out *out) {
    int i; fail_line = 0; zero_bytes(out, sizeof *out);
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) if (uc_image_map(&sections[i])) return 2;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ|UC_MEM_WRITE)) return 3;
    if (uc_image_add_private("obj", 0x03004000u, 0x4000u, UC_MEM_READ|UC_MEM_WRITE)) return 4;
    run_chain(out);
    if (fail_line) { out->code = (uint32_t)fail_line; return fail_line; }
    run_math949(out);
    out->code = (uint32_t)fail_line;
    return fail_line;
}
'''


class Out(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32), ("chain_ok", ctypes.c_uint32),
        ("math_ok", ctypes.c_uint32), ("entered_n", ctypes.c_uint32),
        ("depth_max", ctypes.c_uint32), ("entered0", ctypes.c_uint32),
        ("entered1", ctypes.c_uint32), ("cos_calls", ctypes.c_uint32),
        ("sin_calls", ctypes.c_uint32), ("sqrt_calls", ctypes.c_uint32),
        ("out_x", ctypes.c_uint32), ("out_y", ctypes.c_uint32),
        ("out_z", ctypes.c_uint32), ("field_a4", ctypes.c_uint32),
    ]


def run_harness():
    info = uca.read_inputs(GAME)
    image = p7.read_sections(GAME)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    bodies = []
    for addr in (FRAG, CHILD, MATH949):
        code, _ = lifter.lift(addr)
        name, code = instrument(code, addr)
        bodies.append((addr, name, code))
    src = build_source(bodies)
    work = tempfile.mkdtemp(prefix="uc-phase27-")
    c_path = os.path.join(work, "phase27.c")
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
    dll = os.path.join(work, "uc_phase27.dll")
    p7.link(objs, dll)
    lib = ctypes.CDLL(dll)
    ucrt = ctypes.CDLL("ucrtbase.dll")
    unary = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_double)
    bound = []
    for name in ("sin", "cos", "sqrt"):
        fn = getattr(ucrt, name)
        fn.argtypes = [ctypes.c_double]
        fn.restype = ctypes.c_double
        bound.append(unary(fn))
    lib.uc_phase27_bind(*bound)
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
    lib.uc_phase27_run.restype = ctypes.c_int
    rc = lib.uc_phase27_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        (p7.Section * len(items))(*items), len(items), ctypes.byref(out))
    for field, _t in Out._fields_:
        val = getattr(out, field)
        if field.startswith("out_") or field == "field_a4":
            print(field, struct.unpack("<f", struct.pack("<I", val))[0])
        else:
            print(field, val if field in (
                "code", "chain_ok", "math_ok", "entered_n", "depth_max",
                "cos_calls", "sin_calls", "sqrt_calls") else hex(val))
    if rc != 0:
        lines = src.splitlines()
        print("failed", rc, lines[rc - 1] if 0 < rc <= len(lines) else "")
        print("work", work)
        sys.exit(1)
    print("uc phase27 chain+math tests passed")


def main():
    test_pre_entry_analysis()
    run_harness()


if __name__ == "__main__":
    main()
