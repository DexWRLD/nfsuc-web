#!/usr/bin/env python3
"""Phase 26: _CIsqrt HLE unit/ABI tests + real UC consumer 0x00924D30.

Does not start nfs.exe. Protected sections stay unmapped.
"""
import ctypes
import math
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

ROOT = p7.ROOT
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
CONSUMER = 0x00924D30
THUNK = 0x00AE5116


def instrument(code, addr):
    match = re.search(r"void (sub_[0-9a-f]+)\(CPU \*restrict c\) \{", code)
    if not match:
        sys.exit("no definition in %08x" % addr)
    name = match.group(1)
    code = code.replace(
        "void %s(CPU *restrict c) {" % name,
        "void %s_impl(CPU *restrict c) {\n    uc_fn_enter(0x%08xu, c);" % (name, addr),
        1)
    for pat in (
        "POP32(c->eip); return;",
        "POP32(c->eip); c->esp += 4u; return;",
        "POP32(c->eip); c->esp += 8u; return;",
        "POP32(c->eip); c->esp += 12u; return;",
    ):
        code = code.replace(
            pat,
            "uc_fn_leave(0x%08xu, c); %s" % (addr, pat),
        )

    def repl(found):
        target = int(found.group(1), 16)
        if target == THUNK:
            return found.group(0)
        return "uc_direct(0x%08xu, c)" % target

    code = re.sub(r"sub_([0-9a-f]+)\(c\)", repl, code)
    code = re.sub(
        r"MR32\(([^;]*?)\) = \(([^;]*?)\);",
        r"uc_guest_store32(\1, (uint32_t)(\2), 0);",
        code)
    code = re.sub(
        r"MR8\(([^;]*?)\) = \(([^;]*?)\);",
        r"uc_guest_store8(\1, (uint8_t)(\2));",
        code)
    if re.search(r"\bdispatch_indirect\s*\(", code):
        sys.exit("indirect dispatch in %08x" % addr)
    return name, code


def build_source(name, body):
    return r'''
#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"
#include <stddef.h>

uint8_t *g_mem;
int _fltused;
static int uc_hle_fail;
static int uc_direct_fail;
static uint32_t uc_sqrt_calls;
static UcHostUnary saved_sqrt;

void %s_impl(CPU *restrict c);

void *memset(void *dst, int v, size_t n) {
    unsigned char *p = (unsigned char *)dst;
    while (n--) *p++ = (unsigned char)v;
    return dst;
}
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}
static void zero_bytes(void *p, unsigned n) {
    memset(p, 0, n);
}
static void uc_direct(uint32_t target, CPU *c) {
    (void)target; (void)c; uc_direct_fail = 1;
}
static void uc_thunk(CPU *c, uint32_t thunk) {
    const UcImport *imp = uc_import_find(thunk);
    uc_esp_mark_at(3, c);
    uc_trace(UC_EV_IMPORT_CALL, uc_current_fn, c->eip, thunk, c);
    if (!imp || !uc_import_invoke(c, imp, 0)) uc_hle_fail = 1;
    else if (thunk == 0x00AE5116u) uc_sqrt_calls++;
    uc_esp_mark_at(4, c);
    uc_trace(UC_EV_IMPORT_RETURN, uc_current_fn, c->eip, thunk, c);
}
void sub_00ae5116(CPU *c) { uc_thunk(c, 0x00ae5116u); }

%s

void dispatch_indirect(CPU *c, uint32_t target) {
    (void)c; (void)target; uc_direct_fail = 1;
}
void dispatch_tail(CPU *c) { (void)c; }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    (void)c; (void)addr; (void)why; uc_direct_fail = 1;
}

typedef struct UcPhase26Out {
    uint32_t code;
    uint32_t unit_ok;
    uint32_t edge_ok;
    uint32_t before_rejected;
    uint32_t consumer_ok;
    uint32_t sqrt_calls;
    uint32_t hle_fail;
    uint32_t eip;
    uint32_t esp;
    uint32_t eax_preserved;
    uint32_t top_same;
    uint64_t st0_bits;
    uint32_t out_x;
    uint32_t out_y;
    uint32_t out_z;
    uint32_t hle_id;
} UcPhase26Out;

static int fail_line;
#define EXPECT(cond) do { if (!(cond)) { fail_line = __LINE__; return; } } while (0)

static uint64_t dbits(double v) {
    uint64_t u;
    zero_bytes(&u, sizeof u);
    *(double *)&u = v;
    return u;
}
static int near_f32(uint32_t bits, float expect) {
    float got;
    zero_bytes(&got, sizeof got);
    *(uint32_t *)&got = bits;
    float d = got - expect;
    if (d < 0) d = -d;
    return d < 1e-5f;
}
static void wr32(uint32_t addr, uint32_t value) {
    uc_guest_store32(addr, value, 0);
}
static void wrf32(uint32_t addr, float value) {
    uint32_t bits;
    zero_bytes(&bits, sizeof bits);
    *(float *)&bits = value;
    wr32(addr, bits);
}
static uint32_t rdf32bits(uint32_t addr) {
    return *(uint32_t *)uc_guest_ptr(addr, 4, 0);
}

static void run_unit(UcPhase26Out *out) {
    CPU cpu, *c = &cpu;
    const UcImport *imp;
    const double vals[5] = { 0.0, 1.0, 4.0, 0.25, 2.0 };
    double expect[5] = { 0.0, 1.0, 2.0, 0.5, 0.0 }; /* last filled via host */
    int i;
    uint32_t esp0, eax0;
    int32_t top0;
    zero_bytes(c, sizeof *c);
    imp = uc_import_find(0x00AE5116u);
    EXPECT(imp && imp->hle == UC_HLE_CISQRT);
    EXPECT(imp->arg_loc == UC_LOC_ST0 && imp->ret_loc == UC_LOC_ST0);
    EXPECT(imp->stack_dwords == 0 && imp->abi == UC_ABI_CDECL);
    out->hle_id = (uint32_t)imp->hle;
    EXPECT(uc_host_sqrt != 0);

    /* Before: unbound host rejects without corrupting ST0/ESP/EAX/TOP. */
    c->esp = 0x0300f000u;
    c->eax = 0xa5a5a5a5u;
    c->top = 7;
    ST(0) = 9.0;
    ST(1) = 1.25;
    esp0 = c->esp; eax0 = c->eax; top0 = c->top;
    PUSH32(0x00dec0deu);
    uc_host_sqrt = 0;
    uc_hle_fail = 0;
    uc_x87_fault.active = 0;
    EXPECT(uc_import_invoke(c, imp, 0) == 0);
    /* Failure restores ESP to the invoke-entry value (return still stacked). */
    EXPECT(c->esp == esp0 - 4u);
    EXPECT(c->eax == eax0);
    EXPECT(c->top == top0);
    EXPECT(dbits(ST(0)) == dbits(9.0));
    EXPECT(uc_x87_fault.active == 1);
    out->before_rejected = 1;
    uc_host_sqrt = saved_sqrt;

    expect[4] = uc_host_sqrt(2.0);
    for (i = 0; i < 5; i++) {
        zero_bytes(c, sizeof *c);
        c->esp = 0x0300f000u;
        c->eax = 0x11112222u;
        c->ebx = 0xb0b0b0b0u;
        c->esi = 0x51515151u;
        c->edi = 0xd1d1d1d1u;
        c->ebp = 0xebebebebu;
        c->top = 7;
        ST(0) = vals[i];
        ST(1) = 3.5;
        esp0 = c->esp; eax0 = c->eax; top0 = c->top;
        PUSH32(0x00dec0deu);
        EXPECT(uc_import_invoke(c, imp, 0) == 1);
        EXPECT(c->eip == 0x00dec0deu);
        EXPECT(c->esp == esp0); /* cdecl: ret popped, no stack args */
        EXPECT(c->eax == eax0);
        EXPECT(c->top == top0);
        EXPECT(dbits(ST(0)) == dbits(expect[i]));
        EXPECT(dbits(ST(1)) == dbits(3.5));
        EXPECT(c->ebx == 0xb0b0b0b0u && c->esi == 0x51515151u);
        EXPECT(c->edi == 0xd1d1d1d1u && c->ebp == 0xebebebebu);
    }
    out->unit_ok = 1;
    out->st0_bits = dbits(ST(0));
    out->eax_preserved = 1;
    out->top_same = 1;

    /* Edge: +0, +inf if representable, NaN, negative. */
    {
        double neg, nanv, pinf;
        uint64_t bits;
        zero_bytes(c, sizeof *c);
        c->esp = 0x0300f000u;
        c->eax = 0x33334444u;
        c->top = 7;
        ST(0) = 0.0;
        esp0 = c->esp;
        PUSH32(0x00dec0deu);
        EXPECT(uc_import_invoke(c, imp, 0) == 1);
        EXPECT(c->esp == esp0);
        EXPECT(dbits(ST(0)) == dbits(0.0));

        bits = 0x7ff0000000000000ull; /* +inf */
        zero_bytes(&pinf, sizeof pinf);
        *(uint64_t *)&pinf = bits;
        ST(0) = pinf;
        c->esp = 0x0300f000u;
        eax0 = c->eax; top0 = c->top; esp0 = c->esp;
        PUSH32(0x00dec0deu);
        EXPECT(uc_import_invoke(c, imp, 0) == 1);
        EXPECT(c->eax == eax0 && c->top == top0 && c->esp == esp0);
        /* Host sqrt(+inf) is typically +inf; do not require bit-identical. */

        bits = 0x7ff8000000000001ull; /* qNaN */
        zero_bytes(&nanv, sizeof nanv);
        *(uint64_t *)&nanv = bits;
        ST(0) = nanv;
        c->esp = 0x0300f000u;
        eax0 = c->eax; esp0 = c->esp;
        PUSH32(0x00dec0deu);
        EXPECT(uc_import_invoke(c, imp, 0) == 1);
        EXPECT(c->eax == eax0 && c->esp == esp0);
        /* Result is host-dependent NaN; guest integer regs untouched. */

        ST(0) = -4.0;
        c->esp = 0x0300f000u;
        eax0 = c->eax; top0 = c->top; esp0 = c->esp;
        PUSH32(0x00dec0deu);
        EXPECT(uc_import_invoke(c, imp, 0) == 1);
        EXPECT(c->eax == eax0 && c->top == top0 && c->esp == esp0);
        neg = ST(0);
        (void)neg; /* host may return NaN; state must stay coherent */
        out->edge_ok = 1;
    }
}

static void run_consumer(UcPhase26Out *out) {
    CPU cpu, *c = &cpu;
    uint32_t esp = 0x0300f000u;
    uint32_t obj = 0x03004000u;
    zero_bytes(c, sizeof *c);
    uc_hle_fail = 0;
    uc_direct_fail = 0;
    uc_sqrt_calls = 0;
    c->esp = esp;
    c->ecx = obj;
    c->eax = 0xa5a5a5a5u;
    wr32(esp, 0x00dec0deu);
    wrf32(esp + 4, 3.0f);
    wrf32(esp + 8, 4.0f);
    %s_impl(c);
    out->sqrt_calls = uc_sqrt_calls;
    out->hle_fail = (uint32_t)uc_hle_fail;
    out->eip = c->eip;
    out->esp = c->esp;
    out->out_x = rdf32bits(obj);
    out->out_y = rdf32bits(obj + 4);
    out->out_z = rdf32bits(obj + 8);
    EXPECT(uc_hle_fail == 0);
    EXPECT(uc_direct_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(uc_sqrt_calls == 1);
    EXPECT(c->eip == 0x00dec0deu);
    EXPECT(c->esp == esp + 12); /* entry had ret; ret 8 pops ret then frees 8 arg bytes */
    EXPECT(near_f32(out->out_x, 0.6f));
    EXPECT(near_f32(out->out_y, 0.8f));
    EXPECT(near_f32(out->out_z, 1.0f));
    out->consumer_ok = 1;
}

__declspec(dllexport) int uc_phase26_run(
    uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int nsections,
    UcPhase26Out *out) {
    int i;
    fail_line = 0;
    zero_bytes(out, sizeof *out);
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) {
        if (uc_image_map(&sections[i])) return 2;
    }
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE)) return 3;
    if (uc_image_add_private("obj", 0x03004000u, 0x1000u, UC_MEM_READ | UC_MEM_WRITE)) return 4;
    run_unit(out);
    if (fail_line) { out->code = (uint32_t)fail_line; return fail_line; }
    run_consumer(out);
    out->code = (uint32_t)fail_line;
    return fail_line;
}

__declspec(dllexport) void uc_phase26_bind(UcHostUnary sq) {
    saved_sqrt = uc_host_sqrt = sq;
}
''' % (name, body, name)


class Out(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32),
        ("unit_ok", ctypes.c_uint32),
        ("edge_ok", ctypes.c_uint32),
        ("before_rejected", ctypes.c_uint32),
        ("consumer_ok", ctypes.c_uint32),
        ("sqrt_calls", ctypes.c_uint32),
        ("hle_fail", ctypes.c_uint32),
        ("eip", ctypes.c_uint32),
        ("esp", ctypes.c_uint32),
        ("eax_preserved", ctypes.c_uint32),
        ("top_same", ctypes.c_uint32),
        ("st0_bits", ctypes.c_uint64),
        ("out_x", ctypes.c_uint32),
        ("out_y", ctypes.c_uint32),
        ("out_z", ctypes.c_uint32),
        ("hle_id", ctypes.c_uint32),
    ]


def main():
    info = uca.read_inputs(GAME)
    image = p7.read_sections(GAME)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    code, _ = lifter.lift(CONSUMER)
    name, code = instrument(code, CONSUMER)
    src = build_source(name, code)
    work = tempfile.mkdtemp(prefix="uc-phase26-")
    c_path = os.path.join(work, "phase26.c")
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
    dll = os.path.join(work, "uc_phase26.dll")
    p7.link(objs, dll)
    lib = ctypes.CDLL(dll)
    ucrt = ctypes.CDLL("ucrtbase.dll")
    unary = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_double)
    sq = getattr(ucrt, "sqrt")
    sq.argtypes = [ctypes.c_double]
    sq.restype = ctypes.c_double
    bound = unary(sq)
    lib.uc_phase26_bind(bound)

    mem = (ctypes.c_uint8 * p7.MEM_SIZE)()
    items = []
    keep = []
    for sec in image["sections"]:
        if sec["name"] not in p7.ALLOWED and sec["name"] not in p7.PROTECTED:
            continue
        item = p7.Section()
        item.va = sec["va"]
        item.vsize = sec["vsize"]
        item.flags = sec["flags"]
        item.name = sec["name"].encode("ascii")
        if sec["raw"] is not None:
            buf = ctypes.create_string_buffer(sec["raw"])
            keep.append(buf)
            item.raw = ctypes.cast(buf, ctypes.c_void_p)
            item.raw_len = len(sec["raw"])
        items.append(item)
    arr = (p7.Section * len(items))(*items)
    out = Out()
    lib.uc_phase26_run.restype = ctypes.c_int
    rc = lib.uc_phase26_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        arr, len(items), ctypes.byref(out))
    for field, _typ in Out._fields_:
        val = getattr(out, field)
        if field in ("st0_bits",):
            print(field, hex(val))
        elif field.startswith("out_"):
            print(field, struct.unpack("<f", struct.pack("<I", val))[0], hex(val))
        else:
            print(field, val if field in (
                "code", "unit_ok", "edge_ok", "before_rejected", "consumer_ok",
                "sqrt_calls", "hle_fail", "eax_preserved", "top_same", "hle_id"
            ) else hex(val))
    print("host_sqrt(2)", math.sqrt(2.0))
    if rc != 0:
        lines = src.splitlines()
        text = lines[rc - 1] if 0 < rc <= len(lines) else ""
        print("failed line", rc, text)
        print("work", work)
        sys.exit(1)
    print("uc phase26 _CIsqrt tests passed")


if __name__ == "__main__":
    main()
