"""Phase 9 native harness.

Executes the x87 CRT contract required by the 0x00A124B0 closure.
The game executable is not started, and protected sections stay unmapped.
Host sin, cos, and acos are bound from the process C runtime. They are the
mathematical operation only. Results are not claimed to match MSVCR80 bits.
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

ROOT = p7.ROOT
FUNCS = (
    0x00A11AF0, 0x00A11B40, 0x00A11BD0, 0x00A11C50, 0x00A12280, 0x00A124B0,
)
THUNKS = {0x0087B2E0: "acos", 0x00AE5110: "cos", 0x00AE5140: "sin"}


def instrument(code, addr):
    match = re.search(r"void (sub_[0-9a-f]+)\(CPU \*restrict c\) \{", code)
    if not match:
        sys.exit("no definition in %08x" % addr)
    name = match.group(1)
    code = code.replace(
        "void %s(CPU *restrict c) {" % name,
        "void %s_impl(CPU *restrict c) {\n    uc_fn_enter(0x%08xu, c);\n    uc_note_fn(0x%08xu, c);"
        % (name, addr, addr),
        1)

    def repl_ret(found):
        extra = found.group(1) or ""
        return "uc_note_leave(); uc_fn_leave(0x%08xu, c); POP32(c->eip);%s return;" % (addr, extra)

    code = re.sub(r"POP32\(c->eip\);( c->esp \+= \d+u;)? return;", repl_ret, code)

    def repl_call(found):
        target = int(found.group(1), 16)
        if target in THUNKS:
            return found.group(0)
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
    if "dispatch_indirect" in code:
        sys.exit("indirect dispatch in %08x" % addr)
    return name, code


def build_source(bodies):
    decls = []
    switch = []
    for addr, name, _code in bodies:
        decls.append("void %s_impl(CPU *restrict c);" % name)
        switch.append("    case 0x%08xu: %s_impl(c); break;" % (addr, name))
    joined = "\n".join(code for _a, _n, code in bodies)
    return r'''
#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"
#include <stddef.h>

uint8_t *g_mem;
int _fltused;
static int fail_line;
static int uc_hle_fail;
static int uc_direct_fail;
static int note_n;
static int seen_n;
static int depth;
static int max_depth;
static uint32_t uc_sin_calls, uc_cos_calls, uc_acos_calls;
static uint32_t seen_fn[8];

typedef struct UcNote {
    uint32_t thunk;
    uint32_t fn;
    int32_t top_in, top_out;
    uint32_t esp_in, esp_out;
    uint32_t eax_in, eax_out;
    double st_in, st_out, st1_in, st1_out;
} UcNote;
static UcNote notes[16];

typedef struct UcPhase9Out {
    uint32_t code;
    uint32_t top_two;
    uint32_t top_pop;
    uint64_t push_st0;
    uint64_t push_st1;
    uint64_t sin_bits[5];
    uint64_t cos_bits[4];
    uint64_t acos_bits[5];
    uint64_t acos_oor;
    uint32_t oor_top_same;
    uint32_t oor_fsw;
    uint32_t unbound_rejected;
    uint32_t af_calls;
    uint64_t af_st;
    uint32_t af_mem;
    uint32_t af_esp;
    uint32_t af_eip;
    uint32_t af_ecx;
    uint32_t af_eax;
    int32_t af_top_in;
    int32_t af_top_out;
    uint32_t af_esp_in;
    uint32_t af_esp_out;
    uint64_t af_in;
    uint32_t af_skip_calls;
    uint32_t af_pos;
    uint32_t af_neg;
    uint32_t sc_sin_calls;
    uint32_t sc_cos_calls;
    uint32_t sc_dest[4];
    uint32_t sc_esp;
    uint32_t sc_eip;
    uint32_t sc_eax;
    uint32_t sc_ebx;
    uint32_t sc_esi;
    uint32_t sc_ebp;
    int32_t sc_sin_top_in;
    int32_t sc_sin_top_out;
    int32_t sc_cos_top_in;
    int32_t sc_cos_top_out;
    uint64_t sc_sin_in, sc_sin_out, sc_cos_in, sc_cos_out;
    uint32_t sc_dest2[4];
    uint32_t fn_count;
    uint32_t fns[8];
    uint32_t max_depth;
    uint32_t ci_count;
    uint32_t ci_thunk[8];
    uint64_t ci_in[8];
    uint64_t ci_out[8];
    uint32_t out_bits;
    uint32_t repeat_bits;
    uint32_t repeat_regs;
    uint32_t out_bits_b;
    uint32_t ci_count_b;
    uint64_t ci_in_b[8];
    uint64_t ci_out_b[8];
    uint32_t final_esp;
    uint32_t final_eip;
    uint32_t final_eax;
    uint32_t final_ebx;
    uint32_t final_ecx;
    uint32_t final_top;
    uint32_t span_count;
    uint32_t span_lo[12];
    uint32_t span_hi[12];
    uint32_t span_write[12];
    uint32_t fault_kind;
    uint32_t fault_addr;
    char fault_section[16];
    uint32_t x87_active;
    uint32_t x87_fn;
    uint32_t x87_eip;
    int32_t x87_top;
    uint64_t x87_st0;
    uint64_t x87_st1;
    uint32_t x87_fcw;
    uint32_t x87_fsw;
    uint32_t unknown_rejected;
    uint32_t bd0_bits;
    uint32_t scratch_bits[4];
} UcPhase9Out;

#define EXPECT(cond) do { if (!(cond)) { fail_line = __LINE__; return; } } while (0)

double fabs(double v);
float sqrtf(float v);
void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
void *memset(void *dst, int v, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    size_t i;
    for (i = 0; i < n; i++) d[i] = (uint8_t)v;
    return dst;
}

static uint64_t dbits(double v) {
    uint64_t u;
    memcpy(&u, &v, 8);
    return u;
}
static uint32_t fbits(float v) {
    uint32_t u;
    memcpy(&u, &v, 4);
    return u;
}
static int is_nan(double v) {
    return v != v;
}
static uint32_t current_fn(void) { return uc_current_fn; }

static void uc_guest_storef32(uint32_t addr, float value) {
    uc_guest_store32(addr, fbits(value), 0);
}
static uint32_t bd0_bits;
static void uc_note_fn(uint32_t va, CPU *c) {
    int i, ok;
    if (va == 0x00a11bd0u)
        bd0_bits = uc_guest_load32(c->ecx + 0xcu, &ok);
    depth++;
    if (depth > max_depth) max_depth = depth;
    for (i = 0; i < seen_n; i++) if (seen_fn[i] == va) return;
    if (seen_n < 8) seen_fn[seen_n++] = va;
}
static void uc_note_leave(void) {
    if (depth > 0) depth--;
}

''' + "\n".join(decls) + r'''

static void uc_direct(uint32_t target, CPU *c) {
    uint32_t caller = uc_current_fn;
    uc_trace(UC_EV_DIRECT_CALL, caller, c->eip, target, c);
    if (!uc_guest_execute(target)) { uc_direct_fail = 1; return; }
    switch (target) {
''' + "\n".join(switch) + r'''
    default:
        uc_direct_fail = 1;
        uc_trace(UC_EV_INDIRECT_CALL, caller, c->eip, target, c);
        return;
    }
    uc_current_fn = caller;
}

static void uc_thunk(CPU *c, uint32_t thunk, uint32_t *counter) {
    const UcImport *imp = uc_import_find(thunk);
    UcNote *n;
    (*counter)++;
    if (note_n >= 16) { uc_hle_fail = 1; return; }
    n = &notes[note_n];
    n->thunk = thunk;
    n->fn = uc_current_fn;
    n->top_in = c->top;
    n->esp_in = c->esp;
    n->eax_in = c->eax;
    n->st_in = ST(0);
    n->st1_in = ST(1);
    uc_trace(UC_EV_IMPORT_CALL, uc_current_fn, c->eip, thunk, c);
    if (!imp || !uc_import_invoke(c, imp, 0)) { uc_hle_fail = 1; return; }
    n->top_out = c->top;
    n->esp_out = c->esp;
    n->eax_out = c->eax;
    n->st_out = ST(0);
    n->st1_out = ST(1);
    note_n++;
    uc_trace(UC_EV_IMPORT_RETURN, uc_current_fn, c->eip, thunk, c);
}
void sub_0087b2e0(CPU *c) { uc_thunk(c, 0x0087b2e0u, &uc_acos_calls); }
void sub_00ae5110(CPU *c) { uc_thunk(c, 0x00ae5110u, &uc_cos_calls); }
void sub_00ae5140(CPU *c) { uc_thunk(c, 0x00ae5140u, &uc_sin_calls); }

''' + joined + r'''

void dispatch_indirect(CPU *c, uint32_t target) {
    (void)c; uc_direct_fail = 1;
    uc_trace(UC_EV_INDIRECT_CALL, uc_current_fn, c->eip, target, c);
}
void dispatch_tail(CPU *c) { (void)c; }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    (void)c; (void)addr; (void)why; uc_direct_fail = 1;
}

static void prepare(CPU *c) {
    memset(c, 0, sizeof *c);
    c->esp = 0x0300f000u;
    c->eax = 0xa5a5a5a5u;
    c->ebx = 0xb0b0b0b0u;
    c->ecx = 0xc0c0c0c0u;
    c->edx = 0xd0d0d0d0u;
    c->esi = 0x51515151u;
    c->edi = 0xd1d1d1d1u;
    c->ebp = 0xebebebebu;
    c->top = 0;
    c->fcw = 0x037fu;
}

static void wrf(uint32_t addr, float v) {
    uc_guest_store32(addr, fbits(v), 0);
}
static void vec4(uint32_t addr, float a, float b, float c0, float d) {
    wrf(addr, a); wrf(addr + 4u, b); wrf(addr + 8u, c0); wrf(addr + 12u, d);
}

static int call_unary(CPU *c, void (*fn)(CPU *), double in) {
    uint32_t esp;
    int32_t top;
    prepare(c);
    FPUSH(1.25);
    FPUSH(in);
    top = c->top;
    esp = c->esp;
    PUSH32(0x00dec0deu);
    fn(c);
    if (uc_hle_fail) { fail_line = __LINE__; return 0; }
    if (c->esp != esp) { fail_line = __LINE__; return 0; }
    if (c->eip != 0x00dec0deu) { fail_line = __LINE__; return 0; }
    if (c->top != top) { fail_line = __LINE__; return 0; }
    if (dbits(ST(1)) != dbits(1.25)) { fail_line = __LINE__; return 0; }
    if (c->eax != 0xa5a5a5a5u) { fail_line = __LINE__; return 0; }
    if (c->ebx != 0xb0b0b0b0u || c->ecx != 0xc0c0c0c0u) { fail_line = __LINE__; return 0; }
    if (c->edx != 0xd0d0d0d0u || c->esi != 0x51515151u) { fail_line = __LINE__; return 0; }
    if (c->edi != 0xd1d1d1d1u || c->ebp != 0xebebebebu) { fail_line = __LINE__; return 0; }
    if (notes[note_n - 1].esp_out != notes[note_n - 1].esp_in + 4u) { fail_line = __LINE__; return 0; }
    if (notes[note_n - 1].top_in != notes[note_n - 1].top_out) { fail_line = __LINE__; return 0; }
    if (notes[note_n - 1].eax_in != notes[note_n - 1].eax_out) { fail_line = __LINE__; return 0; }
    if (dbits(notes[note_n - 1].st1_in) != dbits(notes[note_n - 1].st1_out)) { fail_line = __LINE__; return 0; }
    return 1;
}

static UcHostUnary saved_sin, saved_cos, saved_acos;
static double (*host_fabs)(double);
static float (*host_sqrtf)(float);
double fabs(double v) { return host_fabs(v); }
float sqrtf(float v) { return host_sqrtf(v); }

static void run_cases(UcPhase9Out *out) {
    CPU cpu;
    CPU *c = &cpu;
    const double sins[5] = { 0.0, 0.5, -0.3, 1.5707963267948966, 10.0 };
    const double coss[4] = { 0.0, 0.5, -0.3, 1.0 };
    const double acs[5] = { -1.0, -0.5, 0.0, 0.5, 1.0 };
    int i;
    uint32_t esp, calls;
    uint16_t fsw_before;
    prepare(c);
    FPUSH(1.5);
    FPUSH(2.25);
    out->top_two = (uint32_t)c->top;
    out->push_st0 = dbits(ST(0));
    out->push_st1 = dbits(ST(1));
    EXPECT(c->top == 6);
    EXPECT(dbits(ST(0)) == dbits(2.25));
    EXPECT(dbits(ST(1)) == dbits(1.5));
    FPOP();
    out->top_pop = (uint32_t)c->top;
    EXPECT(c->top == 7);
    EXPECT(dbits(ST(0)) == dbits(1.5));
    FPOP();
    EXPECT(c->top == 0);

    note_n = 0;
    for (i = 0; i < 5; i++) {
        if (!call_unary(c, sub_00ae5140, sins[i])) return;
        EXPECT(dbits(ST(0)) == dbits(uc_host_sin(sins[i])));
        out->sin_bits[i] = dbits(ST(0));
        FPOP();
        EXPECT(dbits(ST(0)) == dbits(1.25));
        FPOP();
    }
    for (i = 0; i < 4; i++) {
        if (!call_unary(c, sub_00ae5110, coss[i])) return;
        EXPECT(dbits(ST(0)) == dbits(uc_host_cos(coss[i])));
        out->cos_bits[i] = dbits(ST(0));
        FPOP();
        FPOP();
    }
    for (i = 0; i < 5; i++) {
        if (!call_unary(c, sub_0087b2e0, acs[i])) return;
        EXPECT(dbits(ST(0)) == dbits(uc_host_acos(acs[i])));
        out->acos_bits[i] = dbits(ST(0));
        FPOP();
        FPOP();
    }

    prepare(c);
    FPUSH(2.0);
    fsw_before = c->fsw;
    esp = c->esp;
    PUSH32(0x00dec0deu);
    calls = uc_acos_calls;
    sub_0087b2e0(c);
    EXPECT(uc_hle_fail == 0);
    EXPECT(uc_acos_calls == calls + 1u);
    EXPECT(is_nan(ST(0)));
    EXPECT(c->top == 7);
    EXPECT(c->esp == esp);
    EXPECT(c->eax == 0xa5a5a5a5u);
    EXPECT(c->fsw == fsw_before);
    out->acos_oor = dbits(ST(0));
    out->oor_top_same = 1;
    out->oor_fsw = c->fsw;

    prepare(c);
    FPUSH(0.25);
    esp = c->esp;
    PUSH32(0x00dec0deu);
    uc_host_sin = 0;
    uc_hle_fail = 0;
    sub_00ae5140(c);
    EXPECT(uc_hle_fail == 1);
    EXPECT(c->esp == esp - 4u);
    EXPECT(c->eax == 0xa5a5a5a5u);
    EXPECT(dbits(ST(0)) == dbits(0.25));
    EXPECT(uc_x87_fault.active == 1);
    EXPECT(uc_x87_fault.top == c->top);
    EXPECT(dbits(uc_x87_fault.st0) == dbits(0.25));
    out->unbound_rejected = 1;
    out->x87_active = 1;
    out->x87_fn = uc_x87_fault.function_va;
    out->x87_eip = uc_x87_fault.eip;
    out->x87_top = uc_x87_fault.top;
    out->x87_st0 = dbits(uc_x87_fault.st0);
    out->x87_st1 = dbits(uc_x87_fault.st1);
    out->x87_fcw = uc_x87_fault.fcw;
    out->x87_fsw = uc_x87_fault.fsw;
    uc_host_sin = saved_sin;
    uc_x87_fault.active = 0;
    uc_hle_fail = 0;
}

__declspec(dllexport) void uc_phase9_bind(
    UcHostUnary s, UcHostUnary co, UcHostUnary a,
    double (*fb)(double), float (*sq)(float)) {
    saved_sin = uc_host_sin = s;
    saved_cos = uc_host_cos = co;
    saved_acos = uc_host_acos = a;
    host_fabs = fb;
    host_sqrtf = sq;
    uc_x87_current_fn = current_fn;
}

static void restore_host(void) {
    uc_host_sin = saved_sin;
    uc_host_cos = saved_cos;
    uc_host_acos = saved_acos;
}

static void run_callers(UcPhase9Out *out) {
    CPU cpu;
    CPU *c = &cpu;
    uint32_t calls, bits, esp0, base_notes;
    float arg, expect, got;
    double scale, input;
    int i, ok;

    restore_host();
    note_n = 0;
    calls = uc_acos_calls;
    arg = 0.5f;
    prepare(c);
    PUSH32(fbits(arg));
    PUSH32(0x00dec0deu);
    esp0 = 0x0300f000u;
    base_notes = (uint32_t)note_n;
    sub_00a11af0_impl(c);
    EXPECT(uc_hle_fail == 0 && uc_direct_fail == 0 && uc_access_fault.active == 0);
    EXPECT(uc_acos_calls == calls + 1u);
    EXPECT(c->eip == 0x00dec0deu);
    EXPECT(c->esp == esp0 - 4u);
    /* push ecx is a spill slot: fstp dword [esp] overwrites it with |arg|. */
    EXPECT(c->ecx == fbits(arg));
    EXPECT(c->eax == 0xa5a5a5a5u);
    EXPECT(c->ebx == 0xb0b0b0b0u && c->esi == 0x51515151u && c->ebp == 0xebebebebu);
    expect = (float)uc_host_acos((double)arg);
    EXPECT(dbits(ST(0)) == dbits((double)expect));
    bits = 0;
    EXPECT(uc_guest_load32(c->esp, &ok) == fbits(expect) && ok == 1);
    out->af_calls = uc_acos_calls - calls;
    out->af_st = dbits(ST(0));
    out->af_mem = fbits(expect);
    out->af_esp = c->esp;
    out->af_eip = c->eip;
    out->af_ecx = c->ecx;
    out->af_eax = c->eax;
    EXPECT(note_n == (int)base_notes + 1);
    out->af_top_in = notes[base_notes].top_in;
    out->af_top_out = notes[base_notes].top_out;
    out->af_esp_in = notes[base_notes].esp_in;
    out->af_esp_out = notes[base_notes].esp_out;
    out->af_in = dbits(notes[base_notes].st_in);
    EXPECT(notes[base_notes].top_in == notes[base_notes].top_out);
    EXPECT(notes[base_notes].esp_out == notes[base_notes].esp_in + 4u);
    EXPECT(notes[base_notes].eax_in == notes[base_notes].eax_out);
    EXPECT(dbits(notes[base_notes].st_in) == dbits((double)arg));

    calls = uc_acos_calls;
    arg = 2.0f;
    prepare(c);
    PUSH32(fbits(arg));
    PUSH32(0x00dec0deu);
    sub_00a11af0_impl(c);
    EXPECT(uc_acos_calls == calls);
    EXPECT(c->eip == 0x00dec0deu && c->esp == esp0 - 4u);
    EXPECT(uc_guest_load32(c->esp, &ok) == fbits(0.0f) && ok == 1);
    EXPECT(dbits(ST(0)) == dbits(0.0));
    out->af_skip_calls = uc_acos_calls - calls;
    out->af_pos = fbits(0.0f);

    calls = uc_acos_calls;
    arg = -1.0f;
    prepare(c);
    PUSH32(fbits(arg));
    PUSH32(0x00dec0deu);
    sub_00a11af0_impl(c);
    EXPECT(uc_acos_calls == calls);
    bits = uc_guest_load32(0x00b6dcf0u, &ok);
    EXPECT(ok == 1);
    EXPECT(uc_guest_load32(c->esp, &ok) == bits && ok == 1);
    out->af_neg = bits;

    calls = uc_sin_calls;
    {
        uint32_t cos_calls = uc_cos_calls;
        float angle = 1.0f;
        float pred[4];
        vec4(0x03004050u, 1.0f, 2.0f, 3.0f, 4.0f);
        vec4(0x03004040u, 0.0f, 0.0f, 0.0f, 0.0f);
        prepare(c);
        c->ecx = 0x03004040u;
        PUSH32(fbits(angle));
        PUSH32(0x03004050u);
        PUSH32(0x00dec0deu);
        base_notes = (uint32_t)note_n;
        sub_00a11c50_impl(c);
        EXPECT(uc_hle_fail == 0 && uc_direct_fail == 0 && uc_access_fault.active == 0);
        EXPECT(uc_sin_calls == calls + 1u);
        EXPECT(uc_cos_calls == cos_calls + 1u);
        EXPECT(c->eip == 0x00dec0deu);
        EXPECT(c->esp == esp0);
        EXPECT(c->eax == 0x03004050u);
        EXPECT(c->ebx == 0xb0b0b0b0u && c->ecx == 0x03004040u);
        EXPECT(c->esi == 0x51515151u && c->ebp == 0xebebebebu);
        memcpy(&scale, g_mem + 0x00b71cf0u, 8);
        EXPECT(scale == 0.5);
        input = (double)(float)((double)angle * scale);
        pred[0] = 1.0f * (float)uc_host_sin(input);
        pred[1] = 2.0f * (float)uc_host_sin(input);
        pred[2] = 3.0f * (float)uc_host_sin(input);
        pred[3] = (float)uc_host_cos(input);
        for (i = 0; i < 4; i++) {
            bits = uc_guest_load32(0x03004040u + (uint32_t)(4 * i), &ok);
            EXPECT(ok == 1);
            memcpy(&got, &bits, 4);
            EXPECT(got == pred[i]);
            out->sc_dest[i] = bits;
        }
        out->sc_sin_calls = 1;
        out->sc_cos_calls = 1;
        out->sc_esp = c->esp;
        out->sc_eip = c->eip;
        out->sc_eax = c->eax;
        out->sc_ebx = c->ebx;
        out->sc_esi = c->esi;
        out->sc_ebp = c->ebp;
        EXPECT(note_n >= (int)base_notes + 2);
        out->sc_sin_top_in = notes[base_notes].top_in;
        out->sc_sin_top_out = notes[base_notes].top_out;
        out->sc_sin_in = dbits(notes[base_notes].st_in);
        out->sc_sin_out = dbits(notes[base_notes].st_out);
        out->sc_cos_top_in = notes[base_notes + 1].top_in;
        out->sc_cos_top_out = notes[base_notes + 1].top_out;
        out->sc_cos_in = dbits(notes[base_notes + 1].st_in);
        out->sc_cos_out = dbits(notes[base_notes + 1].st_out);
        EXPECT(notes[base_notes].thunk == 0x00ae5140u);
        EXPECT(notes[base_notes + 1].thunk == 0x00ae5110u);
        EXPECT(notes[base_notes].top_in == notes[base_notes].top_out);
        EXPECT(notes[base_notes + 1].top_in == notes[base_notes + 1].top_out);
        EXPECT(dbits(notes[base_notes].st_in) == dbits(input));
        EXPECT(dbits(notes[base_notes].st_out) == dbits(uc_host_sin(input)));
        EXPECT(dbits(notes[base_notes + 1].st_out) == dbits(uc_host_cos(input)));

        angle = 0.0f;
        vec4(0x03004040u, 9.0f, 9.0f, 9.0f, 9.0f);
        prepare(c);
        c->ecx = 0x03004040u;
        PUSH32(fbits(angle));
        PUSH32(0x03004050u);
        PUSH32(0x00dec0deu);
        sub_00a11c50_impl(c);
        EXPECT(uc_hle_fail == 0 && c->esp == esp0 && c->eip == 0x00dec0deu);
        input = 0.0;
        pred[3] = (float)uc_host_cos(input);
        for (i = 0; i < 3; i++) {
            bits = uc_guest_load32(0x03004040u + (uint32_t)(4 * i), &ok);
            EXPECT(ok == 1 && bits == fbits(0.0f));
            out->sc_dest2[i] = bits;
        }
        bits = uc_guest_load32(0x0300404cu, &ok);
        EXPECT(bits == fbits(pred[3]));
        out->sc_dest2[3] = bits;
        EXPECT(out->sc_dest2[3] != out->sc_dest[3]);
    }
}

static void fill_ci(UcPhase9Out *out, int which) {
    int i, n = note_n;
    if (n > 8) n = 8;
    if (which == 0) {
        out->ci_count = (uint32_t)note_n;
        for (i = 0; i < n; i++) {
            out->ci_thunk[i] = notes[i].thunk;
            out->ci_in[i] = dbits(notes[i].st_in);
            out->ci_out[i] = dbits(notes[i].st_out);
        }
    } else {
        out->ci_count_b = (uint32_t)note_n;
        for (i = 0; i < n; i++) {
            out->ci_in_b[i] = dbits(notes[i].st_in);
            out->ci_out_b[i] = dbits(notes[i].st_out);
        }
    }
}

static void run_one(CPU *c, float sx, float sy, float sz, float sw,
                    float ox, float oy, float oz, float ow) {
    prepare(c);
    vec4(0x03004000u, sx, sy, sz, sw);
    vec4(0x03004010u, ox, oy, oz, ow);
    vec4(0x03004020u, 0.0f, 0.0f, 0.0f, 0.0f);
    wrf(0x03004030u, 123.0f);
    note_n = 0;
    seen_n = 0;
    depth = 0;
    max_depth = 0;
    uc_span_count = 0;
    uc_hle_fail = 0;
    uc_direct_fail = 0;
    uc_access_fault.active = 0;
    c->ecx = 0x03004000u;
    PUSH32(0x03004030u);
    PUSH32(0x03004020u);
    PUSH32(0x03004010u);
    PUSH32(0x00dec0deu);
    uc_direct(0x00a124b0u, c);
}

static void run_closure(UcPhase9Out *out) {
    CPU cpu;
    CPU *c = &cpu;
    int i, ok;
    uint32_t bits, repeat, regs;

    run_one(c, 0.0f, 0.0f, 0.0f, 1.0f, 0.6f, 0.3f, 0.1f, 0.7f);
    EXPECT(uc_hle_fail == 0 && uc_direct_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(c->eip == 0x00dec0deu);
    EXPECT(c->esp == 0x0300f000u);
    EXPECT(c->ebx == 0xb0b0b0b0u && c->esi == 0x51515151u);
    EXPECT(c->edi == 0xd1d1d1d1u && c->ebp == 0xebebebebu);
    EXPECT(note_n > 0);
    out->bd0_bits = bd0_bits;
    for (i = 0; i < 4; i++)
        out->scratch_bits[i] = uc_guest_load32(0x03004020u + (uint32_t)(4 * i), &ok);
    out->fn_count = (uint32_t)seen_n;
    out->max_depth = (uint32_t)max_depth;
    for (i = 0; i < seen_n && i < 8; i++) out->fns[i] = seen_fn[i];
    fill_ci(out, 0);
    EXPECT(seen_n == 6);
    bits = uc_guest_load32(0x03004030u, &ok);
    EXPECT(ok == 1);
    out->out_bits = bits;
    out->final_esp = c->esp;
    out->final_eip = c->eip;
    out->final_eax = c->eax;
    out->final_ebx = c->ebx;
    out->final_ecx = c->ecx;
    out->final_top = (uint32_t)c->top;
    out->fn_count = (uint32_t)seen_n;
    out->max_depth = (uint32_t)max_depth;
    for (i = 0; i < seen_n && i < 8; i++) out->fns[i] = seen_fn[i];
    fill_ci(out, 0);
    out->span_count = (uint32_t)uc_span_count;
    for (i = 0; i < uc_span_count && i < 12; i++) {
        out->span_lo[i] = uc_spans[i].lo;
        out->span_hi[i] = uc_spans[i].hi;
        out->span_write[i] = (uint32_t)uc_spans[i].write;
    }
    regs = c->eax ^ c->ebx ^ c->ecx ^ c->edx ^ c->esi ^ c->edi ^ c->ebp ^ (uint32_t)c->top;

    run_one(c, 0.0f, 0.0f, 0.0f, 1.0f, 0.6f, 0.3f, 0.1f, 0.7f);
    EXPECT(uc_hle_fail == 0 && uc_direct_fail == 0 && uc_access_fault.active == 0);
    EXPECT(c->eip == 0x00dec0deu && c->esp == 0x0300f000u);
    repeat = uc_guest_load32(0x03004030u, &ok);
    EXPECT(ok == 1 && repeat == bits);
    EXPECT((c->eax ^ c->ebx ^ c->ecx ^ c->edx ^ c->esi ^ c->edi ^ c->ebp ^ (uint32_t)c->top) == regs);
    EXPECT(note_n == (int)out->ci_count);
    EXPECT(seen_n == (int)out->fn_count && max_depth == (int)out->max_depth);
    for (i = 0; i < note_n && i < 8; i++) {
        EXPECT(notes[i].thunk == out->ci_thunk[i]);
        EXPECT(dbits(notes[i].st_in) == out->ci_in[i]);
        EXPECT(dbits(notes[i].st_out) == out->ci_out[i]);
    }
    out->repeat_bits = repeat;
    out->repeat_regs = 1;

    run_one(c, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f);
    EXPECT(uc_hle_fail == 0 && uc_direct_fail == 0 && uc_access_fault.active == 0);
    EXPECT(c->eip == 0x00dec0deu && c->esp == 0x0300f000u);
    repeat = uc_guest_load32(0x03004030u, &ok);
    EXPECT(ok == 1);
    out->out_bits_b = repeat;
    fill_ci(out, 1);
    EXPECT(repeat != bits || note_n != (int)out->ci_count);
    {
        int changed = repeat != bits;
        for (i = 0; i < note_n && i < (int)out->ci_count && i < 8; i++) {
            if (dbits(notes[i].st_in) != out->ci_in[i]) changed = 1;
            if (dbits(notes[i].st_out) != out->ci_out[i]) changed = 1;
        }
        EXPECT(changed == 1);
    }

    {
    const UcImport *unknown = uc_import_find(0x0087a7aeu);
    prepare(c);
    i = uc_import_invoke(c, unknown, 0);
    EXPECT(i == 0);
    EXPECT(c->esp == 0x0300f000u);
    EXPECT(c->eax == 0xa5a5a5a5u);
    out->unknown_rejected = 1;

    uc_current_fn = 0x00a124b0u;
    uc_fault_eip = 0x00a124b0u;
    uc_access_clear();
    ok = 1;
    EXPECT(uc_guest_load32(0x01fc7000u, &ok) == 0 && ok == 0);
    EXPECT(uc_access_fault.kind == UC_ACCESS_READ);
    }
}

__declspec(dllexport) uint32_t uc_phase9_out_size(void) {
    return (uint32_t)sizeof(UcPhase9Out);
}
__declspec(dllexport) void uc_phase9_offs(uint32_t *o) {
    o[0] = (uint32_t)sizeof(UcPhase9Out);
    o[1] = (uint32_t)offsetof(UcPhase9Out, sin_bits);
    o[2] = (uint32_t)offsetof(UcPhase9Out, out_bits);
    o[3] = (uint32_t)offsetof(UcPhase9Out, fault_section);
    o[4] = (uint32_t)offsetof(UcPhase9Out, fns);
}

__declspec(dllexport) int uc_phase9_run(
    uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int nsections,
    UcPhase9Out *out) {
    int i;
    fail_line = 0;
    memset(out, 0, sizeof *out);
    if (!uc_host_sin || !uc_host_cos || !uc_host_acos || !host_fabs || !host_sqrtf) return 3;
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) {
        if (uc_image_map(&sections[i])) return 2;
    }
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 4;
    uc_exec_trace = 1;
    run_cases(out);
    if (!fail_line) run_callers(out);
    if (!fail_line) run_closure(out);
    out->code = (uint32_t)fail_line;
    if (uc_access_fault.active) {
        out->fault_kind = (uint32_t)uc_access_fault.kind;
        out->fault_addr = uc_access_fault.address;
        for (i = 0; i < 15 && uc_access_fault.section[i]; i++)
            out->fault_section[i] = uc_access_fault.section[i];
    }
    if (uc_x87_fault.active) {
        out->x87_active = 1;
        out->x87_fn = uc_x87_fault.function_va;
        out->x87_eip = uc_x87_fault.eip;
        out->x87_top = uc_x87_fault.top;
        out->x87_st0 = dbits(uc_x87_fault.st0);
        out->x87_st1 = dbits(uc_x87_fault.st1);
        out->x87_fcw = uc_x87_fault.fcw;
        out->x87_fsw = uc_x87_fault.fsw;
    }
    return fail_line;
}
'''


class Out(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32),
        ("top_two", ctypes.c_uint32),
        ("top_pop", ctypes.c_uint32),
        ("push_st0", ctypes.c_uint64),
        ("push_st1", ctypes.c_uint64),
        ("sin_bits", ctypes.c_uint64 * 5),
        ("cos_bits", ctypes.c_uint64 * 4),
        ("acos_bits", ctypes.c_uint64 * 5),
        ("acos_oor", ctypes.c_uint64),
        ("oor_top_same", ctypes.c_uint32),
        ("oor_fsw", ctypes.c_uint32),
        ("unbound_rejected", ctypes.c_uint32),
        ("af_calls", ctypes.c_uint32),
        ("af_st", ctypes.c_uint64),
        ("af_mem", ctypes.c_uint32),
        ("af_esp", ctypes.c_uint32),
        ("af_eip", ctypes.c_uint32),
        ("af_ecx", ctypes.c_uint32),
        ("af_eax", ctypes.c_uint32),
        ("af_top_in", ctypes.c_int32),
        ("af_top_out", ctypes.c_int32),
        ("af_esp_in", ctypes.c_uint32),
        ("af_esp_out", ctypes.c_uint32),
        ("af_in", ctypes.c_uint64),
        ("af_skip_calls", ctypes.c_uint32),
        ("af_pos", ctypes.c_uint32),
        ("af_neg", ctypes.c_uint32),
        ("sc_sin_calls", ctypes.c_uint32),
        ("sc_cos_calls", ctypes.c_uint32),
        ("sc_dest", ctypes.c_uint32 * 4),
        ("sc_esp", ctypes.c_uint32),
        ("sc_eip", ctypes.c_uint32),
        ("sc_eax", ctypes.c_uint32),
        ("sc_ebx", ctypes.c_uint32),
        ("sc_esi", ctypes.c_uint32),
        ("sc_ebp", ctypes.c_uint32),
        ("sc_sin_top_in", ctypes.c_int32),
        ("sc_sin_top_out", ctypes.c_int32),
        ("sc_cos_top_in", ctypes.c_int32),
        ("sc_cos_top_out", ctypes.c_int32),
        ("sc_sin_in", ctypes.c_uint64),
        ("sc_sin_out", ctypes.c_uint64),
        ("sc_cos_in", ctypes.c_uint64),
        ("sc_cos_out", ctypes.c_uint64),
        ("sc_dest2", ctypes.c_uint32 * 4),
        ("fn_count", ctypes.c_uint32),
        ("fns", ctypes.c_uint32 * 8),
        ("max_depth", ctypes.c_uint32),
        ("ci_count", ctypes.c_uint32),
        ("ci_thunk", ctypes.c_uint32 * 8),
        ("ci_in", ctypes.c_uint64 * 8),
        ("ci_out", ctypes.c_uint64 * 8),
        ("out_bits", ctypes.c_uint32),
        ("repeat_bits", ctypes.c_uint32),
        ("repeat_regs", ctypes.c_uint32),
        ("out_bits_b", ctypes.c_uint32),
        ("ci_count_b", ctypes.c_uint32),
        ("ci_in_b", ctypes.c_uint64 * 8),
        ("ci_out_b", ctypes.c_uint64 * 8),
        ("final_esp", ctypes.c_uint32),
        ("final_eip", ctypes.c_uint32),
        ("final_eax", ctypes.c_uint32),
        ("final_ebx", ctypes.c_uint32),
        ("final_ecx", ctypes.c_uint32),
        ("final_top", ctypes.c_uint32),
        ("span_count", ctypes.c_uint32),
        ("span_lo", ctypes.c_uint32 * 12),
        ("span_hi", ctypes.c_uint32 * 12),
        ("span_write", ctypes.c_uint32 * 12),
        ("fault_kind", ctypes.c_uint32),
        ("fault_addr", ctypes.c_uint32),
        ("fault_section", ctypes.c_char * 16),
        ("x87_active", ctypes.c_uint32),
        ("x87_fn", ctypes.c_uint32),
        ("x87_eip", ctypes.c_uint32),
        ("x87_top", ctypes.c_int32),
        ("x87_st0", ctypes.c_uint64),
        ("x87_st1", ctypes.c_uint64),
        ("x87_fcw", ctypes.c_uint32),
        ("x87_fsw", ctypes.c_uint32),
        ("unknown_rejected", ctypes.c_uint32),
        ("bd0_bits", ctypes.c_uint32),
        ("scratch_bits", ctypes.c_uint32 * 4),
    ]


def f32(bits):
    return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]


def f64(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


def main():
    game = sys.argv[1]
    info = uca.read_inputs(game)
    image = p7.read_sections(game)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    bodies = []
    for addr in FUNCS:
        code, _ = lifter.lift(addr)
        name, code = instrument(code, addr)
        bodies.append((addr, name, code))
    src = build_source(bodies)
    work = tempfile.mkdtemp(prefix="uc-phase9-")
    c_path = os.path.join(work, "phase9.c")
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
            sys.exit(proc.returncode or 1)
        objs.append(obj)
    dll = os.path.join(work, "uc_phase9.dll")
    p7.link(objs, dll)
    lib = ctypes.CDLL(dll)
    if ctypes.sizeof(Out) != lib.uc_phase9_out_size():
        print("struct size", ctypes.sizeof(Out), "c size", lib.uc_phase9_out_size())
        sys.exit(1)
    offs = (ctypes.c_uint32 * 5)()
    lib.uc_phase9_offs(offs)
    py = (
        ctypes.sizeof(Out),
        getattr(Out, "sin_bits").offset,
        getattr(Out, "out_bits").offset,
        getattr(Out, "fault_section").offset,
        getattr(Out, "fns").offset,
    )
    if tuple(offs) != py:
        print("offsets", tuple(offs), py)
        sys.exit(1)

    ucrt = ctypes.CDLL("ucrtbase.dll")
    unary = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_double)
    sqrtf_t = ctypes.CFUNCTYPE(ctypes.c_float, ctypes.c_float)
    bound = []
    for name in ("sin", "cos", "acos", "fabs"):
        fn = getattr(ucrt, name)
        fn.argtypes = [ctypes.c_double]
        fn.restype = ctypes.c_double
        bound.append(unary(fn))
    sq = getattr(ucrt, "sqrtf")
    sq.argtypes = [ctypes.c_float]
    sq.restype = ctypes.c_float
    bound.append(sqrtf_t(sq))
    lib.uc_phase9_bind(*bound)

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
    lib.uc_phase9_run.restype = ctypes.c_int
    rc = lib.uc_phase9_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        arr, len(items), ctypes.byref(out))
    print("top_two", out.top_two, "top_pop", out.top_pop)
    print("push", f64(out.push_st0), f64(out.push_st1))
    print("sin", [f64(out.sin_bits[i]) for i in range(5)])
    print("cos", [f64(out.cos_bits[i]) for i in range(4)])
    print("acos", [f64(out.acos_bits[i]) for i in range(5)])
    print("acos_oor_nan", f64(out.acos_oor) != f64(out.acos_oor), "fsw", hex(out.oor_fsw))
    print("unbound", out.unbound_rejected, "x87_top", out.x87_top, "fcw", hex(out.x87_fcw), "fsw", hex(out.x87_fsw))
    print("af calls", out.af_calls, "st", f64(out.af_st), "mem", f32(out.af_mem))
    print("af esp", hex(out.af_esp), "eip", hex(out.af_eip), "ecx", hex(out.af_ecx))
    print("af top", out.af_top_in, out.af_top_out, "esp", hex(out.af_esp_in), hex(out.af_esp_out), "in", f64(out.af_in))
    print("af skip", out.af_skip_calls, "pos", f32(out.af_pos), "neg", f32(out.af_neg))
    print("sc dest", [f32(out.sc_dest[i]) for i in range(4)])
    print("sc dest2", [f32(out.sc_dest2[i]) for i in range(4)])
    print("sc esp", hex(out.sc_esp), "eip", hex(out.sc_eip), "eax", hex(out.sc_eax))
    print("sc sin", out.sc_sin_top_in, out.sc_sin_top_out, f64(out.sc_sin_in), f64(out.sc_sin_out))
    print("sc cos", out.sc_cos_top_in, out.sc_cos_top_out, f64(out.sc_cos_in), f64(out.sc_cos_out))
    print("fns", out.fn_count, [hex(out.fns[i]) for i in range(out.fn_count)])
    print("depth", out.max_depth, "ci", out.ci_count)
    for i in range(min(8, out.ci_count)):
        print(" ci", hex(out.ci_thunk[i]), f64(out.ci_in[i]), f64(out.ci_out[i]))
    print("out", f32(out.out_bits), "repeat", f32(out.repeat_bits), "regs", out.repeat_regs)
    print("out_b", f32(out.out_bits_b), "ci_b", out.ci_count_b)
    for i in range(min(8, out.ci_count_b)):
        print(" ci_b", f64(out.ci_in_b[i]), f64(out.ci_out_b[i]))
    print("final", hex(out.final_esp), hex(out.final_eip), hex(out.final_eax), "top", out.final_top)
    print("spans", out.span_count)
    for i in range(min(12, out.span_count)):
        print(" span", hex(out.span_lo[i]), hex(out.span_hi[i]), out.span_write[i])
    print("fault", out.fault_kind, hex(out.fault_addr), bytes(out.fault_section).split(b"\0", 1)[0])
    print("unknown", out.unknown_rejected)
    print("bd0", f32(out.bd0_bits), "scratch", [f32(out.scratch_bits[i]) for i in range(4)])
    if rc != 0:
        lines = src.splitlines()
        text = lines[rc - 1] if 0 < rc <= len(lines) else ""
        print("failed line", rc, text)
        print("work", work)
        sys.exit(1)
    print("uc phase9 tests passed")
    print("work", work)


if __name__ == "__main__":
    main()
