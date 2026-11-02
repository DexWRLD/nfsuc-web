"""Phase 10 native harness.

Executes the largest ordinary closure the frontier classified as runnable,
then one deeper closure until the first unsupported boundary. The game
executable is not started. Protected sections stay unmapped.
"""
import ctypes
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
import uc_code_analyze as uca
import uc_phase7_test as p7

ROOT = p7.ROOT
COOKIE = 0x00DEC0DE
OBJ = 0x03001000
ARG = 0x03000800
PAT = 0x03000C00
READY = 0x00968D10
PURE = 0x00B01EB0
BOUNDARY = 0x0099DCD0

FIELDS = [
    "ready_status", "ready_calls", "ready_unique", "ready_depth",
    "ready_imports", "ready_indirect", "ready_eip", "ready_esp",
    "ready_eax", "ready_ebx", "ready_ecx", "ready_esi", "ready_edi", "ready_ebp",
    "ready_hash", "ready_flag", "ready_fault_addr", "ready_fault_eip", "ready_fault_fn",
    "ready_fault_kind", "ready_limit", "ready_chain_n",
]
FIELDS += ["ready_fn_%d" % i for i in range(40)]
FIELDS += ["ready_chain_%d" % i for i in range(16)]
FIELDS += ["ready_imp_%d" % i for i in range(8)]
FIELDS += ["ready_obj_%d" % i for i in range(8)]
FIELDS += [
    "repeat_status", "repeat_hash", "repeat_eip", "repeat_esp", "repeat_eax",
    "repeat_calls", "repeat_unique", "repeat_depth", "repeat_fault",
]
FIELDS += [
    "other_status", "other_hash", "other_eip", "other_esp", "other_eax",
    "other_calls", "other_unique", "other_depth", "other_fault",
]
FIELDS += ["other_fn_%d" % i for i in range(40)]
FIELDS += ["other_obj_%d" % i for i in range(8)]
FIELDS += [
    "pure_status", "pure_calls", "pure_unique", "pure_depth", "pure_eip",
    "pure_esp", "pure_eax", "pure_hash", "pure_fault",
    "pure_b_status", "pure_b_hash", "pure_b_eip", "pure_b_calls", "pure_b_unique",
    "pure_b_fault",
]
FIELDS += ["pure_fn_%d" % i for i in range(24)]
FIELDS += [
    "bound_status", "bound_eip", "bound_fn", "bound_target", "bound_calls",
    "bound_depth", "bound_imports", "bound_indirect", "bound_fault_addr",
    "bound_fault_fn", "bound_limit", "bound_chain_n", "bound_trace_n",
]
FIELDS += ["bound_chain_%d" % i for i in range(16)]
FIELDS += ["bound_tk_%d" % i for i in range(16)]
FIELDS += ["bound_tf_%d" % i for i in range(16)]
FIELDS += ["bound_te_%d" % i for i in range(16)]
FIELDS += ["bound_tt_%d" % i for i in range(16)]
FIELDS += ["sitext_%d" % i for i in range(6)]
FIELDS += [
    "other_repeat_status", "other_repeat_hash", "other_repeat_eip",
    "other_repeat_calls", "other_repeat_unique", "other_repeat_fault",
]
INDEX = {name: i for i, name in enumerate(FIELDS)}


def instrument(code, addr, thunks):
    match = re.search(r"void (sub_[0-9a-f]+)\(CPU \*restrict c\) \{", code)
    if not match:
        sys.exit("no definition in %08x" % addr)
    name = match.group(1)
    code = code.replace(
        "void %s(CPU *restrict c) {" % name,
        "void %s_impl(CPU *restrict c) {\n    uc_fn_enter(0x%08xu, c);\n    uc_note_enter(0x%08xu);\n    if (uc_stop) return;"
        % (name, addr, addr),
        1)

    def repl_ret(found):
        extra = found.group(1) or ""
        return "uc_note_leave(); uc_fn_leave(0x%08xu, c); POP32(c->eip);%s return;" % (addr, extra)

    code = re.sub(r"POP32\(c->eip\);( c->esp \+= \d+u;)? return;", repl_ret, code)

    def repl_call(found):
        target = int(found.group(1), 16)
        if target in thunks:
            return found.group(0)
        return "uc_direct(0x%08xu, c)" % target

    code = re.sub(r"sub_([0-9a-f]+)\(c\)", repl_call, code)
    code = re.sub(
        r"/\* ([0-9a-fA-F]+)  ",
        lambda m: "if (uc_stop) return; c->eip = 0x%s; /* %s  " % (m.group(1), m.group(1)),
        code)
    code = code.replace(
        "DISPATCH_CALL(c, _ct);",
        "dispatch_indirect(c, _ct); if (uc_stop) return;")
    code = code.replace(
        ");   /* indirect tail call */",
        "); if (uc_stop) return; /* indirect tail call */")
    code = code.replace("DISPATCH_TAIL(c, ", "dispatch_indirect(c, ")
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


def build_source(bodies, thunks):
    decls = []
    switch = []
    stubs = []
    for addr, name, _code in bodies:
        decls.append("void %s_impl(CPU *restrict c);" % name)
        switch.append("    case 0x%08xu: %s_impl(c); break;" % (addr, name))
    for addr in sorted(thunks):
        stubs.append("void sub_%08x(CPU *c) { uc_import_thunk(c, 0x%08xu); }" % (addr, addr))
    enum = ["enum {"]
    for name, idx in INDEX.items():
        enum.append("    W_%s = %d," % (name.upper(), idx))
    enum.append("    W_COUNT = %d" % len(FIELDS))
    enum.append("};")
    joined = "\n".join(code for _a, _n, code in bodies)
    return r'''
#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"
#include <stddef.h>

#define OBJ 0x03001000u
#define ARG 0x03000800u
#define PAT 0x03000C00u

uint8_t *g_mem;
int _fltused;
void __chkstk(void) {}
static int uc_stop;
static int uc_import_fail;
static int depth;
static int max_depth;
static int seen_n;
static uint32_t seen_fn[64];
static uint32_t chain[16];
static int chain_n;
static uint32_t import_seen[8];
static int import_n;
static uint32_t last_indirect;
static uint32_t stop_fn;
double (*uc_host_fabs)(double);
float (*uc_host_sqrtf)(float);

''' + "\n".join(enum) + r'''

#define SETW(w, i, v) do { if ((i) < nwords) (w)[i] = (uint32_t)(v); } while (0)

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
double fabs(double v) { return uc_host_fabs ? uc_host_fabs(v) : 0.0; }
float sqrtf(float v) { return uc_host_sqrtf ? uc_host_sqrtf(v) : 0.0f; }

static uint32_t fbits(float v) {
    uint32_t u;
    memcpy(&u, &v, 4);
    return u;
}
static void uc_guest_storef32(uint32_t addr, float value) {
    uc_guest_store32(addr, fbits(value), 0);
}
static int poll(void) {
    if (uc_access_fault.active || uc_limit_stop.active) {
        uc_stop = 1;
        if (!stop_fn) stop_fn = uc_current_fn;
    }
    return 0;
}
static void uc_note_enter(uint32_t va) {
    int i;
    depth++;
    if (depth > max_depth) max_depth = depth;
    if (chain_n < 16) chain[chain_n++] = va;
    for (i = 0; i < seen_n; i++) if (seen_fn[i] == va) return;
    if (seen_n < 64) seen_fn[seen_n++] = va;
}
static void uc_note_leave(void) {
    if (depth > 0) depth--;
    if (chain_n > 0) chain_n--;
}

''' + "\n".join(decls) + r'''

static void uc_direct(uint32_t target, CPU *c) {
    uint32_t caller = uc_current_fn;
    if (uc_stop) return;
    uc_trace(UC_EV_DIRECT_CALL, caller, c->eip, target, c);
    if (!uc_guest_execute(target)) { uc_stop = 1; return; }
    switch (target) {
''' + "\n".join(switch) + r'''
    default:
        uc_stop = 1;
        uc_trace(UC_EV_INDIRECT_CALL, caller, c->eip, target, c);
        return;
    }
    uc_current_fn = caller;
    if (uc_stop) return;
}

static void uc_import_thunk(CPU *c, uint32_t thunk) {
    const UcImport *imp = uc_import_find(thunk);
    if (import_n < 8) import_seen[import_n++] = thunk;
    uc_trace(UC_EV_IMPORT_CALL, uc_current_fn, c->eip, thunk, c);
    if (!uc_limit_note_import(c, thunk) || !imp || !uc_import_invoke(c, imp, 0)) {
        uc_import_fail = 1;
        uc_stop = 1;
        return;
    }
    uc_trace(UC_EV_IMPORT_RETURN, uc_current_fn, c->eip, thunk, c);
}

''' + "\n".join(stubs) + "\n" + joined + r'''

void dispatch_indirect(CPU *c, uint32_t target) {
    last_indirect = target;
    stop_fn = uc_current_fn;
    uc_limit_note_indirect(c, target);
    uc_trace(UC_EV_INDIRECT_CALL, uc_current_fn, c->eip, target, c);
    uc_stop = 1;
}
void dispatch_tail(CPU *c) { dispatch_indirect(c, c->eip); }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    (void)why;
    c->eip = addr;
    uc_stop = 1;
}

static void prepare_cpu(CPU *c) {
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
static void zero_range(uint32_t addr, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++) g_mem[addr + i] = 0;
}
static uint32_t memhash(uint32_t addr, uint32_t n) {
    uint32_t i, h = 2166136261u;
    for (i = 0; i < n; i++) { h ^= g_mem[addr + i]; h *= 16777619u; }
    return h;
}
static void begin_run(void) {
    int i;
    uc_stop = 0;
    uc_import_fail = 0;
    depth = 0;
    max_depth = 0;
    seen_n = 0;
    chain_n = 0;
    import_n = 0;
    last_indirect = 0;
    stop_fn = 0;
    for (i = 0; i < 8; i++) import_seen[i] = 0;
    uc_access_clear();
    uc_limits_clear();
    uc_limit_calls = 100000u;
    uc_limit_depth = 64u;
    uc_limit_imports = 10000u;
    uc_limit_indirect = 8u;
    uc_limit_ms = 5000u;
    uc_exec_trace = 1;
    uc_limit_hook = poll;
    uc_trace_total = 0;
    uc_trace_count = 0;
}
static void end_run(void) { uc_limit_hook = 0; }
static uint32_t status_of(CPU *c) {
    if (uc_access_fault.active) return 1;
    if (uc_import_fail) return 3;
    if (uc_stat_indirect) return 2;
    if (uc_limit_stop.active) return 4;
    if (c->eip == 0x00dec0deu && !uc_stop) return 0;
    return 5;
}
static void store_trace(uint32_t *words, int nwords) {
    int n, i;
    n = uc_trace_total < 16 ? uc_trace_total : 16;
    SETW(words, W_BOUND_TRACE_N, n);
    for (i = 0; i < n; i++) {
        int idx = (uc_trace_total - n + i) % 64;
        UcTraceEvent *e = &uc_trace_log[idx];
        SETW(words, W_BOUND_TK_0 + i, e->kind);
        SETW(words, W_BOUND_TF_0 + i, e->fn);
        SETW(words, W_BOUND_TE_0 + i, e->eip);
        SETW(words, W_BOUND_TT_0 + i, e->target);
    }
}

static void run_ready(CPU *c, int other) {
    prepare_cpu(c);
    zero_range(OBJ, 0x800u);
    zero_range(ARG, 16u);
    zero_range(PAT, 8u);
    if (other) {
        g_mem[PAT] = 1; g_mem[PAT + 1] = 2; g_mem[PAT + 2] = 3; g_mem[PAT + 3] = 4;
        g_mem[OBJ + 0x5c] = (uint8_t)(PAT);
        g_mem[OBJ + 0x5d] = (uint8_t)(PAT >> 8);
        g_mem[OBJ + 0x5e] = (uint8_t)(PAT >> 16);
        g_mem[OBJ + 0x5f] = (uint8_t)(PAT >> 24);
        g_mem[OBJ + 0x6f] = 1;
        g_mem[OBJ + 0x73] = 1;
        g_mem[OBJ + 0x77] = 3;
        g_mem[ARG] = 0x10;
        g_mem[ARG + 4] = 0x20;
    }
    begin_run();
    c->ecx = OBJ;
    PUSH32(ARG);
    PUSH32(0x00dec0deu);
    uc_direct(0x00968d10u, c);
    end_run();
}
static void run_pure(CPU *c, int other) {
    uint32_t i;
    prepare_cpu(c);
    zero_range(OBJ, 0x800u);
    zero_range(0x03000900u, 64u);
    if (other) {
        g_mem[OBJ + 4] = 1;
        for (i = 0; i < 16; i++) {
            g_mem[0x03000900u + i * 4] = 0;
            g_mem[0x03000901u + i * 4] = 0;
            g_mem[0x03000902u + i * 4] = 0x80;
            g_mem[0x03000903u + i * 4] = 0x3f;
        }
    }
    begin_run();
    PUSH32(OBJ);
    PUSH32(0);
    PUSH32(other ? 0x03000900u : 0);
    PUSH32(0);
    PUSH32(0x00dec0deu);
    uc_direct(0x00b01eb0u, c);
    end_run();
}
static void run_bound(CPU *c) {
    prepare_cpu(c);
    begin_run();
    PUSH32(2u);
    PUSH32(0);
    PUSH32(0x00dec0deu);
    uc_direct(0x0099dcd0u, c);
    end_run();
}
static void save_common(uint32_t *words, int nwords, CPU *c, int base_status, int base_hash,
                        int base_eip, int base_esp, int base_eax, int base_calls, int base_unique,
                        int base_depth, int base_fault) {
    SETW(words, base_status, status_of(c));
    SETW(words, base_hash, memhash(OBJ, 0x200u));
    SETW(words, base_eip, c->eip);
    SETW(words, base_esp, c->esp);
    SETW(words, base_eax, c->eax);
    SETW(words, base_calls, uc_stat_calls);
    SETW(words, base_unique, seen_n);
    SETW(words, base_depth, max_depth);
    SETW(words, base_fault, uc_access_fault.active ? uc_access_fault.address : 0);
}

__declspec(dllexport) int uc_phase10_words(void) { return W_COUNT; }

__declspec(dllexport) void uc_phase10_bind(void *fabs_fn, void *sqrtf_fn, uint64_t (*now_ms)(void)) {
    uc_host_fabs = (double (*)(double))fabs_fn;
    uc_host_sqrtf = (float (*)(float))sqrtf_fn;
    uc_host_ms = now_ms;
}

__declspec(dllexport) int uc_phase10_run(uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int section_count, uint32_t *words, int nwords) {
    CPU cpu;
    CPU *c = &cpu;
    int i, ok;
    if (!words || nwords < W_COUNT) return 1;
    for (i = 0; i < nwords; i++) words[i] = 0;
    if (uc_image_reset(mem, mem_size)) return 2;
    for (i = 0; i < section_count; i++)
        if (uc_image_map(&sections[i])) return 3;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 4;
    g_mem = mem;

    run_ready(c, 0);
    save_common(words, nwords, c, W_READY_STATUS, W_READY_HASH, W_READY_EIP, W_READY_ESP,
                W_READY_EAX, W_READY_CALLS, W_READY_UNIQUE, W_READY_DEPTH, W_READY_FAULT_ADDR);
    SETW(words, W_READY_EBX, c->ebx);
    SETW(words, W_READY_ECX, c->ecx);
    SETW(words, W_READY_ESI, c->esi);
    SETW(words, W_READY_EDI, c->edi);
    SETW(words, W_READY_EBP, c->ebp);
    SETW(words, W_READY_IMPORTS, uc_stat_imports);
    SETW(words, W_READY_INDIRECT, uc_stat_indirect);
    SETW(words, W_READY_FLAG, g_mem[0x0188dafc]);
    SETW(words, W_READY_FAULT_EIP, uc_access_fault.eip);
    SETW(words, W_READY_FAULT_FN, uc_access_fault.function_va);
    SETW(words, W_READY_FAULT_KIND, uc_access_fault.active ? (uint32_t)uc_access_fault.kind : 0);
    SETW(words, W_READY_LIMIT, uc_limit_stop.active ? (uint32_t)uc_limit_stop.code : 0);
    SETW(words, W_READY_CHAIN_N, chain_n);
    for (i = 0; i < seen_n && i < 40; i++) SETW(words, W_READY_FN_0 + i, seen_fn[i]);
    for (i = 0; i < chain_n && i < 16; i++) SETW(words, W_READY_CHAIN_0 + i, chain[i]);
    for (i = 0; i < import_n && i < 8; i++) SETW(words, W_READY_IMP_0 + i, import_seen[i]);
    for (i = 0; i < 8; i++) SETW(words, W_READY_OBJ_0 + i, *(uint32_t *)(g_mem + OBJ + i * 4));
    SETW(words, W_READY_OBJ_0 + 7, *(uint32_t *)(g_mem + OBJ + 0x184));

    if (uc_image_reset(mem, mem_size)) return 5;
    for (i = 0; i < section_count; i++)
        if (uc_image_map(&sections[i])) return 6;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 7;
    g_mem = mem;
    run_ready(c, 0);
    save_common(words, nwords, c, W_REPEAT_STATUS, W_REPEAT_HASH, W_REPEAT_EIP, W_REPEAT_ESP,
                W_REPEAT_EAX, W_REPEAT_CALLS, W_REPEAT_UNIQUE, W_REPEAT_DEPTH, W_REPEAT_FAULT);

    if (uc_image_reset(mem, mem_size)) return 8;
    for (i = 0; i < section_count; i++)
        if (uc_image_map(&sections[i])) return 9;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 10;
    g_mem = mem;
    run_ready(c, 1);
    save_common(words, nwords, c, W_OTHER_STATUS, W_OTHER_HASH, W_OTHER_EIP, W_OTHER_ESP,
                W_OTHER_EAX, W_OTHER_CALLS, W_OTHER_UNIQUE, W_OTHER_DEPTH, W_OTHER_FAULT);
    for (i = 0; i < seen_n && i < 40; i++) SETW(words, W_OTHER_FN_0 + i, seen_fn[i]);
    for (i = 0; i < 8; i++) SETW(words, W_OTHER_OBJ_0 + i, *(uint32_t *)(g_mem + OBJ + i * 4));

    if (uc_image_reset(mem, mem_size)) return 21;
    for (i = 0; i < section_count; i++)
        if (uc_image_map(&sections[i])) return 22;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 23;
    g_mem = mem;
    run_ready(c, 1);
    SETW(words, W_OTHER_REPEAT_STATUS, status_of(c));
    SETW(words, W_OTHER_REPEAT_HASH, memhash(OBJ, 0x200u));
    SETW(words, W_OTHER_REPEAT_EIP, c->eip);
    SETW(words, W_OTHER_REPEAT_CALLS, uc_stat_calls);
    SETW(words, W_OTHER_REPEAT_UNIQUE, seen_n);
    SETW(words, W_OTHER_REPEAT_FAULT, uc_access_fault.active ? uc_access_fault.address : 0);

    if (uc_image_reset(mem, mem_size)) return 11;
    for (i = 0; i < section_count; i++)
        if (uc_image_map(&sections[i])) return 12;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 13;
    g_mem = mem;
    run_pure(c, 0);
    SETW(words, W_PURE_STATUS, status_of(c));
    SETW(words, W_PURE_CALLS, uc_stat_calls);
    SETW(words, W_PURE_UNIQUE, seen_n);
    SETW(words, W_PURE_DEPTH, max_depth);
    SETW(words, W_PURE_EIP, c->eip);
    SETW(words, W_PURE_ESP, c->esp);
    SETW(words, W_PURE_EAX, c->eax);
    SETW(words, W_PURE_HASH, memhash(OBJ, 0x200u));
    SETW(words, W_PURE_FAULT, uc_access_fault.active ? uc_access_fault.address : 0);
    for (i = 0; i < seen_n && i < 24; i++) SETW(words, W_PURE_FN_0 + i, seen_fn[i]);

    if (uc_image_reset(mem, mem_size)) return 14;
    for (i = 0; i < section_count; i++)
        if (uc_image_map(&sections[i])) return 15;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 16;
    g_mem = mem;
    run_pure(c, 1);
    SETW(words, W_PURE_B_STATUS, status_of(c));
    SETW(words, W_PURE_B_HASH, memhash(OBJ, 0x200u));
    SETW(words, W_PURE_B_EIP, c->eip);
    SETW(words, W_PURE_B_CALLS, uc_stat_calls);
    SETW(words, W_PURE_B_UNIQUE, seen_n);
    SETW(words, W_PURE_B_FAULT, uc_access_fault.active ? uc_access_fault.address : 0);

    if (uc_image_reset(mem, mem_size)) return 17;
    for (i = 0; i < section_count; i++)
        if (uc_image_map(&sections[i])) return 18;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 19;
    g_mem = mem;
    run_bound(c);
    SETW(words, W_BOUND_STATUS, status_of(c));
    SETW(words, W_BOUND_EIP, c->eip);
    SETW(words, W_BOUND_FN, stop_fn ? stop_fn : uc_current_fn);
    SETW(words, W_BOUND_TARGET, last_indirect);
    SETW(words, W_BOUND_CALLS, uc_stat_calls);
    SETW(words, W_BOUND_DEPTH, max_depth);
    SETW(words, W_BOUND_IMPORTS, uc_stat_imports);
    SETW(words, W_BOUND_INDIRECT, uc_stat_indirect);
    SETW(words, W_BOUND_FAULT_ADDR, uc_access_fault.active ? uc_access_fault.address : 0);
    SETW(words, W_BOUND_FAULT_FN, uc_access_fault.function_va);
    SETW(words, W_BOUND_LIMIT, uc_limit_stop.active ? (uint32_t)uc_limit_stop.code : 0);
    SETW(words, W_BOUND_CHAIN_N, chain_n);
    for (i = 0; i < chain_n && i < 16; i++) SETW(words, W_BOUND_CHAIN_0 + i, chain[i]);
    store_trace(words, nwords);

    uc_limit_hook = 0;
    uc_access_clear();
    (void)uc_guest_load32(0x01fc7000u, &ok);
    SETW(words, W_SITEXT_0, uc_access_fault.active);
    SETW(words, W_SITEXT_1, uc_access_fault.address);
    SETW(words, W_SITEXT_2, (uint32_t)uc_access_fault.kind);
    SETW(words, W_SITEXT_3, uc_access_fault.section[0]);
    SETW(words, W_SITEXT_4, uc_access_fault.section[1]);
    SETW(words, W_SITEXT_5, uc_access_fault.section[2]);
    (void)ok;
    return 0;
}
'''


def names_of(words, prefix, count):
    out = []
    for i in range(count):
        value = words[INDEX["%s_%d" % (prefix, i)]]
        if not value:
            continue
        out.append(value)
    return out


def main():
    game = sys.argv[1]
    frontier = json.load(open(os.path.join(ROOT, "analysis", "undercover", "runtime-frontier.json"), encoding="utf-8"))
    abi = json.load(open(os.path.join(ROOT, "analysis", "undercover", "import-abi.json"), encoding="utf-8"))
    ready = [int(x, 16) for x in frontier["all_node_extremes"]["READY_WITH_IMPLEMENTED_IMPORTS"]["functions"]]
    pure = [int(x, 16) for x in frontier["all_node_extremes"]["READY"]["functions"]]
    funcs = []
    for addr in ready + pure + [BOUNDARY]:
        if addr not in funcs:
            funcs.append(addr)
    thunks = set(int(row["thunk"], 16) for row in abi["imports"])
    info = uca.read_inputs(game)
    image = p7.read_sections(game)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=True)
    bodies = []
    for addr in funcs:
        try:
            code, _ = lifter.lift(addr)
        except Exception as exc:
            sys.exit("lift %08x: %s" % (addr, exc))
        name, code = instrument(code, addr, thunks)
        bodies.append((addr, name, code))
    src = build_source(bodies, thunks)
    if "DISPATCH_" in src.split("void dispatch_indirect", 1)[-1]:
        pass
    work = tempfile.mkdtemp(prefix="uc-phase10-")
    c_path = os.path.join(work, "phase10.c")
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
            err = proc.stderr
            sys.stderr.write(err[:2500])
            sys.stderr.write("\n---\n")
            sys.stderr.write(err[-1500:])
            print("compile failed", src_path)
            print("work", work)
            sys.exit(proc.returncode or 1)
        objs.append(obj)
    dll = os.path.join(work, "uc_phase10.dll")
    p7.link(objs, dll)
    lib = ctypes.CDLL(dll)
    lib.uc_phase10_words.restype = ctypes.c_int
    count = lib.uc_phase10_words()
    if count != len(FIELDS):
        print("word count", count, len(FIELDS))
        sys.exit(1)
    ucrt = ctypes.CDLL("ucrtbase.dll")
    unary = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_double)
    sqrt_t = ctypes.CFUNCTYPE(ctypes.c_float, ctypes.c_float)
    fabs_raw = ucrt.fabs
    fabs_raw.argtypes = [ctypes.c_double]
    fabs_raw.restype = ctypes.c_double
    sqrt_raw = ucrt.sqrtf
    sqrt_raw.argtypes = [ctypes.c_float]
    sqrt_raw.restype = ctypes.c_float
    bound = [unary(fabs_raw), sqrt_t(sqrt_raw)]
    now_ms = ctypes.CFUNCTYPE(ctypes.c_uint64)(lambda: int(time.perf_counter() * 1000))
    lib.uc_phase10_bind.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.uc_phase10_bind(bound[0], bound[1], now_ms)
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
    words = (ctypes.c_uint32 * len(FIELDS))()
    lib.uc_phase10_run.restype = ctypes.c_int
    lib.uc_phase10_run.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32,
        ctypes.POINTER(p7.Section), ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
    ]
    rc = lib.uc_phase10_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        arr, len(items), words, len(FIELDS))
    w = words

    def show(title, status, calls, unique, depth, eip, esp, eax, fault, fns):
        print(title, "status", status, "calls", calls, "unique", unique, "depth", depth)
        print("  eip", hex(eip), "esp", hex(esp), "eax", hex(eax), "fault", hex(fault))
        print("  fns", [hex(x) for x in fns])

    show("ready", w[INDEX["ready_status"]], w[INDEX["ready_calls"]], w[INDEX["ready_unique"]],
         w[INDEX["ready_depth"]], w[INDEX["ready_eip"]], w[INDEX["ready_esp"]], w[INDEX["ready_eax"]],
         w[INDEX["ready_fault_addr"]], names_of(w, "ready_fn", 40))
    print("  regs", hex(w[INDEX["ready_ebx"]]), hex(w[INDEX["ready_ecx"]]), hex(w[INDEX["ready_esi"]]),
          hex(w[INDEX["ready_edi"]]), hex(w[INDEX["ready_ebp"]]), "fault_fn", hex(w[INDEX["ready_fault_fn"]]),
          "fault_eip", hex(w[INDEX["ready_fault_eip"]]))
    print("  imports", w[INDEX["ready_imports"]], [hex(w[INDEX["ready_imp_%d" % i]]) for i in range(8) if w[INDEX["ready_imp_%d" % i]]])
    print("  indirect", w[INDEX["ready_indirect"]], "limit", w[INDEX["ready_limit"]], "flag", w[INDEX["ready_flag"]])
    print("  hash", hex(w[INDEX["ready_hash"]]), "chain", [hex(w[INDEX["ready_chain_%d" % i]]) for i in range(w[INDEX["ready_chain_n"]])])
    print("  obj", [hex(w[INDEX["ready_obj_%d" % i]]) for i in range(8)])
    print("repeat", w[INDEX["repeat_status"]], hex(w[INDEX["repeat_hash"]]), "calls", w[INDEX["repeat_calls"]],
          "unique", w[INDEX["repeat_unique"]], "eip", hex(w[INDEX["repeat_eip"]]))
    show("other", w[INDEX["other_status"]], w[INDEX["other_calls"]], w[INDEX["other_unique"]],
         w[INDEX["other_depth"]], w[INDEX["other_eip"]], w[INDEX["other_esp"]], w[INDEX["other_eax"]],
         w[INDEX["other_fault"]], names_of(w, "other_fn", 40))
    print("  other hash", hex(w[INDEX["other_hash"]]), "obj", [hex(w[INDEX["other_obj_%d" % i]]) for i in range(8)])
    print("other repeat", w[INDEX["other_repeat_status"]], hex(w[INDEX["other_repeat_hash"]]),
          "eip", hex(w[INDEX["other_repeat_eip"]]), "calls", w[INDEX["other_repeat_calls"]],
          "unique", w[INDEX["other_repeat_unique"]])
    show("pure", w[INDEX["pure_status"]], w[INDEX["pure_calls"]], w[INDEX["pure_unique"]],
         w[INDEX["pure_depth"]], w[INDEX["pure_eip"]], w[INDEX["pure_esp"]], w[INDEX["pure_eax"]],
         w[INDEX["pure_fault"]], names_of(w, "pure_fn", 24))
    print("  pure hash", hex(w[INDEX["pure_hash"]]))
    print("pure_b", w[INDEX["pure_b_status"]], "hash", hex(w[INDEX["pure_b_hash"]]),
          "eip", hex(w[INDEX["pure_b_eip"]]), "calls", w[INDEX["pure_b_calls"]],
          "unique", w[INDEX["pure_b_unique"]], "fault", hex(w[INDEX["pure_b_fault"]]))
    print("boundary status", w[INDEX["bound_status"]], "eip", hex(w[INDEX["bound_eip"]]),
          "fn", hex(w[INDEX["bound_fn"]]), "target", hex(w[INDEX["bound_target"]]))
    print("  calls", w[INDEX["bound_calls"]], "depth", w[INDEX["bound_depth"]],
          "imports", w[INDEX["bound_imports"]], "indirect", w[INDEX["bound_indirect"]],
          "fault", hex(w[INDEX["bound_fault_addr"]]), "fault_fn", hex(w[INDEX["bound_fault_fn"]]),
          "limit", w[INDEX["bound_limit"]])
    print("  chain", [hex(w[INDEX["bound_chain_%d" % i]]) for i in range(w[INDEX["bound_chain_n"]])])
    for i in range(w[INDEX["bound_trace_n"]]):
        print("  trace", w[INDEX["bound_tk_%d" % i]], hex(w[INDEX["bound_tf_%d" % i]]),
              hex(w[INDEX["bound_te_%d" % i]]), hex(w[INDEX["bound_tt_%d" % i]]))
    print("sitext", w[INDEX["sitext_0"]], hex(w[INDEX["sitext_1"]]), w[INDEX["sitext_2"]],
          bytes([w[INDEX["sitext_3"]], w[INDEX["sitext_4"]], w[INDEX["sitext_5"]]]))
    print("work", work)
    if rc != 0:
        print("run failed", rc)
        sys.exit(1)
    same = (
        w[INDEX["ready_status"]] == w[INDEX["repeat_status"]]
        and w[INDEX["ready_hash"]] == w[INDEX["repeat_hash"]]
        and w[INDEX["ready_eip"]] == w[INDEX["repeat_eip"]]
        and w[INDEX["ready_esp"]] == w[INDEX["repeat_esp"]]
        and w[INDEX["ready_eax"]] == w[INDEX["repeat_eax"]]
        and w[INDEX["ready_calls"]] == w[INDEX["repeat_calls"]]
        and w[INDEX["ready_unique"]] == w[INDEX["repeat_unique"]]
        and w[INDEX["ready_fault_addr"]] == w[INDEX["repeat_fault"]]
    )
    if not same:
        print("repeat mismatch")
        sys.exit(1)
    other_same = (
        w[INDEX["other_status"]] == w[INDEX["other_repeat_status"]]
        and w[INDEX["other_hash"]] == w[INDEX["other_repeat_hash"]]
        and w[INDEX["other_eip"]] == w[INDEX["other_repeat_eip"]]
        and w[INDEX["other_calls"]] == w[INDEX["other_repeat_calls"]]
        and w[INDEX["other_unique"]] == w[INDEX["other_repeat_unique"]]
        and w[INDEX["other_fault"]] == w[INDEX["other_repeat_fault"]]
    )
    if not other_same:
        print("completed-input repeat mismatch")
        sys.exit(1)
    if not w[INDEX["sitext_0"]] or w[INDEX["sitext_1"]] != 0x01FC7000:
        print("sitext was not rejected")
        sys.exit(1)
    if w[INDEX["bound_status"]] == 0:
        print("boundary run did not stop")
        sys.exit(1)
    print("uc phase10 tests passed")


if __name__ == "__main__":
    main()
