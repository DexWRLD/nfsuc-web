"""Phase 11 initializer harness.

Runs the ordinary leaf at 0x009E8AD0, which the provenance scan found writing
0x0189D1A4, then retries 0x0099DCD0. The harness does not store a guessed
address into that slot. A zero target still stops. Protected sections stay
unmapped and the game executable is not started.
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
INIT = 0x009E8AD0
CALLBACK = 0x009E78C0
SLOT = 0x0189D1A4
STORE_EIP = 0x009E8B16
BOUNDARY = 0x0099DCD0
BSS_LO = 0x012A6000
BSS_HI = 0x018B1E74

FIELDS = [
    "pre_status", "pre_eip", "pre_target", "pre_slot", "pre_calls", "pre_cb",
    "init_status", "init_eip", "init_esp", "init_slot", "init_writes",
    "init_slot_eip", "init_slot_old", "init_slot_new", "init_slot_fn",
    "range_n", "range_bytes", "range_text_ptrs",
]
FIELDS += ["range_addr_%d" % i for i in range(24)]
FIELDS += ["range_size_%d" % i for i in range(24)]
FIELDS += ["range_new_%d" % i for i in range(24)]
FIELDS += [
    "post_status", "post_eip", "post_esp", "post_eax", "post_target",
    "post_calls", "post_unique", "post_depth", "post_fault", "post_slot",
    "post_cb", "flag",
]
FIELDS += ["post_fn_%d" % i for i in range(32)]
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
        lambda m: "if (uc_stop) return; c->eip = 0x%s; uc_guest_eip = 0x%s; /* %s  " % (
            m.group(1), m.group(1), m.group(1)),
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

uint8_t *g_mem;
int _fltused;
void __chkstk(void) {}
static int uc_stop;
static int uc_import_fail;
static int depth;
static int max_depth;
static int seen_n;
static uint32_t seen_fn[64];
static uint32_t last_indirect;
static uint8_t bss_snap[%d];
double (*uc_host_fabs)(double);
float (*uc_host_sqrtf)(float);

''' % (BSS_HI - BSS_LO) + "\n".join(enum) + r'''

#define SETW(w, i, v) do { if ((i) < nwords) (w)[i] = (uint32_t)(v); } while (0)
#define SLOT 0x0189D1A4u
#define INIT 0x009E8AD0u
#define CALLBACK 0x009E78C0u
#define BSS_LO 0x012A6000u
#define BSS_HI 0x018B1E74u
#define TEXT_LO 0x00401000u
#define TEXT_HI 0x00B61000u

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
    if (uc_access_fault.active || uc_limit_stop.active) uc_stop = 1;
    return 0;
}
static void uc_note_enter(uint32_t va) {
    int i;
    depth++;
    if (depth > max_depth) max_depth = depth;
    for (i = 0; i < seen_n; i++) if (seen_fn[i] == va) return;
    if (seen_n < 64) seen_fn[seen_n++] = va;
}
static void uc_note_leave(void) {
    if (depth > 0) depth--;
}
static uint32_t load32(uint32_t addr) {
    return (uint32_t)g_mem[addr] | ((uint32_t)g_mem[addr + 1] << 8)
        | ((uint32_t)g_mem[addr + 2] << 16) | ((uint32_t)g_mem[addr + 3] << 24);
}
static int seen_callback(void) {
    int i;
    for (i = 0; i < seen_n; i++) if (seen_fn[i] == CALLBACK) return 1;
    return 0;
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
        return;
    }
    uc_current_fn = caller;
    if (uc_stop) return;
}

static void uc_import_thunk(CPU *c, uint32_t thunk) {
    const UcImport *imp = uc_import_find(thunk);
    uc_trace(UC_EV_IMPORT_CALL, uc_current_fn, c->eip, thunk, c);
    if (!uc_limit_note_import(c, thunk) || !imp || !uc_import_invoke(c, imp, 0)) {
        uc_import_fail = 1;
        uc_stop = 1;
        return;
    }
}

''' + "\n".join(stubs) + "\n" + joined + r'''

void dispatch_indirect(CPU *c, uint32_t target) {
    uint32_t caller = uc_current_fn;
    last_indirect = target;
    uc_trace(UC_EV_INDIRECT_CALL, caller, c->eip, target, c);
    uc_limit_note_indirect(c, target);
    if (uc_stop || !target) { uc_stop = 1; return; }
    if (!uc_guest_execute(target)) { uc_stop = 1; return; }
    switch (target) {
''' + "\n".join(switch) + r'''
    default:
        uc_stop = 1;
        return;
    }
    uc_current_fn = caller;
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
static void begin_run(void) {
    uc_stop = 0;
    uc_import_fail = 0;
    depth = 0;
    max_depth = 0;
    seen_n = 0;
    last_indirect = 0;
    uc_access_clear();
    uc_limits_clear();
    uc_limit_calls = 20000u;
    uc_limit_depth = 32u;
    uc_limit_imports = 1000u;
    uc_limit_indirect = 32u;
    uc_limit_ms = 5000u;
    uc_exec_trace = 1;
    uc_limit_hook = poll;
}
static void end_run(void) { uc_limit_hook = 0; }
static uint32_t status_of(CPU *c) {
    if (uc_access_fault.active) return 1;
    if (uc_import_fail) return 3;
    if (uc_stat_indirect && uc_stop && c->eip != 0x00dec0deu) return 2;
    if (uc_limit_stop.active) return 4;
    if (c->eip == 0x00dec0deu && !uc_stop) return 0;
    return 5;
}
static void save_bss(void) {
    memcpy(bss_snap, g_mem + BSS_LO, BSS_HI - BSS_LO);
}
static void report_diff(uint32_t *words, int nwords) {
    uint32_t i = 0, n = BSS_HI - BSS_LO, ranges = 0, bytes = 0, textp = 0;
    while (i < n) {
        uint32_t start, size, addr, val;
        if (g_mem[BSS_LO + i] == bss_snap[i]) { i++; continue; }
        start = i;
        while (i < n && g_mem[BSS_LO + i] != bss_snap[i]) i++;
        size = i - start;
        bytes += size;
        addr = BSS_LO + start;
        val = load32(addr);
        if (val >= TEXT_LO && val < TEXT_HI) textp++;
        if (ranges < 24) {
            SETW(words, W_RANGE_ADDR_0 + ranges, addr);
            SETW(words, W_RANGE_SIZE_0 + ranges, size);
            SETW(words, W_RANGE_NEW_0 + ranges, val);
        }
        ranges++;
    }
    SETW(words, W_RANGE_N, ranges);
    SETW(words, W_RANGE_BYTES, bytes);
    SETW(words, W_RANGE_TEXT_PTRS, textp);
}
static void note_slot_write(uint32_t *words, int nwords) {
    int i, n = uc_gwrite_count;
    SETW(words, W_INIT_WRITES, uc_gwrite_total);
    for (i = 0; i < n; i++) {
        if (uc_gwrites[i].addr != SLOT) continue;
        SETW(words, W_INIT_SLOT_EIP, uc_gwrites[i].eip);
        SETW(words, W_INIT_SLOT_OLD, uc_gwrites[i].oldv);
        SETW(words, W_INIT_SLOT_NEW, uc_gwrites[i].newv);
        SETW(words, W_INIT_SLOT_FN, uc_gwrites[i].fn);
        return;
    }
}

__declspec(dllexport) int uc_phase11_words(void) { return W_COUNT; }

__declspec(dllexport) void uc_phase11_bind(void *fabs_fn, void *sqrtf_fn, uint64_t (*now_ms)(void)) {
    uc_host_fabs = (double (*)(double))fabs_fn;
    uc_host_sqrtf = (float (*)(float))sqrtf_fn;
    uc_host_ms = now_ms;
}

__declspec(dllexport) int uc_phase11_run(uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int section_count, uint32_t *words, int nwords) {
    CPU cpu;
    CPU *c = &cpu;
    int i;
    if (!words || nwords < W_COUNT) return 1;
    for (i = 0; i < nwords; i++) words[i] = 0;
    if (uc_image_reset(mem, mem_size)) return 2;
    for (i = 0; i < section_count; i++)
        if (uc_image_map(&sections[i])) return 3;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE))
        return 4;
    g_mem = mem;
    uc_global_trace = 0;

    prepare_cpu(c);
    begin_run();
    PUSH32(2u);
    PUSH32(0);
    PUSH32(0x00dec0deu);
    uc_direct(0x0099dcd0u, c);
    end_run();
    SETW(words, W_PRE_STATUS, status_of(c));
    SETW(words, W_PRE_EIP, c->eip);
    SETW(words, W_PRE_TARGET, last_indirect);
    SETW(words, W_PRE_SLOT, load32(SLOT));
    SETW(words, W_PRE_CALLS, uc_stat_calls);
    SETW(words, W_PRE_CB, seen_callback());

    save_bss();
    uc_global_clear();
    uc_global_lo = BSS_LO;
    uc_global_hi = BSS_HI;
    uc_global_trace = 1;
    prepare_cpu(c);
    begin_run();
    PUSH32(0x00dec0deu);
    uc_direct(INIT, c);
    end_run();
    uc_global_trace = 0;
    SETW(words, W_INIT_STATUS, status_of(c));
    SETW(words, W_INIT_EIP, c->eip);
    SETW(words, W_INIT_ESP, c->esp);
    SETW(words, W_INIT_SLOT, load32(SLOT));
    note_slot_write(words, nwords);
    report_diff(words, nwords);

    prepare_cpu(c);
    begin_run();
    PUSH32(2u);
    PUSH32(0);
    PUSH32(0x00dec0deu);
    uc_direct(0x0099dcd0u, c);
    end_run();
    SETW(words, W_POST_STATUS, status_of(c));
    SETW(words, W_POST_EIP, c->eip);
    SETW(words, W_POST_ESP, c->esp);
    SETW(words, W_POST_EAX, c->eax);
    SETW(words, W_POST_TARGET, last_indirect);
    SETW(words, W_POST_CALLS, uc_stat_calls);
    SETW(words, W_POST_UNIQUE, seen_n);
    SETW(words, W_POST_DEPTH, max_depth);
    SETW(words, W_POST_FAULT, uc_access_fault.active ? uc_access_fault.address : 0);
    SETW(words, W_POST_SLOT, load32(SLOT));
    SETW(words, W_POST_CB, seen_callback());
    SETW(words, W_FLAG, g_mem[0x0188dafc]);
    for (i = 0; i < seen_n && i < 32; i++) SETW(words, W_POST_FN_0 + i, seen_fn[i]);
    return 0;
}
'''


def main():
    game = sys.argv[1]
    frontier = json.load(open(os.path.join(ROOT, "analysis", "undercover", "runtime-frontier.json"), encoding="utf-8"))
    abi = json.load(open(os.path.join(ROOT, "analysis", "undercover", "import-abi.json"), encoding="utf-8"))
    funcs = [INIT, CALLBACK]
    for item in frontier["only_indirect"]["functions"]:
        addr = int(item, 16)
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
    work = tempfile.mkdtemp(prefix="uc-phase11-")
    c_path = os.path.join(work, "phase11.c")
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
            sys.stderr.write(proc.stderr[-2000:])
            print("compile failed", src_path)
            print("work", work)
            sys.exit(proc.returncode or 1)
        objs.append(obj)
    dll = os.path.join(work, "uc_phase11.dll")
    p7.link(objs, dll)
    lib = ctypes.CDLL(dll)
    lib.uc_phase11_words.restype = ctypes.c_int
    if lib.uc_phase11_words() != len(FIELDS):
        sys.exit("word count mismatch")
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
    lib.uc_phase11_bind.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.uc_phase11_bind(bound[0], bound[1], now_ms)
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
    lib.uc_phase11_run.restype = ctypes.c_int
    lib.uc_phase11_run.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32,
        ctypes.POINTER(p7.Section), ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
    ]
    rc = lib.uc_phase11_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        arr, len(items), words, len(FIELDS))
    w = words
    print("pre", w[INDEX["pre_status"]], "eip", hex(w[INDEX["pre_eip"]]),
          "target", hex(w[INDEX["pre_target"]]), "slot", hex(w[INDEX["pre_slot"]]),
          "calls", w[INDEX["pre_calls"]], "cb", w[INDEX["pre_cb"]])
    print("init", w[INDEX["init_status"]], "eip", hex(w[INDEX["init_eip"]]),
          "esp", hex(w[INDEX["init_esp"]]), "slot", hex(w[INDEX["init_slot"]]),
          "writes", w[INDEX["init_writes"]])
    print("  slot write", hex(w[INDEX["init_slot_eip"]]), "fn", hex(w[INDEX["init_slot_fn"]]),
          "old", hex(w[INDEX["init_slot_old"]]), "new", hex(w[INDEX["init_slot_new"]]))
    print("ranges", w[INDEX["range_n"]], "bytes", w[INDEX["range_bytes"]],
          "textish", w[INDEX["range_text_ptrs"]])
    for i in range(min(8, w[INDEX["range_n"]])):
        print("  range", hex(w[INDEX["range_addr_%d" % i]]), w[INDEX["range_size_%d" % i]],
              hex(w[INDEX["range_new_%d" % i]]))
    fns = [w[INDEX["post_fn_%d" % i]] for i in range(w[INDEX["post_unique"]] if w[INDEX["post_unique"]] < 32 else 32)]
    print("post", w[INDEX["post_status"]], "eip", hex(w[INDEX["post_eip"]]),
          "esp", hex(w[INDEX["post_esp"]]), "eax", hex(w[INDEX["post_eax"]]),
          "target", hex(w[INDEX["post_target"]]), "fault", hex(w[INDEX["post_fault"]]))
    print("  calls", w[INDEX["post_calls"]], "unique", w[INDEX["post_unique"]],
          "depth", w[INDEX["post_depth"]], "cb", w[INDEX["post_cb"]],
          "slot", hex(w[INDEX["post_slot"]]), "flag", w[INDEX["flag"]])
    print("  fns", [hex(x) for x in fns])
    print("work", work)
    if rc != 0:
        print("run failed", rc)
        sys.exit(1)
    if w[INDEX["pre_slot"]] != 0 or w[INDEX["pre_target"]] != 0 or w[INDEX["pre_cb"]] != 0:
        print("zero target was not fail-closed")
        sys.exit(1)
    if w[INDEX["pre_status"]] == 0:
        print("pre-init boundary returned")
        sys.exit(1)
    if w[INDEX["init_status"]] != 0 or w[INDEX["init_slot"]] != CALLBACK:
        print("initializer did not write the recorded target")
        sys.exit(1)
    if (w[INDEX["init_slot_eip"]] != STORE_EIP or w[INDEX["init_slot_fn"]] != INIT
            or w[INDEX["init_slot_old"]] != 0 or w[INDEX["init_slot_new"]] != CALLBACK):
        print("slot write was not the ordinary store")
        sys.exit(1)
    if w[INDEX["post_cb"]] != 1 or w[INDEX["post_slot"]] != CALLBACK:
        print("callback was not entered from the initialized slot")
        sys.exit(1)
    if w[INDEX["flag"]] != 0:
        print("flag changed without its writer")
        sys.exit(1)
    print("uc phase11 tests passed")


if __name__ == "__main__":
    main()
