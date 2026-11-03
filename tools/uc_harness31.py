#!/usr/bin/env python3
"""Phase 31 generic real-UC execution harness.

Lifts ordinary HIGH functions (never nfs.exe execution), compiles them with the
guest-checked image runtime and runs one root per spec. Calls that leave the
lifted set, imports without an HLE, rdtsc/cpuid, unsupported instructions and
guest access faults are recorded as the real blocker; nothing is stubbed to
"keep going". Does not start nfs.exe.
"""
import ctypes
import json
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
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

STACK_TOP = 0x0300F000
OBJ_BASE = 0x03004000
SRC_BASE = 0x03004800
TEB_BASE = 0x03010000
RET_SENTINEL = 0x00DEC0DE

K_NONE, K_IMPORT, K_UNLIFTED, K_PROTECTED, K_TIMING, K_UNSUPPORTED, K_FAULT, K_CPUID = range(8)
KIND_NAMES = {
    0: "NONE", 1: "IMPORT", 2: "UNLIFTED", 3: "PROTECTED", 4: "TIMING",
    5: "UNSUPPORTED", 6: "FAULT", 7: "CPUID",
}
PROTECTED_CALLS = {0x00686000, 0x00686030}
ENT_CAP = 160
IMP_CAP = 24


class Spec(ctypes.Structure):
    _fields_ = [
        ("root", ctypes.c_uint32), ("ecx", ctypes.c_uint32), ("edx", ctypes.c_uint32),
        ("nargs", ctypes.c_uint32), ("args", ctypes.c_uint32 * 8),
        ("ninit", ctypes.c_uint32),
        ("init_addr", ctypes.c_uint32 * 64), ("init_val", ctypes.c_uint32 * 64),
        ("nzero", ctypes.c_uint32),
        ("zero_addr", ctypes.c_uint32 * 8), ("zero_len", ctypes.c_uint32 * 8),
        ("teb", ctypes.c_uint32), ("ret_pop", ctypes.c_uint32),
        # DIAGNOSTIC ONLY (never counted in metrics): treat one unresolved IAT
        # target as a stdcall no-op returning TRUE to measure the next blocker.
        ("noop_target", ctypes.c_uint32), ("noop_args", ctypes.c_uint32),
    ]


class Out(ctypes.Structure):
    _fields_ = [
        ("ran", ctypes.c_uint32), ("entered_n", ctypes.c_uint32),
        ("entered", ctypes.c_uint32 * ENT_CAP),
        ("depth_max", ctypes.c_uint32),
        ("blocked_kind", ctypes.c_uint32), ("blocked_va", ctypes.c_uint32),
        ("blocked_fn", ctypes.c_uint32),
        ("clean", ctypes.c_uint32), ("eip", ctypes.c_uint32), ("esp", ctypes.c_uint32),
        ("esp_expected", ctypes.c_uint32), ("eax", ctypes.c_uint32),
        ("fault_active", ctypes.c_uint32), ("fault_addr", ctypes.c_uint32),
        ("fault_why", ctypes.c_char * 48),
        ("nimp", ctypes.c_uint32),
        ("imp_target", ctypes.c_uint32 * IMP_CAP),
        ("imp_ok", ctypes.c_uint32 * IMP_CAP),
        ("imp_hle", ctypes.c_uint32 * IMP_CAP),
        ("tls_alloc", ctypes.c_uint32), ("tls_set", ctypes.c_uint32),
        ("unsupported_why", ctypes.c_char * 48),
        ("mem_eax", ctypes.c_uint32),
        ("diag_hits", ctypes.c_uint32),
        ("ics_calls", ctypes.c_uint32), ("mutex_calls", ctypes.c_uint32),
        ("cs_count", ctypes.c_uint32), ("mutex_count", ctypes.c_uint32),
        ("gpc_calls", ctypes.c_uint32), ("sem_calls", ctypes.c_uint32),
        ("sem_count", ctypes.c_uint32), ("priority_class", ctypes.c_uint32),
        ("gct_calls", ctypes.c_uint32), ("gtp_calls", ctypes.c_uint32),
        ("spc_calls", ctypes.c_uint32), ("stp_calls", ctypes.c_uint32),
        ("thread_priority", ctypes.c_int32),
        ("qpc_calls", ctypes.c_uint32), ("qpf_calls", ctypes.c_uint32),
        ("qpc_ticks_lo", ctypes.c_uint32), ("qpc_ticks_hi", ctypes.c_uint32),
    ]


def instrument(code, addr):
    match = re.search(r"void (sub_[0-9a-f]+)\(CPU \*restrict c\) \{", code)
    if not match:
        raise RuntimeError("no def %08x" % addr)
    name = match.group(1)
    code = code.replace(
        "void %s(CPU *restrict c) {" % name,
        "void %s_impl(CPU *restrict c) {\n"
        "    note_enter(0x%08xu);\n"
        "    if (abort_run) { return; }\n"
        "    uc_fn_enter(0x%08xu, c);" % (name, addr, addr), 1)

    def repl_ret(m):
        extra = m.group(1) or ""
        return ("depth_now--; uc_fn_leave(0x%08xu, c); "
                "POP32(c->eip);%s return;" % (addr, extra))

    code = re.sub(r"POP32\(c->eip\);( c->esp \+= \d+u;)? return;", repl_ret, code)
    code = re.sub(r"sub_([0-9a-f]+)\(c\)",
                  lambda m: "uc_direct(0x%08xu, c)" % int(m.group(1), 16), code)
    code = re.sub(r"MR32\(([^;]*?)\) = \(([^;]*?)\);",
                  r"uc_guest_store32(\1, (uint32_t)(\2), 0);", code)
    code = re.sub(r"MR8\(([^;]*?)\) = \(([^;]*?)\);",
                  r"uc_guest_store8(\1, (uint8_t)(\2));", code)
    return name, code


C_HEAD = r'''
#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"
#include <stddef.h>

uint8_t *g_mem;
int _fltused;
guest_fn_t g_dtab[DISPATCH_TEXT_SIZE];
static int abort_run, blocked_kind, block_tls_set, cur_root;
static uint32_t blocked_va, blocked_fn, tls_alloc_calls, tls_set_calls;
static uint32_t ics_calls, mutex_calls, gpc_calls, sem_calls;
static uint32_t gct_calls, gtp_calls, spc_calls, stp_calls;
static uint32_t qpc_calls, qpf_calls;
static uint32_t entered[%(ent_cap)d];
static int entered_n, depth_now, depth_max;
static uint32_t imp_target[%(imp_cap)d], imp_ok[%(imp_cap)d], imp_hle[%(imp_cap)d];
static int nimp;
static char unsup_why[48];
static uint32_t diag_noop_target, diag_noop_args, diag_hits;
'''

C_RUNTIME = r'''
void *memset(void *dst, int v, size_t n) {
    unsigned char *p = (unsigned char *)dst; while (n--) *p++ = (unsigned char)v; return dst;
}
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst; const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++; return dst;
}
static void zero_bytes(void *p, unsigned n) { memset(p, 0, n); }
/* Host-independent rounding for lifted x87/SSE rounding ops (no libm link). */
double trunc(double x) {
    if (x != x || x >= 9.2e18 || x <= -9.2e18) return x;
    return (double)(long long)x;
}
double floor(double x) { double t = trunc(x); return (t > x) ? t - 1.0 : t; }
double ceil(double x) { double t = trunc(x); return (t < x) ? t + 1.0 : t; }
double nearbyint(double x) {
    double f = floor(x), d = x - f;
    if (d < 0.5) return f;
    if (d > 0.5) return f + 1.0;
    return ((long long)f & 1) ? f + 1.0 : f;
}
static void note_visit(uint32_t fn) {
    int i; for (i = 0; i < entered_n; i++) if (entered[i] == fn) return;
    if (entered_n < %(ent_cap)d) entered[entered_n++] = fn;
}
static void note_block(uint32_t va, int kind) {
    if (!blocked_kind) { blocked_kind = kind; blocked_va = va; blocked_fn = uc_current_fn; }
    abort_run = 1;
}
static void note_enter(uint32_t fn) {
    depth_now++;
    if (depth_now > depth_max) depth_max = depth_now;
    note_visit(fn);
    if (uc_access_fault.active) note_block(uc_access_fault.address, 6);
}
static void uc_direct(uint32_t target, CPU *c) {
    if (abort_run) { POP32(c->eip); return; }
    if (uc_access_fault.active) note_block(uc_access_fault.address, 6);
    switch (target) {
%(switch)s
    case 0x00686000u: case 0x00686030u: note_block(target, 3); POP32(c->eip); return;
    default: note_block(target, 2); POP32(c->eip); return;
    }
}
void dispatch_indirect(CPU *c, uint32_t target) {
    const UcImport *imp = uc_import_find_dispatch_target(target);
    int ok;
    if (abort_run) { POP32(c->eip); return; }
    if (uc_access_fault.active) note_block(uc_access_fault.address, 6);
    if (diag_noop_target && target == diag_noop_target) {
        POP32(c->eip); c->esp += 4u * diag_noop_args; c->eax = 1; diag_hits++; return;
    }
    if (nimp < %(imp_cap)d) { imp_target[nimp] = target; imp_hle[nimp] = imp ? (uint32_t)imp->hle : 0xffffu; }
    if (imp && imp->hle == UC_HLE_TLSALLOC) tls_alloc_calls++;
    if (imp && imp->hle == UC_HLE_TLSSETVALUE) tls_set_calls++;
    if (imp && imp->hle == UC_HLE_INITCRITSEC) ics_calls++;
    if (imp && imp->hle == UC_HLE_CREATEMUTEXA) mutex_calls++;
    if (imp && imp->hle == UC_HLE_GETPRIORITYCLASS) gpc_calls++;
    if (imp && imp->hle == UC_HLE_CREATESEMAPHOREA) sem_calls++;
    if (imp && imp->hle == UC_HLE_GETCURRENTTHREAD) gct_calls++;
    if (imp && imp->hle == UC_HLE_GETTHREADPRIORITY) gtp_calls++;
    if (imp && imp->hle == UC_HLE_SETPRIORITYCLASS) spc_calls++;
    if (imp && imp->hle == UC_HLE_SETTHREADPRIORITY) stp_calls++;
    if (imp && imp->hle == UC_HLE_QUERYPERFORMANCECOUNTER) qpc_calls++;
    if (imp && imp->hle == UC_HLE_QUERYPERFORMANCEFREQUENCY) qpf_calls++;
    ok = imp ? uc_import_invoke(c, imp, 0) : 0;
    if (nimp < %(imp_cap)d) imp_ok[nimp] = (uint32_t)ok;
    nimp++;
    if (ok) return;
    note_block(target, 1);
    /* Not an emulation: only unwinds the call so the aborted run ends in a
     * bounded number of steps. blocked_kind keeps the first real blocker. */
    POP32(c->eip);
    c->eax = 0;
}
void dispatch_tail(CPU *c) { (void)c; note_block(c->eip, 5); }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    int i; (void)c;
    for (i = 0; i < 47 && why && why[i]; i++) unsup_why[i] = why[i];
    unsup_why[i] = 0;
    note_block(addr, 5);
}
void cpuid_shim(CPU *c) { (void)c; note_block(c->eip, 7); }
/* Coherent virtual TSC from the guest performance clock — not host time.
 * Blocking here would stop the ordinary QPC calibration path after HLE QPC. */
uint64_t rdtsc_shim(void) { return uc_guest_clock_tsc(); }
'''

C_RUN = r'''
typedef struct Spec {
    uint32_t root, ecx, edx, nargs, args[8], ninit, init_addr[64], init_val[64];
    uint32_t nzero, zero_addr[8], zero_len[8], teb, ret_pop, noop_target, noop_args;
} Spec;
typedef struct Out {
    uint32_t ran, entered_n, entered[%(ent_cap)d], depth_max, blocked_kind, blocked_va, blocked_fn;
    uint32_t clean, eip, esp, esp_expected, eax, fault_active, fault_addr;
    char fault_why[48];
    uint32_t nimp, imp_target[%(imp_cap)d], imp_ok[%(imp_cap)d], imp_hle[%(imp_cap)d];
    uint32_t tls_alloc, tls_set;
    char unsupported_why[48];
    uint32_t mem_eax;
    uint32_t diag_hits;
    uint32_t ics_calls, mutex_calls, cs_count, mutex_count;
    uint32_t gpc_calls, sem_calls, sem_count, priority_class;
    uint32_t gct_calls, gtp_calls, spc_calls, stp_calls;
    int32_t thread_priority;
    uint32_t qpc_calls, qpf_calls, qpc_ticks_lo, qpc_ticks_hi;
} Out;

static void wr32(uint32_t a, uint32_t v) { uc_guest_store32(a, v, 0); }

__declspec(dllexport) int uc_p31_setup(
    uint8_t *mem, uint32_t mem_size, const UcSectionIn *sections, int nsections) {
    int i;
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) if (uc_image_map(&sections[i])) return 2;
    if (uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ|UC_MEM_WRITE)) return 3;
    if (uc_image_add_private("obj", 0x03004000u, 0x4000u, UC_MEM_READ|UC_MEM_WRITE)) return 4;
    if (uc_image_add_private("teb", 0x03010000u, 0x1000u, UC_MEM_READ|UC_MEM_WRITE)) return 5;
    (void)uc_import_bind_hle_iats();
    return 0;
}

__declspec(dllexport) int uc_p31_run(const Spec *s, Out *out) {
    CPU cpu, *c = &cpu;
    uint32_t i, esp0, argn;
    zero_bytes(out, sizeof *out);
    zero_bytes(c, sizeof *c);
    uc_tls_reset();
    uc_sync_reset();
    uc_process_reset();
    uc_thread_reset();
    uc_guest_clock_reset();
    uc_access_fault.active = 0;
    uc_import_fault.active = 0;
    uc_current_fn = 0;
    entered_n = depth_now = depth_max = nimp = 0;
    abort_run = blocked_kind = 0; blocked_va = blocked_fn = 0;
    tls_alloc_calls = tls_set_calls = 0;
    ics_calls = mutex_calls = gpc_calls = sem_calls = 0;
    gct_calls = gtp_calls = spc_calls = stp_calls = 0;
    qpc_calls = qpf_calls = 0;
    unsup_why[0] = 0;
    diag_noop_target = s->noop_target; diag_noop_args = s->noop_args; diag_hits = 0;
    for (i = 0; i < 0x1000; i++) uc_guest_store8(0x03004000u + i, 0);
    for (i = 0; i < s->nzero; i++) { uint32_t k; for (k = 0; k < s->zero_len[i]; k++) uc_guest_store8(s->zero_addr[i] + k, 0); }
    for (i = 0; i < s->ninit; i++) wr32(s->init_addr[i], s->init_val[i]);
    if (s->teb) {
        c->fs_base = 0x03010000u;
        wr32(0x03010000u, 0xffffffffu);
    }
    argn = s->nargs;
    esp0 = 0x0300f000u;
    c->esp = esp0;
    wr32(esp0, 0x00dec0deu);
    for (i = 0; i < argn; i++) wr32(esp0 + 4u + 4u * i, s->args[i]);
    c->ecx = s->ecx; c->edx = s->edx;
    out->esp_expected = esp0 + 4u + s->ret_pop;
    uc_direct(s->root, c);
    if (uc_access_fault.active && !blocked_kind) { blocked_kind = 6; blocked_va = uc_access_fault.address; blocked_fn = uc_current_fn; }
    out->ran = 1;
    out->entered_n = (uint32_t)entered_n;
    for (i = 0; i < (uint32_t)entered_n && i < %(ent_cap)d; i++) out->entered[i] = entered[i];
    out->depth_max = (uint32_t)depth_max;
    out->blocked_kind = (uint32_t)blocked_kind;
    out->blocked_va = blocked_va;
    out->blocked_fn = blocked_fn;
    out->eip = c->eip; out->esp = c->esp; out->eax = c->eax;
    out->clean = (!blocked_kind && !uc_access_fault.active && c->eip == 0x00dec0deu && c->esp == out->esp_expected) ? 1u : 0u;
    out->fault_active = (uint32_t)uc_access_fault.active;
    out->fault_addr = uc_access_fault.address;
    for (i = 0; i < 47 && uc_access_fault.why[i]; i++) out->fault_why[i] = uc_access_fault.why[i];
    out->nimp = (uint32_t)nimp;
    for (i = 0; i < (uint32_t)nimp && i < %(imp_cap)d; i++) {
        out->imp_target[i] = imp_target[i]; out->imp_ok[i] = imp_ok[i]; out->imp_hle[i] = imp_hle[i];
    }
    out->tls_alloc = tls_alloc_calls; out->tls_set = tls_set_calls; out->diag_hits = diag_hits;
    out->ics_calls = ics_calls; out->mutex_calls = mutex_calls;
    out->cs_count = uc_sync_critsec_count(); out->mutex_count = uc_sync_mutex_count();
    out->gpc_calls = gpc_calls; out->sem_calls = sem_calls;
    out->sem_count = uc_sync_semaphore_count();
    out->priority_class = uc_process_priority_class();
    out->gct_calls = gct_calls; out->gtp_calls = gtp_calls;
    out->spc_calls = spc_calls; out->stp_calls = stp_calls;
    out->thread_priority = uc_thread_priority();
    out->qpc_calls = qpc_calls; out->qpf_calls = qpf_calls;
    {
        uint64_t ticks = uc_guest_clock_qpc();
        out->qpc_ticks_lo = (uint32_t)ticks;
        out->qpc_ticks_hi = (uint32_t)(ticks >> 32);
    }
    for (i = 0; i < 47 && unsup_why[i]; i++) out->unsupported_why[i] = unsup_why[i];
    return 0;
}
'''


def build_source(bodies):
    decls, switch = [], []
    for addr, name, _c in bodies:
        decls.append("void %s_impl(CPU *restrict c);" % name)
        switch.append("    case 0x%08xu: %s_impl(c); break;" % (addr, name))
    fmt = {"ent_cap": ENT_CAP, "imp_cap": IMP_CAP, "switch": "\n".join(switch)}
    joined = "\n".join(c for _a, _n, c in bodies)
    return (C_HEAD % fmt + "\n" + "\n".join(decls) + "\n"
            + C_RUNTIME % fmt + "\n" + joined + "\n" + C_RUN % fmt)


class Harness:
    def __init__(self, addrs, work=None):
        self.addrs = sorted(set(addrs))
        info = uca.read_inputs(GAME)
        self.image = p7.read_sections(GAME)
        lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
        bodies, self.failed = [], {}
        for addr in self.addrs:
            try:
                code, _calls = lifter.lift(addr)
                name, code = instrument(code, addr)
                bodies.append((addr, name, code))
            except Exception as exc:  # lifter Unsupported etc.
                self.failed[addr] = str(exc)[:80]
        self.lifted = [b[0] for b in bodies]
        self.src = build_source(bodies)
        self.work = work or tempfile.mkdtemp(prefix="uc-p31-")
        self.c_path = os.path.join(self.work, "p31.c")
        with open(self.c_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(self.src)
        includes = ["-I", os.path.join(ROOT, "tests", "uc_host"),
                    "-I", os.path.join(ROOT, "tests"),
                    "-I", os.path.join(ROOT, "runtime")]
        common = [p7.clang(), "-c", "-std=c11", "-O0", "-ffreestanding",
                  "-DUC_GUEST_CHECKED", "-w"] + includes
        objs = []
        for src_path in (self.c_path, os.path.join(ROOT, "runtime", "uc_import.c"),
                         os.path.join(ROOT, "runtime", "uc_image.c")):
            obj = os.path.join(self.work, os.path.basename(src_path) + ".o")
            proc = subprocess.run(common + ["-o", obj, src_path], capture_output=True, text=True)
            if proc.returncode != 0:
                sys.stderr.write(proc.stderr[:4000])
                raise RuntimeError("compile failed: %s" % self.c_path)
            objs.append(obj)
        self.dll_path = os.path.join(self.work, "uc_p31.dll")
        p7.link(objs, self.dll_path)
        self.lib = ctypes.CDLL(self.dll_path)
        self.lib.uc_p31_setup.restype = ctypes.c_int
        self.lib.uc_p31_run.restype = ctypes.c_int
        self.lib.uc_p31_run.argtypes = [ctypes.POINTER(Spec), ctypes.POINTER(Out)]
        self.mem = (ctypes.c_uint8 * p7.MEM_SIZE)()
        items, self.keep = [], []
        for sec in self.image["sections"]:
            if sec["name"] not in p7.ALLOWED and sec["name"] not in p7.PROTECTED:
                continue
            item = p7.Section()
            item.va, item.vsize, item.flags = sec["va"], sec["vsize"], sec["flags"]
            item.name = sec["name"].encode("ascii")
            if sec["raw"] is not None:
                buf = ctypes.create_string_buffer(sec["raw"])
                self.keep.append(buf)
                item.raw = ctypes.cast(buf, ctypes.c_void_p)
                item.raw_len = len(sec["raw"])
            items.append(item)
        self.items = (p7.Section * len(items))(*items)
        self.nitems = len(items)

    def setup(self):
        ctypes.memset(self.mem, 0, len(self.mem))
        rc = self.lib.uc_p31_setup(
            ctypes.cast(self.mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
            self.items, self.nitems)
        if rc:
            raise RuntimeError("setup rc %d" % rc)

    def run(self, spec):
        """Fresh image per run so writes never leak between roots."""
        self.setup()
        out = Out()
        rc = self.lib.uc_p31_run(ctypes.byref(spec), ctypes.byref(out))
        if rc:
            raise RuntimeError("run rc %d" % rc)
        return out


def make_spec(root, ecx=0, edx=0, args=(), init=(), zero=(), teb=False, ret_pop=0,
              noop_target=0, noop_args=0):
    s = Spec()
    s.noop_target = noop_target
    s.noop_args = noop_args
    s.root = root
    s.ecx = ecx
    s.edx = edx
    s.nargs = len(args)
    for i, a in enumerate(args):
        s.args[i] = a & 0xFFFFFFFF
    s.ninit = len(init)
    for i, (a, v) in enumerate(init):
        s.init_addr[i] = a
        s.init_val[i] = v & 0xFFFFFFFF
    s.nzero = len(zero)
    for i, (a, n) in enumerate(zero):
        s.zero_addr[i] = a
        s.zero_len[i] = n
    s.teb = 1 if teb else 0
    s.ret_pop = ret_pop
    return s


def closure(root, fmap_by, limit=40, skip=()):
    """Bounded static closure over HIGH direct callees (function-map)."""
    seen, todo = [], [root]
    while todo and len(seen) < limit:
        va = todo.pop(0)
        if va in seen or va in PROTECTED_CALLS or va in skip:
            continue
        row = fmap_by.get(va)
        if not row or row.get("label") != "HIGH_CONFIDENCE":
            continue
        seen.append(va)
        for key in ("calls", "tails"):
            for t in row.get(key) or []:
                todo.append(int(t, 16))
    return seen


def import_name_for_target(target):
    """Resolve an unbound IAT name RVA VA to (dll-less) symbol, ordinary .rdata only."""
    try:
        import pefile
        pef = getattr(import_name_for_target, "_pef", None)
        if pef is None:
            pef = pefile.PE(GAME, fast_load=False)
            import_name_for_target._pef = pef
            import_name_for_target._mm = pef.get_memory_mapped_image()
        base = pef.OPTIONAL_HEADER.ImageBase
        mm = import_name_for_target._mm
        # The unbound IAT dword is an RVA to IMAGE_IMPORT_BY_NAME; accept a VA too.
        off = target
        if not (0x1000 <= off < 0xCAC000):
            return None
        raw = mm[off + 2:off + 100]
        return raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    except Exception:
        return None


def load_fmap():
    with open(os.path.join(ANALYSIS, "function-map.json"), encoding="utf-8") as fh:
        rows = json.load(fh)["functions"]
    return {int(r["va"], 16): r for r in rows}
