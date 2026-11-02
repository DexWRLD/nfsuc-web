"""Phase 8 native harness.

Executes the ordinary string-object cluster selected from the high-confidence
graph. The game executable is not started, and protected sections stay unmapped.
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
    0x009B0490, 0x009AE2A0, 0x009AE140, 0x009DDA50, 0x009DDA70,
    0x009AEBD0, 0x009AF0B0,
)
THUNKS = {0x00AE52C8: "strcmp", 0x00AE52D4: "memcmp", 0x00AE52EC: "strlen"}


def instrument(code, addr):
    match = re.search(r"void (sub_[0-9a-f]+)\(CPU \*restrict c\) \{", code)
    if not match:
        sys.exit("no definition in %08x" % addr)
    name = match.group(1)
    code = code.replace(
        "void %s(CPU *restrict c) {" % name,
        "void %s_impl(CPU *restrict c) {\n    uc_fn_enter(0x%08xu, c);" % (name, addr),
        1)
    code = code.replace(
        "POP32(c->eip); return;",
        "uc_fn_leave(0x%08xu, c); POP32(c->eip); return;" % addr)
    code = code.replace(
        "POP32(c->eip); c->esp += 4u; return;",
        "uc_fn_leave(0x%08xu, c); POP32(c->eip); c->esp += 4u; return;" % addr)
    code = code.replace(
        "POP32(c->eip); c->esp += 8u; return;",
        "uc_fn_leave(0x%08xu, c); POP32(c->eip); c->esp += 8u; return;" % addr)

    def repl(found):
        target = int(found.group(1), 16)
        if target in THUNKS:
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
    for thunk in THUNKS:
        found = re.search(
            r"PUSH32\((0x[0-9a-f]+)u\); sub_%08x\(c\);" % thunk, code)
        if not found:
            continue
        code = code.replace(
            found.group(0),
            "uc_esp_mark_at(0, c);\n    %s\n    uc_esp_mark_at(1, c);" % found.group(0),
            1)
        pos = code.find("uc_esp_mark_at(1, c);")
        assign = "c->esp = (uint32_t)(_r);"
        at = code.find(assign, pos)
        if at < 0:
            sys.exit("missing caller cleanup in %08x" % addr)
        code = code[:at + len(assign)] + "\n    uc_esp_mark_at(2, c);" + code[at + len(assign):]
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

uint8_t *g_mem;
int _fltused;
static int uc_hle_fail;
static int uc_direct_fail;
static uint32_t uc_strlen_calls, uc_memcmp_calls, uc_strcmp_calls;
static uint32_t uc_arg0, uc_arg1, uc_arg2;

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

static void uc_thunk(CPU *c, uint32_t thunk) {
    const UcImport *imp = uc_import_find(thunk);
    uc_esp_mark_at(3, c);
    uc_arg0 = MR32(c->esp + 4u);
    uc_arg1 = MR32(c->esp + 8u);
    uc_arg2 = MR32(c->esp + 12u);
    uc_trace(UC_EV_IMPORT_CALL, uc_current_fn, c->eip, thunk, c);
    if (!imp || !uc_import_invoke(c, imp, 0)) uc_hle_fail = 1;
    uc_esp_mark_at(4, c);
    uc_trace(UC_EV_IMPORT_RETURN, uc_current_fn, c->eip, thunk, c);
}
void sub_00ae52c8(CPU *c) { uc_strcmp_calls++; uc_thunk(c, 0x00ae52c8u); }
void sub_00ae52d4(CPU *c) { uc_memcmp_calls++; uc_thunk(c, 0x00ae52d4u); }
void sub_00ae52ec(CPU *c) { uc_strlen_calls++; uc_thunk(c, 0x00ae52ecu); }

''' + joined + r'''

void dispatch_indirect(CPU *c, uint32_t target) {
    (void)c; uc_direct_fail = 1; uc_trace(UC_EV_INDIRECT_CALL, uc_current_fn, c->eip, target, c);
}
void dispatch_tail(CPU *c) { (void)c; }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) { (void)c; (void)addr; (void)why; }

typedef struct UcPhase8Out {
    uint32_t code;
    uint32_t strlen_eax, strlen_esp, strlen_before, strlen_inside, strlen_after, strlen_cleanup;
    uint32_t match_eax, nomatch_eax;
    uint32_t memcmp_al, memcmp_diff_al, memcmp_len_al, memcmp_calls;
    uint32_t memcmp_before, memcmp_inside, memcmp_after, memcmp_cleanup;
    uint32_t strcmp_al, strcmp_same_al, strcmp_pos_al, strcmp_calls;
    uint32_t strcmp_before, strcmp_inside, strcmp_after, strcmp_cleanup;
    uint32_t esi_ok, ebp_ok;
    uint32_t trace_count, trace_kind[24], trace_fn[24], trace_target[24];
    uint32_t fault_kind, fault_addr;
    char fault_section[16];
} UcPhase8Out;

static int fail_line;
#define EXPECT(cond) do { if (!(cond)) { fail_line = __LINE__; return; } } while (0)

static void wr32(uint32_t addr, uint32_t value) {
    g_mem[addr] = (uint8_t)value;
    g_mem[addr + 1] = (uint8_t)(value >> 8);
    g_mem[addr + 2] = (uint8_t)(value >> 16);
    g_mem[addr + 3] = (uint8_t)(value >> 24);
}
static uint32_t rd32(uint32_t addr) {
    return (uint32_t)g_mem[addr] | ((uint32_t)g_mem[addr + 1] << 8)
        | ((uint32_t)g_mem[addr + 2] << 16) | ((uint32_t)g_mem[addr + 3] << 24);
}
static void prepare(CPU *c, uint32_t esp) {
    unsigned i;
    uint8_t *p = (uint8_t *)c;
    for (i = 0; i < sizeof(*c); i++) p[i] = 0;
    c->esp = esp;
    c->ebx = 0xb0b0b0b0u;
    c->ebp = 0xebebebebu;
    c->esi = 0x51515151u;
    c->edi = 0xd1d1d1d1u;
    wr32(esp, 0x00dec0deu);
}
static void plant(uint32_t obj, uint32_t inner, uint16_t n, const uint8_t *bytes, unsigned len) {
    unsigned i;
    wr32(obj, inner);
    for (i = 0; i < 32; i++) g_mem[inner + i] = 0;
    g_mem[inner + 2] = (uint8_t)n;
    g_mem[inner + 3] = (uint8_t)(n >> 8);
    for (i = 0; i < len; i++) g_mem[inner + 8 + i] = bytes[i];
}
static void putstr(uint32_t addr, const char *s) {
    unsigned i = 0;
    while (s[i]) { g_mem[addr + i] = (uint8_t)s[i]; i++; }
    g_mem[addr + i] = 0;
}

static void run_cases(UcPhase8Out *out) {
    CPU c;
    uint32_t esp = 0x0300f000u;
    uint32_t calls;
    int ok;
    const uint8_t xy[] = { 'a', 'b', 'c', 'X', 'Y' };
    const uint8_t abcd[] = { 'a', 'b', 'c', 'd' };
    const uint8_t abc[] = { 'a', 'b', 'c', 0 };
    const uint8_t abd[] = { 'a', 'b', 'd', 0 };
    const uint8_t abx[] = { 'a', 'b', 'X', 0 };
    uc_exec_trace = 1;
    uc_import_trace = 1;
    EXPECT(uc_image_add_private("harness-stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE) == 0);
    putstr(0x03001000u, "");
    putstr(0x03001010u, "XY");
    putstr(0x03001020u, "zz");

    plant(0x03002000u, 0x03002100u, 4, abcd, 4);
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03001000u);
    wr32(esp + 8, 100);
    sub_009b0490_impl(&c);
    out->strlen_eax = c.eax;
    out->strlen_esp = c.esp;
    out->strlen_before = uc_esp_mark[0];
    out->strlen_inside = uc_esp_mark[3];
    out->strlen_after = uc_esp_mark[4];
    out->strlen_cleanup = uc_esp_mark[2];
    EXPECT(uc_hle_fail == 0 && uc_direct_fail == 0 && uc_access_fault.active == 0);
    EXPECT(c.eax == 4);
    EXPECT(c.esp == esp + 12);
    EXPECT(c.eip == 0x00dec0deu);
    EXPECT(uc_esp_mark[3] + 4 == uc_esp_mark[0]);
    EXPECT(uc_esp_mark[4] == uc_esp_mark[0]);
    EXPECT(uc_esp_mark[1] == uc_esp_mark[0]);
    EXPECT(uc_esp_mark[2] == uc_esp_mark[0] + 4);
    EXPECT(uc_arg0 == 0x03001000u);
    EXPECT(c.esi == 0x51515151u && c.ebx == 0xb0b0b0b0u && c.edi == 0xd1d1d1d1u && c.ebp == 0xebebebebu);
    EXPECT(uc_strlen_calls == 1);
    EXPECT(uc_import_trace_last.abi == UC_ABI_CDECL && uc_import_trace_last.stack_dwords == 1);

    plant(0x03002000u, 0x03002100u, 5, xy, 5);
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03001010u);
    wr32(esp + 8, 100);
    sub_009b0490_impl(&c);
    out->match_eax = c.eax;
    EXPECT(c.eax == 3 && c.esp == esp + 12 && uc_access_fault.active == 0);

    plant(0x03002000u, 0x03002100u, 4, abcd, 4);
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03001020u);
    wr32(esp + 8, 100);
    sub_009b0490_impl(&c);
    out->nomatch_eax = c.eax;
    EXPECT(c.eax == 0xffffffffu && c.esp == esp + 12);

    calls = uc_memcmp_calls;
    plant(0x03002000u, 0x03002100u, 3, abc, 4);
    plant(0x03002200u, 0x03002300u, 3, abc, 4);
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03002200u);
    sub_009aebd0_impl(&c);
    out->memcmp_al = c.eax & 0xffu;
    out->memcmp_calls = uc_memcmp_calls;
    out->memcmp_before = uc_esp_mark[0];
    out->memcmp_inside = uc_esp_mark[3];
    out->memcmp_after = uc_esp_mark[4];
    out->memcmp_cleanup = uc_esp_mark[2];
    EXPECT((c.eax & 0xffu) == 1);
    EXPECT(uc_memcmp_calls == calls + 1);
    EXPECT(c.esp == esp + 8 && c.eip == 0x00dec0deu);
    EXPECT(uc_esp_mark[3] + 4 == uc_esp_mark[0]);
    EXPECT(uc_esp_mark[4] == uc_esp_mark[0]);
    EXPECT(uc_esp_mark[2] == uc_esp_mark[0] + 12);
    EXPECT(uc_arg0 == 0x03002108u);
    EXPECT(uc_arg1 == 0x03002308u);
    EXPECT(uc_arg2 == 3);
    EXPECT(c.esi == 0x51515151u && c.ebp == 0xebebebebu);
    EXPECT(uc_import_trace_last.stack_dwords == 3 && uc_import_trace_last.abi == UC_ABI_CDECL);

    plant(0x03002200u, 0x03002300u, 3, abx, 4);
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03002200u);
    sub_009aebd0_impl(&c);
    out->memcmp_diff_al = c.eax & 0xffu;
    EXPECT((c.eax & 0xffu) == 0 && c.esp == esp + 8);

    calls = uc_memcmp_calls;
    plant(0x03002200u, 0x03002300u, 4, abcd, 4);
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03002200u);
    sub_009aebd0_impl(&c);
    out->memcmp_len_al = c.eax & 0xffu;
    EXPECT((c.eax & 0xffu) == 0);
    EXPECT(uc_memcmp_calls == calls);

    calls = uc_strcmp_calls;
    plant(0x03002000u, 0x03002100u, 3, abc, 4);
    plant(0x03002200u, 0x03002300u, 3, abd, 4);
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03002200u);
    sub_009af0b0_impl(&c);
    out->strcmp_al = c.eax & 0xffu;
    out->strcmp_calls = uc_strcmp_calls;
    out->strcmp_before = uc_esp_mark[0];
    out->strcmp_inside = uc_esp_mark[3];
    out->strcmp_after = uc_esp_mark[4];
    out->strcmp_cleanup = uc_esp_mark[2];
    EXPECT((c.eax & 0xffu) == 1);
    EXPECT(uc_strcmp_calls == calls + 1);
    EXPECT(c.esp == esp + 8);
    EXPECT(uc_esp_mark[3] + 4 == uc_esp_mark[0]);
    EXPECT(uc_esp_mark[4] == uc_esp_mark[0]);
    EXPECT(uc_esp_mark[2] == uc_esp_mark[0] + 8);
    EXPECT(uc_arg0 == 0x03002108u);
    EXPECT(uc_arg1 == 0x03002308u);
    EXPECT(uc_import_trace_last.stack_dwords == 2);
    EXPECT(c.esi == 0x51515151u && c.ebp == 0xebebebebu && c.ebx == 0xb0b0b0b0u);
    out->esi_ok = c.esi;
    out->ebp_ok = c.ebp;

    calls = uc_strcmp_calls;
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03002000u);
    sub_009af0b0_impl(&c);
    out->strcmp_same_al = c.eax & 0xffu;
    EXPECT((c.eax & 0xffu) == 0);
    EXPECT(uc_strcmp_calls == calls);

    plant(0x03002000u, 0x03002100u, 3, abd, 4);
    plant(0x03002200u, 0x03002300u, 3, abc, 4);
    prepare(&c, esp);
    c.ecx = 0x03002000u;
    wr32(esp + 4, 0x03002200u);
    sub_009af0b0_impl(&c);
    out->strcmp_pos_al = c.eax & 0xffu;
    EXPECT((c.eax & 0xffu) == 0 && c.esp == esp + 8);
    EXPECT(uc_access_fault.active == 0);

    out->trace_count = (uint32_t)uc_trace_count;
    {
        uint32_t i, n = uc_trace_count;
        if (n > 24) n = 24;
        for (i = 0; i < n; i++) {
            out->trace_kind[i] = (uint32_t)uc_trace_log[i].kind;
            out->trace_fn[i] = uc_trace_log[i].fn;
            out->trace_target[i] = uc_trace_log[i].target;
        }
    }
    uc_current_fn = 0x009b0490u;
    uc_fault_eip = 0x009b0490u;
    uc_access_clear();
    ok = 1;
    EXPECT(uc_guest_load32(0x01fc7000u, &ok) == 0 && ok == 0);
    EXPECT(uc_access_fault.kind == UC_ACCESS_READ);
    out->fault_kind = (uint32_t)uc_access_fault.kind;
    out->fault_addr = uc_access_fault.address;
    {
        unsigned i;
        for (i = 0; i < 15 && uc_access_fault.section[i]; i++)
            out->fault_section[i] = uc_access_fault.section[i];
    }
}

__declspec(dllexport) int uc_phase8_run(
    uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int nsections,
    UcPhase8Out *out) {
    int i;
    fail_line = 0;
    out->code = 0;
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) {
        if (uc_image_map(&sections[i])) return 2;
    }
    run_cases(out);
    out->code = (uint32_t)fail_line;
    return fail_line;
}
'''


class Out(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32),
        ("strlen_eax", ctypes.c_uint32), ("strlen_esp", ctypes.c_uint32),
        ("strlen_before", ctypes.c_uint32), ("strlen_inside", ctypes.c_uint32),
        ("strlen_after", ctypes.c_uint32), ("strlen_cleanup", ctypes.c_uint32),
        ("match_eax", ctypes.c_uint32), ("nomatch_eax", ctypes.c_uint32),
        ("memcmp_al", ctypes.c_uint32), ("memcmp_diff_al", ctypes.c_uint32),
        ("memcmp_len_al", ctypes.c_uint32), ("memcmp_calls", ctypes.c_uint32),
        ("memcmp_before", ctypes.c_uint32), ("memcmp_inside", ctypes.c_uint32),
        ("memcmp_after", ctypes.c_uint32), ("memcmp_cleanup", ctypes.c_uint32),
        ("strcmp_al", ctypes.c_uint32), ("strcmp_same_al", ctypes.c_uint32),
        ("strcmp_pos_al", ctypes.c_uint32), ("strcmp_calls", ctypes.c_uint32),
        ("strcmp_before", ctypes.c_uint32), ("strcmp_inside", ctypes.c_uint32),
        ("strcmp_after", ctypes.c_uint32), ("strcmp_cleanup", ctypes.c_uint32),
        ("esi_ok", ctypes.c_uint32), ("ebp_ok", ctypes.c_uint32),
        ("trace_count", ctypes.c_uint32),
        ("trace_kind", ctypes.c_uint32 * 24),
        ("trace_fn", ctypes.c_uint32 * 24),
        ("trace_target", ctypes.c_uint32 * 24),
        ("fault_kind", ctypes.c_uint32), ("fault_addr", ctypes.c_uint32),
        ("fault_section", ctypes.c_char * 16),
    ]


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
    work = tempfile.mkdtemp(prefix="uc-phase8-")
    c_path = os.path.join(work, "phase8.c")
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
    dll = os.path.join(work, "uc_phase8.dll")
    p7.link(objs, dll)
    lib = ctypes.CDLL(dll)
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
    lib.uc_phase8_run.restype = ctypes.c_int
    rc = lib.uc_phase8_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        arr, len(items), ctypes.byref(out))
    names = (
        "code", "strlen_eax", "strlen_esp", "strlen_before", "strlen_inside",
        "strlen_after", "strlen_cleanup", "match_eax", "nomatch_eax",
        "memcmp_al", "memcmp_diff_al", "memcmp_len_al", "memcmp_calls",
        "memcmp_before", "memcmp_inside", "memcmp_after", "memcmp_cleanup",
        "strcmp_al", "strcmp_same_al", "strcmp_pos_al", "strcmp_calls",
        "strcmp_before", "strcmp_inside", "strcmp_after", "strcmp_cleanup",
        "esi_ok", "ebp_ok", "trace_count", "fault_kind", "fault_addr")
    decimal = {"code", "memcmp_al", "memcmp_diff_al", "memcmp_len_al", "memcmp_calls",
               "strcmp_al", "strcmp_same_al", "strcmp_pos_al", "strcmp_calls",
               "trace_count", "fault_kind"}
    for name in names:
        value = getattr(out, name)
        print(name, value if name in decimal else hex(value))
    print("fault_section", bytes(out.fault_section).split(b"\0", 1)[0])
    for i in range(min(24, out.trace_count)):
        print(" trace", i, out.trace_kind[i], hex(out.trace_fn[i]), hex(out.trace_target[i]))
    if rc != 0:
        lines = src.splitlines()
        text = lines[rc - 1] if 0 < rc <= len(lines) else ""
        print("failed line", rc, text)
        print("work", work)
        sys.exit(1)
    print("uc phase8 tests passed")


if __name__ == "__main__":
    main()
