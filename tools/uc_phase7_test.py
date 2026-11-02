"""Phase 7 native harness.

Loads ordinary PE sections into a guest image, then runs recompiled
Undercover functions. Protected sections are named and left unmapped.
The game executable is not started.
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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLANG_CANDIDATES = (
    os.environ.get("CLANG", ""),
    r"C:\Program Files\Unity\Hub\Editor\6000.6.7f1\Editor\Data\PlaybackEngines\WebGLSupport\BuildTools\Emscripten\llvm\clang.exe",
    "clang",
)
ALLOWED = (".text", ".rdata", ".data", ".tls", ".rsrc")
PROTECTED = ("Stext", "Sitext", "Srdata", "Sdata", "Sidata", ".securom")
MEM_READ, MEM_WRITE, MEM_EXEC = 1, 2, 4
SECTION_PROTECTED = 0x80000000
MEM_SIZE = 0x03100000
STACK_VA = 0x03000000
STACK_SIZE = 0x10000
SCN_EXEC, SCN_READ, SCN_WRITE = 0x20000000, 0x40000000, 0x80000000
IMPORT_FN = 0x00739B90
DATA_FN = 0x009D9150
PAIR_A, PAIR_B = 0x009B3910, 0x009CF900
CHAIN = (0x00AEC8E0, 0x00983AB0, 0x009EE750)
RDATA_FN = 0x00816E50
MEMSET_THUNK = 0x0087B2D6
RDATA_FLOAT = 0x00B69278


def clang():
    for path in CLANG_CANDIDATES:
        if path and (os.path.isfile(path) or path == "clang"):
            return path
    sys.exit("clang was not found")


def link(objs, dll):
    lld = os.path.join(os.path.dirname(clang()), "lld.exe")
    if not os.path.isfile(lld):
        lld = "lld"
    cmd = [lld, "-flavor", "link", "-dll", "-noentry", "-out:" + dll] + objs
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.exit(proc.returncode or 1)


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def read_sections(path):
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        file_size = fh.tell()
        fh.seek(0)
        head = fh.read(0x400)
        if head[:2] != b"MZ":
            sys.exit("not a PE image")
        e = u32(head, 0x3C)
        fh.seek(0)
        head = fh.read(e + 0x400)
        if head[e:e + 4] != b"PE\0\0":
            sys.exit("not a PE image")
        nsec = u16(head, e + 6)
        optsz = u16(head, e + 20)
        opt = e + 24
        image_base = u32(head, opt + 28)
        size_image = u32(head, opt + 56)
        need = opt + optsz + nsec * 40
        if len(head) < need:
            fh.seek(0)
            head = fh.read(need)
        sections = []
        off = opt + optsz
        for i in range(nsec):
            raw = head[off + i * 40:off + (i + 1) * 40]
            name = raw[:8].split(b"\0", 1)[0].decode("latin1")
            vsz, va, rsz, rawptr, chars = (
                u32(raw, 8), u32(raw, 12), u32(raw, 16), u32(raw, 20), u32(raw, 36))
            item = {
                "name": name,
                "va": image_base + va,
                "vsize": vsz,
                "raw_size": rsz,
                "raw_ptr": rawptr,
                "chars": chars,
                "raw": None,
            }
            if name in PROTECTED:
                item["flags"] = SECTION_PROTECTED
            elif name in ALLOWED:
                flags = 0
                if chars & SCN_READ:
                    flags |= MEM_READ
                if chars & SCN_WRITE:
                    flags |= MEM_WRITE
                if chars & SCN_EXEC:
                    flags |= MEM_EXEC
                take = min(vsz, rsz)
                if rawptr + take > file_size:
                    sys.exit("section extends past the file: " + name)
                fh.seek(rawptr)
                blob = fh.read(take)
                if len(blob) != take:
                    sys.exit("short read of " + name)
                item["raw"] = blob
                item["flags"] = flags
            else:
                item["flags"] = 0
            sections.append(item)
    return {"image_base": image_base, "size_image": size_image, "sections": sections}


def instrument(code, addr, watch):
    match = re.search(r"void (sub_[0-9a-f]+)\(CPU \*restrict c\) \{", code)
    if not match:
        sys.exit("lifted function has no definition: %08x" % addr)
    name = match.group(1)
    code = code.replace(
        "void %s(CPU *restrict c) {" % name,
        "void %s_impl(CPU *restrict c) {\n    uc_fn_enter(0x%08xu, c);" % (name, addr),
        1)
    code = code.replace(
        "POP32(c->eip); return;",
        "uc_fn_leave(0x%08xu, c); POP32(c->eip); return;" % addr)
    def repl(found):
        target = int(found.group(1), 16)
        if target == MEMSET_THUNK:
            return found.group(0)
        return "uc_direct(0x%08xu, c)" % target
    code = re.sub(r"sub_([0-9a-f]+)\(c\)", repl, code)
    code = re.sub(
        r"MR32\(([^;]*?)\) = \(([^;]*?)\);",
        r"uc_guest_store32(\1, (uint32_t)(\2), 0);",
        code)
    ret_const = 0
    if watch:
        found = re.search(r"PUSH32\((0x[0-9a-f]+)u\); sub_%08x\(c\);" % MEMSET_THUNK, code)
        if not found:
            sys.exit("import call was not left intact in %08x" % addr)
        ret_const = int(found.group(1), 16)
        code = code.replace(
            found.group(0),
            "uc_esp_mark_at(0, c);\n    %s\n    uc_esp_mark_at(1, c);" % found.group(0),
            1)
        pos = code.find("uc_esp_mark_at(1, c);")
        assign = "c->esp = (uint32_t)(_r);"
        at = code.find(assign, pos)
        if at < 0:
            sys.exit("caller cleanup was not found in %08x" % addr)
        code = code[:at + len(assign)] + "\n    uc_esp_mark_at(2, c);" + code[at + len(assign):]
    if "dispatch_indirect" in code:
        sys.exit("selected function contains an indirect dispatch: %08x" % addr)
    return code, name, ret_const


def build_source(bodies, import_ret, data_ret):
    switch = []
    decls = []
    for addr, name, _code in bodies:
        decls.append("void %s_impl(CPU *restrict c);" % name)
        switch.append("    case 0x%08xu: %s_impl(c); break;" % (addr, name))
    joined = "\n".join(code for _addr, _name, code in bodies)
    return r'''
#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"

uint8_t *g_mem;
static int uc_hle_fail;
static int uc_direct_fail;
static uint32_t uc_indirect_target;
static int uc_indirect_seen;

''' + "\n".join(decls) + "\nvoid sub_0087b2d6(CPU *c);\n" + r'''

static void uc_direct(uint32_t target, CPU *c) {
    uint32_t caller = uc_current_fn;
    uc_trace(UC_EV_DIRECT_CALL, caller, c->eip, target, c);
    if (!uc_guest_execute(target)) {
        uc_direct_fail = 1;
        return;
    }
    switch (target) {
''' + "\n".join(switch) + r'''
    default:
        uc_direct_fail = 1;
        uc_trace(UC_EV_INDIRECT_CALL, caller, c->eip, target, c);
        return;
    }
    uc_current_fn = caller;
}

''' + joined + r'''

void sub_0087b2d6(CPU *c) {
    const UcImport *imp = uc_import_find(0x0087b2d6u);
    uc_esp_mark_at(3, c);
    uc_trace(UC_EV_IMPORT_CALL, uc_current_fn, c->eip, 0x0087b2d6u, c);
    if (!uc_import_invoke(c, imp, 0)) uc_hle_fail = 1;
    uc_esp_mark_at(4, c);
    uc_trace(UC_EV_IMPORT_RETURN, uc_current_fn, c->eip, 0x0087b2d6u, c);
}

void dispatch_indirect(CPU *c, uint32_t target) {
    (void)c;
    uc_indirect_seen = 1;
    uc_indirect_target = target;
    uc_trace(UC_EV_INDIRECT_CALL, uc_current_fn, c->eip, target, c);
}
void dispatch_tail(CPU *c) { (void)c; }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    (void)c; (void)addr; (void)why;
}
int _fltused;
void *memcpy(void *dst, const void *src, size_t n) {
    size_t i;
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

typedef struct UcPhase7Config {
    uint32_t text_va, text_dword;
    uint32_t rdata_va, rdata_dword;
    uint32_t data_tail;
    uint32_t sitext_va;
    uint32_t gap_va;
    uint32_t image_end;
    uint32_t rdata_float;
    uint32_t import_ret;
    uint32_t data_ret;
} UcPhase7Config;

typedef struct UcPhase7Out {
    uint32_t code;
    uint32_t section_bytes;
    uint32_t out_bytes;
    uint32_t esp_entry, esp_before_call, esp_inside, esp_after_import, esp_after_cleanup, esp_final;
    uint32_t eax_final, eip_final;
    uint32_t data_before, data_inside, data_after_import, data_after_cleanup, data_final, data_eax;
    uint32_t pair_final, pair_eax, pair_ebp;
    uint32_t chain_eax, chain_counter, chain_esi;
    uint32_t import_abi, import_stack;
    uint32_t span_count, trace_count;
    uint32_t span_lo[16], span_hi[16], span_write[16];
    char span_name[16][16];
    uint32_t trace_kind[32], trace_fn[32], trace_target[32];
    uint32_t fault_kind, fault_addr, fault_eip, fault_fn;
    char fault_section[16];
} UcPhase7Out;

static int fail_line;

#define EXPECT(cond) do { if (!(cond)) { fail_line = __LINE__; return; } } while (0)

static int same(const char *a, const char *b) {
    unsigned i = 0;
    while (a[i] && a[i] == b[i]) i++;
    return a[i] == b[i];
}

static uint32_t rd32(uint32_t addr) {
    uint8_t *p = g_mem + addr;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(uint32_t addr, uint32_t value) {
    g_mem[addr] = (uint8_t)value;
    g_mem[addr + 1] = (uint8_t)(value >> 8);
    g_mem[addr + 2] = (uint8_t)(value >> 16);
    g_mem[addr + 3] = (uint8_t)(value >> 24);
}

static int span_has(uint32_t addr, int write, const char *section) {
    int i;
    for (i = 0; i < uc_span_count; i++) {
        if (uc_spans[i].write != write) continue;
        if (!same(uc_spans[i].section, section)) continue;
        if (addr >= uc_spans[i].lo && addr < uc_spans[i].hi) return 1;
    }
    return 0;
}

static void prepare(CPU *c, uint32_t esp, uint32_t ret) {
    unsigned i;
    uint32_t *p = (uint32_t *)c;
    for (i = 0; i < sizeof(*c) / sizeof(uint32_t); i++) p[i] = 0;
    c->esp = esp;
    c->ecx = 0xc0c0c0c0u;
    c->edx = 0xd0d0d0d0u;
    c->ebx = 0xb0b0b0b0u;
    c->ebp = 0xebebebebu;
    c->esi = 0x51515151u;
    c->edi = 0xd1d1d1d1u;
    wr32(esp, ret);
}

static void run_cases(const UcPhase7Config *cfg, UcPhase7Out *out) {
    CPU c;
    uint32_t esp, i, saved;
    int ok;
    const UcImport *imp;
    uint32_t dest = 0x03002000u;
    uint32_t obj = 0x03004000u;
    uint32_t cell = 0x03005000u;
    uint32_t flt = 0x03006000u;
    uc_exec_trace = 1;
    uc_import_trace = 1;
    EXPECT(uc_image_add_private("harness-stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE) == 0);
    EXPECT(uc_guest_execute(0x00739b90u) == 1);
    imp = uc_import_find(0x0087b2d6u);
    EXPECT(imp && imp->abi == UC_ABI_CDECL && imp->hle == UC_HLE_MEMSET);
    EXPECT(imp->stack_dwords == 3);
    out->import_abi = (uint32_t)imp->abi;
    out->import_stack = (uint32_t)imp->stack_dwords;

    for (i = 0; i < 0x181; i++) g_mem[dest + i] = 0xa5;
    esp = 0x0300f000u;
    prepare(&c, esp, 0x00dec0deu);
    c.eax = 0x11111111u;
    wr32(esp + 4, dest);
    out->esp_entry = esp;
    sub_00739b90_impl(&c);
    out->esp_before_call = uc_esp_mark[0];
    out->esp_inside = uc_esp_mark[3];
    out->esp_after_import = uc_esp_mark[4];
    out->esp_after_cleanup = uc_esp_mark[2];
    out->esp_final = c.esp;
    out->eax_final = c.eax;
    out->eip_final = c.eip;
    EXPECT(uc_hle_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(uc_esp_mark[0] == esp - 12);
    EXPECT(uc_esp_mark[3] == esp - 16);
    EXPECT(uc_esp_mark[4] == esp - 12);
    EXPECT(uc_esp_mark[1] == esp - 12);
    EXPECT(uc_esp_mark[2] == esp);
    EXPECT(c.esp == esp + 4);
    EXPECT(c.eip == 0x00dec0deu);
    EXPECT(c.eax == dest);
    EXPECT(rd32(uc_esp_mark[3]) == cfg->import_ret);
    EXPECT(rd32(uc_esp_mark[0]) == dest);
    EXPECT(c.ecx == 0xc0c0c0c0u && c.edx == 0xd0d0d0d0u && c.ebx == 0xb0b0b0b0u);
    EXPECT(c.esi == 0x51515151u && c.edi == 0xd1d1d1d1u && c.ebp == 0xebebebebu);
    for (i = 0; i < 0x180; i++) EXPECT(g_mem[dest + i] == 0);
    EXPECT(g_mem[dest + 0x180] == 0xa5);
    EXPECT(uc_import_trace_last.ok == 1);
    EXPECT(uc_import_trace_last.esp_before == uc_esp_mark[3]);
    EXPECT(uc_import_trace_last.esp_after == uc_esp_mark[4]);
    EXPECT(same(uc_import_trace_last.symbol, "memset"));

    prepare(&c, esp, 0x00dec0deu);
    c.eax = 0xa5a5a5a5u;
    sub_009b3910_impl(&c);
    out->pair_final = c.esp;
    out->pair_eax = c.eax;
    out->pair_ebp = c.ebp;
    EXPECT(uc_direct_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(c.esp == esp + 4);
    EXPECT(c.eip == 0x00dec0deu);
    EXPECT(c.eax == 0xa5a5a5a5u);
    EXPECT(c.ebp == 0xebebebebu);
    EXPECT(c.ecx == 0xc0c0c0c0u && c.esi == 0x51515151u && c.edi == 0xd1d1d1d1u && c.ebx == 0xb0b0b0b0u);

    for (i = 0; i < 0x100; i++) g_mem[obj + i] = 0;
    wr32(obj + 0xd4, 1);
    wr32(obj + 0x30, cell);
    wr32(cell, 5);
    prepare(&c, esp, 0x00dec0deu);
    c.ecx = obj;
    sub_00aec8e0_impl(&c);
    out->chain_eax = c.eax;
    out->chain_counter = rd32(cell);
    out->chain_esi = c.esi;
    EXPECT(uc_direct_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(c.esp == esp + 4);
    EXPECT(c.eip == 0x00dec0deu);
    EXPECT(c.eax == 4);
    EXPECT(rd32(cell) == 4);
    EXPECT(c.esi == 0x51515151u && c.ebx == 0xb0b0b0b0u && c.edi == 0xd1d1d1d1u && c.ebp == 0xebebebebu);

    g_mem[0x0189cdf3u] = 0xa5;
    for (i = 0; i < 0x28; i++) g_mem[0x0189cdf4u + i] = 0xa5;
    g_mem[0x0189ce20u] = 0xa5;
    wr32(0x0189ce1cu, 0xffffffffu);
    wr32(0x0129729cu, 0xffffffffu);
    prepare(&c, esp, 0x00dec0deu);
    sub_009d9150_impl(&c);
    out->data_before = uc_esp_mark[0];
    out->data_inside = uc_esp_mark[3];
    out->data_after_import = uc_esp_mark[4];
    out->data_after_cleanup = uc_esp_mark[2];
    out->data_final = c.esp;
    out->data_eax = c.eax;
    EXPECT(uc_hle_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(uc_esp_mark[0] == esp - 16);
    EXPECT(uc_esp_mark[3] == esp - 20);
    EXPECT(uc_esp_mark[4] == esp - 16);
    EXPECT(uc_esp_mark[2] == esp - 4);
    EXPECT(c.esp == esp + 4);
    EXPECT(c.eip == 0x00dec0deu);
    EXPECT(c.eax == 0x0189cdf4u);
    EXPECT(c.ebp == 0xebebebebu);
    EXPECT(rd32(uc_esp_mark[3]) == cfg->data_ret);
    for (i = 0; i < 0x28; i++) EXPECT(g_mem[0x0189cdf4u + i] == 0);
    EXPECT(g_mem[0x0189cdf3u] == 0xa5);
    EXPECT(g_mem[0x0189ce20u] == 0xa5);
    EXPECT(rd32(0x0189ce1cu) == 0);
    EXPECT(rd32(0x0129729cu) == 4);
    EXPECT(span_has(0x0189cdf4u, 1, ".data"));
    EXPECT(span_has(0x0189ce1cu, 1, ".data"));
    EXPECT(span_has(0x0129729cu, 1, ".data"));

    prepare(&c, esp, 0x00dec0deu);
    c.ecx = flt;
    wr32(flt + 0x130, 0x40000000u);
    sub_00816e50_impl(&c);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(c.esp == esp + 4);
    EXPECT(span_has(cfg->rdata_float, 0, ".rdata"));
    {
        float a = *(float *)(g_mem + flt + 0x130);
        float b = *(float *)(g_mem + cfg->rdata_float);
        double expect = (double)a * (double)b;
        EXPECT(c.st[c.top & 7] == expect);
    }

    EXPECT(rd32(cfg->text_va) == cfg->text_dword);
    EXPECT(rd32(cfg->rdata_va) == cfg->rdata_dword);
    ok = 1;
    EXPECT(uc_guest_load32(cfg->data_tail, &ok) == 0 && ok == 1);

    out->span_count = (uint32_t)uc_span_count;
    for (i = 0; i < 16 && i < (uint32_t)uc_span_count; i++) {
        unsigned k;
        out->span_lo[i] = uc_spans[i].lo;
        out->span_hi[i] = uc_spans[i].hi;
        out->span_write[i] = (uint32_t)uc_spans[i].write;
        for (k = 0; k < 15; k++) out->span_name[i][k] = uc_spans[i].section[k];
    }
    out->trace_count = (uint32_t)uc_trace_count;
    for (i = 0; i < 32 && i < (uint32_t)uc_trace_count; i++) {
        out->trace_kind[i] = (uint32_t)uc_trace_log[i].kind;
        out->trace_fn[i] = uc_trace_log[i].fn;
        out->trace_target[i] = uc_trace_log[i].target;
    }

    uc_current_fn = 0x00739b90u;
    uc_fault_eip = 0x00739b90u;
    uc_access_clear();
    ok = 1;
    EXPECT(uc_guest_load32(cfg->gap_va, &ok) == 0 && ok == 0);
    EXPECT(uc_access_fault.kind == UC_ACCESS_READ);
    EXPECT(same(uc_access_fault.section, "unmapped"));
    EXPECT(uc_access_fault.function_va == 0x00739b90u);

    uc_access_clear();
    ok = 1;
    EXPECT(uc_guest_load32(cfg->sitext_va, &ok) == 0 && ok == 0);
    EXPECT(same(uc_access_fault.section, "Sitext"));
    EXPECT(uc_access_fault.kind == UC_ACCESS_READ);
    out->fault_kind = (uint32_t)uc_access_fault.kind;
    out->fault_addr = uc_access_fault.address;
    out->fault_eip = uc_access_fault.eip;
    out->fault_fn = uc_access_fault.function_va;
    for (i = 0; i < 15; i++) out->fault_section[i] = uc_access_fault.section[i];

    saved = rd32(cfg->rdata_va);
    uc_access_clear();
    ok = 1;
    uc_guest_store32(cfg->rdata_va, 0x11223344u, &ok);
    EXPECT(ok == 0);
    EXPECT(uc_access_fault.kind == UC_ACCESS_WRITE);
    EXPECT(same(uc_access_fault.section, ".rdata"));
    EXPECT(rd32(cfg->rdata_va) == saved);

    uc_access_clear();
    EXPECT(uc_guest_execute(cfg->sitext_va) == 0);
    EXPECT(uc_access_fault.kind == UC_ACCESS_EXECUTE);
    EXPECT(same(uc_access_fault.section, "Sitext"));

    uc_access_clear();
    ok = 1;
    EXPECT(uc_guest_load32(cfg->image_end, &ok) == 0 && ok == 0);
    EXPECT(rd32(cfg->rdata_va) == cfg->rdata_dword);

    uc_indirect_seen = 0;
    c.eip = 0x00aec8e0u;
    c.esp = esp;
    dispatch_indirect(&c, 0x0087a7aeu);
    EXPECT(uc_indirect_seen == 1);
    EXPECT(uc_indirect_target == 0x0087a7aeu);
    EXPECT(c.eip == 0x00aec8e0u);
    EXPECT(c.esp == esp);
}

__declspec(dllexport) void uc_phase7_sizes(uint32_t *section_size, uint32_t *out_size) {
    *section_size = (uint32_t)sizeof(UcSectionIn);
    *out_size = (uint32_t)sizeof(UcPhase7Out);
}

__declspec(dllexport) int uc_phase7_run(
    uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int nsections,
    const UcPhase7Config *cfg, UcPhase7Out *out) {
    int i;
    fail_line = 0;
    out->code = 0;
    out->section_bytes = (uint32_t)sizeof(UcSectionIn);
    out->out_bytes = (uint32_t)sizeof(UcPhase7Out);
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) {
        if (uc_image_map(&sections[i])) return 2;
    }
    run_cases(cfg, out);
    out->code = (uint32_t)fail_line;
    return fail_line;
}
'''


class Section(ctypes.Structure):
    _fields_ = [
        ("va", ctypes.c_uint32),
        ("vsize", ctypes.c_uint32),
        ("raw_len", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("raw", ctypes.c_void_p),
        ("name", ctypes.c_char * 16),
    ]


class Config(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in (
        "text_va", "text_dword", "rdata_va", "rdata_dword", "data_tail",
        "sitext_va", "gap_va", "image_end", "rdata_float", "import_ret", "data_ret")]


class Out(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32),
        ("section_bytes", ctypes.c_uint32),
        ("out_bytes", ctypes.c_uint32),
        ("esp_entry", ctypes.c_uint32),
        ("esp_before_call", ctypes.c_uint32),
        ("esp_inside", ctypes.c_uint32),
        ("esp_after_import", ctypes.c_uint32),
        ("esp_after_cleanup", ctypes.c_uint32),
        ("esp_final", ctypes.c_uint32),
        ("eax_final", ctypes.c_uint32),
        ("eip_final", ctypes.c_uint32),
        ("data_before", ctypes.c_uint32),
        ("data_inside", ctypes.c_uint32),
        ("data_after_import", ctypes.c_uint32),
        ("data_after_cleanup", ctypes.c_uint32),
        ("data_final", ctypes.c_uint32),
        ("data_eax", ctypes.c_uint32),
        ("pair_final", ctypes.c_uint32),
        ("pair_eax", ctypes.c_uint32),
        ("pair_ebp", ctypes.c_uint32),
        ("chain_eax", ctypes.c_uint32),
        ("chain_counter", ctypes.c_uint32),
        ("chain_esi", ctypes.c_uint32),
        ("import_abi", ctypes.c_uint32),
        ("import_stack", ctypes.c_uint32),
        ("span_count", ctypes.c_uint32),
        ("trace_count", ctypes.c_uint32),
        ("span_lo", ctypes.c_uint32 * 16),
        ("span_hi", ctypes.c_uint32 * 16),
        ("span_write", ctypes.c_uint32 * 16),
        ("span_name", (ctypes.c_char * 16) * 16),
        ("trace_kind", ctypes.c_uint32 * 32),
        ("trace_fn", ctypes.c_uint32 * 32),
        ("trace_target", ctypes.c_uint32 * 32),
        ("fault_kind", ctypes.c_uint32),
        ("fault_addr", ctypes.c_uint32),
        ("fault_eip", ctypes.c_uint32),
        ("fault_fn", ctypes.c_uint32),
        ("fault_section", ctypes.c_char * 16),
    ]


def main():
    game = sys.argv[1]
    info = uca.read_inputs(game)
    image = read_sections(game)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    selected = [IMPORT_FN, DATA_FN, PAIR_A, PAIR_B, *CHAIN, RDATA_FN]
    bodies = []
    rets = {}
    for addr in selected:
        code, _ = lifter.lift(addr)
        code, name, ret = instrument(code, addr, addr in (IMPORT_FN, DATA_FN))
        bodies.append((addr, name, code))
        if ret:
            rets[addr] = ret
    src = build_source(bodies, rets[IMPORT_FN], rets[DATA_FN])
    work = tempfile.mkdtemp(prefix="uc-phase7-")
    c_path = os.path.join(work, "phase7.c")
    with open(c_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(src)
    includes = ["-I", os.path.join(ROOT, "tests", "uc_host"),
                "-I", os.path.join(ROOT, "tests"),
                "-I", os.path.join(ROOT, "runtime")]
    common = [clang(), "-c", "-std=c11", "-O0", "-ffreestanding", "-DUC_GUEST_CHECKED"] + includes
    objs = []
    for src_path in (c_path, os.path.join(ROOT, "runtime", "uc_import.c"),
                     os.path.join(ROOT, "runtime", "uc_image.c")):
        obj = os.path.join(work, os.path.basename(src_path) + ".o")
        proc = subprocess.run(common + ["-o", obj, src_path], capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            sys.stderr.write(src_path + "\n")
            sys.exit(proc.returncode or 1)
        objs.append(obj)
    dll = os.path.join(work, "uc_phase7.dll")
    link(objs, dll)
    lib = ctypes.CDLL(dll)
    lib.uc_phase7_sizes.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    sec_size = ctypes.c_uint32()
    out_size = ctypes.c_uint32()
    lib.uc_phase7_sizes(ctypes.byref(sec_size), ctypes.byref(out_size))
    if sec_size.value != ctypes.sizeof(Section) or out_size.value != ctypes.sizeof(Out):
        sys.exit("struct size mismatch section %s/%s out %s/%s" % (
            sec_size.value, ctypes.sizeof(Section), out_size.value, ctypes.sizeof(Out)))
    lib.uc_phase7_run.restype = ctypes.c_int
    mem = (ctypes.c_uint8 * MEM_SIZE)()
    items = []
    keep = []
    for sec in image["sections"]:
        if sec["name"] not in ALLOWED and sec["name"] not in PROTECTED:
            continue
        item = Section()
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
    arr = (Section * len(items))(*items)
    text = next(s for s in image["sections"] if s["name"] == ".text")
    rdata = next(s for s in image["sections"] if s["name"] == ".rdata")
    data = next(s for s in image["sections"] if s["name"] == ".data")
    sitext = next(s for s in image["sections"] if s["name"] == "Sitext")
    cfg = Config()
    cfg.text_va = text["va"]
    cfg.text_dword = struct.unpack_from("<I", text["raw"], 0)[0]
    cfg.rdata_va = rdata["va"]
    cfg.rdata_dword = struct.unpack_from("<I", rdata["raw"], 0)[0]
    tail = data["va"] + min(data["raw_size"], data["vsize"])
    tail = (tail + 3) & ~3
    if tail + 4 > data["va"] + data["vsize"]:
        sys.exit(".data has no virtual tail to check")
    cfg.data_tail = tail
    cfg.sitext_va = sitext["va"]
    gap = text["va"] + text["vsize"]
    gap = (gap + 3) & ~3
    mapped = [s for s in image["sections"] if s["name"] in ALLOWED]
    moved = True
    while moved:
        moved = False
        for sec in mapped:
            if sec["va"] <= gap < sec["va"] + sec["vsize"]:
                gap = (sec["va"] + sec["vsize"] + 3) & ~3
                moved = True
    cfg.gap_va = gap
    cfg.image_end = image["image_base"] + image["size_image"]
    cfg.rdata_float = RDATA_FLOAT
    cfg.import_ret = rets[IMPORT_FN]
    cfg.data_ret = rets[DATA_FN]
    out = Out()
    rc = lib.uc_phase7_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), MEM_SIZE,
        arr, len(items), ctypes.byref(cfg), ctypes.byref(out))
    if out.section_bytes and out.section_bytes != ctypes.sizeof(Section):
        print("section struct mismatch", out.section_bytes, ctypes.sizeof(Section))
    if out.out_bytes and out.out_bytes != ctypes.sizeof(Out):
        print("result struct mismatch", out.out_bytes, ctypes.sizeof(Out))
    print("work", work)
    print("import_ret", hex(rets[IMPORT_FN]), "data_ret", hex(rets[DATA_FN]))
    print("sections")
    for sec in image["sections"]:
        kind = "protected" if sec["name"] in PROTECTED else ("mapped" if sec["name"] in ALLOWED else "skipped")
        print(" ", sec["name"], hex(sec["va"]), "vsize", sec["vsize"], kind, "flags", hex(sec["flags"]))
    fields = (
        "code", "esp_entry", "esp_before_call", "esp_inside", "esp_after_import",
        "esp_after_cleanup", "esp_final", "eax_final", "eip_final",
        "data_before", "data_inside", "data_after_import", "data_after_cleanup",
        "data_final", "data_eax", "pair_final", "pair_eax", "pair_ebp",
        "chain_eax", "chain_counter", "chain_esi", "import_abi", "import_stack",
        "span_count", "trace_count", "fault_kind", "fault_addr", "fault_eip", "fault_fn")
    for name in fields:
        value = getattr(out, name)
        print(f"{name} {value if name == 'code' or name.endswith('count') or name == 'import_abi' or name == 'import_stack' or name == 'fault_kind' else hex(value)}")
    print("fault_section", out.fault_section)
    for i in range(min(16, out.span_count)):
        name = bytes(out.span_name[i]).split(b"\0", 1)[0].decode("ascii", "replace")
        print(" span", i, name, "write" if out.span_write[i] else "read",
              hex(out.span_lo[i]), hex(out.span_hi[i]))
    for i in range(min(32, out.trace_count)):
        print(" trace", i, out.trace_kind[i], hex(out.trace_fn[i]), hex(out.trace_target[i]))
    if rc != 0:
        lines = src.splitlines()
        text = lines[rc - 1] if 0 < rc <= len(lines) else ""
        print("failed line", rc, text)
        sys.exit(1)
    print("uc phase7 tests passed")


if __name__ == "__main__":
    main()
