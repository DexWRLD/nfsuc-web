#!/usr/bin/env python3
"""Phase 25: strncpy HLE + real Undercover consumer 0x0088390D.

Does not start nfs.exe. Protected sections stay unmapped.
"""
import ctypes
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
import uc_code_analyze as uca
import uc_phase7_test as p7

ROOT = p7.ROOT
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
CONSUMER = 0x0088390D
THUNK = 0x0087B6A0


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
    found = re.search(
        r"PUSH32\((0x[0-9a-f]+)u\); sub_%08x\(c\);" % THUNK, code)
    if found:
        code = code.replace(
            found.group(0),
            "uc_esp_mark_at(0, c);\n    %s\n    uc_esp_mark_at(1, c);" % found.group(0),
            1)
        pos = code.find("uc_esp_mark_at(1, c);")
        assign = "c->esp = (uint32_t)(_r);"
        at = code.find(assign, pos)
        if at >= 0:
            code = code[:at + len(assign)] + "\n    uc_esp_mark_at(2, c);" + code[at + len(assign):]
    if re.search(r"\bdispatch_indirect\s*\(", code):
        sys.exit("indirect dispatch in %08x" % addr)
    return name, code


def build_source(name, body):
    return r'''
#include "cpu.h"
#include "uc_abi.h"
#include "uc_image.h"

uint8_t *g_mem;
int _fltused;
static int uc_hle_fail;
static int uc_direct_fail;
static uint32_t uc_strncpy_calls;

static void zero_bytes(void *p, unsigned n) {
    unsigned char *b = (unsigned char *)p;
    while (n--) *b++ = 0;
}

void %s_impl(CPU *restrict c);

static void uc_direct(uint32_t target, CPU *c) {
    (void)target; (void)c; uc_direct_fail = 1;
}
static void uc_thunk(CPU *c, uint32_t thunk) {
    const UcImport *imp = uc_import_find(thunk);
    uc_esp_mark_at(3, c);
    uc_trace(UC_EV_IMPORT_CALL, uc_current_fn, c->eip, thunk, c);
    if (!imp || !uc_import_invoke(c, imp, 0)) uc_hle_fail = 1;
    else if (thunk == 0x0087B6A0u) uc_strncpy_calls++;
    uc_esp_mark_at(4, c);
    uc_trace(UC_EV_IMPORT_RETURN, uc_current_fn, c->eip, thunk, c);
}
void sub_0087b6a0(CPU *c) { uc_thunk(c, 0x0087b6a0u); }

%s

void dispatch_indirect(CPU *c, uint32_t target) {
    (void)c; (void)target; uc_direct_fail = 1;
}
void dispatch_tail(CPU *c) { (void)c; }
void unsupported_insn(CPU *c, uint32_t addr, const char *why) {
    (void)c; (void)addr; (void)why; uc_direct_fail = 1;
}

typedef struct UcPhase25Out {
    uint32_t code;
    uint32_t strncpy_calls;
    uint32_t hle_fail;
    uint32_t direct_fail;
    uint32_t eip;
    uint32_t esp;
    uint32_t dest0;
    uint32_t dest9;
    uint32_t dest10;
    uint32_t dest11;
    uint32_t hle_id;
} UcPhase25Out;

static int fail_line;
#define EXPECT(cond) do { if (!(cond)) { fail_line = __LINE__; return; } } while (0)

static void wr32(uint32_t addr, uint32_t value) {
    uc_guest_store32(addr, value, 0);
}
static void putstr(uint32_t addr, const char *s) {
    unsigned i = 0;
    while (s[i]) { uc_guest_store8(addr + i, (uint8_t)s[i]); i++; }
    uc_guest_store8(addr + i, 0);
}

static void run_consumer(UcPhase25Out *out) {
    CPU c;
    uint32_t esp = 0x0300f000u;
    uint32_t obj = 0x03004000u;
    uint32_t src = 0x03005000u;
    unsigned i;
    zero_bytes(&c, sizeof c);
    EXPECT(uc_image_add_private("stack", 0x03000000u, 0x10000u, UC_MEM_READ | UC_MEM_WRITE) == 0);
    EXPECT(uc_image_add_private("obj", 0x03004000u, 0x2000u, UC_MEM_READ | UC_MEM_WRITE) == 0);
    putstr(src, "UNDERCOVER");
    for (i = 0; i < 0x800; i++) uc_guest_store8(obj + i, 0xA5);
    uc_hle_fail = 0;
    uc_direct_fail = 0;
    uc_strncpy_calls = 0;
    c.esp = esp;
    c.ecx = obj;
    wr32(esp, 0x00dec0deu);
    wr32(esp + 4, src);
    %s_impl(&c);
    out->strncpy_calls = uc_strncpy_calls;
    out->hle_fail = (uint32_t)uc_hle_fail;
    out->direct_fail = (uint32_t)uc_direct_fail;
    out->eip = c.eip;
    out->esp = c.esp;
    out->dest0 = uc_guest_ptr(obj + 0xb4u, 1, 0)[0];
    out->dest9 = uc_guest_ptr(obj + 0xb4u, 1, 0)[9];
    out->dest10 = uc_guest_ptr(obj + 0xb4u, 1, 0)[10];
    out->dest11 = uc_guest_ptr(obj + 0xb4u, 1, 0)[11];
    out->hle_id = (uint32_t)(uc_import_find(0x0087B6A0u)
                             ? uc_import_find(0x0087B6A0u)->hle : 0);
    EXPECT(uc_hle_fail == 0);
    EXPECT(uc_direct_fail == 0);
    EXPECT(uc_access_fault.active == 0);
    EXPECT(uc_strncpy_calls == 1);
    EXPECT(c.eip == 0x00dec0deu);
    EXPECT(out->dest0 == 'U');
    EXPECT(out->dest9 == 'R');
    EXPECT(out->dest10 == 0);
    EXPECT(out->dest11 == 0);
    EXPECT(out->hle_id == (uint32_t)UC_HLE_STRNCPY);
}

__declspec(dllexport) int uc_phase25_run(
    uint8_t *mem, uint32_t mem_size,
    const UcSectionIn *sections, int nsections,
    UcPhase25Out *out) {
    int i;
    fail_line = 0;
    zero_bytes(out, sizeof *out);
    if (uc_image_reset(mem, mem_size)) return 1;
    for (i = 0; i < nsections; i++) {
        if (uc_image_map(&sections[i])) return 2;
    }
    run_consumer(out);
    out->code = (uint32_t)fail_line;
    return fail_line;
}
''' % (name, body, name)


class Out(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32),
        ("strncpy_calls", ctypes.c_uint32),
        ("hle_fail", ctypes.c_uint32),
        ("direct_fail", ctypes.c_uint32),
        ("eip", ctypes.c_uint32),
        ("esp", ctypes.c_uint32),
        ("dest0", ctypes.c_uint32),
        ("dest9", ctypes.c_uint32),
        ("dest10", ctypes.c_uint32),
        ("dest11", ctypes.c_uint32),
        ("hle_id", ctypes.c_uint32),
    ]


def main():
    info = uca.read_inputs(GAME)
    image = p7.read_sections(GAME)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    code, _ = lifter.lift(CONSUMER)
    name, code = instrument(code, CONSUMER)
    src = build_source(name, code)
    work = tempfile.mkdtemp(prefix="uc-phase25-")
    c_path = os.path.join(work, "phase25.c")
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
    dll = os.path.join(work, "uc_phase25.dll")
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
    lib.uc_phase25_run.restype = ctypes.c_int
    rc = lib.uc_phase25_run(
        ctypes.cast(mem, ctypes.POINTER(ctypes.c_uint8)), p7.MEM_SIZE,
        arr, len(items), ctypes.byref(out))
    for field, _typ in Out._fields_:
        print(field, getattr(out, field))
    if rc != 0:
        lines = src.splitlines()
        text = lines[rc - 1] if 0 < rc <= len(lines) else ""
        print("failed line", rc, text)
        print("work", work)
        sys.exit(1)
    print("uc phase25 consumer tests passed")


if __name__ == "__main__":
    main()
