#!/usr/bin/env python3
"""Native tests for the Undercover import ABI and one recompiled leaf.

The leaf is generated into a temporary C file and executed as C. nfs.exe
is only read so the lifter can translate 0x00721070. It is not executed.
"""
import os, shutil, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
import uc_code_analyze as uca

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = 0x00721070
CLANGS = (
    os.environ.get("CLANG") or "",
    "clang",
    r"C:\Program Files\Unity\Hub\Editor\6000.6.7f1\Editor\Data\PlaybackEngines\WebGLSupport\BuildTools\Emscripten\llvm\clang.exe",
)


def clang():
    for cand in CLANGS:
        if not cand:
            continue
        path = cand if os.path.isfile(cand) else shutil.which(cand)
        if path:
            return path
    sys.exit("clang was not found")


def link(objs, exe):
    lld = os.path.join(os.path.dirname(clang()), "lld.exe")
    if not os.path.isfile(lld):
        lld = shutil.which("lld")
    if not lld:
        sys.exit("lld was not found")
    proc = subprocess.run(
        [lld, "-flavor", "link", "-out:" + exe, "-entry:main", "-subsystem:console"] + objs,
        capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.exit(proc.returncode or 1)


def main():
    exe = sys.argv[1]
    info = uca.read_inputs(exe)
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    code, _calls = lifter.lift(TARGET)
    if "dispatch_indirect" in code or "sub_" in code.replace(f"sub_{TARGET:08x}", ""):
        sys.exit("the selected function is not a leaf:\n" + code)
    if "esp += 8u" not in code:
        sys.exit("ret 8 was not lowered:\n" + code)
    src = r'''#include "uc_harness.h"
#include "uc_abi.h"
static uint8_t image[0x100000];
uint8_t *g_mem = image;
int _fltused;
void unsupported_insn(CPU *c, uint32_t a, const char *w) { (void)c; (void)a; (void)w; }
void cpuid_shim(CPU *c) { (void)c; }
uint64_t rdtsc_shim(void) { return 0; }
''' + code + r'''
static int fail;
static int fail_id;
static void expect_at(int id, uint32_t got, uint32_t want) {
    if (got != want) { if (!fail_id) fail_id = id; fail++; }
}
#define expect(g, w) expect_at(__LINE__, (uint32_t)(g), (uint32_t)(w))
static void zero(void *p, unsigned n) {
    unsigned char *b = p;
    unsigned i;
    for (i = 0; i < n; i++) b[i] = 0;
}
static void plant(CPU *c, uint32_t esp, uint32_t ret, const uint32_t *args, int n) {
    int i;
    c->esp = esp;
    MR32(esp) = ret;
    for (i = 0; i < n; i++) MR32(esp + 4u + 4u * (uint32_t)i) = args[i];
}
static uint32_t sum2(CPU *c, const UcDecoded *in, int *ok) {
    (void)c;
    *ok = 1;
    return in->stack[0] + in->stack[1];
}
static uint32_t this_add(CPU *c, const UcDecoded *in, int *ok) {
    (void)c;
    *ok = 1;
    return in->ecx + in->stack[0];
}
static uint32_t fast_add(CPU *c, const UcDecoded *in, int *ok) {
    (void)c;
    *ok = 1;
    return in->ecx + in->edx + in->stack[0];
}
static void test_abi(void) {
    CPU cpu, *c = &cpu;
    UcImport desc;
    const UcImport *imp;
    uint32_t args[3];
    uint32_t traced;
    zero(c, sizeof cpu);
    uc_guest_limit = sizeof image;
    uc_import_trace = 0;
    uc_import_trace_count = 0;
    expect(uc_abi_callee_bytes(UC_ABI_CDECL, 3), 0);
    expect(uc_abi_callee_bytes(UC_ABI_STDCALL, 3), 12);
    expect(uc_abi_callee_bytes(UC_ABI_THISCALL, 0), 0);
    expect(uc_abi_callee_bytes(UC_ABI_THISCALL, 1), 4);
    expect(uc_abi_callee_bytes(UC_ABI_FASTCALL, 1), 4);
    expect((uint32_t)uc_abi_callee_bytes(UC_ABI_UNKNOWN, 3), 0xffffffffu);

    zero(&desc, sizeof desc);
    desc.dll = "MSVCR80.dll";
    desc.symbol = "memcpy";
    desc.ordinal = -1;
    desc.abi = UC_ABI_CDECL;
    desc.stack_dwords = 3;
    desc.hle = UC_HLE_MEMCPY;
    args[0] = 0x1100;
    args[1] = 0x1000;
    args[2] = 4;
    MR8(0x1000) = 0x11; MR8(0x1001) = 0x22; MR8(0x1002) = 0x33; MR8(0x1003) = 0x44;
    c->eip = 0x00721000u;
    c->ecx = 0x55aa55aau;
    plant(c, 0x8000, 0x00abcdefu, args, 3);
    expect((uint32_t)uc_import_invoke(c, &desc, 0), 1);
    expect(c->eax, 0x1100);
    expect(c->eip, 0x00abcdefu);
    expect(c->esp, 0x8004);
    expect(c->ecx, 0x55aa55aau);
    expect(MR8(0x1100), 0x11);
    expect(MR8(0x1103), 0x44);
    expect(uc_import_trace_count, 0);
    c->esp += 12;
    expect(c->esp, 0x8010);

    zero(&desc, sizeof desc);
    desc.dll = "KERNEL32.dll";
    desc.symbol = "synthetic";
    desc.ordinal = -1;
    desc.abi = UC_ABI_STDCALL;
    desc.stack_dwords = 2;
    args[0] = 20;
    args[1] = 22;
    c->eip = 0x00401000u;
    plant(c, 0x8200, 0x11111111u, args, 2);
    expect((uint32_t)uc_import_invoke(c, &desc, sum2), 1);
    expect(c->eax, 42);
    expect(c->eip, 0x11111111u);
    expect(c->esp, 0x820c);

    zero(&desc, sizeof desc);
    desc.dll = "MSVCR80.dll";
    desc.symbol = "synthetic_this";
    desc.ordinal = -1;
    desc.abi = UC_ABI_THISCALL;
    desc.stack_dwords = 1;
    c->ecx = 0x100;
    c->eip = 0x00402000u;
    args[0] = 7;
    plant(c, 0x8400, 0x22222222u, args, 1);
    expect((uint32_t)uc_import_invoke(c, &desc, this_add), 1);
    expect(c->eax, 0x107);
    expect(c->ecx, 0x100);
    expect(c->esp, 0x8408);

    zero(&desc, sizeof desc);
    desc.dll = "synthetic.dll";
    desc.symbol = "synthetic_fast";
    desc.ordinal = -1;
    desc.abi = UC_ABI_FASTCALL;
    desc.stack_dwords = 1;
    c->ecx = 3;
    c->edx = 4;
    c->eip = 0x00403000u;
    args[0] = 5;
    plant(c, 0x8600, 0x33333333u, args, 1);
    expect((uint32_t)uc_import_invoke(c, &desc, fast_add), 1);
    expect(c->eax, 12);
    expect(c->esp, 0x8608);

    imp = uc_import_find(0x0087A7AEu);
    c->eip = 0x0071B85Fu;
    c->esp = 0x8800;
    c->eax = 0x99;
    c->ecx = 0x77;
    c->edx = 0x66;
    MR32(0x8800) = 0x44444444u;
    traced = uc_import_trace_count;
    expect((uint32_t)uc_import_invoke(c, imp, sum2), 0);
    expect(c->esp, 0x8800);
    expect(c->eax, 0x99);
    expect(MR32(0x8800), 0x44444444u);
    expect((uint32_t)uc_import_fault.active, 1);
    expect(uc_import_fault.call_site, 0x0071B85Fu);
    expect(uc_import_fault.thunk, 0x0087A7AEu);
    expect(uc_import_fault.esp, 0x8800);
    expect(uc_import_fault.ecx, 0x77);
    expect(uc_import_fault.edx, 0x66);
    expect(uc_import_trace_count, traced);
    if (!imp || imp->abi != UC_ABI_UNKNOWN) fail++;

    imp = uc_import_find(0x0087C2F8u);
    if (!imp || imp->abi != UC_ABI_THISCALL || imp->stack_dwords != 0) fail++;
    c->esp = 0x8a00;
    c->eip = 0x0087C2F8u;
    expect((uint32_t)uc_import_invoke(c, imp, 0), 0);
    expect(c->esp, 0x8a00);
    if (!uc_import_fault.active) fail++;

    imp = uc_import_find(0x0087B44Cu);
    if (!imp || imp->abi != UC_ABI_CDECL || imp->hle != UC_HLE_MEMCPY || imp->stack_dwords != 3) fail++;
    args[0] = 0x1200; args[1] = 0x1201; args[2] = 4;
    MR32(0x1200) = 0x11111111u;
    c->eip = 0x00900000u;
    plant(c, 0x8c00, 0x55555555u, args, 3);
    expect((uint32_t)uc_import_invoke(c, imp, 0), 0);
    expect(c->esp, 0x8c00);
    expect(MR32(0x1200), 0x11111111u);

    zero(c, sizeof cpu);
    uc_import_trace = 1;
    args[0] = 0x1300; args[1] = 0x1310; args[2] = 3;
    MR8(0x1310) = 'a'; MR8(0x1311) = 'b'; MR8(0x1312) = 'c';
    c->eip = 0x00A00000u;
    plant(c, 0x8e00, 0x66666666u, args, 3);
    expect((uint32_t)uc_import_invoke(c, imp, 0), 1);
    expect(c->esp, 0x8e04);
    expect(MR8(0x1300), 'a');
    expect(MR8(0x1302), 'c');
    expect(uc_import_trace_count, 1);
    expect(uc_import_trace_last.call_site, 0x00A00000u);
    expect(uc_import_trace_last.esp_before, 0x8e00);
    expect(uc_import_trace_last.esp_after, 0x8e04);
    expect(uc_import_trace_last.eax, 0x1300);
    expect((uint32_t)uc_import_trace_last.abi, (uint32_t)UC_ABI_CDECL);
    expect((uint32_t)uc_import_trace_last.stack_dwords, 3);
    uc_import_trace = 0;

    imp = uc_import_find(0x0087B2D6u);
    if (!imp || imp->hle != UC_HLE_MEMSET) fail++;
    args[0] = 0x1400; args[1] = 0xAB; args[2] = 4;
    c->eip = 0x00A10000u;
    plant(c, 0x9000, 0x77777777u, args, 3);
    expect((uint32_t)uc_import_invoke(c, imp, 0), 1);
    expect(c->eax, 0x1400);
    expect(c->esp, 0x9004);
    expect(MR8(0x1400), 0xAB);
    expect(MR8(0x1403), 0xAB);

    imp = uc_import_find(0x0087B4B8u);
    if (!imp || imp->hle != UC_HLE_MEMMOVE) fail++;
    MR32(0x1500) = 0x11223344u;
    args[0] = 0x1502; args[1] = 0x1500; args[2] = 4;
    c->eip = 0x00A20000u;
    plant(c, 0x9200, 0x88888888u, args, 3);
    expect((uint32_t)uc_import_invoke(c, imp, 0), 1);
    expect(c->esp, 0x9204);
    expect(MR8(0x1502), 0x44);
    expect(MR8(0x1503), 0x33);
    expect(MR8(0x1504), 0x22);
    expect(MR8(0x1505), 0x11);
    {
        const UcImport *cmp = 0, *len = 0, *eq = 0, *ncmp = 0;
        unsigned n = uc_import_count();
        uint32_t t;
        for (t = 0x0087A000u; t < 0x00880000u && (!cmp || !len || !eq || !ncmp); t++) {
            const UcImport *row = uc_import_find(t);
            if (!row) continue;
            if (row->hle == UC_HLE_MEMCMP) cmp = row;
            if (row->hle == UC_HLE_STRLEN) len = row;
            if (row->hle == UC_HLE_STRCMP) eq = row;
            if (row->hle == UC_HLE_STRNCMP) ncmp = row;
        }
        (void)n;
        if (!cmp || !len || !eq || !ncmp) { fail++; return; }
        MR8(0x1600) = 1; MR8(0x1601) = 2; MR8(0x1610) = 1; MR8(0x1611) = 9;
        args[0] = 0x1600; args[1] = 0x1610; args[2] = 2;
        plant(c, 0x9400, 0x99999999u, args, 3);
        expect((uint32_t)uc_import_invoke(c, cmp, 0), 1);
        expect(c->eax, (uint32_t)(int)(2 - 9));
        expect(c->esp, 0x9404);
        MR8(0x1700) = 'h'; MR8(0x1701) = 'i'; MR8(0x1702) = 0;
        args[0] = 0x1700;
        plant(c, 0x9600, 0xaaaaaaaau, args, 1);
        expect((uint32_t)uc_import_invoke(c, len, 0), 1);
        expect(c->eax, 2);
        expect(c->esp, 0x9604);
        MR8(0x1710) = 'h'; MR8(0x1711) = 'i'; MR8(0x1712) = 0;
        args[0] = 0x1700; args[1] = 0x1710;
        plant(c, 0x9800, 0xbbbbbbbbu, args, 2);
        expect((uint32_t)uc_import_invoke(c, eq, 0), 1);
        expect(c->eax, 0);
        expect(c->esp, 0x9804);
        args[0] = 0x1700; args[1] = 0x1710; args[2] = 1;
        plant(c, 0x9a00, 0xccccccccu, args, 3);
        expect((uint32_t)uc_import_invoke(c, ncmp, 0), 1);
        expect(c->eax, 0);
        expect(c->esp, 0x9a04);
    }
}
static void test_leaf(void) {
    CPU cpu, *c = &cpu;
    uint32_t entry = 0x7000;
    zero(c, sizeof cpu);
    uc_guest_limit = sizeof image;
    c->ecx = 0x12345678u;
    c->edx = 0x9abcdef0u;
    c->ebx = 0x11111111u;
    c->esi = 0x22222222u;
    c->edi = 0x33333333u;
    c->ebp = 0x44444444u;
    c->esp = entry;
    MR32(entry) = 0x00dec0deu;
    MR32(entry + 4) = 0x11111111u;
    MR32(entry + 8) = 0x01010101u;
    sub_00721070(c);
    expect(c->eax, 0x10101010u);
    expect(c->eip, 0x00dec0deu);
    expect(c->esp, entry + 12);
    expect(MR32(entry), 0x00dec0deu);
    expect(MR32(entry + 4), 0x11111111u);
    expect(MR32(entry + 8), 0x01010101u);
    expect(c->ecx, 0x12345678u);
    expect(c->edx, 0x9abcdef0u);
    expect(c->ebx, 0x11111111u);
    expect(c->esi, 0x22222222u);
    expect(c->edi, 0x33333333u);
    expect(c->ebp, 0x44444444u);

    c->esp = entry;
    MR32(entry) = 0x00abbabeu;
    MR32(entry + 4) = 0xffffffffu;
    MR32(entry + 8) = 0xffffffffu;
    sub_00721070(c);
    expect(c->eax, 0);
    expect(c->eip, 0x00abbabeu);
    expect(c->esp, entry + 12);
}
int main(void) {
    test_abi();
    test_leaf();
    return fail ? fail_id : 0;
}
'''
    # The overlap memcpy is expected to fail and restore ESP. Confirm the
    # descriptor used above is the real memcpy thunk before compiling.
    work = tempfile.mkdtemp(prefix="uc-phase6-")
    path = os.path.join(work, "test.c")
    obj_c = os.path.join(work, "test.o")
    obj_r = os.path.join(work, "uc_import.o")
    exe_path = os.path.join(work, "test.exe")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(src)
    includes = [
        "-I", os.path.join(ROOT, "tests", "uc_host"),
        "-I", os.path.join(ROOT, "tests"),
        "-I", os.path.join(ROOT, "runtime"),
    ]
    common = [clang(), "-c", "-std=c11", "-O0", "-ffreestanding"] + includes
    for src_path, obj in (
        (path, obj_c),
        (os.path.join(ROOT, "runtime", "uc_import.c"), obj_r),
    ):
        proc = subprocess.run(common + ["-o", obj, src_path], capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            sys.stderr.write(src_path + "\n")
            sys.exit(proc.returncode or 1)
    link([obj_c, obj_r], exe_path)
    run = subprocess.run([exe_path], capture_output=True, text=True)
    sys.stdout.write(run.stdout)
    sys.stderr.write(run.stderr)
    if run.returncode == 0:
        print("uc phase6 tests passed")
    else:
        lines = open(path, encoding="utf-8").read().splitlines()
        n = run.returncode
        text = lines[n - 1] if 0 < n <= len(lines) else ""
        print(f"uc phase6 tests failed at C line {n}: {text}")
        print(path)
    sys.exit(run.returncode)


if __name__ == "__main__":
    main()
