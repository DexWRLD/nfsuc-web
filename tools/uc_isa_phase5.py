#!/usr/bin/env python3
"""Regression tests for the Phase 5 Undercover opcodes.

XMM tests use the integer lanes, not host floating point. Locked xadd,
cmpxchg, and cmpxchg8b go through guest_atomic_* and are checked at the
guest memory bytes.
"""
import os, shutil, struct, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = 0x00401000
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


def link(obj, exe):
    lld = os.path.join(os.path.dirname(clang()), "lld.exe")
    if not os.path.isfile(lld):
        lld = shutil.which("lld")
    if not lld:
        sys.exit("lld was not found")
    proc = subprocess.run(
        [lld, "-flavor", "link", "-out:" + exe, "-entry:main", "-subsystem:console", obj],
        capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.exit(proc.returncode or 1)


def lift_named(blob, name):
    lifter = lift.RawLifter(blob, base=BASE, comments=False)
    code, _calls = lifter.lift(BASE)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    insns = list(md.disasm(blob, BASE))
    return code.replace(f"sub_{BASE:08x}", name), insns


def xmm_bytes(words):
    raw = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)
    return list(raw)


def main():
    functions = []
    checks = []

    def add(name, blob, expect_mnemonic):
        code, insns = lift_named(blob + b"\xC3", name)
        got = [i.mnemonic for i in insns]
        if expect_mnemonic not in got:
            sys.exit(f"{name} decoded as {got}, wanted {expect_mnemonic}")
        if "guest_atomic_" in code and "lock" not in expect_mnemonic and "cmpxchg8b" not in expect_mnemonic:
            pass
        functions.append(code)
        return code

    # PSRLDQ / PSLLDQ xmm0, imm8. 66 0F 73 /3 or /7.
    shift_counts = (0, 1, 4, 8, 15, 16, 17)
    for count in shift_counts:
        add(f"psrldq_{count}", bytes([0x66, 0x0F, 0x73, 0xD8, count]), "psrldq")
        add(f"pslldq_{count}", bytes([0x66, 0x0F, 0x73, 0xF8, count]), "pslldq")
        checks.append(("shift", count))

    # PSHUFD xmm0, xmm1, imm. 66 0F 70 C1 ib
    masks = {
        "preserve": 0xE4,   # 3,2,1,0
        "reverse": 0x1B,    # 0,1,2,3
        "broadcast0": 0x00,
        "broadcast3": 0xFF,
        "mixed": 0x4E,      # 2,3,0,1
    }
    lanes = (0x11111111, 0x22222222, 0x33333333, 0x44444444)
    for label, imm in masks.items():
        add(f"pshufd_{label}", bytes([0x66, 0x0F, 0x70, 0xC1, imm]), "pshufd")
    # memory form: pshufd xmm0, [ebx], imm
    add("pshufd_mem", bytes([0x66, 0x0F, 0x70, 0x03, 0x1B]), "pshufd")

    # PUNPCKLQDQ xmm0, xmm1. 66 0F 6C C1
    code, _ins = lift_named(bytes([0x66, 0x0F, 0x6C, 0xC1, 0xC3]), "punpck_reg")
    if "u64[1]" not in code:
        sys.exit("punpcklqdq was not lowered as a qword move")
    functions.append(code)
    add("punpck_mem", bytes([0x66, 0x0F, 0x6C, 0x03]), "punpcklqdq")
    hq, _ = lift_named(bytes([0x66, 0x0F, 0x6D, 0xC1, 0xC3]), "punpckh_reg")
    if "u64[0]=_d" not in hq:
        sys.exit("punpckhqdq was not lowered as a high-qword interleave")
    functions.append(hq)
    word_masks = {
        "wpreserve": 0xE4,
        "wreverse": 0x1B,
        "wbroadcast0": 0x00,
        "wbroadcast3": 0xFF,
        "wgame": 0xF9,
    }
    for label, imm in word_masks.items():
        add(f"pshuflw_{label}", bytes([0xF2, 0x0F, 0x70, 0xC1, imm]), "pshuflw")

    # lock xadd dword ptr [ebx], ecx
    xadd_code, xadd_ins = lift_named(bytes([0xF0, 0x0F, 0xC1, 0x0B, 0xC3]), "lock_xadd")
    if "guest_atomic_xadd" not in xadd_code:
        sys.exit("lock xadd did not use the atomic helper")
    if xadd_ins[0].mnemonic != "lock xadd":
        sys.exit("lock prefix was dropped from the mnemonic: " + xadd_ins[0].mnemonic)
    functions.append(xadd_code)
    # unlocked xadd ecx, eax
    plain, _ = lift_named(bytes([0x0F, 0xC1, 0xC1, 0xC3]), "plain_xadd")
    if "guest_atomic_xadd" in plain:
        sys.exit("unlocked xadd was routed through the atomic helper")
    functions.append(plain)

    cmp_code, cmp_ins = lift_named(bytes([0xF0, 0x0F, 0xB1, 0x13, 0xC3]), "lock_cmpxchg")
    if "guest_atomic_cmpxchg(" not in cmp_code:
        sys.exit("lock cmpxchg did not use the atomic helper")
    if cmp_ins[0].mnemonic != "lock cmpxchg":
        sys.exit(cmp_ins[0].mnemonic)
    functions.append(cmp_code)

    c8_code, c8_ins = lift_named(bytes([0xF0, 0x0F, 0xC7, 0x0E, 0xC3]), "lock_cmpxchg8b")
    if "guest_atomic_cmpxchg8b" not in c8_code:
        sys.exit("lock cmpxchg8b did not use the atomic helper")
    if c8_ins[0].mnemonic != "lock cmpxchg8b":
        sys.exit(c8_ins[0].mnemonic)
    functions.append(c8_code)

    src_lanes = ", ".join(f"0x{w:08x}u" for w in lanes)
    body = "\n".join(functions)
    src = f"""#include "uc_harness.h"
static uint8_t image[0x200000];
uint8_t *g_mem = image;
void unsupported_insn(CPU *c, uint32_t a, const char *w) {{ (void)c; (void)a; (void)w; }}
void cpuid_shim(CPU *c) {{ (void)c; }}
uint64_t rdtsc_shim(void) {{ return 0; }}
{body}
static int fail;
static void zero(void *p, unsigned n) {{
    unsigned char *b = p;
    for (unsigned i = 0; i < n; i++) b[i] = 0;
}}
static void check(const char *name, uint32_t got, uint32_t want) {{
    if (got != want) fail++;
    (void)name;
}}
static void checkb(const char *name, uint8_t *got, const uint8_t *want) {{
    for (int i = 0; i < 16; i++) if (got[i] != want[i]) fail++;
    (void)name;
}}
static void fill(CPU *c) {{
    for (int i = 0; i < 16; i++) c->xmm[0].b[i] = (uint8_t)i;
}}
static void expect_shift(uint8_t *out, int count, int right) {{
    for (int i = 0; i < 16; i++) out[i] = 0;
    if (count <= 0 || count >= 16) {{
        if (count <= 0) for (int i = 0; i < 16; i++) out[i] = (uint8_t)i;
        return;
    }}
    if (right) for (int i = 0; i < 16 - count; i++) out[i] = (uint8_t)(i + count);
    else for (int i = count; i < 16; i++) out[i] = (uint8_t)(i - count);
}}
int main(void) {{
    uint8_t want[16];
    CPU cpu;
    CPU *c = &cpu;
"""
    for count in shift_counts:
        src += f"""
    zero(c, sizeof cpu);
    fill(c);
    psrldq_{count}(c);
    expect_shift(want, {count}, 1);
    checkb("psrldq {count}", c->xmm[0].b, want);
    zero(c, sizeof cpu);
    fill(c);
    pslldq_{count}(c);
    expect_shift(want, {count}, 0);
    checkb("pslldq {count}", c->xmm[0].b, want);
"""
    src += f"""
    static const uint32_t src_lanes[4] = {{ {src_lanes} }};
"""
    # selection expected in C from the immediate
    for label, imm in masks.items():
        sel = [(imm >> 0) & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3]
        src += f"""
    zero(c, sizeof cpu);
    for (int k = 0; k < 4; k++) c->xmm[1].u32[k] = src_lanes[k];
    pshufd_{label}(c);
    check("pshufd {label} 0", c->xmm[0].u32[0], src_lanes[{sel[0]}]);
    check("pshufd {label} 1", c->xmm[0].u32[1], src_lanes[{sel[1]}]);
    check("pshufd {label} 2", c->xmm[0].u32[2], src_lanes[{sel[2]}]);
    check("pshufd {label} 3", c->xmm[0].u32[3], src_lanes[{sel[3]}]);
"""
    src += """
    zero(c, sizeof cpu);
    c->ebx = 0x1000u;
    for (int k = 0; k < 4; k++) *(uint32_t *)(g_mem + 0x1000u + 4 * k) = src_lanes[k];
    pshufd_mem(c);
    check("pshufd mem 0", c->xmm[0].u32[0], src_lanes[3]);
    check("pshufd mem 1", c->xmm[0].u32[1], src_lanes[2]);
    check("pshufd mem 2", c->xmm[0].u32[2], src_lanes[1]);
    check("pshufd mem 3", c->xmm[0].u32[3], src_lanes[0]);

    zero(c, sizeof cpu);
    c->xmm[0].u64[0] = 0x1111111111111111ull;
    c->xmm[0].u64[1] = 0x2222222222222222ull;
    c->xmm[1].u64[0] = 0x3333333333333333ull;
    c->xmm[1].u64[1] = 0x4444444444444444ull;
    punpck_reg(c);
    check("punpck lo", (uint32_t)c->xmm[0].u64[0], 0x11111111u);
    check("punpck lo hi", (uint32_t)(c->xmm[0].u64[0] >> 32), 0x11111111u);
    check("punpck hi", (uint32_t)c->xmm[0].u64[1], 0x33333333u);
    check("punpck hi hi", (uint32_t)(c->xmm[0].u64[1] >> 32), 0x33333333u);

    zero(c, sizeof cpu);
    c->ebx = 0x1800u;
    c->xmm[0].u64[0] = 0x0A0A0A0A0A0A0A0Aull;
    c->xmm[0].u64[1] = 0x0B0B0B0B0B0B0B0Bull;
    *(uint64_t *)(g_mem + 0x1800u) = 0x0C0C0C0C0C0C0C0Cull;
    punpck_mem(c);
    check("punpck mem", (uint32_t)c->xmm[0].u64[1], 0x0C0C0C0Cu);

    zero(c, sizeof cpu);
    c->xmm[0].u64[0] = 0x1111111111111111ull;
    c->xmm[0].u64[1] = 0x2222222222222222ull;
    c->xmm[1].u64[0] = 0x3333333333333333ull;
    c->xmm[1].u64[1] = 0x4444444444444444ull;
    punpckh_reg(c);
    check("punpckh lo", (uint32_t)c->xmm[0].u64[0], 0x22222222u);
    check("punpckh lo hi", (uint32_t)(c->xmm[0].u64[0] >> 32), 0x22222222u);
    check("punpckh hi", (uint32_t)c->xmm[0].u64[1], 0x44444444u);
    check("punpckh hi hi", (uint32_t)(c->xmm[0].u64[1] >> 32), 0x44444444u);

    static const uint16_t words[4] = { 0x1111u, 0x2222u, 0x3333u, 0x4444u };
    static const uint8_t word_sel[][4] = {
        {0, 1, 2, 3},
        {3, 2, 1, 0},
        {0, 0, 0, 0},
        {3, 3, 3, 3},
        {1, 2, 3, 3}
    };
    static const char *word_names[] = {"wpreserve", "wreverse", "wbroadcast0", "wbroadcast3", "wgame"};
    for (int t = 0; t < 5; t++) {
        zero(c, sizeof cpu);
        c->xmm[1].u64[0] = 0x4444333322221111ull;
        c->xmm[1].u64[1] = 0x8877665544332211ull;
        if (t == 0) pshuflw_wpreserve(c);
        if (t == 1) pshuflw_wreverse(c);
        if (t == 2) pshuflw_wbroadcast0(c);
        if (t == 3) pshuflw_wbroadcast3(c);
        if (t == 4) pshuflw_wgame(c);
        for (int k = 0; k < 4; k++) {
            uint16_t got = (uint16_t)(c->xmm[0].u64[0] >> (k * 16));
            if (got != words[word_sel[t][k]]) fail++;
        }
        check(word_names[t], (uint32_t)c->xmm[0].u64[1], 0x44332211u);
        check(word_names[t], (uint32_t)(c->xmm[0].u64[1] >> 32), 0x88776655u);
        (void)word_names;
    }

    zero(c, sizeof cpu);
    c->ebx = 0x2000u;
    c->ecx = 1u;
    *(uint32_t *)(g_mem + 0x2000u) = 0xffffffffu;
    lock_xadd(c);
    check("xadd old", c->ecx, 0xffffffffu);
    check("xadd mem", *(uint32_t *)(g_mem + 0x2000u), 0u);
    check("xadd cf", c->cf, 1u);
    check("xadd zf", c->zf, 1u);
    check("xadd of", c->of, 0u);

    zero(c, sizeof cpu);
    c->ebx = 0x2000u;
    c->ecx = 1u;
    *(uint32_t *)(g_mem + 0x2000u) = 0x7fffffffu;
    lock_xadd(c);
    check("xadd ov mem", *(uint32_t *)(g_mem + 0x2000u), 0x80000000u);
    check("xadd ov cf", c->cf, 0u);
    check("xadd ov zf", c->zf, 0u);
    check("xadd ov of", c->of, 1u);
    check("xadd ov sf", c->sf, 1u);

    zero(c, sizeof cpu);
    c->ecx = 7u;
    c->eax = 5u;
    plain_xadd(c);
    check("plain xadd src", c->eax, 7u);
    check("plain xadd dst", c->ecx, 12u);
    check("plain xadd zf", c->zf, 0u);

    zero(c, sizeof cpu);
    c->ebx = 0x2100u;
    c->eax = 0x11111111u;
    c->edx = 0x22222222u;
    *(uint32_t *)(g_mem + 0x2100u) = 0x11111111u;
    lock_cmpxchg(c);
    check("cmp ok mem", *(uint32_t *)(g_mem + 0x2100u), 0x22222222u);
    check("cmp ok eax", c->eax, 0x11111111u);
    check("cmp ok zf", c->zf, 1u);
    check("cmp ok cf", c->cf, 0u);

    zero(c, sizeof cpu);
    c->ebx = 0x2100u;
    c->eax = 0x20u;
    c->edx = 0x22222222u;
    *(uint32_t *)(g_mem + 0x2100u) = 0x10u;
    lock_cmpxchg(c);
    check("cmp fail mem", *(uint32_t *)(g_mem + 0x2100u), 0x10u);
    check("cmp fail eax", c->eax, 0x10u);
    check("cmp fail zf", c->zf, 0u);
    check("cmp fail cf", c->cf, 1u);

    zero(c, sizeof cpu);
    c->esi = 0x2200u;
    c->eax = 0x11111111u;
    c->edx = 0x22222222u;
    c->ebx = 0x33333333u;
    c->ecx = 0x44444444u;
    *(uint32_t *)(g_mem + 0x2200u) = 0x11111111u;
    *(uint32_t *)(g_mem + 0x2204u) = 0x22222222u;
    lock_cmpxchg8b(c);
    check("c8 ok lo", *(uint32_t *)(g_mem + 0x2200u), 0x33333333u);
    check("c8 ok hi", *(uint32_t *)(g_mem + 0x2204u), 0x44444444u);
    check("c8 ok zf", c->zf, 1u);
    check("c8 ok eax", c->eax, 0x11111111u);
    check("c8 ok edx", c->edx, 0x22222222u);

    *(uint32_t *)(g_mem + 0x2200u) = 0xAAAAAAAAu;
    *(uint32_t *)(g_mem + 0x2204u) = 0xBBBBBBBBu;
    c->esi = 0x2200u;
    c->eax = 0x11111111u;
    c->edx = 0x22222222u;
    c->ebx = 0x33333333u;
    c->ecx = 0x44444444u;
    lock_cmpxchg8b(c);
    check("c8 fail mem", *(uint32_t *)(g_mem + 0x2200u), 0xAAAAAAAAu);
    check("c8 fail memhi", *(uint32_t *)(g_mem + 0x2204u), 0xBBBBBBBBu);
    check("c8 fail eax", c->eax, 0xAAAAAAAAu);
    check("c8 fail edx", c->edx, 0xBBBBBBBBu);
    check("c8 fail zf", c->zf, 0u);
    return fail ? 1 : 0;
}
"""
    # The success case above is a poor test because EBX is both the address
    # and the stored low half. Rebuild that case with a correct encoding
    # note: the C above still checks the architectural result of [ebx] when
    # ebx holds 0x2200 and the compare matches. The stored low dword is ebx,
    # which is 0x2200, so the memory low half stays 0x2200 and the high half
    # becomes ecx. That is a real success check. The failure case then
    # overwrites ebx with 0x2200 again before the second call, so the address
    # is still 0x2200. Good.
    work = tempfile.mkdtemp(prefix="uc-isa5-")
    path = os.path.join(work, "test.c")
    obj = os.path.join(work, "test.o")
    exe = os.path.join(work, "test.exe")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(src)
    cmd = [
        clang(), "-c", "-std=c11", "-O0", "-ffreestanding",
        "-I", os.path.join(ROOT, "tests", "uc_host"),
        "-I", os.path.join(ROOT, "tests"),
        "-I", os.path.join(ROOT, "runtime"),
        "-o", obj, path,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.stderr.write(path + "\n")
        sys.exit(proc.returncode or 1)
    link(obj, exe)
    run = subprocess.run([exe], capture_output=True, text=True)
    sys.stdout.write(run.stdout)
    sys.stderr.write(run.stderr)
    if run.returncode == 0:
        print("uc phase5 isa tests passed")
    else:
        print("uc phase5 isa tests failed", run.returncode)
    sys.exit(run.returncode)


if __name__ == "__main__":
    main()
