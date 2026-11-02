#!/usr/bin/env python3
"""Regression tests for the Undercover lifter gaps.

F3 C3 (Capstone: repz ret) must return like C3. MOVMSKPS must copy the four
lane sign bits into the low four bits of a register. The bits are checked as
integers, including +0 and -0.
"""
import os, shutil, struct, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift

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
    """This clang has no MSVC link.exe. lld's link flavor is enough for a freestanding main."""
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


def lift_bytes(blob):
    lifter = lift.RawLifter(blob, base=BASE, comments=False)
    code, _calls = lifter.lift(BASE)
    blocks, _calls = lifter.discover(BASE)
    insns = [insn for block in blocks.values() for insn in block]
    return code, insns


def ret_body(opcode):
    # mov eax, 1; <ret>; mov eax, 2; ret
    # A real return leaves eax at 1. Falling through the prefixed ret sets 2.
    return bytes([0xB8, 0x01, 0x00, 0x00, 0x00]) + opcode + bytes([0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3])


def mask_body():
    # movmskps eax, xmm0
    return bytes([0x0F, 0x50, 0xC0, 0xC3])


def lanes(words):
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)


CASES = [
    ("all positive", (0x3F800000, 0x3F800000, 0x3F800000, 0x3F800000), 0),
    ("all negative", (0xBF800000, 0xBF800000, 0xBF800000, 0xBF800000), 0xF),
    ("alternating - + - +", (0xBF800000, 0x3F800000, 0xBF800000, 0x3F800000), 0x5),
    ("+0 +0 +0 +0", (0x00000000, 0x00000000, 0x00000000, 0x00000000), 0),
    ("-0 -0 -0 -0", (0x80000000, 0x80000000, 0x80000000, 0x80000000), 0xF),
    ("only lane 0", (0x80000000, 0x00000001, 0x3F800000, 0x7FFFFFFF), 0x1),
    ("only lane 1", (0x00000000, 0x80000000, 0x00000000, 0x3F800000), 0x2),
    ("only lane 2", (0x3F800000, 0x00000000, 0x80000001, 0x00000000), 0x4),
    ("only lane 3", (0x7FFFFFFF, 0x3F800000, 0x00000000, 0x80000000), 0x8),
]


def main():
    plain, plain_ins = lift_bytes(ret_body(b"\xC3"))
    prefixed, pref_ins = lift_bytes(ret_body(b"\xF3\xC3"))
    if not any(i.mnemonic == "ret" for i in plain_ins):
        sys.exit("C3 was not decoded as ret")
    if not any(i.mnemonic == "repz ret" for i in pref_ins):
        sys.exit("F3 C3 was not decoded as repz ret: " + ", ".join(i.mnemonic for i in pref_ins))
    if any(i.mnemonic == "mov" and i.op_str.startswith("eax, 2") for i in pref_ins):
        sys.exit("repz ret did not end the function; the lifter followed past it")
    if "POP32(c->eip);" not in plain or "POP32(c->eip);" not in prefixed:
        sys.exit("a return form was not lowered to POP32")
    mask_code, mask_ins = lift_bytes(mask_body())
    if not any(i.mnemonic == "movmskps" for i in mask_ins):
        sys.exit("movmskps was not decoded")
    if "u32[0]>>31" not in mask_code:
        sys.exit("movmskps was not lowered from the integer lane bits")

    lane_rows = ",\n".join(
        "        {" + ", ".join(f"0x{w:08x}u" for w in words) + "}"
        for _name, words, _want in CASES
    )
    wants = ", ".join(f"0x{want:x}u" for _name, _words, want in CASES)
    names = ", ".join(f'"{name}"' for name, _words, _want in CASES)
    plain_fn = plain
    pref_fn = prefixed.replace(f"sub_{BASE:08x}", "sub_rep")
    mask_fn = mask_code.replace(f"sub_{BASE:08x}", "sub_mask")
    src = f"""#include "uc_harness.h"
static uint8_t image[0x200000];
uint8_t *g_mem = image;
void unsupported_insn(CPU *c, uint32_t a, const char *w) {{ (void)c; (void)a; (void)w; }}
void cpuid_shim(CPU *c) {{ (void)c; }}
uint64_t rdtsc_shim(void) {{ return 0; }}
{plain_fn}
{pref_fn}
{mask_fn}
static int fail;
static void zero(void *p, unsigned n) {{
    unsigned char *b = p;
    for (unsigned i = 0; i < n; i++) b[i] = 0;
}}
static void check(const char *name, uint32_t got, uint32_t want) {{
    if (got != want) {{
        (void)name; (void)got; (void)want;
        fail++;
    }}
}}
static void call_ret(void (*fn)(CPU *), const char *name) {{
    CPU cpu;
    CPU *c = &cpu;
    zero(c, sizeof cpu);
    c->esp = 0x180000u;
    c->eax = 0xffffffffu;
    PUSH32(0xDEADC0DEu);
    uint32_t esp_after_push = c->esp;
    fn(c);
    check(name, c->eax, 1u);
    check(name, c->eip, 0xDEADC0DEu);
    check(name, c->esp, esp_after_push + 4u);
}}
int main(void) {{
    call_ret(sub_{BASE:08x}, "C3");
    call_ret(sub_rep, "F3 C3");
    static const uint32_t lanes[{len(CASES)}][4] = {{
{lane_rows}
    }};
    static const uint32_t wants[{len(CASES)}] = {{ {wants} }};
    static const char *names[{len(CASES)}] = {{ {names} }};
    for (unsigned i = 0; i < {len(CASES)}; i++) {{
        CPU cpu;
        CPU *c = &cpu;
        zero(c, sizeof cpu);
        c->esp = 0x180000u;
        for (int k = 0; k < 4; k++) c->xmm[0].u32[k] = lanes[i][k];
        c->eax = 0xffffffffu;
        PUSH32(0x11111111u);
        sub_mask(c);
        check(names[i], c->eax, wants[i]);
    }}
    return fail ? 1 : 0;
}}
"""
    work = tempfile.mkdtemp(prefix="uc-isa-")
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
        sys.exit(proc.returncode or 1)
    link(obj, exe)
    run = subprocess.run([exe], capture_output=True, text=True)
    sys.stdout.write(run.stdout)
    sys.stderr.write(run.stderr)
    if run.returncode == 0:
        print("uc isa tests passed")
    sys.exit(run.returncode)


if __name__ == "__main__":
    main()
