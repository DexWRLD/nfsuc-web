"""Build a restricted browser module from the verified Undercover image."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

import lift
import uc_code_analyze as uca
import uc_phase7_test as p7

SOURCE_SHA = "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd"
ENTRY = 0x009E8AD0
BRIDGE = r"""
typedef unsigned u32;
typedef u32 uint32_t;
typedef struct { u32 esp, eip, eax, ebp, ecx, edx; } CPU;
static u32 slots[55];
static u32 writes, stack_word;
static u32 *mapped(u32 address) {
    if (address < 0x0189d198u || address > 0x0189d270u || (address & 3u))
        __builtin_trap();
    return &slots[(address - 0x0189d198u) / 4u];
}
static u32 *store(u32 address) { writes++; return mapped(address); }
static u32 pop(CPU *c) {
    if (c->esp != 0x0300effcu) __builtin_trap();
    c->esp += 4;
    return stack_word;
}
#define MR32(addr) (*store(addr))
#define POP32(dst) ((dst) = pop(c))
"""
PREFIX_BRIDGE = r"""
static u32 stack[64], zero_fields[3], zero_core, fault, trace[8], entered;
static int equal, less;
static u32 *access(u32 a) {
    if (!(a & 3u)) {
        if (a >= 0x0300ef00u && a < 0x0300f000u) return &stack[(a-0x0300ef00u)/4u];
        if (a >= 0x0189d0a0u && a <= 0x0189d0a8u) return &zero_fields[(a-0x0189d0a0u)/4u];
        if (a == 0x0189da84u) return &zero_core;
        if (a == 0x0189d1a4u) return mapped(a);
    }
    fault = a;
    __builtin_trap();
}
static void push(CPU *c, u32 value) { c->esp -= 4; *access(c->esp) = value; }
static u32 prefix_pop(CPU *c) { u32 value = *access(c->esp); c->esp += 4; return value; }
#undef MR32
#undef POP32
#define MR32(a) (*access(a))
#define PUSH32(v) push(c, (v))
#define POP32(v) ((v) = prefix_pop(c))
#define FLAGS_SUB_M(a,b,r,n,m) do { if (m) { equal = !(r); less = (int)(a) < (int)(b); } } while (0)
#define FLAGS_ADD_M(a,b,r,n,m) do { if (m) { equal = !(r); less = (int)(r) < 0; } } while (0)
#define FLAGS_LOG_M(r,n,m) do { equal = !(r); less = (int)(r) < 0; } while (0)
#define CC_E equal
#define CC_NE (!equal)
#define CC_L less
#define CC_G (!equal && !less)
static void sub_009e78c0(CPU *c);
#define DISPATCH_CALL(c,target) do { if ((target) != 0x009e78c0u) __builtin_trap(); sub_009e78c0(c); } while (0)
"""
PREFIX_EXPORTS = r"""
u32 prefix_fault(void) { return fault; }
u32 prefix_entry(u32 i) { return i < entered ? trace[i] : 0; }
u32 run_prefix(void) {
    if (writes != 49 || entered) __builtin_trap();
    cpu = (CPU){.esp=0x0300eff4u};
    *access(0x0300eff4u) = 0x00dec0deu;
    *access(0x0300eff8u) = 0;
    *access(0x0300effcu) = 2;
    sub_0099dcd0(&cpu);
    return cpu.eip;
}
"""

def build_prefix(lifter):
    """Keep the documented path and reject continuation outside this probe."""
    bodies = []
    for addr in (0x009E78C0, 0x009E4B10, 0x009B6290, 0x0099DCD0):
        body, _ = lifter.lift(addr)
        start = f"void sub_{addr:08x}(CPU *restrict c) {{"
        body = body.replace(start, start + f"\n    if (entered >= 8) __builtin_trap(); trace[entered++] = {addr}u;")
        if addr == 0x0099DCD0:
            cut = "    MR32(c->ebp+0xfffffffcu) = (c->eax);"
            if body.count(cut) != 1:
                raise ValueError("Unexpected startup continuation")
            body = body.split(cut)[0] + "    __builtin_trap();\nL_0099de20: __builtin_trap();\n}"
        bodies.append(body)
    return "\n".join(bodies)

EXPORTS = r"""
static CPU cpu;
u32 read_slot(u32 addr) { return *mapped(addr); }
u32 write_count(void) { return writes; }
u32 guest_esp(void) { return cpu.esp; }
u32 guest_eax(void) { return cpu.eax; }
u32 run_init(void) {
    if (writes) __builtin_trap();
    stack_word = 0x00dec0deu;
    cpu = (CPU){0x0300effcu, 0x009e8ad0u, 0};
    sub_009e8ad0(&cpu);
    return cpu.eip;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if hashlib.sha256(args.image.read_bytes()).hexdigest() != SOURCE_SHA:
        parser.error("image SHA-256 does not match Undercover PC 1.1.2.1")
    info = uca.read_inputs(str(args.image))
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    body, calls = lifter.lift(ENTRY)
    operations = [line.strip() for line in body.splitlines() if line.startswith("    ")]
    stores = operations[1:-1]
    if (calls or len(operations) != 51 or operations[0] != "goto L_009e8ad0;"
            or operations[-1] != "POP32(c->eip); return;"
            or not all(re.fullmatch(r"MR32[(]0x[0-9a-f]+u[)] = [(]0x[0-9a-f]+u[)];", op) for op in stores)):
        parser.error("initializer has unsupported guest operations")
    # Link through clang's wasm target with no libc, imports or guest callbacks.
    clang = p7.clang()
    linker = Path(clang).with_name("wasm-ld.exe")
    linker_arg = ["--ld-path=" + str(linker)] if linker.is_file() else []
    exports = ["run_init", "read_slot", "write_count", "guest_esp", "guest_eax", "run_prefix", "prefix_fault", "prefix_entry"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "init.c"
        source.write_text(BRIDGE + body + EXPORTS + PREFIX_BRIDGE + build_prefix(lifter) + PREFIX_EXPORTS, encoding="utf-8")
        subprocess.run([clang, "--target=wasm32-unknown-unknown", *linker_arg, "-O2",
                        "-ffreestanding", "-nostdlib", "-Wl,--no-entry",
                        *["-Wl,--export=" + name for name in exports],
                        str(source), "-o", str(args.output)], check=True)
    print(f"Built {args.output} from {SOURCE_SHA}, entry {ENTRY:#010x}")


if __name__ == "__main__":
    main()
