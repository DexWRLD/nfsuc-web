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
typedef struct { u32 esp, eip, eax; } CPU;
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
    body, calls = lift.RawLifter(info["bytes"], info["text_va"], comments=False).lift(ENTRY)
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
    exports = ["run_init", "read_slot", "write_count", "guest_esp", "guest_eax"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "init.c"
        source.write_text(BRIDGE + body + EXPORTS, encoding="utf-8")
        subprocess.run([clang, "--target=wasm32-unknown-unknown", *linker_arg, "-O2",
                        "-ffreestanding", "-nostdlib", "-Wl,--no-entry",
                        *["-Wl,--export=" + name for name in exports],
                        str(source), "-o", str(args.output)], check=True)
    print(f"Built {args.output} from {SOURCE_SHA}, entry {ENTRY:#010x}")


if __name__ == "__main__":
    main()
