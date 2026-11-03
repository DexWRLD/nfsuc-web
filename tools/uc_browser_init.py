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
typedef int int32_t;
typedef signed char int8_t;
typedef struct { u32 esp, eip, eax, ebp, ecx, edx, esi, edi; } CPU;
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
static int equal, less, below;
static u32 queue_memory[64], queue_active, queue_boundary, queue_numeric;
static const unsigned char *frontend_data(u32 a, u32 size);
static u32 read_base, read_delta;
static u32 apt_mode, apt_headers[19], apt_cell, apt_calls;
static const u32 apt_offsets[] = {0, 12, 24, 36, 48, 64};
static u32 *access(u32 a) {
    if (!(a & 3u)) {
        if (queue_active && a >= 0x0300ed00u && a < 0x0300ee00u) return &queue_memory[(a-0x0300ed00u)/4u];
        if (a >= 0x0300ef00u && a < 0x0300f000u) return &stack[(a-0x0300ef00u)/4u];
        if (apt_mode && a >= 0x0189d0a0u && a < 0x0189d0ecu) return &apt_headers[(a-0x0189d0a0u)/4u];
        if (apt_mode == 2 && a == 0x0300ee00u) return &apt_cell;
        if (a >= 0x0189d0a0u && a <= 0x0189d0a8u) return &zero_fields[(a-0x0189d0a0u)/4u];
        if (a == 0x0189da84u) return &zero_core;
        if (a == 0x0189d1a4u) return mapped(a);
    }
    fault = a;
    __builtin_trap();
}
static u32 frontend_word(u32 a) {
    const unsigned char *data = frontend_data(a, 4);
    if (data) return data[0] | ((u32)data[1]<<8) | ((u32)data[2]<<16) | ((u32)data[3]<<24);
    return *access(a);
}
static unsigned char frontend_byte(u32 a) {
    const unsigned char *data = frontend_data(a, 1);
    if (!data) __builtin_trap();
    return *data;
}
static u32 *indexed_read(u32 base, u32 delta) {
    read_base = base;
    read_delta = delta;
    return access(base + delta * 4u - 4u);
}
static void push(CPU *c, u32 value) { c->esp -= 4; *access(c->esp) = value; }
static u32 prefix_pop(CPU *c) { u32 value = *access(c->esp); c->esp += 4; return value; }
#undef MR32
#undef POP32
#define MR32(a) (*access(a))
#define PUSH32(v) push(c, (v))
#define POP32(v) ((v) = prefix_pop(c))
#define FLAGS_SUB_M(a,b,r,n,m) do { if (m) { equal = !(r); less = (int)(a) < (int)(b); below = (a) < (b); } } while (0)
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
u32 prefix_read_base(void) { return read_base; }
u32 prefix_read_delta(void) { return read_delta; }
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
        if addr == 0x009E4B10:
            operand = "MR32(c->edx+c->eax*4+0xfffffffcu)"
            if body.count(operand) != 2:
                raise ValueError("Unexpected indexed read")
            body = body.replace(operand, "(*indexed_read(c->edx, c->eax))")
        if addr == 0x0099DCD0:
            cut = "    MR32(c->ebp+0xfffffffcu) = (c->eax);"
            if body.count(cut) != 1:
                raise ValueError("Unexpected startup continuation")
            body = body.split(cut)[0] + "    __builtin_trap();\nL_0099de20: __builtin_trap();\n}"
        bodies.append(body)
    return "\n".join(bodies)

APT_EXPORTS = r"""
static void apt_frame(u32 argument, u32 has_argument) {
    cpu = (CPU){.esp=0x0300effcu - 4u * has_argument, .ecx=0x0189d0a0u};
    *access(cpu.esp) = 0x00dec0deu;
    if (has_argument) *access(cpu.esp+4) = argument;
}
u32 run_apt_constructor(void) {
    if (apt_mode) __builtin_trap();
    apt_mode = 1;
    for (u32 i=0; i<19; i++) apt_headers[i] = 0xaaaaaaaa;
    apt_frame(0,0);
    sub_009e7540(&cpu);
    if (apt_calls != 6 || apt_headers[15] != 0xaaaaaaaa) __builtin_trap();
    for (u32 i=0; i<6; i++) {
        u32 j = apt_offsets[i]/4;
        if (apt_headers[j] || apt_headers[j+1] || apt_headers[j+2]) __builtin_trap();
    }
    return apt_calls;
}
u32 run_apt_fixture(void) {
    if (apt_mode || entered) __builtin_trap();
    apt_mode = 2;
    apt_headers[1] = 1;
    apt_headers[2] = 0x0300ee00u;
    apt_frame(0x0300ee04u,1);
    sub_009e47d0(&cpu);
    if (cpu.eip != 0x00dec0deu || cpu.esp != 0x0300f000u ||
        apt_headers[0] != 1 || apt_cell != 0x0300ee04u) __builtin_trap();
    apt_frame(0,1);
    sub_009b6290(&cpu);
    if (cpu.eip != 0x00dec0deu || cpu.esp != 0x0300f000u ||
        cpu.eax != apt_cell || read_base != 0x0300ee00u || read_delta != 1)
        __builtin_trap();
    return cpu.eax;
}
"""

def build_apt(lifter):
    leaf, leaf_calls = lifter.lift(0x009E75A0)
    ctor, ctor_calls = lifter.lift(0x009E7540)
    push, push_calls = lifter.lift(0x009E47D0)
    cut = "    PUSH32(0x9e7591u); sub_009c1830(c);"
    if (leaf_calls or push_calls or ctor_calls != {0x009E75A0, 0x009C1830}
            or ctor.count(cut) != 1 or ctor.count("sub_009e75a0(c);") != 6):
        raise ValueError("Unexpected Apt lifecycle instruction shape")
    leaf = leaf.replace("    goto L_009e75a0;", "    apt_calls++;\n    goto L_009e75a0;")
    return "\n".join((leaf, ctor.split(cut)[0] + "}", push, APT_EXPORTS))

def build_frontend(lifter, image):
    sections = p7.read_sections(str(image))["sections"]

    def read(va, length):
        for section in sections:
            raw = section["raw"]
            offset = va - section["va"]
            if section["name"] in (".data", ".rdata") and raw and 0 <= offset <= len(raw) - length:
                return raw[offset:offset + length]
        raise ValueError(f"Unmapped frontend static data at {va:#x}")

    cell = 0x0129D858
    name = int.from_bytes(read(cell, 4), "little")
    if read(name, 14) != b"localToGlobal\0" or int.from_bytes(read(cell + 4, 4), "little") != 0x7F:
        raise ValueError("Unexpected original method entry")
    if read(0x0127D304, 4) != (0x00BBAAC8).to_bytes(4, "little") or read(0x00BBAAC8, 28) != b"_level0._root.gblPushScreen\0":
        raise ValueError("Unexpected frontend method pointer")
    spans = [(cell, 8), (name, 14)]
    spans.extend((0x01295F90 + 4 * byte, 4) for byte in sorted(set(b"localToGlobal")))
    arrays = []
    ranges = []
    for index, (address, size) in enumerate(spans):
        arrays.append(f"static const unsigned char span{index}[] = {{{','.join(map(str, read(address, size)))}}};")
        ranges.append(f"if (a >= {address}u && a <= {address + size}u && size <= {address + size}u - a) return span{index} + (a - {address}u);")
    data = "\n".join(arrays + ["static const unsigned char *frontend_data(u32 a, u32 size) {", *ranges, "return 0; }"])
    hash_code, hash_calls = lifter.lift(0x009DE390)
    lookup, lookup_calls = lifter.lift(0x009981F0)
    cut = "L_00998241:; /* --- block --- */"
    if hash_calls or lookup_calls != {0x009DE390, 0x00AE52C8} or lookup.count(cut) != 1:
        raise ValueError("Unexpected frontend lookup shape")
    # The comparison thunk is unresolved in this bridge. End the diagnostic at its block.
    tail = "DISPATCH_TAIL(c, MR32(c->eax*4+0x9de414u));"
    if hash_code.count(tail) != 1:
        raise ValueError("Unexpected short-name hash branch")
    hash_code = hash_code.replace(tail, "__builtin_trap();")
    lookup = lookup.split(cut)[0] + r"""
L_00998241:
    lookup_stop = 0x00998241u;
    return;
""" + lookup[lookup.index("L_00998267:;"):lookup.index("L_00998269:;")] + "}"
    for address in ("c->edx*4+0x1295f90u", "c->edx*8+0x129d4a8u"):
        hash_code = hash_code.replace(f"MR32({address})", f"frontend_word({address})")
        lookup = lookup.replace(f"MR32({address})", f"frontend_word({address})")
    return "\n".join((data, "static u32 lookup_stop;", "#define MR8(a) frontend_byte(a)",
        "#define CC_A (!below && !equal)\n#define CC_B below", hash_code, lookup, f"""
u32 frontend_lookup(u32 length) {{
    if (length != 13 && length != 1 && length != 21) __builtin_trap();
    lookup_stop = 0;
    cpu = (CPU){{.esp=0x0300eff4u}};
    *access(cpu.esp) = 0x00dec0deu;
    *access(cpu.esp+4) = {name}u;
    *access(cpu.esp+8) = length;
    sub_009981f0(&cpu);
    if (lookup_stop) {{
        if (cpu.esp != 0x0300efe8u || cpu.eip != 0x0099820fu) __builtin_trap();
        return *access(cpu.ebp-4);
    }}
    if (cpu.eax || cpu.eip != 0x00dec0deu || cpu.esp != 0x0300eff8u) __builtin_trap();
    return 0;
}}
u32 frontend_stop(void) {{ return lookup_stop; }}
u32 frontend_native_id(void) {{ return lookup_stop ? frontend_word({cell + 4}u) : 0; }}
"""))

def build_queue(lifter):
    append, append_calls = lifter.lift(0x0080F4F0)
    scan, scan_calls = lifter.lift(0x008091E0)
    growth = "PUSH32(0x80f518u); sub_005d6b20(c);"
    producer = "PUSH32(0x809205u); sub_0055feb0(c);"
    if (append_calls != {0x005D6B20} or scan_calls != {0x0055FEB0, 0x00804550}
            or append.count(growth) != 1 or scan.count(producer) != 1):
        raise ValueError("Unexpected frontend queue instruction shape")
    append = append.replace(growth, "queue_boundary = 0x005d6b20u; __builtin_trap();")
    start, suffix = scan.split(producer)
    resume = "L_00809217:;"
    if suffix.count(resume) != 1:
        raise ValueError("Unexpected frontend queue loop continuation")
    scan = start + "queue_numeric = c->eax; queue_boundary = 0x0055feb0u; __builtin_trap();\n" + suffix[suffix.index(resume):]
    return "\n".join((r"""
#undef MR8
#define MR8(a) ((unsigned char)*access(a))
#define CC_AE (!below)
""", append, scan, QUEUE_EXPORTS))


QUEUE_EXPORTS = r"""
#define QBASE 0x0300ed00u
#define QCELL 0x0300ed40u
#define QARRAY 0x0300ed48u
#define QENTRY 0x0300ed60u
#define QOBJECT 0x0300ed80u
u32 queue_word(u32 address) {
    if (!queue_active || address < QBASE || address >= 0x0300ee00u) __builtin_trap();
    return *access(address);
}
u32 queue_stop(void) { return queue_boundary; }
u32 queue_value(void) { return queue_numeric; }
u32 run_queue(u32 mode) {
    if (queue_active || mode > 8) __builtin_trap();
    queue_active = 1;
    *access(QBASE+0x10) = QARRAY;
    *access(QBASE+0x14) = QARRAY + ((mode == 0 || mode == 4) ? 0 : 4);
    *access(QBASE+0x18) = QARRAY + (mode == 2 ? 4 : 8);
    *access(QBASE+0x24) = mode == 3;
    *access(QCELL) = QENTRY;
    *access(QARRAY-4) = 0x11223344u;
    *access(QARRAY) = mode == 7 ? 0 : (mode == 8 ? 0xdead0000u : QENTRY);
    *access(QARRAY+4) = 0xaabbccddu;
    *access(QARRAY+8) = 0x55667788u;
    *access(QENTRY) = QOBJECT;
    *access(QENTRY+4) = mode == 5 ? 2 : 1;
    *access(QENTRY+0xc) = 7;
    *access(QOBJECT+0x58) = 900;
    cpu = (CPU){.esp=mode < 3 ? 0x0300eff8u : 0x0300effcu,
                .ecx=QBASE+(mode < 3 ? 0x10u : 0u),
                .esi=0x1234u, .edi=0x5678u};
    *access(cpu.esp) = 0x00dec0deu;
    if (mode < 3) {
        *access(cpu.esp+4) = QCELL;
        if (mode == 0) *access(QARRAY) = 0xaabbccddu;
        sub_0080f4f0(&cpu);
    } else {
        sub_008091e0(&cpu);
    }
    if (cpu.esp != 0x0300f000u || cpu.eip != 0x00dec0deu ||
        cpu.esi != 0x1234u || cpu.edi != 0x5678u) __builtin_trap();
    return cpu.eip;
}
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
    exports = ["run_init", "read_slot", "write_count", "guest_esp", "guest_eax", "run_prefix", "prefix_fault", "prefix_entry", "prefix_read_base", "prefix_read_delta", "run_apt_constructor", "run_apt_fixture", "frontend_lookup", "frontend_stop", "frontend_native_id", "run_queue", "queue_word", "queue_stop", "queue_value"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "init.c"
        source.write_text(BRIDGE + body + EXPORTS + PREFIX_BRIDGE + build_prefix(lifter) + PREFIX_EXPORTS + build_apt(lifter) + build_frontend(lifter, args.image) + build_queue(lifter), encoding="utf-8")
        subprocess.run([clang, "--target=wasm32-unknown-unknown", *linker_arg, "-O2",
                        "-ffreestanding", "-nostdlib", "-Wl,--no-entry",
                        *["-Wl,--export=" + name for name in exports],
                        str(source), "-o", str(args.output)], check=True)
    print(f"Built {args.output} from {SOURCE_SHA}, entry {ENTRY:#010x}")


if __name__ == "__main__":
    main()
