"""Ordinary-code provenance for Undercover global slots.

Reads ordinary PE sections and the high-confidence function map. Protected
sections are not read. The game is not started. Nothing here writes a guessed
value into a global.

The backward slice tracks a short list of address-forming instructions
(mov/lea/add/sub/xor) and stops at a call, an unknown write, or the bound.
It is not a full symbolic executor.
"""
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_code_analyze as uca
import uc_phase7_test as p7
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EAX, X86_REG_ECX, X86_REG_EDX

ROOT = p7.ROOT
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
TEXT_LO = 0x00401000
SLICE_BOUND = 48
CALLER_SAVED = {X86_REG_EAX, X86_REG_ECX, X86_REG_EDX}


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def full_reg(reg):
    """Map a partial GPR to its 32-bit capstone id, or return None."""
    name = {
        19: 19, 20: 20, 21: 21, 22: 22, 23: 23, 24: 24, 25: 25, 26: 26,  # filled below
    }
    return GPR32.get(reg)


# Filled after capstone constants are known. Partial registers kill the parent.
GPR32 = {}
PARENT = {}


def _init_regs():
    from capstone.x86 import (
        X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX,
        X86_REG_ESI, X86_REG_EDI, X86_REG_EBP, X86_REG_ESP,
        X86_REG_AX, X86_REG_BX, X86_REG_CX, X86_REG_DX,
        X86_REG_SI, X86_REG_DI, X86_REG_BP, X86_REG_SP,
        X86_REG_AL, X86_REG_BL, X86_REG_CL, X86_REG_DL,
        X86_REG_AH, X86_REG_BH, X86_REG_CH, X86_REG_DH,
    )
    pairs = [
        (X86_REG_EAX, X86_REG_EAX), (X86_REG_AX, X86_REG_EAX),
        (X86_REG_AL, X86_REG_EAX), (X86_REG_AH, X86_REG_EAX),
        (X86_REG_EBX, X86_REG_EBX), (X86_REG_BX, X86_REG_EBX),
        (X86_REG_BL, X86_REG_EBX), (X86_REG_BH, X86_REG_EBX),
        (X86_REG_ECX, X86_REG_ECX), (X86_REG_CX, X86_REG_ECX),
        (X86_REG_CL, X86_REG_ECX), (X86_REG_CH, X86_REG_ECX),
        (X86_REG_EDX, X86_REG_EDX), (X86_REG_DX, X86_REG_EDX),
        (X86_REG_DL, X86_REG_EDX), (X86_REG_DH, X86_REG_EDX),
        (X86_REG_ESI, X86_REG_ESI), (X86_REG_SI, X86_REG_ESI),
        (X86_REG_EDI, X86_REG_EDI), (X86_REG_DI, X86_REG_EDI),
        (X86_REG_EBP, X86_REG_EBP), (X86_REG_BP, X86_REG_EBP),
        (X86_REG_ESP, X86_REG_ESP), (X86_REG_SP, X86_REG_ESP),
    ]
    for reg, parent in pairs:
        PARENT[reg] = parent
        GPR32[parent] = parent


_init_regs()


def writes_reg(insn, parent):
    for op in insn.operands:
        if op.type == X86_OP_REG and PARENT.get(op.reg) == parent and (op.access & 2):
            return True
    # Capstone sometimes omits the access flag on the destination of mov/lea/add.
    if not insn.operands:
        return False
    op0 = insn.operands[0]
    if op0.type == X86_OP_REG and PARENT.get(op0.reg) == parent and insn.mnemonic in (
            "mov", "lea", "add", "sub", "xor", "or", "and", "imul", "shl", "shr",
            "pop", "inc", "dec", "neg", "not", "xchg", "movzx", "movsx"):
        return True
    return False


def slice_address(insns, index):
    """Return (address, how, confidence) if the memory operand at index is a constant.

    confidence is 'high', 'medium', or None when the address is not a constant.
    """
    insn = insns[index]
    mem = None
    for op in insn.operands:
        if op.type == X86_OP_MEM:
            mem = op.mem
            break
    if mem is None:
        return None
    if mem.base == 0 and mem.index == 0:
        return (mem.disp & 0xFFFFFFFF, "absolute", "high")
    if mem.index and mem.base:
        return None
    reg = PARENT.get(mem.base or mem.index)
    if reg is None:
        return None
    adj = mem.disp
    scale = mem.scale if mem.index else 1
    steps = []
    for j in range(index - 1, max(-1, index - SLICE_BOUND), -1):
        prev = insns[j]
        if prev.mnemonic in ("call", "lcall", "ret", "retn"):
            if reg in CALLER_SAVED or reg == X86_REG_EAX:
                return None
            # A call may preserve ebx/esi/edi/ebp. Keep looking, but drop confidence.
            steps.append("across-call")
            continue
        if not writes_reg(prev, reg):
            continue
        ops = prev.operands
        if prev.mnemonic == "mov" and ops[0].type == X86_OP_REG and len(ops) > 1:
            src = ops[1]
            if src.type == X86_OP_IMM:
                base = src.imm & 0xFFFFFFFF
                addr = (base * scale + adj) & 0xFFFFFFFF
                how = "mov-imm " + ",".join(steps)
                conf = "medium" if steps else "high"
                return (addr, how, conf)
            if src.type == X86_OP_REG and PARENT.get(src.reg):
                reg = PARENT[src.reg]
                steps.append("mov-reg")
                continue
            return None
        if prev.mnemonic == "lea" and len(ops) > 1 and ops[1].type == X86_OP_MEM:
            src = ops[1].mem
            if src.index:
                return None
            adj = (adj + src.disp) & 0xFFFFFFFF
            if src.base == 0:
                addr = (adj * scale) & 0xFFFFFFFF if scale != 1 else (adj & 0xFFFFFFFF)
                # lea reg, [imm]; address uses reg + original adj already folded
                how = "lea-abs " + ",".join(steps)
                return (adj & 0xFFFFFFFF, how, "medium" if steps else "high")
            parent = PARENT.get(src.base)
            if not parent:
                return None
            reg = parent
            steps.append("lea")
            continue
        if prev.mnemonic == "add" and len(ops) > 1 and ops[1].type == X86_OP_IMM:
            adj = (adj + (ops[1].imm & 0xFFFFFFFF)) & 0xFFFFFFFF
            steps.append("add")
            continue
        if prev.mnemonic == "sub" and len(ops) > 1 and ops[1].type == X86_OP_IMM:
            adj = (adj - (ops[1].imm & 0xFFFFFFFF)) & 0xFFFFFFFF
            steps.append("sub")
            continue
        if prev.mnemonic == "xor" and len(ops) > 1 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            if PARENT.get(ops[0].reg) == PARENT.get(ops[1].reg) == reg:
                addr = adj & 0xFFFFFFFF
                return (addr, "xor-zero " + ",".join(steps), "medium")
        return None
    return None


def decode_window(blob, base, va, size):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    start = va - base
    if start < 0 or start >= len(blob):
        return []
    size = min(size, len(blob) - start)
    out = []
    for insn in md.disasm(blob[start:start + size], va):
        out.append(insn)
        if insn.address + insn.size > va + size:
            break
    return out


def classify_encoding(blob, base, disp_off, target):
    """Classify a little-endian immediate of `target` inside .text bytes."""
    if disp_off < 0 or disp_off + 4 > len(blob):
        return None
    va = base + disp_off
    b = blob
    def at(n):
        return b[disp_off + n] if 0 <= disp_off + n < len(b) else None
    prev = at(-1)
    prev2 = at(-2)
    if prev2 == 0xFF and prev == 0x15:
        return ("INDIRECT_CALL", va - 2, "call dword ptr [0x%08X]" % target, "high")
    if prev2 == 0xFF and prev == 0x25:
        return ("INDIRECT_JUMP", va - 2, "jmp dword ptr [0x%08X]" % target, "high")
    if prev2 == 0xC7 and prev == 0x05:
        imm = u32(b, disp_off + 4) if disp_off + 8 <= len(b) else None
        return ("WRITE", va - 2, "mov dword ptr [0x%08X], 0x%08X" % (target, imm or 0), "high")
    if prev2 == 0xC6 and prev == 0x05:
        imm = at(4)
        return ("WRITE", va - 2, "mov byte ptr [0x%08X], 0x%02X" % (target, imm or 0), "high")
    if prev == 0xA3:
        return ("WRITE", va - 1, "mov dword ptr [0x%08X], eax" % target, "high")
    if prev == 0xA1:
        return ("READ", va - 1, "mov eax, dword ptr [0x%08X]" % target, "high")
    if prev == 0xA2:
        return ("WRITE", va - 1, "mov byte ptr [0x%08X], al" % target, "high")
    if prev == 0xA0:
        return ("READ", va - 1, "mov al, byte ptr [0x%08X]" % target, "high")
    mov_rm = {
        0x05: "eax", 0x0D: "ecx", 0x15: "edx", 0x1D: "ebx",
        0x25: "esp", 0x2D: "ebp", 0x35: "esi", 0x3D: "edi",
    }
    if prev2 == 0x89 and prev in mov_rm:
        return ("WRITE", va - 2, "mov dword ptr [0x%08X], %s" % (target, mov_rm[prev]), "high")
    if prev2 == 0x8B and prev in mov_rm:
        return ("READ", va - 2, "mov %s, dword ptr [0x%08X]" % (mov_rm[prev], target), "high")
    if prev2 == 0x88 and prev in mov_rm:
        return ("WRITE", va - 2, "mov byte ptr [0x%08X], %s" % (target, mov_rm[prev][1:]), "medium")
    if prev2 == 0x8A and prev in mov_rm:
        return ("READ", va - 2, "mov %s, byte ptr [0x%08X]" % (mov_rm[prev][1:], target), "medium")
    if prev2 in (0x01, 0x03, 0x09, 0x0B, 0x21, 0x23, 0x29, 0x2B, 0x31, 0x33) and prev in mov_rm:
        kind = "WRITE" if prev2 in (0x01, 0x09, 0x21, 0x29, 0x31) else "READ"
        return (kind, va - 2, "alu 0x%02X modrm 0x%02X [0x%08X]" % (prev2, prev, target), "medium")
    if prev2 in (0x80, 0x81, 0x83) and prev == 0x05:
        return ("WRITE", va - 2, "alu-imm dword ptr [0x%08X]" % target, "medium")
    if prev2 == 0xC7 and prev == 0x00:
        return None
    # Immediate used as an address constant, not a memory operand.
    if prev is not None and 0xB8 <= prev <= 0xBF:
        reg = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")[prev - 0xB8]
        return ("ADDRESS_TAKEN", va - 1, "mov %s, 0x%08X" % (reg, target), "high")
    if prev == 0x68:
        return ("ADDRESS_TAKEN", va - 1, "push 0x%08X" % target, "high")
    return ("UNKNOWN", va, "immediate 0x%08X inside an unclassified encoding" % target, "low")


def iter_immediates(blob, base, target):
    pat = struct.pack("<I", target)
    start = 0
    while True:
        i = blob.find(pat, start)
        if i < 0:
            return
        yield i
        start = i + 1


def load_functions(path):
    fm = json.load(open(os.path.join(ROOT, "analysis", "undercover", "function-map.json"), encoding="utf-8"))
    abi = json.load(open(os.path.join(ROOT, "analysis", "undercover", "import-abi.json"), encoding="utf-8"))
    thunks = {int(row["thunk"], 16) for row in abi["imports"]}
    info = uca.read_inputs(path)
    image = p7.read_sections(path)
    highs = []
    for row in fm["functions"]:
        va = int(row["va"], 16)
        if row["label"] != "HIGH_CONFIDENCE" or not row["reachable"] or va in thunks:
            continue
        highs.append((va, row))
    highs.sort()
    return info, image, highs, thunks


def function_bytes(info, highs, index):
    va, row = highs[index]
    base = info["text_va"]
    nxt = highs[index + 1][0] if index + 1 < len(highs) else base + len(info["bytes"])
    size = min(nxt - va, max(row["insns"], 1) * 16)
    return va, size


def scan_code(info, highs, target, store_lo, store_hi):
    """One pass: encodings of `target`, alias stores of it, and constant stores."""
    import bisect
    blob = info["bytes"]
    base = info["text_va"]
    text_hi = base + len(blob)
    vas = [va for va, _row in highs]
    refs = []
    seen = set()
    for off in iter_immediates(blob, base, target):
        classified = classify_encoding(blob, base, off, target)
        if not classified:
            continue
        kind, insn_va, text, conf = classified
        if insn_va in seen:
            continue
        seen.add(insn_va)
        owner_i = bisect.bisect_right(vas, insn_va) - 1
        owner = vas[owner_i] if owner_i >= 0 else 0
        refs.append({
            "function": owner,
            "eip": insn_va,
            "kind": kind,
            "text": text,
            "confidence": conf,
        })
    stores = []
    ptr_stores = []
    for index, (va, _row) in enumerate(highs):
        _va, size = function_bytes(info, highs, index)
        insns = decode_window(blob, base, va, size)
        for n, insn in enumerate(insns):
            mem = next((op for op in insn.operands if op.type == X86_OP_MEM), None)
            if not mem or (mem.access & 2) == 0:
                continue
            got = slice_address(insns, n)
            if not got:
                continue
            addr, how, conf = got
            if addr == target and insn.address not in seen and how != "absolute":
                refs.append({
                    "function": va,
                    "eip": insn.address,
                    "kind": "POTENTIAL_ALIAS",
                    "text": "%s %s ; slice %s => 0x%08X" % (insn.mnemonic, insn.op_str, how, addr),
                    "confidence": conf,
                })
                seen.add(insn.address)
            if not (store_lo <= addr < store_hi):
                continue
            stored = None
            for op in insn.operands:
                if op.type == X86_OP_IMM:
                    stored = op.imm & 0xFFFFFFFF
            row = {
                "function": va,
                "eip": insn.address,
                "addr": addr,
                "how": how,
                "confidence": conf,
                "insn": "%s %s" % (insn.mnemonic, insn.op_str),
                "imm": stored,
            }
            stores.append(row)
            if stored is not None and TEXT_LO <= stored < text_hi:
                ptr_stores.append(row)
        if index and index % 1000 == 0:
            print("  scan", index, file=sys.stderr)
    refs.sort(key=lambda item: item["eip"])
    return refs, stores, ptr_stores


def pointer_runs(buf, va, text_lo, text_hi, min_run=4):
    runs = []
    run_start = None
    run_n = 0
    n = len(buf) // 4
    for i in range(n):
        val = u32(buf, i * 4)
        ok = text_lo <= val < text_hi
        if ok:
            if run_start is None:
                run_start = i
                run_n = 1
            else:
                run_n += 1
        else:
            if run_n >= min_run:
                runs.append((va + run_start * 4, run_n))
            run_start = None
            run_n = 0
    if run_n >= min_run:
        runs.append((va + run_start * 4, run_n))
    return runs


def changed_ranges(before, after):
    """Compact dword changes. `before` and `after` are address -> dword."""
    out = []
    for addr in sorted(set(before) | set(after)):
        old = before.get(addr, 0)
        new = after.get(addr, 0)
        if old == new:
            continue
        out.append({
            "addr": addr,
            "size": 4,
            "old": old,
            "new": new,
            "points_into_text": TEXT_LO <= new < TEXT_LO + 0x01000000,
        })
    return out


def relative_callers(blob, base, target):
    """Direct E8 sites whose displacement lands on `target`."""
    hits = []
    for off in range(len(blob) - 5):
        if blob[off] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        if (base + off + 5 + rel) & 0xFFFFFFFF == target:
            hits.append(base + off)
    return hits


def section_named(image, name):
    for sec in image["sections"]:
        if sec["name"] == name:
            return sec
    return None


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    target = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x0189D1A4
    info, image, highs, _thunks = load_functions(game)
    print("high", len(highs), "target", hex(target), file=sys.stderr)
    data = section_named(image, ".data")
    rdata = section_named(image, ".rdata")
    bss = data["va"] + min(data["vsize"], data["raw_size"])
    data_end = data["va"] + data["vsize"]
    text_hi = info["text_va"] + len(info["bytes"])
    print("bss", hex(bss), hex(data_end), file=sys.stderr)
    refs, stores, ptr_stores = scan_code(info, highs, target, bss, data_end)
    print("refs", len(refs), "bss stores", len(stores), "text-pointer stores", len(ptr_stores), file=sys.stderr)
    tables = []
    if rdata and rdata["raw"]:
        tables.extend(pointer_runs(rdata["raw"], rdata["va"], TEXT_LO, text_hi))
    if data and data["raw"]:
        tables.extend(pointer_runs(data["raw"], data["va"], TEXT_LO, text_hi))
    tables.sort(key=lambda item: -item[1])
    print("pointer tables", len(tables), "largest", tables[:5], file=sys.stderr)
    out_dir = os.path.join(ROOT, "analysis", "undercover")
    summary = {
        "target": "0x%08X" % target,
        "refs": [{k: (hex(v) if isinstance(v, int) else v) for k, v in row.items()} for row in refs],
        "bss_store_count": len(stores),
        "text_pointer_store_count": len(ptr_stores),
        "pointer_tables": [{"va": "0x%08X" % va, "count": n} for va, n in tables[:40]],
    }
    with open(os.path.join(out_dir, "init-provenance.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    # Keep the heavy store list beside it, not inside the small summary the report quotes.
    with open(os.path.join(out_dir, "init-stores.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "stores": [{k: (hex(v) if isinstance(v, int) else v) for k, v in row.items()} for row in stores],
            "pointer_stores": [{k: (hex(v) if isinstance(v, int) else v) for k, v in row.items()} for row in ptr_stores],
        }, fh)
    print("wrote provenance", len(refs), "refs")


if __name__ == "__main__":
    main()
