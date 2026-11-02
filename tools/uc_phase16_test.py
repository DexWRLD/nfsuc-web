"""Phase 16 CFG-aware function discovery tests.

Uses synthetic blobs and optional game checks. Does not execute nfs.exe,
implement Direct3D, or promote addresses by special case.
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

import lift
import uc_funcmap as fm

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def expect(cond, text):
    if not cond:
        sys.exit(text)


class FakeLifter:
    def __init__(self, base, size):
        self.base = base
        self.size = size

    def in_text(self, va):
        return self.base <= (va & 0xffffffff) < self.base + self.size

    def _jt_bound(self, ins):
        return None

    def _jt_table(self, ins, bound):
        return None


def make_starts(blob, base):
    starts = bytearray(len(blob))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    off = 0
    while off < len(blob):
        found = list(md.disasm(blob[off:off + 16], base + off))
        if not found:
            off += 1
            continue
        insn = found[0]
        starts[insn.address - base] = 1
        off = insn.address + insn.size - base
    return starts


def walk_blob(blob, base=0x1000, entries=None, **budgets):
    starts = make_starts(blob, base)
    lifter = FakeLifter(base, len(blob))
    walker = fm.Walker(blob, base, starts, lifter, **budgets)
    walker.entry_set = set(entries or ())
    return walker.walk(base, set(entries or ()))


def test_linear_over_24():
    # push ecx; many mov eax,imm32; ret  -> >24 instructions, one block
    body = b"\x51" + (b"\xb8\x01\x00\x00\x00" * 40) + b"\xc3"
    facts, owned = walk_blob(body)
    expect(facts["insns"] > 24, "insns>24")
    expect(facts["ends_ret"], "ret")
    expect(facts["termination"] == "RET_REACHED", "term ret")
    expect(not facts["budget_exceeded"], "no budget")
    label, score, _ = fm.classify(facts, False, False)
    expect(label == "HIGH_CONFIDENCE", "high " + label)
    expect(score >= 60, "score")


def test_multiple_blocks_and_jcc():
    # xor eax,eax; test eax,eax; je +5; mov eax,1; ret; mov eax,2; ret
    blob = bytes.fromhex("33c085c07405b801000000c3b802000000c3")
    facts, _ = walk_blob(blob)
    expect(facts["blocks"] >= 2, "blocks")
    expect(facts["insns"] >= 6, "insns")
    expect(facts["ends_ret"], "ret")
    expect(len(facts["returns"]) >= 1, "returns")


def test_loop():
    # xor ecx,ecx; inc ecx; cmp ecx,2; jl -6; ret
    blob = bytes.fromhex("33c94183f9027cfac3")
    facts, _ = walk_blob(blob)
    expect(facts["insns"] >= 4, "loop insns")
    expect(facts["ends_ret"], "loop ret")
    expect(facts["termination"] == "RET_REACHED", "loop term")


def test_multiple_returns():
    # test eax; je L2; ret; L2: ret
    blob = bytes.fromhex("85c07401c3c3")
    facts, _ = walk_blob(blob)
    expect(facts["ends_ret"], "multi ret flag")
    expect(facts["termination"] in ("MULTIPLE_RETURNS", "RET_REACHED"), facts["termination"])


def test_tail_transfer():
    # 0x1000: jmp 0x100B; int3 pad; 0x100B: push ebp; mov ebp,esp; ret
    blob = b"\xE9\x06\x00\x00\x00" + (b"\xCC" * 6) + b"\x55\x8B\xEC\xC3"
    facts, _ = walk_blob(blob, entries={0x100B})
    expect(facts["ends_tail"], "tail")
    expect(0x100B in facts["tails"], "tail target")
    expect(facts["termination"] == "TAIL_TRANSFER", facts["termination"])


def test_known_entry_collision():
    # Linear fall into a second prologue should stop, not absorb.
    # entry: ret-sized nop via mov; then foreign prologue.
    blob = b"\xB8\x01\x00\x00\x00\xC3" + b"\x55\x8B\xEC\xC3"
    facts, owned = walk_blob(blob, entries={0x1006})
    expect(facts["ends_ret"], "first ret")
    expect(max(owned) < 0x1006, "no absorb")


def test_decode_failure():
    blob = b"\xFF\xFF\xFF\xFF"
    starts = bytearray(len(blob))
    starts[0] = 1
    lifter = FakeLifter(0x1000, len(blob))
    walker = fm.Walker(blob, 0x1000, starts, lifter)
    facts, _ = walker.walk(0x1000, set())
    expect(facts["undecodable"] >= 1 or facts["insns"] <= 1, "decode")


def test_data_island_entry_bad():
    # aad as first instruction
    blob = b"\xD5\x0A\xC3"
    facts, _ = walk_blob(blob)
    expect(facts["entry_nonsense"], "aad entry")
    label, _, _ = fm.classify(facts, False, False)
    expect(label == "REJECTED_DATA_LIKE", "reject aad")


def test_cfg_budget():
    body = b"\x51" + (b"\xb8\x01\x00\x00\x00" * 80) + b"\xc3"
    facts, _ = walk_blob(body, insn_budget=10, block_budget=100, byte_span_budget=100000)
    expect(facts["budget_exceeded"] or facts["termination"] == "CFG_BUDGET_EXCEEDED", "budget")
    label, _, reasons = fm.classify(facts, False, False)
    expect(label != "HIGH_CONFIDENCE", "no high on budget")
    expect(any("budget" in r.lower() for r in reasons), "budget reason")


def test_no_range24_in_source():
    text = open(os.path.join(ROOT, "tools", "uc_funcmap.py"), encoding="utf-8").read()
    expect("for _ in range(24):" not in text, "24-insn linear walk removed")
    expect("CFG_BUDGET_EXCEEDED" in text, "budget term present")
    expect("INSN_BUDGET" in text, "insn budget")


def test_graphics_regression_optional():
    if not os.path.isfile(GAME):
        print("skip game graphics regression")
        return
    import uc_code_analyze as uca
    import uc_gen as ucg
    info = uca.read_inputs(GAME)
    blob, base = info["bytes"], info["text_va"]
    starts, _ = fm.mark_starts(blob, base)
    lifter = ucg.make_lifter(blob, base)
    walker = fm.Walker(blob, base, starts, lifter)
    for va, min_insns in ((0x00766730, 100), (0x0072E340, 100)):
        facts, _ = walker.walk(va, set())
        expect(facts["insns"] > 24, hex(va) + " >24")
        expect(facts["insns"] >= min_insns, hex(va) + " coherent")
        expect(facts["ends_ret"], hex(va) + " ret")
        expect(facts["termination"] in ("RET_REACHED", "MULTIPLE_RETURNS"), facts["termination"])
        label, score, _ = fm.classify(facts, False, False)
        expect(label == "HIGH_CONFIDENCE", hex(va) + " " + label)
        expect(score >= 60, hex(va) + " score")


def main():
    test_no_range24_in_source()
    test_linear_over_24()
    test_multiple_blocks_and_jcc()
    test_loop()
    test_multiple_returns()
    test_tail_transfer()
    test_known_entry_collision()
    test_decode_failure()
    test_data_island_entry_bad()
    test_cfg_budget()
    test_graphics_regression_optional()
    print("phase 16 cfg discovery ok")


if __name__ == "__main__":
    main()
