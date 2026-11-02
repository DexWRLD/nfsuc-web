"""Focused checks for ordinary-address slicing and provenance helpers.

These cases are hand-assembled instruction bytes. They do not read the game.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_initprov as prov

TARGET = 0x0189D1A4


def asm(blob):
    return prov.decode_window(blob, 0x00400000, 0x00400000, len(blob))


def expect_addr(blob, index, address, confidence=None):
    insns = asm(blob)
    got = prov.slice_address(insns, index)
    if got is None or got[0] != address:
        raise SystemExit("slice %s index %d got %s" % (blob.hex(), index, got))
    if confidence and got[2] != confidence:
        raise SystemExit("confidence %s got %s" % (confidence, got))
    return got


def test_mov_imm_store():
    # mov eax, TARGET; mov dword ptr [eax], ebx
    blob = bytes([0xB8]) + struct.pack("<I", TARGET) + bytes([0x89, 0x18])
    expect_addr(blob, 1, TARGET, "high")


def test_add_alias():
    # mov eax, TARGET-0x1A4; add eax, 0x1A4; mov [eax], ebx
    base = (TARGET - 0x1A4) & 0xFFFFFFFF
    blob = bytes([0xB8]) + struct.pack("<I", base) + bytes([0x05]) + struct.pack("<I", 0x1A4) + bytes([0x89, 0x18])
    expect_addr(blob, 2, TARGET)


def test_lea_alias():
    # lea eax, [TARGET]; mov [eax+4], ebx  writes TARGET+4, not TARGET
    blob = bytes([0x8D, 0x05]) + struct.pack("<I", TARGET) + bytes([0x89, 0x58, 0x04])
    got = expect_addr(blob, 1, (TARGET + 4) & 0xFFFFFFFF)
    if got[0] == TARGET:
        raise SystemExit("displacement was ignored")


def test_wrong_address_is_not_target():
    blob = bytes([0xB8]) + struct.pack("<I", TARGET - 4) + bytes([0x89, 0x18])
    got = prov.slice_address(asm(blob), 1)
    if got and got[0] == TARGET:
        raise SystemExit("unrelated address matched the target")


def test_absolute_call_encoding():
    blob = bytes([0x90, 0xFF, 0x15]) + struct.pack("<I", TARGET) + bytes([0x90])
    kind, va, text, conf = prov.classify_encoding(blob, 0x00400000, 3, TARGET)
    if kind != "INDIRECT_CALL" or conf != "high" or va != 0x00400001:
        raise SystemExit((kind, hex(va), text, conf))


def test_absolute_write_encoding():
    blob = bytes([0xC7, 0x05]) + struct.pack("<I", TARGET) + struct.pack("<I", 0x00401000)
    kind, va, text, conf = prov.classify_encoding(blob, 0x00400000, 2, TARGET)
    if kind != "WRITE" or conf != "high":
        raise SystemExit((kind, text, conf))


def test_address_taken_encoding():
    blob = bytes([0xB8]) + struct.pack("<I", TARGET)
    kind, _va, text, conf = prov.classify_encoding(blob, 0x00400000, 1, TARGET)
    if kind != "ADDRESS_TAKEN" or conf != "high":
        raise SystemExit((kind, text, conf))


def test_pointer_runs_and_ranges():
    text = 0x00401000
    buf = struct.pack("<IIIIII", text, text + 0x10, text + 0x20, text + 0x30, 0, text)
    runs = prov.pointer_runs(buf, 0x00B61000, text, text + 0x1000, min_run=4)
    if runs != [(0x00B61000, 4)]:
        raise SystemExit(runs)
    before = {0x0189D000: 0, 0x0189D1A4: 0, 0x00B61000: 1}
    after = {0x0189D000: 0, 0x0189D1A4: text, 0x00B61000: 1}
    changes = prov.changed_ranges(before, after)
    if len(changes) != 1 or changes[0]["addr"] != 0x0189D1A4 or changes[0]["new"] != text:
        raise SystemExit(changes)
    if not changes[0]["points_into_text"]:
        raise SystemExit("text pointer not flagged")


def test_relative_caller():
    target = 0x00401010
    rel = target - (0x00400000 + 5)
    blob = bytes([0xE8]) + struct.pack("<i", rel) + bytes([0x90])
    hits = prov.relative_callers(blob, 0x00400000, target)
    if hits != [0x00400000]:
        raise SystemExit(hits)


def main():
    test_mov_imm_store()
    test_add_alias()
    test_lea_alias()
    test_wrong_address_is_not_target()
    test_absolute_call_encoding()
    test_absolute_write_encoding()
    test_address_taken_encoding()
    test_pointer_runs_and_ranges()
    test_relative_caller()
    print("uc initprov tests passed")


if __name__ == "__main__":
    main()
