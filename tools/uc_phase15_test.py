"""Phase 15 checks for the graphics-frontier provenance facts.

Ordinary .text and allowed sections only. Does not execute graphics code,
fill 0x01311E1C, or implement Direct3DCreate9.
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uc_code_analyze as uca
import uc_initprov as ip
import uc_phase7_test as p7

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def expect(cond, text):
    if not cond:
        sys.exit(text)


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    info = uca.read_inputs(game)
    image = p7.read_sections(game)
    blob, base = info["bytes"], info["text_va"]

    flag = 0x01311E1C
    # Image value is zero (virtual tail or file zero).
    data = next(sec for sec in image["sections"] if sec["name"] == ".data")
    off = flag - data["va"]
    if off + 4 <= len(data["raw"]):
        expect(struct.unpack_from("<I", data["raw"], off)[0] == 0, "flag image value")
    else:
        expect(True, "flag in virtual tail")

    refs = [ip.classify_encoding(blob, base, o, flag) for o in ip.iter_immediates(blob, base, flag)]
    refs = [r for r in refs if r]
    kinds = {}
    for kind, _eip, _text, _conf in refs:
        kinds[kind] = kinds.get(kind, 0) + 1
    expect(kinds.get("READ") == 4, "flag reads")
    expect(kinds.get("ADDRESS_TAKEN") == 3, "flag address-taken")
    expect(kinds.get("WRITE", 0) == 0, "no absolute mov write")

    # Definite xchg writers: eax=1 at 0x00722D66.., eax=2 at 0x0072996D.., eax=0 at 0x00B4F990.
    expect(blob[0x00722D66 - base:0x00722D66 - base + 10] == bytes.fromhex("b801000000b91c1e3101"), "set1")
    expect(blob[0x00722D70 - base] == 0x87, "xchg1")
    expect(blob[0x0072996D - base:0x0072996D - base + 10] == bytes.fromhex("b802000000b91c1e3101"), "set2")
    expect(blob[0x00B4F990 - base:0x00B4F990 - base + 8] == bytes.fromhex("33c0b91c1e310187"), "clear0")

    # Value-1 writer has no relative call site.
    sites = 0
    for i in range(len(blob) - 5):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        if (base + i + 5 + rel) & 0xFFFFFFFF == 0x00722D60:
            sites += 1
    expect(sites == 0, "no E8 to flag=1 writer")

    # Wait helper shape.
    expect(blob[0x009773B0 - base:0x009773B0 - base + 4] == bytes.fromhex("8b442404"), "wait head")
    # call [0x00B61188] at 0x009773B9: FF 15 88 11 B6 00
    expect(blob[0x009773B9 - base:0x009773B9 - base + 6] == bytes.fromhex("ff158811b600"), "wait indirect")

    # Direct3DCreate9 site.
    rel = struct.unpack_from("<i", blob, 0x0072E3B9 + 1 - base)[0]
    expect((0x0072E3B9 + 5 + rel) & 0xFFFFFFFF == 0x0087A79C, "d3d thunk")
    expect(blob[0x0072E3B7 - base] == 0x6A and blob[0x0072E3B8 - base] == 0x20, "push 0x20")

    # ESI slot mid-instruction: previous byte is 0x74 (je).
    rdata = next(sec for sec in image["sections"] if sec["name"] == ".rdata")
    slot = struct.unpack_from("<I", rdata["raw"], 0x00B615C4 - rdata["va"])[0]
    expect(slot == 0x008AA3AE, "esi slot value")
    expect(blob[slot - 1 - base] == 0x74, "slot points into je")

    # CEA3F0 is zero.
    cea = next(sec for sec in image["sections"] if sec["name"] == ".data")
    expect(struct.unpack_from("<I", cea["raw"], 0x00CEA3F0 - cea["va"])[0] == 0, "cea3f0 zero")

    # Object address immediate in outer caller.
    expect(blob[0x00766763 - base:0x00766763 - base + 5] == bytes.fromhex("b970813101"), "object imm")

    # Discovery cap still present (document, do not change here).
    text = open(os.path.join(ROOT, "tools", "uc_funcmap.py"), encoding="utf-8").read()
    expect("for _ in range(24):" in text, "24-insn fact walk still present")

    # No helper call in the create span.
    lo, hi = 0x0072E340 - base, 0x0072E5C0 - base
    for i in range(lo, hi - 5):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        dest = (base + i + 5 + rel) & 0xFFFFFFFF
        expect(dest != 0x00686000, "helper in create span")

    status_path = os.path.join(ANALYSIS, "project-status.json")
    if os.path.isfile(status_path):
        status = json.load(open(status_path, encoding="utf-8"))
        gfx = status.get("graphics") or {}
        expect(gfx.get("independent_of_0x00686000") == "YES", "status independence")
        expect(gfx.get("enterable_now") in ("NO", "UNKNOWN"), "status not falsely enterable")

    print("phase 15 ok")


if __name__ == "__main__":
    main()
