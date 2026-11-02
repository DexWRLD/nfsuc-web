"""Phase 13 checks for the two unresolved call targets.

Reads ordinary .text only. Does not execute either target, does not substitute
an allocator, and does not start the game.
"""
import json
import os
import struct
import sys

import uc_code_analyze as uca
import uc_phase13_audit as audit

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    info = uca.read_inputs(game)
    other = audit.independent_text(game)
    if info["image_base"] != other["image_base"] or info["text"]["va"] != other["va"]:
        sys.exit("PE parsers disagree")
    if info["text"]["raw_ptr"] != other["raw_ptr"]:
        sys.exit("text file pointer disagrees")
    blob, base = info["bytes"], info["text_va"]
    with open(game, "rb") as fh:
        for va, expect in (
            (0x008101B0, bytes.fromhex("6aff68")),
            (0x00686000, bytes.fromhex("e8f63f2fae")),
            (0x0055FF30, bytes.fromhex("46")),
        ):
            off = audit.file_offset(info, va)
            fh.seek(off)
            raw = fh.read(len(expect))
            if raw != blob[va - base:va - base + len(expect)] or raw != expect:
                sys.exit("bytes changed at %08x" % va)
    # High-confidence call: E8 at 0x0071E6B0, next is mov esi, eax; add esp, 0xC.
    eip = 0x0071E6B0
    rel = struct.unpack_from("<i", blob, eip + 1 - base)[0]
    dest = (eip + 5 + rel) & 0xFFFFFFFF
    if blob[eip - base] != 0xE8 or dest != 0x00686000:
        sys.exit("call displacement is not 0x00686000")
    if blob[eip + 5 - base:eip + 10 - base] != bytes.fromhex("8bf083c40c"):
        sys.exit("return is not mov esi, eax; add esp, 0xC")
    sites = audit.callers(blob, base, 0x00686000)
    if len(sites) != 249 or any(kind != "call" for _eip, kind in sites):
        sys.exit("caller count changed: %d" % len(sites))
    other_sites = audit.callers(blob, base, 0x0055FF30)
    if len(other_sites) != 4:
        sys.exit("0x0055FF30 caller count changed")
    abi_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "analysis", "undercover", "import-abi.json")
    abi = json.load(open(abi_path, encoding="utf-8"))
    thunks = {int(row["thunk"], 16) for row in abi["imports"]}
    if 0x00686000 in thunks or 0x0055FF30 in thunks:
        sys.exit("target is an import thunk")
    print("uc phase13 target checks passed")


if __name__ == "__main__":
    main()
