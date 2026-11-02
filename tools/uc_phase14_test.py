"""Phase 14 checks for the helper cut and the graphics prefix.

Reads ordinary sections only. Does not execute 0x00686000, does not substitute
an allocator, and does not start the game.
"""
import struct
import sys

import uc_phase7_test as p7
import uc_phase14_cut as cut

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"


def expect(cond, text):
    if not cond:
        sys.exit(text)


def test_path_class():
    must_graph = {1: [2], 2: []}
    must_calls = {1: cut.HELPER}
    expect(cut.path_class(must_graph, must_calls, 1, set(), set()) == cut.MUST, "straight call")
    may_graph = {1: [2, 3], 2: [4], 3: [], 4: []}
    may_calls = {2: cut.HELPER}
    expect(cut.path_class(may_graph, may_calls, 1, set(), set()) == cut.MAY, "conditional call")
    none_graph = {1: []}
    expect(cut.path_class(none_graph, {}, 1, set(), set()) == cut.NONE, "return only")


def main():
    test_path_class()
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    ctx = cut.analyze(game)
    labels = ctx["labels"]
    counts = ctx["counts"]
    # Phase 16 rebuilt the HIGH set; cut counts scale with that set but stay narrow.
    expect(ctx["high"] >= 20000, "high count")
    expect(counts[cut.MUST] == 74, "must count")
    expect(counts[cut.MAY] == 139, "may count")
    expect(counts[cut.NONE] == 22394, "independent count")
    expect(ctx["direct_functions"] >= 19, "direct callers")
    expect(ctx["direct_sites_reached"] >= 42, "direct sites")
    expect(labels[0x0099DCD0] == cut.NONE, "102 root")
    expect(labels[0x00B01EB0] == cut.NONE, "ready root")
    expect(labels[0x00968D10] == cut.NONE, "import root")
    expect(labels[0x00830380] == cut.MUST, "heavy caller")
    expect(labels[0x0072C2A0] == cut.MAY, "partial caller")
    expect(labels.get(0x0072E340) == cut.NONE, "create function independent")
    blob, base = ctx["blob"], ctx["base"]
    eip = 0x0072E3B9
    rel = struct.unpack_from("<i", blob, eip + 1 - base)[0]
    dest = (eip + 5 + rel) & 0xFFFFFFFF
    expect(dest == 0x0087A79C, "create call target")
    lo, hi = 0x0072E340 - base, 0x0072E5C0 - base
    for off in range(lo, hi - 5):
        if blob[off] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        target = (base + off + 5 + rel) & 0xFFFFFFFF
        expect(target not in (cut.HELPER, cut.UNKNOWN_B), "helper inside create span")
    row = ctx["by"][0x0072E340]
    # Phase 16 CFG enrollment promotes these; they stay independent of 0x00686000.
    expect(row["label"] == "HIGH_CONFIDENCE" and row.get("reachable"), "create confidence")
    caller = ctx["by"][0x0072E5D0]
    expect(caller["label"] == "HIGH_CONFIDENCE" and caller.get("reachable"), "graphics caller")
    image = p7.read_sections(game)
    rdata = next(sec for sec in image["sections"] if sec["name"] == ".rdata")
    off = 0x00B615C4 - rdata["va"]
    slot = int.from_bytes(rdata["raw"][off:off + 4], "little")
    expect(slot == 0x008AA3AE, "indirect slot dword")
    print("phase 14 ok", ctx["high"], counts)


if __name__ == "__main__":
    main()
