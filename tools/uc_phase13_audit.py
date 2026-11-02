"""Audit two ordinary .text call targets without assigning them an implementation.

Reads the PE headers and ordinary sections only. Protected sections are not
read. The game is not started.
"""
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_code_analyze as uca
import uc_initprov as prov
import uc_phase7_test as p7
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
TARGETS = (0x00686000, 0x0055FF30)
ANCHORS = (0x008101B0, 0x009E4640, 0x009E8AD0, 0x00401000)


def file_offset(info, va):
    text = info["text"]
    if not (text["va"] <= va < text["va"] + text["vsize"]):
        return None
    delta = va - text["va"]
    if delta >= text["raw_size"]:
        return None
    return text["raw_ptr"] + delta


def independent_text(path):
    """Second PE parse, separate from uc_code_analyze.read_inputs."""
    with open(path, "rb") as fh:
        fh.seek(0x3C)
        e = struct.unpack("<I", fh.read(4))[0]
        fh.seek(e)
        if fh.read(4) != b"PE\0\0":
            raise SystemExit("no PE")
        machine, nsec = struct.unpack("<HH", fh.read(4))
        fh.read(12)
        optsz = struct.unpack("<H", fh.read(2))[0]
        fh.read(2)
        if machine != 0x14C:
            raise SystemExit("not i386")
        opt = fh.tell()
        magic = struct.unpack("<H", fh.read(2))[0]
        if magic != 0x10B:
            raise SystemExit("not PE32")
        fh.seek(opt + 28)
        image_base = struct.unpack("<I", fh.read(4))[0]
        fh.seek(opt + optsz)
        for _ in range(nsec):
            raw = fh.read(40)
            name = raw[:8].split(b"\0", 1)[0].decode("latin1")
            vsz, va, rsz, rawptr = struct.unpack_from("<IIII", raw, 8)
            if name == ".text":
                return {
                    "image_base": image_base,
                    "va": image_base + va,
                    "vsize": vsz,
                    "raw_size": rsz,
                    "raw_ptr": rawptr,
                }
    raise SystemExit("no .text")


def callers(blob, base, target):
    hits = []
    for off in range(len(blob) - 5):
        op = blob[off]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        dest = (base + off + 5 + rel) & 0xFFFFFFFF
        if dest == target:
            hits.append((base + off, "call" if op == 0xE8 else "jmp"))
    return hits


def owner(vas, by, addr):
    import bisect
    i = bisect.bisect_right(vas, addr) - 1
    if i < 0:
        return None
    va = vas[i]
    return va, by[va]


def pushes_before(md, blob, base, eip, limit=14):
    start = max(base, eip - 48)
    insns = list(md.disasm(blob[start - base:eip - base], start))
    # Keep only the tail that reaches eip exactly.
    aligned = []
    for insn in insns:
        if insn.address + insn.size == eip or (aligned and insn.address == aligned[-1].address + aligned[-1].size):
            if not aligned or insn.address == aligned[-1].address + aligned[-1].size:
                aligned.append(insn)
    if not aligned or aligned[-1].address + aligned[-1].size != eip:
        # Resync by trying each recent start.
        aligned = []
        for back in range(0, 40):
            trial = eip - back
            if trial < base:
                break
            got = list(md.disasm(blob[trial - base:eip - base + 1], trial))
            if got and got[-1].address + got[-1].size == eip and got[0].address == trial:
                aligned = got
                break
    pushes = []
    for insn in aligned[-limit:]:
        if insn.mnemonic == "push":
            pushes.append(insn.op_str)
        elif insn.mnemonic == "call":
            pushes = []
    return aligned[-8:], pushes


def after_call(md, blob, base, eip):
    insns = list(md.disasm(blob[eip - base:eip - base + 24], eip))
    return insns[:5]


def data_hits(image, target):
    pat = struct.pack("<I", target)
    found = []
    for sec in image["sections"]:
        raw = sec.get("raw")
        if not raw or sec["name"] not in p7.ALLOWED:
            continue
        start = 0
        while True:
            i = raw.find(pat, start)
            if i < 0:
                break
            found.append((sec["name"], sec["va"] + i))
            start = i + 1
            if len(found) > 12:
                return found
    return found


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    info = uca.read_inputs(game)
    other = independent_text(game)
    blob, base = info["bytes"], info["text_va"]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    fm = json.load(open(os.path.join(uca.ROOT, "analysis", "undercover", "function-map.json"), encoding="utf-8"))
    by = {int(r["va"], 16): r for r in fm["functions"]}
    vas = sorted(by)
    abi = json.load(open(os.path.join(uca.ROOT, "analysis", "undercover", "import-abi.json"), encoding="utf-8"))
    thunks = {int(row["thunk"], 16) for row in abi["imports"]}
    image = p7.read_sections(game)

    print("image_base", hex(info["image_base"]), "match", info["image_base"] == other["image_base"])
    print("text", hex(info["text"]["va"]), "raw", hex(info["text"]["raw_ptr"]),
          "other", hex(other["va"]), hex(other["raw_ptr"]),
          "match", info["text"]["raw_ptr"] == other["raw_ptr"] and info["text"]["va"] == other["va"])
    print("size_image", hex(info["size_image"]), "file", info["file_size"])

    with open(game, "rb") as fh:
        for va in ANCHORS + TARGETS:
            off = file_offset(info, va)
            fh.seek(off)
            raw = fh.read(8)
            cached = blob[va - base:va - base + 8]
            print("anchor", hex(va), "file", hex(off), "same", raw == cached, raw.hex())

    for target in TARGETS:
        print("\n====", hex(target))
        off = file_offset(info, target)
        window = blob[target - 32 - base:target + 48 - base]
        print("window", (target - 32), window.hex())
        digest = hashlib.sha256(window).hexdigest()[:16]
        print("sha256-80", digest)
        # int3 runs in the 64 bytes before
        pre = blob[target - 64 - base:target - base]
        runs = []
        i = 0
        while i < len(pre):
            if pre[i] == 0xCC:
                j = i
                while j < len(pre) and pre[j] == 0xCC:
                    j += 1
                if j - i >= 2:
                    runs.append((target - 64 + i, j - i))
                i = j
            else:
                i += 1
        print("int3", [(hex(a), n) for a, n in runs])
        sites = callers(blob, base, target)
        labels = {}
        print("direct", len(sites))
        for eip, kind in sites:
            own = owner(vas, by, eip)
            label = own[1]["label"] if own else "NONE"
            labels[label] = labels.get(label, 0) + 1
            before, pushes = pushes_before(md, blob, base, eip)
            after = after_call(md, blob, base, eip)
            nxt = ""
            if len(after) > 1:
                nxt = "%s %s" % (after[1].mnemonic, after[1].op_str)
            print(" site", hex(eip), kind, "owner", hex(own[0]) if own else None, label,
                  "pushes", pushes, "next", nxt)
        print("labels", labels)
        print("thunk", target in thunks)
        hits = data_hits(image, target)
        print("data", [(n, hex(a)) for n, a in hits])
        writes = []
        for rel in prov.iter_immediates(blob, base, target):
            got = prov.classify_encoding(blob, base, rel, target)
            if got and got[3] != "low":
                writes.append((hex(got[1]), got[0], got[2], got[3]))
        print("encodings", len(writes))
        for row in writes[:12]:
            print(" ", row)
        # nearby map entries
        near = [va for va in vas if abs(va - target) <= 0x180]
        print("map near", [(hex(va), by[va]["label"], by[va]["insns"]) for va in near[:12]], "n", len(near))
        # alternative starts
        print("shifts")
        for delta in range(-8, 9):
            va = target + delta
            insns = list(md.disasm(blob[va - base:va - base + 24], va))
            if not insns:
                print(" ", delta, "undecodable")
                continue
            first = insns[0]
            text = "; ".join("%s %s" % (i.mnemonic, i.op_str) for i in insns[:4])
            print(" ", delta, "%08X" % first.address, first.mnemonic, text[:110])


if __name__ == "__main__":
    main()
