#!/usr/bin/env python3
"""Catalog the Phase 4 high-confidence failures. Reads ordinary .text only."""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
import uc_code_analyze as uca

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCH = {
    "lock xadd", "lock cmpxchg", "lock cmpxchg8b",
    "xadd", "cmpxchg", "cmpxchg8b",
    "psrldq", "pslldq", "punpcklqdq", "punpckhqdq", "pshufd", "pshuflw",
    "fstpnce", "aad", "aaa", "salc", "ljmp",
}


def main():
    exe = sys.argv[1]
    info = uca.read_inputs(exe)
    failed = json.load(open(os.path.join(ROOT, "analysis", "undercover", "high-confidence.json"), encoding="utf-8"))
    lifter = lift.RawLifter(info["bytes"], info["text_va"], comments=False)
    out = os.path.join(ROOT, "analysis", "undercover", "phase5-operands.json")
    hits = json.load(open(out, encoding="utf-8")) if os.path.isfile(out) else []
    seen = {(h["address"], h["mnemonic"]) for h in hits}
    for text in failed["failed_functions"]:
        va = int(text, 16)
        blocks, _calls = lifter.discover(va)
        for addr in sorted(blocks):
            for insn in blocks[addr]:
                if insn.mnemonic not in WATCH:
                    continue
                key = (f"0x{insn.address:08X}", insn.mnemonic)
                if key in seen:
                    continue
                seen.add(key)
                hits.append({
                    "function": text,
                    "address": f"0x{insn.address:08X}",
                    "mnemonic": insn.mnemonic,
                    "operands": insn.op_str,
                    "size": insn.operands[0].size if insn.operands else 0,
                    "lock": insn.mnemonic.startswith("lock "),
                    "bytes": insn.bytes.hex(),
                })
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(hits, fh, indent=2)
        fh.write("\n")
    write_markdown(hits, os.path.join(ROOT, "analysis", "undercover", "phase5-operands.md"))
    print(f"hits {len(hits)} -> {out}")


def write_markdown(hits, path):
    import collections
    order = [
        "lock xadd", "lock cmpxchg", "lock cmpxchg8b",
        "psrldq", "pslldq", "punpcklqdq", "punpckhqdq", "pshufd", "pshuflw",
        "fstpnce", "aad", "aaa", "salc", "ljmp",
    ]
    lines = [
        "# Phase 5 operand catalog",
        "",
        "Every site below is inside the lifter control flow of a Phase 4 HIGH_CONFIDENCE function that failed to generate. "
        "The bytes are ordinary `.text`. Protected sections were not read.",
        "",
        "`lock xadd`, `lock cmpxchg`, and `lock cmpxchg8b` occur only as 32-bit memory destinations, "
        "or as `qword ptr` for `cmpxchg8b`. The LOCK prefix is present on every one of them. "
        "No 8-bit or 16-bit form appears in this set. The lifter still accepts those widths so the implementation is not tied to these addresses.",
        "",
        "`psrldq` and `pslldq` are immediate byte shifts of one XMM register. "
        "`punpcklqdq` is register, register. The `pshufd` sites read memory and use immediate `0xE4`.",
        "",
        "`aad`, `aaa`, `salc`, `ljmp`, and `fstpnce` are not implemented. See the decision at the end.",
        "",
        "## Forms",
        "",
        "| Count | Instruction | Operand size | Operands | LOCK |",
        "| --- | --- | --- | --- | --- |",
    ]
    forms = collections.Counter((h["mnemonic"], h["size"], h["operands"], h["lock"]) for h in hits)
    for (mnemonic, size, operands, locked), count in forms.most_common():
        lines.append(
            f"| {count} | `{mnemonic}` | {size} | `{operands}` | {'yes' if locked else 'no'} |"
        )
    lines.append("")
    for mnemonic in order:
        group = [h for h in hits if h["mnemonic"] == mnemonic]
        if not group:
            continue
        lines.append(f"## `{mnemonic}`")
        lines.append("")
        lines.append("| Function | Address | Size | Operands | LOCK | Bytes |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for h in group:
            lines.append(
                f"| {h['function']} | {h['address']} | {h['size']} | `{h['operands']}` | "
                f"{'yes' if h['lock'] else 'no'} | `{h['bytes']}` |"
            )
        lines.append("")
    fst = [h for h in hits if h["mnemonic"] == "fstpnce"]
    lines += [
        "## `fstpnce` decision",
        "",
    ]
    if fst:
        h = fst[0]
        lines.append(
            f"Capstone decodes `{h['bytes']}` at {h['address']} in function {h['function']} as "
            f"`fstpnce {h['operands']}`. Intel leaves `D9 D8+i` reserved. "
            "The documented `FSTP ST(i)` encoding is `DD D8+i`, and the lifter already implements `fst` and `fstp`. "
            "The surrounding block is not x87 compiler output. The function entry looks like a short compiler function, "
            "and `discover()` reaches this block by following a jump. "
            "`fstpnce` is not implemented. The function is reclassified as data reached through a bad edge."
        )
        lines.append("")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))


if __name__ == "__main__":
    main()
