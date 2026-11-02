#!/usr/bin/env python3
"""Find small Undercover call chains. Reads ordinary .text only."""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_code_analyze as uca
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_ESP, X86_REG_EBP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HLE = {"memcpy", "memmove", "memset", "memcmp", "strlen", "strcmp", "strncmp"}


def main():
    info = uca.read_inputs(sys.argv[1])
    blob, base = info["bytes"], info["text_va"]
    fmap = json.load(open(os.path.join(ROOT, "analysis", "undercover", "function-map.json"), encoding="utf-8"))
    abi = json.load(open(os.path.join(ROOT, "analysis", "undercover", "import-abi.json"), encoding="utf-8"))
    thunk = {}
    for row in abi["imports"]:
        thunk[int(row["thunk"], 16)] = row
    hle = {addr for addr, row in thunk.items() if row["symbol"] in HLE}
    graph = {}
    for row in fmap["functions"]:
        if row.get("reachable") and row["label"] == "HIGH_CONFIDENCE":
            graph[int(row["va"], 16)] = row
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    hits = []
    for va, row in graph.items():
        calls = [int(x, 16) for x in row.get("calls") or []]
        if len(calls) != 1 or calls[0] not in hle:
            continue
        if row.get("tails") or row.get("switches") or row.get("insns", 99) > 40:
            continue
        body = linear(md, blob, base, va, 48)
        text = [f"{i.mnemonic} {i.op_str}".rstrip() for i in body]
        if any(i.mnemonic == "call" and i.operands and i.operands[0].type == X86_OP_IMM and (i.operands[0].imm & 0xffffffff) not in hle for i in body):
            continue
        if any(i.mnemonic == "call" and (not i.operands or i.operands[0].type != X86_OP_IMM) for i in body):
            continue
        hits.append((row["insns"], va, thunk[calls[0]]["symbol"], text))
    hits.sort()
    print("import leaves", len(hits))
    for ins, va, sym, text in hits[:12]:
        print(f"\n{va:#010x} {sym} insns={ins}")
        for line in text:
            print(" ", line)

    pairs = []
    for va, row in graph.items():
        calls = [int(x, 16) for x in row.get("calls") or []]
        if len(calls) != 1 or calls[0] not in graph:
            continue
        if row.get("tails") or row.get("switches"):
            continue
        callee = graph[calls[0]]
        if callee.get("calls") or callee.get("tails") or callee.get("switches"):
            continue
        if row.get("insns", 99) > 30 or callee.get("insns", 99) > 20:
            continue
        pairs.append((row["insns"] + callee["insns"], va, calls[0], row["insns"], callee["insns"]))
    pairs.sort()
    print("\npairs", len(pairs))
    for item in pairs[:8]:
        print(item)


def linear(md, blob, base, va, limit):
    rel = va - base
    out = []
    for insn in md.disasm(blob[rel:rel + 256], va):
        out.append(insn)
        if insn.mnemonic.startswith("ret") or len(out) >= limit:
            break
    return out


if __name__ == "__main__":
    main()
