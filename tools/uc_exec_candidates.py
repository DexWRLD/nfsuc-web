#!/usr/bin/env python3
"""Rank small high-confidence Undercover functions for a native harness.

Reads ordinary .text only. Does not execute nfs.exe.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_code_analyze as uca
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_ESP, X86_REG_EBP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT_LO = 0x00401000
TEXT_HI = 0x00B603FB


def main():
    exe = sys.argv[1]
    info = uca.read_inputs(exe)
    blob, base = info["bytes"], info["text_va"]
    fmap = json.load(open(os.path.join(ROOT, "analysis", "undercover", "function-map.json"), encoding="utf-8"))
    abi = json.load(open(os.path.join(ROOT, "analysis", "undercover", "import-abi.json"), encoding="utf-8"))
    thunks = {int(row["thunk"], 16) for row in abi["imports"]}
    high = [
        row for row in fmap["functions"]
        if row.get("reachable") and row["label"] == "HIGH_CONFIDENCE"
        and not row.get("calls") and not row.get("tails") and not row.get("switches")
        and 1 <= row.get("insns", 0) <= 24
    ]
    high.sort(key=lambda row: (row["insns"], row["va"]))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    rows = []
    for row in high[:400]:
        va = int(row["va"], 16)
        rel = va - base
        if not 0 <= rel < len(blob):
            continue
        insns = list(md.disasm(blob[rel:rel + 160], va))
        if not insns:
            continue
        # Stop at the first near ret so a linear window does not run into the next function.
        body = []
        for insn in insns:
            body.append(insn)
            if insn.mnemonic in ("ret", "retn", "repz ret", "rep ret"):
                break
            if len(body) >= row["insns"] + 2:
                break
        facts = classify(body, thunks)
        facts["va"] = row["va"]
        facts["map_insns"] = row["insns"]
        facts["score_map"] = row["score"]
        rows.append(facts)
    rows.sort(key=lambda item: (-item["suitable_score"], item["map_insns"], item["va"]))
    out = os.path.join(ROOT, "analysis", "undercover", "execution-candidates.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rows[:40], fh, indent=2)
        fh.write("\n")
    print(f"ranked {len(rows)} wrote {out}")
    for item in rows[:15]:
        print(item["va"], item["map_insns"], item["suitable_score"], item["reason"])


def classify(body, thunks):
    calls = []
    imports = []
    globals_ = []
    indirect = []
    protected = []
    text = []
    for insn in body:
        text.append(f"0x{insn.address:08X} {insn.mnemonic} {insn.op_str}".rstrip())
        mems = [op for op in insn.operands if op.type == X86_OP_MEM]
        for op in mems:
            if op.mem.base not in (0, X86_REG_ESP, X86_REG_EBP) or op.mem.index:
                if op.mem.disp and op.mem.base == 0 and op.mem.index == 0:
                    globals_.append(f"0x{op.mem.disp & 0xffffffff:08X}")
                else:
                    globals_.append(insn.op_str)
        if insn.mnemonic in ("call", "jmp") or insn.mnemonic.startswith("j"):
            if insn.operands and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm & 0xffffffff
                if insn.mnemonic == "call":
                    calls.append(f"0x{target:08X}")
                    if target in thunks:
                        imports.append(f"0x{target:08X}")
                if not TEXT_LO <= target <= TEXT_HI:
                    protected.append(f"0x{target:08X}")
            elif insn.mnemonic in ("call", "jmp"):
                indirect.append(insn.op_str or insn.mnemonic)
    reason = []
    score = 0
    if not calls and not indirect and not protected and not imports:
        score += 50
        reason.append("no calls and no indirect control flow")
    if not globals_:
        score += 30
        reason.append("no absolute or non-stack memory")
    if len(body) <= 8:
        score += 10
        reason.append("small straight-line body")
    if any(insn.mnemonic in ("ret", "retn", "repz ret") for insn in body):
        score += 10
        reason.append("ends with a near return")
    else:
        score -= 40
        reason.append("linear window did not end in a return")
    if calls:
        score -= 25
        reason.append("has direct calls")
    if imports:
        score -= 20
        reason.append("calls an import thunk")
    if indirect:
        score -= 30
        reason.append("indirect control flow")
    if protected:
        score -= 50
        reason.append("edge leaves .text")
    if globals_:
        score -= 10
        reason.append("touches memory outside a plain stack/frame operand")
    return {
        "insns": [{"addr": f"0x{i.address:08X}", "text": f"{i.mnemonic} {i.op_str}".rstrip()} for i in body],
        "calls": calls,
        "imports": imports,
        "globals": globals_,
        "indirect": indirect,
        "protected": protected,
        "suitable_score": score,
        "reason": "; ".join(reason),
    }


if __name__ == "__main__":
    main()
