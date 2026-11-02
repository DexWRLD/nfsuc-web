#!/usr/bin/env python3
"""Undercover-only function confidence and validated call graph.

The NFSU2 discovery path (tools/genall.py) is not used and is not changed.
Roots are not taken from every CALL a linear sweep can decode. Seeds are
phase 3 functions that compiled, plus instruction-boundary MSVC frame
prologues that sit after int3 padding. The walk then follows direct calls,
direct jumps that land on an entry, and recognized switch-table targets.

  tools/uc_funcmap.py <nfs.exe> [--generate]

Writes analysis/undercover/function-map.json and function-map.md.
With --generate, lifts and compile-checks only HIGH_CONFIDENCE functions.
Generated C stays under generated/undercover/high/ and is gitignored.
"""
import collections, json, os, sys, time

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import uc_code_analyze as uca
import uc_gen as ucg
import lift

BCD = {"aaa", "aas", "daa", "das", "aam", "aad"}
FAR = {"lcall", "ljmp", "retf", "iret", "iretd"}
PRIV = {
    "cli", "sti", "hlt", "lgdt", "lidt", "lldt", "ltr", "lmsw", "clts",
    "invd", "wbinvd", "sysenter", "syscall", "in", "out", "ins", "insb",
    "insw", "insd", "outs", "outsb", "outsw", "outsd", "wrmsr", "rdmsr",
}
LES = {"les", "lds"}
RARE = {"arpl", "bound", "salc", "into", "icebp", "ud0", "ud1"}
ENTRY_BAD = BCD | FAR | PRIV | LES | RARE
# Opcodes the lifter does not treat as compiler output. A HIGH or MEDIUM
# function whose control flow reaches one of these is data reached by a jump,
# not a missing instruction. Privileged opcodes the lifter already comments
# out (in, hlt, cli) are not in this set.
DATA_CFG = BCD | {"lcall", "ljmp", "les", "lds", "salc", "fstpnce", "iret", "iretd", "into", "arpl", "bound"}
STACK = {"push", "pop", "pushfd", "popfd", "enter", "leave"}
LOOP = {"jecxz", "jcxz", "loop", "loope", "loopz", "loopne", "loopnz"}


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


def hx(n):
    return f"0x{n & 0xffffffff:08X}"


def is_jcc(m):
    return (m.startswith("j") and m[1:] in lift.CC) or m in LOOP


def phase3_compiled(path):
    out = []
    if not os.path.isfile(path):
        return out
    for line in open(path, encoding="utf-8"):
        if not line.startswith("| 0x"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) >= 6 and cols[4] == "yes" and cols[5] == "yes":
            out.append(int(cols[0], 16))
    return out


def mark_starts(blob, base):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    starts = bytearray(len(blob))
    off = 0
    n = len(blob)
    decoded = 0
    while off < n:
        insns = list(md.disasm(blob[off:off + 65536], base + off))
        if not insns:
            off += 1
            continue
        for insn in insns:
            rel = insn.address - base
            if 0 <= rel < n:
                starts[rel] = 1
            decoded += 1
        off = insns[-1].address + insns[-1].size - base
    return starts, decoded


def on_boundary(starts, base, n, va):
    rel = va - base
    return 0 <= rel < n and starts[rel] == 1


def prologue_at(blob, off):
    return blob[off:off + 3] == b"\x55\x8b\xec"


def after_int3(blob, off):
    return off > 0 and blob[off - 1] == 0xCC


def entry_shape(blob, base, va):
    off = va - base
    if off < 0 or off >= len(blob):
        return False
    return prologue_at(blob, off) or after_int3(blob, off)


class Walker:
    def __init__(self, blob, base, starts, lifter):
        self.blob = blob
        self.base = base
        self.n = len(blob)
        self.starts = starts
        self.L = lifter
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True

    def decode(self, va):
        if not on_boundary(self.starts, self.base, self.n, va):
            return None
        off = va - self.base
        found = list(self.md.disasm(self.blob[off:off + 15], va))
        return found[0] if found else None

    def walk(self, entry, entries):
        facts = {
            "va": entry,
            "on_boundary": on_boundary(self.starts, self.base, self.n, entry),
            "frame": prologue_at(self.blob, entry - self.base),
            "after_int3": after_int3(self.blob, entry - self.base),
            "insns": 0,
            "bytes": 0,
            "stack": 0,
            "calls": [],
            "tails": [],
            "switches": 0,
            "switch_targets": 0,
            "bad_branch": 0,
            "undecodable": 0,
            "privileged": 0,
            "far": 0,
            "bcd": 0,
            "les": 0,
            "nonsense": 0,
            "ends_ret": False,
            "ends_tail": False,
            "ends_import": False,
            "entry_nonsense": False,
            "truncated": False,
            "span": 0,
        }
        if not facts["on_boundary"]:
            return facts, set()
        first = self.decode(entry)
        if first is None:
            facts["undecodable"] += 1
            return facts, set()
        if first.mnemonic in ENTRY_BAD:
            facts["entry_nonsense"] = True
            facts["insns"] = 1
            self._tally(facts, first)
            return facts, set()

        blocks = {}
        queue = collections.deque([entry])
        seen = set()
        owned = set()
        while queue and facts["insns"] < 20000:
            va = queue.popleft()
            if va in seen:
                continue
            if not on_boundary(self.starts, self.base, self.n, va):
                facts["bad_branch"] += 1
                continue
            seen.add(va)
            ins = []
            cur = va
            while facts["insns"] < 20000 and len(ins) < 4000:
                if ins and prologue_at(self.blob, cur - self.base) and cur != entry:
                    break
                insn = self.decode(cur)
                if insn is None:
                    facts["undecodable"] += 1
                    break
                ins.append(insn)
                facts["insns"] += 1
                facts["bytes"] += insn.size
                self._own(owned, insn)
                self._tally(facts, insn)
                m = insn.mnemonic
                nxt = insn.address + insn.size
                if lift._is_near_ret(m):
                    facts["ends_ret"] = True
                    break
                if m == "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                    target = insn.operands[0].imm & 0xffffffff
                    if self.L.in_text(target) and (
                        entry_shape(self.blob, self.base, target) or target in entries
                    ) and target != entry:
                        facts["tails"].append(target)
                        facts["ends_tail"] = True
                    elif self.L.in_text(target) and on_boundary(self.starts, self.base, self.n, target):
                        queue.append(target)
                    else:
                        facts["bad_branch"] += 1
                    break
                if m == "jmp" and insn.operands and insn.operands[0].type == X86_OP_MEM:
                    mem = insn.operands[0].mem
                    slot = mem.disp & 0xffffffff
                    if not mem.base and not mem.index and not self.L.in_text(slot):
                        facts["ends_import"] = True
                    break
                if is_jcc(m) and insn.operands and insn.operands[0].type == X86_OP_IMM:
                    target = insn.operands[0].imm & 0xffffffff
                    for dest in (target, nxt):
                        if self.L.in_text(dest) and on_boundary(self.starts, self.base, self.n, dest):
                            queue.append(dest)
                        elif self.L.in_text(dest):
                            facts["bad_branch"] += 1
                    break
                if m == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                    target = insn.operands[0].imm & 0xffffffff
                    if self.L.in_text(target):
                        facts["calls"].append(target)
                if m == "int3":
                    pad = self.blob[nxt - self.base:nxt - self.base + 3]
                    if pad == b"\xcc\xcc\xcc":
                        break
                if m in ("hlt", "ud2", "retf"):
                    break
                if not self.L.in_text(nxt):
                    break
                cur = nxt
            else:
                if len(ins) >= 4000:
                    facts["truncated"] = True
            if ins:
                blocks[ins[0].address] = ins
        if facts["insns"] >= 20000:
            facts["truncated"] = True
        self._switches(facts, blocks, queue, seen, owned)
        if facts["insns"]:
            last = max(owned) if owned else entry
            facts["span"] = max(1, last + 1 - entry)
        facts["calls"] = sorted(set(facts["calls"]))
        facts["tails"] = sorted(set(facts["tails"]))
        facts["owned"] = owned
        return facts, owned

    def _own(self, owned, insn):
        for addr in range(insn.address, insn.address + insn.size):
            owned.add(addr)

    def _tally(self, facts, insn):
        m = insn.mnemonic
        base = m.split()[-1]
        if m in STACK or (m == "sub" and "esp" in insn.op_str) or (m == "add" and "esp" in insn.op_str):
            facts["stack"] += 1
        if base in PRIV or m in PRIV:
            facts["privileged"] += 1
        if base in FAR or m in FAR:
            facts["far"] += 1
        if base in BCD or m in BCD:
            facts["bcd"] += 1
        if base in LES or m in LES:
            facts["les"] += 1
        if base in RARE or m in RARE:
            facts["nonsense"] += 1

    def _switches(self, facts, blocks, queue, seen, owned):
        bounds = {}
        for ins in blocks.values():
            if not ins:
                continue
            bound = self.L._jt_bound(ins)
            if bound:
                bounds[bound[2]] = bound[:2]
        added = True
        while added:
            added = False
            for ba, ins in list(blocks.items()):
                if not ins or ba not in bounds:
                    continue
                jmp = ins[-1]
                if jmp.address in facts.get("_jtab", ()):
                    continue
                try:
                    tab = self.L._jt_table(ins, bounds[ba])
                except Exception:
                    tab = None
                if not tab:
                    if jmp.mnemonic == "jmp" and jmp.operands and jmp.operands[0].type == X86_OP_MEM:
                        mem = jmp.operands[0].mem
                        if mem.index and (mem.scale or 0) == 4:
                            facts["bad_branch"] += 1
                    continue
                facts.setdefault("_jtab", set()).add(jmp.address)
                facts["switches"] += 1
                _reg, _disp, targets = tab
                for target in targets:
                    target &= 0xffffffff
                    facts["switch_targets"] += 1
                    if target in seen:
                        continue
                    if not on_boundary(self.starts, self.base, self.n, target):
                        facts["bad_branch"] += 1
                        continue
                    seen.add(target)
                    added = True
                    ins2 = []
                    cur = target
                    while facts["insns"] < 20000 and len(ins2) < 4000:
                        insn = self.decode(cur)
                        if insn is None:
                            facts["undecodable"] += 1
                            break
                        ins2.append(insn)
                        facts["insns"] += 1
                        facts["bytes"] += insn.size
                        self._own(owned, insn)
                        self._tally(facts, insn)
                        m = insn.mnemonic
                        nxt = insn.address + insn.size
                        if lift._is_near_ret(m) or m in ("jmp", "hlt", "ud2", "retf") or is_jcc(m):
                            if m == "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                                dest = insn.operands[0].imm & 0xffffffff
                                if self.L.in_text(dest) and on_boundary(self.starts, self.base, self.n, dest):
                                    if dest not in seen:
                                        seen.add(dest)
                                        # decoded lazily by the outer loop via queue
                                        queue.append(dest)
                            elif is_jcc(m) and insn.operands and insn.operands[0].type == X86_OP_IMM:
                                dest = insn.operands[0].imm & 0xffffffff
                                for dest2 in (dest, nxt):
                                    if self.L.in_text(dest2) and dest2 not in seen and on_boundary(
                                        self.starts, self.base, self.n, dest2
                                    ):
                                        queue.append(dest2)
                            if lift._is_near_ret(m):
                                facts["ends_ret"] = True
                            break
                        if m == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                            target2 = insn.operands[0].imm & 0xffffffff
                            if self.L.in_text(target2):
                                facts["calls"].append(target2)
                        cur = nxt
                    if ins2:
                        blocks[ins2[0].address] = ins2
            # Drain targets queued from switch cases with the same rules as the main walk.
            while queue and facts["insns"] < 20000:
                va = queue.popleft()
                if va in seen:
                    continue
                if not on_boundary(self.starts, self.base, self.n, va):
                    facts["bad_branch"] += 1
                    continue
                seen.add(va)
                ins = []
                cur = va
                while facts["insns"] < 20000 and len(ins) < 4000:
                    insn = self.decode(cur)
                    if insn is None:
                        facts["undecodable"] += 1
                        break
                    ins.append(insn)
                    facts["insns"] += 1
                    facts["bytes"] += insn.size
                    self._own(owned, insn)
                    self._tally(facts, insn)
                    m = insn.mnemonic
                    nxt = insn.address + insn.size
                    if lift._is_near_ret(m):
                        facts["ends_ret"] = True
                        break
                    if m == "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                        target = insn.operands[0].imm & 0xffffffff
                        if self.L.in_text(target) and on_boundary(self.starts, self.base, self.n, target):
                            if entry_shape(self.blob, self.base, target) or target in entries_placeholder(self):
                                facts["tails"].append(target)
                                facts["ends_tail"] = True
                            else:
                                queue.append(target)
                        else:
                            facts["bad_branch"] += 1
                        break
                    if is_jcc(m) and insn.operands and insn.operands[0].type == X86_OP_IMM:
                        target = insn.operands[0].imm & 0xffffffff
                        for dest in (target, nxt):
                            if dest not in seen and self.L.in_text(dest) and on_boundary(
                                self.starts, self.base, self.n, dest
                            ):
                                queue.append(dest)
                        break
                    if m == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                        target = insn.operands[0].imm & 0xffffffff
                        if self.L.in_text(target):
                            facts["calls"].append(target)
                    if m in ("hlt", "ud2", "retf"):
                        break
                    cur = nxt
                if ins:
                    blocks[ins[0].address] = ins
                    bound = self.L._jt_bound(ins)
                    if bound:
                        bounds[bound[2]] = bound[:2]
                        added = True


def entries_placeholder(walker):
    return getattr(walker, "entry_set", set())


def classify(facts, from_call, calls_known):
    """Score one function. A frame pointer is evidence, not a requirement."""
    reasons = []
    if not facts["on_boundary"]:
        return "REJECTED_DATA_LIKE", 0, ["not on a linear-sweep instruction boundary"]
    if facts["entry_nonsense"]:
        return "REJECTED_DATA_LIKE", 0, ["first instruction is not ordinary application code"]
    score = 20
    reasons.append("instruction boundary")
    if from_call:
        score += 25
        reasons.append("referenced from a validated function")
    if facts["frame"]:
        score += 25
        reasons.append("MSVC frame prologue")
    elif facts["stack"]:
        score += 12
        reasons.append("stack operation without requiring a frame pointer")
    if facts["after_int3"]:
        score += 15
        reasons.append("preceded by int3 padding")
    if facts["bad_branch"] == 0 and facts["insns"] > 0:
        score += 15
        reasons.append("internal branches land on instruction boundaries")
    elif facts["bad_branch"]:
        score -= 20
        reasons.append("branch misses the instruction stream or enters embedded data")
    if facts["ends_ret"] or facts["ends_tail"] or facts["ends_import"]:
        score += 15
        reasons.append("ends in ret, a tail jump, or an import jump")
    if facts["stack"]:
        score += 8
        reasons.append("plausible stack traffic")
    if calls_known:
        score += 10
        reasons.append("calls another classified function")
    if facts["switches"]:
        score += 10
        reasons.append("recognized switch table")
    span = facts["span"] or facts["bytes"] or 1
    density = facts["bytes"] / span
    if density >= 0.85 and facts["insns"] > 0:
        score += 10
        reasons.append("high density of decoded bytes")
    if facts["privileged"] and (facts["privileged"] >= 3 or facts["privileged"] * 25 >= max(facts["insns"], 1)):
        score -= 40
        reasons.append("privileged instructions in ordinary code")
    if facts["far"]:
        score -= 35
        reasons.append("far call or jump")
    if facts["bcd"]:
        score -= 30
        reasons.append("BCD arithmetic")
    if facts["les"]:
        score -= 30
        reasons.append("les or lds")
    if facts["nonsense"] >= 2:
        score -= 25
        reasons.append("repeated rare legacy opcodes")
    if facts["undecodable"] >= 3:
        score -= 25
        reasons.append("undecodable bytes inside the CFG")
    if facts["truncated"]:
        score -= 10
        reasons.append("walk hit its instruction cap")
    hard = facts["far"] or facts["bcd"] or facts["les"] or facts["entry_nonsense"]
    terminated = facts["ends_ret"] or facts["ends_tail"] or facts["ends_import"] or facts["switches"]
    if hard or score < 20 or facts["insns"] == 0:
        label = "REJECTED_DATA_LIKE"
    elif score >= 60 and facts["bad_branch"] == 0 and not facts["truncated"] and terminated:
        label = "HIGH_CONFIDENCE"
    elif score >= 40 and facts["bad_branch"] <= 1:
        label = "MEDIUM_CONFIDENCE"
    elif score >= 20:
        label = "LOW_CONFIDENCE"
    else:
        label = "REJECTED_DATA_LIKE"
    return label, score, reasons


def demote_data_cfg(blob, base, graph, coverage):
    """Reject a scored function when the lifter's CFG reaches embedded data.

    The linear walk stops at instruction-boundary jumps. discover() follows
    every in-range jump, which is how a real-looking entry can land on aad,
    aaa, salc, ljmp, or the reserved bytes Capstone calls fstpnce. Those are
    not implemented. The function is reclassified instead.
    """
    lifter = lift.RawLifter(blob, base, comments=False)
    demoted = []
    for row in graph.values():
        if row["label"] not in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE"):
            continue
        bad = None
        blocks, _calls = lifter.discover(row["va"])
        for insns in blocks.values():
            for insn in insns:
                if insn.mnemonic.split()[-1] in DATA_CFG:
                    bad = insn.mnemonic
                    break
            if bad:
                break
        if not bad:
            continue
        row["label"] = "REJECTED_DATA_LIKE"
        row["score"] = 0
        row["reasons"] = [
            f"lifter control flow reaches `{bad}`",
            "following a jump leaves compiler-shaped code and enters embedded data",
        ]
        row.pop("_owned", None)
        demoted.append({"va": row["va"], "mnemonic": bad})
    for index in range(len(coverage)):
        coverage[index] = 0
    for row in graph.values():
        owned = row.pop("_owned", None)
        if not owned or row["label"] not in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE"):
            continue
        for addr in owned:
            rel = addr - base
            if 0 <= rel < len(coverage):
                coverage[rel] = 1
    return demoted


def build(info):
    blob = info["bytes"]
    base = info["text_va"]
    print("  marking instruction boundaries", file=sys.stderr)
    t0 = time.time()
    starts, decoded = mark_starts(blob, base)
    print(f"  boundaries {decoded} instructions ({time.time() - t0:.0f}s)", file=sys.stderr)
    lifter = ucg.make_lifter(blob, base)
    walker = Walker(blob, base, starts, lifter)
    seeds = []
    seed_reason = {}
    for va in phase3_compiled(os.path.join(ROOT, "analysis", "undercover", "phase3-baseline.md")):
        if on_boundary(starts, base, len(blob), va):
            seeds.append(va)
            seed_reason[va] = "phase 3 function that compiled"
    for off in range(len(blob) - 3):
        if starts[off] and prologue_at(blob, off) and after_int3(blob, off):
            va = base + off
            if va not in seed_reason:
                seeds.append(va)
                seed_reason[va] = "frame prologue after int3"
    print(f"  seeds {len(seeds)}", file=sys.stderr)
    entry_set = set(seeds)
    walker.entry_set = entry_set
    graph = {}
    coverage = bytearray(len(blob))
    queue = collections.deque((va, False, seed_reason[va]) for va in seeds)
    seen_entries = set()
    while queue:
        va, from_call, why = queue.popleft()
        if va in seen_entries:
            continue
        if not on_boundary(starts, base, len(blob), va):
            graph[va] = {
                "va": va,
                "label": "REJECTED_DATA_LIKE",
                "score": 0,
                "reasons": ["call or jump target is not on an instruction boundary"],
                "reachable": True,
                "from_call": from_call,
                "seed": why,
                "insns": 0,
                "calls": [],
                "tails": [],
                "switches": 0,
            }
            seen_entries.add(va)
            continue
        seen_entries.add(va)
        facts, owned = walker.walk(va, entry_set)
        label, score, reasons = classify(facts, from_call, False)
        row = {
            "va": va,
            "label": label,
            "score": score,
            "reasons": reasons,
            "reachable": True,
            "from_call": from_call,
            "seed": why if not from_call else "",
            "insns": facts["insns"],
            "bytes": facts["bytes"],
            "calls": facts["calls"],
            "tails": facts["tails"],
            "switches": facts["switches"],
            "bad_branch": facts["bad_branch"],
            "frame": facts["frame"],
            "after_int3": facts["after_int3"],
            "ends_ret": facts["ends_ret"],
            "entry_nonsense": facts["entry_nonsense"],
        }
        graph[va] = row
        if label in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE"):
            row["_owned"] = list(owned)
            for addr in owned:
                rel = addr - base
                if 0 <= rel < len(coverage):
                    coverage[rel] = 1
            for target in facts["calls"] + facts["tails"]:
                entry_set.add(target)
                walker.entry_set = entry_set
                if target not in seen_entries:
                    queue.append((target, True, ""))
        if len(graph) % 500 == 0:
            print(f"  classified {len(graph)}", file=sys.stderr)

    # A call into an already classified function is extra evidence. It can raise a
    # score. It does not erase a rejection for an illegal first instruction.
    for row in graph.values():
        if row.get("entry_nonsense") or row["label"] == "REJECTED_DATA_LIKE":
            continue
        known = any(
            graph.get(target, {}).get("label") in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE")
            for target in row.get("calls") or []
        )
        if not known:
            continue
        row["score"] += 10
        row["reasons"].append("calls another classified function")
        if row["label"] == "MEDIUM_CONFIDENCE" and row["score"] >= 60 and row.get("bad_branch", 0) == 0 and row.get("ends_ret"):
            row["label"] = "HIGH_CONFIDENCE"

    demoted = demote_data_cfg(blob, base, graph, coverage)

    unreachable = []
    for off in range(len(blob) - 3):
        if not starts[off] or coverage[off] or (base + off) in graph:
            continue
        # int3 itself is an instruction, so a padding run must not be counted once
        # per 0xCC. The candidate is the first real instruction after four or more
        # padding bytes, or a frame prologue the walk never reached.
        if blob[off] == 0xCC:
            continue
        padded = off >= 4 and blob[off - 4:off] == b"\xcc\xcc\xcc\xcc"
        if not prologue_at(blob, off) and not padded:
            continue
        va = base + off
        window = _window(blob, base, starts, va)
        label, score, reasons = classify(window, False, False)
        unreachable.append({
            "va": va,
            "label": label,
            "score": score,
            "reasons": reasons,
            "reachable": False,
            "insns": window["insns"],
        })
    covered = sum(coverage)
    return {
        "decoded_boundaries": decoded,
        "seeds": len(seeds),
        "graph": graph,
        "unreachable": unreachable,
        "covered_bytes": covered,
        "text_size": len(blob),
        "data_cfg_rejected": demoted,
    }


def _window(blob, base, starts, va):
    """Cheap look at an unreachable candidate. Does not follow calls."""
    md = _window.md
    facts = {
        "on_boundary": True,
        "frame": prologue_at(blob, va - base),
        "after_int3": after_int3(blob, va - base),
        "insns": 0,
        "bytes": 0,
        "span": 1,
        "stack": 0,
        "bad_branch": 0,
        "undecodable": 0,
        "privileged": 0,
        "far": 0,
        "bcd": 0,
        "les": 0,
        "nonsense": 0,
        "ends_ret": False,
        "ends_tail": False,
        "ends_import": False,
        "entry_nonsense": False,
        "switches": 0,
        "truncated": False,
    }
    cur = va
    for _ in range(24):
        if not on_boundary(starts, base, len(blob), cur):
            facts["undecodable"] += 1
            break
        found = list(md.disasm(blob[cur - base:cur - base + 15], cur))
        if not found:
            facts["undecodable"] += 1
            break
        insn = found[0]
        if facts["insns"] == 0 and insn.mnemonic in ENTRY_BAD:
            facts["entry_nonsense"] = True
        facts["insns"] += 1
        facts["bytes"] += insn.size
        m = insn.mnemonic
        base_m = m.split()[-1]
        if m in STACK or "esp" in insn.op_str:
            facts["stack"] += 1
        if base_m in PRIV:
            facts["privileged"] += 1
        if base_m in FAR:
            facts["far"] += 1
        if base_m in BCD:
            facts["bcd"] += 1
        if base_m in LES:
            facts["les"] += 1
        if lift._is_near_ret(m):
            facts["ends_ret"] = True
            break
        if m == "jmp":
            facts["ends_tail"] = True
            break
        cur = insn.address + insn.size
    facts["span"] = max(1, facts["bytes"])
    return facts


_window.md = Cs(CS_ARCH_X86, CS_MODE_32)


def write_reports(doc, out_dir):
    graph = doc["graph"]
    counts = collections.Counter(row["label"] for row in graph.values())
    un_counts = collections.Counter(row["label"] for row in doc["unreachable"])
    reachable = len(graph)
    lines = [
        "# Undercover validated function map",
        "",
        "This map is Undercover-specific. `tools/genall.py` and the NFSU2 root list were not changed.",
        "Protected sections were not disassembled. The PE entry point was not used.",
        "",
        "## How a function is scored",
        "",
        "A candidate starts at an instruction boundary from a linear sweep of `.text`. "
        "That boundary is required. Missing it rejects the candidate.",
        "",
        "Seeds are not every direct CALL the sweep can decode. They are:",
        "",
        "- phase 3 functions that generated and compiled",
        "- `55 8B EC` at a boundary whose preceding byte is `int3`",
        "",
        "From a function classified HIGH or MEDIUM the walk follows:",
        "",
        "- a direct `call` whose target is inside `.text`",
        "- a direct `jmp` whose target already looks like an entry (frame prologue, int3 padding, or an existing entry)",
        "- targets of a switch table recognized by the same bounds the lifter uses",
        "",
        "A direct `jmp` to any other in-range address stays inside the function. "
        "Switch targets stay inside the function. A call into a target whose first instruction is "
        "privileged, far, BCD, `les`/`lds`, or another rare legacy opcode is rejected and is not expanded.",
        "",
        "Optimized MSVC code often omits `55 8B EC`. A frame pointer adds points. It is not required.",
        "",
        "| Evidence | Points |",
        "| --- | --- |",
        "| On a linear-sweep instruction boundary | +20, required |",
        "| Called or tail-called from a HIGH or MEDIUM function | +25 |",
        "| MSVC frame prologue | +25 |",
        "| Stack setup without a frame pointer | +12 |",
        "| Preceded by int3 padding | +15 |",
        "| Internal branches stay on boundaries | +15 |",
        "| Ends in near ret (including `repz ret`), a tail jmp, or `jmp [abs]` | +15 |",
        "| Stack traffic | +8 |",
        "| Calls another HIGH or MEDIUM function | +10 |",
        "| Recognized switch table | +10 |",
        "| Decoded bytes cover at least 85% of the span | +10 |",
        "| A branch leaves the instruction stream | -20 |",
        "| Privileged opcodes are common in the body | -40 |",
        "| Far call or jump | -35 |",
        "| BCD opcode | -30 |",
        "| `les` or `lds` | -30 |",
        "| Repeated rare legacy opcodes | -25 |",
        "| Three or more undecodable gaps | -25 |",
        "",
        "Labels: HIGH at 60 or more with a terminator and no bad branch; "
        "MEDIUM at 40 or more; LOW at 20 or more; otherwise REJECTED_DATA_LIKE. "
        "An illegal first instruction is rejected before the points are added.",
        "",
        "After scoring, HIGH and MEDIUM functions are checked with the lifter's own control-flow walk. "
        "If that walk reaches `aad`, `aaa`, `salc`, `ljmp`, `fstpnce`, or another opcode in the same data class, "
        "the function is reclassified REJECTED_DATA_LIKE. The opcode is not added to the lifter. "
        f"Phase 5 rejected {len(doc.get('data_cfg_rejected') or [])} functions this way.",
        "",
        "## Change from Phase 4",
        "",
        "Phase 4 scored 6,604 HIGH and 79 MEDIUM from the linear walk. "
        "Phase 5 keeps that score, then rejects a function whose lifter control flow reaches embedded data. "
        "Generation of the original 6,604 is recorded in `high-confidence.md` and is not recomputed from this smaller set.",
        "",
        "| | Phase 4 | Phase 5 |",
        "| --- | --- | --- |",
        "| HIGH_CONFIDENCE | 6,604 | " + str(counts["HIGH_CONFIDENCE"]) + " |",
        "| MEDIUM_CONFIDENCE | 79 | " + str(counts["MEDIUM_CONFIDENCE"]) + " |",
        "| LOW_CONFIDENCE | 20 | " + str(counts["LOW_CONFIDENCE"]) + " |",
        "| REJECTED_DATA_LIKE | 478 | " + str(counts["REJECTED_DATA_LIKE"]) + " |",
        "| CFG-covered bytes | 1,853,801 | " + str(doc["covered_bytes"]) + " |",
        "",
        "Seven former HIGH functions were rejected. Six are the generation failures. "
        "The seventh, `0x004A7520`, is data that the lifter still compiled because `into` is emitted as a comment. "
        "Former MEDIUM functions rejected by the same check include real `55 8B EC` prologues that jump into data. "
        "That rejection is a boundary problem.",
        "",
        "## Counts",
        "",
        f"- Seeds: {doc['seeds']}",
        f"- Reachable entries walked: {reachable}",
        f"- HIGH_CONFIDENCE: {counts['HIGH_CONFIDENCE']}",
        f"- MEDIUM_CONFIDENCE: {counts['MEDIUM_CONFIDENCE']}",
        f"- LOW_CONFIDENCE: {counts['LOW_CONFIDENCE']}",
        f"- REJECTED_DATA_LIKE among walked entries: {counts['REJECTED_DATA_LIKE']}",
        f"- Unreachable prologue or padding candidates: {len(doc['unreachable'])}",
        "- Short-window sketch of those candidates, not a second graph and not generated: "
        f"{un_counts['HIGH_CONFIDENCE']} score like HIGH, "
        f"{un_counts['MEDIUM_CONFIDENCE']} like MEDIUM, "
        f"{un_counts['LOW_CONFIDENCE']} like LOW, "
        f"{un_counts['REJECTED_DATA_LIKE']} like REJECTED_DATA_LIKE",
        f"- CFG coverage of `.text`: {doc['covered_bytes']} / {doc['text_size']} bytes "
        f"({doc['covered_bytes'] / doc['text_size']:.1%})",
        "",
        "Coverage counts bytes of instructions that belong to a reachable HIGH or MEDIUM function, "
        "including its switch targets. LOW and rejected entries do not add coverage.",
        "",
        "An unreachable candidate is a frame prologue, or the first instruction after a run of at least four `int3` bytes, "
        "that the direct-call walk never entered and that is not already inside a walked body. "
        "The short window is only a sketch. Those addresses were not generated. "
        "`function-map.json` stores the first 5000 of them.",
        "",
        "## Examples",
        "",
    ]
    for label in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE", "LOW_CONFIDENCE", "REJECTED_DATA_LIKE"):
        rows = [row for row in graph.values() if row["label"] == label]
        rows.sort(key=lambda row: row["va"])
        lines.append(f"### {label}")
        lines.append("")
        if not rows:
            lines.append("None.")
            lines.append("")
            continue
        lines.append("| Function | Score | Insns | Why |")
        lines.append("| --- | --- | --- | --- |")
        for row in rows[:12]:
            why = "; ".join(row["reasons"][:3])
            lines.append(f"| {hx(row['va'])} | {row['score']} | {row.get('insns', 0)} | {why} |")
        if len(rows) > 12:
            lines.append("")
            lines.append(f"{len(rows) - 12} more are in `function-map.json`.")
        lines.append("")
    path_md = os.path.join(out_dir, "function-map.md")
    with open(path_md, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    stored = []
    for row in sorted(graph.values(), key=lambda row: row["va"]):
        stored.append({
            "va": hx(row["va"]),
            "label": row["label"],
            "score": row["score"],
            "reasons": row["reasons"],
            "reachable": True,
            "insns": row.get("insns", 0),
            "calls": [hx(v) for v in row.get("calls") or []],
            "tails": [hx(v) for v in row.get("tails") or []],
            "switches": row.get("switches", 0),
        })
    for row in doc["unreachable"][:5000]:
        stored.append({
            "va": hx(row["va"]),
            "label": row["label"],
            "score": row["score"],
            "reasons": row["reasons"],
            "reachable": False,
            "insns": row.get("insns", 0),
            "calls": [],
            "tails": [],
            "switches": 0,
        })
    body = {
        "seeds": doc["seeds"],
        "reachable": reachable,
        "counts": dict(counts),
        "unreachable_candidates": len(doc["unreachable"]),
        "unreachable_counts": dict(un_counts),
        "covered_bytes": doc["covered_bytes"],
        "text_size": doc["text_size"],
        "data_cfg_rejected": [
            {"va": hx(item["va"]), "mnemonic": item["mnemonic"]}
            for item in doc.get("data_cfg_rejected") or []
        ],
        "phase4_high_confidence": 6604,
        "classification_note": (
            "Phase 4 scored 6604 HIGH_CONFIDENCE functions from the linear walk. "
            "Phase 5 keeps that score, then rejects a function whose lifter CFG reaches embedded data. "
            "Generation statistics for the original 6604 are in high-confidence.md and are not recomputed from the reduced set."
        ),
        "functions": stored,
    }
    path_json = os.path.join(out_dir, "function-map.json")
    with open(path_json, "w", encoding="utf-8") as fh:
        json.dump(body, fh)
        fh.write("\n")
    print(f"  wrote {path_md}", file=sys.stderr)
    return counts


def generate_high(info, vas, clang):
    high = sorted(vas)
    print(f"  generating {len(high)} HIGH_CONFIDENCE functions", file=sys.stderr)
    lifter = ucg.make_lifter(info["bytes"], info["text_va"])
    out_dir = os.path.join(ROOT, "generated", "undercover", "high")
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    t0 = time.time()
    for index, va in enumerate(high, 1):
        result = ucg.lift_function(lifter, info, va)
        result["cats"] = ["high"]
        result["incoming"] = 0
        if result["ok"]:
            path = os.path.join(out_dir, f"sub_{va:08x}.c")
            ucg.write_c(path, result["code"], ucg.callee_vas(result["code"]))
            result["path"] = path
            result["source_bytes"] = os.path.getsize(path)
        else:
            result["path"] = ""
            result["source_bytes"] = 0
        rows.append(result)
        if index % 200 == 0:
            ok = sum(1 for row in rows if row["ok"])
            print(f"    generated {ok}/{index} ({time.time() - t0:.0f}s)", file=sys.stderr)
    print("  compiling", file=sys.stderr)
    t1 = time.time()
    compile_rows(clang, rows)
    compile_seconds = time.time() - t1
    return rows, compile_seconds


def compile_rows(clang, rows):
    pending = [row for row in rows if row["ok"]]
    for row in rows:
        if not row["ok"]:
            row["compiled"] = False
            row["compiler_error"] = ""
    obj_dir = os.path.join(ROOT, "generated", "undercover", "high", "obj")
    os.makedirs(obj_dir, exist_ok=True)
    # Shards of 16. A failing shard is compiled one function at a time so the failure stays visible.
    shard = 16
    for start in range(0, len(pending), shard):
        group = pending[start:start + shard]
        if len(group) == 1:
            _compile_single(clang, group[0], obj_dir)
            continue
        ok, err = _compile_many(clang, group, obj_dir, start // shard)
        if ok:
            for row in group:
                row["compiled"] = True
                row["compiler_error"] = ""
        else:
            for row in group:
                _compile_single(clang, row, obj_dir)


def _compile_single(clang, row, obj_dir):
    obj = os.path.join(obj_dir, os.path.basename(row["path"])[:-2] + ".o")
    ok, err = ucg.compile_one(clang, row["path"], obj)
    row["compiled"] = ok
    row["compiler_error"] = "" if ok else err[:2000]
    if not ok and os.path.exists(obj):
        os.remove(obj)


def _compile_many(clang, group, obj_dir, index):
    work = os.path.join(obj_dir, f"shard_{index:04d}.c")
    parts = []
    decls = []
    for row in group:
        text = open(row["path"], encoding="utf-8").read()
        # Drop the banner and the harness include; the shard includes them once.
        body = text.split('#include "uc_harness.h"', 1)[-1]
        decls.append(body)
    shard = "\n".join([
        "/* Generated shard. Do not commit. */",
        '#include "uc_harness.h"',
        "",
        "\n".join(decls),
        "",
    ])
    with open(work, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(shard)
    obj = os.path.join(obj_dir, f"shard_{index:04d}.o")
    return ucg.compile_one(clang, work, obj)


def write_generation(rows, compile_seconds, out_dir):
    attempted = len(rows)
    generated = [row for row in rows if row["ok"]]
    compiled = [row for row in generated if row.get("compiled")]
    failed = [row for row in rows if not row["ok"]]
    compile_failed = [row for row in generated if not row.get("compiled")]
    reasons = collections.Counter((row["failure"]["mnemonic"] or row["failure"]["reason"]) for row in failed)
    source = sum(row.get("source_bytes") or 0 for row in generated)
    tus = len(generated)
    indirect = sum(len((row.get("facts") or {}).get("indirect_calls") or []) for row in rows)
    external = [edge for row in rows for edge in ((row.get("facts") or {}).get("external") or [])]
    switches = sum(len((row.get("facts") or {}).get("switches") or []) for row in rows)
    rejected = sum(len((row.get("facts") or {}).get("rejected_switches") or []) for row in rows)
    lines = [
        "# High-confidence generation",
        "",
        "This is the exact Phase 4 HIGH_CONFIDENCE address list when `--from-list` is used. MEDIUM and LOW roots were not translated.",
        "A later reclassification does not remove a failure from this percentage.",
        "Generated C is under `generated/undercover/high/` and is not committed.",
        "The game was not executed.",
        "",
        f"- Functions attempted: {attempted}",
        f"- Functions generated: {len(generated)}",
        f"- Generation success: {len(generated) / attempted:.1%}" if attempted else "- Generation success: n/a",
        f"- Functions compiled: {len(compiled)}",
        f"- Compilation success: {len(compiled) / len(generated):.1%}" if generated else "- Compilation success: n/a",
        f"- Compiler failures: {len(compile_failed)}",
        f"- Unresolved indirect calls: {indirect}",
        f"- Unresolved external direct edges: {len(external)}",
        f"- Recognized switches: {switches}",
        f"- Rejected switches: {rejected}",
        f"- Generated source size: {source} bytes",
        f"- Translation units: {tus}",
        f"- Compile time: {compile_seconds:.0f}s",
        "",
        "## Generation failures",
        "",
    ]
    if not reasons:
        lines.append("None.")
    else:
        for name, count in reasons.most_common():
            lines.append(f"- `{name}`: {count}")
        lines.append("")
        lines.append("| Function | Mnemonic | Reason |")
        lines.append("| --- | --- | --- |")
        for row in failed:
            item = row["failure"]
            lines.append(f"| {ucg.hx(row['va'])} | `{item['mnemonic']}` | {item['reason']} |")
    lines += ["", "## Compiler failures", ""]
    if not compile_failed:
        lines.append("None.")
    else:
        for row in compile_failed:
            lines.append(f"### {ucg.hx(row['va'])}")
            lines.append("")
            lines.append("```")
            lines.append((row.get("compiler_error") or "unknown").rstrip())
            lines.append("```")
            lines.append("")
    lines.append("")
    path = os.path.join(out_dir, "high-confidence.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    summary = {
        "attempted": attempted,
        "generated": len(generated),
        "compiled": len(compiled),
        "compiler_failures": len(compile_failed),
        "fail_mnemonics": reasons.most_common(),
        "indirect_calls": indirect,
        "external_edges": len(external),
        "switches": switches,
        "rejected_switches": rejected,
        "source_bytes": source,
        "translation_units": tus,
        "compile_seconds": round(compile_seconds, 1),
        "failed_functions": [ucg.hx(row["va"]) for row in failed],
        "compiler_failed_functions": [ucg.hx(row["va"]) for row in compile_failed],
    }
    with open(os.path.join(out_dir, "high-confidence.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    return summary


def load_address_list(path):
    addrs = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        addrs.append(int(line.split()[0], 16))
    return addrs


def main(argv):
    if len(argv) < 2:
        die("usage: uc_funcmap.py <nfs.exe> [--generate | --from-list addresses.txt]")
    exe = argv[1]
    do_gen = "--generate" in argv
    list_path = ""
    if "--from-list" in argv:
        index = argv.index("--from-list")
        if index + 1 >= len(argv):
            die("--from-list needs a path")
        list_path = argv[index + 1]
    info = uca.read_inputs(exe)
    info["path"] = os.path.abspath(exe)
    out_dir = uca.assert_output_ok(os.path.join(ROOT, "analysis", "undercover"), exe)
    uca.assert_output_ok(os.path.join(ROOT, "generated", "undercover"), exe)
    if list_path:
        addrs = load_address_list(list_path)
        clang = ucg.find_clang()
        if not clang:
            die("clang was not found")
        print(f"  generating the saved list ({len(addrs)} addresses)", file=sys.stderr)
        rows, compile_seconds = generate_high(info, addrs, clang)
        summary = write_generation(rows, compile_seconds, out_dir)
        print(
            f"  high generated {summary['generated']}/{summary['attempted']} "
            f"compiled {summary['compiled']}/{summary['generated']}",
            file=sys.stderr,
        )
        return
    t0 = time.time()
    doc = build(info)
    counts = write_reports(doc, out_dir)
    print(
        f"  HIGH {counts['HIGH_CONFIDENCE']} MEDIUM {counts['MEDIUM_CONFIDENCE']} "
        f"LOW {counts['LOW_CONFIDENCE']} REJECTED {counts['REJECTED_DATA_LIKE']} "
        f"({time.time() - t0:.0f}s)",
        file=sys.stderr,
    )
    if not do_gen:
        return
    clang = ucg.find_clang()
    if not clang:
        die("clang was not found")
    vas = [va for va, row in doc["graph"].items() if row["label"] == "HIGH_CONFIDENCE"]
    rows, compile_seconds = generate_high(info, vas, clang)
    summary = write_generation(rows, compile_seconds, out_dir)
    print(
        f"  high generated {summary['generated']}/{summary['attempted']} "
        f"compiled {summary['compiled']}/{summary['generated']}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main(sys.argv)
