#!/usr/bin/env python3
"""Isolated static-recompilation experiment for Need for Speed Undercover.

Reads only the ordinary .text section of a user-owned nfs.exe. Does not use
the PE entry point, does not read Stext, Sitext, Srdata, Sdata, Sidata or
.securom, and does not modify tools/lift.py or the NFSU2 generator.

  python tools/uc_gen.py <nfs.exe>
  python tools/uc_gen.py <nfs.exe> --sample-only
  python tools/uc_gen.py <nfs.exe> --smoke 0x0087B350

Generated C is written under generated/undercover/ and is gitignored.
Statistics are written under analysis/undercover/.
"""
import collections, json, os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
import uc_code_analyze as uca
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import (
    X86_OP_IMM, X86_OP_REG, X86_OP_MEM,
    X86_REG_ECX, X86_REG_EDX,
    X86_GRP_FPU, X86_GRP_SSE1, X86_GRP_SSE2,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTECTED = ("Stext", "Sitext", "Srdata", "Sdata", "Sidata", ".securom")
REQUIRED = (0x0087B350, 0x00A0AF20, 0x00686030)
WATCH = (
    "lock xadd", "lock cmpxchg", "lock cmpxchg8b",
    "movmskps", "pshuflw", "psrldq", "pslldq",
    "fnsave", "frstor", "fnstenv", "fsave", "fstenv",
)
PRIVILEGED = {
    "in", "out", "insb", "insw", "insd", "outsb", "outsw", "outsd",
    "cli", "sti", "hlt", "clts", "invd", "wbinvd", "lgdt", "lidt", "lldt", "ltr",
    "lmsw", "smsw", "invlpg", "sysenter", "sysexit", "syscall", "sysret",
    "rdmsr", "wrmsr", "rdpmc", "iret", "iretd", "into", "bound", "arpl",
    "ud0", "ud1", "ud2",
}
CLANG_GUESSES = (
    os.environ.get("CLANG") or "",
    "clang",
    r"C:\Program Files\Unity\Hub\Editor\6000.6.7f1\Editor\Data\PlaybackEngines\WebGLSupport\BuildTools\Emscripten\llvm\clang.exe",
)


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


def hx(n):
    return f"0x{n & 0xffffffff:08X}"


def make_lifter(blob, base):
    os.environ["JTSWITCH"] = "1"
    os.environ.pop("FTOL2INL", None)
    os.environ.pop("FLAGABI", None)
    os.environ.pop("LREGS", None)
    return lift.RawLifter(blob, base=base, comments=False)


def find_clang():
    for cand in CLANG_GUESSES:
        if not cand:
            continue
        path = cand if os.path.isfile(cand) else shutil.which(cand)
        if path:
            return path
    return None


def sweep_entries(blob, base):
    """Instruction starts and direct-call counts. No other section is decoded."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    n = len(blob)
    starts = bytearray(n)
    incoming = collections.Counter()
    notable = collections.Counter()
    off = 0
    decoded = 0
    last = 0
    while off < n:
        if off - last >= 0x100000:
            print(f"  sweep {off / n:.0%} ({decoded} instructions)", file=sys.stderr)
            last = off
        insns = list(md.disasm(blob[off:off + 65536], base + off))
        if not insns:
            off += 1
            continue
        for insn in insns:
            rel = insn.address - base
            if 0 <= rel < n:
                starts[rel] = 1
            decoded += 1
            if insn.mnemonic in ("ret", "repz ret", "rep ret"):
                notable[insn.mnemonic] += 1
            if insn.mnemonic != "call" or not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != X86_OP_IMM:
                continue
            target = op.imm & 0xffffffff
            if base <= target < base + n:
                incoming[target] += 1
        off = insns[-1].address + insns[-1].size - base
    strong = [base + i for i in range(n) if starts[i] and incoming[base + i]]
    print(f"  sweep done: {decoded} instructions, {len(strong)} strong roots", file=sys.stderr)
    return strong, incoming, notable


def _mem_disp(op):
    return op.mem.disp


def _table_jmp(insn):
    if insn.mnemonic != "jmp" or not insn.operands:
        return False
    op = insn.operands[0]
    if op.type != X86_OP_MEM or op.size != 4:
        return False
    mem = op.mem
    return not mem.segment and not mem.base and bool(mem.index) and mem.scale == 4


def _convention(block, index, info):
    """A label, not a proof. Import names are not recovered from .text."""
    insn = block[index]
    op = insn.operands[0]
    if op.type == X86_OP_IMM:
        return "unknown"
    if op.type == X86_OP_MEM:
        mem = op.mem
        disp = mem.disp
        iat = info.get("iat")
        if not mem.base and not mem.index and iat and iat[0] <= (disp & 0xffffffff) < iat[1]:
            return "import-unclassified"
        if mem.base and not mem.index and 0 < disp <= 0x400 and disp % 4 == 0:
            return "likely-thiscall"
        return "unknown"
    if op.type != X86_OP_REG:
        return "unknown"
    wrote_ecx = wrote_edx = False
    for prev in reversed(block[:index]):
        if prev.mnemonic in ("call", "jmp", "ret", "retf"):
            break
        if prev.mnemonic not in ("mov", "lea", "pop") or not prev.operands:
            continue
        dest = prev.operands[0]
        if dest.type != X86_OP_REG:
            continue
        if dest.reg == X86_REG_ECX:
            wrote_ecx = True
        elif dest.reg == X86_REG_EDX:
            wrote_edx = True
    if wrote_ecx and wrote_edx:
        return "possible-fastcall"
    if wrote_ecx:
        return "likely-thiscall"
    return "unknown"


def inspect_blocks(L, info):
    """Control-flow facts for one discovered function. Does not follow edges."""
    external = []
    indirect_calls = []
    indirect_jmps = []
    watch = []
    privileged = []
    conventions = collections.Counter()
    internal_calls = 0
    x87 = sse = 0
    insns = 0
    truncated_block = False
    recognized = dict(getattr(L, "jtab", {}) or {})
    for ins in L.last_blocks.values():
        if len(ins) > 4000:
            truncated_block = True
        for index, insn in enumerate(ins):
            insns += 1
            groups = set(insn.groups)
            if X86_GRP_FPU in groups:
                x87 += 1
            if X86_GRP_SSE1 in groups or X86_GRP_SSE2 in groups:
                sse += 1
            mnemonic = insn.mnemonic
            if mnemonic in WATCH:
                watch.append({
                    "address": hx(insn.address),
                    "mnemonic": mnemonic,
                    "operands": insn.op_str,
                    "raw": bytes(insn.bytes).hex(),
                })
            if mnemonic in PRIVILEGED or mnemonic.split(" ", 1)[-1] in PRIVILEGED:
                privileged.append(hx(insn.address) + " " + mnemonic)
            if mnemonic == "call" and insn.operands:
                op = insn.operands[0]
                conv = _convention(ins, index, info)
                if op.type == X86_OP_IMM:
                    target = op.imm & 0xffffffff
                    if L.in_text(target):
                        internal_calls += 1
                        if _import_thunk(info, target):
                            conv = "import-thunk"
                    else:
                        external.append(_edge(info, insn, "call", target))
                else:
                    indirect_calls.append({
                        "address": hx(insn.address),
                        "form": f"{mnemonic} {insn.op_str}",
                        "convention": conv,
                    })
                conventions[conv] += 1
            elif mnemonic == "jmp" and insn.operands:
                op = insn.operands[0]
                if op.type == X86_OP_IMM:
                    target = op.imm & 0xffffffff
                    if not L.in_text(target):
                        external.append(_edge(info, insn, "jmp", target))
                else:
                    indirect_jmps.append({
                        "address": hx(insn.address),
                        "form": f"{mnemonic} {insn.op_str}",
                        "switch": insn.address in recognized,
                    })
            elif mnemonic.startswith("j") and insn.operands and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm & 0xffffffff
                if not L.in_text(target):
                    external.append(_edge(info, insn, "jcc", target))
    rejected = []
    for ins in L.last_blocks.values():
        for insn in ins:
            if _table_jmp(insn) and insn.address not in recognized:
                rejected.append({
                    "address": hx(insn.address),
                    "form": f"{insn.mnemonic} {insn.op_str}",
                })
    switches = []
    for addr, tab in recognized.items():
        _reg, disp, targets = tab
        switches.append({
            "jmp": hx(addr),
            "table": hx(disp),
            "entries": len(targets),
        })
    return {
        "insns": insns,
        "blocks": len(L.last_blocks),
        "x87": x87,
        "sse": sse,
        "internal_calls": internal_calls,
        "external": external,
        "indirect_calls": indirect_calls,
        "indirect_jmps": indirect_jmps,
        "switches": switches,
        "rejected_switches": rejected,
        "conventions": dict(conventions),
        "watch": watch,
        "privileged": privileged[:8],
        "privileged_count": len(privileged),
        "truncated_block": truncated_block,
    }


def _import_thunk(info, target):
    """A direct callee whose first instruction is jmp dword ptr [abs] outside .text."""
    base = info["text_va"]
    blob = info["bytes"]
    off = target - base
    if not 0 <= off < len(blob) - 6:
        return False
    cached = info.setdefault("thunk_cache", {})
    if target in cached:
        return cached[target]
    md = info.setdefault("md", Cs(CS_ARCH_X86, CS_MODE_32))
    md.detail = True
    hit = False
    decoded = list(md.disasm(blob[off:off + 8], target))
    if decoded:
        insn = decoded[0]
        if insn.mnemonic == "jmp" and insn.operands and insn.operands[0].type == X86_OP_MEM:
            mem = insn.operands[0].mem
            slot = mem.disp & 0xffffffff
            if not mem.base and not mem.index and not (base <= slot < base + len(blob)):
                hit = True
    cached[target] = hit
    return hit


def _edge(info, insn, kind, target):
    name = uca.section_of(info["sections"], target)
    return {
        "address": hx(insn.address),
        "kind": kind,
        "target": hx(target),
        "section": name or "unmapped",
        "protected": name in PROTECTED,
        "form": f"{insn.mnemonic} {insn.op_str}",
    }


def trace_insn(L):
    if not hasattr(L, "_insn_orig"):
        L._insn_orig = L.insn
    orig = L._insn_orig
    box = {}

    def insn(i, targets):
        box["i"] = i
        return orig(i, targets)

    L.insn = insn
    return box


def failure_record(func, insn, reason):
    if insn is None:
        return {
            "function": hx(func),
            "address": hx(func),
            "raw": "",
            "mnemonic": "",
            "operands": "",
            "reason": reason,
        }
    return {
        "function": hx(func),
        "address": hx(insn.address),
        "raw": bytes(insn.bytes).hex(),
        "mnemonic": insn.mnemonic,
        "operands": insn.op_str,
        "reason": reason,
    }


def lift_function(L, info, va):
    box = trace_insn(L)
    try:
        code, _calls = L.lift(va)
    except lift.Unsupported as exc:
        return {
            "va": va,
            "ok": False,
            "code": None,
            "failure": failure_record(va, box.get("i"), str(exc) or "unsupported"),
            "facts": _facts_after_error(L, info),
        }
    except Exception as exc:
        return {
            "va": va,
            "ok": False,
            "code": None,
            "failure": failure_record(va, box.get("i"), f"{type(exc).__name__}: {exc}"),
            "facts": _facts_after_error(L, info),
        }
    facts = inspect_blocks(L, info)
    facts["truncated"] = int(getattr(L, "truncated", 0))
    return {"va": va, "ok": True, "code": code, "failure": None, "facts": facts}


def _facts_after_error(L, info):
    if not getattr(L, "last_blocks", None):
        return None
    try:
        facts = inspect_blocks(L, info)
    except Exception:
        return None
    facts["truncated"] = int(getattr(L, "truncated", 0))
    return facts


def profile_all(L, info, entries):
    out = []
    t0 = time.time()
    for n, va in enumerate(entries, 1):
        blocks, _calls = L.discover(va)
        L.last_blocks = blocks
        facts = inspect_blocks(L, info)
        facts["va"] = va
        facts["incoming"] = 0
        out.append(facts)
        if n % 1000 == 0:
            print(f"  profiled {n}/{len(entries)} ({time.time() - t0:.0f}s)", file=sys.stderr)
    print(f"  profiled {len(entries)} ({time.time() - t0:.0f}s)", file=sys.stderr)
    return out


def _tag(chosen, facts, cat):
    row = chosen.get(facts["va"])
    if row is None:
        chosen[facts["va"]] = {"facts": facts, "cats": [cat]}
    elif cat not in row["cats"]:
        row["cats"].append(cat)


def select_sample(profiles, incoming):
    for facts in profiles:
        facts["incoming"] = incoming[facts["va"]]
    chosen = {}
    by_va = {p["va"]: p for p in profiles}
    for va in REQUIRED:
        if va in by_va:
            _tag(chosen, by_va[va], "required")
    hot = sorted(profiles, key=lambda p: (-p["incoming"], p["va"]))[:15]
    for facts in hot:
        _tag(chosen, facts, "highly-called")

    def evenly(pool, count, cat):
        pool = sorted(pool, key=lambda p: p["va"])
        if not pool:
            return
        if len(pool) <= count:
            for facts in pool:
                _tag(chosen, facts, cat)
            return
        for i in range(count):
            _tag(chosen, pool[int(i * len(pool) / count)], cat)

    evenly([p for p in profiles if 0 < p["insns"] <= 16], 12, "small")
    evenly([p for p in profiles if 48 <= p["insns"] <= 200], 12, "medium")
    for facts in sorted((p for p in profiles if p["insns"] >= 400), key=lambda p: -p["insns"])[:12]:
        _tag(chosen, facts, "large")
    for facts in sorted((p for p in profiles if p["x87"] >= 8), key=lambda p: -p["x87"])[:12]:
        _tag(chosen, facts, "x87")
    for facts in sorted((p for p in profiles if p["sse"] >= 8), key=lambda p: -p["sse"])[:12]:
        _tag(chosen, facts, "sse")
    evenly([p for p in profiles if p["switches"]], 12, "switch")
    evenly([p for p in profiles if p["indirect_calls"]], 12, "indirect")
    if len(chosen) < 100:
        for facts in sorted(profiles, key=lambda p: p["va"]):
            if 16 < facts["insns"] < 400:
                _tag(chosen, facts, "fill")
            if len(chosen) >= 100:
                break
    return [chosen[va] for va in sorted(chosen)]


def write_c(path, code, callees):
    lines = [
        "/* Generated by tools/uc_gen.py. Local experiment output. Do not commit. */",
        '#include "uc_harness.h"',
        "",
    ]
    for va in sorted(set(callees)):
        lines.append(f"void sub_{va:08x}(CPU *c);")
    lines.append("")
    lines.append(code)
    lines.append("")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))


def callee_vas(code):
    found = []
    token = "sub_"
    start = 0
    while True:
        i = code.find(token, start)
        if i < 0:
            return found
        hexes = code[i + 4:i + 12]
        if len(hexes) == 8 and all(c in "0123456789abcdef" for c in hexes):
            found.append(int(hexes, 16))
        start = i + 4


def compile_one(clang, src, obj):
    cmd = [
        clang, "-c", "-std=c11",
        "-I", os.path.join(ROOT, "tests", "uc_host"),
        "-I", os.path.join(ROOT, "tests"),
        "-I", os.path.join(ROOT, "runtime"),
        "-o", obj, src,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    err = (proc.stderr or "") + (proc.stdout or "")
    return proc.returncode == 0, err.strip()


def compile_sample(clang, rows):
    obj_dir = os.path.join(ROOT, "generated", "undercover", "sample", "obj")
    os.makedirs(obj_dir, exist_ok=True)
    for row in rows:
        if not row["ok"]:
            row["compiled"] = False
            row["compiler_error"] = ""
            continue
        src = row["path"]
        obj = os.path.join(obj_dir, os.path.basename(src)[:-2] + ".o")
        ok, err = compile_one(clang, src, obj)
        row["compiled"] = ok
        row["compiler_error"] = "" if ok else err[:4000]
        if not ok and os.path.exists(obj):
            os.remove(obj)


def _sum_counter(rows, key):
    total = collections.Counter()
    for row in rows:
        facts = row.get("facts") or {}
        total.update(facts.get(key) or {})
    return dict(total)


REAL_GAP_MNEMONICS = (
    "fnsave", "frstor", "fnstenv", "fsave", "fstenv",
)


def real_gap_names(rows):
    found = []
    for row in rows:
        failure = row.get("failure")
        if not failure:
            continue
        name = failure["mnemonic"]
        if name in REAL_GAP_MNEMONICS and name not in found:
            found.append(name)
    return found


def recommend(sample, full, top_failure="", real_gaps=()):
    attempted = sample["attempted"]
    generated = sample["generated"]
    compiled = sample["compiled"]
    gen_rate = generated / attempted if attempted else 0
    comp_rate = compiled / generated if generated else 0
    body = full if full is not None else None
    full_rate = None
    if body is not None and body["attempted"]:
        full_rate = body["generated"] / body["attempted"]
    protected = sample["protected_edges"]
    internal = sample["internal_calls"]
    if attempted == 0 or gen_rate < 0.50 or comp_rate < 0.50:
        return (
            "RECOMPILATION ARCHITECTURE NOT SUITABLE",
            "The sample does not produce C that the existing lifter and CPU header can carry. "
            f"Generation {generated}/{attempted}, compile {compiled}/{generated}.",
        )
    if protected > max(5, internal // 100):
        return (
            "RECOMPILATION ARCHITECTURE NOT SUITABLE",
            "Reached sample functions branch into protected sections often enough that "
            "a .text-only translation would not be a closed body.",
        )
    if real_gaps:
        names = ", ".join(f"`{name}`" for name in real_gaps)
        return (
            "ADAPT LIFTER FIRST",
            "Functions whose bodies look like compiler output lift and, once the compile harness "
            "declares the math helpers the lifter emits, they compile. "
            f"Real refusals in this sample are {names}. "
            "Other refusals (`aaa`, `les`, `lcall`, `ljmp`, and similar) sit in call targets whose "
            "bytes are not compiler code; a linear-sweep call count made them look popular. "
            "A pass over all 13,090 targets would mix those roots with real functions and would "
            "still drop every function that uses the missing opcodes. "
            "Lower the missing opcodes before translating the whole section.",
        )
    rate = full_rate if full_rate is not None else gen_rate
    if rate >= 0.90 and comp_rate >= 0.90:
        return (
            "PROCEED TO FULL .TEXT RECOMPILATION",
            "Direct-call roots inside ordinary .text lift and compile with the existing architecture. "
            "The remaining gaps are individual opcodes and the unresolved protected startup, "
            "not a failed control-flow model.",
        )
    detail = f" The most common refusal was `{top_failure}`." if top_failure else ""
    return (
        "ADAPT LIFTER FIRST",
        "The control-flow shape is usable, but unsupported opcodes or compile failures "
        "are common enough that a full translation should wait until those forms are "
        "lowered deliberately." + detail,
    )


def write_failure_reports(rows, path_md, path_json):
    failures = []
    for row in rows:
        if row.get("failure"):
            failures.append(row["failure"])
        facts = row.get("facts") or {}
        for item in facts.get("watch") or []:
            if row["ok"]:
                item = dict(item)
                item["function"] = hx(row["va"])
                item["outcome"] = "present in a function the lifter accepted"
                failures.append({
                    "function": item["function"],
                    "address": item["address"],
                    "raw": item["raw"],
                    "mnemonic": item["mnemonic"],
                    "operands": item["operands"],
                    "reason": "watchlist instruction was lowered rather than rejected; see the lifter",
                })
    doc = {
        "description": "Generation failures are instructions the lifter refused. "
                       "Watchlist instructions that were lowered are listed separately so a no-op "
                       "or an existing lowering is not counted as a failed function.",
        "failures": [row["failure"] for row in rows if row.get("failure")],
        "watchlist_in_lifted_functions": [
            dict(item, function=hx(row["va"]))
            for row in rows if row["ok"]
            for item in (row.get("facts") or {}).get("watch") or []
        ],
    }
    with open(path_json, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    lines = [
        "# Undercover generation failures",
        "",
        "Genuine failures are instructions `Lifter.lift` refused. "
        "Unsupported opcodes were not replaced with NOPs. "
        "The existing lifter already emits a comment for privileged instructions; those are counted in the feasibility report and are not listed here as successes of translation.",
        "",
        f"Failed functions: {len(doc['failures'])}",
        "",
        "| Function | Instruction | Bytes | Mnemonic | Operands | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    shown = doc["failures"][:80]
    for item in shown:
        lines.append(
            f"| {item['function']} | {item['address']} | `{item['raw']}` | `{item['mnemonic']}` | `{item['operands']}` | {item['reason']} |"
        )
    if len(doc["failures"]) > len(shown):
        lines.append("")
        lines.append(f"The JSON file has the other {len(doc['failures']) - len(shown)} failures.")
    lines.append("")
    lines.append("## Watchlist instructions inside functions the lifter accepted")
    lines.append("")
    if not doc["watchlist_in_lifted_functions"]:
        lines.append("None of the watched opcodes occurred in a function that generated successfully.")
    else:
        lines.append("| Function | Instruction | Mnemonic | Operands |")
        lines.append("| --- | --- | --- | --- |")
        for item in doc["watchlist_in_lifted_functions"][:80]:
            lines.append(f"| {item['function']} | {item['address']} | `{item['mnemonic']}` | `{item['operands']}` |")
    lines.append("")
    with open(path_md, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))


DATA_LIKE_MNEMONICS = (
    "aaa", "aas", "daa", "das", "aam", "aad", "salc", "into", "arpl", "bound",
    "les", "lds", "lcall", "ljmp", "iret", "iretd",
)


def write_feasibility(path, info, sample_rows, clang, verdict, why, full, elapsed, phase=""):
    attempted = len(sample_rows)
    generated = [r for r in sample_rows if r["ok"]]
    compiled = [r for r in generated if r.get("compiled")]
    failed = [r for r in sample_rows if not r["ok"]]
    compile_failed = [r for r in generated if not r.get("compiled")]
    external = [e for r in sample_rows for e in ((r.get("facts") or {}).get("external") or [])]
    protected = [e for e in external if e["protected"]]
    indirect = sum(len((r.get("facts") or {}).get("indirect_calls") or []) for r in sample_rows)
    switches = sum(len((r.get("facts") or {}).get("switches") or []) for r in sample_rows)
    rejected = sum(len((r.get("facts") or {}).get("rejected_switches") or []) for r in sample_rows)
    source = sum(r.get("source_bytes") or 0 for r in generated)
    conventions = collections.Counter()
    for row in sample_rows:
        conventions.update((row.get("facts") or {}).get("conventions") or {})
    internal = sum((r.get("facts") or {}).get("internal_calls") or 0 for r in sample_rows)
    privileged = sum((r.get("facts") or {}).get("privileged_count") or 0 for r in sample_rows)
    cats = collections.Counter(cat for r in sample_rows for cat in r["cats"])
    lines = [
        "# Undercover recompilation feasibility",
        "",
        "Sample of `.text` roots taken from the phase 3 address list. "
        "The PE entry point was not used. Protected sections were not disassembled or followed. "
        + (phase or "Generated C was compiled and was not committed."),
        "",
        f"- Input: `{info['path']}`",
        f"- `.text`: {hx(info['text_va'])} .. {hx(info['text_va'] + info['text_size'] - 1)} ({info['text_size']} bytes)",
        f"- Clang: `{clang or 'not found'}`",
        f"- Elapsed: {elapsed:.0f}s",
        "",
        "## Sample",
        "",
        f"- Functions attempted: {attempted}",
        f"- Functions generated: {len(generated)}",
        f"- Generation failures: {len(failed)}",
        f"- Functions compiled: {len(compiled)}",
        f"- Compiler failures: {len(compile_failed)}",
        f"- Generated source size: {source} bytes",
        f"- Unresolved direct edges leaving `.text`: {len(external)}",
        f"- Of those, into a protected section: {len(protected)}",
        f"- Unresolved indirect calls: {indirect}",
        f"- Recognized switch tables: {switches}",
        f"- Rejected `[reg*4]` jumps: {rejected}",
        f"- Direct calls that stay in `.text`: {internal}",
        f"- Privileged instructions inside these CFGs (the lifter comments them out; they are not counted as translated): {privileged}",
        f"- Return forms in the linear sweep of `.text`: {info.get('return_forms') or {}}",
        "",
        "Categories (a function may be in more than one):",
        "",
    ]
    for name, count in sorted(cats.items()):
        lines.append(f"- {name}: {count}")
    lines += [
        "",
        "| Function | Insns | In | Categories | Generated | Compiled |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in sample_rows:
        facts = row.get("facts") or {}
        lines.append(
            f"| {hx(row['va'])} | {facts.get('insns', 0)} | {row.get('incoming', 0)} | "
            f"{', '.join(row['cats'])} | {'yes' if row['ok'] else 'no'} | "
            f"{'yes' if row.get('compiled') else 'no'} |"
        )
    lines += [
        "",
        "## Unsupported instructions",
        "",
    ]
    if not failed:
        lines.append("No sample function was rejected by the lifter.")
    else:
        reasons = collections.Counter((r["failure"]["mnemonic"] or r["failure"]["reason"]) for r in failed)
        for name, count in reasons.most_common():
            lines.append(f"- `{name}`: {count}")
        lines.append("")
        lines.append("Instruction-level records are in `generation-failures.md`.")
        lines.append("")
        genuine = []
        data_like = []
        other = []
        for row in failed:
            name = row["failure"]["mnemonic"] or row["failure"]["reason"]
            if name in REAL_GAP_MNEMONICS:
                genuine.append((row, name))
            elif name in DATA_LIKE_MNEMONICS:
                data_like.append((row, name))
            else:
                other.append((row, name))
        lines.append(
            f"Genuine unsupported instructions in compiler-shaped functions: {len(genuine)}. "
            f"Rejected likely-data roots: {len(data_like)}. "
            f"Other generation failures: {len(other)}."
        )
        lines.append("")
        if genuine:
            lines.append("Genuine gaps:")
            lines.append("")
            for row, name in genuine:
                lines.append(f"- {hx(row['va'])}: `{name}`")
            lines.append("")
        if data_like:
            lines.append("Likely-data roots (the failing opcode is not treated as a missing lifter feature):")
            lines.append("")
            for row, name in data_like:
                lines.append(f"- {hx(row['va'])}: `{name}`")
            lines.append("")
        seen = {name for _row, name in genuine + data_like + other}
        if "movmskps" in seen or "repz ret" in seen or "rep ret" in seen:
            lines.append(
                "`movmskps` and `repz ret` occur in functions that also contain ordinary compiler output "
                "(`push ebp; mov ebp, esp`, or the short `cmp` / `jne` / `rep ret` idiom)."
            )
        if data_like:
            lines.append(
                "`aaa`, `das`, `les`, `lcall`, `ljmp`, `iretd`, and `aad` occur in targets whose first bytes "
                "are not a compiler prologue. Those targets stay generation failures. They are not evidence "
                "that the lifter lacks those opcodes."
            )
    lines += ["", "## Calling conventions", ""]
    lines.append(
        "Sites are classified from the instruction shape only. "
        "A direct call inside `.text` has no symbol, so its convention stays unknown. "
        "`likely-thiscall` means a vtable-shaped `call [reg+4*n]` or a `call reg` whose preceding instructions write `ecx`. "
        "`possible-fastcall` means the preceding instructions write both `ecx` and `edx`. "
        "Neither is proof. No absolute call through the PE IAT was required for this classification."
    )
    lines.append("")
    if not conventions:
        lines.append("No call sites were classified.")
    else:
        for name, count in sorted(conventions.items()):
            lines.append(f"- {name}: {count}")
    lines += [
        "",
        "The NFSU2 runtime's `win32_call` always pops `4 * nargs` after an import, which is stdcall. "
        "Undercover imports MSVCR80 and MSVCP80, which are cdecl. "
        "This `.text` sample does not contain the absolute `call [IAT]` form that runtime rewrites, "
        "so that mismatch is not yet attached to a concrete call site. "
        "It still has to be fixed before any import in those DLLs can be called. "
        "`cpu.h` sizes its fast dispatch table for the NFSU2 `.text` span (`DISPATCH_TEXT_SIZE`), "
        "which ends before this image's `.text`.",
        "",
        "## Control flow outside .text",
        "",
    ]
    if not external:
        lines.append("No direct edge in the sample leaves `.text`.")
    else:
        grouped = collections.Counter((e["section"], e["kind"]) for e in external)
        lines.append("| Section | Kind | Edges |")
        lines.append("| --- | --- | --- |")
        for (section, kind), count in sorted(grouped.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {section} | {kind} | {count} |")
        lines.append("")
        lines.append("These were emitted as an indirect dispatch or as `unsupported_insn(..., \"branch-out\")` for a conditional branch. They were not followed.")
    if compile_failed:
        lines += ["", "## Compiler failures", ""]
        for row in compile_failed[:12]:
            first = (row.get("compiler_error") or "").splitlines()
            head = first[0] if first else "unknown"
            lines.append(f"- {hx(row['va'])}: {head}")
    if full is not None:
        lines += [
            "",
            "## Full strong-root pass",
            "",
            "Generated C for this pass is under `generated/undercover/full/` and is not committed.",
            "",
            f"- Roots attempted: {full['attempted']}",
            f"- Generated: {full['generated']}",
            f"- Generation failures: {full['failed']}",
            f"- Source bytes: {full['source_bytes']}",
            f"- Unresolved direct external edges: {full['external']}",
            f"- Protected-section edges: {full['protected']}",
            f"- Unresolved indirect calls: {full['indirect_calls']}",
            f"- Recognized switch tables: {full['switches']}",
            f"- Rejected switch-shaped jumps: {full['rejected_switches']}",
            f"- Shards: {full['shards']}",
            "",
        ]
        if full.get("fail_mnemonics"):
            lines.append("Failure mnemonics:")
            lines.append("")
            for name, count in full["fail_mnemonics"]:
                lines.append(f"- `{name}`: {count}")
            lines.append("")
    lines += [
        "## Verdict",
        "",
        why,
        "",
        verdict,
        "",
    ]
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))


def sample_stats(rows):
    external = [e for r in rows for e in ((r.get("facts") or {}).get("external") or [])]
    return {
        "attempted": len(rows),
        "generated": sum(1 for r in rows if r["ok"]),
        "compiled": sum(1 for r in rows if r.get("compiled")),
        "protected_edges": sum(1 for e in external if e["protected"]),
        "internal_calls": sum((r.get("facts") or {}).get("internal_calls") or 0 for r in rows),
    }


def run_sample(L, info, entries, incoming, clang, only):
    if only:
        chosen = []
        strong = set(entries) if entries else set(only)
        for va in only:
            if entries and va not in strong:
                print(f"  skip {hx(va)}: not a strong root", file=sys.stderr)
                continue
            chosen.append({"facts": {"va": va, "incoming": incoming.get(va, 0)}, "cats": ["only"]})
    else:
        print("  profiling strong roots", file=sys.stderr)
        profiles = profile_all(L, info, entries)
        chosen = select_sample(profiles, incoming)
    print(f"  lifting {len(chosen)} functions", file=sys.stderr)
    sample_dir = os.path.join(ROOT, "generated", "undercover", "sample")
    os.makedirs(sample_dir, exist_ok=True)
    rows = []
    for item in chosen:
        va = item["facts"]["va"]
        result = lift_function(L, info, va)
        result["cats"] = item["cats"]
        result["incoming"] = item["facts"].get("incoming", incoming.get(va, 0))
        result["source_bytes"] = 0
        result["path"] = ""
        if result["ok"]:
            path = os.path.join(sample_dir, f"sub_{va:08x}.c")
            write_c(path, result["code"], callee_vas(result["code"]))
            result["path"] = path
            result["source_bytes"] = os.path.getsize(path)
        result.pop("code", None)
        rows.append(result)
        state = "ok" if result["ok"] else result["failure"]["reason"]
        print(f"    {hx(va)} {state}", file=sys.stderr)
    if clang:
        print("  compiling", file=sys.stderr)
        compile_sample(clang, rows)
    else:
        for row in rows:
            row["compiled"] = False
            row["compiler_error"] = "clang was not found"
    return rows


def _shard_job(payload):
    idx, addrs, blob, base, out_dir, sections, iat = payload
    os.environ["JTSWITCH"] = "1"
    info = {"sections": sections, "iat": iat, "text_va": base, "bytes": blob}
    L = make_lifter(blob, base)
    parts = []
    generated = failed = source = 0
    external = protected = indirect = switches = rejected = 0
    reasons = collections.Counter()
    fail_rows = []
    for va in addrs:
        result = lift_function(L, info, va)
        facts = result.get("facts") or {}
        external += len(facts.get("external") or [])
        protected += sum(1 for e in facts.get("external") or [] if e["protected"])
        indirect += len(facts.get("indirect_calls") or [])
        switches += len(facts.get("switches") or [])
        rejected += len(facts.get("rejected_switches") or [])
        if not result["ok"]:
            failed += 1
            reasons[result["failure"]["mnemonic"] or result["failure"]["reason"]] += 1
            if len(fail_rows) < 40:
                fail_rows.append(result["failure"])
            continue
        generated += 1
        parts.append(result["code"])
    text = "\n".join(parts)
    path = os.path.join(out_dir, f"shard_{idx:04d}.c")
    header = "/* Generated by tools/uc_gen.py. Local experiment output. Do not commit. */\n#include \"uc_harness.h\"\n\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(header)
        fh.write(text)
        fh.write("\n")
    source = os.path.getsize(path)
    return {
        "generated": generated,
        "failed": failed,
        "source_bytes": source,
        "external": external,
        "protected": protected,
        "indirect_calls": indirect,
        "switches": switches,
        "rejected_switches": rejected,
        "reasons": dict(reasons),
        "fail_rows": fail_rows,
    }


_FULL = {}


def _full_init(blob, base, out_dir, sections, iat):
    _FULL["blob"] = blob
    _FULL["base"] = base
    _FULL["out"] = out_dir
    _FULL["sections"] = sections
    _FULL["iat"] = iat


def _full_shard(item):
    idx, addrs = item
    return _shard_job((idx, addrs, _FULL["blob"], _FULL["base"], _FULL["out"], _FULL["sections"], _FULL["iat"]))


def run_full(blob, base, entries, info):
    import multiprocessing as mp
    out_dir = os.path.join(ROOT, "generated", "undercover", "full")
    os.makedirs(out_dir, exist_ok=True)
    nshard = 128
    chunks = [(i, entries[i::nshard]) for i in range(nshard) if entries[i::nshard]]
    print(f"  full pass: {len(entries)} roots in {len(chunks)} shards", file=sys.stderr)
    totals = collections.Counter()
    reasons = collections.Counter()
    fail_rows = []
    t0 = time.time()
    workers = max(1, min(8, os.cpu_count() or 1))
    with mp.Pool(workers, _full_init, (blob, base, out_dir, info["sections"], info["iat"])) as pool:
        for n, part in enumerate(pool.imap_unordered(_full_shard, chunks), 1):
            for key in ("generated", "failed", "source_bytes", "external", "protected",
                        "indirect_calls", "switches", "rejected_switches"):
                totals[key] += part[key]
            reasons.update(part["reasons"])
            fail_rows.extend(part["fail_rows"])
            if n % 8 == 0 or n == len(chunks):
                print(f"    {n}/{len(chunks)} shards ({time.time() - t0:.0f}s)", file=sys.stderr)
    return {
        "attempted": len(entries),
        "generated": totals["generated"],
        "failed": totals["failed"],
        "source_bytes": totals["source_bytes"],
        "external": totals["external"],
        "protected": totals["protected"],
        "indirect_calls": totals["indirect_calls"],
        "switches": totals["switches"],
        "rejected_switches": totals["rejected_switches"],
        "shards": len(payloads),
        "fail_mnemonics": reasons.most_common(20),
        "fail_rows": fail_rows,
    }


def main(argv):
    if len(argv) < 2:
        die("usage: uc_gen.py <nfs.exe> [--sample-only|--exact FILE|--smoke 0xADDR]")
    exe = argv[1]
    sample_only = "--sample-only" in argv or "--exact" in argv
    smoke = []
    exact = []
    exact_meta = {}
    if "--smoke" in argv:
        i = argv.index("--smoke")
        if i + 1 >= len(argv):
            die("--smoke needs an address")
        smoke = [int(x, 16) for x in argv[i + 1].split(",")]
    if "--exact" in argv:
        i = argv.index("--exact")
        if i + 1 >= len(argv):
            die("--exact needs a file of phase 3 addresses")
        with open(argv[i + 1], encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                va = int(parts[0], 16)
                exact.append(va)
                exact_meta[va] = {
                    "incoming": int(parts[1]) if len(parts) > 1 else 0,
                    "cats": parts[2].split(",") if len(parts) > 2 and parts[2] != "-" else ["phase3"],
                }
    info = uca.read_inputs(exe)
    info["path"] = os.path.abspath(exe)
    out_analysis = uca.assert_output_ok(os.path.join(ROOT, "analysis", "undercover"), exe)
    uca.assert_output_ok(os.path.join(ROOT, "generated", "undercover"), exe)
    clang = find_clang()
    print(f".text {hx(info['text_va'])} size {info['text_size']}", file=sys.stderr)
    print(f"clang {clang}", file=sys.stderr)
    t0 = time.time()
    if smoke or exact:
        entries, incoming = [], {}
        blob_entries = smoke or exact
    else:
        entries, incoming, notable = sweep_entries(info["bytes"], info["text_va"])
        info["return_forms"] = dict(notable)
        blob_entries = entries
    L = make_lifter(info["bytes"], info["text_va"])
    rows = run_sample(L, info, entries, incoming, clang, (smoke or exact) or None)
    if exact:
        for row in rows:
            meta = exact_meta.get(row["va"])
            if not meta:
                continue
            row["incoming"] = meta["incoming"]
            row["cats"] = meta["cats"]
    if smoke:
        ok = sum(1 for r in rows if r["ok"])
        compiled = sum(1 for r in rows if r.get("compiled"))
        print(f"smoke generated {ok}/{len(rows)} compiled {compiled}/{ok}", file=sys.stderr)
        for row in rows:
            if row.get("compiler_error"):
                print(row["compiler_error"][:1500], file=sys.stderr)
        return
    stats = sample_stats(rows)
    fail_names = collections.Counter(
        (r["failure"]["mnemonic"] or r["failure"]["reason"]) for r in rows if r.get("failure")
    )
    top_failure = fail_names.most_common(1)[0][0] if fail_names else ""
    full = None
    gaps = real_gap_names(rows)
    verdict, why = recommend(stats, None, top_failure, gaps)
    phase = ""
    if exact:
        phase = (
            "This is the phase 4 rerun of the same 100 addresses. "
            "`repz ret` and `movmskps` are lowered. "
            "The linear-sweep list of 13,090 roots is not generated from this mode. "
            "Generated C was compiled and was not committed."
        )
        if not gaps and stats["compiled"] == stats["generated"] and stats["generated"]:
            verdict = "SAMPLE UNBLOCKED"
            why = (
                "The phase 3 sample addresses that failed on `repz ret` or `movmskps` "
                "are no longer refused for those opcodes. "
                "Remaining refusals, if any, are recorded above and are not rewritten into successes. "
                "A full translation uses the validated function graph, not every linear-sweep call target."
            )
    if verdict == "PROCEED TO FULL .TEXT RECOMPILATION" and not sample_only:
        full = run_full(info["bytes"], info["text_va"], entries, info)
        verdict, why = recommend(stats, full, top_failure, gaps)
        fail_path = os.path.join(out_analysis, "generation-failures.json")
    else:
        fail_path = os.path.join(out_analysis, "generation-failures.json")
    write_failure_reports(rows, os.path.join(out_analysis, "generation-failures.md"), fail_path)
    if full is not None:
        with open(fail_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["full_pass_failure_sample"] = full["fail_rows"]
        doc["full_pass_failure_mnemonics"] = full["fail_mnemonics"]
        with open(fail_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        with open(os.path.join(out_analysis, "full-pass.json"), "w", encoding="utf-8") as fh:
            body = dict(full)
            body.pop("fail_rows", None)
            json.dump(body, fh, indent=2)
            fh.write("\n")
    write_feasibility(
        os.path.join(out_analysis, "recompilation-feasibility.md"),
        info, rows, clang, verdict, why, full, time.time() - t0, phase,
    )
    print(verdict, file=sys.stderr)


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    main(sys.argv)
