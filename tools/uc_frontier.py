"""Rank ordinary Undercover closures by what the current runtime can execute.

Reads the function map, the import table, and ordinary PE sections only.
Protected sections are not read. The game is not started.
"""
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_code_analyze as uca
import uc_phase7_test as p7
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

ROOT = p7.ROOT
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
IMPLEMENTED = {
    "memcpy", "memmove", "memset", "memcmp", "strlen", "strcmp", "strncmp",
    "strncpy",
    "_CIsin", "_CIcos", "_CIacos",
}
# Deterministic helpers whose convention is already recorded as cdecl and whose
# operation is a pure value transform. Not a promise they are implemented.
SIMPLE_CDECL = {
    "strchr", "strrchr", "strnlen", "strcpy", "strcat", "strstr",
    "strncat", "_stricmp", "_strnicmp", "tolower", "toupper", "isspace",
    "isdigit", "isxdigit", "isalnum", "isprint", "isalpha", "iscntrl",
    "atoi", "abs", "_isnan", "strtol", "strtoul", "strtod", "atof",
    "strcspn", "strpbrk", "bsearch",
    "_CIsqrt", "_CIpow", "_CIatan2", "_CIlog", "_CIlog10", "_CItan", "_CIfmod",
    "_CIasin", "floor", "ceil", "atan", "ldexp",
}


def classify_symbol(dll, symbol):
    name = symbol or ""
    low = name.lower()
    dll_l = (dll or "").lower()
    if name in IMPLEMENTED:
        return "READY_WITH_IMPLEMENTED_IMPORTS"
    if "d3d9" in dll_l or "d3dx" in dll_l or low.startswith("d3d"):
        return "GRAPHICS_BOUNDARY"
    if "dinput" in dll_l or "xinput" in dll_l:
        return "INPUT_BOUNDARY"
    if "dsound" in dll_l:
        return "AUDIO_BOUNDARY"
    if "ws2_32" in dll_l or "wsock" in dll_l or "netapi" in dll_l or low == "netbios":
        return "NETWORK_BOUNDARY"
    if name in ("_beginthreadex", "_endthreadex"):
        return "THREAD_BOUNDARY"
    if name in ("malloc", "free", "_aligned_malloc", "_aligned_free"):
        return "MEMORY_BOUNDARY"
    if name in ("GetTickCount", "_time64", "_localtime64", "_gmtime64", "_mktime64",
                "_localtime32", "_difftime64", "_mkgmtime64", "asctime"):
        return "TIMING_BOUNDARY"
    if name in ("fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "fflush",
                "remove", "setvbuf", "_open", "_read", "_write", "_close", "_lseek",
                "_mkdir", "_rmdir", "_findfirst32", "_findnext32", "_findclose",
                "_fullpath", "_getdiskfree", "_getdrive", "_filelength",
                "GetFileVersionInfoA", "GetFileVersionInfoSizeA", "VerQueryValueA"):
        return "FILESYSTEM_BOUNDARY"
    if name in SIMPLE_CDECL:
        return "KNOWN_IMPORT_MISSING_HLE"
    if name in ("printf", "sprintf", "sscanf", "vsprintf", "_snprintf", "_vsnprintf",
                "_snprintf_s", "_vsnwprintf", "sscanf_s", "qsort"):
        return "KNOWN_IMPORT_MISSING_HLE"
    return "UNKNOWN_RUNTIME_DEPENDENCY"


def section_span(sections):
    spans = []
    for sec in sections:
        spans.append((sec["va"], sec["va"] + sec["vsize"], sec["name"], sec.get("flags", 0)))
    return spans


def section_at(spans, va):
    for lo, hi, name, flags in spans:
        if lo <= va < hi:
            return name, flags
    return None, 0


def load_image(sections):
    """Guest-address lookup for ordinary sections only."""
    blobs = {}
    for sec in sections:
        if sec["name"] in p7.PROTECTED or sec["raw"] is None:
            continue
        blobs[sec["name"]] = (sec["va"], sec["raw"])
    return blobs


def read_u32(blobs, spans, va):
    name, flags = section_at(spans, va)
    if name in p7.PROTECTED or name not in blobs:
        return None
    base, raw = blobs[name]
    off = va - base
    if off < 0 or off + 4 > len(raw):
        return None
    return struct.unpack_from("<I", raw, off)[0]


def main():
    sys.setrecursionlimit(10000)
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    info = uca.read_inputs(game)
    text, text_va = info["bytes"], info["text_va"]
    image = p7.read_sections(game)
    spans = section_span(image["sections"])
    blobs = load_image(image["sections"])
    fmap = json.load(open(os.path.join(ROOT, "analysis", "undercover", "function-map.json"), encoding="utf-8"))
    abi = json.load(open(os.path.join(ROOT, "analysis", "undercover", "import-abi.json"), encoding="utf-8"))
    by_va = {}
    for row in fmap["functions"]:
        by_va[int(row["va"], 16)] = row
    high = {va for va, row in by_va.items() if row["label"] == "HIGH_CONFIDENCE" and row.get("reachable")}
    thunks = {}
    for row in abi["imports"]:
        thunks[int(row["thunk"], 16)] = row
    starts = sorted(by_va)
    nxt = {}
    for i, va in enumerate(starts):
        nxt[va] = starts[i + 1] if i + 1 < len(starts) else text_va + len(text)

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    local = {}
    indirect_kinds = collections.Counter()
    indirect_examples = collections.defaultdict(list)

    def in_text(va):
        return text_va <= va < text_va + len(text)

    def decode_at(va):
        if not in_text(va):
            return None
        off = va - text_va
        found = list(md.disasm(text[off:off + 15], va))
        return found[0] if found else None

    print("scanning", len(high), "high functions", file=sys.stderr)
    done = 0
    for va in sorted(high):
        done += 1
        if done % 1000 == 0:
            print(" ", done, file=sys.stderr)
        row = by_va[va]
        facts = {
            "imports": collections.Counter(),
            "import_class": collections.Counter(),
            "uc_calls": [],
            "unknown_targets": [],
            "protected_targets": [],
            "indirect": [],
            "abs_data": [],
            "abs_rdata": [],
            "protected_mem": [],
            "fs": 0,
            "tls_mem": 0,
        }
        if va in thunks:
            local[va] = facts
            continue
        queue = collections.deque([va])
        seen = set()
        insns = 0
        while queue and insns < 4000 and len(seen) < 2000:
            cur = queue.popleft()
            if cur in seen or not in_text(cur):
                continue
            if cur != va and cur in by_va and cur not in thunks:
                continue
            seen.add(cur)
            while insns < 4000:
                insn = decode_at(cur)
                if insn is None:
                    break
                insns += 1
                if insn.bytes and insn.bytes[0] in (0x64, 0x65):
                    facts["fs"] += 1
                for op in insn.operands:
                    if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                        disp = op.mem.disp & 0xFFFFFFFF
                        name, flags = section_at(spans, disp)
                        if name in p7.PROTECTED:
                            facts["protected_mem"].append(disp)
                        elif name == ".data":
                            facts["abs_data"].append(disp)
                        elif name == ".rdata":
                            facts["abs_rdata"].append(disp)
                        elif name == ".tls":
                            facts["tls_mem"] += 1
                m = insn.mnemonic
                nva = insn.address + insn.size
                if m.startswith("ret") or m in ("retn", "int3"):
                    break
                if m == "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                    target = insn.operands[0].imm & 0xFFFFFFFF
                    if in_text(target):
                        queue.append(target)
                    break
                if m.startswith("j") and m != "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                    queue.append(insn.operands[0].imm & 0xFFFFFFFF)
                    cur = nva
                    continue
                if m in ("call", "jmp") and insn.operands and insn.operands[0].type != X86_OP_IMM:
                    kind, detail = classify_indirect(insn, facts, blobs, spans, high, thunks)
                    facts["indirect"].append((insn.address, kind, detail))
                    indirect_kinds[kind] += 1
                    if len(indirect_examples[kind]) < 8:
                        indirect_examples[kind].append((va, insn.address, detail))
                    if m == "jmp":
                        break
                if not in_text(nva):
                    break
                cur = nva
        for target_s in row.get("calls") or []:
            target = int(target_s, 16)
            note_target(facts, target, high, thunks, spans)
        for target_s in row.get("tails") or []:
            target = int(target_s, 16)
            note_target(facts, target, high, thunks, spans)
        local[va] = facts

    print("closing", file=sys.stderr)
    children = {}
    for va in high:
        if va in thunks:
            children[va] = []
            continue
        kids = []
        for target_s in (by_va[va].get("calls") or []) + (by_va[va].get("tails") or []):
            target = int(target_s, 16)
            if target in high and target not in thunks:
                kids.append(target)
        children[va] = kids

    memo = {}
    visiting = set()

    def close(root):
        if root in memo:
            return memo[root]
        if root in visiting or root in thunks or root not in high:
            return None
        visiting.add(root)
        functions = {root}
        depth = 1
        for kid in children.get(root, []):
            sub = close(kid)
            if not sub:
                continue
            functions.update(sub["functions"])
            if sub["depth"] + 1 > depth:
                depth = sub["depth"] + 1
        visiting.remove(root)
        imports = collections.Counter()
        classes = collections.Counter()
        unknown = []
        protected = []
        indirect = []
        data = set()
        rdata = set()
        fs = 0
        tls = 0
        pmem = []
        for va in functions:
            facts = local[va]
            imports.update(facts["imports"])
            classes.update(facts["import_class"])
            unknown.extend(facts["unknown_targets"])
            protected.extend(facts["protected_targets"])
            indirect.extend(facts["indirect"])
            data.update(facts["abs_data"])
            rdata.update(facts["abs_rdata"])
            fs += facts["fs"]
            tls += facts["tls_mem"]
            pmem.extend(facts["protected_mem"])
        rec = {
            "root": root,
            "size": len(functions),
            "depth": depth,
            "functions": functions,
            "imports": imports,
            "classes": classes,
            "unknown": unknown,
            "protected": protected,
            "indirect": indirect,
            "data": data,
            "rdata": rdata,
            "fs": fs,
            "tls": tls,
            "pmem": pmem,
        }
        rec["label"] = label_closure(rec)
        memo[root] = rec
        return rec

    # Sources: high functions that no other high function calls.
    incoming = collections.Counter()
    for va, kids in children.items():
        for kid in kids:
            incoming[kid] += 1
    sources = [va for va in high if va not in thunks and incoming[va] == 0]
    print("sources", len(sources), file=sys.stderr)
    closures = [close(va) for va in sources]
    closures.sort(key=lambda rec: (-rec["size"], rec["root"]))

    # Distinct by function set, keep the largest root's record.
    best = []
    covered = []
    for rec in closures:
        key = frozenset(rec["functions"])
        if any(key <= prev for prev in covered):
            continue
        covered.append(key)
        best.append(rec)
        if len(best) >= 40:
            break

    # Import leverage: otherwise-clean closures missing exactly one symbol,
    # and the set of missing symbols for otherwise-clean closures.
    unlock = collections.Counter()
    unlock_funcs = collections.defaultdict(set)
    unlock_closures = collections.Counter()
    set_best = {}
    for va in high:
        if va in thunks:
            continue
        rec = close(va)
        if rec["indirect"] or rec["protected"] or rec["unknown"] or rec["pmem"] or rec["fs"]:
            continue
        missing = [name for name, count in rec["imports"].items() if name not in IMPLEMENTED]
        if not missing:
            continue
        key = tuple(sorted(set(missing)))
        set_best[key] = max(set_best.get(key, 0), rec["size"])
        if len(key) == 1:
            unlock[key[0]] += 1
            unlock_closures[key[0]] += 1
            unlock_funcs[key[0]].update(rec["functions"])

    # Also count functions whose closure contains the import, regardless of other blockers.
    reach = collections.Counter()
    for va in high:
        if va in thunks:
            continue
        rec = close(va)
        for name in rec["imports"]:
            if name not in IMPLEMENTED:
                reach[name] += 1

    def pack(rec):
        missing = sorted(name for name in rec["imports"] if name not in IMPLEMENTED)
        return {
            "root": "0x%08X" % rec["root"],
            "size": rec["size"],
            "depth": rec["depth"],
            "label": rec["label"],
            "imports": rec["imports"].most_common(16),
            "missing": missing,
            "indirect": len(rec["indirect"]),
            "unknown": len(rec["unknown"]),
            "protected_edges": len(rec["protected"]),
            "protected_mem": len(rec["pmem"]),
            "functions": ["0x%08X" % va for va in sorted(rec["functions"])],
        }

    all_recs = [rec for rec in memo.values() if rec]
    by_all = {}
    only_indirect = None
    only_missing = None
    for rec in all_recs:
        cur = by_all.get(rec["label"])
        if cur is None or rec["size"] > cur["size"]:
            by_all[rec["label"]] = rec
        missing = [name for name in rec["imports"] if name not in IMPLEMENTED]
        blocked = rec["pmem"] or rec["protected"] or rec["fs"] or rec["unknown"] or rec["tls"]
        if rec["indirect"] and not missing and not blocked:
            if only_indirect is None or rec["size"] > only_indirect["size"]:
                only_indirect = rec
        if missing and not rec["indirect"] and not blocked:
            if only_missing is None or rec["size"] > only_missing["size"]:
                only_missing = rec

    out_dir = os.path.join(ROOT, "analysis", "undercover")
    write_frontier(os.path.join(out_dir, "runtime-frontier.md"), best, closures, indirect_kinds, indirect_examples, high, thunks, by_all)
    write_imports(os.path.join(out_dir, "import-frontier.md"), abi, unlock_funcs, unlock_closures, reach, set_best, thunks)
    summary = {
        "high": len(high) - sum(1 for va in high if va in thunks),
        "sources": len(sources),
        "largest": [{"root": hex(rec["root"]), "size": rec["size"], "depth": rec["depth"], "label": rec["label"],
                     "imports": rec["imports"].most_common(12),
                     "indirect": len(rec["indirect"]), "unknown": len(rec["unknown"]),
                     "protected": len(rec["protected"]), "pmem": len(rec["pmem"])} for rec in best[:20]],
        "all_node_extremes": {label: pack(rec) for label, rec in by_all.items()},
        "only_indirect": pack(only_indirect) if only_indirect else None,
        "only_missing_import": pack(only_missing) if only_missing else None,
        "indirect_kinds": dict(indirect_kinds),
        "single_unlock": {name: len(unlock_funcs[name]) for name in unlock_funcs},
    }
    with open(os.path.join(out_dir, "runtime-frontier.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print("largest", summary["largest"][:8])
    print("indirect", dict(indirect_kinds))
    print("single unlock", sorted(summary["single_unlock"].items(), key=lambda kv: -kv[1])[:12])


def note_target(facts, target, high, thunks, spans):
    if target in thunks:
        row = thunks[target]
        symbol = row["symbol"] or ("ordinal %s" % row["ordinal"])
        facts["imports"][symbol] += 1
        if row["calling_convention"] == "unknown" or row["confidence"] != "high":
            facts["import_class"]["UNKNOWN_IMPORT_ABI"] += 1
        else:
            facts["import_class"][classify_symbol(row["dll"], row["symbol"])] += 1
        return
    if target in high:
        facts["uc_calls"].append(target)
        return
    name, _flags = section_at(spans, target)
    if name in p7.PROTECTED:
        facts["protected_targets"].append(target)
    else:
        facts["unknown_targets"].append(target)


def classify_indirect(insn, facts, blobs, spans, high, thunks):
    op = insn.operands[0]
    if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
        disp = op.mem.disp & 0xFFFFFFFF
        name, _flags = section_at(spans, disp)
        if name in p7.PROTECTED:
            return "E_PROTECTED_SLOT", hex(disp)
        value = read_u32(blobs, spans, disp)
        if value is None:
            return "D_UNKNOWN", hex(disp)
        if value in thunks:
            return "B_IMPORT_SLOT", thunks[value]["symbol"] or hex(value)
        if value in high:
            return "B_GENERATED_TARGET", hex(value)
        tname, _ = section_at(spans, value)
        if tname in p7.PROTECTED:
            return "E_PROTECTED_TARGET", hex(value)
        return "D_UNKNOWN", hex(value)
    if op.type == X86_OP_REG:
        return "D_REGISTER", insn.op_str
    return "D_UNKNOWN", insn.op_str


def label_closure(rec):
    if rec["pmem"] or rec["protected"]:
        return "PROTECTED_BOUNDARY"
    if rec["fs"] or rec["tls"]:
        return "TLS_BOUNDARY"
    if rec["indirect"]:
        kinds = {kind for _addr, kind, _detail in rec["indirect"]}
        if kinds <= {"B_GENERATED_TARGET", "B_IMPORT_SLOT"}:
            return "RESOLVABLE_INDIRECT_CALL"
        return "UNRESOLVED_INDIRECT_CALL"
    if rec["unknown"]:
        return "UNKNOWN_RUNTIME_DEPENDENCY"
    classes = set(rec["classes"])
    major = classes & {
        "GRAPHICS_BOUNDARY", "AUDIO_BOUNDARY", "INPUT_BOUNDARY", "NETWORK_BOUNDARY",
        "THREAD_BOUNDARY", "FILESYSTEM_BOUNDARY", "TIMING_BOUNDARY", "MEMORY_BOUNDARY",
        "UNKNOWN_IMPORT_ABI", "UNKNOWN_RUNTIME_DEPENDENCY",
    }
    if major:
        # Prefer the boundary that appears, in a stable order.
        for name in ("PROTECTED_BOUNDARY", "THREAD_BOUNDARY", "GRAPHICS_BOUNDARY",
                     "NETWORK_BOUNDARY", "AUDIO_BOUNDARY", "INPUT_BOUNDARY",
                     "FILESYSTEM_BOUNDARY", "MEMORY_BOUNDARY", "TIMING_BOUNDARY",
                     "UNKNOWN_IMPORT_ABI", "UNKNOWN_RUNTIME_DEPENDENCY"):
            if name in major:
                return name
    missing = [name for name in rec["imports"] if name not in IMPLEMENTED]
    if missing:
        return "KNOWN_IMPORT_MISSING_HLE"
    if rec["imports"]:
        return "READY_WITH_IMPLEMENTED_IMPORTS"
    return "READY"


def hx(values, limit=6):
    out = []
    for value in list(values)[:limit]:
        if isinstance(value, int):
            out.append("0x%08X" % value)
        else:
            out.append(str(value))
    return ", ".join(out)


def write_frontier(path, best, closures, kinds, examples, high, thunks, by_all=None):
    by_label = collections.Counter(rec["label"] for rec in closures)
    lines = [
        "# Undercover native runtime frontier",
        "",
        "Ordinary high-confidence functions only. Import thunks are edges, not functions in a closure. Protected sections were not read. The game was not started.",
        "",
        "A closure follows direct calls and tail jumps through reachable `HIGH_CONFIDENCE` functions. Import and indirect counts are the union of the functions in the set, each function counted once. The label is the first boundary that stops the current runtime from executing the whole set. A function that is not a source can head a larger closure than any source, so the last section is the one to use for size.",
        "",
        "Executed paths are smaller than these static closures. `analysis/undercover/runtime-phase10.md` records which functions actually ran.",
        "",
        "## Source closures by boundary",
        "",
        "| boundary | source closures |",
        "| --- | --- |",
    ]
    for name, count in by_label.most_common():
        lines.append("| %s | %d |" % (name, count))
    lines += [
        "",
        "Reachable high-confidence functions, excluding import thunks: %d." % (len(high) - sum(1 for va in high if va in thunks)),
        "",
        "## Indirect sites",
        "",
        "| kind | sites |",
        "| --- | --- |",
    ]
    for name, count in kinds.most_common():
        lines.append("| %s | %d |" % (name, count))
    lines += ["", "Examples are guest addresses, not names invented for the code.", ""]
    for kind, rows in examples.items():
        lines.append("- %s: %s" % (kind, "; ".join("fn 0x%08X at 0x%08X %s" % (fn, addr, detail) for fn, addr, detail in rows[:4])))
    lines += ["", "## Largest distinct source closures", "",
              "| root | functions | depth | boundary | imports | indirect | other edges |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for rec in best[:25]:
        imps = ", ".join("%s:%d" % pair for pair in rec["imports"].most_common(6)) or "-"
        other = []
        if rec["unknown"]:
            other.append("unknown %d" % len(rec["unknown"]))
        if rec["protected"]:
            other.append("protected %d" % len(rec["protected"]))
        if rec["data"]:
            other.append("data %d" % len(rec["data"]))
        lines.append("| `0x%08X` | %d | %d | %s | %s | %d | %s |" % (
            rec["root"], rec["size"], rec["depth"], rec["label"], imps, len(rec["indirect"]), ", ".join(other) or "-"))
    buckets = {"READY": [], "READY_WITH_IMPLEMENTED_IMPORTS": [], "KNOWN_IMPORT_MISSING_HLE": [],
               "MEMORY_BOUNDARY": [], "FILESYSTEM_BOUNDARY": [], "GRAPHICS_BOUNDARY": [],
               "PROTECTED_BOUNDARY": [], "UNRESOLVED_INDIRECT_CALL": [], "TIMING_BOUNDARY": []}
    for rec in closures:
        if rec["label"] in buckets:
            buckets[rec["label"]].append(rec)
    lines += ["", "## Extremes", ""]
    for label, rows in buckets.items():
        if not rows:
            lines.append("- %s: none" % label)
            continue
        rows.sort(key=lambda rec: -rec["size"])
        top = rows[0]
        lines.append("- %s: largest source closure is `%d` functions at `0x%08X` (depth %d)." % (
            label, top["size"], top["root"], top["depth"]))
    if by_all:
        lines += ["", "## Largest closure of each label, any high-confidence root", ""]
        for label, rec in sorted(by_all.items(), key=lambda kv: -kv[1]["size"]):
            missing = [name for name in rec["imports"] if name not in IMPLEMENTED]
            lines.append("- %s: `%d` functions at `0x%08X` (depth %d, missing imports %s)." % (
                label, rec["size"], rec["root"], rec["depth"], ", ".join(missing[:8]) or "none"))
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote", path, file=sys.stderr)


def write_imports(path, abi, unlock_funcs, unlock_closures, reach, set_best, thunks):
    by_symbol = {}
    for row in abi["imports"]:
        symbol = row["symbol"] or ("ordinal %s" % row["ordinal"])
        by_symbol.setdefault(symbol, row)
    lines = [
        "# Undercover import frontier",
        "",
        "Counts use the reachable high-confidence graph. A function is unlocked by one missing import when its closure has no indirect call, no protected edge, no unknown callee, and that import is the only unimplemented one. That column is the unlock count. The last column counts high-confidence roots whose closure contains the import along with whatever else blocks them. It is not an unlock count. `sprintf` and `printf` are counted, and they are not small helpers.",
        "",
        "## Single missing import",
        "",
        "| symbol | DLL | convention | direct sites | closures blocked only by it | functions in those closures | high roots whose closure also contains it |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    rows = []
    for row in abi["imports"]:
        symbol = row["symbol"] or ("ordinal %s" % row["ordinal"])
        if symbol in IMPLEMENTED:
            continue
        funcs = len(unlock_funcs.get(symbol, ()))
        rows.append((funcs, reach[symbol], row["call_sites"], symbol, row))
    rows.sort(key=lambda item: (-item[0], -item[1], -item[2]))
    seen = set()
    for funcs, reached, sites, symbol, row in rows:
        if symbol in seen:
            continue
        seen.add(symbol)
        if funcs == 0 and reached == 0:
            continue
        lines.append("| `%s` | %s | %s | %d | %d | %d | %d |" % (
            symbol, row["dll"], row["calling_convention"], sites,
            unlock_closures[symbol], funcs, reached))
    lines += ["", "## Otherwise-clean closures by their missing-import set", "",
              "Only sets that account for a closure of at least 8 functions are listed.",
              "",
              "| missing imports | largest such closure |",
              "| --- | --- |"]
    sets = sorted(set_best.items(), key=lambda kv: -kv[1])
    for key, size in sets[:20]:
        if size < 8:
            continue
        lines.append("| %s | %d |" % (", ".join("`%s`" % name for name in key), size))
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote", path, file=sys.stderr)


if __name__ == "__main__":
    main()
