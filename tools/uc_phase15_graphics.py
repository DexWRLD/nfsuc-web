"""Phase 15 graphics-frontier provenance.

Ordinary .text and allowed data only. Does not execute the game, fill flags,
implement Direct3D, or promote medium-confidence functions.
"""

import bisect
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

import uc_code_analyze as uca
import uc_initprov as ip
import uc_phase7_test as p7

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"
MAP_PATH = os.path.join(ANALYSIS, "function-map.json")
ABI_PATH = os.path.join(ANALYSIS, "import-abi.json")

FLAG = 0x01311E1C
OBJ_CALLER = 0x00766730
HIGH_CALLER = 0x0072E5D0
CREATE_FN = 0x0072E340
CREATE_SITE = 0x0072E3B9
CREATE_THUNK = 0x0087A79C
WAIT_FN = 0x009773B0
SLOT_B611D4 = 0x00B611D4
SLOT_B61188 = 0x00B61188
SLOT_B615C4 = 0x00B615C4
SLOT_CEA3F0 = 0x00CEA3F0
TLS_INDEX = 0x01882C34
HELPER = 0x00686000
INTERIOR = 0x008AA3AE
OWNER_INTERIOR = 0x008A9480


def md():
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    return cs


def hx(n):
    return "0x%08X" % (n & 0xFFFFFFFF)


def load_map():
    data = json.load(open(MAP_PATH, encoding="utf-8"))
    by = {int(row["va"], 16): row for row in data["functions"]}
    return by, sorted(by)


def owner_of(vas, by, eip):
    va = vas[bisect.bisect_right(vas, eip) - 1]
    return va, by[va]


def mapped_dword(image, va):
    for sec in image["sections"]:
        if sec["va"] <= va < sec["va"] + sec["vsize"]:
            raw = sec.get("raw")
            if raw is None:
                return {"section": sec["name"], "value": None, "reason": "no raw / BSS or protected"}
            off = va - sec["va"]
            if off + 4 > len(raw):
                return {"section": sec["name"], "value": 0, "reason": "virtual tail zero"}
            return {
                "section": sec["name"],
                "value": struct.unpack_from("<I", raw, off)[0],
                "reason": "file-backed",
            }
    return {"section": None, "value": None, "reason": "outside mapped sections"}


def refs_of(blob, base, target):
    out = []
    for off in ip.iter_immediates(blob, base, target):
        classified = ip.classify_encoding(blob, base, off, target)
        if classified:
            out.append(classified)
    return out


def decode_linear(blob, base, start, limit=400, stop_ret=True):
    cs = md()
    lines = []
    cur = start
    for _ in range(limit):
        if cur < base or cur >= base + len(blob):
            break
        insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
        if insn is None:
            lines.append({"va": cur, "text": "??", "size": 1, "mnemonic": "??", "bytes": []})
            break
        lines.append({
            "va": insn.address,
            "text": "%s %s" % (insn.mnemonic, insn.op_str),
            "size": insn.size,
            "mnemonic": insn.mnemonic,
            "bytes": list(insn.bytes),
            "operands": insn.operands,
        })
        if stop_ret and (insn.mnemonic.startswith("ret") or insn.mnemonic == "int3"):
            break
        cur = insn.address + insn.size
    return lines


def cfg_walk(blob, base, entry, limit=12000):
    """Bounded CFG walk. Returns seen instruction VAs, calls, returns, and abs mem."""
    cs = md()
    stack = [entry]
    seen = set()
    insns = {}
    calls = []
    rets = []
    abs_mem = []
    n = 0
    while stack and n < limit:
        va = stack.pop()
        if va in seen or va < base or va >= base + len(blob):
            continue
        seen.add(va)
        cur = va
        while n < limit:
            insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                break
            n += 1
            seen.add(insn.address)
            insns[insn.address] = "%s %s" % (insn.mnemonic, insn.op_str)
            m = insn.mnemonic
            nxt = insn.address + insn.size
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                    abs_mem.append((insn.address, op.mem.disp & 0xFFFFFFFF, m, insn.op_str))
            if m.startswith("ret") or m == "int3":
                rets.append(insn.address)
                break
            if m in ("call", "jmp") and insn.operands and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm & 0xFFFFFFFF
                calls.append((insn.address, target, m))
                if m == "jmp":
                    if base <= target < base + len(blob):
                        stack.append(target)
                    break
                stack.append(nxt)
                cur = nxt
                continue
            if m.startswith("j") and m != "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm & 0xFFFFFFFF
                stack.append(target)
                cur = nxt
                continue
            if m == "jmp":
                break
            cur = nxt
            if cur < base or cur >= base + len(blob):
                break
    return {
        "seen": sorted(seen),
        "insns": n,
        "unique": len(seen),
        "calls": calls,
        "rets": rets,
        "abs_mem": abs_mem,
        "min": min(seen) if seen else entry,
        "max": max(seen) if seen else entry,
    }


def e8_sites(blob, base, dest):
    sites = []
    for off in range(len(blob) - 5):
        if blob[off] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        if (base + off + 5 + rel) & 0xFFFFFFFF == dest:
            sites.append((base + off, "call" if blob[off] == 0xE8 else "jmp"))
    return sites


def follow_alias_writes(blob, base, by, vas, target, bound=80):
    """After ADDRESS_TAKEN of target, look for stores through that register."""
    cs = md()
    results = []
    for kind, eip, text, conf in refs_of(blob, base, target):
        if kind != "ADDRESS_TAKEN":
            continue
        owner, row = owner_of(vas, by, eip)
        # Decode a window from the owner or from eip-32.
        start = max(owner, eip - 8)
        cur = start
        # Find the lea/mov that took the address.
        took = None
        reg = None
        for _ in range(40):
            insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                break
            if insn.address == eip or (eip <= insn.address < eip + 8):
                took = insn
                if insn.operands and insn.operands[0].type == X86_OP_REG:
                    reg = insn.operands[0].reg
                break
            cur = insn.address + insn.size
        if took is None:
            # decode from eip itself
            took = next(cs.disasm(blob[eip - base:eip - base + 15], eip), None)
            if took and took.operands and took.operands[0].type == X86_OP_REG:
                reg = took.operands[0].reg
        if took is None or reg is None:
            results.append({
                "class": "UNKNOWN",
                "eip": eip,
                "owner": owner,
                "text": text,
                "note": "could not recover destination register",
            })
            continue
        # Forward walk looking for [reg+disp] stores of the same base.
        cur = took.address + took.size
        found = []
        live = {reg}
        aliases = {reg: 0}  # reg -> displacement from target
        for step in range(bound):
            insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                break
            m = insn.mnemonic
            if m in ("call", "ret", "retn", "jmp"):
                break
            # mov reg2, reg
            if m == "mov" and len(insn.operands) >= 2:
                dst, src = insn.operands[0], insn.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_REG and src.reg in aliases:
                    aliases[dst.reg] = aliases[src.reg]
                    live.add(dst.reg)
                elif dst.type == X86_OP_REG and dst.reg in aliases and not (
                        src.type == X86_OP_REG and src.reg in aliases):
                    # clobber
                    aliases.pop(dst.reg, None)
                    live.discard(dst.reg)
                elif dst.type == X86_OP_MEM and dst.mem.base in aliases:
                    disp = dst.mem.disp
                    base_off = aliases[dst.mem.base]
                    if dst.mem.index == 0 and base_off + disp == 0:
                        imm = None
                        if src.type == X86_OP_IMM:
                            imm = src.imm & 0xFFFFFFFF
                        found.append({
                            "eip": insn.address,
                            "text": "%s %s" % (m, insn.op_str),
                            "imm": imm,
                            "confidence": "high" if imm is not None else "medium",
                        })
            if m in ("lea",) and len(insn.operands) >= 2:
                dst, src = insn.operands[0], insn.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_MEM and src.mem.base in aliases and src.mem.index == 0:
                    aliases[dst.reg] = aliases[src.mem.base] + src.mem.disp
                    live.add(dst.reg)
            # store forms: mov [reg], imm / mov [reg], eax
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base in aliases and op.mem.index == 0:
                    if (op.access & 2) or m.startswith("mov") or m in ("xchg",):
                        if aliases[op.mem.base] + op.mem.disp == 0 and m.startswith("mov"):
                            imm = None
                            if len(insn.operands) >= 2 and insn.operands[1].type == X86_OP_IMM:
                                imm = insn.operands[1].imm & 0xFFFFFFFF
                            if not any(item["eip"] == insn.address for item in found):
                                found.append({
                                    "eip": insn.address,
                                    "text": "%s %s" % (m, insn.op_str),
                                    "imm": imm,
                                    "confidence": "high" if imm is not None else "medium",
                                })
            # conditional branches: continue fallthrough only for this bound walk
            if m.startswith("j") and m != "jmp":
                cur = insn.address + insn.size
                continue
            cur = insn.address + insn.size
        results.append({
            "class": "DEFINITE_WRITER" if any(f.get("imm") is not None for f in found)
            else ("POSSIBLE_WRITER" if found else "NO_WRITER"),
            "eip": eip,
            "owner": owner,
            "owner_label": row.get("label"),
            "owner_reachable": bool(row.get("reachable")),
            "text": text,
            "reg": took.reg_name(reg) if hasattr(took, "reg_name") else str(reg),
            "stores": found,
        })
    return results


def field_accesses(walk, object_regs=("ecx", "esi", "ebx", "edi", "ebp")):
    """Parse abs and relative [reg+disp] from instruction text is weak; use operands from re-walk."""
    return walk


def analyze_object_fields(blob, base, entry, this_reg_hint="ecx", limit=8000):
    cs = md()
    fields = collections.defaultdict(lambda: {"ops": set(), "sites": []})
    stack = [entry]
    seen = set()
    n = 0
    # Track which registers hold `this` after mov ebx, ecx etc. Start with ECX.
    # Conservative: treat ECX at entry and any mov X, ecx / mov X, esi if esi was this.
    this_regs = set()
    from capstone.x86 import X86_REG_ECX, X86_REG_ESI, X86_REG_EBX, X86_REG_EDI, X86_REG_EBP
    this_regs.add(X86_REG_ECX)
    while stack and n < limit:
        va = stack.pop()
        if va in seen or va < base or va >= base + len(blob):
            continue
        seen.add(va)
        cur = va
        while n < limit:
            insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                break
            n += 1
            m = insn.mnemonic
            nxt = insn.address + insn.size
            if m == "mov" and len(insn.operands) >= 2:
                dst, src = insn.operands[0], insn.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_REG and src.reg in this_regs:
                    this_regs.add(dst.reg)
                elif dst.type == X86_OP_REG and dst.reg in this_regs and not (
                        src.type == X86_OP_REG and src.reg in this_regs):
                    this_regs.discard(dst.reg)
            for op_i, op in enumerate(insn.operands):
                if op.type != X86_OP_MEM:
                    continue
                if op.mem.base in this_regs and op.mem.index == 0:
                    off = op.mem.disp
                    write = bool(op.access & 2) or (op_i == 0 and m.startswith("mov"))
                    kind = "WRITE" if write else "READ"
                    if m == "call":
                        kind = "CALL_TARGET"
                    fields[off]["ops"].add(kind)
                    fields[off]["sites"].append((insn.address, kind, "%s %s" % (m, insn.op_str)))
            if m.startswith("ret") or m == "int3":
                break
            if m in ("call", "jmp") and insn.operands and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm & 0xFFFFFFFF
                if m == "jmp":
                    if base <= target < base + len(blob):
                        stack.append(target)
                    break
                cur = nxt
                continue
            if m.startswith("j") and m != "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                stack.append(insn.operands[0].imm & 0xFFFFFFFF)
                cur = nxt
                continue
            if m == "jmp":
                break
            cur = nxt
    out = []
    for off in sorted(fields):
        rec = fields[off]
        out.append({
            "offset": off,
            "ops": sorted(rec["ops"]),
            "sites": [{"eip": hx(e), "kind": k, "text": t} for e, k, t in rec["sites"][:12]],
            "site_count": len(rec["sites"]),
        })
    return out


def main():
    info = uca.read_inputs(GAME)
    image = p7.read_sections(GAME)
    blob, base = info["bytes"], info["text_va"]
    by, vas = load_map()
    abi = json.load(open(ABI_PATH, encoding="utf-8"))
    thunks = {int(row["thunk"], 16): row for row in abi["imports"]}

    report = {
        "flag": {},
        "wait": {},
        "extents": {},
        "slots": {},
        "create": {},
        "object_fields": {},
        "callers": {},
    }

    # --- Flag 0x01311E1C ---
    mapped = mapped_dword(image, FLAG)
    refs = refs_of(blob, base, FLAG)
    by_kind = collections.Counter(r[0] for r in refs)
    ref_rows = []
    for kind, eip, text, conf in refs:
        owner, row = owner_of(vas, by, eip)
        ref_rows.append({
            "kind": kind,
            "eip": hx(eip),
            "text": text,
            "confidence": conf,
            "owner": hx(owner),
            "owner_label": row.get("label"),
            "owner_reachable": bool(row.get("reachable")),
            "owner_score": row.get("score"),
        })
    aliases = follow_alias_writes(blob, base, by, vas, FLAG)
    report["flag"] = {
        "address": hx(FLAG),
        "mapped": mapped,
        "ref_counts": dict(by_kind),
        "refs": ref_rows,
        "alias_writes": [
            {
                "class": a["class"],
                "eip": hx(a["eip"]),
                "owner": hx(a["owner"]),
                "owner_label": a.get("owner_label"),
                "owner_reachable": a.get("owner_reachable"),
                "text": a["text"],
                "stores": [
                    {"eip": hx(s["eip"]), "text": s["text"], "imm": None if s["imm"] is None else hx(s["imm"]),
                     "confidence": s["confidence"]}
                    for s in a.get("stores") or []
                ],
            }
            for a in aliases
        ],
    }

    # Reads usage: dump the owner bodies around each READ.
    read_uses = []
    for kind, eip, text, conf in refs:
        if kind != "READ":
            continue
        owner, row = owner_of(vas, by, eip)
        start = eip - 12 if eip - 12 >= owner else owner
        window = decode_linear(blob, base, start, limit=30, stop_ret=False)
        read_uses.append({
            "eip": hx(eip),
            "owner": hx(owner),
            "owner_label": row.get("label"),
            "window": [{"va": hx(l["va"]), "text": l["text"]} for l in window if abs(l["va"] - eip) < 48],
        })
    report["flag"]["read_windows"] = read_uses

    # --- Wait function ---
    wait_row = by.get(WAIT_FN, {})
    wait_walk = cfg_walk(blob, base, WAIT_FN)
    wait_callers = []
    for eip, kind in e8_sites(blob, base, WAIT_FN):
        owner, row = owner_of(vas, by, eip)
        wait_callers.append({
            "site": hx(eip), "kind": kind, "owner": hx(owner),
            "label": row.get("label"), "reachable": bool(row.get("reachable")),
        })
    report["wait"] = {
        "va": hx(WAIT_FN),
        "map": {k: wait_row.get(k) for k in ("label", "score", "reachable", "insns", "reasons")},
        "walk_insns": wait_walk["insns"],
        "walk_rets": [hx(x) for x in wait_walk["rets"]],
        "walk_calls": [{"eip": hx(a), "target": hx(b), "op": c} for a, b, c in wait_walk["calls"][:20]],
        "abs_mem": [{"eip": hx(a), "addr": hx(b), "text": "%s %s" % (c, d)} for a, b, c, d in wait_walk["abs_mem"][:30]],
        "callers": wait_callers,
        "linear": [{"va": hx(l["va"]), "text": l["text"]} for l in decode_linear(blob, base, WAIT_FN, 40)],
    }

    # --- Extents ---
    for va, name in ((OBJ_CALLER, "766730"), (CREATE_FN, "72e340"), (HIGH_CALLER, "72e5d0"), (0x0072DD00, "72dd00"),
                     (0x0072DCA0, "72dca0"), (OWNER_INTERIOR, "8a9480")):
        row = by.get(va, {})
        walk = cfg_walk(blob, base, va)
        next_va = None
        i = bisect.bisect_right(vas, va)
        if i < len(vas):
            next_va = vas[i]
        # Check if walk reaches a ret past the map's recorded size.
        report["extents"][name] = {
            "va": hx(va),
            "map_label": row.get("label"),
            "map_score": row.get("score"),
            "map_insns": row.get("insns"),
            "map_reachable": bool(row.get("reachable")),
            "map_reasons": row.get("reasons"),
            "next_map_entry": None if next_va is None else hx(next_va),
            "walk_insns": walk["insns"],
            "walk_unique": walk["unique"],
            "walk_min": hx(walk["min"]),
            "walk_max": hx(walk["max"]),
            "walk_rets": [hx(x) for x in walk["rets"]],
            "walk_calls": [{"eip": hx(a), "target": hx(b), "op": c} for a, b, c in walk["calls"][:40]],
            "gap_to_next": None if next_va is None else next_va - walk["max"],
            "ret_before_next": bool(walk["rets"]) and (next_va is None or max(walk["rets"]) < next_va),
        }

    # --- Create function detail ---
    create_linear = decode_linear(blob, base, CREATE_FN, limit=200, stop_ret=True)
    # Also walk without stopping at first ret if CFG finds more.
    create_walk = report["extents"]["72e340"]
    report["create"] = {
        "linear_to_ret": [{"va": hx(l["va"]), "text": l["text"]} for l in create_linear],
        "direct3d_call": hx(CREATE_SITE),
        "thunk": thunks.get(CREATE_THUNK),
        "fields": analyze_object_fields(blob, base, CREATE_FN),
        "fields_caller": analyze_object_fields(blob, base, HIGH_CALLER),
        "fields_outer": analyze_object_fields(blob, base, OBJ_CALLER),
    }

    # Verify Direct3DCreate9 site bytes
    rel = struct.unpack_from("<i", blob, CREATE_SITE + 1 - base)[0]
    report["create"]["call_target"] = hx((CREATE_SITE + 5 + rel) & 0xFFFFFFFF)
    report["create"]["push_before"] = list(blob[CREATE_SITE - 2 - base:CREATE_SITE - base])

    # --- Callers of chain ---
    for dest, key in ((OBJ_CALLER, "to_766730"), (HIGH_CALLER, "to_72e5d0"), (CREATE_FN, "to_72e340")):
        rows = []
        for eip, kind in e8_sites(blob, base, dest):
            owner, row = owner_of(vas, by, eip)
            rows.append({
                "site": hx(eip), "kind": kind, "owner": hx(owner),
                "label": row.get("label"), "reachable": bool(row.get("reachable")),
                "score": row.get("score"),
            })
        report["callers"][key] = rows

    # --- Slots ---
    for slot, key in (
        (SLOT_B611D4, "b611d4"),
        (SLOT_B61188, "b61188"),
        (SLOT_B615C4, "b615c4"),
        (SLOT_CEA3F0, "cea3f0"),
        (TLS_INDEX, "tls_01882c34"),
    ):
        mapped = mapped_dword(image, slot)
        refs = refs_of(blob, base, slot)
        ref_rows = []
        for kind, eip, text, conf in refs:
            owner, row = owner_of(vas, by, eip)
            ref_rows.append({
                "kind": kind, "eip": hx(eip), "text": text, "confidence": conf,
                "owner": hx(owner), "owner_label": row.get("label"),
                "owner_reachable": bool(row.get("reachable")),
            })
        aliases = follow_alias_writes(blob, base, by, vas, slot) if any(r[0] == "ADDRESS_TAKEN" for r in refs) else []
        target = mapped.get("value")
        target_info = None
        if target:
            owner, row = owner_of(vas, by, target) if vas else (None, {})
            # Is target a map entry?
            entry = by.get(target)
            target_info = {
                "value": hx(target),
                "map_entry": entry is not None,
                "span_owner": None if owner is None else hx(owner),
                "span_label": None if not row else row.get("label"),
                "at_entry": entry is not None,
                "delta_from_owner": None if owner is None else target - owner,
            }
            if entry is None and owner is not None:
                # decode at target
                target_info["disasm"] = [
                    {"va": hx(l["va"]), "text": l["text"]}
                    for l in decode_linear(blob, base, target, 12)
                ]
                target_info["owner_disasm_head"] = [
                    {"va": hx(l["va"]), "text": l["text"]}
                    for l in decode_linear(blob, base, owner, 8)
                ]
        report["slots"][key] = {
            "address": hx(slot),
            "mapped": mapped,
            "ref_counts": dict(collections.Counter(r[0] for r in refs)),
            "refs": ref_rows,
            "alias_writes": [
                {
                    "class": a["class"], "eip": hx(a["eip"]), "owner": hx(a["owner"]),
                    "stores": [{"eip": hx(s["eip"]), "text": s["text"], "imm": None if s["imm"] is None else hx(s["imm"])}
                               for s in a.get("stores") or []],
                }
                for a in aliases
            ],
            "target": target_info,
        }

    # Interior point classification
    interior_walk = cfg_walk(blob, base, INTERIOR, limit=2000)
    owner_walk = cfg_walk(blob, base, OWNER_INTERIOR, limit=4000)
    report["slots"]["b615c4"]["interior"] = {
        "va": hx(INTERIOR),
        "owner": hx(OWNER_INTERIOR),
        "reachable_from_owner": INTERIOR in set(owner_walk["seen"]),
        "interior_walk_rets": [hx(x) for x in interior_walk["rets"]],
        "interior_walk_insns": interior_walk["insns"],
        "bytes_at_interior": list(blob[INTERIOR - base:INTERIOR - base + 16]),
        "disasm": [{"va": hx(l["va"]), "text": l["text"]} for l in decode_linear(blob, base, INTERIOR, 20)],
    }

    # Helper dependence on graphics chain functions
    for va in (OBJ_CALLER, HIGH_CALLER, CREATE_FN, WAIT_FN):
        walk = cfg_walk(blob, base, va)
        hits = [hx(eip) for eip, target, op in walk["calls"] if target == HELPER]
        report.setdefault("helper_hits", {})[hx(va)] = hits

    # ESI provenance in create function: first instructions
    report["create"]["esi_origin"] = []
    for l in create_linear[:30]:
        report["create"]["esi_origin"].append({"va": hx(l["va"]), "text": l["text"]})

    out = os.path.join(ANALYSIS, "phase15-raw.json")
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print("wrote", out)
    print("flag refs", report["flag"]["ref_counts"])
    print("alias", [(a["class"], a["eip"], len(a["stores"])) for a in report["flag"]["alias_writes"]])
    print("extents")
    for k, v in report["extents"].items():
        print(" ", k, v["map_label"], "map_insns", v["map_insns"], "walk", v["walk_insns"],
              "rets", v["walk_rets"], "next", v["next_map_entry"])
    print("slots")
    for k, v in report["slots"].items():
        print(" ", k, v["mapped"], v["ref_counts"], "target", None if not v["target"] else v["target"].get("value"))


if __name__ == "__main__":
    main()
