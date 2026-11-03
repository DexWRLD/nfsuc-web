"""Phase 17: graphics factory initialization provenance.

Ordinary sections only. Does not execute nfs.exe, implement Direct3D/TLS/Win32,
synthesize flag/slot/object state, or loosen Phase 16 discovery rules.
"""
from __future__ import annotations

import bisect
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

import lift
import uc_code_analyze as uca
import uc_gen as ucg
import uc_initprov as ip
import uc_phase7_test as p7
import uc_phase15_graphics as g15

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

FLAG = 0x01311E1C
FLAG_SET1 = 0x00722D60
FLAG_SET2_OWNER = 0x00729750
FLAG_CLEAR = 0x00B4F990
OBJ = 0x01318170
OUTER = 0x00766730
HIGH_CALLER = 0x0072E5D0
CREATE = 0x0072E340
CREATE_SITE = 0x0072E3B9
THUNK = 0x0087A79C
WAIT = 0x009773B0
SLOTS = {
    0x00B611D4: 0x008A9F58,
    0x00B61188: 0x008AB180,
    0x00B615C4: 0x008AA3AE,
}
TLS = 0x01882C34
HELPER = 0x00686000


def hx(n):
    return "0x%08X" % (n & 0xFFFFFFFF)


def md():
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    return cs


def load_map():
    data = json.load(open(os.path.join(ANALYSIS, "function-map.json"), encoding="utf-8"))
    by = {int(row["va"], 16): row for row in data["functions"]}
    return data, by, sorted(by)


def owner_of(vas, by, eip):
    i = bisect.bisect_right(vas, eip) - 1
    if i < 0:
        return None, {}
    return vas[i], by.get(vas[i], {})


def e8_sites(blob, base, dest):
    out = []
    for off in range(len(blob) - 5):
        if blob[off] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        if (base + off + 5 + rel) & 0xFFFFFFFF == dest:
            out.append((base + off, "DIRECT_CALL" if blob[off] == 0xE8 else "DIRECT_JUMP"))
    return out


def abs_dword_sites(blob, base, value):
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    out = []
    start = 0
    while True:
        off = blob.find(needle, start)
        if off < 0:
            break
        out.append(base + off)
        start = off + 1
    return out


def section_refs(image, value, allowed=(".text", ".rdata", ".data", ".tls", ".rsrc")):
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    hits = []
    for sec in image["sections"]:
        if sec["name"] not in allowed:
            continue
        raw = sec.get("raw") or b""
        start = 0
        while True:
            off = raw.find(needle, start)
            if off < 0:
                break
            hits.append({"section": sec["name"], "va": hx(sec["va"] + off)})
            start = off + 1
    return hits


def classify_va_ref(blob, base, eip, target):
    kind = ip.classify_encoding(blob, base, eip - base, target)
    if not kind:
        # fall back for raw find hits that are not Capstone immediates
        return ("TABLE_ENTRY", eip, "raw dword", "low")
    return kind


def decode_fn(blob, base, entry, limit=8000):
    return g15.cfg_walk(blob, base, entry, limit=limit)


def linear_until(blob, base, start, stop_addrs, limit=500):
    cs = md()
    lines = []
    cur = start
    for _ in range(limit):
        insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
        if insn is None:
            break
        lines.append(insn)
        if insn.address in stop_addrs:
            break
        if lift._is_near_ret(insn.mnemonic):
            break
        cur = insn.address + insn.size
    return lines


def covering_insn(blob, base, va):
    cs = md()
    # walk back a little to find an instruction that contains va
    for back in range(0, 16):
        start = va - back
        if start < base:
            continue
        insn = next(cs.disasm(blob[start - base:start - base + 15], start), None)
        if insn is None:
            continue
        if insn.address <= va < insn.address + insn.size:
            return insn
    return None


def slot_target_class(blob, base, starts, by, value):
    """Classify PE slot target. Linear-sweep boundary is authoritative.

    Capstone can decode mid-instruction bytes as plausible junk; that must not
    promote an INVALID_INSTRUCTION_BOUNDARY into a callable entry.
    """
    if value == 0:
        return "DATA/SENTINEL"
    if not (base <= value < base + len(blob)):
        return "UNKNOWN"
    on = starts[value - base] == 1
    cov = covering_insn(blob, base, value)
    if cov is not None and cov.address != value:
        return "INVALID_INTERIOR_ENTRY"
    if not on:
        # Mid-stream or non-boundary even if Capstone accepts a start here.
        return "INVALID_INTERIOR_ENTRY"
    if value in by and by[value].get("label") == "HIGH_CONFIDENCE":
        return "VALID_FUNCTION_ENTRY"
    walk = decode_fn(blob, base, value, limit=64)
    if walk["insns"] >= 4 and walk["rets"]:
        return "VALID_INTERIOR_ENTRY"
    return "SHARED_CODE_ENTRY"


def analyze_flag_writer(blob, base, entry):
    lines = g15.decode_linear(blob, base, entry, limit=80, stop_ret=True)
    text = []
    xchg = None
    for row in lines:
        text.append("%s: %s" % (hx(row["va"]), row["text"]))
        if row["mnemonic"] == "xchg":
            xchg = {"va": hx(row["va"]), "text": row["text"]}
    return {"entry": hx(entry), "listing": text, "xchg": xchg}


def object_field_traffic(blob, base, by, vas, obj=OBJ):
    """Scan HIGH functions that address-take OBJ and collect [reg+disp] traffic after mov ecx/esi/ebx, OBJ."""
    cs = md()
    fields = collections.defaultdict(lambda: {"readers": set(), "writers": set(), "ops": collections.Counter()})
    roots = collections.Counter()
    for kind, eip, text, conf in g15.refs_of(blob, base, obj):
        if kind != "ADDRESS_TAKEN":
            continue
        owner, row = owner_of(vas, by, eip)
        if not owner or row.get("label") != "HIGH_CONFIDENCE":
            continue
        roots[owner] += 1
        # walk a short window after the address-take looking for [reg+disp]
        cur = eip
        reg_holding = None
        for _ in range(120):
            insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                break
            # detect mov reg, imm obj
            if insn.mnemonic == "mov" and insn.operands:
                if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
                    if (insn.operands[1].imm & 0xFFFFFFFF) == obj:
                        reg_holding = insn.operands[0].reg
            for op in insn.operands:
                if op.type != X86_OP_MEM:
                    continue
                mem = op.mem
                if reg_holding is not None and mem.base == reg_holding and mem.index == 0:
                    off = mem.disp & 0xFFFFFFFF
                    if off > 0x2000:
                        continue
                    access = "WRITE" if (op.access & 2) or insn.mnemonic in ("mov", "xchg", "add", "sub", "or", "and", "xor", "fstp") and insn.operands[0].type == X86_OP_MEM else "READ"
                    # refine write: first operand memory for mov/xchg/fstp
                    if insn.mnemonic in ("mov", "xchg", "fstp", "movss", "movsd") and insn.operands and insn.operands[0].type == X86_OP_MEM:
                        access = "WRITE"
                    elif insn.mnemonic.startswith("mov") and insn.operands and insn.operands[0].type == X86_OP_MEM:
                        access = "WRITE"
                    elif op.access & 2:
                        access = "WRITE"
                    else:
                        access = "READ"
                    fields[off]["ops"][insn.mnemonic] += 1
                    if access == "WRITE":
                        fields[off]["writers"].add(owner)
                    else:
                        fields[off]["readers"].add(owner)
            if lift._is_near_ret(insn.mnemonic):
                break
            cur = insn.address + insn.size
    out_fields = {}
    for off, info in sorted(fields.items()):
        out_fields[hx(off)] = {
            "offset": off,
            "readers": [hx(v) for v in sorted(info["readers"])],
            "writers": [hx(v) for v in sorted(info["writers"])],
            "ops": dict(info["ops"]),
        }
    return out_fields, [{"root": hx(r), "address_taken_sites": n} for r, n in roots.most_common(40)]


def pre_factory_path(blob, base, by):
    """Linear shortest path from CREATE through CREATE_SITE (fall-through biased).

    Captures absolute mem reads, register-indirect calls (call esi), and the
    direct helpers on the way to Direct3DCreate9.
    """
    cs = md()
    mem_reads = []
    indirects = []
    conditions = []
    calls_before = []
    reg_loads = {}
    listing = []
    cur = CREATE
    reached_site = False
    for _ in range(400):
        insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
        if insn is None:
            break
        listing.append("%s: %s %s" % (hx(insn.address), insn.mnemonic, insn.op_str))
        m = insn.mnemonic
        if insn.address == CREATE_SITE:
            reached_site = True
        # mov reg, [abs]
        if m == "mov" and insn.operands and insn.operands[0].type == X86_OP_REG:
            if insn.operands[1].type == X86_OP_MEM and insn.operands[1].mem.base == 0 and insn.operands[1].mem.index == 0:
                slot = insn.operands[1].mem.disp & 0xFFFFFFFF
                reg_loads[insn.operands[0].reg] = slot
                mem_reads.append({"eip": hx(insn.address), "slot": hx(slot), "text": "%s %s" % (m, insn.op_str)})
        if m == "call":
            if insn.operands and insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm & 0xFFFFFFFF
                calls_before.append({"eip": hx(insn.address), "target": hx(target), "form": "direct"})
            elif insn.operands and insn.operands[0].type == X86_OP_REG:
                reg = insn.operands[0].reg
                slot = reg_loads.get(reg)
                indirects.append({
                    "eip": hx(insn.address),
                    "reg": insn.reg_name(reg),
                    "slot": hx(slot) if slot is not None else None,
                    "text": "%s %s" % (m, insn.op_str),
                    "form": "register",
                })
            elif insn.operands and insn.operands[0].type == X86_OP_MEM:
                mem = insn.operands[0].mem
                if mem.base == 0 and mem.index == 0:
                    slot = mem.disp & 0xFFFFFFFF
                    indirects.append({
                        "eip": hx(insn.address),
                        "slot": hx(slot),
                        "text": "%s %s" % (m, insn.op_str),
                        "form": "memory",
                    })
        if m.startswith("j") and m != "jmp" and insn.operands and insn.operands[0].type == X86_OP_IMM:
            conditions.append({
                "eip": hx(insn.address),
                "mnemonic": m,
                "target": hx(insn.operands[0].imm & 0xFFFFFFFF),
                "fallthrough": hx(insn.address + insn.size),
                "text": "%s %s" % (m, insn.op_str),
            })
            # stay on fall-through toward create site when possible
            dest = insn.operands[0].imm & 0xFFFFFFFF
            nxt = insn.address + insn.size
            if CREATE_SITE >= nxt and (dest > CREATE_SITE or dest < CREATE):
                cur = nxt
                continue
            cur = nxt
            continue
        if insn.address >= CREATE_SITE and m == "call":
            break
        if lift._is_near_ret(m):
            break
        cur = insn.address + insn.size
        if cur > CREATE_SITE + 32:
            break
    return {
        "reached_create_site": reached_site,
        "listing": listing,
        "mem_reads": mem_reads,
        "indirects": indirects,
        "conditions": conditions,
        "calls_before": [c for c in calls_before if int(c["eip"], 16) <= CREATE_SITE],
        "reg_loads": {str(k): hx(v) for k, v in reg_loads.items()},
    }


def factory_frontier(by, blob, base, pre, slot_classes, flag_invocable, tls_required):
    row = by.get(CREATE, {})
    high = row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable")
    # generated/compiled check via high-confidence.json
    hc = json.load(open(os.path.join(ANALYSIS, "high-confidence.json"), encoding="utf-8"))
    failed = {int(x, 16) for x in hc.get("failed_functions") or []}
    callees = []
    for c in pre.get("calls_before") or []:
        t = int(c["target"], 16)
        if t == THUNK:
            continue
        callees.append(t)
    callees_ok = all(
        (t in by and by[t].get("label") == "HIGH_CONFIDENCE" and t not in failed)
        or t == THUNK
        for t in callees
    )
    indirects = pre.get("indirects") or []
    indirect_ok = True
    indirect_detail = []
    for item in indirects:
        slot_text = item.get("slot")
        if not slot_text:
            indirect_ok = False
            indirect_detail.append({"slot": None, "class": None, "ok": False, "text": item.get("text")})
            continue
        slot = int(slot_text, 16)
        cls = slot_classes.get(hx(slot), {}).get("final_class")
        ok = cls in ("VALID_FUNCTION_ENTRY", "VALID_INTERIOR_ENTRY")
        if slot == 0x00CEA3F0:
            ok = True  # PE zero skips call
        if not ok:
            indirect_ok = False
        indirect_detail.append({"slot": slot_text, "class": cls, "ok": ok, "text": item.get("text")})
    # globals: flag must be 1 for outer gate; for CREATE alone check ESI slot
    globals_ok = False  # flag writer not invocable
    reasons = []
    if not high:
        reasons.append("create not HIGH reachable")
    if not callees_ok:
        reasons.append("pre-factory direct callee not generated/HIGH")
    if not indirect_ok:
        reasons.append("pre-factory indirect target invalid")
    if not flag_invocable and HIGH_CALLER in [CREATE]:  # placeholder
        pass
    if tls_required:
        reasons.append("TLS required on chosen prefix")
    # For CREATE alone: ESI from B615C4 is required before factory
    if any(int(i["slot"], 16) == 0x00B615C4 for i in indirects) or True:
        # create loads ESI from B615C4 then call esi thrice before Direct3DCreate9
        esi_cls = slot_classes.get(hx(0x00B615C4), {}).get("final_class")
        if esi_cls not in ("VALID_FUNCTION_ENTRY", "VALID_INTERIOR_ENTRY"):
            reasons.append("ESI callback slot 0x00B615C4 not valid")
            globals_ok = False
        else:
            globals_ok = True
    if not flag_invocable:
        # create itself may not read flag; outer does. Note separately.
        pass
    ready = high and callees_ok and indirect_ok and not reasons
    return {
        "FACTORY_FRONTIER_READY": ready,
        "create_high_reachable": high,
        "callees_ok": callees_ok,
        "indirect_ok": indirect_ok,
        "indirect_detail": indirect_detail,
        "reasons": reasons,
        "failed_callees": [hx(t) for t in callees if t in failed],
        "attempted_compiled": hc.get("compiled"),
    }


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    print("phase17 loading", file=sys.stderr)
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    image = p7.read_sections(game)
    data, by, vas = load_map()

    starts = bytearray(len(blob))
    cs = md()
    off = 0
    while off < len(blob):
        found = list(cs.disasm(blob[off:off + 65536], base + off))
        if not found:
            off += 1
            continue
        for insn in found:
            rel = insn.address - base
            if 0 <= rel < len(blob):
                starts[rel] = 1
        off = found[-1].address + found[-1].size - base

    # --- 0x00722D60 provenance ---
    row = by.get(FLAG_SET1, {})
    e8 = e8_sites(blob, base, FLAG_SET1)
    abs_hits = section_refs(image, FLAG_SET1)
    text_imm = []
    for o in ip.iter_immediates(blob, base, FLAG_SET1):
        classified = ip.classify_encoding(blob, base, o, FLAG_SET1)
        if classified:
            text_imm.append({
                "kind": classified[0],
                "eip": hx(classified[1]),
                "text": classified[2],
                "conf": classified[3],
                "owner": hx(owner_of(vas, by, classified[1])[0] or 0),
            })
    # Why reachable: Phase 16 enrolled CFG-complete int3-padded entries into the
    # ordinary discovery graph. That sets reachable=true without a caller edge.
    after_int3 = blob[FLAG_SET1 - base - 1] == 0xCC if FLAG_SET1 > base else False
    prologue = blob[FLAG_SET1 - base:FLAG_SET1 - base + 3] == b"\x55\x8b\xec"
    writer_body = analyze_flag_writer(blob, base, FLAG_SET1)
    set2_body = analyze_flag_writer(blob, base, 0x00729960)  # near writer
    # find owner of set2
    set2_owner, set2_row = owner_of(vas, by, 0x00729977)
    clear_body = analyze_flag_writer(blob, base, FLAG_CLEAR)

    # Flag reads
    flag_refs = []
    for kind, eip, text, conf in g15.refs_of(blob, base, FLAG):
        owner, orow = owner_of(vas, by, eip)
        flag_refs.append({
            "kind": kind, "eip": hx(eip), "text": text, "conf": conf,
            "owner": hx(owner) if owner else None,
            "owner_label": orow.get("label"),
            "owner_reachable": orow.get("reachable"),
        })

    # Gate in 0x0072E5D0
    gate_listing = g15.decode_linear(blob, base, HIGH_CALLER, limit=80, stop_ret=False)

    # --- slots ---
    slot_info = {}
    for slot, value in SLOTS.items():
        consumers = []
        for kind, eip, text, conf in g15.refs_of(blob, base, slot):
            owner, orow = owner_of(vas, by, eip)
            consumers.append({
                "kind": kind, "eip": hx(eip), "text": text,
                "owner": hx(owner) if owner else None,
                "owner_label": orow.get("label"),
            })
        cov = covering_insn(blob, base, value)
        interior = slot_target_class(blob, base, starts, by, value)
        abi = json.load(open(os.path.join(ANALYSIS, "import-abi.json"), encoding="utf-8"))
        iat = {int(row["thunk"], 16) for row in abi["imports"]}
        writers = [r for r in consumers if r["kind"] == "WRITE"]
        # PE .rdata code-pointer slot with no writer and invalid target:
        # treated as a static sentinel that must be replaced before use, but
        # without PE import evidence it is not classified as an IAT entry.
        if interior.startswith("INVALID") and not writers and consumers:
            final = "RUNTIME_REPLACEMENT_REQUIRED"
        else:
            final = interior
        alts = {
            "linear_sweep_boundary": bool(starts[value - base]),
            "low_bits_cleared": hx(value & ~3),
            "is_iat_thunk_value": value in iat,
            "slot_is_iat": slot in iat,
            "import_like_without_pe_evidence": final == "RUNTIME_REPLACEMENT_REQUIRED",
        }
        slot_info[hx(slot)] = {
            "pe_value": hx(value),
            "section": g15.mapped_dword(image, slot),
            "consumers": consumers,
            "writers_absolute": writers,
            "on_linear_sweep_boundary": bool(starts[value - base]),
            "covering_insn": None if cov is None else {
                "va": hx(cov.address),
                "text": "%s %s" % (cov.mnemonic, cov.op_str),
                "size": cov.size,
                "contains_ptr": cov.address != value,
            },
            "final_class": final,
            "interior_class": interior,
            "alternatives": alts,
        }

    # CEA3F0
    cea = g15.mapped_dword(image, 0x00CEA3F0)

    # --- object ---
    fields, obj_roots = object_field_traffic(blob, base, by, vas)
    # classify key offsets relative to create path
    key_offs = [0x10, 0x54, 0x4C0, 0x4C8, 0x4D0, 0x534]
    field_roles = {}
    for off in key_offs:
        info_f = fields.get(hx(off), {"readers": [], "writers": []})
        writers = info_f.get("writers") or []
        readers = info_f.get("readers") or []
        # +0x10 written by factory with D3D result
        if off == 0x10:
            role = "WRITTEN_BY_FACTORY_PATH"
        elif any(int(w, 16) == CREATE for w in writers):
            role = "WRITTEN_BY_FACTORY_PATH"
        elif readers and not writers:
            role = "MUST_BE_INITIALIZED_BEFORE_FACTORY" if any(
                int(r, 16) in (CREATE, HIGH_CALLER, OUTER) for r in readers
            ) else "UNKNOWN"
        elif writers and not any(int(w, 16) in (CREATE, HIGH_CALLER) for w in writers):
            role = "MUST_BE_INITIALIZED_BEFORE_FACTORY"
        else:
            role = "UNKNOWN"
        # 4C0/4C8/4D0 are lea targets for call esi args - reads of object fields as args
        if off in (0x4C0, 0x4C8, 0x4D0):
            role = "MUST_BE_INITIALIZED_BEFORE_FACTORY"  # pointers/buffers passed to callbacks; may be zero OK?
            # Phase 15: these are lea ecx,[ebx+off] as args - zero may be intentional
            role = "UNKNOWN"  # do not assume nonzero required
        if off == 0x54:
            role = "ONLY_USED_AFTER_FACTORY"
        field_roles[hx(off)] = {"role": role, "readers": readers, "writers": writers}

    # --- TLS ---
    tls_refs = []
    for kind, eip, text, conf in g15.refs_of(blob, base, TLS):
        owner, orow = owner_of(vas, by, eip)
        tls_refs.append({
            "kind": kind, "eip": hx(eip), "text": text,
            "owner": hx(owner) if owner else None,
            "label": orow.get("label"),
        })
    tls_map = g15.mapped_dword(image, TLS)
    # extract TLS use in OUTER
    outer_listing = g15.decode_linear(blob, base, OUTER, limit=100, stop_ret=False)
    tls_seq = [x for x in outer_listing if "1882c34" in x["text"].lower() or "fs:" in x["text"].lower() or "2ch" in x["text"].lower()]

    # prefix requirements
    prefixes = {}
    for name, entry in (("outer", OUTER), ("high_caller", HIGH_CALLER), ("create", CREATE)):
        walk = decode_fn(blob, base, entry)
        abs_mem = walk["abs_mem"]
        prefixes[name] = {
            "entry": hx(entry),
            "label": (by.get(entry) or {}).get("label"),
            "reachable_enrolled": (by.get(entry) or {}).get("reachable"),
            "insns": walk["insns"],
            "calls": [{"eip": hx(a), "target": hx(b), "op": c} for a, b, c in walk["calls"][:40]],
            "abs_mem_sample": [{"eip": hx(a), "slot": hx(b), "m": c, "text": d} for a, b, c, d in abs_mem[:50]],
            "uses_tls_index": any(b == TLS for _, b, _, _ in abs_mem),
            "uses_flag": any(b == FLAG for _, b, _, _ in abs_mem),
            "uses_slots": sorted({hx(b) for _, b, _, _ in abs_mem if b in SLOTS}),
            "calls_helper": any(b == HELPER for _, b, _ in walk["calls"]),
        }

    pre = pre_factory_path(blob, base, by)

    # XCHG semantics from lifter
    xchg_note = {
        "lifter": "non-locked xchg uses temp swap of both operands; mem form swaps register and memory",
        "models_old_in_register": True,
        "models_new_in_memory": True,
        "uses_guest_atomic": False,
        "lock_prefix_on_flag_writers": False,
        "correct_for_single_threaded": True,
        "atomicity": "not claimed; unlocked xchg",
    }
    # verify bytes at writers have no lock prefix
    for site in (0x00722D70, 0x00729977, 0x00B4F997):
        prev = blob[site - base - 1]
        xchg_note.setdefault("sites", []).append({"va": hx(site), "prev_byte": hx(prev), "is_lock": prev == 0xF0})

    flag_invocable = bool(e8) or bool(text_imm)
    tls_required_for_create = prefixes["create"]["uses_tls_index"]
    frontier = factory_frontier(by, blob, base, pre, slot_info, flag_invocable, tls_required_for_create)
    # refine: create path needs valid ESI targets
    if any(s.get("final_class", "").startswith("INVALID") or s.get("final_class") == "RUNTIME_REPLACEMENT_REQUIRED"
           for s in (slot_info.get(hx(0x00B615C4)),)):
        frontier["FACTORY_FRONTIER_READY"] = False
        if "ESI callback slot" not in " ".join(frontier["reasons"]):
            frontier["reasons"].append("ESI callback slot 0x00B615C4 invalid / needs replacement")

    # helper dependence of create
    helper_cut = json.load(open(os.path.join(ANALYSIS, "helper-cut.json"), encoding="utf-8"))
    must = set(helper_cut.get("must") or [])
    may = set(helper_cut.get("may") or [])
    create_helper = "MUST" if hx(CREATE) in must else ("MAY" if hx(CREATE) in may else "NO_PATH")

    # remaining blockers
    blockers = []
    if not flag_invocable:
        blockers.append({"item": "0x01311E1C=1", "class": "UNKNOWN", "note": "writer HIGH enrolled but no ordinary invocation path"})
    for slot, meta in slot_info.items():
        blockers.append({
            "item": slot,
            "class": "UNKNOWN" if meta["final_class"] == "RUNTIME_REPLACEMENT_REQUIRED" else "ORDINARY_PROVENANCE",
            "note": meta["final_class"],
        })
    if tls_map.get("value") == 0 and prefixes["outer"]["uses_tls_index"]:
        blockers.append({"item": "0x01882C34", "class": "TLS_RUNTIME", "note": "PE zero; no ordinary absolute writer"})
    blockers.append({"item": "Direct3DCreate9", "class": "IMPORT_RUNTIME", "note": "unimplemented; stop before call"})
    blockers.append({"item": "0x01318170 zero object", "class": "UNKNOWN", "note": "address-taken; no constructor proven"})

    out = {
        "terminology": {
            "reachable_in_function_map": (
                "Enrolled in the Phase 16 ordinary discovery graph (seed BFS or "
                "CFG-complete strong-entry enrollment). NOT proven call-graph "
                "reachability from a live root."
            ),
            "FLAG_SET1_enrollment": (
                "int3-padded CFG-complete strong entry; score 105 HIGH; "
                "reachable=true from enrollment, zero call/tail predecessors."
            ),
        },
        "flag_writer": {
            "va": hx(FLAG_SET1),
            "map": {k: row.get(k) for k in ("label", "score", "reachable", "insns", "termination", "calls", "reasons")},
            "after_int3": after_int3,
            "frame_prologue": prologue,
            "e8_e9_sites": [{"eip": hx(a), "kind": b} for a, b in e8],
            "section_dword_hits": abs_hits,
            "text_immediate_refs": text_imm,
            "invocation_path": "NONE",
            "body": writer_body,
        },
        "flag_state_machine": {
            "pe_value": 0,
            "transitions": [
                {"from": "ANY", "to": 1, "writer": hx(FLAG_SET1), "site": "0x00722D70", "mechanism": "xchg [ecx],eax with eax=1"},
                {"from": "ANY", "to": 2, "writer": hx(set2_owner) if set2_owner else None, "site": "0x00729977", "mechanism": "xchg [ecx],eax with eax=2"},
                {"from": "ANY", "to": 0, "writer": hx(FLAG_CLEAR), "site": "0x00B4F997", "mechanism": "xchg [ecx],eax with eax=0"},
            ],
            "reads": flag_refs,
            "meaning": {
                "0": "image / cleared state; clearer leaf stores 0",
                "1": "gate value required by 0x0072E5D0 before call 0x0072E340; also produced by 0x00722D60",
                "2": "observed exit/compare value associated with 0x00722D60 after storing 1 (Phase 15)",
                "established": False,
                "note": "Do not equate 1 with 'initialized' beyond the gate compare.",
            },
            "set2_owner": {"va": hx(set2_owner) if set2_owner else None, "label": set2_row.get("label"), "reachable": set2_row.get("reachable")},
            "clear_body": clear_body,
            "gate_sample": [
                {"va": hx(row["va"]), "text": row["text"]} for row in gate_listing[:25]
            ],
        },
        "xchg": xchg_note,
        "slots": slot_info,
        "cea3f0": cea,
        "object": {
            "va": hx(OBJ),
            "pe": g15.mapped_dword(image, OBJ),
            "field_count": len(fields),
            "fields_sample": {k: fields[k] for k in list(fields)[:40]},
            "key_field_roles": field_roles,
            "initializer_roots": obj_roots[:20],
        },
        "tls": {
            "index": hx(TLS),
            "pe": tls_map,
            "refs": tls_refs,
            "writes": [r for r in tls_refs if r["kind"] == "WRITE"],
            "outer_tls_insns": [
                {"va": hx(row["va"]), "text": row["text"]} for row in tls_seq
            ],
            "required_on_create_prefix": tls_required_for_create,
            "required_on_outer": prefixes["outer"]["uses_tls_index"],
            "required_on_high_caller": prefixes["high_caller"]["uses_tls_index"],
        },
        "prefixes": prefixes,
        "pre_factory": pre,
        "create_helper_cut": create_helper,
        "frontier": frontier,
        "blockers": blockers,
        "execution": {
            "ran": False,
            "reason": "FACTORY_FRONTIER_READY is false; no legitimate initializer sequence to execute",
            "reached_before_d3d": False,
        },
        "first_frame_estimate": {
            "best_case_phase": 20,
            "likely_low": 23,
            "likely_high": 31,
            "note": "Static factory reachable; runtime provenance did not close flag/slots/TLS/object.",
        },
    }

    path = os.path.join(ANALYSIS, "phase17-raw.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print("ready", frontier["FACTORY_FRONTIER_READY"], file=sys.stderr)
    print("flag refs", len(text_imm), "e8", len(e8), file=sys.stderr)
    print("slots", {k: v["final_class"] for k, v in slot_info.items()}, file=sys.stderr)
    print("wrote", path)


if __name__ == "__main__":
    main()
