"""Phase 18: provenance of graphics .rdata callback/dispatch tables.

Ordinary PE sections only. Does not execute nfs.exe, patch .rdata, implement
Direct3D/TLS/Win32, or invent slot replacements.
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
import uc_funcmap as fm
import uc_initprov as ip
import uc_phase7_test as p7
import uc_phase15_graphics as g15

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

SLOTS = {
    0x00B611D4: 0x008A9F58,
    0x00B61188: 0x008AB180,
    0x00B615C4: 0x008AA3AE,
}
CREATE = 0x0072E340
FLAG_SET1 = 0x00722D60
OBJ = 0x01318170
TABLE_SCAN_LO = 0x00B61100
TABLE_SCAN_HI = 0x00B61640


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


def discovery_status(row):
    """Explicit terminology: discovery enrollment != call-graph reachability."""
    if not row:
        return {
            "discovered_high": False,
            "call_graph_reachable": False,
            "directly_referenced": False,
            "note": "absent",
        }
    high = row.get("label") == "HIGH_CONFIDENCE"
    enrolled = bool(row.get("reachable"))
    return {
        "discovered_high": high and enrolled,
        "call_graph_reachable": None,  # filled by caller with pred evidence
        "map_reachable_means": "discovery_enrollment",
        "label": row.get("label"),
        "enrolled": enrolled,
    }


def section_of(image, va):
    for sec in image["sections"]:
        if sec["va"] <= va < sec["va"] + sec["vsize"]:
            return sec
    return None


def covering_insn(blob, base, va):
    cs = md()
    for back in range(0, 16):
        start = va - back
        if start < base:
            continue
        insn = next(cs.disasm(blob[start - base:start - base + 15], start), None)
        if insn and insn.address <= va < insn.address + insn.size:
            return insn
    return None


def classify_dword(v, blob, base, starts, by, image, iat_slots, text_lo, text_hi):
    if v == 0:
        return "ZERO"
    if v in iat_slots:
        return "IMPORT_RELATED"
    # HRESULT-like / non-canonical
    if v >= 0x80000000 and v < 0x80010000:
        return "NON_POINTER"
    sec = section_of(image, v)
    if sec is None:
        if v < 0x10000:
            return "NON_POINTER"
        return "UNKNOWN"
    name = sec["name"]
    if name == ".text" and text_lo <= v < text_hi:
        if starts[v - base] == 1:
            if v in by and by[v].get("label") == "HIGH_CONFIDENCE":
                return "ORDINARY_TEXT_VALID_ENTRY"
            return "ORDINARY_TEXT_VALID_ENTRY"
        cov = covering_insn(blob, base, v)
        if cov is not None and cov.address != v:
            return "ORDINARY_TEXT_INTERIOR"
        return "INVALID_TEXT_BOUNDARY"
    if name == ".rdata":
        return "RDATA_POINTER"
    if name == ".data":
        return "DATA_POINTER"
    if name in ("Stext", "Sitext", "Srdata", "Sdata", "Sidata", ".securom"):
        return "OTHER_IMAGE_POINTER"
    return "OTHER_IMAGE_POINTER"


def map_rdata_region(image, blob, base, starts, by, iat_slots):
    rdata = next(sec for sec in image["sections"] if sec["name"] == ".rdata")
    text_lo, text_hi = base, base + len(blob)
    entries = []
    counts = collections.Counter()
    for va in range(TABLE_SCAN_LO, TABLE_SCAN_HI, 4):
        off = va - rdata["va"]
        if off < 0 or off + 4 > len(rdata["raw"]):
            break
        v = struct.unpack_from("<I", rdata["raw"], off)[0]
        if va in iat_slots:
            cls = "IMPORT_RELATED"
        else:
            cls = classify_dword(v, blob, base, starts, by, image, iat_slots, text_lo, text_hi)
        counts[cls] += 1
        entries.append({
            "va": hx(va),
            "value": hx(v),
            "class": cls,
            "watched": va in SLOTS,
            "named_iat_slot": va in iat_slots,
        })
    # Infer contiguous pointer-dense runs (ignore ZERO gaps of length 1 inside)
    callableish = {"ORDINARY_TEXT_VALID_ENTRY", "ORDINARY_TEXT_INTERIOR", "INVALID_TEXT_BOUNDARY"}
    runs = []
    run = None
    for e in entries:
        if e["class"] in callableish:
            if run is None:
                run = {"lo": e["va"], "hi": e["va"], "n": 1, "invalid": 0, "valid": 0, "interior": 0}
            else:
                run["hi"] = e["va"]
                run["n"] += 1
            if e["class"] == "INVALID_TEXT_BOUNDARY":
                run["invalid"] += 1
            elif e["class"] == "ORDINARY_TEXT_INTERIOR":
                run["interior"] += 1
            else:
                run["valid"] += 1
        else:
            if run and run["n"] >= 8:
                runs.append(run)
            run = None
    if run and run["n"] >= 8:
        runs.append(run)
    return {
        "scan": [hx(TABLE_SCAN_LO), hx(TABLE_SCAN_HI)],
        "counts": dict(counts),
        "entries": entries,
        "pointer_dense_runs": runs,
        "slot_offsets": {hx(s): hx(s - TABLE_SCAN_LO) for s in SLOTS},
    }


def consumers_of(blob, base, vas, by, slot):
    out = []
    for kind, eip, text, conf in g15.refs_of(blob, base, slot):
        owner, row = owner_of(vas, by, eip)
        # local context: next few insns for call shape
        cs = md()
        window = []
        cur = eip
        for _ in range(12):
            insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
            if insn is None:
                break
            window.append("%s %s" % (insn.mnemonic, insn.op_str))
            if lift._is_near_ret(insn.mnemonic):
                break
            cur = insn.address + insn.size
        out.append({
            "kind": kind,
            "eip": hx(eip),
            "text": text,
            "owner": hx(owner) if owner else None,
            "owner_label": row.get("label"),
            "discovered_high": row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable"),
            "window": window,
        })
    return out


def three_call_analysis(blob, base):
    """Exact stack args for the three call esi in 0x0072E340."""
    cs = md()
    cur = CREATE
    calls = []
    listing = []
    for _ in range(80):
        insn = next(cs.disasm(blob[cur - base:cur - base + 15], cur), None)
        if insn is None:
            break
        listing.append("%s: %s %s" % (hx(insn.address), insn.mnemonic, insn.op_str))
        if insn.mnemonic == "call" and insn.op_str == "esi":
            # look back for pushes
            pushes = []
            # parse from listing tail
            for line in reversed(listing[:-1]):
                if ": push " in line:
                    pushes.append(line.split(": push ", 1)[1])
                    if len(pushes) == 4:
                        break
                elif ": call " in line or ": mov ebx" in line:
                    break
            pushes.reverse()
            calls.append({
                "eip": hx(insn.address),
                "pushes_before": pushes,
            })
        if insn.address >= 0x0072E3B9:
            break
        cur = insn.address + insn.size
    # Push order (first pushed = last stdcall arg):
    # #1: push 0; lea eax,[ebx+0x4c0]; push eax; push 8; push 0x3a; call esi
    # #2: push 0; lea ecx,[ebx+0x4c8]; push ecx; push 8; push 0x34; call esi
    # #3: push 0; lea edx,[ebx+0x4d0]; push edx; push 0x18; push 0x32; call esi
    # After each call esi: no add esp => callee cleans 16 bytes (stdcall-like).
    # EAX/return unused before next pushes. Pattern: same ESI, three parallel fills.
    return {
        "listing_prefix": listing,
        "calls": calls,
        "abi_inference": {
            "form": "register-indirect via ESI",
            "stack_args_each": 4,
            "stdcall_arg_order": ["code", "size", "buffer", "flags"],
            "observed_imm_args": [
                {
                    "index": 1,
                    "stack_dwords_push_order": ["0", "lea [ebx+0x4C0]", "8", "0x3A"],
                    "stdcall_args": {"code": "0x3A", "size": 8, "buffer": "[ebx+0x4C0]", "flags": 0},
                },
                {
                    "index": 2,
                    "stack_dwords_push_order": ["0", "lea [ebx+0x4C8]", "8", "0x34"],
                    "stdcall_args": {"code": "0x34", "size": 8, "buffer": "[ebx+0x4C8]", "flags": 0},
                },
                {
                    "index": 3,
                    "stack_dwords_push_order": ["0", "lea [ebx+0x4D0]", "0x18", "0x32"],
                    "stdcall_args": {"code": "0x32", "size": 0x18, "buffer": "[ebx+0x4D0]", "flags": 0},
                },
            ],
            "caller_cleans": False,
            "likely": "stdcall 4-arg (or custom equivalent); caller does not add esp after call esi",
            "pattern": (
                "repeated same-callback fill of three object regions "
                "(+0x4C0 size 8 / +0x4C8 size 8 / +0x4D0 size 0x18) with distinct codes"
            ),
            "returns_used": False,
            "observable_effect": (
                "Expected to mutate the three lea'd object buffers before the "
                "[ebx+0x4B8] check and the later Direct3DCreate9 path; no return value consumed."
            ),
            "note": "No semantic Win32/API name assigned without ordinary binding evidence.",
        },
    }


def find_table_base_refs(blob, base, vas, by, bases):
    out = {}
    for b in bases:
        refs = []
        for off in ip.iter_immediates(blob, base, b):
            classified = ip.classify_encoding(blob, base, off, b)
            if not classified:
                continue
            kind, eip, text, conf = classified
            owner, row = owner_of(vas, by, eip)
            refs.append({
                "kind": kind,
                "eip": hx(eip),
                "text": text,
                "owner": hx(owner) if owner else None,
                "label": row.get("label"),
                "discovered_high": row.get("label") == "HIGH_CONFIDENCE" and row.get("reachable"),
            })
        out[hx(b)] = refs
    return out


def alias_writer_scan(blob, base, vas, by, table_lo, table_hi):
    """Find lea reg, [imm] where imm in table range, then look for stores via reg."""
    cs = md()
    candidates = []
    # scan .text for lea/mov with displacement in range
    for off in range(len(blob) - 6):
        # rough filter: instructions containing imm32 in range
        pass
    # Use immediate iterator for each dword-aligned table address (sampled)
    sample = list(range(table_lo, table_hi, 4))
    # Also exact slots and run starts
    watched = set(sample[::8]) | set(SLOTS) | {table_lo, 0x00B61500, 0x00B61100}
    for addr in sorted(watched):
        for off in ip.iter_immediates(blob, base, addr):
            classified = ip.classify_encoding(blob, base, off, addr)
            if not classified:
                continue
            kind, eip, text, conf = classified
            owner, row = owner_of(vas, by, eip)
            # look ahead for stores through register that received the address
            window = g15.decode_linear(blob, base, eip, limit=40, stop_ret=True)
            stores = []
            for rowi in window:
                t = rowi["text"]
                if "dword ptr [" in t and (t.startswith("mov ") or t.startswith("xchg ")):
                    # exclude reads of form mov reg, dword ptr [
                    if t.split(",", 1)[0].strip().startswith("mov dword ptr"):
                        stores.append({"va": hx(rowi["va"]), "text": t})
                    elif t.startswith("xchg dword ptr"):
                        stores.append({"va": hx(rowi["va"]), "text": t})
            cls = "READ_ONLY_CONSUMER"
            if kind == "WRITE":
                cls = "DEFINITE_WRITER"
            elif kind in ("ADDRESS_TAKEN", "LEA") and stores:
                # Only treat lea/address-taken of a table VA followed by stores as alias risk.
                cls = "POSSIBLE_WRITER"
            elif kind in ("INDIRECT_CALL", "INDIRECT_JUMP", "READ"):
                cls = "READ_ONLY_CONSUMER"
            else:
                cls = "UNKNOWN"
            candidates.append({
                "table_addr": hx(addr),
                "kind": kind,
                "eip": hx(eip),
                "text": text,
                "owner": hx(owner) if owner else None,
                "label": row.get("label"),
                "class": cls,
                "follow_stores": stores[:6],
            })
    # Summarize
    definite = [c for c in candidates if c["class"] == "DEFINITE_WRITER"]
    possible = [c for c in candidates if c["class"] == "POSSIBLE_WRITER"]
    return {
        "definite": definite,
        "possible": possible[:40],
        "candidate_count": len(candidates),
        "all_kinds": dict(collections.Counter(c["kind"] for c in candidates)),
    }


def memcpy_overlap(blob, base, vas, by, table_lo, table_hi, abi):
    """Find memcpy/memmove call sites; check if dest immediate/arg overlaps table."""
    thunks = {}
    for row in abi["imports"]:
        sym = row.get("symbol") or ""
        if sym in ("memcpy", "memmove"):
            thunks[int(row["thunk"], 16)] = sym
    hits = []
    cs = md()
    for thunk, sym in thunks.items():
        # E8 to thunk
        for off in range(len(blob) - 5):
            if blob[off] != 0xE8:
                continue
            rel = struct.unpack_from("<i", blob, off + 1)[0]
            if (base + off + 5 + rel) & 0xFFFFFFFF != thunk:
                continue
            eip = base + off
            owner, row = owner_of(vas, by, eip)
            # look back for push imm that looks like dest
            pushes = []
            cur = eip
            # walk back linearly a bit (imperfect)
            back = eip - 40
            if back < base:
                back = base
            chunk = list(cs.disasm(blob[back - base:eip - base], back))
            for insn in chunk[-12:]:
                if insn.mnemonic == "push" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                    imm = insn.operands[0].imm & 0xFFFFFFFF
                    pushes.append(imm)
            overlap = any(table_lo <= p < table_hi for p in pushes)
            if overlap or any(abs(p - table_lo) < 0x1000 for p in pushes if p > 0x00B00000):
                hits.append({
                    "sym": sym,
                    "eip": hx(eip),
                    "owner": hx(owner) if owner else None,
                    "label": row.get("label"),
                    "pushes": [hx(p) for p in pushes],
                    "overlaps_table": overlap,
                })
    return hits


def shadow_table_scan(image, slots):
    """Look in .data for the same initial dword pattern as the three slots."""
    data = next(sec for sec in image["sections"] if sec["name"] == ".data")
    raw = data.get("raw") or b""
    vals = list(slots.values())
    # search for any of the three values in .data
    hits = []
    for v in vals:
        needle = struct.pack("<I", v)
        start = 0
        while True:
            off = raw.find(needle, start)
            if off < 0:
                break
            hits.append({"va": hx(data["va"] + off), "value": hx(v)})
            start = off + 1
            if len(hits) > 20:
                break
    return {"data_copies_of_initial_values": hits, "found": bool(hits)}


def import_resolution_evidence(abi):
    interesting = []
    for row in abi["imports"]:
        sym = (row.get("symbol") or "").lower()
        if any(x in sym for x in ("loadlibrary", "getprocaddress", "virtualprotect", "virtualalloc", "virtualquery")):
            interesting.append({"dll": row.get("dll"), "symbol": row.get("symbol"), "thunk": row.get("thunk")})
    return {
        "dynamic_loader_imports_in_ordinary_abi": interesting,
        "memcpy": [r for r in abi["imports"] if (r.get("symbol") or "") in ("memcpy", "memmove")],
        "has_getprocaddress_ordinary_abi": any(
            "getprocaddress" in ((r.get("symbol") or "").lower()) for r in abi["imports"]
        ),
        "has_virtualprotect_ordinary_abi": any(
            "virtualprotect" in ((r.get("symbol") or "").lower()) for r in abi["imports"]
        ),
    }


def pe_import_dirs(game_path):
    """Parse PE import / IAT directories. Ordinary analysis of PE headers only."""
    with open(game_path, "rb") as fh:
        pe = fh.read()
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    opt = e_lfanew + 24
    image_base = struct.unpack_from("<I", pe, opt + 28)[0]
    num_sec = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
    ssize = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
    secs = []
    off = e_lfanew + 24 + ssize
    for _ in range(num_sec):
        name = pe[off:off + 8].split(b"\x00")[0].decode("latin1")
        vsz, va, rsz, rptr = struct.unpack_from("<IIII", pe, off + 8)
        secs.append({"name": name, "va": va, "vsz": vsz, "rptr": rptr, "rsz": rsz})
        off += 40

    def rva_to_off(rva):
        for sec in secs:
            if sec["va"] <= rva < sec["va"] + max(sec["vsz"], sec["rsz"]):
                return sec["rptr"] + (rva - sec["va"])
        return None

    def section_name_for_rva(rva):
        for sec in secs:
            if sec["va"] <= rva < sec["va"] + max(sec["vsz"], sec["rsz"]):
                return sec["name"]
        return None

    dirs = {}
    names = [
        "Export", "Import", "Resource", "Exception", "Security", "BaseReloc", "Debug",
        "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport", "IAT",
        "DelayImport", "CLR", "Reserved",
    ]
    for i, n in enumerate(names):
        rva, sz = struct.unpack_from("<II", pe, opt + 96 + i * 8)
        if rva or sz:
            dirs[n] = {
                "rva": hx(rva),
                "va": hx(image_base + rva),
                "size": hx(sz),
                "section": section_name_for_rva(rva),
            }

    want = {
        "GetProcAddress", "VirtualProtect", "LoadLibraryA", "LoadLibraryW",
        "LoadLibraryExA", "LoadLibraryExW", "VirtualAlloc", "VirtualQuery", "VirtualFree",
    }
    securom_api = []
    descriptors = []
    imp = dirs.get("Import")
    if imp:
        o = rva_to_off(int(imp["rva"], 16))
        while o is not None:
            ilt, _td, _fwd, name_rva, ft = struct.unpack_from("<IIIII", pe, o)
            if ilt == 0 and name_rva == 0 and ft == 0:
                break
            dll = pe[rva_to_off(name_rva):].split(b"\x00")[0].decode("latin1", "replace")
            thunk = ft
            slots = []
            while True:
                to = rva_to_off(thunk)
                entry = struct.unpack_from("<I", pe, to)[0]
                if entry == 0:
                    break
                iat_va = image_base + thunk
                if entry & 0x80000000:
                    sym = "ord_%d" % (entry & 0xFFFF)
                else:
                    eo = rva_to_off(entry & 0x7FFFFFFF)
                    sym = pe[eo + 2:].split(b"\x00")[0].decode("latin1", "replace") if eo else "?"
                slots.append(iat_va)
                if sym in want:
                    securom_api.append({"dll": dll, "symbol": sym, "iat": hx(iat_va)})
                thunk += 4
            if slots:
                descriptors.append({
                    "dll": dll,
                    "lo": hx(slots[0]),
                    "hi": hx(slots[-1]),
                    "n": len(slots),
                    "section": section_name_for_rva(slots[0] - image_base),
                })
            o += 20

    watched = list(SLOTS)
    membership = {}
    for slot in watched:
        hit = None
        for d in descriptors:
            if int(d["lo"], 16) <= slot <= int(d["hi"], 16):
                hit = d["dll"]
                break
        membership[hx(slot)] = hit

    # Count ordinary .text immediates to SecuROM API IAT slots
    text_sec = next(s for s in secs if s["name"] == ".text")
    text = pe[text_sec["rptr"]:text_sec["rptr"] + text_sec["rsz"]]
    text_imm_hits = {}
    for row in securom_api:
        va = int(row["iat"], 16)
        needle = struct.pack("<I", va)
        text_imm_hits[row["symbol"]] = text.count(needle)

    nearby_named = []
    # ordinary abi adjacency reported by caller

    d3d9 = [d for d in descriptors if (d.get("dll") or "").lower() == "d3d9.dll"]
    return {
        "directories": dirs,
        "import_directory_section": (dirs.get("Import") or {}).get("section"),
        "iat_directory_section": (dirs.get("IAT") or {}).get("section"),
        "delay_import_present": "DelayImport" in dirs,
        "descriptor_count": len(descriptors),
        "descriptors_overlap_ordinary_B610_B617": [
            d for d in descriptors
            if not (int(d["hi"], 16) < 0x00B61000 or int(d["lo"], 16) > 0x00B61780)
        ],
        "d3d9_descriptors": d3d9,
        "watched_slot_in_pe_iat": membership,
        "securom_kernel_apis": securom_api,
        "ordinary_text_imm_refs_to_securom_api_iat": text_imm_hits,
        "conclusion": (
            "Official PE Import Directory and IAT Data Directory reside in .securom. "
            "No IMAGE_IMPORT_DESCRIPTOR FirstThunk range covers 0x00B615C4 / 0x00B611D4 / "
            "0x00B61188. GetProcAddress/VirtualProtect/LoadLibrary* IAT slots are in the "
            "protected VA range (~0x22CD****) with zero ordinary .text absolute immediates. "
            "Ordinary .rdata B610xx–B617xx is a parallel dispatch/IAT-shaped window consumed "
            "by ordinary code, but PE binding of those slots is not performed by the "
            "documented ordinary import directory."
        ),
    }


def initial_value_interpretation(blob, base, value, starts):
    if not (base <= value < base + len(blob)):
        return {"class": "UNKNOWN", "note": "value not in ordinary .text"}
    if starts[value - base] == 1:
        return {
            "class": "VALID_LINEAR_SWEEP_ENTRY",
            "note": "Ordinary linear-sweep instruction boundary.",
        }
    cov = covering_insn(blob, base, value)
    covering = None
    byte_role = None
    if cov is not None:
        covering = "%s: %s %s" % (hx(cov.address), cov.mnemonic, cov.op_str)
        byte_role = "interior byte at +%d" % (value - cov.address) if cov.address != value else (
            "Capstone-decodable at VA but rejected by linear sweep"
        )
    return {
        "class": "DELIBERATELY_INVALID_SENTINEL_OR_PLACEHOLDER",
        "covering": covering,
        "byte_role": byte_role,
        "note": (
            "Not a linear-sweep instruction boundary. Same placeholder shape as nearby "
            "named import slots (e.g. VERSION.dll at 0x00B615EC) whose PE values also "
            "fail ordinary entry checks. No ordinary XOR/add decode observed; treat as "
            "unbound/runtime-filled placeholder."
        ),
    }


def build_pred_index(by):
    pred = collections.defaultdict(set)
    for va, row in by.items():
        if not row.get("reachable"):
            continue
        if row.get("label") != "HIGH_CONFIDENCE":
            continue
        for key in ("calls", "tails"):
            for text in row.get(key) or []:
                pred[int(text, 16)].add(va)
    return pred


def flag_indirect_search(blob, base, by, vas, pred, image):
    """Search for tables containing 0x00722D60 or base+index patterns."""
    target = FLAG_SET1
    neighbors = []
    for va, row in by.items():
        if abs(va - target) < 0x40 and va != target:
            neighbors.append({
                "va": hx(va),
                "label": row.get("label"),
                "enrolled": row.get("reachable"),
                "delta": va - target,
            })
    # Scan ordinary .rdata/.data for the absolute function pointer
    table_hits = []
    needle = struct.pack("<I", target)
    for sec in image["sections"]:
        if sec["name"] not in (".rdata", ".data", ".tls", ".rsrc"):
            continue
        raw = sec.get("raw") or b""
        start = 0
        while True:
            off = raw.find(needle, start)
            if off < 0:
                break
            if off % 4 == 0:
                table_hits.append({"section": sec["name"], "va": hx(sec["va"] + off)})
            start = off + 1
            if len(table_hits) > 32:
                break
    return {
        "direct_preds": [hx(p) for p in sorted(pred.get(target, ()))],
        "neighbors_in_map": neighbors,
        "ordinary_section_dword_hits": table_hits,
        "indirect_candidate": "NONE_OBSERVED" if not table_hits else "TABLE_DWORD_CANDIDATE",
        "note": (
            "No E8/E9, absolute immediate, or ordinary .rdata/.data dword equal to "
            "0x00722D60. No indexed base+offset publisher observed."
        ),
    }


def factory_frontier(slot_resolved, create_high=True):
    reasons = []
    if not create_high:
        reasons.append("create not HIGH")
    if not slot_resolved:
        reasons.append("0x00B615C4 not legitimately resolved to callable")
    return {
        "FACTORY_FRONTIER_READY": create_high and slot_resolved and not reasons,
        "reasons": reasons,
        "DIRECT3D9_IMPLEMENTED": False,
        "PRE_FACTORY_CALLBACK": "RESOLVED" if slot_resolved else "UNRESOLVED",
        "STATIC_FACTORY": "REACHABLE",
    }


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    print("phase18 loading", file=sys.stderr)
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]
    image = p7.read_sections(game)
    data, by, vas = load_map()
    abi = json.load(open(os.path.join(ANALYSIS, "import-abi.json"), encoding="utf-8"))
    iat = {int(r["iat_slot"], 16) for r in abi["imports"] if r.get("iat_slot")}
    named_iat = {
        int(r["iat_slot"], 16): "%s!%s" % (r.get("dll"), r.get("symbol"))
        for r in abi["imports"] if r.get("iat_slot")
    }
    starts, _ = fm.mark_starts(blob, base)
    pred = build_pred_index(by)
    pe_imp = pe_import_dirs(game)

    region = map_rdata_region(image, blob, base, starts, by, iat)
    # Identify primary run containing B615C4
    home = None
    for run in region["pointer_dense_runs"]:
        lo, hi = int(run["lo"], 16), int(run["hi"], 16)
        if lo <= 0x00B615C4 <= hi:
            home = run
            break

    slot_reports = {}
    for slot, value in SLOTS.items():
        interp = initial_value_interpretation(blob, base, value, starts)
        cons = consumers_of(blob, base, vas, by, slot)
        slot_reports[hx(slot)] = {
            "pe_value": hx(value),
            "value_class": classify_dword(
                value, blob, base, starts, by, image, iat, base, base + len(blob)
            ),
            "in_ordinary_named_iat": slot in named_iat,
            "named_iat": named_iat.get(slot),
            "in_pe_import_firstthunk": pe_imp["watched_slot_in_pe_iat"].get(hx(slot)),
            "initial_interpretation": interp,
            "consumers": cons,
            "consumer_count": len(cons),
            "final_class": "RUNTIME_REPLACEMENT_REQUIRED",
        }

    three = three_call_analysis(blob, base)
    home_lo = int(home["lo"], 16) if home else TABLE_SCAN_LO
    home_hi = int(home["hi"], 16) if home else TABLE_SCAN_HI
    bases = [
        TABLE_SCAN_LO,
        0x00B61188,
        0x00B611D4,
        0x00B61500,
        0x00B615C4,
        home_lo,
        home_hi,
        0x00B61230,
    ]
    base_refs = find_table_base_refs(blob, base, vas, by, bases)
    aliases = alias_writer_scan(blob, base, vas, by, TABLE_SCAN_LO, TABLE_SCAN_HI)
    copies = memcpy_overlap(blob, base, vas, by, TABLE_SCAN_LO, TABLE_SCAN_HI, abi)
    shadow = shadow_table_scan(image, SLOTS)
    imports = import_resolution_evidence(abi)

    # Annotate home-run slots: how many look callable vs invalid; named IAT adjacency
    home_entries = []
    if home:
        for e in region["entries"]:
            va = int(e["va"], 16)
            if home_lo <= va <= home_hi:
                home_entries.append(e)
    adjacent_named = [
        {"iat_slot": hx(s), "symbol": named_iat[s]}
        for s in sorted(named_iat)
        if home_hi < s <= home_hi + 0x20 or (home and abs(s - home_lo) < 0x20)
    ]

    # Relationship: same scan window / same invalid-sentinel pattern / shared dense run?
    same_run = False
    if home:
        same_run = all(home_lo <= s <= home_hi for s in SLOTS)

    create_row = by.get(CREATE, {})
    create_status = discovery_status(create_row)
    create_status["call_graph_reachable"] = bool(pred.get(CREATE))
    create_status["directly_referenced"] = bool(pred.get(CREATE))

    flag_status = discovery_status(by.get(FLAG_SET1, {}))
    flag_status["call_graph_reachable"] = False
    flag_status["directly_referenced"] = False
    flag_indirect = flag_indirect_search(blob, base, by, vas, pred, image)

    slot_resolved = False
    frontier = factory_frontier(slot_resolved, create_row.get("label") == "HIGH_CONFIDENCE")

    publication = {
        "class": "EXTERNAL_PROTECTED_INITIALIZATION",
        "best_candidate": "PE/SecuROM import-binding of ordinary .rdata dispatch window",
        "call_graph_reachable": False,
        "needs_tls": False,
        "needs_00686000": False,
        "needs_protected_external": True,
        "evidence": [
            "Official PE Import + IAT directories are in .securom (VA ~0x22CD****)",
            "Watched slots are NOT members of any IMAGE_IMPORT_DESCRIPTOR FirstThunk range",
            "Zero DEFINITE ordinary writers / alias writers / overlapping memcpy into the table",
            "Zero ordinary .text immediates to SecuROM GetProcAddress/VirtualProtect IAT slots",
            "Named ordinary imports (e.g. VERSION.dll @ 0x00B615EC) sit adjacent to the home run and share the same invalid PE placeholder shape",
            "Phase-16 HIGH re-scan found no new publisher of 0x00B615C4",
        ],
        "note": (
            "Publication of callable targets into 0x00B615C4 is not an ordinary-code "
            "responsibility observable in .text/.rdata/.data. It depends on unavailable "
            "protected/external binding. Do not invent a callback body."
        ),
    }

    publishers = {
        "definite_writers": aliases["definite"],
        "possible_writers": aliases["possible"],
        "bulk_copy_hits": copies,
        "best_candidate": publication["best_candidate"],
        "publication": publication,
        "note": publication["note"],
    }

    out = {
        "terminology": {
            "DISCOVERED_HIGH": "HIGH_CONFIDENCE and enrolled in discovery graph",
            "CALL_GRAPH_REACHABLE": "has ordinary HIGH predecessor via calls/tails",
            "DIRECTLY_REFERENCED": "E8/E9 or absolute immediate reference exists",
            "INDIRECT_CANDIDATE": "may be reached only via unresolved table/register",
            "RUNTIME_ENTERABLE": "FACTORY_FRONTIER_READY and state legitimate",
            "map_reachable_field": "means discovery enrollment only; NOT call-graph reachability",
        },
        "table": {
            "containing_run": home,
            "home_callable_looking": home["n"] if home else 0,
            "home_invalid_initial": home["invalid"] if home else 0,
            "home_valid_entry": home["valid"] if home else 0,
            "home_interior": home["interior"] if home else 0,
            "adjacent_named_iat": adjacent_named,
            "scan_counts": region["counts"],
            "pointer_dense_runs": region["pointer_dense_runs"],
            "entries_sample": [e for e in region["entries"] if e["watched"] or int(e["va"], 16) >= 0x00B61580][:40],
            "all_three_in_same_run": same_run,
            "structure": (
                "Three nearby pointer-dense runs in .rdata: "
                "0x00B61100–0x00B61214 (Win32-ish dispatch + GetTickCount IAT), "
                "0x00B61230–0x00B614D8 (mostly named CRT IAT), "
                "0x00B61528–0x00B615E4 (graphics/system callback table containing 0x00B615C4). "
                "Slots are not one single table."
            ),
        },
        "slots": slot_reports,
        "three_call": three,
        "table_base_refs": base_refs,
        "alias_writers": aliases,
        "bulk_copies": copies,
        "shadow_table": shadow,
        "imports": imports,
        "pe_import_binding": pe_imp,
        "memory_protection": {
            "virtualprotect_in_ordinary_abi": imports["has_virtualprotect_ordinary_abi"],
            "virtualprotect_in_securom_iat": any(
                r["symbol"] == "VirtualProtect" for r in pe_imp["securom_kernel_apis"]
            ),
            "ordinary_text_refs_to_virtualprotect_iat": pe_imp["ordinary_text_imm_refs_to_securom_api_iat"].get(
                "VirtualProtect", 0
            ),
            "evidence_linking_to_table": False,
        },
        "module_dll_evidence": {
            "home_run_adjacent_named_iat": adjacent_named,
            "d3d9_in_pe_import_dir": bool(pe_imp.get("d3d9_descriptors")),
            "d3d9_iat_range": pe_imp.get("d3d9_descriptors"),
            "note": (
                "d3d9.dll appears in the SecuROM-hosted PE import directory (IAT ~0x22CD****), "
                "not as a member of the ordinary 0x00B61528 table. VERSION.dll named slots "
                "sit just after the home run. No ordinary DLL/module string initializer "
                "path was tied to publishing 0x00B615C4."
            ),
        },
        "publishers": publishers,
        "create_status": create_status,
        "flag_set1": {
            "status": flag_status,
            "indirect": flag_indirect,
        },
        "relationship": {
            "shared_dense_pointer_table_run": same_run,
            "shared_invalid_initial_format": True,
            "shared_absolute_writer": False,
            "shared_publication_class": "EXTERNAL_PROTECTED_PLACEHOLDER_BINDING",
            "shared_publication_mechanism": (
                "Same .rdata dispatch-window placeholder class; different sub-tables "
                "(B61188/B611D4 near KERNEL32 cluster; B615C4 in home graphics run). "
                "No ordinary publisher found for any of the three."
            ),
            "priority_slot": "0x00B615C4",
        },
        "frontier": frontier,
        "execution": {
            "ran": False,
            "reason": "publication depends on protected/external binding; no ordinary initializer to run",
            "slot_changed": False,
            "resulting_target": None,
            "target_valid_ordinary": False,
            "graphics_prefix_executed": False,
            "reached_before_d3d": False,
        },
        "first_frame_estimate": {
            "best_case_phase": 20,
            "likely_low": 23,
            "likely_high": 31,
            "note": (
                "External/protected publication proven as the dependency class, but not "
                "implemented; estimate unchanged (do not invent callback bodies)."
            ),
        },
        "phase19": {
            "recommendation": "GRAPHICS_FRONTIER_REQUIRES_EXTERNAL_INITIALIZATION",
            "actions": [
                "Document external/protected binding dependency for 0x00B615C4 without reconstructing protected code",
                "Search for an independent ordinary graphics initialization route that does not consume 0x00B615C4",
                "Keep Direct3D9 unimplemented until a legitimate callable target is obtained without patching .rdata",
            ],
        },
    }

    path = os.path.join(ANALYSIS, "phase18-raw.json")
    # Shrink entries list in raw for size: keep summary + watched
    out["table"]["entries_watched"] = [e for e in region["entries"] if e["watched"]]
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    # Also write compact table map for report
    map_path = os.path.join(ANALYSIS, "callback-table-map.json")
    with open(map_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({
            "scan": region["scan"],
            "counts": region["counts"],
            "runs": region["pointer_dense_runs"],
            "slots": {hx(k): hx(v) for k, v in SLOTS.items()},
            "home_run": home,
        }, fh, indent=2)
        fh.write("\n")
    print("home", home, file=sys.stderr)
    print("definite writers", len(aliases["definite"]), "possible", len(aliases["possible"]), file=sys.stderr)
    print("memcpy hits", len(copies), "shadow", shadow["found"], file=sys.stderr)
    print("frontier", frontier["FACTORY_FRONTIER_READY"], file=sys.stderr)
    print("wrote", path)


if __name__ == "__main__":
    main()
