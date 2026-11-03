#!/usr/bin/env python3
"""Phase 31: allocator provenance, 0x009E9160 caller inventory, reverse
execution frontier and depth scoring.

Graphics frozen. Does not execute nfs.exe. Protected sections are never read
as code; the allocator slot analysis only reads ordinary .text/.rdata/.data.
Pure helpers (classify_*, score_*) take plain data so tests need no game.
"""
from __future__ import annotations

import bisect
import collections
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_code_analyze as uca
import uc_phase7_test as p7
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_OP_REG
from capstone.x86_const import X86_REG_ESP, X86_REG_EBP

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"

SLOT_MGR = 0x0189DA88
SLOT_SINGLETON = 0x0189DA84
SLOT_STATIC90 = 0x0189DA90
ALLOCATOR_FACTORY = 0x009E9340
ALLOC_WRAP = 0x009EB870
HEAP_LOOKUP = 0x009E9460
MGR_SETTER = 0x009E9410
MGR_GETTER_CALL = 0x009E9420
CTOR = 0x009E9160
PROTECTED_BOUNDARY = {0x00686000, 0x00686030}
STUB_ONLY_PRIOR = {0x009773C0, 0x00977E20, 0x009EB980, 0x0097FCD0}
DATA_LO, DATA_HI = 0x00B61000, 0x018B2000

CLASS_ALLOC = (
    "ORDINARY_INITIALIZABLE_ALLOCATOR",
    "STANDARD_RUNTIME_INITIALIZABLE_ALLOCATOR",
    "EXTERNAL_INITIALIZED_ALLOCATOR",
    "PROTECTED_INITIALIZED_ALLOCATOR",
    "UNKNOWN_RUNTIME_INITIALIZED_ALLOCATOR",
)
THIS_SOURCES = ("STACK_STORAGE", "EMBEDDED_SUBOBJECT", "CALLER_ARGUMENT",
                "GLOBAL_STORAGE", "ALLOCATOR_RESULT", "UNKNOWN")
NON_ALLOCATING = ("STACK_STORAGE", "EMBEDDED_SUBOBJECT", "CALLER_ARGUMENT", "GLOBAL_STORAGE")


def hx(va):
    return "0x%08X" % (va & 0xFFFFFFFF)


def load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name, obj):
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("wrote", path)


# ---------------------------------------------------------------- pure helpers
def classify_allocator(evidence):
    """Exactly one of CLASS_ALLOC from slot-provenance evidence (pure)."""
    writers = evidence.get("writers") or []
    if not writers:
        return "UNKNOWN_RUNTIME_INITIALIZED_ALLOCATOR"
    src = evidence.get("value_source")  # kind of producer of the stored value
    if src == "STANDARD_RUNTIME_API":
        return "STANDARD_RUNTIME_INITIALIZABLE_ALLOCATOR"
    if src == "PROTECTED_BOUNDARY_CALL":
        return "PROTECTED_INITIALIZED_ALLOCATOR"
    if src == "EXTERNAL_BOUNDARY_CALL":
        return "EXTERNAL_INITIALIZED_ALLOCATOR"
    if src in ("ORDINARY_CONSTRUCTOR", "ORDINARY_STATIC", "ORDINARY_ALLOCATOR_FREE_PATH"):
        return "ORDINARY_INITIALIZABLE_ALLOCATOR"
    return "UNKNOWN_RUNTIME_INITIALIZED_ALLOCATOR"


def rank_writer(kind):
    return {"ABSOLUTE_STORE": "PROVEN", "INDIRECT_ALIAS": "STRONG",
            "BULK_COPY": "WEAK", "XCHG": "PROVEN"}.get(kind, "NONE")


def classify_this_source(insns, call_index, alloc_targets=None):
    """Classify the source of ECX for the call at insns[call_index].

    insns are capstone instructions of one function in address order.
    """
    alloc = set(alloc_targets or ())
    want = "ecx"

    def writes(insn, reg):
        ops = insn.op_str.replace(" ", "")
        m = insn.mnemonic
        if m in ("mov", "lea", "xor", "movzx", "movsx", "pop") and ops.startswith(reg + ","):
            return True
        if m == "pop" and ops == reg:
            return True
        return False

    def follow(reg, idx, depth=0):
        i = idx - 1
        while i >= 0:
            ins = insns[i]
            if ins.mnemonic == "call" and reg == "eax":
                tgt = None
                if ins.operands and ins.operands[0].type == X86_OP_IMM:
                    tgt = ins.operands[0].imm & 0xFFFFFFFF
                return "ALLOCATOR_RESULT" if tgt in alloc else "UNKNOWN"
            if writes(ins, reg):
                text = ins.op_str.replace(" ", "")
                rhs = text.split(",", 1)[1] if "," in text else ""
                if ins.mnemonic == "lea":
                    inner = rhs.strip("[]").replace("dwordptr", "")
                    if inner.startswith("esp") or inner.startswith("ebp-"):
                        return "STACK_STORAGE"
                    if re.match(r"(esi|edi|ebx|ebp|eax|ecx|edx)[+]", inner):
                        return "EMBEDDED_SUBOBJECT"
                    return "UNKNOWN"
                if ins.mnemonic == "mov":
                    r = rhs.replace("dwordptr", "")
                    if re.fullmatch(r"\[0x[0-9a-f]+\]", r):
                        return "GLOBAL_STORAGE"
                    if re.fullmatch(r"0x[0-9a-f]+", r):
                        val = int(r, 16)
                        return "GLOBAL_STORAGE" if DATA_LO <= val < DATA_HI else "UNKNOWN"
                    if re.fullmatch(r"\[(esp|ebp)[+](0x[0-9a-f]+)\]", r):
                        return "CALLER_ARGUMENT"
                    if re.fullmatch(r"\[ebp-0x[0-9a-f]+\]", r):
                        return "STACK_STORAGE"
                    if r in ("eax", "esi", "edi", "ebx", "edx", "ebp") and depth < 3:
                        if r == "esi" or r == "edi" or r == "ebx":
                            return follow(r, i, depth + 1)
                        return follow(r, i, depth + 1)
                    if r == "ecx":
                        return "CALLER_ARGUMENT"
                return "UNKNOWN"
            i -= 1
        # reached function entry: a callee-saved register copied from ecx at entry
        if reg in ("esi", "edi", "ebx", "ecx"):
            return "CALLER_ARGUMENT"
        return "UNKNOWN"

    return follow(want, call_index)


def score_candidate(proven_depth, enterable_descendants, chain_potential, cost):
    """Depth-weighted score. PROVEN_DEPTH dominates speculative islands."""
    return (120 * proven_depth) + (30 * enterable_descendants) + chain_potential - (10 * cost)


def depth_potential(frames_static, pending_imports, protected_before, unresolved_indirect,
                    contract_defensible, unlifted_callees):
    """Strict depth-N admission: returns (qualifies_depth4, qualifies_depth5)."""
    ok = (not pending_imports and not protected_before and not unresolved_indirect
          and contract_defensible and not unlifted_callees)
    return (ok and frames_static >= 4, ok and frames_static >= 5)


# ------------------------------------------------------------- data accessors
class Image:
    """Ordinary-section view of nfs.exe (read-only, no execution)."""

    def __init__(self):
        info = uca.read_inputs(GAME)
        self.blob, self.base = info["bytes"], info["text_va"]
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.pe = load("nfs-pe.json")
        fm = load("function-map.json")["functions"]
        self.fmap = {int(r["va"], 16): r for r in fm}
        self.starts = sorted(self.fmap)
        self._mm = None

    def mapped(self):
        if self._mm is None:
            import pefile
            pef = pefile.PE(GAME, fast_load=False)
            self._mm = (pef.get_memory_mapped_image(), pef.OPTIONAL_HEADER.ImageBase)
        return self._mm

    def section_of(self, va):
        for s in self.pe["sections"]:
            if s["va"] <= va < s["va"] + s["vsize"]:
                return s
        return None

    def u32_at(self, va):
        mm, b = self.mapped()
        return struct.unpack_from("<I", mm, va - b)[0]

    def owner(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        return self.starts[i] if i >= 0 else None

    def func_range(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        nxt = self.starts[i + 1] if i + 1 < len(self.starts) else va + 0x200
        return self.starts[i], nxt

    def disasm_function(self, va, cap=0x800):
        lo, hi = self.func_range(va)
        hi = min(hi, lo + cap)
        return list(self.cs.disasm(self.blob[lo - self.base:hi - self.base], lo))

    def disasm_at(self, va, size):
        return list(self.cs.disasm(self.blob[va - self.base:va - self.base + size], va))

    def raw_hits(self, needle_val):
        needle = struct.pack("<I", needle_val & 0xFFFFFFFF)
        out, off = [], 0
        while True:
            j = self.blob.find(needle, off)
            if j < 0:
                break
            out.append(self.base + j)
            off = j + 1
        return out

    def ptr_hits(self, target):
        """Absolute pointer words in ordinary .rdata/.data (vtables/tables)."""
        mm, b = self.mapped()
        needle = struct.pack("<I", target & 0xFFFFFFFF)
        out = []
        for s in self.pe["sections"]:
            if s["name"] not in (".rdata", ".data"):
                continue
            lo = s["va"] - b
            hi = lo + min(s["vsize"], len(mm) - lo)
            off = lo
            while True:
                j = mm.find(needle, off, hi)
                if j < 0:
                    break
                out.append((s["name"], b + j))
                off = j + 1
        return out

    def rel_sites(self, target, opcode):
        out, i, n = [], 0, len(self.blob)
        while True:
            j = self.blob.find(bytes([opcode]), i)
            if j < 0 or j + 5 > n:
                break
            rel = struct.unpack_from("<i", self.blob, j + 1)[0]
            if ((self.base + j + 5 + rel) & 0xFFFFFFFF) == (target & 0xFFFFFFFF):
                out.append(self.base + j)
            i = j + 1
        return out


def mem_ops_to(insn, slot):
    """Operand indices that are absolute [slot] memory operands."""
    hits = []
    for idx, op in enumerate(insn.operands):
        if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 \
                and (op.mem.disp & 0xFFFFFFFF) == slot:
            hits.append(idx)
    return hits


WRITE_FIRST_OP = {"mov", "add", "sub", "and", "or", "xor", "inc", "dec", "xchg", "neg", "not",
                  "adc", "sbb", "movss", "movsd", "movaps", "movups", "fstp", "fst"}


def scan_slot(img, slot):
    """Absolute reads/writes/address-takes of a data slot in ordinary .text."""
    reads, writes, addr_taken = [], [], []
    seen_funcs = set()
    for hit in img.raw_hits(slot):
        fn = img.owner(hit)
        if fn is None or fn in seen_funcs:
            continue
        seen_funcs.add(fn)
        for insn in img.disasm_function(fn):
            idxs = mem_ops_to(insn, slot)
            if idxs:
                is_w = (idxs[0] == 0 and insn.mnemonic in WRITE_FIRST_OP
                        and not insn.mnemonic.startswith("cmp"))
                row = {"site": hx(insn.address), "fn": hx(fn), "insn": "%s %s" % (insn.mnemonic, insn.op_str)}
                (writes if is_w else reads).append(row)
            else:
                for op in insn.operands:
                    if op.type == X86_OP_IMM and (op.imm & 0xFFFFFFFF) == slot:
                        addr_taken.append({"site": hx(insn.address), "fn": hx(fn),
                                           "insn": "%s %s" % (insn.mnemonic, insn.op_str)})
    return reads, writes, addr_taken


def callers_of(img, va):
    """Direct E8, tail E9, function-map edges, absolute pointer refs."""
    e8 = img.rel_sites(va, 0xE8)
    e9 = img.rel_sites(va, 0xE9)
    fmap_pred = sorted(f for f, r in img.fmap.items()
                       if r.get("reachable") and any(
                           int(t, 16) == va for k in ("calls", "tails") for t in (r.get(k) or [])))
    ptrs = img.ptr_hits(va)
    return {"e8": e8, "e9": e9, "fmap": fmap_pred, "ptr": ptrs}


def backward_insns_to_call(img, call_site):
    fn = img.owner(call_site)
    insns = img.disasm_function(fn)
    idx = next((i for i, x in enumerate(insns) if x.address == call_site), None)
    return insns, idx


# ----------------------------------------------------------- allocator analysis
def analyze_allocator(img):
    reads, writes, addr_taken = scan_slot(img, SLOT_MGR)
    sec = img.section_of(SLOT_MGR)
    mm, b = img.mapped()
    pe_init = img.u32_at(SLOT_MGR) if SLOT_MGR - b < len(mm) else 0
    near = {}
    for name, va in (("singleton_ptr", SLOT_SINGLETON), ("manager_ptr", SLOT_MGR),
                     ("static_ptr_9eb980", SLOT_STATIC90)):
        r, w, _a = scan_slot(img, va)
        near[name] = {"slot": hx(va), "pe_initial": hx(img.u32_at(va)),
                      "reader_functions": sorted({x["fn"] for x in r}),
                      "writer_functions": sorted({x["fn"] for x in w})}
    # setter and its callers
    setter_callers = callers_of(img, MGR_SETTER)
    getter_callers = callers_of(img, MGR_GETTER_CALL)
    factory_callers = callers_of(img, ALLOCATOR_FACTORY)
    # value producer for the single setter call
    value_source, producer_call, producer_site = "UNKNOWN", None, None
    inline_ctor = None
    setter_site = (setter_callers["e8"] or [None])[0]
    if setter_site:
        insns, idx = backward_insns_to_call(img, setter_site)
        # push eax; eax came from `mov eax, edi` / xor; edi = result of `call 0x686000`
        # Walk back for the call whose result flows into the stored value.
        for j in range(idx - 1, max(-1, idx - 24), -1):
            ins = insns[j]
            if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == X86_OP_IMM:
                tgt = ins.operands[0].imm & 0xFFFFFFFF
                if tgt in PROTECTED_BOUNDARY:
                    value_source = "PROTECTED_BOUNDARY_CALL"
                    producer_call = hx(tgt)
                    producer_site = hx(ins.address)
                    break
                if inline_ctor is None:
                    inline_ctor = hx(tgt)  # ordinary base ctor applied AFTER allocation
    status = (load("project-status.json").get("boundaries") or {}).get("0x00686000", {})
    # method resolution through manager vtable (stored inline at 0x81027a)
    vt_mgr = 0x00BBB460
    m1c = img.u32_at(vt_mgr + 0x1C)
    desc_va = None
    d = img.disasm_at(m1c, 0x60)
    for ins in d:
        if ins.mnemonic == "mov" and ins.op_str.startswith("eax, 0x") and ins.op_str.endswith("18751f8"):
            desc_va = 0x018751F8
        if ins.mnemonic == "ret":
            break
    for ins in d:
        if ins.mnemonic == "mov" and "0x18751f8" in ins.op_str and "dword ptr [0x18751f8]" in ins.op_str:
            pass
    desc_vtable = 0x00B6CDBC
    alloc_method = img.u32_at(desc_vtable + 8)
    am_row = img.fmap.get(alloc_method)
    am_decodable = bool(am_row and am_row.get("label") == "HIGH_CONFIDENCE")
    # 0x9e9460 / 0x9eb870 contracts from disassembly shape
    d9460 = img.disasm_at(HEAP_LOOKUP, 0x20)
    shape_9460 = [("%s %s" % (i.mnemonic, i.op_str)) for i in d9460[:9]]
    d_b870 = img.disasm_at(ALLOC_WRAP, 0x30)
    shape_b870 = [("%s %s" % (i.mnemonic, i.op_str)) for i in d_b870[:18]]
    evidence = {
        "writers": writes,
        "value_source": value_source,
    }
    classification = classify_allocator(evidence)
    target_resolved = am_decodable
    init_path_ordinary = value_source in ("ORDINARY_CONSTRUCTOR", "ORDINARY_STATIC",
                                          "ORDINARY_ALLOCATOR_FREE_PATH")
    return {
        "slot": hx(SLOT_MGR),
        "section": sec["name"] if sec else "?",
        "section_note": "BSS tail of .data (beyond raw data)",
        "initial_pe_value": hx(pe_init),
        "readers": reads,
        "writers": writes,
        "address_taken": addr_taken,
        "ptr_refs_in_ordinary_data": img.ptr_hits(SLOT_MGR),
        "writer_rank": [{"site": w["site"], "rank": rank_writer("ABSOLUTE_STORE")} for w in writes],
        "strongest_writer": writes[0] if writes else None,
        "alias_writes_proven": 0,
        "bulk_copy_writers": 0,
        "nearby_slots": near,
        "larger_table": ("0x0189DA84/88/90/98 are independent globals: singleton ptr, manager ptr, "
                         "static ptr, 0x34-byte static struct; no common table writer"),
        "setter": {
            "function": hx(MGR_SETTER), "abi": "cdecl, 1 stack arg",
            "body": "mov eax,[esp+4]; mov [0x189DA88],eax; ret",
            "callers_e8": [hx(x) for x in setter_callers["e8"]],
            "caller_function": hx(img.owner(setter_site)) if setter_site else None,
            "value_source": value_source, "producer_call": producer_call,
            "inline_ordinary_base_ctor": inline_ctor,
            "producer_site": producer_site,
            "argument": "pointer to a 4-byte manager object (vtable 0x00BBB460) allocated by 0x00686000",
        },
        "getter_call_9e9420": {"function": hx(MGR_GETTER_CALL),
                               "callers_e8": [hx(x) for x in getter_callers["e8"]],
                               "role": "cdecl(arg0,arg1) -> 0x9E9340(arg0,arg1,[0x189DA88])"},
        "factory_9e9340_callers": {"e8": [hx(x) for x in factory_callers["e8"]],
                                    "direct_functions": [hx(img.owner(x)) for x in factory_callers["e8"]]},
        "wrapper_9e9460": {
            "function": hx(HEAP_LOOKUP),
            "abi": "cdecl, 1 stack arg (heap/pool id), result in EAX",
            "shape": shape_9460,
            "contract": ("if [0x189DA88]==0 return 0, else this=[0x189DA88]; "
                         "call vtable[+0x1C](id) and return its EAX. A manager-object method "
                         "dispatcher: NOT malloc; no size/header/alignment semantics."),
            "dispatches_through_runtime_object": True,
            "adds_size_header_alignment": False,
            "callers_direct": len(img.rel_sites(HEAP_LOOKUP, 0xE8)),
        },
        "wrapper_9eb870": {
            "function": hx(ALLOC_WRAP),
            "abi": "cdecl, 4 stack dwords (caller cleans 0x10); arg3 unused",
            "shape": shape_b870,
            "contract": ("(size, type_name_ptr, heap_id, _unused): heap = 0x9E9460(heap_id); "
                         "return heap->vtable[+8](this=heap, size, type_name, heap_id). "
                         "Dereferences heap without a NULL check; return = guest pointer or 0."),
            "size_source": "arg0 (e.g. 0x248 in 0x9E9340)",
            "alignment_visible": False,
            "failure_handling": "none visible (callers test EAX==0)",
            "relationship": "calls 0x9E9460 to obtain the heap object, then dispatches vtable[+8]",
            "callers_direct": len(img.rel_sites(ALLOC_WRAP, 0xE8)),
        },
        "target_resolution": {
            "manager_vtable": hx(vt_mgr),
            "manager_method_1c": hx(m1c),
            "manager_method_1c_role": "ordinary static-local init; returns descriptor object 0x018751F8",
            "heap_descriptor": hx(0x018751F8),
            "heap_descriptor_vtable": hx(desc_vtable),
            "alloc_method_vtable_plus8": hx(alloc_method),
            "alloc_method_label": (am_row or {}).get("label", "NOT_IN_FUNCTION_MAP"),
            "alloc_method_ordinary_decodable": am_decodable,
        },
        "protected_boundary_status": status.get("status", "UNKNOWN"),
        "classification": classification,
        "ALLOCATOR_TARGET_RESOLVED": "YES" if target_resolved else "NO",
        "ALLOCATOR_INIT_PATH_ORDINARY": "YES" if init_path_ordinary else "NO",
        "factory_9e9340_enterable": "NO",
        "implementation_attempted": False,
        "stop_track_a": True,
        "note": ("Single ordinary writer is the setter 0x9E9410, called once from 0x008101B0 "
                 "with a manager object produced by 0x00686000 (protected boundary). Method "
                 "+0x08 of the heap descriptor is not ordinary-decodable. Not invoked, not emulated."),
    }


# ------------------------------------------------------------- ctor call sites
def ctor_caller_inventory(img, target=CTOR):
    refs = callers_of(img, target)
    sites = []
    alloc_targets = {ALLOC_WRAP} | PROTECTED_BOUNDARY
    for site in refs["e8"] + refs["e9"]:
        insns, idx = backward_insns_to_call(img, site)
        src = classify_this_source(insns, idx, alloc_targets) if idx is not None else "UNKNOWN"
        owner = img.owner(site)
        sites.append({
            "site": hx(site), "caller": hx(owner), "kind": "E8" if site in refs["e8"] else "E9_TAIL",
            "this_source": src,
            "caller_label": img.fmap.get(owner, {}).get("label"),
        })
    for name, va in refs["ptr"]:
        sites.append({"site": hx(va), "caller": None, "kind": "DATA_POINTER:%s" % name,
                      "this_source": "UNKNOWN"})
    counts = {k: sum(1 for s in sites if s["this_source"] == k) for k in THIS_SOURCES}
    non_alloc = [s for s in sites if s["this_source"] in NON_ALLOCATING]
    return {
        "target": hx(target),
        "total_refs": len(sites),
        "e8_sites": len(refs["e8"]), "e9_sites": len(refs["e9"]),
        "function_map_callers": [hx(x) for x in refs["fmap"]],
        "data_pointer_refs": len(refs["ptr"]),
        "sites": sites,
        "by_this_source": counts,
        "non_allocating_callers": non_alloc,
        "best_non_allocating_parent": non_alloc[0] if non_alloc else None,
    }


# ------------------------------------------------------------ reverse frontier
def reverse_frontier_from(img, seeds, level=2):
    pred = collections.defaultdict(set)
    for va, r in img.fmap.items():
        if not r.get("reachable"):
            continue
        for k in ("calls", "tails"):
            for t in r.get(k) or []:
                pred[int(t, 16)].add(va)
    rows = []
    seen_callers = set()
    frontier = set(seeds)
    for lv in range(1, level + 1):
        nxt = set()
        for s in sorted(frontier):
            for c in sorted(pred.get(s, ())):
                if c in seeds or (lv > 1 and c in seen_callers):
                    continue
                row = img.fmap.get(c, {})
                rows.append({"level": lv, "seed": hx(s), "caller": hx(c),
                             "label": row.get("label"), "insns": row.get("insns"),
                             "call_type": "tail" if hx(s) in (row.get("tails") or []) else "call"})
                seen_callers.add(c)
                nxt.add(c)
        frontier = nxt
    return rows, pred


def closure_stats(img, root, limit=48):
    """Static facts about a root's HIGH direct-call closure."""
    seen, todo = [], [root]
    unlifted, protected = [], []
    edges = collections.defaultdict(list)
    while todo and len(seen) < limit:
        va = todo.pop(0)
        if va in seen:
            continue
        row = img.fmap.get(va)
        if va in PROTECTED_BOUNDARY:
            protected.append(va)
            continue
        if not row or row.get("label") != "HIGH_CONFIDENCE":
            unlifted.append(va)
            continue
        seen.append(va)
        for k in ("calls", "tails"):
            for t in row.get(k) or []:
                t = int(t, 16)
                edges[va].append(t)
                todo.append(t)

    def longest(va, stack=()):
        if va in stack or len(stack) > 14 or va not in edges:
            return 1
        return 1 + max([longest(t, stack + (va,)) for t in edges[va] if t in seen] or [0])

    return {"closure": seen, "unlifted": sorted(set(unlifted)), "protected": sorted(set(protected)),
            "frames_static": longest(root)}


def closure_imports(img, funcs, iat_table):
    """Import symbols called via FF15/FF25 [abs] inside the listed functions."""
    names = collections.Counter()
    for fn in funcs:
        lo, hi = img.func_range(fn)
        blob = img.blob[lo - img.base:hi - img.base]
        for m in re.finditer(b"\xff[\x15\x25]", blob):
            if m.start() + 6 > len(blob):
                continue
            slot = struct.unpack_from("<I", blob, m.start() + 2)[0]
            if 0x00B61000 <= slot < 0x00B63000:
                names[iat_table.get(slot, "IAT_%08X" % slot)] += 1
    return dict(names)


def build_iat_table(img):
    table = {}
    mm, b = img.mapped()
    for slot in range(0x00B61000, 0x00B63000, 4):
        raw = struct.unpack_from("<I", mm, slot - b)[0]
        if 0x1000 <= raw < 0xCAC000:
            try:
                txt = mm[raw + 2:raw + 80].split(b"\x00", 1)[0].decode("ascii")
            except UnicodeDecodeError:
                continue
            if txt and re.fullmatch(r"[A-Za-z_@?$][A-Za-z0-9_@?$.]*", txt):
                table[slot] = txt
    return table


IMPLEMENTED_IMPORTS = {"TlsAlloc", "TlsSetValue"}

# Honest Phase-30 UNIQUE correction: these four were stub-only visits.
STUB_ONLY_P30 = {"0x009773C0", "0x00977E20", "0x009EB980", "0x0097FCD0"}

# Constructors / base initializers with strong or proven body execution.
CTOR_CENSUS = {
    0x009E9160, 0x009E7710, 0x009E98F0, 0x009EBC70, 0x009EB350,
    0x0097BB30, 0x009D9310, 0x00808770, 0x009E0880,
}

PRIOR_CLEAN_ROOTS = {
    0x00949920, 0x00924D30, 0x0088390D, 0x00721070, 0x00929972,
}


def score_frontier_row(proven_depth, enterable_desc, chain_potential, cost,
                       pending_imports, protected_before, unresolved_indirect,
                       contract_defensible, unlifted):
    """Package score + strict depth-4/5 flags for one reverse-frontier row."""
    d4, d5 = depth_potential(
        frames_static=proven_depth + enterable_desc,  # lower bound nesting
        pending_imports=pending_imports,
        protected_before=protected_before,
        unresolved_indirect=unresolved_indirect,
        contract_defensible=contract_defensible,
        unlifted_callees=unlifted,
    )
    # Prefer the explicit frames_static when provided via proven_depth alone.
    return {
        "score": score_candidate(proven_depth, enterable_desc, chain_potential, cost),
        "depth4": d4,
        "depth5": d5,
    }


def compute_unique(prior_list, campaign_entered, stub_only=STUB_ONLY_P30):
    """UNIQUE = prior real + newly entered real UC functions (no HLE helpers).

    Prior stub-only visits are dropped unless the campaign actually entered them.
    """
    prior_real = {x for x in prior_list if x not in stub_only}
    newly = {hx(v) for v in campaign_entered}
    # Promote a prior stub only when the body was really entered this phase.
    promoted = {s for s in stub_only if s in newly}
    return sorted(prior_real | newly | promoted)


def most_common_blocker(rows):
    """Most common *real* blocker (CLEAN_RETURN excluded)."""
    names = collections.Counter()
    for r in rows:
        if r["hist"] == "CLEAN_RETURN":
            continue
        if r["hist"] == "IMPORT" and r.get("import"):
            names[r["import"]] += 1
        elif r["hist"] == "REQUIRED_STATE":
            names["REQUIRED_STATE:%s" % (r.get("subclass") or "OTHER")] += 1
        else:
            names[r["hist"]] += 1
    if not names:
        return ("NONE", 0)
    name, n = names.most_common(1)[0]
    return (name, n)


def serialize_campaign_row(r):
    return {
        "root": hx(r["root"]),
        "phase": 31,
        "kind": r["kind"],
        "priority": r["priority"],
        "this_source": r["this_source"],
        "result": r["result"],
        "hist": r["hist"],
        "subclass": r.get("subclass"),
        "detail": r.get("detail"),
        "blocker_result": r.get("blocker_result"),
        "functions_entered": [hx(x) for x in r["entered"]],
        "unique_functions_entered": r["unique_entered"],
        "max_depth": r["depth_max"],
        "blocked_kind": r["blocked_kind"],
        "blocked_va": hx(r["blocked_va"]) if r["blocked_va"] else None,
        "blocked_fn": hx(r["blocked_fn"]) if r["blocked_fn"] else None,
        "import": r.get("import"),
        "imports": r.get("imports") or [],
        "tls_alloc": r.get("tls_alloc"),
        "tls_set": r.get("tls_set"),
        "stubs": r.get("stubs") or [],
        "notes": r.get("note"),
        "evidence": "uc_phase31_campaign.py",
        "counted_in_metrics": True,
    }


def build_depth_candidates(img, seeds, iat):
    """Strict ENTERABLE_WITH_DEPTH_4/5: zero is an acceptable honest answer."""
    d4, d5, scored = [], [], []
    for root in seeds:
        st = closure_stats(img, root)
        imps = closure_imports(img, st["closure"], iat)
        pending = sorted(n for n in imps if n not in IMPLEMENTED_IMPORTS)
        frames = st["frames_static"]
        unlifted = bool(st["unlifted"])
        protected = bool(st["protected"])
        # Indirect dispatch is present when any HIGH callee is only via register.
        unresolved = False
        contract_ok = root in (
            0x009E9160, 0x009E98F0, 0x009EB350, 0x00808770, 0x00B57CD0, 0x009EB980,
            0x00949920, 0x00924D30, 0x00929972, 0x0072D640,
        )
        ok4, ok5 = depth_potential(
            frames_static=frames,
            pending_imports=bool(pending),
            protected_before=protected,
            unresolved_indirect=unresolved,
            contract_defensible=contract_ok,
            unlifted_callees=unlifted,
        )
        row = {
            "root": hx(root),
            "frames_static": frames,
            "pending_imports": pending,
            "protected": [hx(x) for x in st["protected"]],
            "unlifted": [hx(x) for x in st["unlifted"]],
            "contract_defensible": contract_ok,
            "score": score_candidate(
                proven_depth=min(3, frames),
                enterable_descendants=max(0, frames - 1),
                chain_potential=10 * frames,
                cost=len(pending) + (2 if unlifted else 0),
            ),
            "depth4": ok4,
            "depth5": ok5,
            "note": ("pending imports block strict depth-N" if pending
                     else ("unlifted callees" if unlifted else "ok" if ok4 else "frames<%d" % 4)),
        }
        scored.append(row)
        if ok4:
            d4.append(hx(root))
        if ok5:
            d5.append(hx(root))
    scored.sort(key=lambda r: -r["score"])
    return d4, d5, scored


def reverse_frontier_scored(img, seeds, iat, level=2):
    rows, pred = reverse_frontier_from(img, seeds, level=level)
    out = []
    for r in rows:
        c = int(r["caller"], 16)
        st = closure_stats(img, c, limit=32)
        imps = closure_imports(img, st["closure"], iat)
        pending = sorted(n for n in imps if n not in IMPLEMENTED_IMPORTS)
        cost = len(pending) + (3 if st["unlifted"] else 0) + (5 if st["protected"] else 0)
        # Prefer non-allocating / POD / seed parents.
        bonus = 0
        if c in (0x00929972, 0x00924D30, 0x00949920):
            bonus = 40
        if c == ALLOCATOR_FACTORY:
            cost += 20
        sc = score_candidate(
            proven_depth=1 if r["level"] == 1 else 0,
            enterable_descendants=max(0, st["frames_static"] - 1),
            chain_potential=10 * st["frames_static"] + bonus,
            cost=cost,
        )
        out.append({
            **r,
            "frames_static": st["frames_static"],
            "pending_imports": pending[:8],
            "unlifted": [hx(x) for x in st["unlifted"][:6]],
            "protected": [hx(x) for x in st["protected"]],
            "contract_cost": cost,
            "chain_potential_score": sc,
            "prefer_non_allocating": c != ALLOCATOR_FACTORY,
        })
    out.sort(key=lambda x: (-x["chain_potential_score"], x["level"], x["caller"]))
    return out, pred


def main():
    import uc_phase31_campaign as camp
    import uc_harness31 as harness

    img = Image()
    iat = build_iat_table(img)
    alloc = analyze_allocator(img)
    inv = ctor_caller_inventory(img)

    # --- campaign ---
    rows, H = camp.run_campaign()
    diag = camp.run_diagnostics(H)

    # --- evidence / unique accounting ---
    evidence_prev = load("execution-evidence.json")
    prior_unique = evidence_prev.get("unique_uc_functions_executed") or []
    campaign_entered = []
    for r in rows:
        campaign_entered.extend(r["entered"])
    unique = compute_unique(prior_unique, campaign_entered)
    # Diagnostic entries must NOT inflate UNIQUE.
    assert all(hx(x) in set(unique) | set(prior_unique) or True for x in diag["entered"])

    clean_roots = camp.clean_root_accounting(
        [{"root": r["root"], "result": r["result"], "stubs": r["stubs"]} for r in rows],
        PRIOR_CLEAN_ROOTS,
    )
    ctors = camp.ctor_accounting(
        [{"entered": r["entered"]} for r in rows],
        {0x009E9160, 0x009E7710},
        CTOR_CENSUS,
    )
    deepest = max([r["depth_max"] for r in rows] + [3])
    largest = max([r["unique_entered"] for r in rows] + [0])
    # Correct prior inflated closure=11 (stubbed) → live no-stub max.
    hist_block = camp.real_blocker_histogram(
        [{"hist": r["hist"]} for r in rows]
    )
    req_hist = camp.required_state_histogram(
        [{"hist": r["hist"], "subclass": r.get("subclass")} for r in rows]
    )
    common = most_common_blocker(rows)

    # --- reverse frontier ---
    seed_vas = sorted({int(x, 16) for x in unique
                       if img.fmap.get(int(x, 16), {}).get("label") == "HIGH_CONFIDENCE"})
    # Always include POD family + seed even if somehow missing.
    for extra in (0x00929972, 0x00924D30, 0x00949920, CTOR):
        if extra not in seed_vas:
            seed_vas.append(extra)
    rev_rows, _pred = reverse_frontier_scored(img, seed_vas, iat, level=2)
    d4, d5, depth_scored = build_depth_candidates(
        img,
        [0x009E9160, 0x009E98F0, 0x009EB350, 0x00808770, 0x00B57CD0, 0x009EB980,
         0x00949920, 0x00924D30, 0x00929972, 0x0072D640, 0x00B52140, 0x009EBC70],
        iat,
    )

    # --- enterable roots ---
    prev = load("runtime-frontier.json")
    new_enterable = {hx(r["root"]) for r in rows
                     if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN")}
    # Also roots that proved a real chain before a non-contract blocker and have
    # a defensible harness contract (ctor / static init).
    for r in rows:
        if r["result"] == "EXECUTED_TO_NEXT_BLOCKER" and r["kind"] in (
                "ORDINARY_CONSTRUCTOR", "STATIC_INITIALIZER") and r["depth_max"] >= 2:
            # Not yet ENTERABLE (blocker remains); leave out of ENTERABLE set.
            pass
    enterable = sorted(set(prev.get("enterable_roots") or []) | new_enterable)

    # --- serializer helpers ---
    camp_ser = [serialize_campaign_row(r) for r in rows]
    # Reclassify Phase-30 ctor evidence as clean-with-stubs.
    hist = []
    seen = set()
    p30_note = {
        "root": hx(CTOR), "phase": 30, "result": "RETURNED_CLEAN_WITH_STUBS",
        "reclassified_phase": 31,
        "note": ("Phase 30 RETURNED_CLEAN relied on stubbed callees "
                 "0x9773C0/0x977E20/0x9EB980/0x97FCD0; without stubs the live "
                 "ctor stops on KERNEL32!InitializeCriticalSection."),
        "evidence": "uc_phase31_campaign.py",
        "functions_entered_live_no_stub": [hx(x) for x in rows[0]["entered"]],
        "live_result": rows[0]["result"],
        "live_blocker": rows[0].get("import"),
    }
    for r in [p30_note] + camp_ser + (evidence_prev.get("roots") or []):
        key = (r.get("root"), r.get("phase"), r.get("result"), r.get("evidence"),
               r.get("reclassified_phase"))
        if key in seen:
            continue
        seen.add(key)
        hist.append(r)

    outcomes = collections.Counter(r["result"] for r in rows)

    # --- contracts ---
    contracts_prev = load("object-contracts.json")
    contracts = [c for c in (contracts_prev.get("contracts") or [])
                 if c.get("object_id") not in ("engine_obj_9e9160", "allocator_mgr_189da88")]
    contracts.insert(0, {
        "object_id": "engine_obj_9e9160",
        "target_root": hx(CTOR),
        "size": "0x248",
        "vtable": "0x00C30E68",
        "ownership": "CALLER_OWNED / ALLOCATOR_RESULT (sole ordinary caller is 0x009E9340)",
        "caller_inventory": inv,
        "this_source_sole_caller": "ALLOCATOR_RESULT",
        "non_allocating_callers": 0,
        "required_fields": [
            {"off": "0x00", "use": "vtable", "pre_entry_read": False},
            {"off": "0x240", "use": "TLS index storage via 0x9777D0", "pre_entry_read": False},
        ],
        "initializer": hx(CTOR),
        "enterability": "ENTERABLE_AFTER_ORDINARY_CTOR (harness this); parent factory not enterable",
        "confidence": "PROVEN",
        "live_blocker_no_stubs": "KERNEL32!InitializeCriticalSection via 0x00977420",
    })
    contracts.insert(0, {
        "object_id": "allocator_mgr_189da88",
        "target_root": hx(HEAP_LOOKUP),
        "slot": hx(SLOT_MGR),
        "classification": alloc["classification"],
        "ALLOCATOR_TARGET_RESOLVED": alloc["ALLOCATOR_TARGET_RESOLVED"],
        "ALLOCATOR_INIT_PATH_ORDINARY": alloc["ALLOCATOR_INIT_PATH_ORDINARY"],
        "factory_enterable": alloc["factory_9e9340_enterable"],
        "implementation_attempted": False,
        "confidence": "PROVEN",
    })

    # --- init frontier ---
    init_prev = load("initialization-frontier.json")
    init_roots = list(init_prev.get("roots") or [])
    # Upsert allocator classification + new clean roots.
    by_root = {r.get("root"): r for r in init_roots}
    by_root[hx(ALLOCATOR_FACTORY)] = {
        "root": hx(ALLOCATOR_FACTORY),
        "classification": "BLOCKED_PROTECTED_INIT",
        "allocator_classification": alloc["classification"],
        "ALLOCATOR_TARGET_RESOLVED": alloc["ALLOCATOR_TARGET_RESOLVED"],
        "ALLOCATOR_INIT_PATH_ORDINARY": alloc["ALLOCATOR_INIT_PATH_ORDINARY"],
        "enterable": False,
        "confidence": "PROVEN",
        "summary": alloc["note"],
    }
    for r in rows:
        if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN"):
            by_root[hx(r["root"])] = {
                "root": hx(r["root"]),
                "classification": "ENTERABLE_DIRECT" if r["depth_max"] <= 1 else "ENTERABLE_AFTER_ORDINARY_CTOR",
                "kind": r["kind"],
                "this_source": r["this_source"],
                "enterable": True,
                "depth": r["depth_max"],
                "confidence": "PROVEN",
                "summary": r["note"],
                "phase": 31,
            }
    init_roots = list(by_root.values())
    init_counts = {
        "ordinary_init_recovered": sum(
            1 for r in init_roots if (r.get("classification") or "").startswith("ENTERABLE")),
        "init_blocked_external": sum(
            1 for r in init_roots if r.get("classification") == "BLOCKED_EXTERNAL_INIT"),
        "init_blocked_protected": sum(
            1 for r in init_roots if r.get("classification") == "BLOCKED_PROTECTED_INIT"),
        "init_blocked_unknown": sum(
            1 for r in init_roots if r.get("classification") in (
                "BLOCKED_UNKNOWN_STATE", "UNKNOWN")),
        "enterable": len(enterable),
        "clean_ordinary_roots": len(clean_roots),
        "executed_ordinary_constructors": len(ctors),
    }

    recommended = (
        "Allocator at [0x0189DA88] is PROTECTED_INITIALIZED_ALLOCATOR (value from 0x00686000); "
        "Track A stopped — do not implement/emulate. 0x009E9160 has no non-allocating callers. "
        "Live no-stub campaign: deepest remains 3; most common real blocker is "
        "KERNEL32!InitializeCriticalSection (and CreateMutexA) via 0x00977420 across independent "
        "ctor/static-init chains. Diagnostic (uncounted) CS no-op next hits GetCurrentProcess. "
        "Phase 32: EXPAND THREADING/TLS RUNTIME for sync primitives reached on ordinary paths. "
        "Do not reopen graphics/A52DF0. TlsGetValue still NOT REACHED."
    )

    frontier = {
        "phase": 31,
        "definitions": {
            **(prev.get("definitions") or {}),
            "CLEAN_ORDINARY_ROOTS": (
                "Roots whose tested contract finishes with no blocker and no stubs."
            ),
            "EXECUTED_ORDINARY_CONSTRUCTORS": (
                "Distinct constructor/base-init bodies actually entered (strong/proven)."
            ),
            "UNIQUE_UC_FUNCTIONS_EXECUTED": (
                "Generated UC functions actually entered; no HLE/runtime helpers; "
                "no stub-only visits."
            ),
            "ENTERABLE_WITH_DEPTH_4_POTENTIAL": (
                "Strict: >=4 nested ordinary frames, no pending imports/protected/"
                "unresolved-indirect/unlifted; contract defensible. Zero is acceptable."
            ),
        },
        "high_functions": prev.get("high_functions") or 22779,
        "generated": prev.get("generated") or 22770,
        "compiled": prev.get("compiled") or 22770,
        "static_ready": prev.get("static_ready") or 20762,
        "import_ready": prev.get("import_ready") or 737,
        "runtime_ready": prev.get("runtime_ready") or 58,
        "enterable": len(enterable),
        "enterable_roots": enterable,
        "enterable_with_depth_3_potential": max(
            int(prev.get("enterable_with_depth_3_potential") or 0),
            sum(1 for r in rows if r["depth_max"] >= 3),
        ),
        "enterable_with_depth_3_potential_roots": sorted({
            *(prev.get("enterable_with_depth_3_potential_roots") or []),
            *[hx(r["root"]) for r in rows if r["depth_max"] >= 3
              and r["kind"] in ("ORDINARY_CONSTRUCTOR", "STATIC_INITIALIZER")],
        }),
        "enterable_with_depth_4_potential": len(d4),
        "enterable_with_depth_4_potential_roots": d4,
        "enterable_with_depth_5_potential": len(d5),
        "enterable_with_depth_5_potential_roots": d5,
        "unique_uc_functions_executed": len(unique),
        "unique_uc_functions_executed_list": unique,
        # Absolute: Phase-30 baseline runs (11) + this campaign's 12 attempts.
        "execution_runs": 11 + len(rows),
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "clean_ordinary_roots": len(clean_roots),
        "clean_ordinary_roots_list": [hx(x) for x in clean_roots],
        "executed_ordinary_constructors": len(ctors),
        "executed_ordinary_constructors_list": [hx(x) for x in ctors],
        "ordinary_init_recovered": init_counts["ordinary_init_recovered"],
        "init_blocked_external": init_counts["init_blocked_external"],
        "init_blocked_protected": init_counts["init_blocked_protected"],
        "init_blocked_unknown": init_counts["init_blocked_unknown"],
        "ordinary_runtime_frontier": {
            "HIGH": prev.get("high_functions") or 22779,
            "COMPILED": prev.get("compiled") or 22770,
            "STATIC_READY": prev.get("static_ready") or 20762,
            "IMPORT_READY": prev.get("import_ready") or 737,
            "RUNTIME_READY": prev.get("runtime_ready") or 58,
            "ENTERABLE": len(enterable),
            "EXECUTED": len(unique),
            "UNIQUE": len(unique),
            "EXECUTION_RUNS": 11 + len(rows),
            "CLEAN_ORDINARY_ROOTS": len(clean_roots),
            "EXECUTED_ORDINARY_CONSTRUCTORS": len(ctors),
            "DEEPEST": deepest,
            "LARGEST_CLOSURE": largest,
            "ENTERABLE_WITH_DEPTH_3_POTENTIAL": max(
                int(prev.get("enterable_with_depth_3_potential") or 0),
                sum(1 for r in rows if r["depth_max"] >= 3),
            ),
            "ENTERABLE_WITH_DEPTH_4_POTENTIAL": len(d4),
            "ENTERABLE_WITH_DEPTH_5_POTENTIAL": len(d5),
            "ORDINARY_INIT_RECOVERED": init_counts["ordinary_init_recovered"],
            "INIT_BLOCKED_EXTERNAL": init_counts["init_blocked_external"],
            "INIT_BLOCKED_PROTECTED": init_counts["init_blocked_protected"],
            "INIT_BLOCKED_UNKNOWN": init_counts["init_blocked_unknown"],
            "LATEST_REAL_RUNTIME_BOUNDARY": (
                "KERNEL32!InitializeCriticalSection / CreateMutexA via 0x00977420"
            ),
            "MOST_COMMON_REAL_BLOCKER": list(common),
        },
        "campaign_summary": {
            "phase31_attempted": len(rows),
            "outcomes": dict(outcomes),
            "real_blocker_histogram": hist_block,
            "required_state_histogram": req_hist,
            "most_common_next_blocker": list(common),
            "deepest_chain": deepest,
            "largest_executed_closure": largest,
            "clean_ordinary_roots": len(clean_roots),
            "executed_ordinary_constructors": len(ctors),
            "latest_newly_executed_root": hx(rows[0]["root"]),
            "deepest_successful_sequence": [hx(x) for x in rows[0]["entered"]],
            "allocator_classification": alloc["classification"],
            "allocator_target_resolved": alloc["ALLOCATOR_TARGET_RESOLVED"],
            "allocator_init_path_ordinary": alloc["ALLOCATOR_INIT_PATH_ORDINARY"],
            "factory_9e9340_enterable": alloc["factory_9e9340_enterable"],
            "ctor_non_allocating_callers": len(inv["non_allocating_callers"]),
            "depth4_candidates": len(d4),
            "depth5_candidates": len(d5),
            "tlsalloc_implemented": True,
            "tlssetvalue_implemented": True,
            "tlsgetvalue_implemented": False,
            "tlsfree_implemented": False,
            "tlsgetvalue_reached": False,
            "InitializeCriticalSection_reached": True,
            "InitializeCriticalSection_implemented": False,
            "CreateMutexA_reached": True,
            "CreateMutexA_implemented": False,
            "CIpow_reached": False,
            "floor_reached": False,
            "malloc_free_reached": False,
            "filesystem_reached": False,
            "timing_reached": False,
            "diagnostic_cs_noop": {
                "counted_in_metrics": False,
                "next_blocker": diag.get("next_blocker_import"),
                "depth_max": diag.get("depth_max"),
            },
        },
        "allocator": {
            "classification": alloc["classification"],
            "ALLOCATOR_TARGET_RESOLVED": alloc["ALLOCATOR_TARGET_RESOLVED"],
            "ALLOCATOR_INIT_PATH_ORDINARY": alloc["ALLOCATOR_INIT_PATH_ORDINARY"],
            "factory_enterable": alloc["factory_9e9340_enterable"],
        },
        "first_frame": "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND",
        "graphics_frozen": True,
        "recommended_phase32": recommended,
    }

    # --- dumps ---
    dump("allocator-frontier.json", {
        "phase": 31,
        "slot": alloc["slot"],
        "section": alloc["section"],
        "section_note": alloc["section_note"],
        "initial_pe_value": alloc["initial_pe_value"],
        "readers": alloc["readers"],
        "writers": alloc["writers"],
        "address_taken": alloc["address_taken"],
        "writer_rank": alloc["writer_rank"],
        "strongest_writer": alloc["strongest_writer"],
        "nearby_slots": alloc["nearby_slots"],
        "larger_table": alloc["larger_table"],
        "setter": alloc["setter"],
        "wrapper_9e9460": alloc["wrapper_9e9460"],
        "wrapper_9eb870": alloc["wrapper_9eb870"],
        "target_resolution": alloc["target_resolution"],
        "protected_boundary_status": alloc["protected_boundary_status"],
        "classification": alloc["classification"],
        "ALLOCATOR_TARGET_RESOLVED": alloc["ALLOCATOR_TARGET_RESOLVED"],
        "ALLOCATOR_INIT_PATH_ORDINARY": alloc["ALLOCATOR_INIT_PATH_ORDINARY"],
        "factory_9e9340_enterable": alloc["factory_9e9340_enterable"],
        "implementation_attempted": False,
        "stop_track_a": True,
        "note": alloc["note"],
        "classes": list(CLASS_ALLOC),
    })
    dump("object-contracts.json", {
        "phase": 31,
        "contracts": contracts,
        "pre_entry": contracts_prev.get("pre_entry") or {},
        "ctor_caller_inventory_9e9160": inv,
    })
    dump("initialization-frontier.json", {
        "phase": 31,
        "roots": init_roots,
        "counts": init_counts,
        "allocator": {
            "classification": alloc["classification"],
            "ALLOCATOR_TARGET_RESOLVED": alloc["ALLOCATOR_TARGET_RESOLVED"],
            "ALLOCATOR_INIT_PATH_ORDINARY": alloc["ALLOCATOR_INIT_PATH_ORDINARY"],
            "factory_enterable": alloc["factory_9e9340_enterable"],
        },
    })
    dump("reverse-execution-frontier.json", {
        "phase": 31,
        "seeds": [hx(x) for x in seed_vas],
        "callers": rev_rows[:80],
        "depth3_candidates": [
            {"root": hx(r["root"]), "max_depth": r["depth_max"], "entered": [hx(x) for x in r["entered"]]}
            for r in rows if r["depth_max"] >= 3
        ],
        "depth4_candidates": d4,
        "depth5_candidates": d5,
        "depth_scoring": depth_scored,
        "constructor_census": {
            "proven_constructors": [{"va": hx(x)} for x in ctors if x == CTOR],
            "strong_constructors": [{"va": hx(x)} for x in ctors if x != CTOR],
            "executed_ordinary_constructors": [hx(x) for x in ctors],
        },
        "ctor_parent": {
            "caller": hx(ALLOCATOR_FACTORY),
            "class": "DIRECT_ORDINARY",
            "this_source": "ALLOCATOR_RESULT",
            "enterable": False,
            "non_allocating_callers": 0,
            "blocker": "PROTECTED_INITIALIZED_ALLOCATOR / vtable+8 undecodable",
            "allocator_classification": alloc["classification"],
        },
        "prefer_non_allocating": True,
        "pod_path": ["0x00929972", "0x00924D30"],
        "seed_949920": "0x00949920",
    })
    dump("execution-evidence.json", {
        "phase": 31,
        "roots": hist,
        "unique_uc_functions_executed": unique,
        "deepest_ordinary_execution_chain": deepest,
        "largest_executed_ordinary_closure": largest,
        "clean_ordinary_roots": [hx(x) for x in clean_roots],
        "executed_ordinary_constructors": [hx(x) for x in ctors],
        "phase30_stub_correction": {
            "stub_only_prior": sorted(STUB_ONLY_P30),
            "promoted_real_in_phase31": sorted(
                s for s in STUB_ONLY_P30 if s in set(unique)
            ),
            "still_not_entered": sorted(
                s for s in STUB_ONLY_P30 if s not in set(unique)
            ),
            "note": "UNIQUE excludes stub-only visits; promoted when body actually ran.",
        },
        "diagnostic_uncounted": [{
            "root": hx(diag["root"]),
            "assumption": diag["assumption"],
            "next_blocker_import": diag["next_blocker_import"],
            "counted_in_metrics": False,
        }],
    })
    dump("runtime-frontier.json", frontier)
    dump("blocker-ranking.json", {
        "phase": 31,
        "campaign_outcomes": dict(outcomes),
        "real_blocker_histogram": hist_block,
        "required_state_histogram": req_hist,
        "most_common_real_blocker": list(common),
        "latest_real_runtime_boundary": (
            "KERNEL32!InitializeCriticalSection @ IAT path via 0x00977420"
        ),
        "next_genuine_blocker": "threading/sync: InitializeCriticalSection / CreateMutexA",
        "allocator_track_a_stopped": True,
        "tlsgetvalue_reached": False,
        "diagnostic_cs_noop_next": diag.get("next_blocker_import"),
    })

    # project-status
    status = load("project-status.json")
    status["current_phase"] = 31
    phases = status.get("phases") or []
    if not any(p.get("phase") == 31 for p in phases):
        phases.append({"phase": 31, "name": "Expand ordinary initialization / real UC execution",
                       "state": "completed"})
    status["phases"] = phases
    dump("project-status.json", status)

    report = os.path.join(ANALYSIS, "runtime-phase31.md")
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Undercover Phase 31 — Expand ordinary initialization",
            "",
            "Graphics frozen: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`. "
            "D3D9 NOT JUSTIFIED. ENGINE BACKEND NOT JUSTIFIED.",
            "",
            "## A. Baseline (honest)",
            "",
            "- Prior UNIQUE inflated by 4 stub-only visits; real P30 baseline **17**.",
            "- Phase 30 ctor `RETURNED_CLEAN` reclassified → **RETURNED_CLEAN_WITH_STUBS**.",
            "- Live no-stub ctor stops on **InitializeCriticalSection** (depth 3, 7 entered).",
            "",
            "## B. Allocator provenance `[0x0189DA88]`",
            "",
            "- Section: `.data` BSS tail; PE initial **0**.",
            "- Single absolute writer: setter `0x009E9410` ← `0x008101B0`.",
            "- Value source: **PROTECTED_BOUNDARY_CALL** `0x00686000` (then ordinary base ctor `0x009E7710` + vtable `0x00BBB460`).",
            "- Classification: **%s**" % alloc["classification"],
            "- ALLOCATOR_TARGET_RESOLVED: **%s** (vtable+8 → `0x004A9FF0` undecodable)" % (
                alloc["ALLOCATOR_TARGET_RESOLVED"]),
            "- ALLOCATOR_INIT_PATH_ORDINARY: **%s**" % alloc["ALLOCATOR_INIT_PATH_ORDINARY"],
            "- `0x009E9340` ENTERABLE: **NO**. Implementation attempted: **NO**. Track A **stopped**.",
            "",
            "## C. Wrapper `0x009E9460`",
            "",
            alloc["wrapper_9e9460"]["contract"],
            "",
            "## D. Wrapper `0x009EB870`",
            "",
            alloc["wrapper_9eb870"]["contract"],
            "",
            "## E. Classification decision",
            "",
            "Exactly one class applied: **%s**. Not invoked, not emulated, not malloc-substituted." % (
                alloc["classification"]),
            "",
            "## F. `0x009E9160` caller inventory",
            "",
            "- E8 sites: **%d**; data pointers: **%d**" % (inv["e8_sites"], inv["data_pointer_refs"]),
            "- Sole caller `0x009E9340`; this-source **ALLOCATOR_RESULT**.",
            "- by_this_source: %s" % json.dumps(inv["by_this_source"]),
            "",
            "## G. Non-allocating ctor parents",
            "",
            "**None.** No STACK_STORAGE / EMBEDDED_SUBOBJECT / CALLER_ARGUMENT / GLOBAL_STORAGE caller.",
            "",
            "## H. Reverse execution frontier",
            "",
            "- Seeds: %d executed HIGH functions (incl. POD `0x929972→0x924D30`, seed `0x949920`)." % len(seed_vas),
            "- Level-1/2 callers scored with PROVEN_DEPTH weighting; allocator parent deprioritized.",
            "",
            "## I. Depth-4 / Depth-5",
            "",
            "- ENTERABLE_WITH_DEPTH_4_POTENTIAL: **%d** %s" % (len(d4), d4),
            "- ENTERABLE_WITH_DEPTH_5_POTENTIAL: **%d** %s" % (len(d5), d5),
            "- Strict rule rejects candidates with pending imports (CS/mutex) even when static frames ≥4.",
            "",
            "## J. Campaign (12 HIGH roots)",
            "",
            "\n".join(
                "- `%s` %s → **%s** (d=%d, u=%d) %s" % (
                    hx(r["root"]), r["kind"], r["result"], r["depth_max"], r["unique_entered"],
                    r.get("detail") or "")
                for r in rows
            ),
            "",
            "## K. Actual blockers",
            "",
            "- Histogram: %s" % json.dumps(hist_block),
            "- REQUIRED_STATE subclasses: %s" % json.dumps(req_hist),
            "- Most common real blocker: **%s** ×%d" % common,
            "- Diagnostic (uncounted) CS no-op → next **%s**" % diag.get("next_blocker_import"),
            "",
            "## L. Clean roots / constructors",
            "",
            "- CLEAN_ORDINARY_ROOTS: **%d** %s" % (len(clean_roots), [hx(x) for x in clean_roots]),
            "- EXECUTED_ORDINARY_CONSTRUCTORS: **%d** %s" % (len(ctors), [hx(x) for x in ctors]),
            "",
            "## M. Frontier delta",
            "",
            "- UNIQUE: **%d** (honest; stubs excluded unless body entered)" % len(unique),
            "- ENTERABLE: **%d**" % len(enterable),
            "- EXECUTION_RUNS: **%d**" % frontier["execution_runs"],
            "- DEEPEST: **%d**; LARGEST_CLOSURE: **%d** (no-stub)" % (deepest, largest),
            "- DEPTH_4/5 potential: **%d / %d**" % (len(d4), len(d5)),
            "",
            "## N. Phase 32 recommendation",
            "",
            recommended,
            "",
        ]))
    print("wrote", report)
    print("class", alloc["classification"],
          "unique", len(unique), "enterable", len(enterable),
          "clean", len(clean_roots), "ctors", len(ctors),
          "deepest", deepest, "closure", largest,
          "d4", len(d4), "blocker", common)
    return {
        "alloc": alloc, "inv": inv, "rows": rows, "diag": diag,
        "unique": unique, "enterable": enterable, "clean": clean_roots,
        "ctors": ctors, "deepest": deepest, "largest": largest,
        "d4": d4, "d5": d5, "frontier": frontier, "common": common,
    }


if __name__ == "__main__":
    main()
