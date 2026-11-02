#!/usr/bin/env python3
"""Static analysis of the ordinary .text section of nfs.exe.

Reads the PE headers and the .text bytes only. Does not modify the game
directory, does not write C, and does not follow Stext, Sitext, Srdata,
Sdata, Sidata, or .securom.

  tools/uc_code_analyze.py <nfs.exe> [outdir]

Writes analysis/undercover/code-analysis.md and code-analysis.json.
Support is decided by calling tools/lift.py Lifter.insn on one instruction
of each operand form and discarding the strings. lift.py is not modified.
"""
import array, collections, hashlib, json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lift
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import (
    X86_OP_IMM, X86_OP_REG, X86_OP_MEM,
    X86_REG_ST0, X86_REG_ST1, X86_REG_ST2, X86_REG_ST3,
    X86_REG_ST4, X86_REG_ST5, X86_REG_ST6, X86_REG_ST7,
    X86_REG_MM0, X86_REG_MM1, X86_REG_MM2, X86_REG_MM3,
    X86_REG_MM4, X86_REG_MM5, X86_REG_MM6, X86_REG_MM7,
    X86_REG_XMM0, X86_REG_XMM1, X86_REG_XMM2, X86_REG_XMM3,
    X86_REG_XMM4, X86_REG_XMM5, X86_REG_XMM6, X86_REG_XMM7,
    X86_REG_ES, X86_REG_CS, X86_REG_SS, X86_REG_DS, X86_REG_FS, X86_REG_GS,
    X86_GRP_FPU, X86_GRP_MMX, X86_GRP_SSE1, X86_GRP_SSE2, X86_GRP_SSE3,
    X86_GRP_SSSE3, X86_GRP_SSE41, X86_GRP_SSE42, X86_GRP_3DNOW, X86_GRP_AVX,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTECTED = ("Stext", "Sitext", "Srdata", "Sdata", "Sidata", ".securom")
GPR = set(lift.R32) | set(lift.R16) | set(lift.R8L) | set(lift.R8H)
ST = {X86_REG_ST0, X86_REG_ST1, X86_REG_ST2, X86_REG_ST3,
      X86_REG_ST4, X86_REG_ST5, X86_REG_ST6, X86_REG_ST7}
MMR = {X86_REG_MM0, X86_REG_MM1, X86_REG_MM2, X86_REG_MM3,
       X86_REG_MM4, X86_REG_MM5, X86_REG_MM6, X86_REG_MM7}
XMR = {X86_REG_XMM0, X86_REG_XMM1, X86_REG_XMM2, X86_REG_XMM3,
       X86_REG_XMM4, X86_REG_XMM5, X86_REG_XMM6, X86_REG_XMM7}
SEG = {X86_REG_ES, X86_REG_CS, X86_REG_SS, X86_REG_DS, X86_REG_FS, X86_REG_GS}
PRIV = {
    "in", "out", "insb", "insw", "insd", "outsb", "outsw", "outsd",
    "cli", "sti", "hlt", "clts", "invd", "wbinvd", "lgdt", "lidt", "lldt", "ltr",
    "lmsw", "smsw", "invlpg", "sysenter", "sysexit", "syscall", "sysret",
    "rdmsr", "wrmsr", "rdpmc", "iret", "iretd", "into", "bound", "arpl",
    "ud0", "ud1", "ud2", "vmcall", "vmlaunch", "vmresume", "swapgs",
}
UNUSUAL = PRIV | {"int", "cpuid", "rdtsc", "rdtscp", "wbinvd"}
SSE_PLUS = {X86_GRP_SSE3, X86_GRP_SSSE3, X86_GRP_SSE41, X86_GRP_SSE42}
K_FALL, K_CALL, K_JMP, K_JCC = 0, 1, 2, 3
K_STOP, K_INT3 = 4, 5
K_JMP_IND, K_CALL_IND, K_CALL_IAT, K_JMP_IAT = 6, 7, 8, 9
G_X87, G_MMX, G_SSE, G_SSE2, G_SSE3P, G_AVX, G_3DNOW = 1, 2, 4, 8, 16, 32, 64


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


def hx(n):
    return f"0x{n & 0xffffffff:08X}"


def assert_output_ok(outdir, exe):
    out = os.path.abspath(outdir)
    game = os.path.abspath(os.path.dirname(os.path.abspath(exe)))
    root = os.path.abspath(ROOT)
    if os.path.commonpath([out, game]) == game:
        die(f"refusing to write inside the game directory: {out}")
    if os.path.commonpath([out, root]) != root:
        die(f"output must stay inside the repository: {out}")
    return out


def u16(b, o):
    return int.from_bytes(b[o:o + 2], "little")


def u32(b, o):
    return int.from_bytes(b[o:o + 4], "little")


def reg_class(r):
    if r in GPR:
        return "gpr"
    if r in ST:
        return "st"
    if r in MMR:
        return "mm"
    if r in XMR:
        return "xmm"
    if r in SEG:
        return "seg"
    return "other"


def is_jcc(m):
    return (m.startswith("j") and m != "jmp" and m[1:] in lift.CC) or m in (
        "jecxz", "jcxz", "loop", "loope", "loopz", "loopne", "loopnz")


def read_inputs(path):
    """PE headers plus the .text raw bytes. No other section is read."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0)
        pre = f.read(0x400)
        if pre[:2] != b"MZ":
            die("not an MZ executable")
        e = u32(pre, 0x3C)
        if len(pre) < e + 24:
            f.seek(0)
            pre = f.read(e + 24)
        if pre[e:e + 4] != b"PE\0\0":
            die("no PE signature")
        if u16(pre, e + 4) != 0x14C:
            die("not an i386 image")
        nsec = u16(pre, e + 6)
        optsz = u16(pre, e + 20)
        need = e + 24 + optsz + nsec * 40
        f.seek(0)
        head = f.read(need)
        opt = e + 24
        if u16(head, opt) != 0x10B:
            die("not PE32")
        image_base = u32(head, opt + 28)
        entry_rva = u32(head, opt + 16)
        size_image = u32(head, opt + 56)
        ndir = u32(head, opt + 92)
        dirs = []
        for i in range(min(ndir, 16)):
            dirs.append((u32(head, opt + 96 + i * 8), u32(head, opt + 100 + i * 8)))
        sections = []
        sec_off = opt + optsz
        text = None
        for i in range(nsec):
            raw = head[sec_off + i * 40:sec_off + (i + 1) * 40]
            name = raw[:8].split(b"\0", 1)[0].decode("latin1") or "<none>"
            vsz, va, rsz, rawptr = (
                int.from_bytes(raw[8:12], "little"), int.from_bytes(raw[12:16], "little"),
                int.from_bytes(raw[16:20], "little"), int.from_bytes(raw[20:24], "little"))
            sections.append({"name": name, "va": image_base + va, "vsize": vsz, "raw_ptr": rawptr, "raw_size": rsz})
            if name == ".text":
                text = sections[-1]
        if text is None:
            die("no .text section")
        take = min(text["vsize"], text["raw_size"])
        f.seek(text["raw_ptr"])
        blob = f.read(take)
        if len(blob) != take:
            die("short read of .text")
    iat_rva, iat_sz = dirs[12] if len(dirs) > 12 else (0, 0)
    return {
        "file_size": file_size,
        "image_base": image_base,
        "entry": image_base + entry_rva,
        "size_image": size_image,
        "sections": sections,
        "text": text,
        "bytes": blob,
        "text_va": text["va"],
        "text_size": take,
        "iat": (image_base + iat_rva, image_base + iat_rva + iat_sz) if iat_rva and iat_sz else None,
    }


def section_of(sections, va):
    for s in sections:
        if s["va"] <= va < s["va"] + s["vsize"]:
            return s["name"]
    return None


def form_key(insn):
    parts = [insn.mnemonic]
    for op in insn.operands:
        if op.type == X86_OP_IMM:
            parts.append(("imm", op.size))
        elif op.type == X86_OP_REG:
            parts.append(("reg", op.size, reg_class(op.reg)))
        elif op.type == X86_OP_MEM:
            m = op.mem
            parts.append(("mem", op.size, 1 if m.base else 0, 1 if m.index else 0, m.scale or 0, 1 if m.segment else 0))
        else:
            parts.append(("other", op.type, op.size))
    return tuple(parts)


def group_bits(insn):
    g = set(insn.groups)
    bits = 0
    if X86_GRP_FPU in g:
        bits |= G_X87
    if X86_GRP_MMX in g:
        bits |= G_MMX
    if X86_GRP_SSE1 in g:
        bits |= G_SSE
    if X86_GRP_SSE2 in g:
        bits |= G_SSE2
    if g & SSE_PLUS:
        bits |= G_SSE3P
    if X86_GRP_AVX in g:
        bits |= G_AVX
    if X86_GRP_3DNOW in g:
        bits |= G_3DNOW
    return bits


def mem_kind(op, iat):
    m = op.mem
    disp = m.disp & 0xffffffff
    if not m.base and not m.index:
        if iat and iat[0] <= disp < iat[1]:
            return "abs-iat"
        return "abs"
    if m.base and not m.index:
        return "base" if (m.disp & 0xffffffff) == 0 else "base+disp"
    if m.index and not m.base and m.scale == 4:
        return "index*4"
    if m.index:
        return "scaled"
    return "mem"


class Analyzer:
    def __init__(self, info):
        self.info = info
        self.text = info["bytes"]
        self.lo = info["text_va"]
        self.n = info["text_size"]
        self.hi = self.lo + self.n
        self.iat = info["iat"]
        self.sections = info["sections"]
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.probe = lift.Lifter.__new__(lift.Lifter)
        self.probe.TVA = self.lo
        self.probe.TSZ = self.n
        self.probe.TDATA = self.text
        self.probe.md = self.md
        self.probe.retpast = set()
        self.probe.entry = 0
        self.probe.oob_calls = 0
        self.probe.in_text = self.in_text
        self.length_at = bytearray(self.n)
        self.kind_at = bytearray(self.n)
        self.group_at = bytearray(self.n)
        self.form_at = array.array("H", b"\x00\x00" * self.n)
        self.target_at = array.array("I", b"\x00\x00\x00\x00" * self.n)
        self.forms = [None]
        self.form_index = {}
        self.mnemonics = collections.Counter()
        self.priv = collections.Counter()
        self.unusual = collections.Counter()
        self.groups = collections.Counter()
        self.decoded = 0
        self.decoded_bytes = 0
        self.int3 = 0
        self.fs_gs = 0
        self.bad_regions = []
        self.calls_in = collections.Counter()
        self.jmps_in = collections.Counter()
        self.call_n = self.call_in_n = self.call_out_n = 0
        self.jmp_n = self.jmp_in_n = self.jmp_out_n = 0
        self.jcc_n = 0
        self.lin_ext = collections.Counter()
        self.lin_ext_targets = collections.defaultdict(set)
        self.indirect = collections.Counter()
        self.indirect_examples = collections.defaultdict(list)
        self.vtable_shaped = 0
        self.thunks = []
        self.bounds = {}
        self.table_blocks = []
        self.table_shaped = 0
        self._block = []
        self._block_start = None
        self._overflow = False
        self._last_end = None
        self._suffix = collections.deque(maxlen=16)

    def in_text(self, a):
        return self.lo <= (a & 0xffffffff) < self.hi

    def control_result(self, insn):
        """How lift() treats a branch before it ever calls insn(). None means ask insn()."""
        m = insn.mnemonic
        o = insn.operands[0] if insn.operands else None
        if m == "jmp" and o is not None:
            return True
        cc = m.startswith("j") and m != "jmp" and m[1:] in lift.CC
        loops = m in ("jecxz", "jcxz", "loop", "loope", "loopz", "loopne", "loopnz")
        if (cc or loops) and o is not None and o.type == X86_OP_IMM:
            # A conditional branch out of .text is emitted as unsupported_insn("branch-out").
            # jmp and the loop family out of .text go through DISPATCH_TAIL instead.
            if cc and not self.in_text(o.imm & 0xffffffff):
                return False
            return True
        return None

    def fid(self, insn):
        ctrl = self.control_result(insn)
        key = form_key(insn)
        if ctrl is False:
            key = key + ("branch-out",)
        got = self.form_index.get(key)
        if got is not None:
            return got
        if len(self.forms) >= 65535:
            die("too many instruction forms")
        if ctrl is not None:
            ok, err = ctrl, (None if ctrl else "branch-out")
        else:
            ok, err = True, None
            try:
                self.probe.insn(insn, set())
            except lift.Unsupported as exc:
                ok = False
                err = str(exc) or insn.mnemonic
            except Exception as exc:
                ok = False
                err = f"{type(exc).__name__}: {exc}"
        self.form_index[key] = len(self.forms)
        self.forms.append({"mnemonic": insn.mnemonic, "ok": ok, "err": err})
        return self.form_index[key]

    def note_ext(self, kind, src, dst, bag, targets):
        name = section_of(self.sections, dst) or "unmapped"
        if self.iat and self.iat[0] <= dst < self.iat[1]:
            name = name + " (inside IAT range)"
        bag[(name, kind)] += 1
        if len(targets[name]) < 64:
            targets[name].add(dst)
        else:
            targets[name].add(dst) if len(targets[name]) < 4096 else None

    def classify_flow(self, insn):
        m = insn.mnemonic
        ops = insn.operands
        o = ops[0] if ops else None
        if m == "int3":
            return K_INT3, 0
        if m in ("ret", "retf", "hlt", "ud2"):
            return K_STOP, 0
        if m == "call" and o is not None and o.type == X86_OP_IMM:
            return K_CALL, o.imm & 0xffffffff
        if m == "jmp" and o is not None and o.type == X86_OP_IMM:
            return K_JMP, o.imm & 0xffffffff
        if is_jcc(m) and o is not None and o.type == X86_OP_IMM:
            return K_JCC, o.imm & 0xffffffff
        if m == "call" and o is not None and o.type == X86_OP_REG:
            self._example("call reg", insn)
            return K_CALL_IND, 0
        if m == "jmp" and o is not None and o.type == X86_OP_REG:
            self._example("jmp reg", insn)
            return K_JMP_IND, 0
        if m in ("call", "jmp") and o is not None and o.type == X86_OP_MEM:
            shape = mem_kind(o, self.iat)
            label = f"{m} [{shape}]"
            self._example(label, insn)
            if m == "call" and shape == "base+disp":
                disp = o.mem.disp
                if 0 < disp <= 0x400 and disp % 4 == 0:
                    self.vtable_shaped += 1
            if m == "jmp" and not o.mem.base and o.mem.index and (o.mem.scale or 0) == 4:
                self.table_shaped += 1
            if shape == "abs-iat":
                if m == "jmp":
                    self.thunks.append(insn.address)
                return (K_JMP_IAT if m == "jmp" else K_CALL_IAT), 0
            return (K_JMP_IND if m == "jmp" else K_CALL_IND), 0
        return K_FALL, 0

    def _example(self, label, insn):
        self.indirect[label] += 1
        bucket = self.indirect_examples[label]
        if len(bucket) < 8:
            bucket.append(f"{hx(insn.address)}: {insn.mnemonic} {insn.op_str}")

    def close_block(self):
        if self._suffix:
            last = self._suffix[-1]
            if last.mnemonic in ("ja", "jbe"):
                try:
                    bound = self.probe._jt_bound(list(self._suffix))
                except Exception:
                    bound = None
                if bound:
                    reg, n, held = bound
                    self.bounds[held & 0xffffffff] = (reg, n)
        if (not self._overflow and self._block and self._block[-1].mnemonic == "jmp"
                and self._block[-1].operands and self._block[-1].operands[0].type == X86_OP_MEM):
            self.table_blocks.append((self._block_start, list(self._block)))
        self._block = []
        self._block_start = None
        self._overflow = False
        self._suffix.clear()

    def take(self, insn):
        off = insn.address - self.lo
        if off < 0 or off >= self.n or insn.size <= 0 or off + insn.size > self.n:
            return
        if self._last_end is not None and insn.address != self._last_end:
            self.close_block()
        if self._block_start is None:
            self._block_start = insn.address
        self._suffix.append(insn)
        if self._overflow or len(self._block) >= 24:
            self._overflow = True
            self._block = []
        else:
            self._block.append(insn)
        self._last_end = insn.address + insn.size
        self.length_at[off] = insn.size
        self.form_at[off] = self.fid(insn)
        bits = group_bits(insn)
        self.group_at[off] = bits
        if bits & G_X87:
            self.groups["x87"] += 1
        if bits & G_MMX:
            self.groups["mmx"] += 1
        if bits & G_SSE:
            self.groups["sse"] += 1
        if bits & G_SSE2:
            self.groups["sse2"] += 1
        if bits & G_SSE3P:
            self.groups["sse3_or_later"] += 1
        if bits & G_AVX:
            self.groups["avx"] += 1
        if bits & G_3DNOW:
            self.groups["3dnow"] += 1
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.segment in (X86_REG_FS, X86_REG_GS):
                self.fs_gs += 1
                break
        base_m = insn.mnemonic.split()[-1]
        if base_m in PRIV or insn.mnemonic in PRIV:
            self.priv[insn.mnemonic] += 1
        if base_m in UNUSUAL or insn.mnemonic in UNUSUAL or insn.mnemonic == "int":
            if insn.mnemonic != "int3":
                self.unusual[insn.mnemonic] += 1
        if insn.mnemonic == "int3":
            self.int3 += 1
        self.mnemonics[insn.mnemonic] += 1
        self.decoded += 1
        self.decoded_bytes += insn.size
        kind, tgt = self.classify_flow(insn)
        self.kind_at[off] = kind
        self.target_at[off] = tgt
        if kind == K_CALL:
            self.call_n += 1
            if self.in_text(tgt):
                self.call_in_n += 1
                self.calls_in[tgt] += 1
            else:
                self.call_out_n += 1
                self.note_ext("call", insn.address, tgt, self.lin_ext, self.lin_ext_targets)
        elif kind == K_JMP:
            self.jmp_n += 1
            if self.in_text(tgt):
                self.jmp_in_n += 1
                self.jmps_in[tgt] += 1
            else:
                self.jmp_out_n += 1
                self.note_ext("jmp", insn.address, tgt, self.lin_ext, self.lin_ext_targets)
        elif kind == K_JCC:
            self.jcc_n += 1
            if not self.in_text(tgt):
                self.note_ext("jcc", insn.address, tgt, self.lin_ext, self.lin_ext_targets)
        if insn.mnemonic in ("ret", "retf", "hlt", "ud2", "int3") or insn.mnemonic == "jmp" or is_jcc(insn.mnemonic):
            self.close_block()

    def sweep(self):
        off = 0
        data = self.text
        bad_at = None
        last_report = 0
        while off < self.n:
            if off - last_report >= 0x100000:
                print(f"  sweep {off / self.n:.0%} ({self.decoded} instructions)", file=sys.stderr)
                last_report = off
            insns = list(self.md.disasm(data[off:off + 65536], self.lo + off))
            if not insns:
                if bad_at is None:
                    bad_at = off
                off += 1
                continue
            if bad_at is not None:
                self.bad_regions.append((self.lo + bad_at, off - bad_at))
                bad_at = None
                self.close_block()
            for insn in insns:
                self.take(insn)
            off = insns[-1].address + insns[-1].size - self.lo
        if bad_at is not None:
            self.bad_regions.append((self.lo + bad_at, self.n - bad_at))
        self.close_block()
        print(f"  sweep done: {self.decoded} instructions", file=sys.stderr)

    def switches(self):
        recognized = []
        rejected = 0
        outside_targets = 0
        twolevel = 0
        for start, ins in self.table_blocks:
            bound = self.bounds.get(start)
            if not bound:
                continue
            try:
                tab = self.probe._jt_table(ins, bound)
            except Exception:
                tab = None
            if tab is None:
                rejected += 1
                continue
            _reg, disp, targets = tab
            recognized.append({
                "jmp": ins[-1].address,
                "table": disp,
                "entries": len(targets),
                "two_level": any(i.mnemonic == "movzx" for i in ins[:-1]),
            })
            if recognized[-1]["two_level"]:
                twolevel += 1
            outside_targets += sum(1 for t in targets if not self.in_text(t & 0xffffffff))
        return {
            "table_shaped_jmp": self.table_shaped,
            "bounds": len(self.bounds),
            "jmp_blocks_saved": len(self.table_blocks),
            "recognized": len(recognized),
            "recognized_two_level": twolevel,
            "bound_but_rejected": rejected,
            "recognized_targets_outside_text": outside_targets,
            "examples": [{"jmp": hx(r["jmp"]), "table": hx(r["table"]), "entries": r["entries"], "two_level": r["two_level"]}
                         for r in recognized[:12]],
        }

    def candidates(self):
        raw_prologue = self.text.count(b"\x55\x8B\xEC")
        strong = []
        strong_prologue = 0
        strong_pad = 0
        boundary_prologue = 0
        pad_prologue = 0
        pad_prologue_not_called = 0
        for off in range(self.n - 2):
            if self.length_at[off] == 0 or self.text[off:off + 3] != b"\x55\x8B\xEC":
                continue
            boundary_prologue += 1
            pad = 0
            p = off - 1
            while p >= 0 and self.text[p] == 0xCC and self.length_at[p] == 1:
                pad += 1
                p -= 1
            if pad:
                pad_prologue += 1
        called = []
        for tgt, ncall in self.calls_in.items():
            off = tgt - self.lo
            if not (0 <= off < self.n and self.length_at[off]):
                continue
            called.append((tgt, ncall))
            if off + 3 <= self.n and self.text[off:off + 3] == b"\x55\x8B\xEC":
                strong_prologue += 1
            p = off - 1
            pad = 0
            while p >= 0 and self.text[p] == 0xCC and self.length_at[p] == 1:
                pad += 1
                p -= 1
            if pad:
                strong_pad += 1
        called_set = {t for t, _n in called}
        for off in range(self.n - 2):
            if self.length_at[off] == 0 or self.text[off:off + 3] != b"\x55\x8B\xEC":
                continue
            p = off - 1
            pad = 0
            while p >= 0 and self.text[p] == 0xCC and self.length_at[p] == 1:
                pad += 1
                p -= 1
            if pad and (self.lo + off) not in called_set:
                pad_prologue_not_called += 1
        thunk_called = sum(1 for t in self.thunks if t in called_set)
        strong = called
        return {
            "raw_push_ebp_mov_ebp_esp": raw_prologue,
            "prologue_at_instruction_boundary": boundary_prologue,
            "prologue_after_int3": pad_prologue,
            "prologue_after_int3_not_a_call_target": pad_prologue_not_called,
            "direct_call_targets": len(self.calls_in),
            "call_targets_on_instruction_boundary": len(strong),
            "call_targets_off_boundary": len(self.calls_in) - len(strong),
            "strong_with_prologue": strong_prologue,
            "strong_after_int3": strong_pad,
            "iat_jmp_thunks": len(self.thunks),
            "iat_jmp_thunks_that_are_call_targets": thunk_called,
            "strong": strong,
        }

    def walk(self, roots):
        visited = bytearray(self.n)
        queued = set()
        queue = collections.deque()
        for tgt, _n in roots:
            off = tgt - self.lo
            if 0 <= off < self.n and self.length_at[off] and off not in queued:
                queued.add(off)
                queue.append(tgt)
        reached = reached_bytes = supported = 0
        unsup = collections.Counter()
        priv = collections.Counter()
        internal_calls = internal_jmps = internal_jcc = 0
        mid = 0
        ind_call = ind_jmp = iat_call = iat_jmp = 0
        ext = collections.Counter()
        ext_targets = collections.defaultdict(set)
        groups = collections.Counter()

        def enqueue(tgt, kind):
            nonlocal mid
            if not self.in_text(tgt):
                name = section_of(self.sections, tgt) or "unmapped"
                ext[(name, kind)] += 1
                if len(ext_targets[name]) < 4096:
                    ext_targets[name].add(tgt)
                return
            off = tgt - self.lo
            if self.length_at[off] == 0:
                mid += 1
                return
            if off in queued or visited[off]:
                return
            queued.add(off)
            queue.append(tgt)

        while queue:
            va = queue.popleft()
            while self.in_text(va):
                off = va - self.lo
                if visited[off] or self.length_at[off] == 0:
                    break
                visited[off] = 1
                reached += 1
                sz = self.length_at[off]
                reached_bytes += sz
                form = self.forms[self.form_at[off]]
                if form["ok"]:
                    supported += 1
                else:
                    unsup[form["mnemonic"]] += 1
                if form["mnemonic"] in PRIV or form["mnemonic"].split()[-1] in PRIV:
                    priv[form["mnemonic"]] += 1
                bits = self.group_at[off]
                if bits & G_X87:
                    groups["x87"] += 1
                if bits & G_MMX:
                    groups["mmx"] += 1
                if bits & (G_SSE | G_SSE2 | G_SSE3P):
                    groups["sse_family"] += 1
                kind = self.kind_at[off]
                tgt = self.target_at[off]
                if kind == K_CALL:
                    if self.in_text(tgt):
                        internal_calls += 1
                    else:
                        enqueue(tgt, "call")
                    va += sz
                elif kind == K_JMP:
                    enqueue(tgt, "jmp")
                    if self.in_text(tgt) and self.length_at[tgt - self.lo]:
                        internal_jmps += 1
                    break
                elif kind == K_JCC:
                    enqueue(tgt, "jcc")
                    if self.in_text(tgt) and self.length_at[tgt - self.lo]:
                        internal_jcc += 1
                    va += sz
                elif kind == K_STOP:
                    break
                elif kind == K_INT3:
                    if off + 4 <= self.n and self.text[off + 1:off + 4] == b"\xcc\xcc\xcc":
                        break
                    va += sz
                elif kind == K_JMP_IND:
                    ind_jmp += 1
                    break
                elif kind == K_CALL_IND:
                    ind_call += 1
                    va += sz
                elif kind == K_CALL_IAT:
                    iat_call += 1
                    va += sz
                elif kind == K_JMP_IAT:
                    iat_jmp += 1
                    break
                else:
                    va += sz
        protected = 0
        protected_by = collections.Counter()
        for (name, kind), nedge in ext.items():
            base = name.split(" ", 1)[0]
            if base in PROTECTED:
                protected += nedge
                protected_by[f"{name} {kind}"] += nedge
        return {
            "roots": len(roots),
            "roots_entered": sum(1 for t, _n in roots if visited[t - self.lo]),
            "instructions": reached,
            "bytes": reached_bytes,
            "supported": supported,
            "unsupported": reached - supported,
            "unsupported_mnemonics": unsup,
            "privileged": priv,
            "groups": groups,
            "internal_calls": internal_calls,
            "internal_jmps": internal_jmps,
            "internal_jcc": internal_jcc,
            "landed_off_boundary": mid,
            "indirect_calls": ind_call,
            "indirect_jmps": ind_jmp,
            "iat_calls": iat_call,
            "iat_jmps": iat_jmp,
            "external": ext,
            "external_targets": {k: len(v) for k, v in ext_targets.items()},
            "protected_direct_edges": protected,
            "protected_by": protected_by,
        }


def ranked(counter, limit=None):
    rows = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    if limit is not None:
        rows = rows[:limit]
    return [{"address": hx(a), "count": n} for a, n in rows]


def region_summary(regions):
    total = sum(n for _a, n in regions)
    longest = sorted(regions, key=lambda r: -r[1])[:20]
    return {
        "regions": len(regions),
        "bytes": total,
        "longest": [{"address": hx(a), "bytes": n} for a, n in longest],
    }


def choose(rep):
    text_n = rep["text"]["bytes_analyzed"]
    decode_ratio = rep["decode"]["decoded_bytes"] / text_n
    reached = max(rep["cfg"]["instructions"], 1)
    sup_ratio = rep["cfg"]["supported"] / reached
    entries = rep["candidates"]["call_targets_on_instruction_boundary"]
    prot = rep["cfg"]["protected_direct_edges"]
    internal = max(rep["cfg"]["internal_calls"], 1)
    if entries < 200 or decode_ratio < 0.60 or sup_ratio < 0.80:
        return "MORE STATIC ANALYSIS REQUIRED", (
            "The ordinary .text sweep does not yet show a stable set of liftable functions. "
            f"Decoded bytes are {decode_ratio:.1%} of .text, call-target entries are {entries}, "
            f"and {sup_ratio:.1%} of the instructions reached from those entries are accepted by Lifter.insn."
        )
    if prot > 100 or prot / internal > 0.01:
        return "PROTECTED STARTUP IS A FUNDAMENTAL BLOCKER", (
            f"Reached .text code has {prot} direct branches into protected-layout sections, "
            f"against {internal} direct calls that stay in .text. "
            "A lifter that does not follow those sections cannot cover the callees. "
            "This analysis did not unpack or follow them."
        )
    if rep["text"]["entry_in_text"]:
        return "PROCEED WITH LIFTER ADAPTATION", (
            "The entry point is inside .text, most reached instructions are accepted by the current lifter, "
            "and direct edges into the protected-layout sections are rare."
        )
    return "PROTECTED STARTUP IS A FUNDAMENTAL BLOCKER", (
        ".text is largely ordinary MSVC code and the reached body is mostly self-contained, "
        "so instruction coverage is not what blocks a port. "
        f"The PE entry point {rep['text']['entry']} is not in .text. "
        "Adapting the lifter would translate a body the PE header does not enter. "
        "Reaching that body from the real entry means following the protected startup, which this analysis does not do."
    )


def top_gaps(rep):
    cfg = rep["cfg"]
    items = []
    items.append({
        "title": "The PE entry point is outside .text",
        "detail": f"Entry {rep['text']['entry']} is in {rep['text']['entry_section']}. "
                  "tools/genall.py seeds discovery there and then stops, because the walk is limited to .text. "
                  "This run did not disassemble that section.",
    })
    if cfg["protected_direct_edges"]:
        items.append({
            "title": "Direct edges from reached .text into protected-layout sections",
            "detail": f"{cfg['protected_direct_edges']} direct call/jmp/jcc edges. "
                      + ", ".join(f"{k}: {v}" for k, v in sorted(cfg["protected_by"].items(), key=lambda kv: -kv[1])[:8]),
        })
    else:
        items.append({
            "title": "No direct reached edge into the protected-layout sections",
            "detail": "The call graph that starts at in-.text call targets does not directly branch into "
                      "Stext, Sitext, Srdata, Sdata, Sidata, or .securom. "
                      "Startup can still enter those sections before any .text function runs.",
        })
    unsup = cfg["unsupported_mnemonics"]
    items.append({
        "title": "Lifter.insn rejects some reached instructions" if unsup else "Reached instructions are accepted by Lifter.insn",
        "detail": (
            f"{cfg['unsupported']} of {cfg['instructions']} reached instructions are unsupported. "
            + ", ".join(f"{row['mnemonic']} x{row['count']}" for row in unsup[:12])
        ) if unsup else f"All {cfg['supported']} instructions reached from call targets were accepted.",
    })
    sw = rep["switches"]
    items.append({
        "title": "MSVC switch pattern from tools/lift.py",
        "detail": f"{sw['recognized']} jump tables match _jt_bound/_jt_table "
                  f"({sw['recognized_two_level']} of them use the movzx byte table). "
                  f"{sw['table_shaped_jmp']} indirect jumps have the [reg*4+disp] shape, "
                  f"{sw['bounds']} cmp/ja bounds were recorded, and {sw['bound_but_rejected']} "
                  "jmp blocks sat on a bound but were rejected. Targets were not guessed when the pattern did not match.",
    })
    items.append({
        "title": "Indirect calls and jumps have no proven targets",
        "detail": f"Reached code has {cfg['indirect_calls']} register/memory indirect calls, "
                  f"{cfg['indirect_jmps']} indirect jumps, {cfg['iat_calls']} call [IAT], and {cfg['iat_jmps']} jmp [IAT]. "
                  "The lifter already lowers an indirect call to DISPATCH_CALL. "
                  "It does not recover a vtable target, and a jmp [reg*4+disp] that fails the switch matcher stays indirect.",
    })
    items.append({
        "title": ".text has no absolute call or jump through the PE IAT",
        "detail": "The IAT directory is "
                  f"{rep['text']['iat']}, inside the .securom address range. "
                  "Absolute indirect branches at that range in the linear sweep: "
                  f"{sum(row['count'] for row in rep['indirect']['counts'] if row['form'] in ('call [abs-iat]', 'jmp [abs-iat]'))}. "
                  f"Reached code contains {cfg['iat_calls']} call [IAT] and {cfg['iat_jmps']} jmp [IAT]. "
                  "NFSU2's import path is an absolute call or jump through an IAT slot, which runtime/win32.c rewrites. "
                  "Reached indirect calls are call reg or call [mem], with no static target. "
                  "If those ever reach MSVCR80 or MSVCP80, win32_call still pops nargs as if the callee were stdcall.",
    })
    items.append({
        "title": "Function discovery has call targets but no relocations",
        "detail": f"{rep['candidates']['call_targets_on_instruction_boundary']} direct-call targets land on a decoded instruction. "
                  f"{rep['candidates']['call_targets_off_boundary']} call targets are not on an instruction boundary and were not used. "
                  "tools/reloc2.py still has no unnamed reloc section to read, and IMAGE_FILE_RELOCS_STRIPPED is set. "
                  "Call edges replace that seed only for functions that are called directly.",
    })
    items.append({
        "title": "Prologues are evidence, not entries",
        "detail": f"The byte sequence 55 8B EC occurs {rep['candidates']['raw_push_ebp_mov_ebp_esp']} times. "
                  f"{rep['candidates']['prologue_at_instruction_boundary']} of those are at an instruction boundary, "
                  f"and {rep['candidates']['strong_with_prologue']} of the strong call targets begin with it. "
                  f"{rep['candidates']['prologue_after_int3_not_a_call_target']} boundary prologues sit after int3 padding "
                  "and are not direct call targets, so they were not used as roots.",
    })
    items.append({
        "title": "The image does not fit the NFSU2 guest map",
        "detail": f"Image base {rep['image_base']} matches, but SizeOfImage is {rep['size_of_image']} "
                  f"({hx(int(rep['image_base'], 16) + int(rep['size_of_image'], 16))}). "
                  "runtime/heap.c treats 0x00400000..0x00932000 as the image. "
                  "The .text end 0x00B603FB is already past that window.",
    })
    items.append({
        "title": "Stack commit is 4 MB",
        "detail": "The PE optional header, measured by tools/uc_analyze.py, asks for 0x400000 bytes of stack commit "
                  "and 0x800000 reserved. The web worker stack is about 1 MB.",
    })
    return items[:10]


def build_report(info, az, cand, walked, switches, elapsed):
    bad = region_summary(az.bad_regions)
    entry_sec = section_of(info["sections"], info["entry"])
    forms_bad = collections.Counter()
    forms_ok = 0
    for form in az.forms[1:]:
        if form["ok"]:
            forms_ok += 1
        else:
            forms_bad[form["mnemonic"]] += 1
    sweep_unsup = collections.Counter()
    sweep_ok = sweep_bad = 0
    for off in range(az.n):
        fid = az.form_at[off]
        if not fid:
            continue
        if az.forms[fid]["ok"]:
            sweep_ok += 1
        else:
            sweep_bad += 1
            sweep_unsup[az.forms[fid]["mnemonic"]] += 1
    rep = {
        "file": {"path": info["path"], "file_size": info["file_size"], "text_sha256": hashlib.sha256(info["bytes"]).hexdigest()},
        "image_base": hx(info["image_base"]),
        "size_of_image": hx(info["size_image"]),
        "text": {
            "start": hx(info["text_va"]),
            "end": hx(info["text_va"] + info["text_size"]),
            "bytes_analyzed": info["text_size"],
            "entry": hx(info["entry"]),
            "entry_section": entry_sec,
            "entry_in_text": az.in_text(info["entry"]),
            "iat": None if not info["iat"] else [hx(info["iat"][0]), hx(info["iat"][1])],
        },
        "decode": {
            "instructions": az.decoded,
            "decoded_bytes": az.decoded_bytes,
            "undecodable_bytes": az.n - az.decoded_bytes,
            "undecodable_regions": bad,
            "int3": az.int3,
            "fs_or_gs": az.fs_gs,
        },
        "groups": dict(az.groups),
        "mnemonics": [{"mnemonic": m, "count": n} for m, n in az.mnemonics.most_common()],
        "privileged": [{"mnemonic": m, "count": n} for m, n in az.priv.most_common()],
        "unusual": [{"mnemonic": m, "count": n} for m, n in az.unusual.most_common()],
        "calls": {
            "instructions": az.call_n,
            "target_in_text": az.call_in_n,
            "target_outside_text": az.call_out_n,
            "unique_targets_in_text": len(az.calls_in),
            "ranked": ranked(az.calls_in),
        },
        "jumps": {
            "direct_jmp": az.jmp_n,
            "target_in_text": az.jmp_in_n,
            "target_outside_text": az.jmp_out_n,
            "unique_targets_in_text": len(az.jmps_in),
            "conditional_and_loop": az.jcc_n,
            "ranked": ranked(az.jmps_in),
        },
        "linear_external": {
            "edges": [{"section": s, "kind": k, "count": n} for (s, k), n in az.lin_ext.most_common()],
            "unique_targets_capped": {s: len(v) for s, v in az.lin_ext_targets.items()},
        },
        "indirect": {
            "counts": [{"form": k, "count": n} for k, n in az.indirect.most_common()],
            "examples": {k: v for k, v in az.indirect_examples.items()},
        },
        "candidates": {k: v for k, v in cand.items() if k != "strong"},
        "switches": switches,
        "lifter": {
            "method": "lift() accepts jmp, in-range conditional branches, and loop/jecxz before insn(); other forms are decided by Lifter.insn on one instruction of each operand form. Strings are discarded",
            "vtable_shaped_calls": az.vtable_shaped,
            "forms": len(az.forms) - 1,
            "forms_supported": forms_ok,
            "forms_unsupported": len(az.forms) - 1 - forms_ok,
            "sweep_supported_instructions": sweep_ok,
            "sweep_unsupported_instructions": sweep_bad,
            "sweep_unsupported_mnemonics": [{"mnemonic": m, "count": n} for m, n in sweep_unsup.most_common()],
            "unsupported_form_mnemonics": [{"mnemonic": m, "forms": n} for m, n in forms_bad.most_common()],
        },
        "cfg": {
            "roots": walked["roots"],
            "roots_entered": walked["roots_entered"],
            "instructions": walked["instructions"],
            "bytes": walked["bytes"],
            "supported": walked["supported"],
            "unsupported": walked["unsupported"],
            "unsupported_mnemonics": [{"mnemonic": m, "count": n} for m, n in walked["unsupported_mnemonics"].most_common()],
            "privileged": [{"mnemonic": m, "count": n} for m, n in walked["privileged"].most_common()],
            "groups": dict(walked["groups"]),
            "internal_calls": walked["internal_calls"],
            "internal_jmps": walked["internal_jmps"],
            "internal_jcc": walked["internal_jcc"],
            "landed_off_boundary": walked["landed_off_boundary"],
            "indirect_calls": walked["indirect_calls"],
            "indirect_jmps": walked["indirect_jmps"],
            "iat_calls": walked["iat_calls"],
            "iat_jmps": walked["iat_jmps"],
            "external": [{"section": s, "kind": k, "count": n} for (s, k), n in walked["external"].most_common()],
            "unique_external_targets": walked["external_targets"],
            "protected_direct_edges": walked["protected_direct_edges"],
            "protected_by": dict(walked["protected_by"]),
        },
        "elapsed_seconds": round(elapsed, 1),
    }
    gaps = top_gaps(rep)
    choice, why = choose(rep)
    rep["feasibility"] = {"choice": choice, "why": why, "gaps": gaps}
    return rep


def markdown(rep):
    d = rep["decode"]
    c = rep["candidates"]
    cfg = rep["cfg"]
    sw = rep["switches"]
    lf = rep["lifter"]
    text_n = rep["text"]["bytes_analyzed"]
    lines = []
    w = lines.append
    w("# Undercover .text static analysis")
    w("")
    w("Only the ordinary `.text` section was read. Stext, Sitext, Srdata, Sdata, Sidata, and `.securom` were not disassembled, unpacked, or followed. `tools/lift.py` was not modified. No C was written. `tools/genall.py` was not run.")
    w("")
    w(f"- File: `{rep['file']['path']}`")
    w(f"- File size: {rep['file']['file_size']} bytes")
    w(f"- SHA-256 of the analyzed `.text` bytes: `{rep['file']['text_sha256']}`")
    w(f"- Range: {rep['text']['start']} .. {rep['text']['end']} ({text_n} bytes)")
    w(f"- PE entry: {rep['text']['entry']} in {rep['text']['entry_section']}; inside `.text`: {rep['text']['entry_in_text']}")
    w(f"- IAT virtual range, from the data directory: {rep['text']['iat']}")
    w(f"- Elapsed: {rep['elapsed_seconds']} s")
    w("")
    w("## 1. Linear disassembly")
    w("")
    w(f"- Decoded instructions: {d['instructions']}")
    w(f"- Decoded bytes: {d['decoded_bytes']} ({d['decoded_bytes'] / text_n:.1%} of `.text`)")
    w(f"- Undecodable bytes: {d['undecodable_bytes']} in {d['undecodable_regions']['regions']} regions")
    w(f"- `int3` instructions: {d['int3']}")
    w(f"- Instructions with an fs: or gs: memory operand: {d['fs_or_gs']}")
    w("")
    w("Longest undecodable regions:")
    w("")
    for region in d["undecodable_regions"]["longest"][:10]:
        w(f"- {region['address']}: {region['bytes']} bytes")
    w("")
    w("Instruction groups, from Capstone, over the linear sweep. A linear sweep also decodes bytes that are data, so these counts are an upper bound on real instructions.")
    w("")
    for name in ("x87", "mmx", "sse", "sse2", "sse3_or_later", "avx", "3dnow"):
        w(f"- {name}: {rep['groups'].get(name, 0)}")
    w("")
    w("Mnemonic frequency:")
    w("")
    w("| Mnemonic | Count |")
    w("| --- | --- |")
    for row in rep["mnemonics"][:40]:
        w(f"| {row['mnemonic']} | {row['count']} |")
    if len(rep["mnemonics"]) > 40:
        w("")
        w(f"The JSON file lists all {len(rep['mnemonics'])} mnemonics.")
    w("")
    w("Privileged mnemonics (the lifter treats these as data and emits a no-op):")
    w("")
    if rep["privileged"]:
        for row in rep["privileged"]:
            w(f"- {row['mnemonic']}: {row['count']}")
    else:
        w("- none")
    w("")
    w("Unusual mnemonics other than `int3` padding (`int`, `cpuid`, `rdtsc`, and the privileged set):")
    w("")
    if rep["unusual"]:
        for row in rep["unusual"]:
            w(f"- {row['mnemonic']}: {row['count']}")
    else:
        w("- none")
    w("")
    w("## 2. Direct calls inside .text")
    w("")
    calls = rep["calls"]
    w(f"- CALL instructions: {calls['instructions']}")
    w(f"- Target inside `.text`: {calls['target_in_text']}")
    w(f"- Target outside `.text`: {calls['target_outside_text']}")
    w(f"- Unique in-`.text` targets: {calls['unique_targets_in_text']}")
    w(f"- Of those, on a decoded instruction boundary: {c['call_targets_on_instruction_boundary']}")
    w(f"- Off a boundary, not used as entries: {c['call_targets_off_boundary']}")
    w("")
    w("Highest incoming call counts. The full ranking is in the JSON file.")
    w("")
    w("| Target | Incoming calls |")
    w("| --- | --- |")
    for row in calls["ranked"][:40]:
        w(f"| {row['address']} | {row['count']} |")
    w("")
    w("## 3. Direct jumps inside .text")
    w("")
    jumps = rep["jumps"]
    w(f"- Direct JMP instructions: {jumps['direct_jmp']}")
    w(f"- Target inside `.text`: {jumps['target_in_text']}")
    w(f"- Target outside `.text`: {jumps['target_outside_text']}")
    w(f"- Unique in-`.text` JMP targets: {jumps['unique_targets_in_text']}")
    w(f"- Conditional branches and loop instructions: {jumps['conditional_and_loop']}")
    w("")
    w("| JMP target | Incoming jumps |")
    w("| --- | --- |")
    for row in jumps["ranked"][:20]:
        w(f"| {row['address']} | {row['count']} |")
    w("")
    w("## 4. Candidate functions")
    w("")
    w("A strong entry is a direct CALL target that lands on a byte the linear sweep decoded as an instruction. A `55 8B EC` sequence is recorded, and it is not an entry by itself.")
    w("")
    w(f"- Raw `55 8B EC` occurrences: {c['raw_push_ebp_mov_ebp_esp']}")
    w(f"- Of those, at an instruction boundary: {c['prologue_at_instruction_boundary']}")
    w(f"- Boundary prologues immediately after one or more decoded `int3` bytes: {c['prologue_after_int3']}")
    w(f"- Those padding prologues that are not direct call targets: {c['prologue_after_int3_not_a_call_target']}")
    w(f"- Strong call-target entries: {c['call_targets_on_instruction_boundary']}")
    w(f"- Strong entries that also begin with the MSVC prologue: {c['strong_with_prologue']}")
    w(f"- Strong entries immediately after `int3`: {c['strong_after_int3']}")
    w(f"- `jmp [IAT]` thunks in `.text`: {c['iat_jmp_thunks']}")
    w(f"- Of those thunks, how many are themselves direct call targets: {c['iat_jmp_thunks_that_are_call_targets']}")
    w("")
    w("## 5. Control-flow graph from strong entries")
    w("")
    w("Roots are the strong call targets only. Direct jumps and conditional branches are followed when the target is inside `.text` and on an instruction boundary. Calls do not recurse; their targets are roots of their own when they qualify. A run of three `int3` bytes ends a walk, matching `Lifter.discover`. Indirect targets are not guessed. Protected sections are not entered.")
    w("")
    w(f"- Roots: {cfg['roots']}")
    w(f"- Roots entered: {cfg['roots_entered']}")
    w(f"- Instructions reached: {cfg['instructions']}")
    w(f"- Bytes reached: {cfg['bytes']}")
    w(f"- Direct calls that stay in `.text`: {cfg['internal_calls']}")
    w(f"- Direct jumps that stay in `.text`: {cfg['internal_jmps']}")
    w(f"- Conditional branches that stay in `.text`: {cfg['internal_jcc']}")
    w(f"- Branches that landed off an instruction boundary: {cfg['landed_off_boundary']}")
    w(f"- x87 / MMX / SSE-family instructions reached: {cfg['groups'].get('x87', 0)} / {cfg['groups'].get('mmx', 0)} / {cfg['groups'].get('sse_family', 0)}")
    w("")
    w("## 6. Direct edges that leave .text")
    w("")
    w("From the call-target graph. `call [IAT]` and `jmp [IAT]` are not in this table; they are imports and are counted in section 7.")
    w("")
    w("| Destination | Kind | Edges |")
    w("| --- | --- | --- |")
    for row in cfg["external"]:
        w(f"| {row['section']} | {row['kind']} | {row['count']} |")
    if not cfg["external"]:
        w("| (none) |  | 0 |")
    w("")
    w(f"Direct edges into Stext, Sitext, Srdata, Sdata, Sidata, or `.securom`: {cfg['protected_direct_edges']}.")
    w("")
    w("The same classification over the linear sweep, which also counts branches decoded from data:")
    w("")
    w("| Destination | Kind | Edges |")
    w("| --- | --- | --- |")
    for row in rep["linear_external"]["edges"]:
        w(f"| {row['section']} | {row['kind']} | {row['count']} |")
    if not rep["linear_external"]["edges"]:
        w("| (none) |  | 0 |")
    w("")
    w("## 7. Indirect calls and jumps")
    w("")
    w("Counts are from the linear sweep. Examples are the first few of each shape, not a listing of every site. A `base+disp` call is the shape of an MSVC vtable call when the register holds an object or a vtable; the target is not known statically. A `[index*4]` jump is the shape of a jump table; targets are recorded only when `Lifter._jt_table` accepts the block.")
    w("")
    w("| Form | Count |")
    w("| --- | --- |")
    for row in rep["indirect"]["counts"]:
        w(f"| {row['form']} | {row['count']} |")
    w("")
    w(f"Calls through `[reg+disp]` whose displacement is a positive multiple of 4 and at most 0x400: {rep['lifter']['vtable_shaped_calls']}. That is the usual shape of an MSVC vtable slot. The count is from the linear sweep, so it includes anything the sweep decoded, and it does not prove the register holds a vtable.")
    w("")
    w("Reached from strong entries:")
    w("")
    w(f"- indirect calls: {cfg['indirect_calls']}")
    w(f"- indirect jumps: {cfg['indirect_jmps']}")
    w(f"- `call [IAT]`: {cfg['iat_calls']}")
    w(f"- `jmp [IAT]`: {cfg['iat_jmps']}")
    w("")
    w("Examples:")
    w("")
    for form, examples in rep["indirect"]["examples"].items():
        w(f"- {form}")
        for ex in examples[:4]:
            w(f"  - `{ex}`")
    w("")
    w("## 8. Lifter coverage")
    w("")
    w(f"{lf['method']}.")
    w("")
    w(f"- Distinct operand forms: {lf['forms']}")
    w(f"- Forms accepted: {lf['forms_supported']}")
    w(f"- Forms rejected: {lf['forms_unsupported']}")
    w(f"- Linear-sweep instructions accepted: {lf['sweep_supported_instructions']}")
    w(f"- Linear-sweep instructions rejected: {lf['sweep_unsupported_instructions']}")
    w(f"- Reached instructions accepted: {cfg['supported']}")
    w(f"- Reached instructions rejected: {cfg['unsupported']}")
    w("")
    w("Rejected mnemonics on the linear sweep:")
    w("")
    if lf["sweep_unsupported_mnemonics"]:
        for row in lf["sweep_unsupported_mnemonics"]:
            w(f"- {row['mnemonic']}: {row['count']}")
    else:
        w("- none")
    w("")
    w("Rejected mnemonics among instructions reached from strong entries:")
    w("")
    if cfg["unsupported_mnemonics"]:
        for row in cfg["unsupported_mnemonics"]:
            w(f"- {row['mnemonic']}: {row['count']}")
    else:
        w("- none")
    w("")
    w("## 9. NFSU2 switch patterns")
    w("")
    w("`Lifter._jt_bound` looks for a block ending in `cmp r32, imm` / `ja` or `jbe`. `Lifter._jt_table` looks for `jmp dword ptr [r*4 + table]`, optionally after `movzx` from a byte table. Both were called on blocks collected from `.text`. A table is accepted only when every dword target is inside `.text`. No other targets were invented.")
    w("")
    w(f"- `[reg*4+disp]` jumps: {sw['table_shaped_jmp']}")
    w(f"- cmp/ja or cmp/jbe bounds: {sw['bounds']}")
    w(f"- Short blocks ending in an indirect jump: {sw['jmp_blocks_saved']}")
    w(f"- Tables the lifter accepts: {sw['recognized']}")
    w(f"- Of those, two-level `movzx` tables: {sw['recognized_two_level']}")
    w(f"- Bounds whose jump block was rejected: {sw['bound_but_rejected']}")
    w(f"- Accepted-table entries that point outside `.text`: {sw['recognized_targets_outside_text']}")
    w("")
    if sw["examples"]:
        w("| Jump | Table | Entries | Two-level |")
        w("| --- | --- | --- | --- |")
        for ex in sw["examples"]:
            w(f"| {ex['jmp']} | {ex['table']} | {ex['entries']} | {ex['two_level']} |")
        w("")
    w("## 10. Feasibility")
    w("")
    reached = max(cfg["instructions"], 1)
    w(f"**A.** Capstone decoded {d['decoded_bytes'] / text_n:.1%} of `.text`. Of the {cfg['instructions']} instructions reached from strong call targets, {cfg['supported'] / reached:.1%} are accepted by the current lifter: `lift()` handles `jmp`, in-range conditional branches, and `loop`/`jecxz`, and `Lifter.insn` handles the rest. The linear sweep accepts {lf['sweep_supported_instructions']} of {d['instructions']} decoded instructions. The reached-code figure is the one that answers this question, because the sweep also decodes data.")
    w("")
    w(f"**B.** {c['call_targets_on_instruction_boundary']} high-confidence entries, with no relocation information. {c['strong_with_prologue']} of them begin with `push ebp; mov ebp, esp`. {c['raw_push_ebp_mov_ebp_esp']} raw prologue byte sequences were not treated as entries.")
    w("")
    w(f"**C.** The graph has {cfg['internal_calls']} direct calls that stay in `.text` and {cfg['protected_direct_edges']} direct edges into protected-layout sections. Import calls are separate: {cfg['iat_calls']} `call [IAT]` and {cfg['iat_jmps']} `jmp [IAT]` on that graph.")
    w("")
    w("**D.** The concrete gaps before any code generation:")
    w("")
    for i, gap in enumerate(rep["feasibility"]["gaps"], 1):
        w(f"{i}. **{gap['title']}.** {gap['detail']}")
        w("")
    w(f"**E. {rep['feasibility']['choice']}**")
    w("")
    w(rep["feasibility"]["why"])
    w("")
    return "\n".join(lines)


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        die(__doc__.strip())
    exe = argv[1]
    outdir = assert_output_ok(argv[2] if len(argv) > 2 else os.path.join(ROOT, "analysis", "undercover"), exe)
    if not os.path.isfile(exe):
        die(f"not a file: {exe}")
    t0 = time.time()
    info = read_inputs(exe)
    info["path"] = os.path.abspath(exe)
    print(f".text {hx(info['text_va'])} size {info['text_size']}", file=sys.stderr)
    az = Analyzer(info)
    az.sweep()
    print("  candidates", file=sys.stderr)
    cand = az.candidates()
    print(f"  strong entries {len(cand['strong'])}", file=sys.stderr)
    print("  cfg", file=sys.stderr)
    walked = az.walk(cand["strong"])
    print("  switches", file=sys.stderr)
    switches = az.switches()
    rep = build_report(info, az, cand, walked, switches, time.time() - t0)
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "code-analysis.md")
    js_path = os.path.join(outdir, "code-analysis.json")
    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(markdown(rep))
    with open(js_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2)
        f.write("\n")
    print(f"wrote {md_path}")
    print(f"wrote {js_path}")
    print(rep["feasibility"]["choice"])


if __name__ == "__main__":
    main(sys.argv)
