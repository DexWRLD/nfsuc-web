"""Optional angr static-analysis oracle for Undercover.

UC analyzer/lifter remains authoritative for recompilation. angr is an
independent oracle: compare its output; never silently replace UC metadata.

Does not execute nfs.exe, unpack/decrypt protected sections, or symbolically
execute protected startup. Requires the optional ``angr`` package.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
ANGR_DIR = os.path.join(ANALYSIS, "angr")
GAME_DEFAULT = r"C:\Games\Need For Speed Undercover\nfs.exe"

# Protected PE section VA ranges (absolute), from nfs-pe.json.
PROTECTED_RANGES = (
    (25907200, 33319968),   # Stext
    (33320960, 33347856),   # Sitext
    (33349632, 33787556),   # Srdata
    (33787904, 36427512),   # Sdata
    (36429824, 36451256),   # Sidata
    (36454400, 38420694),   # .securom
)

ORDINARY_TEXT = (0x00401000, 0x00401000 + 7730171)
IMAGE_BASE = 0x00400000
IMAGE_END = 0x024A8000  # size_of_image end approx

DEVICE = 0x013C6510
RENDERER = 0x017AA798

PRIORITY_FUNCS = [
    0x00752AF0,  # Present path
    0x00725200,  # publication / Clear
    0x0072E340,  # factory caller
    0x00766730,  # Phase 16
    0x0072DD00,  # Phase 16
    0x007B2AC0,  # DrawPrimitive strong
    0x007B36A0,
    0x007A1400,
    0x007B2930,
    0x007B17C0,
    0x007A06E0,  # renderer publisher
    0x007B5020,  # renderer publisher
    0x0071E630,  # device field store
    0x007297D0,  # publisher caller
]

NON_FUNCTION_CONTROLS = [0x00686000, 0x0055FF30]

ANGR_VERSION_PIN = "10.0.5"


def hx(n: int) -> str:
    return "0x%08X" % (n & 0xFFFFFFFF)


def is_protected_address(addr: int) -> bool:
    a = addr & 0xFFFFFFFF
    for lo, hi in PROTECTED_RANGES:
        if lo <= a < hi:
            return True
    return False


def is_external_address(addr: int, text_lo: int = None, text_hi: int = None) -> bool:
    a = addr & 0xFFFFFFFF
    if is_protected_address(a):
        return False  # protected is a sharper class
    lo = text_lo if text_lo is not None else ORDINARY_TEXT[0]
    hi = text_hi if text_hi is not None else ORDINARY_TEXT[1]
    if lo <= a < hi:
        return False
    if IMAGE_BASE <= a < IMAGE_END:
        return False  # ordinary data / rdata still in-image
    return True


def classify_edge_target(addr: int) -> str | None:
    a = addr & 0xFFFFFFFF
    if is_protected_address(a):
        return "PROTECTED_BOUNDARY"
    if is_external_address(a):
        return "EXTERNAL_BOUNDARY"
    return None


def angr_available() -> tuple[bool, str | None]:
    try:
        import angr  # noqa: F401

        return True, getattr(sys.modules["angr"], "__version__", "unknown")
    except Exception as exc:  # pragma: no cover - env dependent
        return False, str(exc)


def normalize_addr(value) -> int:
    if isinstance(value, int):
        return value & 0xFFFFFFFF
    text = str(value).strip().lower()
    if text.startswith("0x"):
        return int(text, 16) & 0xFFFFFFFF
    return int(text, 0) & 0xFFFFFFFF


def consensus(uc, angr_val, agree_if_equal=True) -> dict:
    """Build a UC/ANGR/CONSENSUS triple without mutating UC authority."""
    out = {"UC_ANALYZER": uc, "ANGR": angr_val}
    if angr_val in (None, "NOT_RUN", "UNAVAILABLE"):
        out["CONSENSUS"] = "UC_ONLY"
        out["confidence"] = "UC_ONLY"
        return out
    if uc == angr_val and agree_if_equal:
        out["CONSENSUS"] = uc
        out["confidence"] = "AGREE_STRONG" if uc not in ("UNKNOWN", None) else "INCONCLUSIVE"
        return out
    if uc is not None and angr_val is not None and uc != angr_val:
        out["CONSENSUS"] = "DISAGREE"
        out["confidence"] = "DISAGREE"
        return out
    out["CONSENSUS"] = "INCONCLUSIVE"
    out["confidence"] = "INCONCLUSIVE"
    return out


class AngrOracle:
    """Lazy per-function shellcode windows over ordinary .text."""

    def __init__(self, game_path: str):
        ok, ver = angr_available()
        if not ok:
            raise RuntimeError("angr not available: %s" % ver)
        import angr

        self.angr = angr
        self.version = ver
        self.game_path = game_path
        import uc_code_analyze as uca

        info = uca.read_inputs(game_path)
        self.blob = info["bytes"]
        self.text_va = info["text_va"]
        self.text_end = self.text_va + len(self.blob)
        self._cache: dict[int, dict] = {}
        self._uc_map = None

    def _load_uc_map(self):
        if self._uc_map is None:
            path = os.path.join(ANALYSIS, "function-map.json")
            data = json.load(open(path, encoding="utf-8"))
            self._uc_map = {int(r["va"], 16): r for r in data["functions"]}
            self._uc_vas = sorted(self._uc_map)
        return self._uc_map

    def window_for(self, addr: int, pad: int = 0x800) -> tuple[bytes, int, int]:
        """Return (bytes, load_addr, end_addr) for a local CFG window."""
        addr &= 0xFFFFFFFF
        if is_protected_address(addr):
            raise ValueError("PROTECTED_BOUNDARY %s" % hx(addr))
        if not (self.text_va <= addr < self.text_end):
            raise ValueError("outside ordinary .text %s" % hx(addr))
        self._load_uc_map()
        # Next UC function start bounds the window when available.
        import bisect

        i = bisect.bisect_right(self._uc_vas, addr)
        next_va = self._uc_vas[i] if i < len(self._uc_vas) else self.text_end
        # Prefer UC insn estimate * 15, else pad, capped.
        row = self._uc_map.get(addr) or {}
        insns = row.get("insns") or 0
        estimate = max(insns * 16, pad)
        end = min(addr + estimate + pad, next_va + 0x40, self.text_end, addr + 0x4000)
        if end <= addr:
            end = min(addr + pad, self.text_end)
        off = addr - self.text_va
        return self.blob[off : end - self.text_va], addr, end

    def analyze_function(self, addr: int, decompile: bool = False) -> dict:
        addr = normalize_addr(addr)
        key = addr
        if key in self._cache and (not decompile or self._cache[key].get("pseudocode") is not None):
            return self._cache[key]

        edge = classify_edge_target(addr)
        if edge == "PROTECTED_BOUNDARY":
            rec = {
                "address": hx(addr),
                "status": "PROTECTED_BOUNDARY",
                "angr_function": False,
            }
            self._cache[key] = rec
            return rec

        logging.disable(logging.CRITICAL)
        try:
            win, load_addr, end = self.window_for(addr)
            # Byte-scan for known absolute immediates (DEVICE/RENDERER) independent of CFG.
            imm_hits = []
            for target, name in ((DEVICE, "DEVICE"), (RENDERER, "RENDERER")):
                needle = target.to_bytes(4, "little")
                start = 0
                while True:
                    j = win.find(needle, start)
                    if j < 0:
                        break
                    imm_hits.append({"abs": hx(target), "name": name, "at": hx(load_addr + j)})
                    start = j + 1
            proj = self.angr.load_shellcode(win, arch="x86", load_address=load_addr)
            cfg = proj.analyses.CFGFast(
                force_complete_scan=False,
                function_starts=[addr],
                start_at_entry=False,
                resolve_indirect_jumps=False,
                symbols=False,
                normalize=True,
            )
            fn = proj.kb.functions.get(addr)
            rec = {
                "address": hx(addr),
                "status": "OK" if fn else "ANGR_MISSING",
                "angr_function": bool(fn),
                "window": {"start": hx(load_addr), "end": hx(end), "bytes": end - load_addr},
                "size": int(fn.size) if fn else None,
                "block_count": len(list(fn.blocks)) if fn else 0,
                "returning": bool(getattr(fn, "returning", None)) if fn else None,
                "callees": [],
                "jump_targets": [],
                "global_refs": [],
                "immediate_hits": imm_hits,
                "boundary_hits": [],
                "decompiler_available": False,
                "pseudocode": None,
                "pseudocode_sha": None,
            }
            if fn:
                for caddr in sorted(fn.get_call_sites() or []):
                    try:
                        target = fn.get_call_target(caddr)
                    except Exception:
                        target = None
                    if target is None:
                        rec["callees"].append({"site": hx(caddr), "target": None, "kind": "indirect_or_unknown"})
                        continue
                    t = int(target) & 0xFFFFFFFF
                    kind = classify_edge_target(t)
                    if kind:
                        rec["boundary_hits"].append({"site": hx(caddr), "target": hx(t), "class": kind})
                        # Do not follow protected/external edges.
                        continue
                    rec["callees"].append({"site": hx(caddr), "target": hx(t), "kind": "direct"})
                # Absolute memory immediates in blocks (globals).
                for block in fn.blocks:
                    try:
                        for insn in block.capstone.insns:
                            for op in insn.operands:
                                if op.type == 3:  # mem — capstone x86
                                    disp = getattr(op.mem, "disp", 0) & 0xFFFFFFFF
                                    if disp >= 0x01000000:
                                        rec["global_refs"].append(
                                            {"va": hx(insn.address), "abs": hx(disp), "text": insn.op_str}
                                        )
                                if op.type == 2:  # imm
                                    imm = int(op.imm) & 0xFFFFFFFF
                                    if imm in (DEVICE, RENDERER) or imm >= 0x01000000:
                                        rec["global_refs"].append(
                                            {"va": hx(insn.address), "abs": hx(imm), "text": insn.op_str}
                                        )
                    except Exception:
                        continue
                # Dedupe global refs
                seen = set()
                uniq = []
                for g in rec["global_refs"]:
                    k = (g["va"], g["abs"])
                    if k in seen:
                        continue
                    seen.add(k)
                    uniq.append(g)
                rec["global_refs"] = uniq[:80]

                if decompile:
                    try:
                        dec = proj.analyses.Decompiler(fn, cfg=cfg)
                        text = dec.codegen.text if dec and dec.codegen else None
                        rec["decompiler_available"] = bool(text)
                        if text:
                            # Keep a short excerpt only — never giant dumps in metadata.
                            excerpt = text.strip()
                            if len(excerpt) > 4000:
                                excerpt = excerpt[:4000] + "\n/* …truncated… */\n"
                            rec["pseudocode"] = excerpt
                            import hashlib

                            rec["pseudocode_sha"] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
                    except Exception as exc:
                        rec["decompiler_available"] = False
                        rec["decompiler_error"] = str(exc)[:200]
            self._cache[key] = rec
            return rec
        finally:
            logging.disable(logging.NOTSET)

    def natural_opinion(self, addr: int) -> dict:
        """Opinion on a VA without forcing it into the function DB."""
        addr = normalize_addr(addr)
        if is_protected_address(addr):
            return {"address": hx(addr), "natural": "PROTECTED_BOUNDARY", "forced": False}
        if not (self.text_va <= addr < self.text_end):
            return {"address": hx(addr), "natural": "OUTSIDE_ORDINARY_TEXT", "forced": False}
        # Peek: is there an existing UC label?
        self._load_uc_map()
        row = self._uc_map.get(addr)
        # Tiny probe CFG — do not follow first call if protected.
        try:
            rec = self.analyze_function(addr, decompile=False)
            natural = "FUNCTION_LIKE" if rec.get("angr_function") else "NO_FUNCTION"
            # If first callee is protected, record and stop.
            for hit in rec.get("boundary_hits") or []:
                if hit.get("class") == "PROTECTED_BOUNDARY":
                    natural = "FUNCTION_LIKE_WITH_PROTECTED_CALLEE"
                    break
            return {
                "address": hx(addr),
                "natural": natural,
                "forced": False,
                "uc_label": (row or {}).get("label"),
                "angr": {k: rec.get(k) for k in ("status", "size", "block_count", "boundary_hits")},
            }
        except ValueError as exc:
            return {"address": hx(addr), "natural": str(exc), "forced": False}

    def compare_to_uc(self, addr: int) -> dict:
        addr = normalize_addr(addr)
        self._load_uc_map()
        uc = self._uc_map.get(addr)
        angr_rec = None
        try:
            angr_rec = self.analyze_function(addr, decompile=False)
        except ValueError as exc:
            return {
                "address": hx(addr),
                "class": "BOUNDARY_DISAGREEMENT" if "PROTECTED" in str(exc) else "UNKNOWN",
                "UC_ANALYZER": {"present": bool(uc), "label": (uc or {}).get("label")},
                "ANGR": {"error": str(exc)},
            }
        if not uc:
            return {
                "address": hx(addr),
                "class": "UNKNOWN" if not angr_rec.get("angr_function") else "ANGR_ONLY",
                "UC_ANALYZER": {"present": False},
                "ANGR": angr_rec,
            }
        if uc.get("label") == "HIGH_CONFIDENCE" and not angr_rec.get("angr_function"):
            cls = "ANGR_MISSING"
        elif uc.get("label") != "HIGH_CONFIDENCE" and angr_rec.get("angr_function"):
            cls = "CFG_DISAGREEMENT"
        else:
            # Size: UC uses insn count; angr uses byte size — soft compare via blocks.
            uc_insns = uc.get("insns") or 0
            angr_blocks = angr_rec.get("block_count") or 0
            if angr_rec.get("angr_function") and uc.get("label") == "HIGH_CONFIDENCE":
                if angr_blocks == 0 and uc_insns > 0:
                    cls = "CFG_DISAGREEMENT"
                else:
                    cls = "AGREE"
            else:
                cls = "UNKNOWN"
        return {
            "address": hx(addr),
            "class": cls,
            "UC_ANALYZER": {
                "present": True,
                "label": uc.get("label"),
                "insns": uc.get("insns"),
                "reachable": uc.get("reachable"),
            },
            "ANGR": {
                "function": angr_rec.get("angr_function"),
                "size": angr_rec.get("size"),
                "block_count": angr_rec.get("block_count"),
                "status": angr_rec.get("status"),
            },
        }

    def scan_globals_in_fn(self, addr: int, targets: list[int]) -> dict:
        rec = self.analyze_function(addr, decompile=False)
        found = []
        want = {t & 0xFFFFFFFF for t in targets}
        for g in rec.get("global_refs") or []:
            if normalize_addr(g["abs"]) in want:
                found.append(g)
        return {"address": hx(addr), "hits": found, "function": rec.get("angr_function")}


def ensure_dir():
    os.makedirs(ANGR_DIR, exist_ok=True)


def cmd_function(oracle: AngrOracle, addr: int):
    print(json.dumps(oracle.analyze_function(addr, False), indent=2))


def cmd_decompile(oracle: AngrOracle, addr: int):
    rec = oracle.analyze_function(addr, True)
    print(json.dumps({k: rec[k] for k in rec if k != "pseudocode"}, indent=2))
    if rec.get("pseudocode"):
        print("\n/* pseudocode excerpt */\n")
        print(rec["pseudocode"])


def cmd_compare(oracle: AngrOracle, addr: int):
    print(json.dumps(oracle.compare_to_uc(addr), indent=2))


def cmd_xrefs(addr: int, game: str):
    """Xrefs via UC immediate scanner (angr shellcode windows lack full-image xrefs)."""
    import uc_code_analyze as uca
    import uc_phase15_graphics as g15

    info = uca.read_inputs(game)
    refs = g15.refs_of(info["bytes"], info["text_va"], normalize_addr(addr))
    out = [{"kind": k, "eip": hx(e), "text": t, "conf": c} for k, e, t, c in refs]
    print(json.dumps({"address": hx(normalize_addr(addr)), "source": "UC_ANALYZER", "refs": out[:200], "count": len(out)}, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Optional angr oracle (UC remains authoritative)")
    ap.add_argument("command", choices=["function", "decompile", "xrefs", "compare", "status", "controls"])
    ap.add_argument("address", nargs="?", help="VA like 0x007B2AC0")
    ap.add_argument("--game", default=GAME_DEFAULT)
    args = ap.parse_args(argv)

    if args.command == "status":
        ok, ver = angr_available()
        print(json.dumps({
            "angr_available": ok,
            "angr_version": ver,
            "pinned": ANGR_VERSION_PIN,
            "python": sys.version.split()[0],
            "optional": True,
        }, indent=2))
        return 0

    if args.command == "xrefs":
        if not args.address:
            ap.error("address required")
        cmd_xrefs(args.address, args.game)
        return 0

    ok, ver = angr_available()
    if not ok:
        print(json.dumps({"error": "angr unavailable", "detail": ver}), file=sys.stderr)
        return 2

    oracle = AngrOracle(args.game)
    if args.command == "controls":
        out = {"angr_version": oracle.version, "functions": {}, "non_functions": {}}
        for a in PRIORITY_FUNCS[:6]:
            out["functions"][hx(a)] = oracle.compare_to_uc(a)
        for a in NON_FUNCTION_CONTROLS:
            out["non_functions"][hx(a)] = oracle.natural_opinion(a)
        print(json.dumps(out, indent=2))
        return 0

    if not args.address:
        ap.error("address required")
    addr = normalize_addr(args.address)
    if args.command == "function":
        cmd_function(oracle, addr)
    elif args.command == "decompile":
        cmd_decompile(oracle, addr)
    elif args.command == "compare":
        cmd_compare(oracle, addr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
