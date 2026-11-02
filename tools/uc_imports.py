#!/usr/bin/env python3
"""Name Undercover import thunks that .text reaches through .rdata.

Reads nfs.exe and analysis/undercover/nfs-pe.json. Does not read Stext,
Sitext, Srdata, Sdata, Sidata, or .securom. Does not implement the runtime.

A thunk is a direct callee whose first instruction is `jmp dword ptr [slot]`
with `slot` in `.rdata`. The on-disk dword at that slot is the unbound
import entry: either an ordinal (`0x80000000 | n`) or the RVA of an
IMAGE_IMPORT_BY_NAME (a 16-bit hint followed by the symbol). The DLL comes
from the import directory already recorded in nfs-pe.json.

  tools/uc_imports.py <nfs.exe>
"""
import collections, json, os, struct, sys

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import uc_code_analyze as uca

# Undecorated exports from these DLLs use the DLL's default convention.
# A decoration on the symbol overrides the default. Ordinals stay unknown.
CDECL_DLLS = {"msvcr80.dll", "msvcp80.dll"}
STDCALL_DLLS = {
    "kernel32.dll", "user32.dll", "advapi32.dll", "gdi32.dll", "shell32.dll",
    "ole32.dll", "oleaut32.dll", "shlwapi.dll", "setupapi.dll", "version.dll",
    "wintrust.dll", "crypt32.dll", "imagehlp.dll", "ws2_32.dll", "wsock32.dll",
}
# Documented cdecl exports from otherwise stdcall Win32 DLLs.
CDECL_NAMES = {"wsprintfa", "wsprintfw"}
# These two entry points are stdcall. Other DirectX exports are left unknown
# unless their decoration says otherwise.
STDCALL_NAMES = {
    ("d3d9.dll", "direct3dcreate9"),
    ("dinput8.dll", "directinput8create"),
}


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


def hx(n):
    return f"0x{n & 0xffffffff:08X}"


def convention(dll, name):
    """Return cdecl, stdcall, thiscall, fastcall, or unknown. Do not guess."""
    if not name or name.startswith("#"):
        return "unknown"
    low = name.lower()
    if "@@qae" in low or "@@uae" in low or "@@qbe" in low:
        return "thiscall"
    if "@@ya" in low:
        return "cdecl"
    if "@@yg" in low or "@@sg" in low:
        return "stdcall"
    if len(name) > 2 and name[0] == "@" and "@" in name[1:]:
        tail = name.rsplit("@", 1)[-1]
        if tail.isdigit():
            return "fastcall"
    if len(name) > 2 and name[0] == "_" and "@" in name:
        tail = name.rsplit("@", 1)[-1]
        if tail.isdigit():
            return "stdcall"
    if name.startswith("?"):
        return "unknown"
    dll_low = (dll or "").lower()
    if low in CDECL_NAMES:
        return "cdecl"
    if (dll_low, low) in STDCALL_NAMES:
        return "stdcall"
    if dll_low in CDECL_DLLS:
        return "cdecl"
    if dll_low in STDCALL_DLLS:
        return "stdcall"
    return "unknown"


def load_imports(path):
    doc = json.load(open(path, encoding="utf-8"))
    by_name = collections.defaultdict(list)
    by_ordinal = collections.defaultdict(list)
    for entry in doc["imports"]:
        dll = entry["dll"]
        for name in entry["functions"]:
            if name.startswith("#") and name[1:].isdigit():
                by_ordinal[int(name[1:])].append(dll)
            else:
                by_name[name].append(dll)
    return doc["image_base"], by_name, by_ordinal


def resolve_slot(value, image_base, rdata_bytes, rdata_va, by_name, by_ordinal):
    if value & 0x80000000:
        ordinal = value & 0xFFFF
        dlls = sorted(set(by_ordinal.get(ordinal, ())))
        return "#" + str(ordinal), dlls
    va = (image_base + value) & 0xffffffff
    off = va - rdata_va
    if not 0 <= off < len(rdata_bytes) - 3:
        return None, []
    raw = rdata_bytes[off + 2:off + 258]
    end = raw.find(b"\x00")
    if end <= 0 or end > 200:
        return None, []
    try:
        name = raw[:end].decode("ascii")
    except UnicodeDecodeError:
        return None, []
    if not name or any(ord(ch) < 32 or ord(ch) > 126 for ch in name):
        return None, []
    return name, sorted(set(by_name.get(name, ())))


def scan(blob, base, rdata_va, rdata_end):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    thunks = {}
    calls = collections.Counter()
    tails = collections.Counter()
    off = 0
    n = len(blob)
    while off < n:
        insns = list(md.disasm(blob[off:off + 65536], base + off))
        if not insns:
            off += 1
            continue
        for insn in insns:
            if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                continue
            if insn.mnemonic not in ("call", "jmp"):
                continue
            target = insn.operands[0].imm & 0xffffffff
            rel = target - base
            if not 0 <= rel < n - 6 or blob[rel:rel + 2] != b"\xff\x25":
                continue
            slot = struct.unpack_from("<I", blob, rel + 2)[0]
            if not rdata_va <= slot < rdata_end:
                continue
            thunks[target] = slot
            if insn.mnemonic == "call":
                calls[target] += 1
            else:
                tails[target] += 1
        off = insns[-1].address + insns[-1].size - base
    return thunks, calls, tails


def main(argv):
    if len(argv) < 2:
        die("usage: uc_imports.py <nfs.exe>")
    exe = argv[1]
    info = uca.read_inputs(exe)
    out_dir = uca.assert_output_ok(os.path.join(ROOT, "analysis", "undercover"), exe)
    image_base, by_name, by_ordinal = load_imports(os.path.join(out_dir, "nfs-pe.json"))
    rdata = next(section for section in info["sections"] if section["name"] == ".rdata")
    blob_file = open(exe, "rb")
    blob_file.seek(rdata["raw_ptr"])
    rdata_bytes = blob_file.read(rdata["raw_size"])
    blob_file.close()
    print("  scanning .text for .rdata thunks", file=sys.stderr)
    thunks, calls, tails = scan(info["bytes"], info["text_va"], rdata["va"], rdata["va"] + len(rdata_bytes))
    rows = []
    unresolved = 0
    for thunk, slot in sorted(thunks.items()):
        off = slot - rdata["va"]
        value = struct.unpack_from("<I", rdata_bytes, off)[0]
        name, dlls = resolve_slot(value, image_base, rdata_bytes, rdata["va"], by_name, by_ordinal)
        if not name:
            unresolved += 1
            continue
        if len(dlls) == 1:
            dll = dlls[0]
        elif not dlls:
            dll = ""
        else:
            dll = ""
        conv = convention(dll, name) if len(dlls) == 1 else "unknown"
        rows.append({
            "thunk": thunk,
            "slot": slot,
            "dll": dll if len(dlls) == 1 else (" / ".join(dlls) if dlls else ""),
            "dlls": dlls,
            "symbol": name,
            "calls": calls[thunk],
            "tails": tails[thunk],
            "convention": conv,
        })
    by_conv = collections.Counter(row["convention"] for row in rows)
    by_dll = collections.Counter((row["dll"] or "(no unique DLL)") for row in rows)
    lines = [
        "# Undercover import thunks",
        "",
        "`.text` calls a small stub, and the stub is `jmp dword ptr [slot]` with `slot` in `.rdata`. "
        "The PE import address table in the data directory sits in `.securom` and was not read. "
        "The slot's on-disk dword is the unbound import entry already stored in `.rdata`: "
        "an ordinal with the high bit set, or the RVA of a hint followed by the symbol name.",
        "",
        "The DLL is the one `nfs-pe.json` lists for that symbol. "
        "A symbol listed for more than one DLL stays unresolved rather than being assigned. "
        "This file does not implement the Win32 or CRT runtime.",
        "",
        "## Calling convention",
        "",
        "The convention comes from the symbol and the DLL, not from a guess about the call site.",
        "",
        "- `@@QAE`, `@@UAE`, and `@@QBE` are thiscall. `@@YA` is cdecl. `@@YG` and `@@SG` are stdcall.",
        "- A C++ name with some other mangling stays unknown.",
        "- `_name@N` is stdcall. `@name@N` is fastcall.",
        "- An undecorated MSVCR80 or MSVCP80 export is cdecl.",
        "- An undecorated KERNEL32, USER32, GDI32, ADVAPI32, SHELL32, OLE32, OLEAUT32, SHLWAPI, SETUPAPI, VERSION, WINTRUST, CRYPT32, imagehlp, WS2_32, or WSOCK32 export is stdcall.",
        "- `wsprintfA` and `wsprintfW` are cdecl even though they live in USER32.",
        "- `Direct3DCreate9` and `DirectInput8Create` are stdcall. Other DirectX names stay unknown.",
        "- An ordinal (`#N`) stays unknown. The number alone does not say how the callee pops arguments.",
        "",
        "## Counts",
        "",
        f"- Thunks whose slot is in `.rdata`: {len(thunks)}",
        f"- Resolved to a symbol: {len(rows)}",
        f"- Slots that are not an import entry: {unresolved}",
        f"- Direct calls to resolved thunks: {sum(row['calls'] for row in rows)}",
        f"- Direct tail jumps to resolved thunks: {sum(row['tails'] for row in rows)}",
        "",
        "Call and tail counts are from a linear sweep, so a CALL decoded out of embedded data can add to them.",
        "",
        "### By convention",
        "",
    ]
    for name, count in sorted(by_conv.items()):
        lines.append(f"- {name}: {count}")
    lines += ["", "### By DLL", ""]
    for name, count in by_dll.most_common():
        lines.append(f"- {name}: {count}")
    lines += [
        "",
        "## Thunks",
        "",
        "| Thunk | Slot | DLL | Symbol | Calls | Tail jmps | Convention |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {hx(row['thunk'])} | {hx(row['slot'])} | {row['dll']} | `{row['symbol']}` | "
            f"{row['calls']} | {row['tails']} | {row['convention']} |"
        )
    lines.append("")
    path = os.path.join(out_dir, "import-thunks.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print(f"  resolved {len(rows)} unresolved {unresolved}", file=sys.stderr)
    print(f"  wrote {path}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv)
