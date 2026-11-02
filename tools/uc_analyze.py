#!/usr/bin/env python3
"""Read-only PE report for a Need for Speed Undercover nfs.exe.

Compares the file with the assumptions of the NFSU2 static recompiler
(tools/lift.py, tools/reloc2.py, tools/genall.py, tools/argcount.py,
runtime/heap.c, runtime/mem.c, runtime/win32.c).

The game directory is only read. Nothing is unpacked, relocated, emulated,
or written next to the executable.

  tools/uc_analyze.py <nfs.exe> [outdir]

Default outdir is analysis/undercover inside this repository.
Writes nfs-pe.md and nfs-pe.json.
"""
import collections, datetime, hashlib, json, math, os, re, struct, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# What the existing pipeline hard-codes. Addresses are guest VAs.
IMAGE_BASE = 0x00400000
IMAGE_END = 0x00932000          # runtime/heap.c, win/roam_asi/roam_asi.c EXE_END
GUEST_END = 0x28000000          # runtime/cpu.h
GUEST_REGIONS = [
    (0x00400000, 0x00932000, "NFSU2 image window (runtime/heap.c)"),
    (0x00A00000, 0x00A58000, "server.dll (docs/web/DESIGN.md)"),
    (0x01000000, 0x05000000, "module heaps"),
    (0x05000000, 0x05FF0000, "main stack"),
    (0x06000000, 0x08000000, "thread stacks, up to the heap"),
    (0x08000000, 0x28000000, "guest heap"),
]
GUEST_POINTS = [
    (0x00BE0000, "Winsock hostent buffers"),
    (0x00C00000, "thread environment blocks"),
]
# win32_call pops this many arguments for every import (runtime/win32.c).
# MSVCR80 / MSVCP80 are the dynamic CRT; their exports are not that stdcall set.
CDECL_RUNTIME = {"msvcr80.dll", "msvcp80.dll"}
MARKERS = [
    b"Microsoft Visual C++", b"Runtime Error", b"R6002",
    b"__security_cookie", b"_except_handler4", b"_CxxThrowException",
    b"d3dx9_34", b"ON2.COM", b"This program cannot be run in DOS mode",
]
FILE_CHARS = [
    (0x0001, "RELOCS_STRIPPED"), (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"), (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0020, "LARGE_ADDRESS_AWARE"), (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"), (0x1000, "SYSTEM"), (0x2000, "DLL"),
]
SUBSYSTEMS = {2: "WINDOWS_GUI", 3: "WINDOWS_CUI"}
DIR_NAMES = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED",
]
SCN_EXECUTE, SCN_READ, SCN_WRITE = 0x20000000, 0x40000000, 0x80000000


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


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
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def entropy(blob):
    if not blob:
        return 0.0
    n = len(blob)
    return -sum((v / n) * math.log2(v / n) for v in collections.Counter(blob).values())


def flags(value, table):
    return [name for bit, name in table if value & bit]


def perm(ch):
    return ("R" if ch & SCN_READ else "-") + ("W" if ch & SCN_WRITE else "-") + ("X" if ch & SCN_EXECUTE else "-")


def hexu(n):
    return f"0x{n:08X}"


def known_imports():
    src = open(os.path.join(ROOT, "tools", "argcount.py"), encoding="utf-8").read()
    body = src.split("KNOWN={", 1)[1].split("\nhit=", 1)[0]
    return set(re.findall(r"'([^']+)'\s*:", body))


def parse(data):
    if data[:2] != b"MZ":
        die("not an MZ executable")
    e = u32(data, 0x3C)
    if data[e:e + 4] != b"PE\0\0":
        die("no PE signature")
    machine, nsec, timestamp, _, _, optsz, chars = struct.unpack_from("<HHIIIHH", data, e + 4)
    opt = e + 24
    magic = u16(data, opt)
    if magic != 0x10B:
        die(f"expected PE32 (0x10B), found magic {magic:#x}")
    pe = {
        "machine": machine,
        "sections_n": nsec,
        "timestamp": timestamp,
        "characteristics": chars,
        "linker": (data[opt + 2], data[opt + 3]),
        "entry_rva": u32(data, opt + 16),
        "image_base": u32(data, opt + 28),
        "section_align": u32(data, opt + 32),
        "file_align": u32(data, opt + 36),
        "os_version": (u16(data, opt + 40), u16(data, opt + 42)),
        "image_version": (u16(data, opt + 44), u16(data, opt + 46)),
        "subsystem_version": (u16(data, opt + 48), u16(data, opt + 50)),
        "size_of_image": u32(data, opt + 56),
        "size_of_headers": u32(data, opt + 60),
        "checksum": u32(data, opt + 64),
        "subsystem": u16(data, opt + 68),
        "dll_characteristics": u16(data, opt + 70),
        "stack_reserve": u32(data, opt + 72),
        "stack_commit": u32(data, opt + 76),
        "heap_reserve": u32(data, opt + 80),
        "heap_commit": u32(data, opt + 84),
        "num_dirs": u32(data, opt + 92),
    }
    pe["dirs"] = []
    for i in range(min(pe["num_dirs"], 16)):
        rva, size = struct.unpack_from("<II", data, opt + 96 + i * 8)
        pe["dirs"].append({"name": DIR_NAMES[i], "rva": rva, "size": size})
    sections = []
    sec_off = opt + optsz
    for i in range(nsec):
        raw = data[sec_off + i * 40:sec_off + (i + 1) * 40]
        name = raw[:8].split(b"\0", 1)[0].decode("latin1")
        vsz, va, rsz, rawptr = struct.unpack_from("<IIII", raw, 8)
        ch = u32(raw, 36)
        blob = data[rawptr:rawptr + rsz] if rawptr + rsz <= len(data) else b""
        sections.append({
            "name": name or "<none>",
            "va": va, "vsize": vsz, "raw_ptr": rawptr, "raw_size": rsz,
            "characteristics": ch, "data": blob,
        })
    pe["sections"] = sections
    return pe


def section_of(pe, rva):
    for s in pe["sections"]:
        span = max(s["vsize"], s["raw_size"])
        if s["va"] <= rva < s["va"] + span:
            return s
    return None


def rva_bytes(pe, rva, n):
    s = section_of(pe, rva)
    if not s:
        return None
    off = rva - s["va"]
    if off < 0 or off + n > len(s["data"]):
        return None
    return s["data"][off:off + n]


def cstring(pe, rva, limit=260):
    s = section_of(pe, rva)
    if not s:
        return None
    off = rva - s["va"]
    if off < 0 or off >= len(s["data"]):
        return None
    raw = s["data"][off:off + limit]
    end = raw.find(b"\0")
    raw = raw if end < 0 else raw[:end]
    if not raw or any(b < 32 or b > 126 for b in raw):
        return None
    return raw.decode("ascii")


def imports_of(pe):
    imp = next((d for d in pe["dirs"] if d["name"] == "IMPORT"), None)
    if not imp or not imp["rva"]:
        return []
    out = []
    rva = imp["rva"]
    for _ in range(64):
        desc = rva_bytes(pe, rva, 20)
        if not desc:
            break
        oft, _, _, name_rva, ft = struct.unpack("<IIIII", desc)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        dll = cstring(pe, name_rva) or "<unreadable>"
        thunk_rva = oft or ft
        fns = []
        for j in range(8192):
            ent = rva_bytes(pe, thunk_rva + j * 4, 4)
            if not ent:
                break
            val = struct.unpack("<I", ent)[0]
            if val == 0:
                break
            if val & 0x80000000:
                fns.append(f"#{val & 0xFFFF}")
            else:
                nm = cstring(pe, (val & 0x7FFFFFFF) + 2)
                fns.append(nm or "<unreadable>")
        out.append({"dll": dll, "functions": fns, "iat_rva": ft, "oft_rva": oft})
        rva += 20
    return out


def tls_of(pe):
    d = next((x for x in pe["dirs"] if x["name"] == "TLS"), None)
    if not d or not d["rva"]:
        return None
    raw = rva_bytes(pe, d["rva"], 24)
    if not raw:
        return {"present": True, "readable": False, "rva": d["rva"], "size": d["size"]}
    start, end, index, callbacks, zerofill, ch = struct.unpack("<IIIIII", raw)
    return {
        "present": True, "readable": True, "rva": d["rva"], "size": d["size"],
        "start": start, "end": end, "index": index, "callbacks": callbacks,
        "zerofill": zerofill, "characteristics": ch,
        "section": (section_of(pe, d["rva"]) or {}).get("name"),
    }


def debug_of(pe):
    d = next((x for x in pe["dirs"] if x["name"] == "DEBUG"), None)
    if not d or not d["rva"]:
        return None
    raw = rva_bytes(pe, d["rva"], 28)
    if not raw:
        return {"present": True, "readable": False}
    _, _, _, _, typ, size, addr, ptr = struct.unpack("<IIHHIIII", raw)
    info = {"present": True, "readable": True, "type": typ, "size": size,
            "address": addr, "pointer": ptr,
            "section": (section_of(pe, d["rva"]) or {}).get("name")}
    if typ == 2 and 0 < ptr < len(pe["_file"]) and size >= 24:
        blob = pe["_file"][ptr:ptr + min(size, 512)]
        if blob[:4] == b"RSDS" and len(blob) >= 24:
            info["format"] = "RSDS"
            info["age"] = struct.unpack_from("<I", blob, 20)[0]
            path = blob[24:].split(b"\0", 1)[0]
            if path and all(32 <= b < 127 or b in (92, 58) for b in path):
                info["pdb"] = path.decode("ascii")
    return info


def version_of(pe):
    rsrc = next((s for s in pe["sections"] if s["name"] == ".rsrc"), None)
    if not rsrc:
        return None
    blob = rsrc["data"]
    i = blob.find(b"\xBD\x04\xEF\xFE")
    out = {}
    if i >= 0 and i + 52 <= len(blob):
        sig, struc, fms, fls, pms, pls = struct.unpack_from("<IIIIII", blob, i)
        if sig == 0xFEEF04BD:
            out["file_version"] = f"{fms >> 16}.{fms & 0xFFFF}.{fls >> 16}.{fls & 0xFFFF}"
            out["product_version"] = f"{pms >> 16}.{pms & 0xFFFF}.{pls >> 16}.{pls & 0xFFFF}"
    # English UTF-16 version strings live in this small resource section.
    for key in (b"F\0i\0l\0e\0V\0e\0r\0s\0i\0o\0n\0", b"P\0r\0o\0d\0u\0c\0t\0V\0e\0r\0s\0i\0o\0n\0",
                b"P\0r\0o\0d\0u\0c\0t\0N\0a\0m\0e\0", b"O\0r\0i\0g\0i\0n\0a\0l\0F\0i\0l\0e\0n\0a\0m\0e\0",
                b"F\0i\0l\0e\0D\0e\0s\0c\0r\0i\0p\0t\0i\0o\0n\0", b"C\0o\0m\0p\0a\0n\0y\0N\0a\0m\0e\0"):
        at = blob.find(key)
        if at < 0:
            continue
        window = blob[at + len(key):at + len(key) + 400]
        # skip alignment padding up to the next UTF-16 text
        vals = re.findall(b"(?:[\x20-\x7e]\x00){2,120}", window)
        if vals:
            text = vals[0].decode("utf-16le")
            label = key.decode("utf-16le")
            if label not in ("FileVersion", "ProductVersion") or "file_version" not in out:
                out[label] = text
            else:
                out[label] = text
    return out or None


def markers_of(pe):
    found = []
    for s in pe["sections"]:
        hits = []
        for needle in MARKERS:
            n = s["data"].count(needle)
            if n:
                hits.append({"text": needle.decode("ascii"), "count": n})
        if hits:
            found.append({"section": s["name"], "hits": hits})
    return found


def pefile_view(path):
    """Same facts tools/lift.py and tools/reloc2.py read through pefile."""
    try:
        import pefile
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
    ])
    names = []
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode("latin1").strip() or "<none>"
        names.append(nm)
    text = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"), None)
    base = pe.OPTIONAL_HEADER.ImageBase
    entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    tlo = thi = None
    if text is not None:
        tlo = base + text.VirtualAddress
        thi = tlo + text.Misc_VirtualSize
    return {
        "available": True,
        "image_base": base,
        "entry": entry,
        "section_names": names,
        "text": None if tlo is None else {"lo": tlo, "hi": thi},
        "entry_in_text": bool(text is not None and tlo <= entry < thi),
        "unnamed": [n for n in names if n == "<none>"],
        "has_basereloc": hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"),
        "machine": pe.FILE_HEADER.Machine,
        "magic": pe.OPTIONAL_HEADER.Magic,
    }


def build(path):
    with open(path, "rb") as f:
        data = f.read()
    pe = parse(data)
    pe["_file"] = data
    sha = hashlib.sha256(data).hexdigest()
    base = pe["image_base"]
    entry = base + pe["entry_rva"]
    entry_sec = section_of(pe, pe["entry_rva"])
    sections = []
    code_ranges = []
    for s in pe["sections"]:
        ent = entropy(s["data"])
        pro = s["data"].count(b"\x55\x8B\xEC")
        cc = s["data"].count(b"\xCC\xCC\xCC\xCC")
        seh = s["data"].count(b"\x64\xA1\x00\x00\x00\x00")
        execute = bool(s["characteristics"] & SCN_EXECUTE)
        row = {
            "name": s["name"],
            "va": base + s["va"],
            "vsize": s["vsize"],
            "end": base + s["va"] + s["vsize"],
            "raw_ptr": s["raw_ptr"],
            "raw_size": s["raw_size"],
            "permissions": perm(s["characteristics"]),
            "characteristics": s["characteristics"],
            "entropy": round(ent, 2),
            "msvc_frames": pro,
            "int3_padding": cc,
            "seh_fs0_reads": seh,
        }
        sections.append(row)
        if execute:
            if ent >= 7.95 and pro == 0:
                kind = "executable bytes are not clear x86 (entropy at the ceiling, no MSVC frames)"
            elif pro >= 100:
                kind = "clear enough to contain MSVC frame prologues"
            else:
                kind = "executable, with few or no MSVC frame prologues"
            code_ranges.append({
                "name": s["name"], "start": row["va"], "end": row["end"],
                "permissions": row["permissions"], "entropy": row["entropy"],
                "msvc_frames": pro, "kind": kind,
            })
    imps = imports_of(pe)
    known = known_imports()
    for dll in imps:
        dll["missing_from_known"] = [fn for fn in dll["functions"] if fn not in known]
        dll["in_known"] = [fn for fn in dll["functions"] if fn in known]
    text = next(s for s in sections if s["name"] == ".text")
    image_lo, image_hi = base, base + pe["size_of_image"]
    overlaps = []
    for lo, hi, label in GUEST_REGIONS:
        a, b = max(lo, image_lo), min(hi, image_hi)
        if a < b:
            overlaps.append({"region": label, "guest": [lo, hi], "overlap": [a, b]})
    covered_points = [{"address": addr, "what": label} for addr, label in GUEST_POINTS if image_lo <= addr < image_hi]
    reloc = next(d for d in pe["dirs"] if d["name"] == "BASERELOC")
    unnamed = [s["name"] for s in sections if s["name"] == "<none>"]
    tls = tls_of(pe)
    dbg = debug_of(pe)
    ver = version_of(pe)
    rich = data.find(b"Rich", 0x40, u32(data, 0x3C))
    dos_stub = b"This program cannot be run in DOS mode" in data[:u32(data, 0x3C) + 64]
    pipe = pefile_view(path)
    missing = [fn for dll in imps for fn in dll["missing_from_known"]]
    cdecl = [dll["dll"] for dll in imps if dll["dll"].lower() in CDECL_RUNTIME]
    return {
        "file": {"path": os.path.abspath(path), "size": len(data), "sha256": sha},
        "architecture": {
            "machine": pe["machine"], "machine_name": "IMAGE_FILE_MACHINE_I386" if pe["machine"] == 0x14C else hex(pe["machine"]),
            "format": "PE32", "magic": "0x10B",
            "characteristics": flags(pe["characteristics"], FILE_CHARS),
            "dll_characteristics": pe["dll_characteristics"],
            "subsystem": SUBSYSTEMS.get(pe["subsystem"], str(pe["subsystem"])),
            "subsystem_id": pe["subsystem"],
            "linker": f"{pe['linker'][0]}.{pe['linker'][1]}",
            "os_version": f"{pe['os_version'][0]}.{pe['os_version'][1]}",
            "image_version": f"{pe['image_version'][0]}.{pe['image_version'][1]}",
            "subsystem_version": f"{pe['subsystem_version'][0]}.{pe['subsystem_version'][1]}",
            "timestamp": pe["timestamp"],
            "timestamp_utc": datetime.datetime.fromtimestamp(pe["timestamp"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "section_align": pe["section_align"], "file_align": pe["file_align"],
            "checksum": pe["checksum"], "size_of_headers": pe["size_of_headers"],
        },
        "image_base": base,
        "entry_point": {"rva": pe["entry_rva"], "va": entry, "section": entry_sec["name"] if entry_sec else None},
        "size_of_image": pe["size_of_image"],
        "image_end": image_hi,
        "stack": {"reserve": pe["stack_reserve"], "commit": pe["stack_commit"]},
        "heap": {"reserve": pe["heap_reserve"], "commit": pe["heap_commit"]},
        "directories": [d for d in pe["dirs"] if d["rva"] or d["size"]],
        "sections": sections,
        "executable_ranges": code_ranges,
        "imports": imps,
        "relocations": {
            "directory_rva": reloc["rva"], "directory_size": reloc["size"],
            "relocs_stripped": bool(pe["characteristics"] & 0x0001),
            "unnamed_sections": unnamed,
            "types": [],
        },
        "tls": tls,
        "debug": dbg,
        "version": ver,
        "rich_header": rich >= 0,
        "standard_dos_stub": dos_stub,
        "markers": markers_of(pe),
        "pipeline": pipe,
        "text_section": {"start": text["va"], "end": text["end"], "entry_inside": text["va"] <= entry < text["end"]},
        "overlaps": overlaps,
        "covered_points": covered_points,
        "known_import_names": len(known),
        "imports_missing_from_known": missing,
        "cdecl_runtime_dlls": cdecl,
    }


def incompatibilities(rep):
    items = []
    text = rep["text_section"]
    ep = rep["entry_point"]
    if not text["entry_inside"]:
        items.append((
            "blocker",
            "Entry point is outside .text",
            f"tools/lift.py keeps only the section named .text ({hexu(text['start'])}..{hexu(text['end'])}). "
            f"The entry point {hexu(ep['va'])} is in {ep['section']}. tools/genall.py seeds discovery at that "
            f"address and then stops, because the walk leaves .text immediately.",
        ))
    rel = rep["relocations"]
    if rel["relocs_stripped"] or (rel["directory_rva"] == 0 and rel["directory_size"] == 0):
        items.append((
            "blocker",
            "No base relocations",
            "IMAGE_FILE_RELOCS_STRIPPED is set and the base-relocation directory is empty. "
            "tools/reloc2.py reads an unnamed section, and this file has "
            f"{len(rel['unnamed_sections'])} unnamed sections, so it cannot write out/relocs.txt. "
            "tools/genall.py discovers functions from those fixup slots. With none, the only seed is the entry point.",
        ))
    extra = [r for r in rep["executable_ranges"] if r["name"] != ".text"]
    if extra:
        names = ", ".join(f"{r['name']} {r['permissions']} {hexu(r['start'])}..{hexu(r['end'])}" for r in extra)
        items.append((
            "blocker",
            "More than one executable section",
            "The lifter never reads these executable ranges: " + names + ". "
            "Stext and Sdata have entropy 8.00 and no MSVC frame prologues, so their bytes are not an x86 image "
            "the lifter can translate. A section is named .securom. This report does not unpack or emulate it.",
        ))
    if rep["overlaps"] or rep["covered_points"]:
        lines = "; ".join(
            f"{o['region']} overlaps {hexu(o['overlap'][0])}..{hexu(o['overlap'][1])}" for o in rep["overlaps"]
        )
        points = ", ".join(f"{hexu(p['address'])} ({p['what']})" for p in rep["covered_points"])
        items.append((
            "blocker",
            "Image does not fit the guest map",
            f"Image base {hexu(rep['image_base'])} matches SPEED2.EXE, but the image runs "
            f"{hexu(rep['image_base'])}..{hexu(rep['image_end'])} ({rep['size_of_image'] / 1048576:.1f} MB). "
            f"The runtime treats {hexu(IMAGE_BASE)}..{hexu(IMAGE_END)} as the image and places other regions "
            f"on top of the rest. {lines}. Also inside the image: {points}. "
            f"The image ends at {hexu(rep['image_end'])}, before the main stack at 0x05000000, "
            "the thread stacks, and the guest heap at 0x08000000.",
        ))
    if rep["cdecl_runtime_dlls"]:
        items.append((
            "gap",
            "Dynamic Visual C++ 2005 runtime",
            "The import table binds " + ", ".join(rep["cdecl_runtime_dlls"]) + ". "
            "SPEED2.EXE links its CRT into the exe. runtime/win32.c pops nargs for every import "
            "(`c->esp += 4 * nargs`, the stdcall convention). A cdecl CRT call cleans the stack in the caller, "
            "so a non-zero nargs here would pop twice. tools/argcount.py's KNOWN table has no CRT exports.",
        ))
    nmiss = len(rep["imports_missing_from_known"])
    if nmiss:
        dlls = [d["dll"] for d in rep["imports"] if d["missing_from_known"] and not d["in_known"]]
        items.append((
            "gap",
            "Import set is not the SPEED2 set",
            f"{nmiss} imported functions are absent from tools/argcount.py KNOWN "
            f"({rep['known_import_names']} names). DLLs with no name in that table: {', '.join(dlls)}. "
            "gen.sh runs argcount.py with STRICT=1 for a second module and exits on an unknown name.",
        ))
    if rep["tls"] and rep["tls"].get("present"):
        cb = rep["tls"].get("callbacks")
        extra = ""
        if cb is not None and cb < rep["image_base"]:
            extra = f" AddressOfCallBacks is {hexu(cb)}, below the image base, so it is not a VA inside this image."
        items.append((
            "gap",
            "TLS directory is not loaded",
            "A TLS directory is present. runtime/mem.c mem_load_pe copies sections and does not walk TLS callbacks."
            + extra,
        ))
    commit = rep["stack"]["commit"]
    if commit > 1024 * 1024:
        items.append((
            "gap",
            "Stack commit is larger than a browser worker stack",
            f"The optional header asks for {commit // 1024} KB of stack commit and "
            f"{rep['stack']['reserve'] // 1024} KB reserved. docs/web/DESIGN.md records that a Chrome worker "
            "stack is about 1 MB and cannot be raised.",
        ))
    if rep["architecture"]["subsystem_id"] != 2:
        items.append((
            "note",
            "Subsystem is not WINDOWS_GUI",
            f"Subsystem is {rep['architecture']['subsystem']} ({rep['architecture']['subsystem_id']}).",
        ))
    if not rep["rich_header"]:
        items.append((
            "note",
            "No Rich header and no standard DOS stub",
            "The MSVC linker product stamp is absent, and the DOS stub is not the usual "
            "\"This program cannot be run in DOS mode\" stub. Compiler identity comes from the import DLLs, "
            "the frame prologues in .text, and the debug path instead.",
        ))
    return [{"severity": s, "title": t, "detail": d} for s, t, d in items]


def markdown(rep, issues):
    a = rep["architecture"]
    lines = []
    w = lines.append
    w("# Need for Speed Undercover — nfs.exe PE report")
    w("")
    w("Read-only structural report. The game directory was not modified. Protected sections were not unpacked or emulated. The NFSU2 lifter, reloc parser, and runtime were not changed and were not run on this file.")
    w("")
    w(f"- File: `{rep['file']['path']}`")
    w(f"- Size: {rep['file']['size']} bytes")
    w(f"- SHA-256: `{rep['file']['sha256']}`")
    w("")
    w("## PE architecture")
    w("")
    w(f"- Machine: {a['machine_name']} ({a['machine']:#06x})")
    w(f"- Format: {a['format']} (optional-header magic {a['magic']})")
    w(f"- File characteristics: {', '.join(a['characteristics']) or 'none'}")
    w(f"- DllCharacteristics: {a['dll_characteristics']:#x}")
    w(f"- Subsystem: {a['subsystem']} ({a['subsystem_id']})")
    w(f"- Linker version: {a['linker']}")
    w(f"- OS / image / subsystem versions: {a['os_version']} / {a['image_version']} / {a['subsystem_version']}")
    w(f"- TimeDateStamp: {a['timestamp']:#x} ({a['timestamp_utc']} UTC)")
    w(f"- Alignment: section {a['section_align']:#x}, file {a['file_align']:#x}")
    w(f"- SizeOfHeaders: {a['size_of_headers']:#x}")
    w(f"- CheckSum: {a['checksum']:#x}")
    w(f"- Stack reserve / commit: {rep['stack']['reserve']:#x} / {rep['stack']['commit']:#x}")
    w(f"- Heap reserve / commit: {rep['heap']['reserve']:#x} / {rep['heap']['commit']:#x}")
    w("")
    w("## Image base")
    w("")
    w(f"- ImageBase: {hexu(rep['image_base'])}")
    w(f"- SizeOfImage: {hexu(rep['size_of_image'])} ({rep['size_of_image']} bytes)")
    w(f"- Mapped span at the preferred base: {hexu(rep['image_base'])} .. {hexu(rep['image_end'])}")
    w("")
    w("## Entry point")
    w("")
    ep = rep["entry_point"]
    w(f"- AddressOfEntryPoint: {hexu(ep['rva'])}")
    w(f"- Virtual address: {hexu(ep['va'])}")
    w(f"- Section: {ep['section']}")
    w(f"- Inside the lifter's .text range: {rep['text_section']['entry_inside']}")
    w("")
    w("## Sections and permissions")
    w("")
    w("| Section | VA | Virtual size | End | Raw size | Perm | Entropy | MSVC frames | int3 pads |")
    w("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for s in rep["sections"]:
        w(f"| {s['name']} | {hexu(s['va'])} | {hexu(s['vsize'])} | {hexu(s['end'])} | {s['raw_size']} | {s['permissions']} | {s['entropy']:.2f} | {s['msvc_frames']} | {s['int3_padding']} |")
    w("")
    w("Permissions are read, write, execute from the section characteristics. MSVC frames are the byte sequence `55 8B EC` (`push ebp; mov ebp, esp`). int3 pads are runs of four `CC` bytes. Both counts are over the section's raw bytes.")
    w("")
    w("Data directories that are present:")
    w("")
    for d in rep["directories"]:
        w(f"- {d['name']}: RVA {hexu(d['rva'])}, size {hexu(d['size'])}")
    w("")
    w("## Imported DLLs")
    w("")
    for dll in rep["imports"]:
        w(f"- {dll['dll']}: {len(dll['functions'])} functions, IAT RVA {hexu(dll['iat_rva'])}")
    w("")
    w(f"Total: {sum(len(d['functions']) for d in rep['imports'])} functions from {len(rep['imports'])} DLLs.")
    w("")
    w("## Imported functions")
    w("")
    for dll in rep["imports"]:
        w(f"### {dll['dll']}")
        w("")
        for fn in dll["functions"]:
            mark = "" if fn in dll["in_known"] else " — not in tools/argcount.py KNOWN"
            w(f"- {fn}{mark}")
        w("")
    w("## Relocation information")
    w("")
    rel = rep["relocations"]
    w(f"- Base relocation directory: RVA {hexu(rel['directory_rva'])}, size {hexu(rel['directory_size'])}")
    w(f"- IMAGE_FILE_RELOCS_STRIPPED: {rel['relocs_stripped']}")
    w(f"- Unnamed sections (the input tools/reloc2.py parses): {len(rel['unnamed_sections'])}")
    w("- Relocation types present: none")
    w("- HIGHLOW fixup slots: 0")
    w("")
    w("tools/prepare_module.py refuses a module with no base-relocation directory, and it only accepts relocation types ABSOLUTE (0) and HIGHLOW (3). This file has neither a directory nor an unnamed reloc section.")
    w("")
    w("## Executable code ranges")
    w("")
    for r in rep["executable_ranges"]:
        w(f"- {r['name']} {r['permissions']} {hexu(r['start'])} .. {hexu(r['end'])} ({r['end'] - r['start']} bytes), entropy {r['entropy']:.2f}, MSVC frames {r['msvc_frames']}. {r['kind']}.")
    w("")
    w(f"The lifter's code range is .text only: {hexu(rep['text_section']['start'])} .. {hexu(rep['text_section']['end'])}.")
    w("")
    w("## Compiler and runtime patterns")
    w("")
    w(f"- Linker version field: {a['linker']}.")
    w(f"- Rich header present: {rep['rich_header']}. Standard MSVC DOS stub present: {rep['standard_dos_stub']}.")
    if rep["version"]:
        for k, v in rep["version"].items():
            w(f"- Version resource {k}: {v}")
    if rep["debug"] and rep["debug"].get("pdb"):
        w(f"- CodeView PDB path: `{rep['debug']['pdb']}` (age {rep['debug'].get('age')}, directory in section {rep['debug'].get('section')})")
    elif rep["debug"]:
        w(f"- Debug directory present, type {rep['debug'].get('type')}, section {rep['debug'].get('section')}.")
    w("- Dynamic CRT: MSVCR80.dll and MSVCP80.dll are Visual C++ 2005 (VC8). The C++ imports are decorated names.")
    n_cxx = sum(1 for d in rep["imports"] for fn in d["functions"] if fn.startswith("?"))
    w(f"- Decorated C++ import names: {n_cxx}.")
    text = next(s for s in rep["sections"] if s["name"] == ".text")
    w(f"- .text holds {text['msvc_frames']} MSVC frame prologues, {text['int3_padding']} int3 padding runs, and {text['seh_fs0_reads']} `mov eax, fs:[0]` SEH reads.")
    if rep["tls"]:
        t = rep["tls"]
        if t.get("readable"):
            w(f"- TLS directory in {t['section']}: raw data {hexu(t['start'])}..{hexu(t['end'])}, index {hexu(t['index'])}, callbacks {hexu(t['callbacks'])}, zerofill {t['zerofill']}.")
        else:
            w("- TLS directory is present and its body was not readable.")
    load = next((d for d in rep["directories"] if d["name"] == "LOAD_CONFIG"), None)
    w(f"- Load-config directory: {'absent' if not load else hexu(load['rva'])}.")
    w("- Marker strings, counted per section and not quoted beyond the marker itself:")
    for block in rep["markers"]:
        hits = ", ".join(f"{h['text']} x{h['count']}" for h in block["hits"])
        w(f"  - {block['section']}: {hits}")
    pipe = rep["pipeline"]
    w("")
    w("## What the existing pipeline would see")
    w("")
    if not pipe.get("available"):
        w(f"- pefile cross-check unavailable: {pipe.get('error')}")
    else:
        w(f"- pefile machine {pipe['machine']:#x}, magic {pipe['magic']:#x}, image base {hexu(pipe['image_base'])}.")
        w(f"- Section names: {', '.join(pipe['section_names'])}.")
        if pipe["text"]:
            w(f"- Lifter .text selection: {hexu(pipe['text']['lo'])} .. {hexu(pipe['text']['hi'])}.")
        w(f"- Entry in that range: {pipe['entry_in_text']}.")
        w(f"- Unnamed section for tools/reloc2.py: {pipe['unnamed'] or 'none'}.")
        w(f"- DIRECTORY_ENTRY_BASERELOC: {pipe['has_basereloc']}.")
    w("")
    w("## Incompatibilities with the NFSU2 static recompiler")
    w("")
    for i, item in enumerate(issues, 1):
        w(f"### {i}. {item['title']}")
        w("")
        w(f"Severity: {item['severity']}.")
        w("")
        w(item["detail"])
        w("")
    w("## What still matches")
    w("")
    w(f"- PE32, Intel 386. The lifter is Capstone `CS_ARCH_X86` / `CS_MODE_32`.")
    w(f"- Preferred image base {hexu(rep['image_base'])}, the same base the runtime maps SPEED2.EXE at.")
    w(f"- A section named .text exists, so Lifter.__init__ can select it.")
    w(f"- .text contains MSVC frame prologues and int3 padding, which is the compiler family tools/lift.py's switch patterns were written for.")
    w("- Direct3DCreate9, DirectInput8Create, and DirectSoundCreate are imports the current HLE already names.")
    w("")
    w("No generated C was produced. tools/genall.py was not run.")
    w("")
    return "\n".join(lines)


def public_json(rep, issues):
    out = dict(rep)
    out["incompatibilities"] = issues
    # Drop nothing structural; imports stay. The raw section bytes were never stored.
    return out


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        die(__doc__.strip())
    exe = argv[1]
    outdir = assert_output_ok(argv[2] if len(argv) > 2 else os.path.join(ROOT, "analysis", "undercover"), exe)
    if not os.path.isfile(exe):
        die(f"not a file: {exe}")
    rep = build(exe)
    issues = incompatibilities(rep)
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "nfs-pe.md")
    js_path = os.path.join(outdir, "nfs-pe.json")
    text = markdown(rep, issues)
    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    with open(js_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(public_json(rep, issues), f, indent=2)
        f.write("\n")
    print(f"wrote {md_path}")
    print(f"wrote {js_path}")
    print(f"imports {sum(len(d['functions']) for d in rep['imports'])} from {len(rep['imports'])} DLLs")
    print(f"incompatibilities {len(issues)}")


if __name__ == "__main__":
    main(sys.argv)
