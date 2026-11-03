#!/usr/bin/env python3
"""Read-only inventory of Undercover startup-related install files (Phase 51)."""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
INSTALL = r"C:\Games\Need For Speed Undercover"

CANDIDATES = [
    "dialoglogo128x128.jpg",
    r"FRONTEND\LOGOTEXTURES.BUN",
    r"FRONTEND\BOOTFLOWTEXTURES.BUN",
    r"FRONTEND\FRONTB1.BUN",
    r"FRONTEND\FrontB1.lzc",
    r"MOVIES\ea_bumper_english_ntsc.vp6",
    r"MOVIES\attract_english_ntsc.vp6",
    r"UI\splashscreen.big",
    r"UI\bootloadingscreen.big",
    r"UI\psascreen.big",
    r"UI\bootload.big",
]

MAGICS = [
    b"DDS ", b"DXT1", b"DXT3", b"DXT5", b"JDLZ", b"LZ2K", b"\x89PNG",
    b"\xff\xd8\xff", b"RIFF", b"VP60", b"VP61", b"VP6\x00", b"BIND",
    b"BIGF", b"BIG4", b"BIGH", b"EBX\x00",
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def head_bytes(path: str, n: int = 64) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def scan_magics(path: str, limit: int = 512 * 1024) -> list[dict]:
    with open(path, "rb") as fh:
        chunk = fh.read(limit)
    found = []
    for m in MAGICS:
        i = chunk.find(m)
        if i >= 0:
            found.append({"magic": m.decode("latin1", "replace"), "offset": i})
    return found


def jpeg_info(path: str) -> dict | None:
    data = open(path, "rb").read(64)
    if not data.startswith(b"\xff\xd8\xff"):
        return None
    # parse SOF0 for dimensions (bounded)
    blob = open(path, "rb").read()
    i = 2
    w = h = None
    while i + 9 < len(blob):
        if blob[i] != 0xFF:
            break
        marker = blob[i + 1]
        if marker in (0xD8, 0xD9):
            i += 2
            continue
        seglen = struct.unpack(">H", blob[i + 2:i + 4])[0]
        if marker in (0xC0, 0xC1, 0xC2):
            h, w = struct.unpack(">HH", blob[i + 5:i + 9])
            break
        i += 2 + seglen
    return {
        "format": "JPEG",
        "width": w,
        "height": h,
        "independently_decodable": True,
        "browser_native": True,
    }


def bun_header_guess(path: str) -> dict:
    head = head_bytes(path, 64)
    u32 = list(struct.unpack_from("<16I", head)) if len(head) >= 64 else []
    return {
        "u32_le_prefix": [f"0x{x:08X}" for x in u32[:8]],
        "ascii_prefix": "".join(chr(b) if 32 <= b < 127 else "." for b in head[:32]),
        "known_bun_parser": False,
        "note": "No verified Undercover BUN→texture membership parser; format unsupported for authentic decode.",
    }


def main() -> int:
    if not os.path.isdir(INSTALL):
        print(json.dumps({"install": INSTALL, "accessible": False}))
        return 1
    entries = []
    for rel in CANDIDATES:
        path = os.path.join(INSTALL, rel)
        if not os.path.isfile(path):
            entries.append({"relative_path": rel.replace("\\", "/"), "present": False})
            continue
        size = os.path.getsize(path)
        head = head_bytes(path)
        row = {
            "relative_path": rel.replace("\\", "/"),
            "present": True,
            "size": size,
            "sha256": sha256_file(path),
            "head_hex": head[:16].hex(),
            "head_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in head[:16]),
            "magics_in_first_512kib": scan_magics(path),
        }
        if rel.lower().endswith(".jpg") or rel.lower().endswith(".jpeg"):
            row["format_metadata"] = jpeg_info(path)
            row["resource_identity"] = "install-root dialoglogo128x128.jpg"
            row["startup_screen_link"] = (
                "Present in install tree. Not proven to be LS_EALOGO.FNG or a "
                "LOGOTEXTURES.BUN member. Suitable as independently decodable "
                "original ship asset for dialog/GDF branding preview only if labeled as such."
            )
        elif rel.upper().endswith(".BUN") or rel.lower().endswith(".lzc"):
            row["format_metadata"] = bun_header_guess(path)
            row["startup_screen_link"] = (
                "Named in executable string table as frontend bundle lead. "
                "Internal EA logo membership NOT verified."
            )
        elif rel.lower().endswith(".vp6"):
            row["format_metadata"] = {
                "extension": "vp6",
                "browser_native": False,
                "decoder_in_repo": False,
                "note": "VP6 suffix matches path template; container/codec not verified for browser playback.",
            }
            row["startup_screen_link"] = (
                "Concrete movie file present. Matches Attract / ea_bumper naming leads. "
                "No independent browser decoder implemented."
            )
        elif rel.lower().endswith(".big"):
            row["format_metadata"] = {
                "extension": "big",
                "magics": scan_magics(path),
                "independently_decodable": False,
                "note": "UI .big package; format not established for Phase 51 image extract.",
            }
        entries.append(row)

    out = {
        "phase": 51,
        "install_root": INSTALL,
        "accessible": True,
        "read_only": True,
        "ghidra_report": "analysis/undercover/undercover-intro-startup-report.md",
        "entries": entries,
        "fng_names_in_exe_only": [
            "LS_EALOGO.FNG", "LS_SPLASH.FNG", "LS_ATTRACTFMV.FNG",
            "LS_PSA.FNG", "FEANYMOVIE.FNG", "FeMainMenu.fng",
        ],
        "fng_files_on_disk": False,
        "note": (
            ".FNG names are executable string leads; no corresponding .FNG files "
            "were found as loose files. Bundle membership unresolved."
        ),
    }
    os.makedirs(ANALYSIS, exist_ok=True)
    path = os.path.join(ANALYSIS, "startup-asset-inventory.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print("wrote", path)
    # summary
    for e in entries:
        if e.get("present"):
            print(f"{e['relative_path']}: {e['size']} sha={e['sha256'][:12]}… magics={e.get('magics_in_first_512kib')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
