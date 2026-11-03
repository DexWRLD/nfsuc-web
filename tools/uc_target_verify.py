#!/usr/bin/env python3
"""Read-only Undercover PE target verification.

Distinguishes TOOLING_ORIGIN=NFSU2-WEB from GAME_CODE_TARGET=NFS_UNDERCOVER_PC.
Does not copy, execute, or modify the game binary. Does not read protected sections
beyond listing their presence.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase7_test as p7

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")

EXPECTED_SHA256 = "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd"
EXPECTED_IMAGE_BASE = 0x00400000
EXPECTED_ENTRY_VA = 0x01FCA510
EXPECTED_VERSION = "1.1.2.1"
EXPECTED_MACHINE = 0x14C  # IMAGE_FILE_MACHINE_I386
EXPECTED_TEXT_VA = 0x00401000
# Ordinary .text samples used in Phase 40/41 campaigns (first bytes).
ORDINARY_SAMPLES = {
    0x009E9160: bytes.fromhex("5356578bf1e8a6e5ffff8b442410508d"),
    0x009E98F0: bytes.fromhex("83ec44568bf1e815deffff33c0b91000"),
    0x009E9980: bytes.fromhex("b8380fc300c3"),
    0x009E8E00: bytes.fromhex("83ec1453558b6c24208b45008b501456"),
    0x009E9A30: bytes.fromhex("8b51488b4424048950108b514489500c"),
    0x009EB350: bytes.fromhex("568bf1e8b8c3ffff8b44241033c9"),
}


def default_input_path():
    return os.environ.get(
        "UC_UNDERCOVER_EXE",
        r"C:\Games\Need For Speed Undercover\nfs.exe",
    )


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify(path=None):
    path = path or default_input_path()
    out = {
        "tooling_origin": "NFSU2-WEB",
        "game_code_target": "NFS_UNDERCOVER_PC",
        "expected": {
            "filename": "nfs.exe",
            "version": EXPECTED_VERSION,
            "sha256": EXPECTED_SHA256,
            "architecture": "PE32/x86",
            "machine": "0x%04X" % EXPECTED_MACHINE,
            "image_base": "0x%08X" % EXPECTED_IMAGE_BASE,
            "entry_va": "0x%08X" % EXPECTED_ENTRY_VA,
            "ordinary_text_va": "0x%08X" % EXPECTED_TEXT_VA,
        },
        "input_present": False,
        "input_path_recorded": False,  # never commit absolute personal paths
        "verification_status": "TARGET_BINARY_NOT_AVAILABLE_FOR_REHASH",
        "sha256_match": None,
        "pe_match": None,
        "ordinary_text_provenance": None,
        "mismatch": None,
        "ordinary_samples_checked": [],
    }
    if not path or not os.path.isfile(path):
        return out

    out["input_present"] = True
    # Record only that a local input was used — not the absolute path.
    out["input_path_recorded"] = False
    out["input_basename"] = os.path.basename(path)

    digest = sha256_file(path)
    out["observed_sha256"] = digest
    out["sha256_match"] = digest.lower() == EXPECTED_SHA256.lower()

    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        machine = pe.FILE_HEADER.Machine
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_va = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        version = None
        if getattr(pe, "VS_FIXEDFILEINFO", None):
            fi = pe.VS_FIXEDFILEINFO[0]
            version = "%d.%d.%d.%d" % (
                (fi.FileVersionMS >> 16) & 0xFFFF,
                fi.FileVersionMS & 0xFFFF,
                (fi.FileVersionLS >> 16) & 0xFFFF,
                fi.FileVersionLS & 0xFFFF,
            )
        text = None
        for s in pe.sections:
            name = s.Name.split(b"\0", 1)[0].decode("ascii", "replace")
            if name == ".text":
                text = {
                    "va": "0x%08X" % (image_base + s.VirtualAddress),
                    "vsize": "0x%08X" % s.Misc_VirtualSize,
                }
                break
        out["observed"] = {
            "machine": "0x%04X" % machine,
            "image_base": "0x%08X" % image_base,
            "entry_va": "0x%08X" % entry_va,
            "version": version,
            "ordinary_text": text,
        }
        pe_ok = (
            machine == EXPECTED_MACHINE
            and image_base == EXPECTED_IMAGE_BASE
            and entry_va == EXPECTED_ENTRY_VA
            and (version is None or version == EXPECTED_VERSION)
            and text is not None
            and int(text["va"], 16) == EXPECTED_TEXT_VA
        )
        out["pe_match"] = pe_ok
    except Exception as exc:
        out["pe_match"] = False
        out["pe_error"] = str(exc)[:200]
        pe_ok = False

    # Ordinary .text byte samples via existing section mapper (ALLOWED only).
    try:
        sections = p7.read_sections(path)
        text_sec = None
        for s in sections["sections"]:
            if s["name"] == ".text" and s["raw"] is not None:
                text_sec = s
                break
        sample_ok = True
        for va, expect in ORDINARY_SAMPLES.items():
            row = {"va": "0x%08X" % va, "ok": False}
            if text_sec and text_sec["va"] <= va < text_sec["va"] + text_sec["vsize"]:
                off = va - text_sec["va"]
                got = text_sec["raw"][off:off + len(expect)]
                row["ok"] = got == expect
                row["observed_prefix"] = got.hex()
                row["expected_prefix"] = expect.hex()
                if not row["ok"]:
                    sample_ok = False
            else:
                sample_ok = False
                row["error"] = "VA outside ordinary .text"
            out["ordinary_samples_checked"].append(row)
        out["ordinary_text_provenance"] = sample_ok
    except Exception as exc:
        out["ordinary_text_provenance"] = False
        out["ordinary_text_error"] = str(exc)[:200]

    if out["sha256_match"] and out["pe_match"] and out["ordinary_text_provenance"]:
        out["verification_status"] = "VERIFIED_UNDERCOVER_1_1_2_1"
    elif not out["sha256_match"]:
        out["verification_status"] = "HASH_MISMATCH"
        out["mismatch"] = "sha256"
    elif not out["pe_match"]:
        out["verification_status"] = "PE_MISMATCH"
        out["mismatch"] = "pe_characteristics"
    else:
        out["verification_status"] = "ORDINARY_TEXT_MISMATCH"
        out["mismatch"] = "ordinary_text_bytes"
    return out


def write_provenance(path=None):
    result = verify(path)
    # Strip any accidental absolute path keys before commit.
    result.pop("input_path", None)
    out_path = os.path.join(ANALYSIS, "target-provenance.json")
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    return result, out_path


def main(argv=None):
    argv = list(argv or sys.argv[1:])
    path = argv[0] if argv else None
    result, out_path = write_provenance(path)
    print("status", result["verification_status"])
    print("sha256_match", result.get("sha256_match"))
    print("pe_match", result.get("pe_match"))
    print("ordinary_text", result.get("ordinary_text_provenance"))
    print("wrote", out_path)
    if result["verification_status"] not in (
            "VERIFIED_UNDERCOVER_1_1_2_1",
            "TARGET_BINARY_NOT_AVAILABLE_FOR_REHASH"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
