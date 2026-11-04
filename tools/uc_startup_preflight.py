"""Read-only startup preflight for the verified Undercover executable and master export."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SOURCE_SHA = "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd"
MASTER_SHA = "f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a"


def inspect(image_path, repository):
    image = image_path.read_bytes()
    if hashlib.sha256(image).hexdigest() != SOURCE_SHA:
        raise ValueError("Source executable SHA-256 mismatch")
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[:2] != b"MZ" or image[pe:pe+4] != b"PE\0\0":
        raise ValueError("Invalid PE signatures")
    machine, section_count = struct.unpack_from("<HH", image, pe+4)
    optional = pe+24
    optional_size = struct.unpack_from("<H", image, pe+20)[0]
    magic = struct.unpack_from("<H", image, optional)[0]
    entry_rva = struct.unpack_from("<I", image, optional+16)[0]
    image_base = struct.unpack_from("<I", image, optional+28)[0]
    if machine != 0x14C or magic != 0x10B or image_base != 0x400000:
        raise ValueError("Unexpected target architecture")
    section = None
    for index in range(section_count):
        offset = optional+optional_size+40*index
        name = image[offset:offset+8].split(b"\0",1)[0].decode("ascii")
        virtual_size, rva, size, raw_offset = struct.unpack_from("<IIII", image, offset+8)
        if rva <= entry_rva < rva+virtual_size:
            delta = entry_rva-rva
            if delta+25 > size:
                raise ValueError("Entry bytes are not file-backed")
            section = {"name": name, "raw_offset": raw_offset+delta}
            break
    if not section:
        raise ValueError("Entry section missing")
    directory = repository/"analysis"/"undercover"
    master = directory/"nfs_undercover_full_decompile.c"
    if hashlib.sha256(master.read_bytes()).hexdigest() != MASTER_SHA:
        raise ValueError("Master export SHA-256 mismatch")
    inventory = json.loads((directory/"nfs_undercover_function_index.json").read_text(encoding="utf-8"))
    address = f"0x{image_base+entry_rva:08X}"
    function = next(f for f in inventory["functions"] if f["address"] == address)
    offset = section["raw_offset"]
    # The byte check describes the known overlapping-entry boundary. It never runs it.
    if image[offset+0x17:offset+0x19] != bytes.fromhex("ebfa"):
        raise ValueError("Entry boundary no longer matches the recorded instruction")
    registry_path = repository/"tools"/"uc_unified_registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8")) if registry_path.is_file() else {"bindings": []}
    return {
        "unified_registry_addresses": [f"0x{entry['address']:08X}" for entry in registry["bindings"]],
        "independent_initialization_root": "0x00B57DC0",
        "independent_initialization_evidence": "runtime-phase66.md and edge-execution-phase66.json",
        "independent_root_reachability_from_pe_entry": "UNVERIFIED",
        "source_sha256": SOURCE_SHA, "master_sha256": MASTER_SHA,
        "entry": address, "entry_section": section["name"],
        "entry_bytes": image[offset:offset+25].hex(),
        "entry_recovery_status": function["decompilation_status"],
        "entry_warnings": function["warnings"],
        "known_entry_callees": function["known_callees"],
        "startup_status": "BLOCKED_UNVERIFIED_ENTRY_CONTROL_FLOW",
        "first_verified_blocking_edge": {
            "instruction": "0x01FCA527", "target": "0x01FCA523",
            "reason": "Jump enters overlapping instruction bytes; ordinary startup continuation is not verified",
        },
        "undercover_original_startup_prefix_in_browser": False,
        "existing_browser_prefixes_reachable_from_pe_entry": "UNVERIFIED",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = inspect(args.image, args.repository)
    text = json.dumps(result, indent=2)+"\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()

