"""Publish explicitly approved unified-process files through the existing private allowlist."""
import argparse
import json
from pathlib import Path
import subprocess

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset_root", type=Path)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--version", type=int, default=65)
    args = parser.parse_args()
    entries = json.loads(args.allowlist.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        parser.error("Allowlist must be an array")
    files = [
        ("uc-unified-image.json", "application/json"),
        ("uc-unified-image.bin", "application/octet-stream"),
        ("uc-unified.wasm", "application/wasm"),
    ]
    for name, content_type in files:
        if not (args.asset_root/name).is_file():
            parser.error("Missing generated file: " + name)
        if not any(entry["path"] == name for entry in entries):
            entries.append(dict(id=name, path=name, contentType=content_type, required=False))
    args.allowlist.write_text(json.dumps(entries, indent=2)+"\n", encoding="utf-8")
    repository = Path(__file__).resolve().parents[1]
    subprocess.run([
        "node", str(repository/"web/tools/uc-manifest-gen.mjs"),
        "--root", str(args.asset_root), "--allowlist", str(args.allowlist),
        "--out", str(args.manifest), "--authorized", "--version", str(args.version),
    ], check=True)

if __name__ == "__main__":
    main()

