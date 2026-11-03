#!/usr/bin/env python3
"""Export the independently decodable install dialog logo to an authorized
outside-repo directory with provenance metadata (Phase 51).

Does NOT claim this is LS_EALOGO.FNG or NFS_UNDERCOVER_LOGO from BOOTFLOWTEXTURES.
Those BUN entries remain unsupported without a verified texture-pack parser.

  python tools/uc_export_startup_logo.py
  python tools/uc_export_startup_logo.py --out %USERPROFILE%\\.nfsuc-web\\authorized-startup
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

INSTALL = r"C:\Games\Need For Speed Undercover"
SRC_REL = "dialoglogo128x128.jpg"
DEFAULT_OUT = os.path.join(os.path.expanduser("~"), ".nfsuc-web", "authorized-startup")


def jpeg_dims(data: bytes) -> tuple[int, int]:
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            break
        marker = data[i + 1]
        if marker in (0xD8, 0xD9):
            i += 2
            continue
        seglen = struct.unpack(">H", data[i + 2:i + 4])[0]
        if marker in (0xC0, 0xC1, 0xC2):
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            return w, h
        i += 2 + seglen
    raise SystemExit("JPEG SOF not found")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--install", default=INSTALL)
    ap.add_argument("--out", default=os.environ.get("UC_ASSET_ROOT", DEFAULT_OUT))
    args = ap.parse_args()
    src = os.path.join(args.install, SRC_REL)
    if not os.path.isfile(src):
        print("missing", src, file=sys.stderr)
        return 1
    data = open(src, "rb").read()
    if data[:3] != b"\xff\xd8\xff":
        print("not a JPEG", file=sys.stderr)
        return 1
    w, h = jpeg_dims(data)
    sha = hashlib.sha256(data).hexdigest()
    out = os.path.abspath(args.out)
    # refuse writing into the repo
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if (out + os.sep).lower().startswith((repo + os.sep).lower()):
        print("Refuse to write authorized assets inside the repository:", out, file=sys.stderr)
        return 2
    os.makedirs(out, exist_ok=True)
    dest = os.path.join(out, SRC_REL)
    open(dest, "wb").write(data)
    prov = {
        "resourceId": "install.dialoglogo128x128",
        "originalName": "dialoglogo128x128.jpg",
        "sourceRelativePath": SRC_REL.replace("\\", "/"),
        "sourceArtifactId": f"install:{SRC_REL}",
        "sourceSha256": sha,
        "payloadSha256": sha,
        "sourceByteOffset": 0,
        "sourceByteLength": len(data),
        "mediaFormat": "image/jpeg",
        "width": w,
        "height": h,
        "sourceCategory": "authorized-verified",
        "evidenceRef": "analysis/undercover/startup-asset-inventory.json",
        "identityNote": (
            "Original ship file from the Undercover install root (Games Explorer / "
            "dialog branding). NOT proven to be LS_EALOGO.FNG, NFS_UNDERCOVER_LOGO "
            "in BOOTFLOWTEXTURES.BUN, or any LOGOTEXTURES.BUN member."
        ),
        "kind": "authentic-verified",
        "installRoot": os.path.abspath(args.install),
    }
    open(os.path.join(out, SRC_REL + ".provenance.json"), "w", encoding="utf-8", newline="\n").write(
        json.dumps(prov, indent=2) + "\n"
    )
    print(json.dumps({"out": dest, "sha256": sha, "width": w, "height": h, "bytes": len(data)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
