#!/usr/bin/env python3
"""Generate Undercover Phase-47 synthetic fixtures + asset manifest."""
from __future__ import annotations

import hashlib
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "web", "src", "static", "uc-fixtures")
MANIFEST = os.path.join(ROOT, "web", "src", "static", "uc-asset-manifest.json")

FILES = {
    "startup/readme.txt": (
        b"NFSUC synthetic startup fixture. Not Undercover game data. "
        b"GAME_CODE_TARGET=NFS_UNDERCOVER_PC\n"
    ),
    "startup/boot-marker.json": (
        b'{"kind":"synthetic-fixture","playable":false,'
        b'"first_frame":"BLOCKED"}\n'
    ),
    "menu/placeholder.bin": (
        bytes([0x55, 0x43, 0x46, 0x58]) + b"UC-MENU-FIXTURE-v1" + bytes(32)
    ),
}


def main() -> None:
    assets = []
    for rel, data in FILES.items():
        path = os.path.join(FIX, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        digest = hashlib.sha256(data).hexdigest()
        aid = rel.replace("/", ".").rsplit(".", 1)[0]
        required = rel.startswith("startup/")
        assets.append({
            "id": aid,
            "path": rel,
            "url": rel,
            "size": len(data),
            "sha256": digest,
            "contentType": (
                "application/json" if rel.endswith(".json")
                else "text/plain" if rel.endswith(".txt")
                else "application/octet-stream"
            ),
            "category": "startup" if required else "menu",
            "required": required,
            "license": "synthetic-fixture",
        })
        print(rel, len(data), digest)

    # Placeholder for a future authorized commercial asset (never downloadable now).
    assets.append({
        "id": "production.game-data.placeholder",
        "path": "production/UNDERCOVER_GAME_DATA.placeholder",
        "url": "production/UNDERCOVER_GAME_DATA.placeholder",
        "size": 0,
        "sha256": "0" * 64,
        "contentType": "application/octet-stream",
        "category": "gameplay",
        "required": False,
        "license": "copyrighted-unavailable",
    })

    manifest = {
        "manifestVersion": 1,
        "game": "NFS_UNDERCOVER_PC",
        "toolingOrigin": "NFSU2-WEB",
        "targetSha256": (
            "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd"
        ),
        "source": {
            "mode": "fixtures",
            "baseUrl": "/uc-fixtures/",
            "productionAssetsAuthorized": False,
            "note": (
                "Synthetic fixtures only. Production Undercover asset downloads "
                "remain unavailable until a rights-authorized endpoint is configured."
            ),
        },
        "assets": assets,
    }
    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    print("wrote", MANIFEST)


if __name__ == "__main__":
    main()
