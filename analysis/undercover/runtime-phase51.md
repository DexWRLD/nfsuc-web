# Undercover Phase 51 — Authentic startup logo preview

SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

FIRST_FRAME: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## Independent statuses

- `AUTHENTIC_STARTUP_ASSET_PREVIEW`: **READY**
- `AUTHENTIC_INTRO_VIDEO_PREVIEW`: **IDENTIFIED_NO_DECODER**
- `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`: **BLOCKED**

## A. Verified startup image

- Path: `dialoglogo128x128.jpg` (install root)
- SHA-256: `6c30b18704f937bb7257b44598bc66097de2bbc806e007d8f72c2d19765408a7`
- Format: JPEG 128×128, offset 0, length 22685
- Identity: Original ship file from the Undercover install root. NOT proven to be LS_EALOGO.FNG / LOGOTEXTURES.BUN / BOOTFLOWTEXTURES.BUN member.
- Export (outside repo): `tools/uc_export_startup_logo.py` → `%USERPROFILE%\.nfsuc-web\authorized-startup`
- Not committed to git.

## B. Frontend / movie inventory (read-only)

- Install accessible: yes (`C:\Games\Need For Speed Undercover`)
- `FRONTEND/LOGOTEXTURES.BUN`, `BOOTFLOWTEXTURES.BUN`, `FRONTB1.BUN` present; **no verified BUN→image span**
- `.FNG` names are exe string leads only; no loose `.FNG` files
- `MOVIES/ea_bumper_english_ntsc.vp6` present (`d4982c58fa09d353…`); VP6 **IDENTIFIED_NO_DECODER**
- See `startup-asset-inventory.json`

## C. Startup preview (browser)

- State machine: `LOGO → OPTIONAL_VIDEO → MENU_PLACEHOLDER` (`uc-startup-preview.ts`)
- UI panel + OPFS/memory cache publish after digest verify
- Synthetic fixture for CI; authentic JPEG via `UC_ASSET_ROOT`
- Node startup tests: **PASS**
- Browser startup smoke: **PASS**

## D. Validation

- Startup preview: **PASS**
- Browser startup: **PASS**
- DXT1 regression: **PASS**
- Assets: **PASS**
- LAN: **PASS**
- Build: **PASS**

## E. Metrics (50 → 51)

- UNIQUE: 84 → 84
- ENTERABLE: 50 → 50
- RUNS: 346 → 358
- BLOCKED_EXTERNAL: 74
- First frame: BLOCKED

## F. Phase 52

Map verified BUN/BIGF membership for NFS_UNDERCOVER_LOGO or LS_EALOGO with proven offset/length digests; or obtain a rights-cleared offline VP6→browser-safe conversion retaining provenance; continue DXT1 span hunt; keep opaque draw backends untouched; FIRST_FRAME remains blocked.
