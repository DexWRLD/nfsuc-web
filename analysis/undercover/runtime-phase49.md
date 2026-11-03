# Undercover Phase 49 — Private LAN host & clean-PC boot

SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

FIRST_FRAME: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## A. LAN host startup

- Script: `Start-UndercoverLAN.ps1`
- Server: `web/tools/uc-lan-server.mjs`
- Binds selected private IPv4 (not every adapter by default)
- Docs: `web/docs/uc-private-lan.md`

## B. HTTPS

- Cert tool: `web/tools/uc-lan-certs.mjs` (SAN = LAN IPs + localhost)
- Keys written under `%USERPROFILE%\.nfsuc-web\lan-certs\` (outside repo)
- Insecure HTTP origins show an explicit OPFS warning and use memory fallback

## C. Private asset endpoint

- `UC_ASSET_ROOT` / `--asset-root`: serve only manifest-allowlisted paths under `/uc-assets/`
- Path traversal / symlink escape rejected; Range 206 supported

## D. Manifest generation

- `web/tools/uc-manifest-gen.mjs` — curated allowlist only (no whole-install scan)

## E. Boot stages

`BOOT → MANIFEST → CACHE_CHECK → DOWNLOAD → VERIFY → FS_MOUNT → RUNTIME_INIT → READY_OR_BLOCKED`

## F. Validation layers (do not merge)

- Node `uc-assets.test.mjs`: **PASS**
- Node `uc-lan-server.test.mjs`: **PASS**
- Playwright HTTPS loopback: **PASS**
- Frontend build: **PASS**
- Physical second PC: **manual** (not claimed here)
- Guest execution: Phase 48 regression (no metric inflation)
- Synthetic graphics: clear smoke only
- Authentic gameplay: not ready

## G. Metrics (Phase 48 → 49)

- Compiled: 22,770
- UNIQUE: 84 → 84
- ENTERABLE: 50 → 50
- RUNS: 322 → 334
- RUNTIME_READY: 72
- BLOCKED_EXTERNAL: 74
- Asset distribution: PRIVATE_LAN_FIXTURE_HOST_READY
- LAN testing: PRIVATE_LAN_HTTPS_READY
- Browser renderer: SYNTHETIC_CLEAR_SMOKE_ONLY
- First frame: BLOCKED

## H. Phase 50

On authorized curated data: map real Undercover resource formats into /uc; recover scene-scheduling edges toward Present while keeping opaque draw backends (0x006860F0 / 0x00686290) untouched; expand remaining RUNTIME_READY_NOT_EXECUTED leaves only with verified ABIs.
