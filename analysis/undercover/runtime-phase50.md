# Undercover Phase 50 — BC1 decoder & asset preview contracts

SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

FIRST_FRAME: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## Correction

`0x007513E2` is **CreateCubeTexture** (six faces), not CreateVolumeTexture.
See `cube-texture-correction.json` and `undercover-asset-browser-report.md`.

## A. BC1/DXT1 decoder

- Strict standalone decoder: `web/src/app/uc-dxt1.ts`
- Unit tests: **PASS**
- Synthetic fixtures under `web/src/static/uc-fixtures/textures/`

## B. Provenance & preview

- Manifest validation: `uc-texture-manifest.ts`
- Viewer states include `PREVIEW_SYNTHETIC` / `PREVIEW_AUTHENTIC_VERIFIED`
- Authentic texture source identified: **False**
- Authentic texture preview verified: **False**

## C. Vertex declaration & mesh

- Converter `0x0073F300` tables: `uc-vertex-decl.ts`
- Mesh contract: `uc-mesh-validate.ts`
- Synthetic WebGL triangle preview: `uc-mesh-preview.ts`
- Authentic mesh source identified: **False**

## D. Dashboard

- Synthetic texture decoder: WORKING
- Synthetic mesh viewer: WORKING
- Browser game renderer ready: False
- Authentic first frame ready: False

## E. Validation

- Node DXT1/provenance/mesh: **PASS**
- Node assets: **PASS**
- LAN server: **PASS**
- Build: **PASS**
- Guest metrics: Phase 49 regression only (no inflation)

## F. Metrics (49 → 50)

- Compiled: 22,770
- UNIQUE: 84 → 84
- ENTERABLE: 50 → 50
- RUNS: 334 → 346
- RUNTIME_READY: 72
- BLOCKED_EXTERNAL: 74
- Browser renderer: SYNTHETIC_TEXTURE_AND_MESH_PREVIEW
- First frame: BLOCKED

## G. Phase 51

Locate one readable authorized DXT1 span with proven offset/size/format digests; or match XP_SMOKEBALL_* vertex/index spans to a verified 0x50 declaration; keep opaque draw backends untouched; FIRST_FRAME remains blocked.
