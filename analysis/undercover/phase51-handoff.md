# Phase 51 handoff

From Phase 50 BC1 decoder and synthetic asset previews.

## Do not

- Treat synthetic texture/mesh previews as authentic gameplay frames.
- Invent archive offsets for DXT1 or XP_SMOKEBALL_* without digests.
- Reconstruct opaque backends (`0x006860F0`, `0x00686290`, …).
- Commit commercial game assets or TLS private keys.

## Priorities

1. Obtain one authorized readable DXT1 span with proven source SHA256, offset, length, dimensions, format, payload SHA256.
2. Drive `PREVIEW_AUTHENTIC_VERIFIED` through LAN download + OPFS cache.
3. Match `XP_SMOKEBALL_CURL` / `PUFF` to vertex/index spans + 0x50 declaration.
4. Optional textured mesh diagnostic once UV + texture IDs are verified.
5. Keep FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND until opaque draw path is replaced by ordinary evidence.

Locate one readable authorized DXT1 span with proven offset/size/format digests; or match XP_SMOKEBALL_* vertex/index spans to a verified 0x50 declaration; keep opaque draw backends untouched; FIRST_FRAME remains blocked.
