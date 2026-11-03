# Undercover Phase 46 — Matrix expansion & first-frame evidence

SHA-256 target: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

FIRST_FRAME: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## A. First-frame evidence integration

- Device xrefs / defined fns / recorded call sites / edges: **{'device_xrefs': 142, 'defined_functions_disassembled': 69, 'call_pattern_scan_exhaustive_for_indirect_aliases': False}** / call_sites=25 edges=28
- Clear-only Present path in `0x00725200` identified (no draw between Clear and Present).
- Indexed handoff `0x00757C9A → 0x006860F0` remains opaque.
- User-memory handoff `0x00766700 → 0x00686290` remains opaque.
- Scheduling edges callback→scene and scene→later Present: **UNVERIFIED**.

Artifacts: `d3d9-device-call-sites.json`, `render-call-graph.json`, `first-frame-readiness.json`, `draw-handoff-metadata.json`, `mesh-descriptor-field-map.json`, `stream-state-evidence.json`.

## B. New guest-executed functions

| Address | Role | ABI | Clean | Oracle | Dependencies |
|---|---|---|---|---|---|
| `0x00A12850` | const ptr smoke | see inventory | True | True | none protected |
| `0x00A12D10` | matrix add smoke | see inventory | True | True | none protected |
| `0x00A128F0` | scale rows by vec.x | see inventory | True | True | none protected |
| `0x00A12940` | madd rows by vec.x | see inventory | True | True | none protected |
| `0x00A12E60` | 3x3 matrix multiply | see inventory | True | True | none protected |
| `0x00766100` | range reclaim | see inventory | True | True | none protected |
| `0x00766100` | range reclaim | see inventory | True | True | none protected |

Newly unique executed: ['0x00766100', '0x00A128F0', '0x00A12940', '0x00A12E60']
Newly enterable: ['0x00766100', '0x00A128F0', '0x00A12940', '0x00A12E60']
Extended matrix chain clean: True

## C. Synthetic rendering contracts

- Stream-cache hit/miss (miss via injected SetStreamSource).
- Indexed-draw argument preparation (primCount = floor(indexCount/3)); opaque target `0x006860F0` not executed.
- Buffer-range reclaim: guest empty/exact-single + synthetic coalesce cases.
- D3D9 command recorder: clear-only Present sequence + later EndScene/Present.

**These are not authentic Undercover frames and are not browser GPU execution.**

## D. Metrics

- UNIQUE: 75 → 79
- ENTERABLE: 41 → 45
- EXECUTION_RUNS: 282 → 297
- RUNTIME_READY: 72 (policy unchanged)
- BLOCKED_EXTERNAL: 74 (unchanged)

## E. First-frame readiness

See `first-frame-readiness.json`. Authentic game frame: **Blocked**.

## F. Protected boundaries

Opaque: `0x00686000`, `0x00686030`, `0x004A26B0`, `0x007A51B0`, `0x0071E380`, `0x00B615C4`, `0x006860F0`, `0x00686290`, `0x006861B0`.

## G. Phase 47

Recover scheduling edges from render callback 0x00766730 to scene producers (~0x00777253 / 0x007B5972) and from mesh/scene work to later Present (~0x00758674); expand remaining allocator-independent math; continue ordinary stream/state contracts with injected device mocks. Keep 0x006860F0/0x00686290/0x00686000 opaque.
