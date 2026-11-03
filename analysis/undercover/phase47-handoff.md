# Phase 47 handoff

From Phase 46 matrix expansion and first-frame evidence integration.

## Do not

- Reconstruct `0x00686000` / `0x00686030` / `0x006860F0` / `0x00686290` / `0x006861B0`.
- Invent scheduling edges for callback→scene or scene→Present.
- Claim authentic first frame or browser GPU submission.
- Reclassify MUST/BLOCKED_EXTERNAL without an ordinary allocator-free path.

## Priorities

1. Static recovery of scheduling edges: `0x00766730` → `~0x00777253` / `0x007B5972`, and mesh/scene → `~0x00758674`.
2. More allocator-independent `0x00A12xxx` leaves and longer guest chains.
3. Ordinary stream/state/resource contracts with injected device mocks only.
4. Material/texture binding evidence (non-null ordinary paths) if recoverable.

Recover scheduling edges from render callback 0x00766730 to scene producers (~0x00777253 / 0x007B5972) and from mesh/scene work to later Present (~0x00758674); expand remaining allocator-independent math; continue ordinary stream/state contracts with injected device mocks. Keep 0x006860F0/0x00686290/0x00686000 opaque.
