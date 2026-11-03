# Phase 45 handoff

From Phase 44 blocker attribution.

## Do not

- Implement/execute `0x00686000` / `0x00686030` / backends / `0x0071E380` / `0x00B615C4`.
- Invent CreateWindowExA / UpdateWindow / Direct3DCreate9 slot mappings.
- Promote BLOCKED_EXTERNAL → ENTERABLE without an allocator-free ordinary path.
- Treat callback registration DATA edges as executed callbacks.

## Next highest value

1. Expand static recovery of `0x0072B170` and `0x00766730` bodies enough to
   justify or reject callback **execution** edges.
2. Reconcile Ghidra allocator-caller inventory with verified ordinary `.text`
   (audit omitted ≥6 direct callers).
3. Continue ordinary object-family / virtual-interface work that does not
   require the allocator MUST set.

Close allocator-audit caller gaps in static evidence; recover enough of 0x0072B170 / 0x00766730 ordinary bodies to decide whether callback execution edges are justifiable; keep protected backends opaque. Do not promote BLOCKED_EXTERNAL to ENTERABLE without an ordinary allocator-free path.
