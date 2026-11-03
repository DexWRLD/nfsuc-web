# First-frame dependency graph (Phase 46)

Status: `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

## Confirmed direct edges (selected)

- `0x00766730` → `0x0072E5D0` → … → `0x00725200` (device create / clear-only Present)
- `0x00766730` → `0x007661A0` → `0x00766100` (buffer queue / range reclaim)
- `0x00770750` → `0x0076FC30` → `0x00757B80` → **opaque** `0x006860F0`
- `0x00766480` → **opaque** `0x00686290`
- Undefined caller `0x00758674` → `0x00752AF0` (later EndScene/Present)

## Unresolved

- Render callback → scene producer (~`0x00777253`)
- Render callback → scene dispatch (~`0x007B5972` / `0x007B5979`)
- Scene/mesh path → later Present (~`0x00758674`)

## Opaque targets

- `0x006860F0`, `0x00686290`, `0x006861B0`, `0x004A26B0`, `0x007A51B0`, `0x00686000`

Do not invent missing edges. Registration ≠ runtime invocation.
