# Undercover Phase 43 — Graphics evidence integration

Date: 2026-11-03 evidence; implementation phase.

Target: `nfs.exe` 1.1.2.1  SHA-256 `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`.

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`

## Status

`FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`

D3D9: **NOT JUSTIFIED**. ENGINE BACKEND: **NOT JUSTIFIED**.

This phase implements verified ordinary configuration/presentation logic as synthetic, testable models. It does not execute protected code and does not unblock first frame.

## A. Baseline (Phase 42 guest metrics preserved)

- UNIQUE_UC_FUNCTIONS_EXECUTED: 67
- ENTERABLE: 33
- EXECUTION_RUNS: 265
- RUNTIME_READY: 72
- NONTRIVIAL_OBJECT_LIFECYCLES: 3
- CLEAN_VIRTUAL_CALLS: 0

Phase 43 guest deltas: **0** (synthetic-only).

## B. Graphics-object field map

- Base `0x01318170`, minimum extent `0x00000535`, exact size **BLOCKED**.
- Static instance; constructor `0x007279A0`, destructor `0x00727B60`.
- `+0x48` = performance level; **not** config FSAA.
- `+0x18` window-like; HWND **unproven**.

See `graphics-object-layout.json`.

## C. PCDisplayConfig

- Size `0x00000084` (33 DWORDs).
- Dual instances at graphics `+0x50` (caps) and `+0x54` (requested).
- Allocator `0x00686000` remains opaque.

See `pcdisplayconfig-layout.json`.

## D. Configuration clamp `0x0071D7E0`

- Two stack pointers, `RET 8`, no internal calls.
- Signed minima at offsets: 0x00000000, 0x00000004, 0x00000008, 0x0000000C, 0x00000010, 0x00000014, 0x00000024, 0x0000002C, 0x00000048, 0x00000050, 0x00000058, 0x00000060.
- Unsigned minima at: 0x00000018, 0x00000028, 0x0000004C, 0x00000054, 0x0000001C.
- Untouched fields preserved; capability buffer immutable.

## E. AA fallback correction

At `0x00729848`–`0x00729854`:

```
c & (((int32)c > 0) - 1)
```

For capability AA tiers 0..3 the result is **0**, not tier−1.
Outer device retry uses this exact mask.

## F. AA probe / sample table

- Table `0x00CE6A54` → [0, 2, 4, 8].
- `0x0071DC10` probes formats `0x4B`, `0x16`, `0x15`.
- `0x0071DC80` probes samples 2→4→8; stops on first failure.

## G. Display-mode selection

- Record stride `0x0000001C`.
- `0x00723790`: `begin + index * 0x1C`.
- `0x007237B0`: defaults 640×480@60; exact match; aspect ≤ 0.001 (`.rdata` `0x00B64D88`); pixel count >= `0x0003E800`; else last; empty → −1.

## H. Presentation parameters `0x00722EC0`

- Region engine+`0x00000130`, size `0x00000038`.
- Negative selected index: early return, no init.
- VSync → interval 1; else `0x80000000`.
- Engine `+0x19C` hwnd field distinct from graphics `+0x18`.

## I. Device creation model `0x00725200`

- First CreateDevice-shaped call flags `0x40` at `0x007252CF`.
- Nonzero → retry flags `0x20`, type 1 at `0x007252F5`.
- Output global `0x013C6510`.
- Outer AA mask retry modeled separately; imperfect outer check preserved.

## J. Ownership / cleanup fixtures

- Destructor order: caps → requested → engine dtor/free → sync → vector → title.
- Live shutdown hits opaque `0x0071E380` before device release.
- `0x00727ED0` does not clear device global after Release.
- `0x007428B0` skips `+0x0C` release for resource types 1 and 6.

## K. Window / Win32 uncertainties

- Class name `GameFrame` confirmed as data.
- Slot→import mappings for CreateWindowExA/UpdateWindow **not** hardcoded.
- Input object `0x01321188` is separate from the graphics object.

## L. Function coverage

- `0x0071D7E0` | PCDisplayConfig clamp | SYNTHETIC_PURE | tests=PASS | deps=NONE
- `0x00723790` | selected-mode pointer | SYNTHETIC_PURE | tests=PASS | deps=VALID_INDEX_PRECONDITION
- `0x007237B0` | display-mode selection | SYNTHETIC_PURE | tests=PASS | deps=ASPECT_TOLERANCE_INJECTED
- `0x00727FB0` | reflection derived fields | SYNTHETIC_PURE | tests=PASS | deps=NONE
- `0x0071D8F0` | settings getter | SYNTHETIC_PURE | tests=PASS | deps=NONE
- `0x00722EC0` | D3DPRESENT_PARAMETERS builder | SYNTHETIC_PURE | tests=PASS | deps=MEMSET_INJECTED
- `0x0071DC10` | AA multisample probe | SYNTHETIC_WITH_MOCK_D3D9 | tests=PASS | deps=FAKE_IDIRECT3D9
- `0x0071DC80` | AA tier probe policy | SYNTHETIC_WITH_MOCK_D3D9 | tests=PASS | deps=FAKE_IDIRECT3D9
- `0x00725200` | CreateDevice retry sequence | SYNTHETIC_SEQUENCE_MODEL | tests=PASS | deps=FAKE_CREATEDEVICE
- `0x00727B60` | graphics-object destructor ownership | SYNTHETIC_OWNERSHIP_FIXTURE | tests=PASS | deps=OPAQUE_FREE
- `0x00727F40` | live device shutdown | SYNTHETIC_OWNERSHIP_FIXTURE | tests=PASS | deps=OPAQUE_0071E380
- `0x007428B0` | resource release rules | SYNTHETIC_OWNERSHIP_FIXTURE | tests=PASS | deps=FAKE_COM
- `0x00727C60` | settings setter | PARTIAL_NOT_FULLY_INTEGRATED | tests=DEFERRED | deps=SIDE_EFFECT_CALLBACKS
- `0x00754740` | resource creation candidate | NOT_IMPLEMENTED | tests=N/A | deps=DEVICE_SIDE_EFFECTS
- `0x00730450` | input-edge processing | NOT_IMPLEMENTED | tests=N/A | deps=SEPARATE_INPUT_OBJECT
- `0x007661A0` | queued buffer work | NOT_IMPLEMENTED | tests=N/A | deps=BUFFER_MANAGER_GLOBAL
- `0x007408D0` | TLS render-thread gate | NOT_IMPLEMENTED | tests=N/A | deps=TLS_CONTRACT
- `0x009782D0` | thread wrapper | NOT_IMPLEMENTED | tests=N/A | deps=OS_SLOT_UNRESOLVED

Synthetic tests executed: **44** (failures=0).

## M. Evidence corrections

1. AA fallback is zeroing mask, not progressive decrement.
2. Graphics-object `+0x48` ≠ config FSAA `+0x48`.
3. Presentation hwnd source is engine `+0x19C`, not proven alias of G+0x18.
4. Device global not cleared after `0x00727ED0` release.

## N. Remaining blockers

### Ordinary / injectable

- Full setter `0x00727C60` side-effect cases.
- Confirmed Win32/D3D9 slot-to-import provenance.
- Complete mode enumeration (`0x0072B030`) without unsafe decompiler copy.

### Protected / opaque

- `0x00686000` / `0x00686030`
- `0x00B615C4`
- `0x0071E380`
- `0x004A26B0` / `0x007A51B0`

## O. Phase 44 handoff

Integrate verified setter cases of 0x00727C60 with injected side-effect callbacks; resolve aspect/window slot contracts without fabricating Win32/D3D9 import links; keep protected backend opaque.

Priorities:

1. Verified setter cases with injected callbacks.
2. Boundary adapters for factory/window/sync without inventing slot maps.
3. Keep guest ordinary object-family execution separate from graphics synthetic models until dependency contracts are complete.

## P. Artifacts

- `graphics-evidence-2026-11-03.json`
- `graphics-report-2026-11-03.md`
- `graphics-object-layout.json`
- `pcdisplayconfig-layout.json`
- `graphics-function-coverage-phase43.json`
- `tools/uc_graphics43.py`
- `tools/uc_phase43_test.py`
