# Phase 19 — Post-init graphics frontier

Ordinary sections only. Did not execute `nfs.exe`, reconstruct SecuROM binding,
invent callbacks, fabricate COM objects, or implement Direct3D9.

## A. Factory-prefix boundary

| Item | Value |
| --- | --- |
| Path | `0x0072E340` → three `[0x00B615C4]` calls → helpers → `Direct3DCreate9` → `[obj+0x10]` |
| Classification | **BLOCKED_EXTERNAL_PROTECTED_INITIALIZATION** |
| Table | `0x00B61528`–`0x00B615E4` |
| Active work | **stopped** (Phase 18 boundary, not a reverse-engineering target) |

## B. Factory-result consumers

Field: `0x01318180` = `0x01318170 + 0x10` (Direct3DCreate9 return).

| Kind | Count |
| --- | --- |
| Absolute READ | **2** (`0x00722DB0`, `0x00725200`) |
| Alias write in create | `mov [ebx+0x10], eax` at `0x0072E3C2` |

Most use is thiscall/`[reg+0x10]` through the graphics object, not absolute field immediates.

`Direct3DCreate9` call sites after Phase-16 map repair: still **exactly one** (`0x0072E3B9`).

## C–D. Device pointer

| Item | Value |
| --- | --- |
| Location | **`0x013C6510`** (`.data` virtual tail, PE zero) |
| Confidence | **PROVEN_D3D9_DEVICE** |
| Evidence | VT `+0xA4/+0xAC/+0xA8/+0x44` BeginScene/Clear/EndScene/Present; `D3DERR_DEVICELOST` (`0x8876086C`) in `0x00725200`; 125+ patterned COM calls |
| Absolute MOV writer | **none** |
| Publication | out-parameter `push 0x013C6510` into COM call at `0x007252CF` / `0x007252F5` |
| Publisher function | `0x00725200` (HIGH) |
| Publisher caller | `0x007297D0` (HIGH; **closure hits `0x00686000`**) |
| Consumer owners | **64** |

## E. Vtable method histogram (via `0x013C6510`)

**28** distinct offsets. Soft names only where device identity makes them reliable:

| Offset | Calls | Soft name |
| --- | --- | --- |
| `+0x15C` | 22 | — |
| `+0xAC` | 15 | Clear |
| `+0xE4` | 13 | — |
| `+0x1A0` | 13 | — |
| `+0x198` | 12 | — |
| `+0x9C` | 12 | — |
| `+0x44` | 9 | Present |
| `+0xA8` | 4 | EndScene |
| `+0xA4` | 2 | BeginScene |
| … | … | (see `phase19-raw.json`) |

## F. Device-creation candidate

In `0x00725200`: COM call through `[ebp]` at **vtable +0x40** with BehaviorFlags-like `0x40`, present-params-like buffer, out-param `&0x013C6510`.

**Not labeled CreateDevice as proven** (raw `IDirect3D9::CreateDevice` is `+0x3C`). Class: strong device-publication candidate / possible wrapper method.

## G–I. Present / BeginScene / EndScene / Draw

| Milestone | Confidence | Primary sites |
| --- | --- | --- |
| Present (`+0x44`) | PRESENT_STRONG_CANDIDATE | `0x00725350` (`0x00725200`), `0x00752B14` (`0x00752AF0`) |
| BeginScene (`+0xA4`) | STRONG | `0x00725313` |
| EndScene (`+0xA8`) | STRONG | `0x0072533F`, `0x00752B01` |
| Clear (`+0xAC`) | STRONG | histogram + `0x00725200` sequence |
| Draw (`+0x148/14C/150/154`) | **NOT_FOUND** on DEVICE load pattern |

`0x00752AF0` opens with EndScene+Present (frame-end leaf). Later callees can hit `0x00686000`; the present **prefix** needs only DEVICE state.

## J–L. Resources / shaders / D3DX

- Resource-like DEVICE offsets appear in the histogram but are **unnamed** without stronger interface proof.
- D3DX imports remain present (`D3DXMatrixMultiply`, vector transforms, shader profile/constant-table, volume/cube helpers). HIGH callers exist; conventions often still `unknown`. **Not implemented.**
- No shader bytecode copied into analysis output.

## M. Frame-loop candidates

Best ranked Present owners by DEVICE VT diversity / helper avoidance: see `frame_loop_candidates` in raw JSON. Top analytical leaf: **`0x00752AF0`** (Present/EndScene). Top publisher+demo: **`0x00725200`**.

## N. Post-init graphics islands

| Class | Count |
| --- | --- |
| POST_INIT_GRAPHICS_EXTERNAL_STATE_ONLY | **55** |
| PROTECTED_DEPENDENT | **9** |

Best scored entry: **`0x00725200`** (Clear/Begin/End/Present demo; no direct helper in its own closure; publication caller still helper-dependent).

## O. External state vs external code

| Need | Verdict |
| --- | --- |
| Unavailable **code** to publish DEVICE / factory | **YES** |
| Ordinary Present prefix needs only **state** (`[0x013C6510] != 0`) | **YES** |

The project must not reconstruct protected code. Fabricating COM objects is also out of scope for this phase. The boundary is defined, not bypassed.

## P. Post-init runtime contract (not populated)

| Item | Status |
| --- | --- |
| Device pointer `0x013C6510` | REQUIRED |
| Factory interface `[0x01318170+0x10]` | REQUIRED (for factory/create paths) |
| Graphics object `0x01318170` | REQUIRED |
| Slot `0x00B615C4` | REQUIRED only on blocked factory prefix |
| HWND / present-params | UNKNOWN |
| TLS / flag=1 | OPTIONAL for Present-only leaves |

## Q–R. Reset / window

- `D3DERR_DEVICELOST` compared in `0x00725200`.
- No DEVICE `Reset` (`+0x38`) sites matched this pass.
- Ordinary window imports: none listed in the resolved ordinary import-abi subset used here (window APIs may live only on the SecuROM IAT, as with Phase 18).

## S. Minimum D3D9 surface (not implemented)

- **TIER 0:** `Direct3DCreate9`; device publication (`CreateDevice` or wrapper writing `0x013C6510`)
- **TIER 1:** BeginScene, Clear, EndScene, Present
- **TIER 2:** resource/state offsets from histogram (unnamed)
- **TIER 3:** D3DX helpers / later

## T–V. Frontiers

| Frontier | Status |
| --- | --- |
| FIRST_CLEAR | **BLOCKED_EXTERNAL** |
| FIRST_DRAW | **NOT_FOUND** |
| FIRST_PRESENT | **BLOCKED_EXTERNAL** |

## W. Candidate first-frame graph

Post-init Present/Clear **shapes** exist in ordinary code, but every path to a live DEVICE crosses **EXTERNAL_CODE_REQUIRED** / **PROTECTED_BOUNDARY** (`0x00B615C4` factory and/or `0x00686000` on the publisher caller). Edges are listed in `phase19-raw.json`.

## X. Recommended Phase 20

**EXPAND POST-INIT GRAPHICS ANALYSIS**

1. Prove wrapper vs `CreateDevice` identity at `0x00725200`.
2. Search harder for ordinary reset/recreate that publishes DEVICE without `0x00686000`.
3. Extend draw/resource naming only with proven interface identity.
4. Do **not** implement D3D9 until a project decision accepts an external-state contract or an ordinary publisher is found.

Artifacts: `phase19-raw.json`, this report.
