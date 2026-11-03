# Phase 20 — D3D9 device lifecycle, draw frontier, post-init seam

Ordinary sections only. Did not execute `nfs.exe`, fabricate a device at
`0x013C6510`, reconstruct SecuROM, or implement Direct3D9.

Factory prefix remains **BLOCKED_EXTERNAL_PROTECTED_INITIALIZATION**.

## A. Device publication

| Item | Value |
| --- | --- |
| Global | `0x013C6510` |
| Absolute MOV writer | **none** |
| Publication class | **DEFINITE_DEVICE_PUBLICATION** |
| Mechanism | COM out-parameter `push 0x013C6510` |
| Sites | `0x007252B6`, `0x007252E8` inside `0x00725200` |
| Caller | `0x007297D0` (sole HIGH caller) |

## B. `0x00725200`

- **ABI:** thiscall (`ECX` = graphics object → `ESI`) + **4 stack dwords**, `ret 0x10`.
- **EBP:** first stack arg = COM factory/wrapper (`[obj+0x10]` from caller).
- Enumerates adapters via wrapper VT `+0x10` / `+0x14`.
- Publishes device via VT **`+0x40`** (two attempts).
- On HRESULT success: BeginScene → Clear → EndScene → Present on `0x013C6510`.
- Compares HRESULT to `0x8876086C` (DEVICELOST-shaped).
- Returns HRESULT in EAX.

## C. CreateDevice evidence

**CREATEDEVICE_STRONG_CANDIDATE** (not raw-proven).

| Factor | Evidence |
| --- | --- |
| Out-pointer | `push &0x013C6510` |
| Arity/order | matches CreateDevice (Adapter, DevType, HWND, BehaviorFlags, present-params*, out**) |
| BehaviorFlags | `0x40` then retry `0x20` |
| Downstream | published pointer used as IDirect3DDevice9 |
| Offset | **`+0x40`** vs raw `IDirect3D9::CreateDevice` **`+0x3C`** → wrapper-shaped |

## D–F. Dependencies

```
0x007297D0
  -> call 0x00686000          PROTECTED_BOUNDARY (allocator -> [obj+0x50])  [BEFORE pub]
  -> push [obj+0x10]          EXTERNAL_STATE (factory iface from blocked create)
  -> call 0x00725200          ORDINARY_DIRECT
       -> COM +0x40 out-param ORDINARY_INDIRECT_PROVEN
  -> later call 0x00686000    after device already used
```

| Question | Answer |
| --- | --- |
| First unavailable edge | `0x00686000` before publication **and** factory field via frozen `0x00B615C4` |
| Helper before successful publication? | **YES** |
| `0x00B615C4` mandatory for in-game publication? | **YES** (via `[obj+0x10]`) |
| `0x00B615C4` mandatory for Present prefix? | **NO** |

## G–I. Lifecycle / lost / reset

- **Null/clear stores** to `0x013C6510`: none found (ordinary absolute).
- **Release:** DEVICE-linked VT `+0x08` sites present → RELEASE_STRONG_CANDIDATE.
- **DEVICELOST:** compare in `0x00725200`; failure skips the Clear/Present demo.
- **Reset:** **RESET_NOT_FOUND** for DEVICE-linked `+0x38`. Broad `+0x38` hits are non-device false friends.
- **Recovery / republication:** **NO** ordinary path that rewrites `0x013C6510` from null after startup without the blocked publisher.

## J–K. Present params / Present path

- Present-params candidate: `[ESI+0x130]` in `0x00725200` (size unknown).
- **`0x00752AF0` → Present `0x00752B14`:** EndScene then Present; prefix reads only `[0x013C6510]`.
- No TLS / flag / `0x00B615C4` / `0x00686000` on that prefix.

## L–M. Clear

**CLEAR_PROVEN** at `0x0072532F` in `0x00725200` (VT `+0xAC`, flags `7`), after successful publication demo. Also other DEVICE-linked Clear owners.

## N–P. Aliases, wrappers, draw

- Conservative DEVICE aliases: register copies / pushes in short windows; **no durable secondary global store proven**.
- Thin wrappers: DEVICE owners with a single VT offset and few callees (see raw JSON).
- **Draw:** strict COM shapes found:
  - DrawPrimitive `+0x148` (e.g. `0x007B2AC0`)
  - DrawIndexedPrimitive `+0x14C`
  - DrawIndexedPrimitiveUP `+0x154`
- These use renderer global **`0x017AA798`** / helper-returned COM — **not** direct `0x013C6510` loads.
- Confidence: **DRAW_PRIMITIVE_STRONG** (engine COM), device-tied alias **unproven**.

## Q–R. Renderer / resources

- Best renderer object candidate: `0x017AA798`.
- Resource/shader/state: DEVICE histogram from Phase 19 still applies; no new naming without alias proof.

## S. Post-init contract (for `0x00752AF0` prefix)

| Item | Class |
| --- | --- |
| `[0x013C6510]` live | D3D_DEVICE_STATE |
| Mapped ordinary image | PE_STATE |
| Factory field / `0x00B615C4` / `0x00686000` | not required on Present prefix |
| Renderer `0x017AA798` | UNKNOWN (needed for Draw* candidates) |

## T. Architectural seam

**PARTIAL_POST_INIT_SEAM**

Host-owned `IDirect3DDevice9*` at `0x013C6510` is a standard graphics-runtime responsibility for Present/Clear ordinary consumers — **not** SecuROM callback reconstruction.

It is only **partial** because full draw/frame still needs unmapped renderer state, and in-game publication remains externally blocked.

Does **not** require reproducing protected callback semantics for the Present-only seam.

## U. D3D9 implementation decision

**NO** (`D3D9_IMPLEMENTATION_JUSTIFIED = NO`)

Partial seam is documented; draw is not DEVICE-aliased; republication blocked; no implementation this phase.

## V. First-frame estimate

**UNBOUNDED** / **UNBOUNDED** (unchanged).

## W. Recommended Phase 21

**EXPAND POST-INIT GRAPHICS ANALYSIS**

1. Alias `0x013C6510` into `0x017AA798` / Draw* paths.
2. Map `[obj+0x130]` present-params writers.
3. Project decision: accept host DEVICE for a Present-only milestone or keep analysis-only.
4. Do not implement D3D9 until that decision.

Artifacts: `phase20-raw.json`, this report.
