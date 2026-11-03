# Phase 21 — angr oracle + device → renderer → Draw consensus

Ordinary sections only. Did not execute `nfs.exe`, fabricate a device/renderer,
unpack protected sections, symbolically execute protected startup, or implement
Direct3D9.

UC analyzer/lifter remains **recompilation authority**. angr is an optional
independent oracle. See `angr-oracle.md`.

## 1–5. angr load / overlap

| Item | Value |
| --- | --- |
| angr version | **10.0.5** (pin); Python **3.12** |
| Load / CFG | **OK** via ordinary `.text` shellcode windows (not PE entry) |
| Priority functions recovered | **14 / 14** |
| Overlap with UC HIGH (priority) | **AGREE: 14**; full 22,779 HIGH not scanned this phase |
| Major boundary disagreements | **0** on priority set |

Mode: static CFGFast per window, `resolve_indirect_jumps=False`. No symbolic execution.

## 6–8. Controls / non-functions

| VA | Result |
| --- | --- |
| Phase 16 `0x00766730` / `0x0072E340` / `0x0072DD00` | angr **FUNCTION_LIKE** / compare **AGREE** (sizes often truncated vs UC insn counts) |
| `0x00686000` | angr natural **NO_FUNCTION**; not forced into DB; protected callees not followed |
| `0x0055FF30` | angr natural **NO_FUNCTION** (UC `REJECTED_DATA_LIKE`) |

## 9–10. Graphics controls

| Control | Result |
| --- | --- |
| Present `0x00752AF0` | **ANGR_PRESENT_CONTROL_PASS** (DEVICE load + EndScene-shaped `+168`) |
| Clear `0x00725200` | **ANGR_CLEAR_CONTROL_PARTIAL** (DEVICE immediates in window; CFG/decomp truncates before Clear `+0xAC`) |

Control weight: **USEFUL**. Negative Draw provenance from angr is therefore meaningful, not discarded.

## 11–17. Device / renderer relationship

| Side | Classification |
| --- | --- |
| `0x013C6510` UC | **PROVEN_D3D9_DEVICE** |
| `0x013C6510` angr | absolute DEVICE in Present/Clear windows |
| `0x017AA798` UC | **POINTER_TO_ENGINE_OBJECT** (DEFINITE publishers `0x007A06E0`, `0x007B5020`; null clear) |
| `0x017AA798` angr | Draw decomp mentions renderer, **not** DEVICE |
| Publishers | DEFINITE: `0x007A09BB` (`ebp`), `0x007B506B`/`0x007B5072`; NULL: `0x0079D1E0` |
| UC device→renderer | **NO_RELATION_FOUND** (no shared owners; no renderer-linked durable DEVICE store) |
| angr device→renderer | **NO_RELATION_FOUND** |
| **CONSENSUS** | **NO_RELATION_FOUND** (`AGREE`) |

## 18–19. Aliases

| Class | Count |
| --- | --- |
| Transient (reg/stack short windows) | **164** |
| Durable object-field | **1** (`[esi+0x1B0]` in publisher `0x00725200` — graphics object, **not** renderer) |
| Renderer-linked durable | **0** |

## 20–24. Draw

| Item | Value |
| --- | --- |
| `0x007B2AC0` UC | loads `[0x017AA798]`, `call 0x0079E4A0`, VT **`+0x148`**, **ENGINE_COM_DRAW** |
| `0x007B2AC0` angr | ENGINE_COM_DRAW; renderer mentioned; DEVICE absent |
| `+0x148` identity | **ENGINE_COM_METHOD** (offset matches raw DrawPrimitive, this-pointer not proven DEVICE) |
| Five candidates | all **ENGINE_COM_DRAW** consensus |
| Raw-device Draw found | **NO** |

Helper `0x0079E4A0`: renderer thiscall walking `[obj+0x50]..[+0x54]`, returns engine COM.

## 25–29. Init / handoff / frame

| Item | Value |
| --- | --- |
| Renderer init roots | `0x007A06E0`, `0x007B5020` |
| Dependencies | ordinary YES; `0x00686030` sibling POSSIBLE on publisher path; DEVICE/FACTORY UNKNOWN for renderer |
| Device→renderer handoff | **not found** |
| Common frame root | **UNKNOWN** |
| Frame graph | Present/EndScene **PROVEN** on DEVICE; Draw **ENGINE_WRAPPER** via renderer; DEVICE↔renderer edge **UNKNOWN** |

## 30–36. Contracts / seam / decision

| Item | Value |
| --- | --- |
| Device-global publication class | **MIXED** (host fill = standard API state for Present/Clear; in-game pub still game-specific / blocked) |
| Host publication reproduces protected semantics? | **UNCLEAR** (host DEVICE alone does not bind SecuROM; also does not init renderer) |
| Factory after device exists | **DEVICE_ONLY** for Present/Clear consumers |
| Game state Clear/Present | live DEVICE = EXTERNAL_INITIALIZED |
| Game state Draw | renderer + helper COM = EXTERNAL_INITIALIZED / UNKNOWN |
| MINIMUM_FIRST_CLEAR_CONTRACT | DEVICE + ordinary Clear consumer (not fabricated) |
| MINIMUM_FIRST_DRAW_CONTRACT | renderer + helper COM + DEVICE relation (**blocked**) |
| MINIMUM_FIRST_PRESENT_CONTRACT | DEVICE + `0x00752AF0` |
| POST_INIT_SEAM | **PARTIAL_POST_INIT_SEAM** |
| D3D9_IMPLEMENTATION_JUSTIFIED | **NO** |

## 41–42. If NO — blocking uncertainty

Exact gap: whether COM objects from helper **`0x0079E4A0`** (`[renderer+0x50]..[+0x54]`) hold or alias **`0x013C6510`**.

## 43–47. angr value / estimate

| Item | Value |
| --- | --- |
| angr materially improved analysis? | **YES** |
| Strongest new angr finding | Independent Present PASS + Draw decomp without DEVICE, reinforcing NO_RELATION_FOUND |
| Strongest UC/angr disagreement | none on priority compare set (Clear control PARTIAL vs UC PASS on shape) |
| BEST_CASE / LIKELY first frame | **UNBOUNDED** / **UNBOUNDED** |

## 48. Recommended Phase 22

**EXPAND RENDERER STATE PROVENANCE** — map list elements behind `0x0079E4A0` and any field that could alias the proven device. Keep angr optional. Do not implement D3D9 yet.

## Artifacts

- `phase21-raw.json`
- `angr/summary.json`, `functions.json`, `comparison.json`, `graphics-phase21.json`
- `angr-oracle.md` (this role split)

## Dashboard / git note

Dashboard badges read **cached** angr metadata only. Commits must not include game bytes or generated translated C. Do not push unless approved.
