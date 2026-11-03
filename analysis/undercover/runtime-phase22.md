# Phase 22 — renderer COM container and backend handoff

Ordinary sections only. Did not execute `nfs.exe`, fabricate renderer/list
objects, follow protected targets, or implement D3D9. angr stayed optional and
targeted. UC analyzer remains recompilation authority.

## A. `0x0079E4A0`

| Item | Value |
| --- | --- |
| ABI | thiscall; **ret 8**; ECX = renderer |
| Stack | two bool-like filters |
| Return | EAX = selected COM iface or NULL |
| Fields | reads **`+0x50` begin**, **`+0x54` end** |
| Walk | stride **8**; iface at **`[elem+4]`** |
| Calls | VT `+0x70`, `+0x1DC` (filters), `+0x58` (float metric) |
| Anomaly | `jmp 0x0048FCD6` at entry looks non-functional; body at `0x0079E4AF` is the coherent empty-check/iteration |

## B–C. Container / element

**MSVC_VECTOR_LIKE** (STRONG): `+0x50` begin, `+0x54` end, `+0x58` capacity.

Element size **8**. Layout: `+0x00` UNKNOWN; `+0x04` engine COM pointer (**STRONG**).

Evidence: vector init `0x007A45B0`, `sar …, 3` count math, destructor free, clear `end=begin`.

## D–E. Lifecycle / publishers

| Step | Fn | Confidence |
| --- | --- | --- |
| CREATE/INIT + PUBLISH | `0x007B5020` | PROVEN |
| USE / DRAW | helper + Draw owners | PROVEN |
| SHUTDOWN | `0x007A06E0` | STRONG |
| NULL | `0x0079D1E0` stub + dtor epilogue (`ebp==0`) | PROVEN |

**Correction:** Phase 21 called `0x007A06E0` a DEFINITE publisher; it is a **destructor** that NULLs `0x017AA798`. Live publish is **`0x007B5020`** (`lea` this).  
**Correction:** null store owner is stub **`0x0079D1E0`**, not `0x0079D150`.

## F–G. Interfaces / vtables

One dynamic interface family: **ENGINE_GFX_IFACE_00** (list `[elem+4]`).

Static vtables recovered: **0**. Ordinary method bodies: **0** (all indirect).

Observed offsets clustered as draw-like (`+0x148/+0x14C/+0x154`), filters, metric, other.

## H–J. Draw / implementations / graph

Five ENGINE_COM_DRAW paths revalidated (one call-site fix; one owner fix to `0x007B1850`).

| Owner | Offset | Provenance | Terminus |
| --- | --- | --- | --- |
| `0x007B2AC0` | `+0x148` | helper | ENGINE_BACKEND |
| `0x007B36A0` | `+0x148` | related list | ENGINE_BACKEND |
| `0x007A1400` | `+0x14C` | direct vector walk | ENGINE_BACKEND |
| `0x007B2930` | `+0x14C` | helper (call via jmp) | ENGINE_BACKEND |
| `0x007B1850` | `+0x154` | vector gather | ENGINE_BACKEND |

No owner reads `0x013C6510`. Implementation targets: **INDIRECT_COM**.

Graph: renderer CONTAINS vector; helper RETURNS iface; Draw CALLS iface; iface→DEVICE = **UNKNOWN**. Artifact: `renderer-interface-graph.json`.

## K. Durable `+0x1B0`

**FALSE_DEVICE_ALIAS.** `0x007253F1` stores return of `0x0071D300` (feature/index vs 3), after DEVICE was already used for SetRenderState. Not a device pointer. **UNMAPPED** as durable device alias. No renderer link.

## L–M. Handoff / angr

Strongest candidate: helper itself (list select). UC: **NO_ORDINARY_DEVICE_BRIDGE**.  
angr (targeted): agrees no DEVICE in Draw/helper windows — **NEGATIVE_STRONG** where decomp recovers renderer without DEVICE.

## N–Q. Resources / termini / frame

Resource provenance: not established.  
Raw-device Draw: **NO**.  
Frame root: **NO_COMMON_ROOT_FOUND**.  
Ordering: EndScene→Present on DEVICE **PROVEN**; BeginScene→engine Draw→Present **UNKNOWN**.

## R. Init dependencies

Ctor `0x007B5020` is ordinary; does not read DEVICE. Vector init via `0x007A45B0`.  
`0x00686030`: nearby sibling of frozen `0x00686000`, MEDIUM/non-coherent body, used in **dtor only** — **UNKNOWN_NON_ORDINARY_BODY**, not equated to the frozen helper.

## S–V. Boundary / seam / decision / estimate

| Item | Value |
| --- | --- |
| Graphics boundary | **MIXED_BOUNDARY** (raw D3D9 Present/Clear vs engine Draw) |
| POST_INIT_SEAM | **PARTIAL_POST_INIT_SEAM** |
| D3D9 justified | **NO** |
| Engine-backend adapter justified | **NO** |
| First frame | **UNBOUNDED** / **UNBOUNDED** |

Highest remaining uncertainty: **who inserts ENGINE_GFX_IFACE_00 into the vector, and what concrete vtables/method bodies those objects use** (especially whether they eventually read `0x013C6510`).

## W. Recommended Phase 23

**EXPAND RENDERER STATE PROVENANCE** — map vector insert/push sites and concrete iface constructors/vtables; only then reassess backend→device handoff.

Artifacts: `phase22-raw.json`, `angr/renderer-phase22.json`, `renderer-interface-graph.json`, this report.
