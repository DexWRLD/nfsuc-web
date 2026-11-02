# Ordinary initializer graph

Nodes below are ordinary functions in unprotected `.text`. Edges are direct calls or a global the callee writes and a later reader uses. None of these nodes were required to be reachable from the protected PE entry.

## Leaf that fills the callback slots

`0x009E8AD0` is a straight-line GLOBAL_STATE_WRITER / TABLE_INITIALIZER. It writes 49 dwords and returns. It reads nothing, calls nothing, and does not touch a protected address.

Direct-call edge: `0x009E9160` at `0x009E9305` calls it, then returns the object in EAX. `0x009E9340` calls `0x009E9160` and then executes `mov dword ptr [0x0189DA84], eax` (and a zeroing store on the other branch). `0x009E9420` calls `0x009E9340`. `0x008104E9`, in medium-confidence `0x008101B0`, calls `0x009E9420`.

`0x009E9160` also calls several other ordinary functions and writes fields through ECX. It was not executed. Its dependencies are an object and those callees, which this pass did not show the current runtime can supply.

## Source of important globals

| Global | Initial PE value | Source after this pass |
| --- | --- | --- |
| `0x0189D1A4` | 0 | ORDINARY_DIRECT_WRITER `0x009E8AD0` / `0x009E8B16` stores `0x009E78C0` |
| the other 48 dwords in that same leaf | 0 | ORDINARY_DIRECT_WRITER `0x009E8AD0` |
| `0x0189DA84` | 0 | ORDINARY_DIRECT_WRITER `0x009E9396` stores EAX, and `0x009E939D` / `0x009E7CCE` store 0. Not executed |
| `0x0189DA88` | 0 | ORDINARY_DIRECT_WRITER `0x009E9414` stores EAX. Not executed |
| `0x0189D0A0` | 0 object | ADDRESS_TAKEN 219 times. No absolute read or write of the dword. Field stores, if any, are through the pointer |
| `0x0188DAFC` | 0 | ORDINARY_DIRECT_WRITER `0x00B551A3` stores the byte 1, inside the span of `0x00B523E0`, and only after a compare and a call. Not executed |
| harness stack `0x03000000` | none | HARNESS_PROVIDED |
| callback targets | the immediates above | not HARNESS_PROVIDED |

`0x0189BF08`, the other branch of `0x0099DCD0`, is not written by `0x009E8AD0`. The executed retry took the argument-2 path and did not read it.

## Roots

Ranked by what they write and how they are reached, not by the protected entry:

1. `0x009E8AD0`. No incoming edge from the high-confidence discovered graph. One ordinary direct caller. Writes 49 function-pointer slots, including the slot the 102-function closure calls. No dependencies. This is the root that was executed.
2. `0x009E9160`. Calls that leaf and returns an object. Not a safe isolated run.
3. `0x00B523E0`. High-confidence, 355 instructions, no direct caller. Its address is a dword in the ordinary `.rdata` run `0x00B633EC`..`0x00B6343C` (20 `.text` pointers). The function installs an `fs:[0]` frame, mixes a cookie from `0x01285688`, and calls `0x0087B452` eleven times and `0x0087B640` once. The flag store is conditional. It was not treated as the same initializer as the callback table.

## Static pointer runs

Ordinary `.rdata` and file-backed `.data` contain 2447 runs of at least four dwords that point into `.text`. The largest are `0x00B63548` (542), `0x00BC7200` (332), `0x00B62EF0` (302), `0x00B62AF0` (221), and `0x00B62198` (211). They are static image dwords, not stores performed by this run. No semantic name is assigned. The 20-dword run that contains `0x00B523E0` has no absolute reference to its first address in ordinary `.text`.
