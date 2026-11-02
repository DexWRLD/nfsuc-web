# Phase 11

Ordinary initialization provenance for the zero slot at `0x0189D1A4`. Protected sections were not read or executed. The game was not started. The harness did not store a guessed address into the slot.

## A. References to `0x0189D1A4`

906 high-confidence indirect calls and one high-confidence absolute write. No read, no address-taken encoding, no indirect jump, and no sliced alias store. Details and the site list are in `global-0189d1a4.md`. The write is `0x009E8AD0` at `0x009E8B16`: `mov dword ptr [0x0189D1A4], 0x009E78C0`.

## B. Expected callback shape

All 906 sites are followed by `add esp, 0x0C`. Three caller-cleaned stack arguments. The inspected sites do not pass ECX or EDX and do not consume EAX. The immediate stored in the slot, `0x009E78C0`, returns immediately when `0x0189DA84` is 0. When that pointer is nonzero it forwards the three arguments through `[object+0x58]`'s vtable slot `+0x0C`, with ECX left as that object.

## C. Potential writers

One ordinary writer, the absolute store above. The backward slice found no alias. `memcpy` / `memmove` of a range that happens to cover the slot was not shown; this function does not call either.

## D. Registration

`0x009E8AD0` is the registration. It writes 49 immediates into `0x0189D198` through `0x0189D270`. Thirty-four distinct values. Ten stores are `0x00695490`, which does not disassemble as code. Five are `0x00864DF0` (`xor eax, eax; ret`). The rest are ordinary addresses in the same `.text` gap, including `0x009E78C0`.

## E. Function-pointer tables

2447 static runs of at least four `.text` dwords in ordinary `.rdata` and file-backed `.data`. Largest: `0x00B63548` (542), `0x00BC7200` (332), `0x00B62EF0` (302). They are image bytes, not runtime stores from this phase. `0x00B523E0` sits in a 20-dword run at `0x00B633EC`. No absolute `.text` reference to that run's first address was found.

## F. `0x0188DAFC` and `0x00B523E0`

The byte is 0 in the image. `0x00B551A3` is `mov byte ptr [0x0188DAFC], 1`, inside the address span of high-confidence `0x00B523E0` (next discovered function `0x00B55950`). The store is reached in the linear window only after `cmp dword ptr [esp], 1` and `call 0x00920C80` with ECX equal to the flag's address. `0x00B523E0` has no direct caller, uses `fs:[0]`, mixes a cookie from `0x01285688`, and calls `0x0087B452` eleven times. It was not executed. The flag stayed 0 during the leaf run. This is an ordinary global, not Windows TLS.

## G. Graph

See `ordinary-init-graph.md`. The executed node is `0x009E8AD0`. Its caller chain is ordinary `.text` and ends, at the top of the walked edges, in medium-confidence `0x008101B0`. The high-confidence discovered graph does not call the leaf.

## H. Roots

`0x009E8AD0` is the root that can run with no inputs. `0x009E9160` is the object routine that calls it and is not isolated. `0x00B523E0` is a separate high-confidence function referenced from `.rdata`, and it is not an isolated leaf.

## I. Controlled execution

`tools/uc_phase11_test.py` maps the ordinary image, runs `0x0099DCD0` once while the slot is still 0, then runs `0x009E8AD0` with only a harness stack and a synthetic return, then runs `0x0099DCD0` again. The slot is not written by the harness.

Before the leaf: status indirect, EIP `0x0099DCEB`, target 0, slot 0, callback not entered.

Leaf: status completed, EIP `0x00DEC0DE`, ESP `0x0300F000`, 49 global writes. The slot write is EIP `0x009E8B16`, function `0x009E8AD0`, old 0, new `0x009E78C0`.

## J. `.data` diff

The zero-filled `.data` tail `0x012A6000`..`0x018B1E74` gained 49 ranges, 146 bytes. Each range is one of the leaf's dwords. The top byte of each little-endian pointer was already 0, so a dword store shows as three changed bytes, except `0x0189D248` = `0x009E7B00`, whose extra zero byte leaves two. No other BSS range changed. `0x0188DAFC` stayed 0.

## K. Newly initialized function pointers

All 49 stores are addresses in the ordinary `.text` VA range. The one required by `0x0099DCD0` is `0x009E78C0`, and that function was lifted from those bytes before dispatch. `0x00695490` was not dispatched: the bytes are not a function.

## L. Retry of `0x0099DCD0`

The slot was nonzero, in ordinary `.text`, and corresponded to the lifted body, so dispatch entered it.

Path: `0x0099DCD0` -> `0x009E78C0` (returns, because `0x0189DA84` is still 0) -> `0x009B6290` with ECX = `0x0189D0A0` -> `0x009E4B10`.

Stop: status access fault, EIP `0x009E4B49`, address `0xFFFFFFFC`. The instruction is `mov eax, dword ptr [edx + eax*4 - 4]`. EDX came from `[object+8]` and that field is 0. Calls 5, unique 4, depth 4. The old boundary `0x0099DCEB` was passed.

`0x0189D0A0` is address-taken 219 times and has no absolute read or write. Its fields were not filled by the leaf.

## M. Coverage of the Phase 10 closures

Absolute BSS operands in the recorded instruction window of each closure. Register-indirect sites are not in this table. "Known" means an ordinary absolute write encoding exists, or the leaf writes the slot.

| Closure | Root | Zero function-pointer slots | Known writers | Other zero dword globals | Known | Zero flag bytes | Known |
| --- | --- | --- | --- | --- | --- | --- | --- |
| READY | `0x00B01EB0` | 0 | 0 | 0 | 0 | 0 | 0 |
| READY_WITH_IMPLEMENTED_IMPORTS | `0x00968D10` | 0 | 0 | 67 | 2 | 1 | 1 |
| indirect only | `0x0099DCD0` | 3 | 3, all written by the leaf | 4 | 4 | 0 | 0 |
| TLS-labelled | `0x00864E20` | 0 | 0 | 27 | 20 | 0 | 0 |
| protected-reaching | `0x009DA970` | 24 | 21 | 95 | 73 | 9 | 8 |

The 102-function closure's three absolute callback slots are initialized by the leaf. Its other indirects are register-indirect. The 31-function closure's zero state is mostly data pointers, not this callback slot.

## N. No ordinary writer

`0x0189D0A0`'s fields: the address is taken, and no absolute writer of the object was found. `0x0189BF08` is still unread by the executed path and is not in the leaf's stores. The slice does not prove those have no writer through a pointer.

## O. Protected or unknown

The leaf and the callback are ordinary `.text`. The top walked caller is medium-confidence ordinary code, not a protected section. `0x00695490` is ordinary `.text` bytes that are not code; the leaf stores that address anyway. That is not a license to call it. `0x00B523E0` was left unrun because of `fs:[0]` and the cookie, not because it is protected.

## P. Phase 12

Follow the ordinary object at `0x0189D0A0` and the writer of `0x0189DA84` (`0x009E9396`, fed by `0x009E9160`). Both are ordinary code. Do not invent their contents, do not dispatch `0x00695490`, and do not start filesystem, heap, timing, Direct3D, or TLS. `_CIsqrt` was not reached.

## `_CIsqrt` and TLS

`_CIsqrt` was not implemented. The executed path does not call it.

`0x0188DAFC` was not written. The leaf's stores of `0x00864DF0` are ordinary function pointers (`xor eax, eax; ret`), not TLS slots. Windows TLS was not implemented.
