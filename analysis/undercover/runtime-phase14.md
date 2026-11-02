# Runtime phase 14

`0x00686000` is an unavailable protected or external dependency. It was not lifted, executed, or replaced with `malloc`, `new`, `calloc`, a guest heap, or another ordinary function. `0x0055FF30` was not implemented. Protected sections were not read. The game executable was not started.

## A. External-helper graph cut

The reachable high-confidence graph has 6,498 functions after import thunks are excluded. A function is a direct caller only when its control-flow walk reaches an `E8` to `0x00686000`. That is 19 functions and 42 sites. Phase 13's 44 reachable sites include two more that lie in an address span the walk does not enter. The other calls among the 249 are in medium-confidence functions, unreachable high-confidence functions, or the same kind of gap.

Rejecting every path that reaches the helper removes 42 functions. It does not split the remaining graph into a small island. Details and the twenty largest remaining closures are in `external-helper-cut.md`.

## B. MUST / MAY / independent

| class | functions |
| --- | --- |
| `MUST_REACH_EXTERNAL_HELPER` | 11 |
| `MAY_REACH_EXTERNAL_HELPER` | 31 |
| `NO_PATH_TO_EXTERNAL_HELPER` | 6,456 |

`MUST` means every bounded walk to a return hits the helper or a callee already classified `MUST`. `MAY` means at least one walk hits it and at least one return does not. `0x00830380` is `MUST` with 16 sites. `0x0072C2A0` is `MAY` with 8 sites. One `MUST` function, `0x00782570`, does not call the helper itself.

## C. Largest independent ordinary islands

The largest direct-call closure with no path to the helper is `0x009DA970`, 755 functions, depth 36. That is the Phase 10 closure that reaches a protected edge. It is independent of this helper and still not runnable.

The next closures in that size list, from `0x009BBEC0` at 479 down through `0x009BF990` at 389, still carry unknown call targets. The largest closure whose recorded imports are only implemented helpers is `0x0099DCD0` at 102, and that closure has 141 indirect calls.

## D. Alternate initializer roots

`0x009E8AD0`, the leaf that fills `0x0189D1A4`, does not call the helper. Its consumers still need the object field whose writer follows the helper. No new initializer was found that publishes `[0x01311E1C]`, the flag `0x0072E5D0` reads before it calls the graphics method. That dword has reads and address-taken sites and no absolute store. The address-taken sites were not followed into register-relative stores.

The runnable independent roots remain `0x00B01EB0` (19 functions) and `0x00968D10` (31 functions, returning path enters 6). Both were executed in Phase 10. Neither reaches the helper.

## E. Direct3DCreate9 backward graph

| step | address | class | confidence |
| --- | --- | --- | --- |
| only caller of the high function | `0x00766730` | `CONFIDENCE_BLOCKED`, also reads `fs:[0x2C]` | medium, unreachable |
| high caller of the create method | `0x0072E5D0` | `MISSING_INITIALIZATION` on `[0x01311E1C]`, then `CONFIDENCE_BLOCKED` through its callee | high, unreachable; the walk from its entry reaches the call |
| create method | `0x0072E340` | `UNKNOWN_INDIRECT` then `IMPORT_BLOCKED` | medium, score 80, 24 recorded instructions, no recorded return |
| import | `0x0087A79C` | `Direct3DCreate9`, stdcall, one argument | high metadata, not implemented |

`0x0072E340` was not promoted. The score is high enough, and the branches that were walked land on instruction boundaries, but the recorded walk does not terminate in a return. The later bytes do contain the import call. Treating the unread tail as part of a high-confidence function would be a special case. It was not made.

No edge in this chain is `EXTERNAL_HELPER_DEPENDENT`. No edge before the import is a protected section.

## F. Graphics global state

| global | class | evidence |
| --- | --- | --- |
| `0x00B615C4` | `PE_INITIAL_VALUE` | `.rdata` dword `0x008AA3AE`, no writer. The value is inside `0x008A9480`, not at its entry |
| `0x01311E1C` | `PROTECTED_OR_UNKNOWN` | `.data` tail, mapped 0. Four reads, three address-taken sites, no absolute write. The create call is on the side that needs the value 1 |
| `0x00CEA3F0` | `PROTECTED_OR_UNKNOWN` | read by `0x0072DD00` and `0x0072DCA0`, no absolute write |
| `0x01882C34` | `PROTECTED_OR_UNKNOWN` | TLS index read through `fs:[0x2C]` in `0x00766730`. Hundreds of reads, no absolute write |
| `0x00CE69F8`, `0x00CC5B44` | `PE_INITIAL_VALUE` | `.data` addresses copied onto a local. No absolute write. Not dereferenced by this pass |

Nothing in this table was synthesized.

## G. Graphics Win32 dependencies

| API or operation | class |
| --- | --- |
| `Direct3DCreate9` | `KNOWN_ABI_MISSING_HLE` |
| three `call esi` before it, four stack dwords, callee cleanup | `UNKNOWN_ABI` |
| `call dword ptr [0x00B611D4]` and `[0x00B611D8]` in `0x00766730` | `UNKNOWN_ABI` |
| `fs:[0x2C]` TLS array | not implemented |
| window creation, message loop | `NOT_REACHED` on this prefix |

## H. Graphics resource dependencies

No file import is on the prefix from `0x0072E5D0` through `Direct3DCreate9`. The call through `[0x00CEA3F0]` is an indirect call, not a recorded filesystem import. No asset path was copied out.

## I. D3DX frontier

`D3DXMatrixMultiply` (`0x0087A7AE`, unknown convention, low confidence) has reachable high-confidence callers, all `NO_PATH_TO_EXTERNAL_HELPER`. `D3DXVec4Transform` and `D3DXVec3Transform` are the same kind of caller. They are not in the `0x0072E340` component. The other D3DX names in the import table have no reachable high-confidence caller in the function-map call lists. Wrappers were not implemented. Protected sections are not on those direct calls.

## J. Input, audio, filesystem, timing, threading

Reachable code that is independent of the helper does contain small filesystem, timing, and thread-start sites. `DirectInput8Create` and the graphics factory do not have a reachable high-confidence caller. Audio has reachable callers inside large functions, not a clean closure. The graphics predecessor is the one that reads the TEB TLS array, and that function is medium confidence. None of these frontiers is both independent of the helper and close to a visible milestone. Counts and the comparison are in `first-frame-frontier.md`.

## K. Post-initialization ordinary entries

The D3DX matrix callers consume three pointers and return. They do not call the helper and they do not create a device. Calling them would require the unknown D3DX convention and the pointer arguments. That state was not invented, and they were not executed.

`0x0072E340` itself consumes an object in `ECX`, the flag dword, and the indirect slot, then stores a factory pointer at `[object+0x10]`. The flag's producer is not an absolute ordinary store. The function was not called.

## L. Optional controlled execution

Not run. The largest ready island that avoids the helper is still `0x00B01EB0`, already executed in Phase 10 from zeroed ordinary state. No new ready island of useful size appeared. `0x0099DCD0` was not retried.

## M. First-frame feasibility

`Direct3DCreate9` is reachable in ordinary bytes without `0x00686000` and without entering a protected section. It is not reachable from the high-confidence graph, the function around it is medium confidence, and the high-confidence caller only reaches it when `[0x01311E1C]` is already 1. The full answers are in `first-frame-frontier.md`.

## N. Updated phase estimate

| | |
| --- | --- |
| `BEST_CASE_FIRST_FRAME_PHASE` | 20 |
| `LIKELY_FIRST_FRAME_PHASE_RANGE` | 22–28 |
| `MAJOR_UNCERTAINTY` | no absolute writer for the flag in front of the only `Direct3DCreate9` call, and no device or present call on that prefix |

There was no numbered first-frame estimate in the roadmap to preserve. A factory interface is not a frame. Best case still has to find the flag's producer, get through the medium-confidence walk, implement the factory, and only then a device and a present path.

## O. Recommended Phase 15

Follow the three address-taken sites of `0x01311E1C`, and the object `0x0072E5D0` expects in `ECX`, with the same ordinary-writer rules as Phase 11. Do not promote `0x0072E340`. Do not implement Direct3D, Win32 windowing, the filesystem, TLS, or a substitute for `0x00686000`. If those address-taken sites do not store the flag, say so and leave the graphics call unentered.
