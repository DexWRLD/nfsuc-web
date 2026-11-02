# First-frame frontier

Direct3D9 was not implemented. The game was not started. `0x00686000` was not used as a stand-in for anything on this path.

`Direct3DCreate9` has one direct call, at `0x0072E3B9`, inside `0x0072E340`. The bytes from the prologue through that call are:

1. `mov esi, dword ptr [0x00B615C4]`, then three `call esi`. Each passes four stack dwords and does not use `add esp`, so the callee is expected to pop them.
2. A conditional write through the `ECX` object, which both sides skip or fall through.
3. `call 0x0072DD00` and `call 0x0072DCA0`, then `add esp, 0x10`.
4. `push 0x20` and `call 0x0087A79C` (`Direct3DCreate9`). The return is stored at `[ebx+0x10]`. `ECX` was saved in `EBX` at entry, so this is a method on an existing object.

The address span of `0x0072E340` up to the next map entry `0x0072E5C0` contains no call to `0x00686000` and no call to `0x0055FF30`.

## Answers

1. The call is in ordinary `.text`, and that span does not call `0x00686000`. The reachable high-confidence graph does not contain `0x0072E340`. Its one direct caller is high-confidence `0x0072E5D0`, which is itself unreachable. There is an ordinary path in the file. There is no path from the reachable high-confidence graph.

2. The same path does not enter a protected section. It does read `fs:[0x2C]` in the medium function that calls `0x0072E5D0`, and it later calls `0x00695490`, which is not a function. That second call is after `Direct3DCreate9` in `0x0072E5D0`.

3. `0x0072E340` scores 80 and stays `MEDIUM_CONFIDENCE`. The high-confidence rule also requires a walk that ends in a return, a tail jump, an import jump, or a switch. The recorded walk is 24 instructions and does not record that ending. The same is true of `0x0072DD00` and of `0x00766730`, the only caller of `0x0072E5D0`. `0x0072E5D0` is high confidence and unreachable because that caller is medium. None of these was promoted.

4. Initialization the path reads before the create call:
   - `ECX` is the object the method stores the interface into.
   - `[0x01311E1C]` is compared with 1 in `0x0072E5D0`. The dword has four absolute reads and three address-taken sites, and no absolute write. The on-disk image is the `.data` tail, so the mapped value is 0. The walk that reaches `0x0072E340` is the side where the dword is already 1. The other side calls `0x009773B0` and jumps back.
   - `[0x00B615C4]` is the indirect target used three times before the import. It is a `.rdata` dword, value `0x008AA3AE`, with no ordinary write. That address is inside high-confidence `0x008A9480`, not at its entry. It was not called.
   - `[0x00CEA3F0]` is read by `0x0072DD00` and `0x0072DCA0` and has no absolute write.
   - `0x00766730` also reads `[0x01882C34]` as a TLS index through `fs:[0x2C]`. That global has hundreds of absolute reads and no absolute write.

5. The import on the create call is `Direct3DCreate9` from `d3d9.dll`, stdcall, one stack argument, the immediate `0x20`. It is not implemented. The earlier indirect slots are not in the import table.

6. No window-creation import appears on this prefix. The Win32-facing operations that do appear are the stdcall import above, the three callee-cleanup indirect calls, and the `fs:[0x2C]` TLS read in `0x00766730`.

7. No `fopen`, `fread`, or other file import appears between the start of `0x0072E5D0` and `Direct3DCreate9`. `0x0072DD00` calls through `[0x00CEA3F0]` when that dword is nonzero. This pass did not treat that as a filesystem call and did not read path strings out of the two `.data` addresses copied onto the stack (`0x00CE69F8`, `0x00CC5B44`).

8. Indirect calls on the way in: `[0x00B611D4]` in `0x00766730`, `[0x00B61188]` in `0x009773B0` if the flag is not 1, `[0x00B615C4]` three times in `0x0072E340`, and `[0x00CEA3F0]` in `0x0072DD00` / `0x0072DCA0`.

9. The shortest credible chain in the file is `0x00766730` → `0x0072E5D0` → `0x0072E340` → `Direct3DCreate9`. It is not a chain the reachable graph can enter, and with the flag dword left at 0 the middle function does not reach the create call.

10. The implementation that would move a first presented frame is still further than this call. `Direct3DCreate9` returns the factory interface stored at `[object+0x10]`. A device, a swap chain, and a present call are not on this prefix. The nearest unfinished ordinary question is the missing store to `[0x01311E1C]` and the object passed in `ECX`.

## Prerequisite counts

Along `0x0072E5D0` → `0x0072E340` → the import, counting the medium caller and the two ordinary calls immediately before the import:

| blocker | functions |
| --- | --- |
| runnable now, through to the import | 0 |
| blocked by a known import | 1, `Direct3DCreate9` itself |
| blocked by an indirect call on the prefix | `0x0072E340`, `0x009773B0`, `0x00766730`, `0x0072DD00` |
| blocked by `0x00686000` | 0 |
| blocked by another protected or non-function target before the import | 0 |
| confidence-limited | `0x00766730`, `0x0072E340`, `0x0072DD00` |
| missing initialization | `[0x01311E1C]`, the `ECX` object, `[0x00CEA3F0]`, and the TLS index `[0x01882C34]` |

`0x00695490` is called from `0x0072E5D0` after the create call. It is the same non-function rejected in Phase 11. It blocks finishing that caller. It does not sit in front of the import.

## D3DX

The D3DX thunks are a different component. Reachable high-confidence callers of `D3DXMatrixMultiply`, `D3DXVec4Transform`, and `D3DXVec3Transform` are `NO_PATH_TO_EXTERNAL_HELPER`. Their convention in the import metadata is unknown. They do not call `0x0072E340`, and `0x0072E340` does not call them. Texture and shader D3DX calls found earlier remain in unreachable or medium functions. None of these wrappers was implemented.

## Other frontiers, reachable and independent of the helper

| frontier | what the reachable graph actually contains | helper |
| --- | --- | --- |
| input | `DirectInput8Create` sites are in medium functions or in unreachable high-confidence `0x0088113A` | not on those sites |
| audio | reachable high-confidence callers exist, including inside `0x00947B10`; no clean closure | no path from the small measured callers |
| filesystem | Phase 10's clean closure is 2 functions at `0x00A07D60`; other `fopen` sites exist in large functions | the small closure has no path |
| timing | Phase 10's clean closure is the one-function `0x00B0C040` (`_time64`); `GetTickCount` has a reachable caller | no path |
| threading / TLS | `_beginthreadex` has reachable high-confidence callers; `fs:[0x2C]` appears on the graphics predecessor, which is medium | the reachable thread callers have no path |

None of these is a shorter route to a presented frame than the graphics chain, and none of them is runnable through to a visible milestone. The graphics chain is the one that names `Direct3DCreate9`. It is also the one that cannot be entered from documented state.

## Estimate

The docs did not carry a numbered first-frame phase. From this cut:

| | |
| --- | --- |
| `BEST_CASE_FIRST_FRAME_PHASE` | 20 |
| `LIKELY_FIRST_FRAME_PHASE_RANGE` | 22–28 |
| `MAJOR_UNCERTAINTY` | `[0x01311E1C]` has no absolute writer, and the only `Direct3DCreate9` call is in an unreachable medium-confidence function behind that dword and an indirect call |

Best case assumes the flag and the `ECX` object have an ordinary producer still to be found, and that a later phase then implements the factory, the device, and a present path. The range is wider because that producer is not in the absolute-store set, and because device creation was not on this prefix.
