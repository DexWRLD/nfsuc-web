# Undercover initial state required by ordinary code

This list comes from ordinary `.text` and from the Phase 10 runs. Protected startup was not entered, and no global was given a value it does not have on disk.

The image's `.data` virtual tail, from `0x012A6000` upward, is zero because the file copy is shorter than the virtual size. A zero there is the mapped initial state, not a value invented for the run.

## Globals

| guest address | on-disk value | what ordinary code does | source |
| --- | --- | --- | --- |
| `0x0188DAFC` | byte 0 | Compared with 0 by many functions, including `0x00925C90`. `0x00B523E0` contains `mov byte ptr [0x0188DAFC], 1` at `0x00B551A3`. | KNOWN_WRITER_IN_ORDINARY_TEXT |
| `0x0189D1A4` | dword 0 | `call dword ptr [0x0189D1A4]` in `0x0099DCD0` at `0x0099DCEB`, and at other ordinary sites such as `0x0098F05C`. No absolute store of this address was found in ordinary `.text`. | NO_ORDINARY_WRITER_FOUND |
| `0x0189BF08` | dword 0 | Read by `0x0099DCD0` on the path that skips the indirect call (`mov eax, dword ptr [0x0189BF08]`). Not written by the Phase 10 runs. | NO_ORDINARY_WRITER_FOUND |

`0x0188DAFC` stayed 0 during both runs of `0x00968D10`. The writer `0x00B523E0` was not called. Setting the flag to 1 would be synthesizing state, so the heavy side of those compares was not taken.

## Harness memory

| state | role |
| --- | --- |
| stack `0x03000000`–`0x03010000` | HARNESS_OWNED. `0x00968D10` calls `0x0087B570` with EAX `0x3F34` to probe that stack, then stores a stack address at `[object+0x184]`. |
| object at `0x03001000` | HARNESS_OWNED argument, not a game global. A zero object makes `0x009614C0` read address 0. An object whose field at `0x5C` points at a 4-byte harness pattern lets the same root return. |
| float buffer at `0x03000900` | HARNESS_OWNED argument to `0x00B01EB0`. |

## Import-provided state

No Phase 10 run reached an import that returns a pointer, a handle, or a tick count. `memset` is in the static closure of `0x00968D10` and was not reached by either input. Allocators, file handles, and `Direct3DCreate9` were not called.

## What this does not provide

A zero indirect slot at `0x0189D1A4` has no absolute writer in ordinary `.text`. Filling it with a guessed function would be invented startup state. The ordinary writer of `0x0188DAFC` shows that at least one later flag is produced by ordinary code, but that writer was not part of a closure that is runnable now.
