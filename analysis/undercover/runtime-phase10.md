# Undercover runtime phase 10

The high-confidence graph was measured, and the largest closures the current runtime can enter were executed. The game was not started. Protected sections stayed unmapped. No global was assigned a value other than the mapped image or a harness argument.

Static closure sizes count reachable high-confidence callees. A run's unique-function count is the functions actually entered. Those numbers differ, because on-disk data and the arguments prune the path.

## A. Runtime-readiness classification

Reachable high-confidence functions, excluding import thunks: 6,498. Source functions: 1,679.

| label | source closures | largest closure at any root |
| --- | --- | --- |
| UNRESOLVED_INDIRECT_CALL | 903 | 320 at `0x009B3110` |
| READY | 394 | 19 at `0x00B01EB0` |
| PROTECTED_BOUNDARY | 203 | 755 at `0x009DA970` |
| TLS_BOUNDARY | 80 | 174 at `0x00864E20` |
| UNKNOWN_RUNTIME_DEPENDENCY | 56 | 16 at `0x009D0EE0` |
| KNOWN_IMPORT_MISSING_HLE | 26 | 8 at `0x009C58E0` |
| READY_WITH_IMPLEMENTED_IMPORTS | 14 | 31 at `0x00968D10` |
| UNKNOWN_IMPORT_ABI | 3 | 3 at `0x0074D3B0` |
| RESOLVABLE_INDIRECT_CALL | (not a source label in the top cut) | 8 at `0x00908D42` |
| NETWORK_BOUNDARY | none as the first label of a source | 5 at `0x00895D70` |
| FILESYSTEM_BOUNDARY | none | 2 at `0x00A07D60` |
| TIMING_BOUNDARY | none | 1 at `0x00B0C040` |
| MEMORY_BOUNDARY | none | 1 at `0x00A07C50` |
| GRAPHICS_BOUNDARY | none | none |

The first label hides later blockers. The 755-function closure is labeled protected because it reaches one instruction, and it also has hundreds of indirect calls and several missing imports.

## B. Top frontier closures

The twenty largest distinct source closures are in `runtime-frontier.md`. They run from 755 functions down to a few hundred, and almost all are `PROTECTED_BOUNDARY` or `UNRESOLVED_INDIRECT_CALL`. The sizes worth acting on are the any-root extremes:

| question | closure | functions | depth |
| --- | --- | --- | --- |
| A. Fully runnable now | `0x00B01EB0` | 19 | 5 |
| A, with an implemented import in the static set | `0x00968D10` | 31 | 4 |
| B. Runnable if one known helper is added | `_wassert` only, largest such closure | 16 | 6 |
| B, spread across many small closures | `_CIsqrt` only | 62 functions in 41 closures | — |
| C. Blocked by a major subsystem as its first clean label | network `0x00895D70` | 5 | 4 |
| D. Reaches protected code | `0x009DA970` | 755 | 36 |

No helper was added. `_wassert` is not a useful computation, and `_CIsqrt` does not unlock one large closure. `sprintf` and `printf` are not small helpers.

## C. High-leverage missing imports

The unlock count is the number of functions in closures whose only missing piece is that import. From `import-frontier.md`:

| symbol | functions unlocked | largest single closure |
| --- | --- | --- |
| `_CIsqrt` | 62 | under 8 |
| `_wassert` | 22 | 16 |
| `sprintf` | 6 | 6 |
| `strchr` | 5 | 5 |

`malloc` has 66 direct sites and appears in 50 high roots, and it unlocks 0 otherwise-clean functions. `free` is a one-function closure. `_crt_debugger_hook` appears in 581 roots and unlocks 0, because those roots have other blockers.

## D. Largest fully-ready closure

`0x00B01EB0`, 19 high-confidence functions, depth 5, no imports, no indirect calls, no protected or TLS edges. The static set includes `0x00AFEE50`, `0x00AFF2E0`, `0x00AFF620`, `0x00AFF770`, `0x00AFF830`, `0x00AFFA00`, `0x00B00650`, and several `0x00B1A*` callees.

`0x00968D10` is larger and its only import is `memset`, which is already implemented. That import was not reached by the inputs below.

## E. Execution results

Harness: `tools/uc_phase10_test.py`. Image: ordinary sections only, plus a private stack at `0x03000000`. Limits: 100,000 calls, depth 64, 10,000 imports, 8 indirect dispatches, 5,000 ms. The trace keeps the last 64 events. Both identical-input repeats matched.

### `0x00968D10`

Static closure 31. ECX is a 0x800-byte harness object. The one stack argument points at two dwords. `0x0087B570` probes the stack for `0x3F34` bytes. `[object+0x184]` receives a stack address (`0x0300B0E4` on the zero-object run).

| input | result | calls | unique | depth | EIP | ESP |
| --- | --- | --- | --- | --- | --- | --- |
| object zero, argument dwords 0,0 | unmapped read of address 0 | 5 | 5 | 3 | `0x009614D3` | `0x0300B09C` |
| `[object+0x5C]` points at bytes `01 02 03 04`, bytes at `0x6F` and `0x73` are 1, byte at `0x77` is 3, argument dwords `0x10`,`0x20` | returned | 7 | 6 | 3 | `0x00DEC0DE` | `0x0300F000` |

Zero-object functions, in entry order: `0x00968D10`, `0x0087B570`, `0x00967680`, `0x009674B0`, `0x009614C0`. The fault is `movzx ebx, byte ptr [esi]` in `0x009614C0` with ESI 0. `0x00967680` stored a zero pointer and `0x009614C0` dereferenced it. Repeat matched, including the fault EIP and the object hash `0x98F10318`.

The second input also enters `0x009677E0` and returns. EAX is `0xFFFFFFFF`, which is the failure value `0x009674B0` produces when its argument does not match `0xFFE00000`. Unique functions: the five above plus `0x009677E0`. Hash `0x0E5371DD`. The repeat matched. Imports executed: 0. Indirect dispatches: 0. The byte at `0x0188DAFC` stayed 0.

### `0x00B01EB0`

| input | result | calls | unique | depth |
| --- | --- | --- | --- | --- |
| word at `[struct+4]` is 0, other pointers 0 | returned, buffer hash `0x4D7705C5` | 7 | 6 | 3 |
| word is 1 and `[ebp+0xC]` points at 16 harness floats of 1.0 | fault address `0x40` at EIP `0x00AFF32B` | 2 | 2 | — |

The completing functions are `0x00B01EB0`, `0x00AFF2E0`, `0x00AFF770`, `0x00AFFA00`, `0x00B1AAE0`, `0x00AFF830`. ESP after return is `0x0300EFF0`, 16 bytes below the entry value, which is the four cdecl arguments still on the stack. The count-1 path enters `0x00AFF2E0` and then faults. The two inputs do not take the same path.

## F. Deepest controlled run

Root `0x0099DCD0`. Its static closure is the largest set whose imports are already implemented and whose only blocker class is an indirect call: 102 functions, depth 14, imports `memset`, `memcpy`, and `strlen`.

The input was `[ebp+8] = 0`, `[ebp+0xC] = 2`. The function compares that second argument with 2 and then executes `call dword ptr [0x0189D1A4]`.

## G. First unsupported boundary

| field | value |
| --- | --- |
| category | `UNRESOLVED_INDIRECT_CALL`, through `MISSING_INITIALIZATION_STATE` |
| guest function | `0x0099DCD0` |
| guest EIP | `0x0099DCEB` |
| target | 0, the dword at `0x0189D1A4` |
| call chain | `0x0099DCD0` |
| calls / depth / imports / indirect | 1 / 1 / 0 / 1 |
| required state | the mapped dword is 0; no absolute store of `0x0189D1A4` was found in ordinary `.text` |
| subsystem | not a filesystem, heap, timer, or graphics call |

The dispatcher recorded the target and returned. It was not given a guessed callee. The trace window ends with an indirect-call event whose EIP is `0x0099DCEB` and whose target is 0.

## H. Indirect-dispatch frontier

Sites found by a CFG walk of the 6,597 high-confidence functions:

| kind | sites |
| --- | --- |
| D. register (`call`/`jmp` reg) | 9,812 |
| D. unknown memory form | 5,183 |
| E. slot in a protected section | 86 |
| B. slot whose on-disk dword is an import thunk | 13 |
| A/B. generated function stored in an ordinary slot | 0 |

The 13 import-slot sites are calls through a slot that already names a thunk, including `malloc`. They are not a large closure. Category A/B had nothing to hand to the generated-function dispatcher. The 102-function closure's first target is 0, so it was not resolved.

Jump tables that the lifter already lowers still appear in the D counts when the walk sees an indirect jump. The executed ready closures contained no indirect call on the paths that ran.

## I. Memory and allocators

`malloc` 66 sites, `free` 106, `_aligned_malloc` 2, `_aligned_free` 1. No otherwise-clean closure of more than one function is blocked only by an allocator. The one-function `free` closure is `0x00A07C50`. A guest heap was not added. Nothing in the executed paths needed one. Guest pointers used by the harness are guest addresses in the private stack region.

## J. Filesystem

`fopen` 5 sites, `fclose` 5, `fwrite` 13. The largest closure whose first clean label is filesystem is 2 functions at `0x00A07D60` (`fwrite` and `_vsnprintf`). `.rdata` contains on the order of 240 backslash-or-slash strings and about 140 strings with a short list of asset extensions. Those strings were not copied out. The section is read-only in the image. The executed paths did not call a file import. A filesystem runtime was not built.

## K. Timing

`_time64` has 8 sites and a one-function closure at `0x00B0C040`. `GetTickCount` has 2 sites and appears in 5 high roots, none of them blocked only by it. The calls that exist are a CRT wall-clock function and a millisecond counter. No sleep or yield import showed up as a clean closure. No timing semantics were invented, and neither import was implemented.

## L. Initialization-state requirements

See `required-initial-state.md`. The flag at `0x0188DAFC` has an ordinary writer, `0x00B523E0`, and it was left at its on-disk 0. The indirect slot at `0x0189D1A4` has no absolute ordinary writer and is 0. The harness object and stack are harness-owned.

## M. Graphics frontier

See `graphics-frontier.md`. `Direct3DCreate9` has one call, inside unreachable medium-confidence `0x0072E340`. D3DX calls exist from a few small high-confidence functions and stay unknown ABI. No high-confidence closure is labeled graphics. D3D9 is not the next boundary in this graph.

## N. Protected-boundary findings

`0x00804080` is `jmp dword ptr [0x023AF2F8]`. That address is in `.securom`. Reaching it is why the 755-function closure of `0x009DA970` is labeled `PROTECTED_BOUNDARY`. The same closure has 995 indirect sites, 15 unknown edges, and missing imports including `sprintf`, `strcpy`, `strncpy`, `vsprintf`, `_snprintf`, `_wassert`, and `_crt_debugger_hook`. Protected code is not its only blocker.

A read of `0x01FC7000` still faults as `Sitext`. The PE entry was not used.

## O. Recommended next subsystem

Do not start with filesystem, heap, timing, or D3D9. Each of those is a clean closure of at most a handful of functions, or, for D3D9, a call outside the high-confidence graph.

The large ordinary closures stop on unresolved indirect calls. The one that is otherwise ready, 102 functions, stops on a zero `.data` slot with no absolute ordinary writer. A dispatcher cannot invent that target. The next phase should stay on ordinary CPU and runtime work: indirect targets that are concrete at runtime, and ordinary writers of the state those calls need. That is not a graphics, file, heap, or timer bring-up.
