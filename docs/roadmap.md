# Roadmap

Protected startup is not a milestone. `Sitext` holds the PE entry point. Reaching ordinary `.text` from that entry would mean following the protected startup, and this project does not do that. A later, lawful, non-circumvention approach would be a separate decision, not the next item on this list.

| Milestone | State | What it is |
| --- | --- | --- |
| M0 PE analysis | done | `tools/uc_analyze.py`, `analysis/undercover/nfs-pe.md` |
| M1 `.text` static analysis | done | `tools/uc_code_analyze.py`, `analysis/undercover/code-analysis.md` |
| M2 representative static recompilation | done | Phase 3: 83 of 100 roots generated, and all 83 compiled. Phase 4 rerun of the same roots: 86 generated, 86 compiled. `repz ret` and `movmskps` are lowered |
| M3 validated `.text` translation | done | Phase 5: the Phase 4 list of 6,604 functions, 6,598 generated, 6,598 compiled. The six failures are data reached by a jump. `fstpnce` was not implemented. The map now has 6,597 HIGH functions |
| M4 native runtime proof of concept | done | Phase 6 ran `0x00721070`. Phase 7 runs a real `memset` call, a two-function call, and a three-function call on a mapped ordinary image. The game does not run |
| M5 Win32 compatibility expansion | in progress | Real Undercover code has entered cdecl `memset`, `strlen`, `memcmp`, and `strcmp`, and the ST(0) helpers `_CIsin`, `_CIcos`, and `_CIacos`. Phase 10 executed the 31-function and 19-function closures; the completing paths enter 6 functions. Phase 11 ran the ordinary leaf that fills `0x0189D1A4`. Phase 12 traced the next object field to a call whose target is not code. Unknown imports fail closed. `win32_call` was not changed |
| M6 Direct3D 9 compatibility | future | the game's device and resource calls on the existing renderer |
| M7 WebAssembly target | future | compile lifted C to Wasm |
| M8 WebGPU renderer integration | future | Direct3D 9 calls on the browser renderer |
| M9 browser filesystem, input, audio | future | the game's files, controls, and sound in the page |
| M10 playable browser proof of concept | future | not claimed, and not possible from the work above alone |

M3 is the direct-call closure of ordinary `.text`. It is not a translation of every byte in `.text`, and it does not start from the protected entry. M4 has executed ordinary functions, including calls between them and one real `memset`, in a harness. M5 has a convention-aware dispatcher. Lifted code has entered `memset`, `strlen`, `memcmp`, `strcmp`, `_CIsin`, `_CIcos`, and `_CIacos`, and Phase 10 has entered the larger `0x00968D10` and `0x00B01EB0` closures on the paths their arguments actually take. Neither starts the game. Protected startup stays off this list.

The order from here:

1. STATIC RECOMPILATION. Done for the ordinary high-confidence list.
2. ABI / CPU RUNTIME. Done for the tested paths: the integer helpers and the three ST(0) helpers.
3. ORDINARY CALLBACK INITIALIZATION. Demonstrated. `0x009E8AD0` fills `0x0189D1A4`, and `0x0099DCD0` enters that target.
4. ORDINARY OBJECT INITIALIZATION. Phase 12. The writers of `0x0189DA84` and `[0x0189D0A0+8]` are ordinary, and both depend on `0x0189DA88`. The only store to that global calls `0x00686000`, which is not code.
5. LARGE INITIALIZATION EXECUTION. Not started. It waits on that call.
6. GRAPHICS FRONTIER. `Direct3DCreate9` has one call, in a medium-confidence function that is not reachable from the high-confidence graph. This is not the next implementation.
7. FIRST FRAME. Not started. Nothing here renders.

This sequence is not a claim that the game plays.
