# Roadmap

Protected startup is not a milestone. `Sitext` holds the PE entry point. Reaching ordinary `.text` from that entry would mean following the protected startup, and this project does not do that. A later, lawful, non-circumvention approach would be a separate decision, not the next item on this list.

| Milestone | State | What it is |
| --- | --- | --- |
| M0 PE analysis | done | `tools/uc_analyze.py`, `analysis/undercover/nfs-pe.md` |
| M1 `.text` static analysis | done | `tools/uc_code_analyze.py`, `analysis/undercover/code-analysis.md` |
| M2 representative static recompilation | done | Phase 3: 83 of 100 roots generated, and all 83 compiled. Phase 4 rerun of the same roots: 86 generated, 86 compiled. `repz ret` and `movmskps` are lowered |
| M3 validated `.text` translation | done | Phase 5: the Phase 4 list of 6,604 functions, 6,598 generated, 6,598 compiled. The six failures are data reached by a jump. `fstpnce` was not implemented. The map now has 6,597 HIGH functions |
| M4 native runtime proof of concept | done | Phase 6 ran `0x00721070`. Phase 7 runs a real `memset` call, a two-function call, and a three-function call on a mapped ordinary image. The game does not run |
| M5 Win32 compatibility expansion | in progress | Real Undercover code has entered cdecl `memset`, `strlen`, `memcmp`, and `strcmp`, and the ST(0) helpers `_CIsin`, `_CIcos`, and `_CIacos`. Phase 10 executed the 31-function and 19-function closures; the completing paths enter 6 functions. Phase 11 ran the ordinary leaf that fills `0x0189D1A4`. Unknown imports fail closed. `win32_call` was not changed |
| M6 Direct3D 9 compatibility | future | the game's device and resource calls on the existing renderer |
| M7 WebAssembly target | future | compile lifted C to Wasm |
| M8 WebGPU renderer integration | future | Direct3D 9 calls on the browser renderer |
| M9 browser filesystem, input, audio | future | the game's files, controls, and sound in the page |
| M10 playable browser proof of concept | future | not claimed, and not possible from the work above alone |

M3 is the direct-call closure of ordinary `.text`. It is not a translation of every byte in `.text`, and it does not start from the protected entry. M4 has executed ordinary functions, including calls between them and one real `memset`, in a harness. M5 has a convention-aware dispatcher. Lifted code has entered `memset`, `strlen`, `memcmp`, `strcmp`, `_CIsin`, `_CIcos`, and `_CIacos`, and Phase 10 has entered the larger `0x00968D10` and `0x00B01EB0` closures on the paths their arguments actually take. Neither starts the game. Protected startup stays off this list.

The order from here, measured on the ordinary graph rather than chosen in advance:

1. LARGE NATIVE EXECUTION. Phase 10 measured the closures. Phase 11 separated static code readiness from runtime initialization readiness. The 102-function closure's first zero slot is written by ordinary `0x009E8AD0`. After that store, execution passes the old call and stops on a zero field of `0x0189D0A0`. The next work is more of that ordinary state, not a new subsystem.
2. RESOURCE/OS RUNTIME. Filesystem, heap, and timing imports exist, and their clean closures are one or two functions. They are not the current gate.
3. GRAPHICS FRONTIER. `Direct3DCreate9` has one call, in a medium-confidence function that is not reachable from the high-confidence graph. D3DX calls are a few small functions with an unknown convention. This is not the next implementation.
4. FIRST FRAME. Not started. Nothing here renders.
5. INPUT/SIMULATION. Not started.
6. FIRST DRIVE. Not started, and not implied by the steps above.

This sequence is not a claim that the game plays.
