# Roadmap

Protected startup is not a milestone. `Sitext` holds the PE entry point. Reaching ordinary `.text` from that entry would mean following the protected startup, and this project does not do that. A later, lawful, non-circumvention approach would be a separate decision, not the next item on this list.

| Milestone | State | What it is |
| --- | --- | --- |
| M0 PE analysis | done | `tools/uc_analyze.py`, `analysis/undercover/nfs-pe.md` |
| M1 `.text` static analysis | done | `tools/uc_code_analyze.py`, `analysis/undercover/code-analysis.md` |
| M2 representative static recompilation | done | Phase 3: 83 of 100 roots generated, and all 83 compiled. Phase 4 rerun of the same roots: 86 generated, 86 compiled. `repz ret` and `movmskps` are lowered |
| M3 validated `.text` translation | done | Phase 5 started from the Phase 4 list of 6,604. Phase 16 repaired CFG discovery: 22,779 HIGH, 22,770 generated, 22,770 compiled. Remaining generation failures are unsupported opcodes, not the old 24-instruction cap |
| M4 native runtime proof of concept | done | Phase 6 ran `0x00721070`. Phase 7 runs a real `memset` call, a two-function call, and a three-function call on a mapped ordinary image. The game does not run |
| M5 Win32 compatibility expansion | in progress | Real Undercover code has entered cdecl `memset`, `strlen`, `memcmp`, and `strcmp`, and the ST(0) helpers `_CIsin`, `_CIcos`, and `_CIacos`. Phase 16 keeps `call 0x00686000` a narrow cut (74 must / 139 may / 22,394 independent). `Direct3DCreate9` is reachable HIGH in `0x0072E340` and still not enterable. Unknown imports fail closed. `win32_call` was not changed |
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
4. ORDINARY OBJECT INITIALIZATION. Stopped. The writers of `0x0189DA84` and `[0x0189D0A0+8]` follow `call 0x00686000`. That address is an unavailable protected or external dependency. It is not substituted.
5. DEPENDENCY CUT. Phase 14. Eleven reachable functions must hit that call, 31 can hit it on some walk, and 6,456 have no path to it. The 102-function closure at `0x0099DCD0` is in the last set and still needs the object field this call feeds. It is not the primary frontier.
6. FUNCTION DISCOVERY REPAIR. Phase 16. CFG-aware fact walk; old 24-instruction cohort mostly promoted; compiler closure holds.
7. INDEPENDENT SUBSYSTEM FRONTIERS. `Direct3DCreate9` is reachable HIGH and independent of `0x00686000`, but not enterable: flag=1 writer disconnected, callback slots invalid, TLS unwitten, object zeroed. Direct3D was not implemented.
8. FIRST FRAME, if a path becomes available. Not started. A factory pointer is not a frame.

The strategy is ordinary static recompilation, then ordinary runtime islands, then this dependency cut, then independent subsystem frontiers, then a first-frame path if one is available.

This sequence is not a claim that the game plays.
