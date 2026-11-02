# Roadmap

Protected startup is not a milestone. `Sitext` holds the PE entry point. Reaching ordinary `.text` from that entry would mean following the protected startup, and this project does not do that. A later, lawful, non-circumvention approach would be a separate decision, not the next item on this list.

| Milestone | State | What it is |
| --- | --- | --- |
| M0 PE analysis | done | `tools/uc_analyze.py`, `analysis/undercover/nfs-pe.md` |
| M1 `.text` static analysis | done | `tools/uc_code_analyze.py`, `analysis/undercover/code-analysis.md` |
| M2 representative static recompilation | done | Phase 3: 83 of 100 roots generated, and all 83 compiled. Phase 4 rerun of the same roots: 86 generated, 86 compiled. `repz ret` and `movmskps` are lowered |
| M3 validated `.text` translation | in progress | 6,604 high-confidence functions, 6,532 generated, 6,532 compiled. Remaining real gaps: `lock xadd`, `lock cmpxchg`, `lock cmpxchg8b`, `psrldq`, `pslldq`, `punpcklqdq`, `pshufd`, `fstpnce` |
| M4 native runtime proof of concept | future | a host process that can call a lifted function with a real CPU struct. Not started. The game does not run |
| M5 Win32 compatibility expansion | future | MSVCR80 cdecl thunks are identified (`analysis/undercover/import-thunks.md`). `win32_call` is still stdcall-only |
| M6 Direct3D 9 compatibility | future | the game's device and resource calls on the existing renderer |
| M7 WebAssembly target | future | compile lifted C to Wasm |
| M8 WebGPU renderer integration | future | Direct3D 9 calls on the browser renderer |
| M9 browser filesystem, input, audio | future | the game's files, controls, and sound in the page |
| M10 playable browser proof of concept | future | not claimed, and not possible from the work above alone |

M3 is underway for the direct-call closure. It is not a translation of every byte in `.text`, and it does not start from the protected entry. M4 and later are not started. Nothing in M5–M10 runs the game. Protected startup stays off this list.
