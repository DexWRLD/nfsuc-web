# Roadmap

Protected startup is not a milestone. `Sitext` holds the PE entry point. Reaching ordinary `.text` from that entry would mean following the protected startup, and this project does not do that. A later, lawful, non-circumvention approach would be a separate decision, not the next item on this list.

| Milestone | State | What it is |
| --- | --- | --- |
| M0 PE analysis | done | `tools/uc_analyze.py`, `analysis/undercover/nfs-pe.md` |
| M1 `.text` static analysis | done | `tools/uc_code_analyze.py`, `analysis/undercover/code-analysis.md` |
| M2 representative static recompilation | done | Phase 3: 83 of 100 roots generated, and all 83 compiled. Phase 4 rerun of the same roots: 86 generated, 86 compiled. `repz ret` and `movmskps` are lowered |
| M3 validated `.text` translation | done | Phase 5: the Phase 4 list of 6,604 functions, 6,598 generated, 6,598 compiled. The six failures are data reached by a jump. `fstpnce` was not implemented. The map now has 6,597 HIGH functions |
| M4 native runtime proof of concept | future | a host process that can call a lifted function with a real CPU struct. Not started. The atomic helpers are still single-threaded. The game does not run |
| M5 Win32 compatibility expansion | future | Import metadata is in `analysis/undercover/import-abi.json` (199 thunks). `win32_call` is still stdcall-only and was not changed |
| M6 Direct3D 9 compatibility | future | the game's device and resource calls on the existing renderer |
| M7 WebAssembly target | future | compile lifted C to Wasm |
| M8 WebGPU renderer integration | future | Direct3D 9 calls on the browser renderer |
| M9 browser filesystem, input, audio | future | the game's files, controls, and sound in the page |
| M10 playable browser proof of concept | future | not claimed, and not possible from the work above alone |

M3 is the direct-call closure of ordinary `.text`. It is not a translation of every byte in `.text`, and it does not start from the protected entry. M4 and later are not started. Nothing in M5–M10 runs the game. Protected startup stays off this list.
