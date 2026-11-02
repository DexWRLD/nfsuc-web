# nfsuc-web

Experimental research into static recompilation of the 32-bit Windows version of Need for Speed Undercover. The goal is a portable native build and, later, a WebAssembly build with a browser runtime. This repository does not run the game.

You supply your own legally obtained compatible installation. The game directory is an external input. It is read only, and nothing from it is committed.

Not affiliated with or endorsed by Electronic Arts.

```
original user-owned nfs.exe
        |
        v
read-only PE/x86 analysis
        |
        v
function discovery
        |
        v
x86 static lifter
        |
        v
generated C
        |
        +--> native development target
        |
        +--> WebAssembly
                |
                v
        browser compatibility runtime
                |
                +--> Win32 compatibility
                +--> Direct3D 9 -> WebGPU
                +--> audio
                +--> input
                +--> filesystem
                +--> threading
```

The WebAssembly target and the browser runtime boxes are the intended direction. They are not implemented for Undercover. A native harness now runs a few recompiled ordinary functions, including one `memset` call and a three-function chain, against mapped `.rdata` and `.data`. That is not the game.

## What this repository does not distribute

- Need for Speed Undercover
- `nfs.exe`
- Electronic Arts assets
- copyrighted game data
- DRM or copy-protection bypass tools
- generated C or WebAssembly translated from the game

Protected startup (`Sitext` and the other protected sections) is out of scope. The tools do not unpack, decrypt, emulate, patch, or follow it.

## What the measurements show

- The executable is PE32 / x86.
- Ordinary `.text` is about 7.7 MB and is highly analyzable: Capstone decodes 99.5% of it.
- About 13,090 high-confidence function roots come from direct calls that land on a decoded instruction.
- The existing NFSU2 lifter accepts about 99.9% of the 874,653 instructions reached from those roots.
- A 100-function sample first produced C for 83 functions, and all 83 compiled. After `repz ret` and `movmskps` were lowered, the same 100 addresses produced 86 functions and all 86 compiled. The other 14 are data-like roots.
- The Phase 4 high-confidence list is 6,604 functions. After the remaining SSE and locked atomic forms were lowered, 6,598 generated and all 6,598 compiled. The six failures are data reached by a jump, not a missing compiler opcode.
- `0x00721070` runs in a native harness. Real cdecl calls to `memset`, `strlen`, `memcmp`, and `strcmp` run from lifted functions, including a five-function chain. `_CIsin`, `_CIcos`, and `_CIacos` return on ST(0) inside the six-function `0x00A124B0` closure. Unknown imports fail closed. The game does not run.
- The PE entry point is in protected `Sitext`. That startup is unresolved on purpose.

Reports: [docs/feasibility.md](docs/feasibility.md), [analysis/undercover/](analysis/undercover/).

## Layout

| Path | What it is |
| --- | --- |
| `tools/uc_analyze.py` | Read-only PE report. |
| `tools/uc_code_analyze.py` | Static analysis of ordinary `.text` only. |
| `tools/uc_gen.py` | Isolated generation experiment. Does not change the NFSU2 generator. |
| `tools/lift.py` | The x86-to-C lifter. Near `ret` includes `repz ret`. XMM shuffles and locked atomics used by Undercover are lowered. |
| `tools/uc_funcmap.py` | Undercover function confidence and the high-confidence translation. Does not change `genall.py`. |
| `tools/uc_imports.py` | Names `.rdata` import thunks. Does not implement the runtime. |
| `runtime/` | The NFSU2 guest CPU and compatibility runtime. |
| `analysis/undercover/` | Statistics and write-ups. No game bytes. |
| `generated/undercover/` | Local generated C. Gitignored. |
| `docs/architecture.md` | How the pieces fit. |
| `docs/roadmap.md` | Milestones. Protected startup is not one of them. |

```sh
python tools/uc_analyze.py "C:\Games\Need For Speed Undercover\nfs.exe"
python tools/uc_code_analyze.py "C:\Games\Need For Speed Undercover\nfs.exe"
python tools/uc_gen.py "C:\Games\Need For Speed Undercover\nfs.exe" --sample-only
```

Requires Python 3, `capstone`, and `pefile` (`requirements.txt`). The compile check uses clang. `CLANG` can point at the binary.

## Attribution

This tree is a clone of [nfsu2-web](https://github.com/th0mk/nfsu2-web) by Thom. That project is a fork of the MIT release of [NFSU2Recomp](https://github.com/TalhaMudo/NFSU2Recomp) by Talha Müderrisoğlu (16 October 2026) and uses only code from that version. The NFSU2 browser port, its runtime, and its lifter remain in this tree. Their README is preserved at [docs/upstream-nfsu2.md](docs/upstream-nfsu2.md).

New Undercover-only files are the `uc_*.py` tools, `tests/uc_harness.h`, `tests/uc_host/`, `analysis/undercover/`, and the documents listed above. They call the existing lifter. They do not modify it.

## License

MIT. The copyright notice and permission text are in [LICENSE](LICENSE): copyright (c) 2026 th0mk, with portions copyright (c) 2026 Talha Müderrisoğlu. Those notices stay with the code they cover.

*Need for Speed* and *Need for Speed Undercover* are trademarks of Electronic Arts Inc.
