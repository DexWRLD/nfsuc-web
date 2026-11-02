# Architecture

nfsuc-web is a research tree for a portable port of the 32-bit Windows game Need for Speed Undercover. It is built on the static-recompilation architecture of [nfsu2-web](https://github.com/th0mk/nfsu2-web), which itself comes from the MIT release of [NFSU2Recomp](https://github.com/TalhaMudo/NFSU2Recomp). The Undercover game is not in this repository. A legally owned installation is an external input, and it is read only.

The browser port does not run yet. The pieces below are the intended shape. A box that is not implemented is marked as such.

```
original user-owned nfs.exe
        |
        v
read-only PE/x86 analysis          tools/uc_analyze.py, tools/uc_code_analyze.py
        |
        v
function discovery                 tools/uc_funcmap.py (Undercover only; genall.py is unchanged)
        |
        v
x86 static lifter                  tools/lift.py (NFSU2 lifter, plus repz ret and movmskps)
        |
        v
generated C                        generated/undercover/  (not committed)
        |
        +--> native development target
        |
        +--> WebAssembly            not started for Undercover
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

## What is reused from nfsu2-web

These components originated in NFSU2Recomp and nfsu2-web. They still build that Underground 2 port. The Undercover experiment calls them and does not change their behavior.

| Path | Role |
| --- | --- |
| `tools/lift.py` | Capstone x86-32 to C. `RawLifter` translates a `.text` image without opening other sections. Near `ret` includes the `F3 C3` form, and `movmskps` reads the existing XMM lanes. |
| `tools/genall.py` | NFSU2 function discovery and sharded C generation. Not used for Undercover. |
| `tools/reloc2.py`, `tools/argcount.py`, `tools/prepare_module.py` | NFSU2 relocations and stdcall import arities. |
| `runtime/cpu.h` and `runtime/` | Guest CPU, memory, and the Win32 / Direct3D 9 / audio / input runtime for Underground 2. |
| `web/` | Browser page, WebGPU renderer, and multiplayer server for Underground 2. |

`tools/uc_analyze.py`, `tools/uc_code_analyze.py`, `tools/uc_gen.py`, `tools/uc_funcmap.py`, `tools/uc_imports.py`, and `tools/uc_isa_test.py` are the Undercover tools. They read only the caller's nfs.exe and write reports under `analysis/undercover/`. `tools/genall.py` is not on that path.

## Boundaries

Ordinary `.text` (`0x00401000` .. `0x00B603FB`) is the only code the experiment disassembles. The PE entry point is in `Sitext`. These sections are not read, followed, or rewritten:

- `Stext`
- `Sitext`
- `Srdata`
- `Sdata`
- `Sidata`
- `.securom`

A direct branch or call that leaves `.text` stays an unresolved external edge. An indirect call stays on the existing dispatcher (`DISPATCH_CALL`). Switch tables are accepted only when `Lifter._jt_table` proves every target is inside `.text`.

Protected startup is outside this roadmap. There is no plan to unpack, decrypt, emulate, or bypass it.

## Calling conventions

The NFSU2 import path rewrites `call [IAT]` / `jmp [IAT]` and `win32_call` then pops `4 * nargs`, which is stdcall. Undercover's ordinary `.text` does not address the PE import-address table. It calls a stub, `jmp dword ptr [slot]`, whose slot is in `.rdata`.

`analysis/undercover/import-thunks.md` names 199 of those stubs from the on-disk import entry in the slot. Undecorated MSVCR80 exports are cdecl (137). One MSVCR80 method is thiscall. Undecorated Win32 exports in that set are stdcall (19). Ordinals and undecorated DirectX helpers stay unknown (42) rather than being guessed. The runtime still pops every import as stdcall, so generated code can be compiled and cannot yet call these thunks correctly.

## Guest map

The NFSU2 runtime reserves a guest image at `0x00400000` .. `0x00932000` and a dispatch table sized for that `.text`. Undercover's image runs through `0x024A5000`, and its `.text` already ends at `0x00B603FB`. Fitting that image into the guest map is future runtime work. It is not done here.
