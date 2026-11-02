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
x86 static lifter                  tools/lift.py (NFSU2 lifter, plus the Undercover SSE and atomic forms)
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
| `tools/lift.py` | Capstone x86-32 to C. `RawLifter` translates a `.text` image without opening other sections. Near `ret` includes `F3 C3`. XMM byte shifts, shuffles, and qword unpacks use the existing integer lanes. Locked `xadd`, `cmpxchg`, and `cmpxchg8b` call `guest_atomic_*`. |
| `tools/genall.py` | NFSU2 function discovery and sharded C generation. Not used for Undercover. |
| `tools/reloc2.py`, `tools/argcount.py`, `tools/prepare_module.py` | NFSU2 relocations and stdcall import arities. |
| `runtime/cpu.h` and `runtime/` | Guest CPU, memory, and the Win32 / Direct3D 9 / audio / input runtime for Underground 2. `guest_atomic_xadd`, `guest_atomic_cmpxchg`, and `guest_atomic_cmpxchg8b` are the locked read-modify-write boundary. The current body is one guest load and one guest store. A native multithreaded runtime, and a WASM build with shared memory, must replace that body. Until then it is not a browser atomic. |
| `web/` | Browser page, WebGPU renderer, and multiplayer server for Underground 2. |

`tools/uc_analyze.py`, `tools/uc_code_analyze.py`, `tools/uc_gen.py`, `tools/uc_funcmap.py`, `tools/uc_imports.py`, `tools/uc_isa_test.py`, and `tools/uc_isa_phase5.py` are the Undercover tools. They read only the caller's nfs.exe and write reports under `analysis/undercover/`. `tools/genall.py` is not on that path.

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

`analysis/undercover/import-thunks.md` and `analysis/undercover/import-abi.json` name 199 of those stubs. Undecorated MSVCR80 exports are cdecl (137). One MSVCR80 method is thiscall, with no stack arguments. Undecorated Win32 exports in that set are stdcall (19). Ordinals and undecorated DirectX helpers stay unknown (42). 157 of the 199 have high confidence.

`runtime/uc_abi.h` and `runtime/uc_import.c` are the Undercover import path. A call names a descriptor. The descriptor holds the DLL, the symbol or ordinal, the convention, and the known stack-dword count. A decoder reads `ECX`, `EDX`, and the guest stack. An HLE function performs the operation and does not decide who pops arguments. Cdecl pops only the return address. Stdcall, thiscall, and fastcall pop the recorded stack arguments as well. An unknown convention fails with the call site, thunk, DLL, symbol or ordinal, ESP, and the general registers. It is not called as stdcall.

`win32_call` is unchanged and still pops `4 * nargs` for NFSU2. `uc_abi_callee_bytes(UC_ABI_STDCALL, n)` is that same byte count. The two paths are not mixed.

The first HLE set is `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcmp`, and `strncmp`. Copies stay inside the guest image after a range check. `floor` remains unimplemented. `_CIsin`, `_CIcos`, and `_CIacos` are implemented as ST(0) replacements: the descriptor's `arg_loc` and `ret_loc` select that register, and a successful call does not write EAX. The host double function is only the mathematical operation. Import tracing is off unless `uc_import_trace` is set. An x87 failure reports EIP, TOP, ST(0), ST(1), FCW, and FSW. There is no tag word and no modeled x87 exception flag.

`tools/uc_phase7_test.py` is the first harness that enters that dispatcher from a lifted Undercover call. `0x00739B90` and `0x009D9150` call the `memset` thunk `0x0087B2D6`. The generated `add esp, 0xc` removes the three cdecl arguments. The dispatcher removes only the return address.

Direct calls between lifted functions go to the lifted body for that guest address. `dispatch_indirect` does not guess a target. An unknown target records the source function, `EIP`, the target, and the registers, and returns without a callee.

The first cluster taken from the graph, rather than from a chosen subsystem, shares `0x009AE140`, `0x009AE2A0`, and `0x009DDA70`. `tools/uc_phase8_test.py` runs `0x009B0490`, `0x009AEBD0`, and `0x009AF0B0` through the existing `strlen`, `memcmp`, and `strcmp` helpers.

`tools/uc_phase9_test.py` runs the next closed cluster, rooted at `0x00A124B0`. `0x00A11C50` calls `_CIsin` and `_CIcos`. `0x00A11AF0` calls `_CIacos`. The six functions return to the harness. The result is not a claim of bit-exact MSVCR80 math.

## Guest map

The NFSU2 runtime reserves a guest image at `0x00400000` .. `0x00932000` and a dispatch table sized for that `.text`. That map is unchanged.

Undercover's native harness has a separate image. `runtime/uc_image.c` copies `.text`, `.rdata`, `.data`, `.tls`, and `.rsrc` to their guest virtual addresses, honors the section's read, write, and execute flags, and zero-fills a virtual tail when the file copy is shorter than the virtual size. `Stext`, `Sitext`, `Srdata`, `Sdata`, `Sidata`, and `.securom` are recorded and left unmapped. A checked build rejects a read, write, or execute that misses a mapped region, and a write to a read-only region, without crashing the host. The harness stack is a private region at `0x03000000`. It is not part of the PE image.

This image is the Phase 7 test image. It is not the NFSU2 browser map, and it is not a running game.
