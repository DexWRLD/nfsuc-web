# Undercover graphics frontier

Graphics was not implemented. This is a reachability measurement on the ordinary high-confidence graph.

## Direct3DCreate9

| item | value |
| --- | --- |
| thunk | `0x0087A79C` |
| slot | `0x00B616CC` |
| DLL | `d3d9.dll` |
| convention in metadata | stdcall, high confidence |
| direct call sites | 1, at `0x0072E3B9` |
| containing function | `0x0072E340` |
| classification | `MEDIUM_CONFIDENCE`, not reachable from the high-confidence graph |

`0x0072E340` begins by loading `dword ptr [0x00B615C4]` into ESI and calling ESI before it reaches `Direct3DCreate9`. That function is outside the 6,498 reachable high-confidence functions used for the frontier. No high-confidence closure is labeled `GRAPHICS_BOUNDARY`.

## D3DX

The named D3DX imports in `import-abi.json` are low confidence and `unknown` convention. Direct calls from ordinary `.text`:

| symbol | thunk | call sites |
| --- | --- | --- |
| `D3DXMatrixMultiply` | `0x0087A7AE` | 9, including `0x0071B85F` |
| `D3DXVec4Transform` | `0x0087A7B4` | 2 |
| `D3DXVec3Transform` | `0x0087A7BA` | 1 |
| `D3DXGetPixelShaderProfile` | `0x0087A7C0` | 1 |
| `D3DXGetVertexShaderProfile` | `0x0087A7C6` | 1 |
| `D3DXFillVolumeTexture` | `0x0087A7CC` | 2 |
| `D3DXCreateVolumeTextureFromFileInMemory` | `0x0087A7D2` | 1 |
| `D3DXCreateCubeTextureFromFileInMemory` | `0x0087A7D8` | 1 |
| `D3DXGetShaderConstantTable` | `0x0087A7DE` | 2 |
| `D3DXSaveSurfaceToFileInMemory` | `0x0087A7E4` | 1 |

`0x0071B850` is high-confidence and reachable. It is 8 instructions: it re-pushes three stack arguments, calls `0x0087A7AE`, and returns without an `add esp`. That is call-site evidence about stack cleanup. It is not enough to promote the metadata, and the helper was not implemented. The largest high-confidence closure whose first label is the unknown D3DX ABI is 3 functions at `0x0074D3B0` (`D3DXVec4Transform`).

Texture and shader calls such as `D3DXCreateCubeTextureFromFileInMemory` at `0x00748014` sit in `0x00747FF0`, which is high-confidence and not reachable. They also name file-or-memory inputs the filesystem and heap frontiers do not yet supply.

## What would have to exist first

The high-confidence graph does not place `Direct3DCreate9` behind a clean chain of ordinary calls. The closures that are large are blocked earlier by unresolved indirect calls, and the one protected indirect jump described in `runtime-phase10.md`. Filesystem, heap, and timing imports do not sit in front of this call as a large otherwise-ready closure either: their clean closures are 1 or 2 functions.

D3D9 is not the next boundary. Reaching the one `Direct3DCreate9` site means leaving the high-confidence reachable set, and the function around that site already depends on an indirect call through `.rdata` before the create call.
