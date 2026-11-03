# Undercover PC first authentic frame

## Result

**FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND**

The shortest verified initialization path reaches a clear-only presentation at `0x00725350`. The closest verified scene-draw path reaches `0x00757C9A`, where prepared mesh data enters opaque code at `0x006860F0`. A second device presentation site exists at `0x00752B14`. Static evidence has yet to connect the render callback to the mesh path or connect that draw path to the second presentation.

Ghidra verified nfs.exe, PE32 x86, image base `0x00400000`, SHA-256 `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`. The investigation retrieved all 142 recorded references to the device global and disassembled all 69 defined functions containing those references. Device-slot scanning was selective and cannot rule out calls made through other aliases or undefined function bodies. The findings describe static instruction paths.

## A. Render call sites

All receivers below trace to the pointer at `0x013C6510`. `0x007252CF` and `0x007252F5` pass its address as the output pointer to the CreateDevice-shaped call. Actual instructions and receiver provenance are verified. Method names are strongly supported by device vtable layout and argument shapes. The accompanying JSON includes instruction excerpts.

| Call site | Function | Method | Arguments or context |
|---|---|---|---|
| `0x00725313` | `0x00725200` | BeginScene | () |
| `0x0072532F` | `0x00725200` | Clear | (0, NULL, 7, 0, 1.0f, 0) |
| `0x0072533F` | `0x00725200` | EndScene | () |
| `0x00725350` | `0x00725200` | Present | (NULL, NULL, NULL, NULL) |
| `0x0074286D` | `0x00742810` | SetRenderTarget | (0, surface in ECX) |
| `0x0074287F` | `0x00742810` | SetDepthStencilSurface | (NULL) |
| `0x0074289F` | `0x00742810` | Clear | (0, NULL, 1, 0, 1.0f, 0) |
| `0x007666E4` | `0x00766480` | SetVertexDeclaration | (selected declaration) |
| `0x0075EF3F` | `0x0075EF20` | SetVertexDeclaration | ([descriptor]) |
| `0x0075EFAE` | `0x0075EF20` | SetStreamSource | (stream index, buffer from 0179F2DC table, 0, stride & 0x7FFF) |
| `0x00757C29` | `0x00757B80` | SetIndices | (selected index buffer from 0179F2DC + 0x10 table) |
| `0x00757B06` | `0x00757A50` | SetIndices | ([ESI+0x10]) |
| `0x00764AC1` | `0x007649A0` | SetVertexShader | (shader from [material+0xCC]+0x108) |
| `0x00764AFB` | `0x007649A0` | SetPixelShader | (NULL) |
| `0x0073EEC7` | `0x0073EE70` | SetRenderState | (0x16, [EDI]) |
| `0x00731B52` | `0x00731B30` | CreateIndexBuffer | (0x40000, 0x208, 0, 0, this+0x364, NULL) |
| `0x007508B9` | `0x00750870` | CreateVertexShader | (bytecode, output slot) |
| `0x00750939` | `0x007508F0` | CreatePixelShader | (bytecode, output slot) |
| `0x00752BB5` | `0x00752AF0` | SetTexture | (stage ESI, NULL), state cleanup |
| `0x00752B14` | `0x00752AF0` | Present | (NULL, NULL, NULL, NULL), before cleanup |
| `0x00752B01` | `0x00752AF0` | EndScene | () |
| `0x0075DBED` | `0x0075DBC0` | SetPixelShader | ([shader descriptor+0x88]) |
| `0x007515D3` | `0x00751360` | CreateTexture | (width, height, levels, 0, format, pool 1, output, NULL) |
| `0x007707CC` | `0x00770750` | Clear | (0, NULL, 3, 0, 1.0f, 0) |
| `0x00770803` | `0x00770750` | SetDepthStencilSurface | (NULL) |

The startup sequence runs when the final device-creation status in EBX is zero. It calls BeginScene, clears target, depth, and stencil to black, depth 1 and stencil 0, calls EndScene, then presents. There is no intervening draw in this sequence.

The second Present at `0x00752B14` immediately follows EndScene at `0x00752B01` and precedes cleanup and state unbinding. Its known incoming edge at `0x00758674` lies outside a defined Ghidra function. This establishes a presentation endpoint, with scene contents and frame order unresolved.

The call at `0x00766F7A` also loads vtable offset +0x44, but its receiver comes from a function parameter and it supplies one output-buffer pointer. It was excluded from the Present findings.

No direct device DrawPrimitive or DrawIndexedPrimitive site was verified. Two ordinary callers supply draw-shaped arguments to opaque targets.

| Site | Target | Confirmed argument preparation | Interpretation |
|---|---|---|---|
| `0x00757C9A` | `0x006860F0` | Diagnostic label, device, 4, 0, 0, [mesh+0xF4], 0, floor([mesh+0xF0]/3), 1 | Indexed triangle-list-shaped handoff. The extra label and final flag belong to the wrapper contract. |
| `0x00766700` | `0x00686290` | Diagnostic label, device, 6, 2, stack vertex pointer, 24 | User-memory non-indexed draw shape, consistent with two triangle fan primitives at a 24-byte stride. The device call inside the target remains unverified. |

`0x00757B31`, `0x00757A3F`, `0x00725AC9`, and `0x0075EDA3` offer alternative ordinary routes to the indexed wrapper. `0x00764F34`, `0x007653A1`, `0x007530B7`, and `0x0074144E` likewise reach the user-memory wrapper. The edge at `0x00765383` goes to `0x006861B0`, where Ghidra reports bad and overlapping instructions.

## B. Frame and scene call graph

Each site below has a supported static relationship. A callback registration records an address handed to a caller. The later execution of that callback is a separate runtime question.

| Source | Site | Destination | Edge and context |
|---|---|---|---|
| `0x00766730` | `0x00766773` | `0x0072E5D0` | direct. thread callback body |
| `0x0072E5D0` | `0x0072E612` | `0x0072E340` | direct. gate 01311E1C equals 1 |
| `0x0072E5D0` | `0x0072E621` | `0x007297D0` | direct. AL nonzero |
| `0x007297D0` | `0x00729836` | `0x00725200` | direct. first device-creation wrapper call |
| `0x007297D0` | `0x0072986A` | `0x00725200` | direct. AA fallback retry |
| `0x00766730` | `0x007667FB` | `0x0071E630` | direct. device status |
| `0x00766730` | `0x00766807` | `0x0072E5C0` | direct. specific device-lost HRESULT branch |
| `0x00766730` | `0x00766833` | `0x007661A0` | direct. buffer queue processing |
| `0x007661A0` | `0x0076631F` | `0x00766100` | direct. secondary queue / range reclamation |
| `0x00766730` | `0x00766931` | `0x00727F40` | direct. exit cleanup |
| `0x0076CA20` | `0x0076CB40` | `0x00766730` | callback registration. entry address argument, no runtime invocation observed |
| `0x0072E340` | `0x0072E497` | `0x0072B170` | callback registration. window class callback |
| Undefined caller body | `0x00777253` | `0x00770750` | direct. caller function undefined |
| `0x00770750` | `0x007707EE` | `0x0076FC30` | direct. instancing preparation |
| `0x0076FC30` | `0x0076FDA4` | `0x00757B80` | direct. conditional instanced mesh path |
| `0x00757B80` | `0x00757C9A` | `0x006860F0` | opaque boundary. indexed draw-shaped call |
| `0x00766480` | `0x00766700` | `0x00686290` | opaque boundary. non-indexed draw-shaped call |
| Undefined caller body | `0x00782355` | `0x00766480` | direct. caller function undefined |
| Undefined caller body | `0x00758674` | `0x00752AF0` | direct. caller function undefined |
| Undefined caller body | `0x007B5979` | `0x007B36A0` | direct. caller function undefined |
| Undefined caller body | `0x007B5972` | `0x007B2BA0` | direct. caller function undefined |
| `0x007B36A0` | `0x007B3F71` | `0x007A40D0` | direct. scene object branch |
| `0x007B36A0` | `0x007B3FFA` | `0x007AF900` | direct. scene object branch |
| `0x007A40D0` | `0x007A416C` | `0x004A26B0` | opaque boundary. backend |
| `0x007AF900` | `0x007AFC67` | `0x004A26B0` | opaque boundary. backend |
| `0x007B2BA0` | `0x007B2EA0` | `0x007AEA40` | direct. scene state dispatch |
| `0x007AEA40` | `0x007AED59` | `0x007A8690` | direct. conditional path |
| `0x007A8690` | `0x007A86E0` | `0x007A51B0` | opaque boundary. submission |

The callback processes messages through `0x00723A00` at `0x007667B3` and `0x00766819`. It queries device status through `0x0071E630`, whose device vtable offset +0x0C is consistent with TestCooperativeLevel. Comparison to `0x88760869` precedes the device-loss branch. Input update is a separate call at `0x00766890` to `0x00730450`. The buffer queue is the deepest verified render-thread work on this path. Queue draining alone gives no verified edge to either scene producer.

The instancing path at `0x00770750` clears an existing target, runs preparation, and invokes `0x0076FC30` at `0x007707EE`. A conditional branch at `0x0076FDA4` calls `0x00757B80`. That routine returns early for an empty batch, binds stream 0 and an index buffer, sets stream frequencies, binds stream 1, then passes indexed-draw-shaped arguments at `0x00757C9A`. Afterwards it resets frequencies and unbinds stream 1. The earliest verified incoming call to the producer fragment is `0x00777253`, outside a defined caller.

On the separate scene branch, calls at `0x007B5972` and `0x007B5979` lead into state dispatch and scene object preparation. `0x007AF900` scans 8-byte entries and evaluates virtual predicates on their objects. `0x007AEA40` uses the same stride and object slot, filters by virtual predicates, and takes submission-shaped paths. The calls into `0x004A26B0` and `0x007A51B0` are verified. A shared caller region does not establish when either branch runs relative to the render thread or presentation.

## C. Command and resource records

- **Buffer update record, 0x14 bytes.** The reader `0x007661A0` walks the range at manager +0x30/+0x34. Record +0x00 selects a buffer and its high bit selects a table. +0x04 and +0x0C contribute to the element offset, multiplied by the selected stride. +0x08 is the lock/copy byte count and +0x10 is the copy source. A COM-shaped lock at buffer vtable +0x2C precedes copy and unlock at +0x30. The consumer resets the end pointer to the begin pointer. The producer remains unidentified.
- **Secondary buffer queue, 8-byte records.** The same reader traverses manager +0x80/+0x84 and supplies record +0x04 to `0x00766100` at `0x0076631F`. The helper searches a linked list for a matching range, marks it free, and coalesces adjacent free ranges. Exact producer and record +0x00 semantics remain open.
- **Stream cache, 0x0C bytes per stream.** `0x0071B6B0` compares buffer, byte offset, and stride against the three DWORDs at `0x01311AE0 + 0x0C * stream`. On a hit it returns zero at `0x0071B6E2`. The decompiler describes writes and SetStreamSource forwarding on a miss. The defined assembly body ends at the hit return, so miss behavior needs independent boundary verification. The equivalent explicit device forwarding at `0x0075EFAE` is verified.
- **Instanced mesh descriptor.** `0x00757B80` reads batch counts at +0xA8+4*i, per-batch stream offsets at +0xDC+4*i (shifted left by 6), metadata at +0xEC, index count at +0xF0, vertex count at +0xF4, and stride at +0xF8. The minimum read extent is 0xFC bytes. The batch data source is a related allocation prepared by `0x0076FC30`, which also copies groups of 16 DWORDs into per-instance storage. Full descriptor writer, lifetime, and matrix conventions remain unresolved.
- **Scene list, 8-byte records.** `0x007AF900` and `0x007AEA40` walk the range held at scene +0x50/+0x54 and read a pointer at record +0x04. Virtual predicates and candidate selection are visible. The record writer, first DWORD, and predicate semantics remain unknown. The evidence supports a filtered object list. A visibility frustum or complete draw list has yet to be established.

## D. Resource flow

- **Textures and targets.** `0x00751360` uses device CreateTexture at `0x007515D3`. The special branch at `0x007513E2` is **CreateCubeTexture** (six faces), not CreateVolumeTexture — corrected in Phase 50 from `undercover-asset-browser-report.md`. It then locks, copies or clears, and unlocks data. `0x00742810` binds a surface as target 0, unbinds depth, and clears. SetTexture at `0x00752BB5` is cleanup unbinding. A verified ordinary non-null material texture binding remains open.
- **Shaders.** `0x00750870` and `0x007508F0` call the device with bytecode and an output slot at `0x007508B9` and `0x00750939`. Both routines cross allocator or free dependencies. `0x007649A0` selects a vertex shader through material-linked descriptors and `0x0075DBC0` selects a pixel shader from descriptor +0x88. Cached state suppresses repeated calls. `0x0073F0C0` iterates several parameter slots and calls device vtable +0x114 with a record pointer at sites including `0x0073F113` and `0x0073F14C`. The one-pointer calls are insufficient for a reliable method name or shader-constant schema.
- **Buffers.** The index buffer constructor at `0x00731B52` is reached from graphics startup. The callback handles queued buffer updates. Mesh paths read vertex and index buffers through tables rooted at `0x0179F2DC` and pass them through the device stream and index bindings. The actual per-frame mesh payload and the complete vertex-buffer construction path remain open.
- **Scene data.** The ordinary branch at `0x007AF900` takes a 12-byte value from an object virtual call, compares it against three DWORDs from scene +0x124..+0x12C through `0x005D9720`, then uses the result in candidate selection. The complete camera, frustum, and projection contracts remain unresolved. Preserve them as open data dependencies.

## E. Boundaries

The analysis stops at backend `0x004A26B0`, submission `0x007A51B0`, allocator `0x00686000`, free `0x00686030`, and cleanup `0x0071E380`. It also stops at the undefined draw-shaped targets `0x006860F0` and `0x00686290` and the bad-instruction entry `0x006861B0`. These are independently recorded call targets. Their relationship to each other, if any, remains unresolved.

## F. Browser implementation opportunities

1. **Stream-state cache hit logic.** Five stack inputs at `0x0071B6B0` and caller stack cleanup at `0x00757C0E` establish a cdecl-shaped call. Test per-stream cache hits and independently verify each cache-key component. For synthetic miss tests, inject a mock setter and treat the explicit `0x0075EFAE` forwarding path as the separate reference case.
2. **Indexed draw metadata.** Isolate the ordinary argument arithmetic at `0x00757C75`–`0x00757C9A`. Test zero and multiple batches, offset scaling, and index counts that do or do not divide by three. Capture parameters and mock resource identity. This tests producer math while leaving the opaque callee unmodeled.
3. **Buffer range reclamation.** Use `0x00766100` with a synthetic circular list and mock free-node storage. Cover missing range, exact match, and previous/next coalescing with a sentinel boundary. Validate list links and live-node counts. Recover the exact native ABI before integrating the translation.
4. **Descriptor initialization.** `0x0071B600` takes a descriptor in ECX and an input pointer on the stack in the observed thiscall-shaped decompilation. Test null input, +0x80 lookup for non-null input, and the two enable bytes. Confirm the exact epilogue before claiming ABI parity. Its nearby counterpart `0x0071B5B0` crosses an unresolved jump.
5. **Render-state planning and target descriptors.** Model the ordinary state-change predicates and commands with a recorder, including explicit unbinds and clear flags. Use symbolic resource handles until real shader and texture input mappings are available.

These are synthetic validation proposals. No original game code or synthetic port was executed during this investigation.

## G. Remaining prerequisites

The highest-value missing ordinary evidence is the scheduling path from callback `0x00766730` to the caller regions around `0x00777253` and `0x007B5972`, followed by the path from mesh/scene work to `0x00758674`. Recovering those edges would establish ordering between preparation, submission, and the later Present. The draw handoffs, geometry payload, material texture bindings, camera constants, and opaque backend behavior would still need independently supported contracts for an authentic frame.

## H. Machine-readable evidence

See `undercover-first-frame-evidence.json` for exact sites, instruction excerpts, graph edges, record fields, and unresolved dependencies.

