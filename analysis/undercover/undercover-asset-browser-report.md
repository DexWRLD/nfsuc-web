# NFS Undercover PC asset-to-browser investigation

Verified nfs.exe, PE32 x86, image base `0x00400000`, SHA-256 `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`. All findings derive from static Ghidra evidence.

**The shortest browser path is a single readable 2D DXT1 texture.** Its runtime dimensions, format, mip metadata, payload pointer, and upload behavior are recoverable. The missing link is a verified texture identifier and byte range in a readable source resource. A mesh path is also viable once a source record can be mapped to vertex bytes, 16-bit indices, and an associated attribute descriptor. No authentic source fixture has been verified.

## Mesh layout and ownership

`0x00782A50` looks up `XP_SMOKEBALL_CURL` and `XP_SMOKEBALL_PUFF` and calls the template mesh initializer at `0x00782AD8`. These are concrete resource-name candidates. Their numeric identifiers and archive locations remain unresolved because the name resolution and lookup paths through `0x004AA010` and `0x00526C60` produce unusable or unresolved control-flow analysis. The constructor call uses allocation size 0x110 for this template class. That size does not describe a serialized mesh header.

Let M be the source mesh record and S be the stream record addressed by M+0x14. The exact thiscall entry `0x00782570` uses ECX and two stack arguments, with RET 8 at `0x007825DE`.

| Runtime field or source | Confirmed meaning | Instruction evidence |
|---|---|---|
| Template +0xEC | Source mesh record pointer M | `0x0078257A` |
| M+0x14 | Pointer to S | `0x00782581` |
| M+0x30, template +0xF0 | Triangle count multiplied by 3 to initialize index count | `0x00782584`–`0x0078258A` |
| S+0x72, template +0xF8 | 16-bit packed stride, masked by 0x7FFF | `0x00782590`–`0x0078259A` |
| S+0x6C, template +0xF4 | Vertex byte count divided by stride | `0x007825A0`–`0x007825B5` |
| S+0x64 | CPU vertex pointer copied with S+0x6C bytes | `0x00780DA2`–`0x00780DAD` |
| M+0x20 | CPU index pointer copied with 2 times index count bytes | `0x00780DB2`–`0x00780DC4` |
| S+0x68 / S+0x74 | Vertex buffer selector and starting element. Stream byte offset is starting element times stride | `0x00757B9D`–`0x00757BEB` |
| M+0x28 | Index buffer selector | `0x00757BF6`–`0x00757C29` |
| Template +0xA4 | Associated entry +8 from 12-byte table records. Table pointer from input +0x2C and index from S+0x30 | `0x007825C0`–`0x007825D0` |
| Template +0xA8+4*i | Batch instance count. Zero skips draw preparation | `0x00757B80`, `0x00757C2B` |
| Template +0xDC+4*i | Per-batch stream 1 start in 64-byte units | `0x00757C46`–`0x00757C5B` |

The +0xA4 lookup is confirmed. Its interpretation as a material association is a hypothesis. The 16-bit index interpretation has two independent checks. The initializer copies indexCount times two bytes, and the fallback batch builder reads and writes 16-bit entries while rebasing them by vertexCount times batch ordinal at `0x0077A800` and the following loop. This is evidence for this path only.

`0x00780D60` copies both source spans into owned temporary allocations, hands them to `0x0077A610` at `0x00780DE3`, and frees its temporary copies at `0x00780DF1` and `0x00780DF7`. Those copies establish that CPU mesh bytes are present upstream of the GPU upload. They do not establish how their pointers were fixed up from file data. The fallback replicates vertices 60 times, modifies selected attributes, and creates rebased indices. A one-mesh browser preview should consume the source spans before this batch expansion.

Buffer-manager global `0x0179F2DC` is assigned by `0x0075EFD0` at `0x0075EFF9`. Observed tables use 0x0C-byte entries. +0x00 points to allocation metadata with stride at +0x9C64, +0x04 is the COM buffer pointer, and +0x08 is the CPU backing pointer used by upload routines. At `0x00751057` and `0x007510D8`, the upload helpers copy into CPU backing before the GPU lock/copy/unlock sequence. `0x00777BE0` selects a vertex pool by stride, and `0x00777C70` reserves half the byte length as index elements and sets the high bit in the selector. Do not persist pool selectors or GPU pointers as asset IDs.

### Vertex layout

`0x0073F300` is the strongest layout evidence. It converts an 0x50-byte descriptor with four-byte input records into standard-shaped eight-byte D3D elements. It reads the record count at descriptor +0x40 at `0x0073F315`, accumulates a separate byte offset for each of three streams, and writes the current stride to +0x44+4*stream at `0x0073F3C9`.

| Input byte | Meaning | Lookup or rule |
|---|---|---|
| 0 | Stream number | Direct |
| 1 | Usage index into game table | DWORD table `0x00CF0E6C`, read at `0x0073F366` |
| 2 | Type and byte-width table index | Type `0x00CF0E98` at `0x0073F354`, width `0x00CF0E20` at `0x0073F376` |
| 3 | D3D usage index | Direct |

The output is u16 stream, u16 byte offset, u8 type, u8 method zero, u8 usage, u8 usageIndex. It ends with bytes FF 00 00 00 11 00 00 00. The JSON contains the observed static lookup entries. Reading a bounded table span verifies those bytes, while entry-domain validity still needs validation against a real descriptor. `0x0074D540` walks 0x50-byte descriptors starting at owner+0x44, checks count, calls the builder, and creates the device declaration at `0x0074D590` through vtable +0x158. `0x00730040` uses the same format for a declaration variant at `0x0073015D`. `0x0075EF20` binds a selected declaration at `0x0075EF3F` and configures stream stride and buffer at `0x0075EFAE`.

`0x00721EA0` edits a 16-bit value at vertex byte +6 for one stride-32 stream. That establishes a packed field in that case and gives no basis for naming the entire format. The exact attribute descriptor associated with either named smoke mesh has yet to be matched.

### Indexed draw handoff

At `0x00757C9A`, ordinary code passes the diagnostic label, device, primitive type 4, base vertex 0, minimum vertex 0, template +0xF4, start index 0, floor(template +0xF0 divided by 3), and final flag 1 to opaque `0x006860F0`. Type 4 and division by 3 are consistent with triangle-list submission. The selected stream 0 byte offset was set earlier, so the zero draw base must be understood relative to the bound stream. Validate index addressing when adapting a submesh.

`0x0076FC30` copies 16 DWORDs from its input into related instance state +0x60..+0x9C and sets other per-instance values. The hardware path calls `0x00757B80` at `0x0076FDA4`, while the alternate path calls `0x00768EC0` at `0x0076FDB2`. The hardware path binds stream 1 at a 64-byte stride and sets stream frequencies at `0x00757C44` and `0x00757C73`. The 16 DWORD copy and the stride are consistent with a matrix-sized payload. Storage order and transform semantics are unverified. A browser geometry preview can use an explicit viewer transform for one source mesh, with the preview clearly labeled as such.

`0x00757A50` is a separate sprite example. It copies 0x60 bytes per sprite at `0x00757AC1`, binds a 0x18-byte vertex stride at `0x00757ADE`, and passes four vertices and two primitives per sprite at `0x00757B31`. Its layout does not establish the smoke mesh format.

## Texture metadata

Let J be the upload job, T = J.ptr(0x08), and P = T.ptr(0x00). These are runtime objects with CPU or COM pointers.

| Field | Observed meaning | Evidence |
|---|---|---|
| J+0x08 | Descriptor T | `0x0075136F` |
| J+0x0C | Requested level count | `0x0075137B`, pushed into create calls |
| J+0x10 | Conditional CPU payload cleanup flag | `0x007516D4` region, free at `0x007516E2` |
| T+0x10 | Kind discriminator | `0x007513B2`–`0x007513B5` |
| T+0x24 | Initial level byte-count term | `0x00751383` |
| T+0x28 / +0x2A | Signed 16-bit width and height | `0x00751576` / `0x0075157A` |
| T+0x32 | Signed byte source level count | `0x00751377` |
| T+0x50 | CPU payload pointer | `0x00751380`, cleared after conditional free at `0x007516EA` |
| P+0x0C | D3D format DWORD | `0x00751374` |
| P+0x10 | GPU texture output slot | `0x007513CF` and `0x007515BF` |

The ordinary 2D branch calls CreateTexture-shaped vtable +0x5C at `0x007515D3`, with width, height, requested levels, usage 0, format, pool 1, output and null shared handle. The special branch at `0x007513E2` uses +0x64, edge length, and six faces. **This corrects the earlier first-frame report: the evidence supports CreateCubeTexture, not CreateVolumeTexture.** The discriminator at `0x012BAD1C` is initialized by a call using the string “Cubic Environment Map” at `0x00B7277C`, followed by the store at `0x00B485ED`. Its numeric value and name algorithm remain unresolved.

The uploader recognizes DXT1 through DXT5. The 2D path computes block byte counts with 8 bytes per DXT1 block and 16 for the other recognized variants. It locks at `0x00751676`, copies at `0x00751698`, advances the source to the next 16-byte-aligned address at `0x007516A4`–`0x007516B6`, and unlocks at `0x007516C1`. Small compressed dimensions take a separate creation and zero-fill branch. For omitted leading mips, the initial pointer adjustment at `0x007513A0` uses the descriptor's initial byte-count term and shifts that term right by two for each skipped level. Neither operation proves the archive uses these same spans or alignment.

The backward trace reaches a command-style trampoline at `0x00758660` which loads ECX from the stack and tail-jumps at `0x00758664`. Ghidra records this edge as a call. Bounded instruction bytes establish the tail jump. The producer of J, the named asset ID, and the archive byte range that ultimately fills T+0x50 remain open. The material-side trace provides descriptor selection evidence but no verified texture-ID-to-payload connection for one named mesh.

## Resource loading graph and boundaries

- **Named resource lookup and template initialization.** `0x00782A50` resolves the smoke names through opaque or unresolved code, then calls `0x00782570` at `0x00782AD8`. `0x00782570` derives counts and stride, then calls `0x00780D60` at `0x007825BB`. Its CPU data reaches the batching routine at `0x00780DE3`.
- **Index allocation and upload.** `0x0077A610` calls `0x00777F30` at `0x0077A84F`. With the matching thread identity it calls `0x00777D60` at `0x00777FB1`. The alternate path enqueues a command at the list rooted at `0x00CF3EB8`. `0x00777D60` uses pool selection `0x00777C70` and upload `0x007510A0` at `0x00777D9B`. The pool growth branch reaches index-buffer creation in `0x007723E0`.
- **Vertex allocation and upload.** `0x00777D00` takes a prepared job, uses `0x00777BE0` for pool selection, and calls `0x00751020` at `0x00777D3F`. `0x0077A874` is a direct incoming edge without a defined caller body. Pool growth reaches vertex-buffer creation in `0x00771FB0`. A separate lock route from `0x0077A65E` reaches unresolved dispatch `0x007720F9`. No upstream disk parse was inferred from either route.
- **Effect usage file.** `0x0077C150` constructs a path and calls slot `0x00B612DC` at `0x0077C1E7` with mode “rb”. The slot chain is unresolved. Calls through `0x00B61324` and adjacent slots read and size a temporary range before effect processing at `0x0077C324` and declaration creation via `0x0077C32B`. This is an effect usage path, separate from an identified mesh archive parser.
- **Shader files.** `0x007845C0` calls `0x0077EA60` for “ShadersLibrary.bin” and `0x0077ED50` for “ShaderDeDupMapping.bin”. The file-like slots and registration routines are visible. Original shader bytecode and effect lookup are optional for a geometry or texture preview, and required for original material parity.
- **Bundle leads.** “GLOBAL\\GLOBALB.BUN” and “GLOBAL\\GLOBALB.LZC” occur at `0x00B86334` and `0x00B86348`. The BUN name has a data reference at `0x00CC5EF4`. The bundle names alone do not establish where either smoke mesh or a selected DXT texture is stored.

Opaque allocation/free `0x00686000` and `0x00686030`, the name/lookup paths, the unresolved buffer lock dispatch, and draw wrapper `0x006860F0` remain boundaries. No complete source-to-payload path was verified for a named asset. The original first-frame status is independent of this viewer work.

## Cursor specification

### Milestone 1. Display one authenticated texture

1. Accept a manifest and a readable payload supplied by a verified source. Require asset identifier, source filename or artifact ID, source digest, byte offset and length, logical width and height, format, mip level, and row/block layout. Include an independent payload digest. Source provenance is required before calling an output authentic.
2. Start with one DXT1 2D level, preferably with dimensions at least 4×4 and multiples of four. Reject unknown format and kind. Validate length as ceil(width/4) times ceil(height/4) times 8. Reject truncated and trailing data for the single-level contract. Apply source mip alignment only when the source explicitly establishes it.
3. Decode BC1 to RGBA or use an explicitly available compressed-texture path. Display via a simple browser image or textured quad. Keep color-space and orientation choices explicit. Use a checkerboard for alpha verification.
4. Synthetic fixtures should cover known colors, both BC1 interpolation modes, alpha, and rejected lengths. The authentic acceptance test requires one digest-verified readable resource and a deterministic pixel result. Synthetic success is a decoder test.

### Milestone 2. Display one authenticated mesh

1. Define a manifest containing resource identity and provenance, bounded vertex and index spans, counts, topology, index width and byte order, stream strides, and explicit attributes with stream, semantic, offset, encoding, and usage index. Require position for a geometry preview. Require UV and a matching texture reference for a textured preview.
2. Implement the descriptor conversion as a pure helper from the observed tables. Verify record counts, stream range 0..2, allowed lookup indices, known encodings, and attribute extent within stride. Use little-endian reads. Treat undefined, conflicting, or unsupported encodings as errors.
3. Validate vertex byte count against stride and count. For the observed source mesh, require u16 indices, triangle-list topology, a count divisible by three, and every effective index in range. Export the source spans before fallback replication and preserve submesh offset metadata when applicable.
4. Draw a single instance with an explicit browser-owned view/projection and a diagnostic position-only shader. Use UV and a supplied texture in the next test. Shader parity requires a separate contract for authored material selection, texture identifiers, transforms, vertex normalization, and render state.
5. Test a synthetic triangle, two separate streams, malformed descriptors, out-of-range indices, and a rejected missing position. Use a named resource only after verifying its spans and matching attribute descriptor. Retain digests and provenance in the test report.

The first deliverable Cursor can implement today is the manifest-driven decoder and viewer with synthetic fixtures. The smallest research task needed for authentic output is to locate **one readable, named DXT1 payload and prove its offset, dimensions, and format**, or match a named mesh's readable vertex and index spans to one declaration. No browser renderer needs the original protected draw wrapper for these isolated previews.

## Evidence index

The companion JSON records structure offsets, instruction anchors, lookup tables, runtime call edges, and unresolved dependencies. The runtime layout must remain separate from any future on-disk parser.

