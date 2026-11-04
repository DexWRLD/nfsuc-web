# Consolidated Undercover executable export

The canonical file nfs_undercover_full_decompile.c contains all emitted bodies from every function recognized in the saved Ghidra project, followed by all successful non-rejected RawLifter candidates absent from that project. Original addresses identify the two populations. The executable SHA-256 is 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd.

The Ghidra MCP backend was unavailable. Ghidra 12.2 headless opened a copy of UndercoverResearch:/nfs.exe with -readOnly -noanalysis. Original assets and the saved source project were preserved. Export timeout was 15 seconds per function. Rejected discovery classifications and Ghidra warnings remain visible. A returned C body alone does not establish trustworthy behavior.

## Measured coverage

| Population | Count |
|---|---:|
| Ghidra recognized internal functions | 17,367 |
| Ghidra emitted nonempty bodies | 17,018 |
| Bodies with decompiler warnings | 3,143 |
| Bodies without warnings and without discovery rejection | 13,567 |
| Bodies without warnings but rejected by the independent discovery map | 308 |
| Failed/unavailable decompilations | 200 |
| Thunks recorded as target inventory | 149 |
| Discovery entries absent from Ghidra | 9,322 |
| Additional successful RawLifter bodies | 8,401 |
| Additional rejected/unliftable candidates | 921 |
| Total emitted bodies across both disjoint populations | 25,419 |
| Defined external/imported function declarations | 622 |
| Computed callsite occurrences in Ghidra functions | 14,846 |
| Function body overlaps in saved Ghidra ranges | 0 |
| Executable ranges outside recognized function bodies | 18,811 |
| Bytes in those executable ranges | 16,509,459 |

The executable gaps include padding, data, opaque sections and possibly unrecognized code. They are not a measured count of missing functions or wholly undefined instructions. Zero overlapping function ranges does not mean zero overlapping instructions. Ghidra explicitly warns of instruction overlap inside emitted functions. Computed calls are unresolved unless independent runtime or static evidence resolves them. Import signatures identify external API contracts, with implementation readiness unverified. Failed recovery reasons, callers, callees, bounds and indirect callsites are indexed.

The saved project has entry 0x01FCA510, emitted with warnings. It provides the PE entry candidate, with no proven ordinary main or uninterrupted initialization-to-game-loop path. The 22,770/22,779 compilation record is a separate discovery-based batch statistic. Browser execution covers bounded translated functions and prefixes described by the current uc_browser_init.py and Phase 53–60 reports. Whole-program Wasm integration is unverified. The export records browser status as unknown per address because no authoritative exhaustive machine-readable browser execution ledger exists.

## Master file organization and limitations

The file begins with source metadata, imported signatures and recovered function declarations. Ghidra bodies follow in address order, retaining signatures, global references, structure offsets, vtables and indirect calls. A separate labeled section contains CPU/register-level RawLifter translations. The final inventory contains rejected or unavailable candidates, defined data metadata and all executable gaps. This preserves cross-address navigation without assigning speculative subsystem names.

Recovered custom type names remain in pseudocode. Complete type definitions, initialized global byte arrays, alias ownership and compiler-ready global declarations were not reconstructed. The defined-data inventory records address, size and type. This master is a reference artifact requiring Ghidra types and repository runtime helpers, and is not standalone compilable C. Function range endpoints in the JSON are envelopes; body_bytes reflects Ghidra's actual address set. Per-function semantic validation is still required.

## Reproduction

Use a fresh copy of the same saved Ghidra project and Ghidra 12.2. Keep the program filename nfs.exe. From the project root, choose an export working directory with sufficient space. Run:

    analyzeHeadless.bat <copied-project-directory> UndercoverResearch -process nfs.exe -readOnly -noanalysis -scriptPath tools/undercover_export -postScript ExportUndercover.java <export-directory>
    analyzeHeadless.bat <copied-project-directory> UndercoverResearch -process nfs.exe -readOnly -noanalysis -scriptPath tools/undercover_export -postScript ExportMetadata.java <export-directory>
    python tools/undercover_export/export_fallback.py <export-directory> <repository-directory>
    python tools/undercover_export/assemble_decompile.py <export-directory> <repository-directory>

Fallback currently uses the session's explicit installed nfs.exe path and verifies its digest. Source manifest, function order and assembly contain no timestamps. Determinism requires the same saved analysis, Ghidra version, discovery map, lifter and per-function decompiler outcomes. A fresh headless rerun was not byte-compared; deterministic assembly was tested separately.

## Validation

Ghidra completed the full recognized-function traversal, reporting Total 17367. Metadata export exited successfully. RawLifter processed all 9322 additional candidates and emitted 8401 bodies. Assembly assertions verified exactly one marker for every Ghidra entry and fallback body, no duplicate addresses across populations, and 12 TSV fields per function. Master SHA-256 is f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a. The master currently occupies 54,494,254 bytes. Index references and failed bodies remain explicit.

No executable behavior or frontend source was changed by this phase. Browser runtime and gameplay tests from earlier phases are historical evidence, not fresh passes in this export task.

## Browser-port implications

The strongest ordinary frame candidate in existing evidence is the mid-function call block 0x00785CD9 → 0x00785CE3 → 0x008096E0. It is not the PE startup entry. Connected startup needs initialized process/guest state, original globals and object providers, valid calling conventions and supported imports. Known allocator, resource-loading, native argument ownership and virtual dispatch boundaries remain unresolved. Frontend frame processing stops at 0x00548810 or live virtual objects.

DirectX device creation, scene scheduling, shader/buffer/resource upload and same-frame Present require their own verified path. Windows threading, TLS, synchronization, time, file and heap contracts remain separate integration requirements. Native gameplay, input, audio and resource streaming cannot be established by this reference export. The next useful work is address-based inspection of a complete caller chain with explicit dependency closure, using this master and its warnings alongside original instructions.

## Git baseline

At finalization the repository HEAD was 56cca34d and main matched its local origin/main reference. This differs from the earlier phase baseline, reflecting external repository changes during the elapsed session. No remote fetch was performed in this task. Only the export artifacts and generation scripts belong to this task.
