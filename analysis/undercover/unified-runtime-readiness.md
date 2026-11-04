# Unified Undercover runtime foundation

web/src/host/uc-process.ts supplies one WebAssembly.Memory per address-space instance. It mirrors uc_image.h's READ=1, WRITE=2 and EXECUTE=4 bits and retains original guest virtual addresses. Mapping descriptors contain initialized bytes, virtual size, permissions and an unavailable flag. Uninitialized bytes and BSS zero-fill on creation and reset. A fixed 256 MiB process ceiling, range validation, overlap rejection and permission checks constrain supported accesses.

The foundation accepts descriptors, not arbitrary executable files. It does not relocate PE images. The caller must validate source identity and select ordinary sections before mapping them. Unavailable spans cannot be read, written or dispatched. The native protected-region policy remains the reference for eventual PE loading.

## Implemented and tested

- One Wasm memory, initialized little-endian dword reads/writes, zero fill and repeatable reset.
- Segment-level read/write/execute checks for accesses through the checked API.
- Explicit CPU register/eflags state representation. Instruction semantics still belong to translated code.
- Original-address dispatch with source digest, evidence, verification classification and calling convention metadata.
- Call frame pushes, returned EIP and ESP validation for cdecl, stdcall and thiscall.
- Checked vtable pointer/slot resolution, without admitting an unverified target.
- Unknown, candidate, unavailable and unbound-import targets fail before modifying the call stack.
- Trap/return trace records and explicit ABI mismatch failures.
- Original static bytes at vtable cell 0x00BBB2BC were independently read from the source PE and mapped read-only. They resolve to 0x0080D090. No live object or call is implied.

All executable callbacks used in the new unit tests are synthetic host contract fixtures. No original guest body is registered by default. dispatch-candidates.json is generated from the canonical Ghidra index and marks all 17,367 entries noncallable. Bodies with unknown ABI cannot be promoted automatically. The existing Wasm diagnostic builder remains separate.

## Not yet integrated

There is no whole-game PE loader, source relocation, heap allocator, TLS/thread model, exception dispatcher, Windows import implementation set or D3D9 adapter in this foundation. Existing browser worker, filesystem and input/audio/GPU technology remains available for those adapters. windows-service-inventory.json sorts the 622 recovered import declarations for review. Signatures and ownership require validation before binding.

WebAssembly.Memory is intentionally exposed for eventual module imports. The API permissions are instrumentation checks, not hardware memory protection. Any compiled guest module must route every relevant access through equivalent checked helpers. Direct Wasm stores would bypass the JavaScript checks. No Wasm module with an exported private memory can be transparently retargeted to this memory without a compatible imported-memory build and bridge.

Reset currently resets bytes only. CPU registers, dispatcher trace and application objects must be recreated by the process owner. Dispatch faults leave the observed CPU state for diagnosis and do not roll back original guest writes. Memory is single-threaded; synchronization and atomic/shared-memory semantics are unimplemented.

## Startup status

PE entry 0x01FCA510 remains BLOCKED_UNVERIFIED_ENTRY_CONTROL_FLOW. Alternative instruction decodings at 0x01FCA523 and 0x01FCA58F are recorded without selecting a branch. No ordinary initialization continuation from that entry is verified. The foundation supplies testable process contracts for a future verified ordinary entry, while existing browser islands retain their established evidence boundaries.


## Phase 65 integration

uc-unified.ts now instantiates a translated Wasm module importing this process memory. Every original guest dword read and write is routed through the checked address space; the module's compiler CPU/flag scratch occupies reserved low addresses outside guest mappings. The PE sections retain their original virtual addresses and native permission bits. Five ordinary sections are loaded from a hash-verified private payload, while six opaque regions are reserved as unavailable. The guest stack is a separate explicit diagnostic region.

Five previously verified translated bodies are explicitly bound: 0x009E8AD0, 0x0099DCD0, 0x009E78C0, 0x009B6290 and 0x009E4B10. Original lifted CALL instructions push original return addresses before calling the process's callFromGuest dispatcher. Host and module CPU views synchronize at dispatch boundaries, with EIP updated from original instruction tags.

The registration leaf and root are invoked separately by the host. Within the root, the original calls and callback table dispatch are preserved. The fixture-precondition failure at 0x009E4B49 remains. Full startup reachability, general EFLAGS transfer, arbitrary instructions, Windows imports, heap and thread support are still unimplemented. Current translated condition helpers cover the verified prefix. The existing per-diagnostic memory modules remain separate regression controls and share no mutable guest state with the new process.


## Phase 66 connected initialization

The reviewed registry now contains nine callable original addresses and a classified unavailable helper. The new original root 0x00B57DC0 supplies its receiver at 0x00B57DC3 and calls the full constructor chain. Shared PE state receives 27 original writes; eight original callees return before cleanup registration traps at 0x0087B640. A read-only original pointer cell at 0x00B6370C identifies the root without proving native startup scheduling.

CPU register storage is volatile across re-entrant Wasm imports, fixing the stale-register failure exposed by nested constructors. Byte reads/writes and guest-write journals now use the same checked process mapping. The default constructor path needs no Windows service adapter. General EFLAGS and the wrapper's CF-dependent instructions remain unsupported. Native startup and gameplay readiness remain blocked.
