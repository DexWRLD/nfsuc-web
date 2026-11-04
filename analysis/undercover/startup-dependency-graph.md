# Undercover startup dependency graph

The canonical navigation sources are nfs_undercover_full_decompile.c and nfs_undercover_function_index.json. The master SHA-256 remains f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a, size 54,494,254 bytes. Its 25,419 emitted bodies combine 17,018 Ghidra results and 8,401 RawLifter translations. Warnings and recovery status must be checked before execution.

## Verified entry frontier

The PE entry is 0x01FCA510, in Sitext. The index reports calling convention unknown, no verified caller/callee edges, and an instruction-overlap warning. Independent static inspection of file-backed bytes confirms:

| Instruction | Observation | Missing evidence |
|---|---|---|
| 0x01FCA510 PUSHFD | Entry consumes incoming processor state | Exact runtime entry assumptions |
| 0x01FCA511 PUSH 0x6ED | Modifies stack | Meaning and continuation |
| 0x01FCA516 JAE 0x01FCA52A | Conditional path depends on incoming carry flag | A valid path cannot be chosen from the exported pseudocode |
| 0x01FCA520 ADD [ESP],0xD3B7C3 | Stack modification | Its relationship to original startup is unresolved |
| 0x01FCA527 JMP 0x01FCA523 | Branch into overlapping bytes of the prior instruction | Trustworthy callable ordinary continuation |
| 0x01FCA541 MOV EBP,0x01FCA4F8 and loop 0x01FCA550–65 | Alternate path reads adjacent image words | No established ordinary startup call |
| 0x01FCA598 JMP 0x01FCA58F | Another overlapping path | No established ordinary startup call |

There is no first verified ordinary call out of this entry. The earliest readiness failure is unresolved entry control flow, before any proved call to initialization or Windows services. The static export's returns do not establish successful boot. No execution, patching, protected implementation reconstruction or memory dumping was performed.

## Dependency structure

    PE 0x01FCA510 [unresolved entry control flow]
        ? ordinary executable startup [unknown]
        ? CRT/static constructors, globals, TLS and thread setup [unknown ordering]
        ? game managers and graphics/resources [unknown entry reachability]
        ? update and rendering loop [unknown entry reachability]

The following ordinary islands have independently verified edges. No edge from the PE entry to them is claimed.

| Source/caller | Provider and required state | Browser support | Integration requirement |
|---|---|---|---|
| 0x00810957 → 0x00686000, then 0x00810971 → 0x008101B0 | Allocator result, 0x70-byte manager, globals | Unavailable native allocation path | Unknown game helper cannot be replaced without a supported contract |
| 0x009E9305 → 0x009E8AD0 | No arguments; writes 49 callback slots | Leaf runs with bounded guest memory | Caller state and actual startup order |
| 0x009E46A1 storage publication | Capacity, context 0x0189BEEC, Apt factory and heap | Static provenance and synthetic stack tests | Apt allocator 0x004A9FF0 distinct from 0x00686000 |
| 0x0080D098 → 0x009ADCE0 → allocation 0x009ADCE8 | CmdUtil receiver and native function allocation | Callback bodies verified with fixture entry | Native callback object construction and property publication |
| 0x00785CE3 → 0x008096E0 | ECX manager, EBX null sentinel in tested caller slice, gate 0x00CBF590 | Original edge runs on fixture state | Caller scheduler, real manager and 0x00548810 |
| 0x0080970B / 0x00809717 → virtual objects | Live child objects and vtables | Unsupported | Original providers and ABI before adaptation |
| 0x0072E340 → Direct3DCreate9 path | Callback cell 0x00B615C4, graphics object | Static evidence | Resolve callback and device contracts |
| 0x00757C9A → 0x006860F0 | Scene resources, indices, transforms | Unsupported draw boundary | Ordinary caller contracts and same-frame Present |
| 0x00752B14 Present | Live device and frame state | Static evidence | Proven same-frame producer chain |

Windows imports such as file access, timing, memory, thread and synchronization services are legitimate platform-adapter candidates once reached with verified ABI. Existing host workers offer browser-side foundations. Unknown game allocation/factory helpers, script arguments, renderer backends and opaque callbacks require original-code evidence. A browser adapter must not supply fictitious game logic.

## Unified runtime inventory

- Existing Wasm exports share a CPU struct and bounded mappings within each diagnostic module instance. UI tests instantiate fresh instances by design. The builder does not provide a full PE loader or a shared whole-game address space.
- Original-address dispatch is restricted to recorded fixture paths. General function-pointer/vtable dispatch and a complete address table remain absent.
- The stack and selected zero globals are modeled. A coherent image, segment permissions, guest heap, TLS, exception handling and initialized data are not integrated into one game module.
- Native uc_image/uc_import support and the browser host/filesystem/cache components provide reusable code, with browser/native ABI integration still required.
- The manifest-backed filesystem and OPFS cache deliver authorized bytes. They do not implement the original archive loader and scene resource lifetime.
- D3D9 initialization and game geometry submission do not reach a browser renderer through a verified complete chain.
- Error diagnostics and explicit boundary traps are usable today. No full-game module manifest was invented.

## Concrete launch milestone

UNDERCOVER_ORIGINAL_STARTUP_PREFIX_IN_BROWSER requires an independently verified ordinary entry reached from the original executable startup, a reproducible bounded call closure, documented ABI and initialized guest state, imported service contracts and an expected explicit stop. Current diagnostic islands do not establish that reachability.

The first dependency is authoritative evidence for an ordinary continuation from the PE startup boundary. If it remains unavailable, a full game boot cannot be assembled by joining unrelated function roots. After such evidence exists, map the required PE data and TLS into one shared guest image, connect only verified function edges, and adapt each reached Windows import with targeted tests. Keep the first unsupported boundary visible.
