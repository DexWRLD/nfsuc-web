# Undercover startup dependency graph

Phase 70 adds a verified static conditional CRT chain: 0x0087BD95 → cookie 0x0087C264, then 0x0087BD9A → startup 0x0087BB3D; gated C walker at 0x0087BBB4 → 0x0087C232/[0x00B613B4]; C entry 0x00B63DC8 → 0x0087BCB3; sentinel transform at 0x0087BD22/[0x00B6138C] and conditional original stores 0x0087BD2A/2F; gated C++ walker at 0x0087BBE9 → 0x0087C22C/[0x00B613B0]; table slot 0x00B6370C → Apt root 0x00B57DC0. These are not observed traversal or PE-entry reachability. Active MSVCR80 identities are independently verified in .securom, but no effective binding to these .rdata legacy cells is established. The Phase 69 fixture-qualified runtime frontier remains unchanged. See crt-initialization-order-phase70.json and runtime-phase70.md.

Latest Phase 69 frontier: host-entered 0x00B57DC0 → original Apt constructor → 0x0087B640 → 0x0087B59B → original normal SEH prolog 0x0087BEB8, using an explicitly synthetic generic x86 thread fixture. After returning from the prolog, execution stops at 0x0087B5B3 through [0x00B61398]=0x008AAC6A. That raw pointer is inside LEA at 0x008AAC69 and remains rejected. No cleanup registration or original thread startup is proved. Without a supplied thread fixture, the original FS:[0] read fails at 0x0087BEBD. The paired epilog is verified separately with synthetic call frames, not as registrar completion. See runtime-phase69.md and cleanup-registrar-coverage-phase69.json. Historical phase sections below do not supersede this explicitly conditional frontier.

Phase 67 frontier: the independently entered original root 0x00B57DC0 completes the verified Apt constructor calls, enters 0x0087B640 at original callsite 0x00B57DD2, then stops at 0x0087B644 → 0x0087B59B. The latter requires warning-bearing SEH prolog 0x0087BEB8, thread FS state and unresolved provider cells 0x00B61398/94/8C. These are .rdata pointers, not import declarations; 0x008AAC6A lies inside the current instruction listing at 0x008AAC69. The wrapper's result arithmetic is fixture-tested only. This does not connect the island to the PE entry. Detailed evidence: runtime-phase67.md, ghidra-phase67.json and pe-evidence-phase67.json.

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
