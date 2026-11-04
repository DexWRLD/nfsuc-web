# Phase 75 — CRT bootstrap provenance

There are three distinct modes: original PE entry (not executed), host-scheduled compatibility CRT (cookie routine executed in Edge), and synthetic fixtures (unit/negative ABI, clock, budget and reset tests). None supplies evidence for original loader binding or authentic game startup.

| Item | Producer / authority | Classification |
|---|---|---|
| Ordinary PE bytes and initial cookie | Hash-verified original source; existing descriptor/payload | Authenticated original data |
| New cookie body | Existing RawLifter, exact reviewed [0x0087C264,0x0087C2F8), 52 starts | Opt-in ordinary diagnostic; SHL path remains trapped |
| Manual entry / return slot | Host invokes 0x0087C264; sentinel 0x00DEC0DE | Host scheduling and synthetic call frame |
| Legacy operands/name records | Original read-only memory, unchanged | Import metadata, not resolved providers |
| Five service calls | Exact reviewed callsite/operand/name/return ABI; explicit compat.kernel32 namespace | Logged host substitutions |
| Clock values | Browser UTC/monotonic APIs in a defined virtual boot/counter model | Compatibility environment, not game state |
| Process/thread IDs | Unique page-runtime virtual identity allocator | Compatibility context, not host OS identities |
| Cookie and complement | Original XOR/branch/NOT/stores at 0x0087C2E5/ED | Original guest-code writes, derived from service inputs |
| FILETIME/QPC buffers | Host services write validated stack output ranges | Host environment writes, separately logged |
| FS/NT_TIB32 prefix | Host constructs only verified fields after cookie returns | Synthetic Windows-compatible thread, not original initialization |
| Startup globals / initializer tables | Remain original data; no traversal/completion | Unsupported gates, not initialized by host |
| Existing cleanup trap | Unchanged 0x0087B5B3 -> raw 0x008AAC6A | Original-only regression; not redirected in compatibility mode |

The compatibility namespace does not register functions at raw metadata addresses, rewrite legacy/active tables, add the image base, patch CALL bytes, or claim that Windows resolved the original block. It intercepts only five explicitly reviewed original callsites. Unknown sites/targets still trap. Service ABI returns consume actual original return addresses and stdcall arguments.

Original arithmetic remains guest code; host APIs do not take a desired cookie parameter and do not store cookie globals. Deterministic input fixtures validate arithmetic/reset independently and are not used as the live-browser success claim. Buffer faults, clock errors and unsupported SHL stop without manufactured success. NOT and LEAVE preserve defined flags; the checked-shift deficit is explicitly retained.

The successful live invocation executes no original CRT wrapper, PE entry, C table, C++ table, callback registration or gameplay. Prepared [FS:[0x18]+4] is NT_TIB.StackBase; virtual thread ID is separate. Startup owner/state and cleanup globals remain zero, which is not proof of initialized CRT sentinels.

Source and API references, exact operands, argument counts, conventions, cleanup, outputs, errors and deferred service limits are in crt-compatibility-contracts-phase75.json. Actual instruction/service/write journals and exact return are in crt-bootstrap-execution-phase75.json. The optional module is selected locally and excluded from Git/LAN distribution; original assets and the existing manifest remain unchanged.
