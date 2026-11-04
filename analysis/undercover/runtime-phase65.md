# Phase 65 unified translated execution

Baseline d343649f on main, six ahead of local origin/main. Pre-existing discord-bot deletions were preserved. No fetch. The provided brief ended mid-sentence after “shared-state”; implementation followed the supplied requirements.

## Shared process integration

The existing RawLifter emits the already verified initializer and Phase 54 callback prefix. tools/uc_unified_build.py reuses the established bounded prefix selection, verifies the original executable digest, instruments original instruction addresses and changes guest memory operations into imported checked reads/writes. Original guest CALL pushes and return addresses are preserved. Guest address dispatch now handles already-pushed call frames through GuestDispatcher.callFromGuest.

The Wasm imports env.memory plus guest.read32, guest.write32, guest.dispatch and guest.instruction. It runs inside the same WebAssembly.Memory as GuestAddressSpace. There is no original-global shadow array in this module. The low-address compiler CPU/flag scratch is distinct from guest PE and stack mappings. Guest CPU/register views synchronize at each dispatch and return. General EFLAGS support is not claimed.

## Authenticated PE mapping

The original SHA-256 is 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd. Five ordinary sections (.text, .rdata, .data, .tls, .rsrc) retain original virtual addresses and permissions. Data tails zero-fill. Like native uc_image.c, initialized bytes are clipped to virtual size. Six opaque sections are retained as unavailable descriptors without payload bytes. No PE entry is executed.

Private payload size is 15,356,006 bytes, SHA-256 35bc6b5a51a82fa9fc0ea5be991e1f67a4bbcfa87f2cd529867e40ed7961fcfa. The module is 4,484 bytes, SHA-256 025c086bacdedc7790395d1bc1ab2fbf82a7edaf505b634334e21b159804b6b5. The descriptor links source, payload, per-section hashes and module digest. Manifest verification precedes cache publication. Actual initialized bytes and BSS tails, read-only vtable data, protected spans and reset are tested.

Publication was initially rejected by automatic approval review due to LAN exposure of executable sections. The user explicitly approved private LAN delivery. The payload, descriptor and module were then added to the existing curated authorized-startup allowlist. They stay outside Git. tools/uc_unified_publish.py reproduces the allowlist and manifest update for explicitly approved files.

## Original execution evidence

The process maps 50,397,184 bytes including explicit diagnostic stack. Original static vtable cell 0x00BBB2BC reads 0x0080D090 and rejects writes. Initial PE slot 0x0189D1A4 is zero. Translated 0x009E8AD0 performs 49 checked writes, sets the callback to 0x009E78C0, returns EIP 0x00DEC0DE and restores ESP 0x0300F000.

Without resetting memory, the host supplies historical fixture arguments (0,2) to root 0x0099DCD0. Guest execution enters 0x0099DCD0 → 0x009E78C0 → 0x009B6290 → 0x009E4B10 → 0x009E78C0. Calls use original return addresses through the shared dispatcher. The original read at 0x009E4B49 sees EDX=0 and EAX=0 and attempts 0xFFFFFFFC. The checked process rejects it. unified-execution-phase65.json records the trace and register snapshot.

Calling the root before registration traps on unknown dispatch target zero. Reset restores PE bytes, zero tails, CPU and traces. Two runs on the same process verify repeatability. Host order between the registration leaf and root is diagnostic ordering, with original startup order unverified. No constructor state, heap object or callback implementation was fabricated.

## Browser and legacy paths

The existing Execution Inspector now offers Run Shared Process Integration. It downloads the three approved assets through the current manifest, SHA verification, OPFS and memory fallback infrastructure. Edge ran the integration repeatedly and after reload with one total payload request. The JPEG, EA bumper and historical diagnostics retain their existing controls. Older diagnostics are labeled as separate bounded memories for regression purposes.

## Reproduction

    python tools/uc_unified_build.py "C:/Games/Need For Speed Undercover/nfs.exe" "<authorized-asset-root>"
    python tools/uc_unified_publish.py "<authorized-asset-root>" --allowlist "<existing-private-allowlist>" --manifest "<private-manifest>"

From web, build with node build.mjs. Run the HTTPS server with the authorized root and generated private manifest. UC_AUTHENTIC_ASSET_ROOT enables the opt-in Node integration test; UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1 and UC_UNIFIED_TEST=1 enable the combined authentic browser test.

## Validation

- TypeScript and frontend build exited 0.
- Unified Wasm build exited 0.
- Maintained Node and Edge suite: 143 tests, 142 passed, zero failed, one skipped (bundled Chromium unavailable for the older synthetic logo test).
- Opt-in unified-process test passed, including source/module/payload validation, raw bytes and zero tails, blocked section access, write permissions, original call trace, incorrect initialization order and reset.
- Startup/master preflight: three passed; canonical master hash unchanged.
- Python Phase 43–51 regressions each exited 0.
- Guest campaign exited 0 with expected blocked cases.
- Dashboard validation rerun.

The full-game action remains disabled. PE entry remains BLOCKED_UNVERIFIED_ENTRY_CONTROL_FLOW. Historical harness totals are unchanged at 84 unique, 50 enterable and 358 runs.
