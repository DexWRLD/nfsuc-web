# Phase 76 handoff — review ordinary CRT startup context

Phase 75 achieved the host-scheduled compatibility-cookie milestone in Edge. Read runtime-phase75.md, crt-bootstrap-provenance-phase75.md, crt-compatibility-contracts-phase75.json, crt-cookie-evidence-phase75.json and crt-bootstrap-execution-phase75.json. Original PE entry and loader binding remain unverified.

## Preserve the established split

- Original-only default: fourteen-body ordinary module, existing exact provider trap. Selecting the diagnostic variant permits the reviewed cookie body but no host substitution unless Compatibility CRT is explicitly selected.
- Compatibility CRT: one shared checked guest process, separately pinned fifteen-body module and only five reviewed compat.kernel32 service callsites. No raw-address provider registration, import-cell write or CALL patch.
- Synthetic fixtures: deterministic clock/ABI/error/reset tests, separately labeled. Live Edge success uses browser UTC/monotonic values and virtual IDs, not a selected cookie result.

Cookie returns from 0x0087C2F7 to synthetic 0x00DEC0DE and restores ESP=0x0300F000. Original stores write cookie/complement at 0x01285688/8C. Host writes are only the root frame, service output buffers and thread-prefix fields. The conditional SHL at 0x0087C2E0 remains trapped; do not silently add unchecked flags or avoid that branch with selected entropy.

The prepared NT_TIB32 prefix uses FS=0x03100000, exception head FFFFFFFF, StackBase 0x03010000, StackLimit 0x03000000 and Self at +0x18. [Self+4] is StackBase, not the thread ID. This is a single compatible diagnostic thread, not original Windows thread production, full TLS, scheduling or exception dispatch. Reset and unsupported fields/thread changes are checked.

## Next bounded target

Review original 0x0087BB3D before admitting or executing it. Confirm its exact SEH prolog input/scope contract; the existing prolog dispatcher contract is specific to the prior cleanup fixture and must not be reused blindly. Confirm the verified FS:[0x18] and owner-token reads and original state branches.

Its synchronization calls require documented InterlockedCompareExchange/InterlockedExchange/Sleep contracts and exact reviewed operands/ABI. None is implemented yet. Define ownership/reentrancy/error semantics and browser scheduling before permitting the original code to reach those calls. Never pre-mark startup state/owner or report an API-induced host write as a direct original MOV. Stop if faithful synchronization is unavailable.

Only after that gate may _initterm_e be considered. Authenticated C table [0x00B63DC4,0x00B63DD4) contains [0,0x0087BCB3,0x0087BFE4,0x0087C08B]. The first nonnull initializer 0x0087BCB3 is not admitted and requires actual PE-header reads and provider contracts. Do not skip it to run the CPU initializer or Apt constructor. All required nonnull entries must be reviewed and return in order before claiming traversal complete.

__set_app_type legacy equivalence and pointer encoding remain unresolved. Modern _set_app_type documentation does not automatically prove the double-underscore export's exact behavior. No identity transform, secret or sentinel is supplied. C++ range [0x00B61730,0x00B63DC0), Apt cell 0x00B6370C, cleanup registration, locks/callback storage and EH4 remain later gates. Both cleanup globals and startup state/owner remain unchanged zero in Phase 75.

Original loader provenance is still unknown. Compatibility routing is user-authorized host substitution, not new evidence reopening the closed original legacy-binding mechanism. Do not reconstruct protected entry, supply guessed loader behavior or call this authentic startup. Keep full-game Play disabled. Do not revisit x86 performance or graphics.

## Reproduction and validation

Check current HEAD/status; preserve 22 unrelated discord-bot deletions. No fetch/push. Source SHA 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd; canonical master f293d93d31fcbf86ad9b9639f2cf10c34defe9c621cfe7f1a5e975f598ddf88a.

Build the ordinary module plus --crt-cookie-output pointing outside Git and the original installation. The pinned diagnostic file is selected locally in Play Development Preview -> Execution inspector -> CRT bootstrap. No new LAN manifest path is authorized. Keep ordinary module hash/allowlist, OPFS and authentic media intact; no commercial module/payload or DLL belongs in Git.

UC_CRT_COOKIE_MODULE selects the external reviewed file for tests; UC_CRT_EVIDENCE selects a new browser report. Existing x86/Edge results use separate Phase 75 regression files so historical evidence remains intact. Phase 75 validation: 166 Node/Edge tests, 165 passed and one existing skip; 134 Python unit tests; native comparison plus 105 arithmetic cases; frontend/TypeScript/Wasm/preflight/campaign/dashboard passed. Do not inflate unique original function metrics with host calls or reruns.
