# Phase 57 frontend lookup prefix

Baseline main 95cb002, 18 ahead of local origin/main. The earlier audit remains untracked. The existing builder checks the installed PE SHA-256 before extracting and lifting ordinary code.

## Edge evidence

The diagnostic uses original PE string and table bytes with a harness-provided cdecl call frame. Original 0x009981F0 calls original hash 0x009DE390 at 0x0099820A. The length-13 hash returns index 118. The original lookup bounds checks and first-byte comparison run and select 0x0129D858. The diagnostic reads candidate ID 0x7F from original 0x0129D85C. The inner call returns to 0x0099820F and the caller removes eight argument bytes, restoring its local ESP to 0x0300EFE8. Invalid lengths 1 and 21 take the original zero-result path and return with the cdecl arguments still on the guest stack.

Execution stops at 0x00998241 before the full comparison. The next call at 0x0099824F targets 0x00AE52C8, which the lifter independently confirmed tail-dispatches via [0x00B61480]. Short-name hash jump table paths are outside the bounded diagnostic. Arbitrary missing-name and out-of-range hash cases were not executed. This proves candidate selection, with complete name equality and method-object resolution pending.

## Static context and blockers

The supplied Ghidra evidence identifies native localToGlobal at 0x0099DCD0, registered by case 0x7F of 0x009A0BE0, object +0x20, cached at 0x0189CC7C. The reported receiver vtables 0x00C300C0 and 0x00C30298 resolve through slot +0x18 to 0x009A0BE0. Cache hit 0x009A2396 and cache-miss allocation 0x009A2333 → 0x009E12F0 remain static evidence. No cache object or allocator was supplied.

The reported 0x009B4E50 invoker uses five caller-cleaned dwords. The argv push path runs through 0x009B62D0 and 0x009E4760, with retain through value vtable +0 at 0x009E47BC and release through +4. The native call through method +0x20 is at 0x009B91AE. These argument ownership and invocation contracts were not executed in the browser.

The builder independently verifies [0x0127D304] points to the original _level0._root.gblPushScreen string at 0x00BBAAC8. The reported frontend path is 0x00810911 → 0x0080FB50, 0x0080FC52 → 0x008091E0, 0x00809206 → 0x00804550, and 0x008045B4 → 0x009B5080. The list-state-one selection and post-return transition to state two remain static findings. Argument preparation reaches unresolved 0x0055FEB0 and 0x004ACEB0 with an unresolved downstream target. The frontend invocation and original menu were not executed.

## Validation and readiness

TypeScript, frontend and Wasm builds passed. The targeted Node and Edge HTTPS batch passed 53/53, including repeated lookup, historical fixture fault, Apt diagnostics, and authentic bumper playback. Python Phase 43–51 regressions, guest campaign, and dashboard validation were rerun. Historical harness counts stay 84 unique, 50 enterable and 358 runs. This phase adds two browser-executed original functions on one connected lookup-to-hash edge. Native dispatch, frontend invocation, full startup and the first gameplay frame remain unverified.
