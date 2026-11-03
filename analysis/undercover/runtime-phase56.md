# Phase 56 Apt lifecycle

Baseline main c0fedcd, 16 ahead of local origin/main. The earlier audit is untracked. The existing builder verified the installed PE hash before lifting ordinary functions.

## Browser evidence

- The constructor diagnostic enters 0x009E7540 with ECX=0x0189D0A0 and a bounded guest stack. Original calls at 0x009E754A, 0x009E7555, 0x009E7560, 0x009E756B, 0x009E7576 and 0x009E7581 invoke 0x009E75A0 with offsets 0, 0xC, 0x18, 0x24, 0x30 and 0x40. Stores at 0x009E75AA, 0x009E75B3 and 0x009E75BD zero count, capacity and backing pointer. The diagnostic verifies all 18 writes against prefilled sentinel words and verifies the gap at +0x3C stays intact. Each original leaf returns to its caller. The probe cuts before 0x009E758C and does not test the outer constructor return or registration.
- A separate synthetic ABI fixture supplies one writable dword at 0x0300EE00, capacity one and an inert test pointer value 0x0300EE04. Original 0x009E47D0 stores the value at 0x009E480A and increments count at 0x009E4818. A separate host entry at 0x009B6290 makes the original call to 0x009E4B10 at 0x009B629E. Depth zero returns the same value in EAX. Both outer calls restore ESP to 0x0300F000 through their RET 4 contracts. The fixture never dispatches lifetime methods.
- The historical four-function trace still traps at 0x009E4B49 on 0xFFFFFFFC with zero count and backing pointer. This is an Apt fixture precondition failure. No original script caller or argument is established by that trace.

## Allocation and dispatch boundaries

The supplied Ghidra findings identify the allocation caller at 0x009B67D1. 0x009E4640 sets capacity and requests capacity times four bytes through 0x009DC250. The wrapper reserves four more bytes for the size header and returns the interior payload pointer for publication at 0x009E46A1. The reported downstream factory vtable cell 0x00B6CDC4 points at unresolved 0x004A9FF0. That dependency is distinct from 0x00686000 and cleanup. The allocation trace is static and no allocation provider was executed.

The supplied Ghidra findings identify native registration via case 0x7F in 0x009A0BE0, method field +0x20 and publication at 0x0189CC7C. The reported dispatch path 0x009B4E50 → 0x009B62D0 → 0x009E4760 pushes resolved arguments before conditional 0x009B9160 → 0x0099DCD0. Argument ownership, reverse-order pushes and method resolution remain unverified in the browser. No synthetic reference methods or native invocation were supplied.

## Validation

From web, node node_modules/typescript/bin/tsc -p . and node build.mjs passed. python ../tools/uc_browser_init.py with the verified nfs.exe and dist/uc-init-009e8ad0.wasm exited 0 with the existing unused linker-path warning. node --test test/uc-lan-https-browser.test.mjs test/uc-startup-preview.test.mjs test/uc-assets.test.mjs test/uc-lan-server.test.mjs test/uc-dxt1.test.mjs passed 53/53 with UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1 and the authorized media root. The opt-in test verified both Apt diagnostics, exact historical fault and authentic bumper playback.

The constructor edge and synthetic ABI tests are separate browser results. Harness totals stay 84 unique, 50 enterable, 358 runs. Original startup, allocation, native argument dispatch and gameplay first frame remain unverified.
