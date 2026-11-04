# Phase 67 handoff

Keep the unified constructor regression with the original root 0x00B57DC0. It supplies ECX=0x0189D0A0 itself and completes the original constructor callees. Do not substitute an Apt heap object.

The next unsupported original call is 0x00B57DD2 → 0x0087B640. Verify and implement the wrapper's CF/NEG/SBB/DEC semantics using the existing native CPU definitions as the reference. Trace 0x0087B59B → 0x0087BEB8 and state 0x018B1E6C before admitting a deeper prefix. Establish provider identity and ABI for 0x00B61398/0x00B61394; their file values are not verified Windows import identities.

Retain volatile register visibility across re-entrant Wasm dispatch. Add reviewed registry entries only after source bounds, callees, required globals and return contracts are established. Preserve the historical Apt fixture fault, private cache invalidation and master hash.

Reachability from PE entry 0x01FCA510 remains unverified. Connecting independent roots manually cannot establish native startup or the first gameplay frame.
