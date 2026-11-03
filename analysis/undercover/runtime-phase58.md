# Phase 58 frontend error-screen queue

Baseline main 3cf5727, 20 ahead of local origin/main. The earlier audit remains untracked. The Wasm builder checked the installed PE SHA-256 and lifted the original queue bodies.

## Edge execution

The queue diagnostic uses fresh bounded synthetic guest memory per case. Begin is 0x0300ED48, entry pointer cell 0x0300ED40, record 0x0300ED60 and underlying object 0x0300ED80. The record has state 1 except for the nonpending control. Selected index 7 and the object field 900 are fixture values. The scanner does not consume the selected index on the observed prefix.

- 0x0080F4F0 receives manager+0x10 in ECX and the entry-pointer cell on the stack. On empty and one-existing-entry fixtures, the original stores at 0x0080F4FD and 0x0080F508 advance end by four and write the entry pointer to the former end slot. Final ends are 0x0300ED4C and 0x0300ED50. Surrounding sentinels are preserved. RET 4 restores ESP to 0x0300F000. The full case stops at 0x0080F513 before calling unavailable 0x005D6B20 with unchanged vector contents.
- 0x008091E0 receives the manager in ECX with no stack arguments. Disabled, empty and nonpending cases return with ESP, ESI and EDI restored. Pending state 1 reads the underlying object and its +0x58 numeric field. The probe captures 900 and stops at 0x00809200 before calling unavailable 0x0055FEB0. Pending state stays 1. Null and unmapped entries attempt reads at 0x00000004 and 0xDEAD0004 and trap. The UI verifies fixture fields and sentinels across all cases.
- The append and scanner are independently entered. Neither was connected to the original producer or Apt dispatch. The inspector labels all nine cases as synthetic fixtures and shows which original code ran.

## Original path and unresolved providers

The supplied Ghidra evidence identifies 0x00810911 → 0x0080FB50 as an error-screen request, with selector 0x22, selected index from ordinary code and numeric argument 900. Its resource dependency is FRONTEND/ERRORTEXTURES.BUN. The known append call is at 0x0080FBE9 and scanner calls at 0x0080FC52 and callback tail 0x008096D4. Live manager construction, queue entry allocation, the underlying factory object, resource gates and callback scheduling remain unresolved for browser execution.

At 0x00809200 the scanner passes the numeric field to the unresolved string producer. The subsequent call to 0x00804550 uses the returned string and the numeric argument, with caller cleanup of eight bytes. The wrapper formatting path reaches 0x004ACEB0 at 0x00804590. The requested method is _level0._root.gblPushScreen. The screen-name result is unknown. The original state-2 write follows wrapper return at 0x00809210. Neither wrapper return nor screen display was demonstrated.

## Readiness

FRONTEND_QUEUE_APPEND_BROWSER_VERIFIED and FRONTEND_QUEUE_SCAN_BROWSER_VERIFIED apply to the synthetic fixture cases. FRONTEND_QUEUE_NATIVE_STATE_VERIFIED, FRONTEND_SCREEN_ARGUMENTS_VERIFIED, FRONTEND_APT_DISPATCH_BROWSER_VERIFIED, ORIGINAL_FRONTEND_SCREEN_DISPLAYED and ORIGINAL_GAME_BOOT_EXECUTING remain unverified. FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND remains blocked. Historical harness metrics stay 84 unique, 50 enterable and 358 runs.

## Validation

TypeScript, frontend and Wasm builds exited 0. The Wasm builder emitted the existing unused linker-path warning. Node and Edge ran the targeted asset, startup, LAN, BC1 and authentic media tests. The first run exposed a test assertion splitting the inspector output on a literal backslash-n. The corrected run verifies nine queue cases twice inside the HTTPS browser test. Python Phase 43–51, guest campaign and dashboard validation were rerun.
