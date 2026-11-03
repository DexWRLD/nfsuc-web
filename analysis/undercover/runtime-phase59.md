# Phase 59 boot callback diagnostics

Baseline main a808417, 22 ahead of local origin/main. The prior audit was untracked. The existing Wasm builder checked the original executable SHA-256 and lifted the two ordinary callback bodies and their shared tail target.

## Edge HTTPS evidence

BootLoadScreenLoaded at 0x008062A0 writes byte 1 at 0x01873177, then jumps at 0x008062A7 to 0x009ADC50. MainScreenLoaded at 0x00806290 reads [0x01873134], writes byte 1 to manager +0x6C at 0x00806295, and jumps at 0x00806299 to the same helper. Both execute the original MOV EAX,[0x0189BF08] at 0x009ADC53 and RET at 0x009ADC59. The bounded fixture provides zero initial flag bytes, a manager at 0x0300EC00, and a distinguishable return value 0x13572468. Both callbacks write 0 → 1 and repeat idempotently. Adjacent sentinels and the other callback's flag are preserved.

The host invokes each callback with a diagnostic cdecl frame. RET pops the sentinel 0x00DEC0DE and advances ESP from 0x0300EFF4 to 0x0300EFF8. Both caller-cleaned argument dwords and saved EBP remain intact. Null and unmapped manager fixtures trap on writes to 0x0000006C and 0xDEAD006C. The test executes original callback-to-helper control flow with synthetic entry state. It does not execute the native dispatcher or construct an AptManager.

## Registration and consumers

Supplied static chain: 0x008105B1 → 0x00810090, 0x008100E0 → 0x0080F6F0, vtable 0x00BBB27C, 0x0080FAE6 → 0x009B57C0, then dispatch at 0x009B5812 through cell 0x00BBB2BC to 0x0080D090. The first registration saves ECX in ESI and pushes callback 0x00806130 before call 0x0080D098 → 0x009ADCE0. Independent lift confirms that 0x009ADCE8 requests 0x24 bytes from 0x009E12F0 before any native object constructor runs. On nonzero return 0x009ADD00 calls 0x009DD350 with ECX=allocation and the callback argument. The registration then passes name and returned value to 0x009ADDF0 with the saved receiver in ECX. Later callback pushes at 0x0080D1E8 and 0x0080D207 construct MainScreenLoaded and BootLoadScreenLoaded and publish to 0x018731C0 and 0x018731C4 before property insertion. Allocation, successful publication, synchronization semantics and registration return remain unverified at runtime.

A bounded scan for the little-endian absolute operand 0x01873177 in ordinary text found the callback store and no verified direct read. This scan cannot exclude aliased accesses. A separate search for 0x01873134 recovered the manager's null check at 0x00810941, allocator call at 0x00810957 with size 0x70, constructor at 0x00810971 → 0x008101B0, and publication at 0x00810976. Failure writes zero at 0x0081098D. Verified adjacent readers include 0x0080459A (+0x68) and 0x0080FDC5 (+0x48). Neither establishes a read of +0x6C. No completion consumer, actual scheduling edge or browser-executable original transition is verified.

BootLoadingScreen, LS_EALOGO.FNG, LS_SPLASH.FNG, MC_MAIN.FNG and FeMainMenu.fng remain resource leads. LOGOTEXTURES.BUN, BOOTFLOWTEXTURES.BUN and FRONTB1.BUN have no verified member association from this phase. The independent JPEG and EA bumper previews do not establish native order.

## Readiness and validation

BOOT_CALLBACK_BROWSER_VERIFIED and MAIN_CALLBACK_BROWSER_VERIFIED apply to fixture entry. CMDUTIL_REGISTRATION_STATIC_VERIFIED covers the call and publication evidence. Registration execution, flag consumers, first screen identity, native order, screen display and original boot remain unverified. FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND remains blocked. Historical harness totals remain 84 unique, 50 enterable and 358 runs.

From web, node node_modules/typescript/bin/tsc -p ., node build.mjs and python ../tools/uc_browser_init.py with the original nfs.exe and dist/uc-init-009e8ad0.wasm exited 0. Clang retained the unused linker-path warning. The Node batch of uc-lan-https-browser, uc-startup-preview, uc-assets, uc-lan-server and uc-dxt1 passed 53/53 with Edge, UC_BROWSER_INIT_TEST=1 and the authorized local media root. This includes the callback cases and authentic bumper playback. Python Phase 43–51 regressions, guest campaign and dashboard validation were rerun.
