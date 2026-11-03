# Phase 53 Undercover browser initializer

Baseline main 34bcbe3, nine ahead of local origin/main. The homepage edits and post-Phase-52 audit were already in the working tree. Phase 53 includes the homepage changes and leaves the standalone audit untracked.

## Reproduction

From web, run node build.mjs, then:

    python ../tools/uc_browser_init.py "C:/Games/Need For Speed Undercover/nfs.exe" dist/uc-init-009e8ad0.wasm

The builder checks the executable SHA-256, uses the existing RawLifter, checks the lifted instruction shape, and links freestanding Wasm with the existing Unity clang and wasm-ld. The local Wasm is generated in dist and stays out of Git. Open the HTTPS homepage, select Play Development Preview, then Run Initializer.

## Result and dependency inventory

Edge Chromium instantiated the module over HTTPS. The original translated no-argument registration initializer at 0x009E8AD0 executed 49 guest writes. Guest slot 0x0189D1A4 changed from 0 to 0x009E78C0. The return popped the harness sentinel 0x00DEC0DE and restored guest ESP from 0x0300EFFC to 0x0300F000. EAX stayed at its initialized zero. The isolated bridge maps only the aligned slot interval 0x0189D198–0x0189D270 and one stack word. There are no Wasm imports, outgoing guest calls, native callbacks, or synthesized guest objects. Unsupported lifted operations are rejected at build time and out-of-range access traps. The module uses zero-initialized diagnostic slots, not a loaded full PE image.

This is original initialization logic executed in isolation. The real caller chain through 0x009E9160 and 0x008101B0 remains unresolved at runtime. Callback dispatch was not attempted. Earlier harness continuation at 0x0099DCD0 reached 0x009E4B49 and faulted on the missing object field at 0x0189D0A0+8. The allocator-shaped path for 0x0189DA88 and graphics callback cell 0x00B615C4 remain separate dependencies. Full game boot and FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND remain blocked.

## Homepage and dashboard

The default entry boots Undercover previews on user request. It leaves the inherited game loader out of the preview entry. PAGE-NOT-ISOLATED comes from the inherited isolation check for SharedArrayBuffer. MODULE-LOAD wraps the failed game.json fetch on the inherited game path. The private static host returns 403 for the missing game module. No placeholder game.json was generated. The real game action is disabled. The existing authorized media, fixture previews and cache are reused.

Dashboard JSON, HTML, SVG and PNG were regenerated with the latest historical native guest ledger selected for 84 unique, 50 enterable and 358 runs. The browser initializer is a separate result for a previously executed address. The compile tally remains 22,770 of 22,779 high-confidence targets. The readiness population and allocator-rooted count remain 72 and 74 respectively.

## Validation

TypeScript and frontend build exited 0. Python phase regressions 43–51 and tools/uc_progress_test.py exited 0. tools/uc_phase31_campaign.py exited 0 and still reported blocked cases as expected. The targeted Node and Playwright batch passed 53/53, with UC_BROWSER_CHANNEL=msedge, UC_BROWSER_INIT_TEST=1 and UC_AUTHENTIC_ASSET_ROOT set to the authorized local root. The browser test checked the initializer's exact slot and return trace and replayed the authentic MP4. No physical second-PC test was performed.
