# Undercover web project audit after Phase 52

## Executive summary

The project has an independently functioning browser preview for two genuine shipped assets, a JPEG and a video-only EA bumper derivative. It also has a substantial static translation inventory and a small translated execution laboratory. There is no demonstrated Undercover browser boot, live game menu, authentic scene submission, or gameplay loop. Phase 52 finished the local media milestone. Physical second-PC validation and the full media failure matrix remain open.

Git baseline was clean main at 34bcbe3, zero behind and nine ahead of local origin/main. History contains f810d60, 3adbbb2 and 34bcbe3. No fetch was performed. No tracked game.json or Wasm was found by git ls-files. The install nfs.exe hash matched 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd. Historical target metadata identifies Undercover PC 1.1.2.1, PE32 x86, image base 0x00400000.

## Current verified metrics

| Metric | Evidence and interpretation |
|---|---|
| 25,450 discovery map cells | Candidate map population, includes rejected/data cells and does not establish the executable's true total function count. |
| 22,779 HIGH, 165 MEDIUM, 54 LOW, 1,454 rejected | Discovery snapshot categories in progress.json. These displayed discovery totals do not reconcile with the map population, so treat them as separate recorded aggregates. |
| 22,770 of 22,779 compiled, 99.9605% | high-confidence compile record consumed by tools/progress.py and validated by uc_progress_test.py. Nine boundary problems before generation, zero recorded compiler failures. This is a high-confidence batch compilation tally, with no fresh translation or browser link audit. |
| 2,680 map cells outside compiled classification | 1,182 discovered not generated, nine boundary problems and 1,489 rejected/data in the map breakdown. This is not a count of missing runnable functions. |
| 84 unique, 50 enterable, 358 recorded runs | phase51-execution.json and runtime-phase51.md. 346 is Phase 50. No Phase 52 execution increment is recorded. Historical rollup, not a fresh 358-run replay. |
| About 0.369% | 84 divided by 22,770. Indicative coverage assuming shared population, with no independent address-by-address join performed. |
| 72 runtime-ready, 74 BLOCKED_EXTERNAL | Recorded classification rollups. Runtime ready and enterable have distinct definitions. The map's 54 unexecuted-ready cells use older evidence. Subtraction across these populations does not establish a current count. |

Compilation generates and compiles lifted function code from accepted control-flow regions. It does not link a working browser game or prove calls, imports, guest globals, heap state, x86 register and stack conventions or scheduling work together. The historical code analysis lists 1,264 unsupported reached instructions in its analysis population, including lock xadd, far calls and privileged/control-flow instructions. Unresolved calls and import closure are separately tracked. The compiler-success badge contains no whole-program stub inventory or end-to-end entry assertion.

## What works today

- Genuine asset previews: installed dialoglogo128x128.jpg and the authorized copy match SHA-256 6c30b18704f937bb7257b44598bc66097de2bbc806e007d8f72c2d19765408a7. The authorized LAN route served the JPEG and provenance during the browser test. The test asserts movie playback rather than image pixels. Phase 51 records verified image rendering. Archive membership and identification as LS_EALOGO are unresolved.
- Shipped bumper source hash d4982c58fa09d35390b4b02f504035002e0ec665ced3cd13f9f92e413284012c and derivative hash c21e846377132ea74773e1b7a41679f27bcf47f5634fc752dc267b74b7284eb8 matched freshly. Phase 52 provenance records EA VP6, 1280 x 720, 346 frames, 11.544643 seconds, H.264 yuv420p output, and no output audio track. Original and derivative FFmpeg null-decode successes are historical evidence. EA audio revision2=23 was unsupported. This audit replayed the actual derivative over HTTPS, including advancing playback, pause/resume, end/skip and one total MP4 download across a reload.
- Translated guest functions: ordinary math, helpers, constructors and stateful object lifecycle cases entered through harnesses with specified inputs and state. Phase 51 reruns preserve the three recorded lifecycle families. Harness assertions and ABI observations provide local confidence. Host setup and browser models are separate evidence.
- Synthetic demonstrations: D3D-like command recording, WebGL clear/draw previews, fixture-based BC1 decode and mesh/declaration validation. These establish browser components and data contracts.

## What does not work

The real game cannot launch from the Play control. The development surface has independent startup media controls and diagnostics. A single development Play flow that sequences all supported previews was not found. Inherited module boot still requires a valid game.json and runnable module. No accepted Undercover browser boot artifact or reproducible boot-link command was identified. No test showed original code starting the browser game, scheduling a scene, drawing shipped geometry, or steering a car.

## Architecture and subsystem scorecard

Weights express priority for a playable game, not measured completion. Critical means a dependency of the first gameplay loop, supporting means useful but separable, and distribution means deployment validation.

| Area | Weight | Verified state | Remaining work | Confidence |
|---|---|---|---|---|
| Static analysis | Supporting | Large address/CFG inventory and callsite records | Resolve boot and frame caller edges and data provenance | High for recorded edges |
| Compilation | Critical | High-confidence batch compile record | Reproducible linked Undercover module, ABI and imports | High for record, low for integration |
| Guest execution | Critical | Stateful harness islands and isolated functions | Browser-callable connected startup slice | High for harness scope |
| Platform compatibility | Critical | Selected import/helpers and fixture filesystem models | Process/thread and synchronization semantics, timing and Windows API contracts | Medium |
| Runtime boot | Critical | Entry scheduling unproven, globals and allocation incomplete | Establish ordinary entry, static constructors, allocator-owned global state | High |
| Asset loading | Critical | Manifest delivery, SHA checks, OPFS/memory fallback, virtual path bridge | Native archive I/O and verified resource spans | High for delivery |
| UI/frontend | Supporting | Independent startup panels and inherited shell | Authentic menu resources and state transitions | High |
| Video playback | Supporting | Actual shipped derivative plays | Source audio and native boot scheduling | High |
| Audio | Critical for substantial playability | No verified Undercover mixer or source audio in preview | Source format, runtime sound banks, mixer and timing | High for preview limitation |
| 3D rendering | Critical | Synthetic browser graphics and format utilities | Device initialization, real buffers, textures, shaders, camera and scheduling | High |
| Gameplay simulation | Critical | No demonstrated real simulation loop | World, vehicle, input and time-step integration | High |
| Browser deployment | Distribution | Local HTTPS private manifest pipeline | Trusted certificates and production module isolation | High for preview |
| Second-PC testing | Distribution | Loopback Edge test and historical clean-profile evidence | Physical LAN playback, trust and cache test | High |

Input, saves/configuration, and event loops in inherited browser infrastructure are not verified against Undercover. Render-thread ordering, scene lifetime and device creation are missing or blocked. Guest memory tests exercise bounded prepared objects. They do not establish Windows process memory, allocator ownership, TLS, full initialization or stack/calling convention behavior across arbitrary lifted code.

The LAN server provides private HTTPS, curated allowlists, path checks and Range support. OPFS and memory fallback support manifest-backed downloads and the bridge exposes virtual paths. PAGE-NOT-ISOLATED means the inherited SharedArrayBuffer check failed, distinct from HTTPS secure context. Inspect crossOriginIsolated and actual COOP/COEP on the intended module host before treating it as resolved. MODULE-LOAD surfaces the fetch failure for /game.json. The static LAN server rejects unavailable paths with 403; a working preview does not require that module. Neither a secure connection nor bypassing the inherited launch flow proves native launch readiness.

## Critical blockers

1. No proven browser-loadable Undercover module tied to an ordinary startup path with initialized guest state. In 00686000-provenance.md, the allocator-shaped call from 0x008101B0 feeds the only recorded ordinary store path for 0x0189DA88. The 0x0099DCD0 closure has 102 statically bounded functions but the tested prefix entered four and faulted at 0x009E4B49 when [0x0189D0A0+8] was zero. A clean allocator-edge cut does not supply the required object.
2. Missing lawful device startup and scheduling proof. At 0x0072E340, three indirect calls through the pointer cell 0x00B615C4 precede Direct3DCreate9. The file value 0x008AA3AE is inside another function and is not a verified CFG entry. Treat this as unresolved indirect state. The static caller 0x0072E5D0 does not establish a reached runtime edge.
3. The clear-only 0x00725200 sequence reaches BeginScene, Clear, EndScene and Present in the static record. No authentic draw lies in that clear bracket. Scene path 0x00770750 → 0x0076FC30 → 0x00757B80 reaches 0x00757C9A → 0x006860F0. Later Present at 0x00752B14 is separate evidence. No verified same-frame scheduling, geometry, or browser handoff connects those observations.
4. Missing verified game-resource spans and upload. Capture a bounded ordinary reader and associate the exact file, span, size, SHA and consumer fields with a decoded texture or mesh. For geometry establish declaration, stride, index bounds, transforms, shader/texture bindings and lifetime before testing presentation.

| Address | Evidence classification |
|---|---|
| 0x00686000 | Unavailable allocator-shaped helper with ordinary callsites and pointer return provenance. The 74 BLOCKED_EXTERNAL cells count must-reach allocator-rooted cases from the helper cut, not all rendering or runtime blockers. |
| 0x00686030 | Free-shaped opaque target, separate identity and caller evidence. |
| 0x004A26B0 | Opaque backend target on scene branches, recorded calls at 0x007A416C and 0x007AFC67. |
| 0x007A51B0 | Opaque submission target, recorded edge from 0x007A86E0. |
| 0x0071E380 | Opaque cleanup target with bad-instruction evidence. |
| 0x00B615C4 | Indirect pointer cell with invalid-as-entry file value, no callable implementation established. |
| 0x006860F0 / 0x00686290 | Distinct undefined indexed and user-memory draw-shaped targets. |
| 0x006861B0 | Separate bad/overlapping instruction entry reached at 0x00765383. |

These labels come from repository static evidence, especially graphics-init-graph.md and first-frame-report-2026-11-03.md. Undefined or overlapping instructions alone do not identify DRM or justify implementing a stand-in.

## Game-resource evidence

Fresh inventory confirmed GLOBALB.BUN (13,659,904 bytes), GlobalB.lzc (6,138,385), LOGOTEXTURES.BUN (2,178,816), BOOTFLOWTEXTURES.BUN (530,176) and FRONTB1.BUN (450,304). Presence establishes candidate containers. No new archive format or membership proof was made. LS_EALOGO.FNG and FeMainMenu.fng are name leads. Cars, levels, shaders, fonts, sound banks, genuine vertex/index buffers and transforms have no verified extraction-to-native-loading chain in the reviewed evidence. JPEG and VP6 have independent validation and presentation paths. Native game asset loading remains unverified even for those assets. For a bounded UI milestone use an ordinary loader or a validated directory record to prove a boot-texture span from LOGOTEXTURES/BOOTFLOWTEXTURES. For 3D, XP_SMOKEBALL_CURL/PUFF have leads but require matching vertex/index spans and declaration before using them as a test resource.

## Historical phase audit

| Phase | Objective | Reported and audited evidence | Remaining dependency |
|---|---|---|---|
| Foundations–42 | Discover/lift functions, create guest harnesses, execute object chains | Compiler record, helper-cut, lifecycle evidence. Phase 42 snapshot 67 unique, 33 enterable, 265 runs. Historical baseline. | Real entry, linked module, state providers |
| 43 | Graphics object and PCDisplayConfig evidence | Static fields/config contracts and passing regression | Dynamic identity, device and lifecycle |
| 44 | Attribute external cuts | 74 allocator-rooted population and passing regression | Other opaque and indirect dependencies |
| 45 | Allocator-independent guest work | Matrix/helper entries and passing regression | State-bearing boot edge |
| 46 | Extend guest helpers and map first frame | Clear/draw distinction, matrix and reclaim cases, passing regression | Device, scheduler and submission |
| 47 | Clean-profile assets and renderer | Manifest/cache, synthetic renderer and harness expansions | Authentic archive loading |
| 48 | Hardening and clean-PC validation | Digest/error paths and 84 unique, 50 enterable reported | Native initialization |
| 49 | Private LAN and browser boot stages | HTTPS host and secure cache. Boot-stage names describe browser preparation | Physical PC and game module |
| 50 | BC1, declaration and mesh validation | Synthetic format utility tests, cube texture correction. 346 runs reported | Authentic payload provenance |
| 51 | Authentic dialog JPEG | Authorized asset pipeline and 358-run ledger, no new unique entries | Native logo proof and video |
| 52 | Authentic bumper preview | MP4 delivery and playback independently replayed during audit | Original audio and startup order |

The older map and newer execution ledgers are duplicated reporting layers with mismatched semantics. Similar matrix smoke cases expand execution counts with limited boot impact. The previous no-decoder banner was superseded for offline video, while unsupported original audio remains real. No retired implementation was independently established.

## Test validation

Windows PowerShell, local Node and Python, installed Edge Chromium for the authentic test. Commands ran in the repository or web subdirectory. The working tree was clean after the test batch.

| Command | New result | Scope |
|---|---|---|
| python tools/uc_phaseNN_test.py for NN=43 through 51 | Nine scripts exit 0 | Existing phase regressions, individual assertion counts not captured |
| python tools/uc_progress_test.py | Exit 0, 25,450 cells and 15 completed entries in map check | Dashboard generation/invariants, does not prove freshness |
| node node_modules/typescript/bin/tsc -p . | Exit 0 | TypeScript |
| node --test test/uc-assets.test.mjs test/uc-lan-server.test.mjs test/uc-startup-preview.test.mjs test/uc-dxt1.test.mjs | 51/51, exit 0 | Asset integrity, LAN, media state machine and synthetic graphics/data |
| UC_BROWSER_CHANNEL=msedge and UC_AUTHENTIC_ASSET_ROOT set to authorized-startup, then node --test --test-name-pattern='authorized EA bumper' test/uc-lan-https-browser.test.mjs | 1/1, exit 0 | Genuine MP4, local HTTPS, real browser and cache reuse |

Phase 52 has prior frontend build and FFmpeg evidence. No fresh full guest campaign replay, exhaustive Playwright suite, live Ghidra session inspection or physical second-PC test is claimed. This audit did not execute the original game.

## Progress dashboard audit

tools/progress.py and tools/uc_funcmap.py are the generator/input path to review. progress.json carries a Phase 52 strategy headline but retains 67 unique, 33 enterable and 265 runs in ordinary_runtime_frontier. Its 15 completed and 18 recorded entries are map-log counts, not the newer unique campaign tally. progress.html has a separate Phase 52 media section. progress.svg and progress.png were not updated by the Phase 52 dashboard commit. Fix the generator's source selection to ingest the latest execution ledger and an independently sourced browser/media readiness record. Keep map, harness and browser counts separate and regenerate each output together. Legacy NFSU2 wording remains in the inherited package/shell diagnostics. Preserve provenance for inherited tooling while labeling the active target accurately.

## Critical-path roadmap

A and B can advance independently of the longest chain, which is C → D → E → F. Asset span recovery and renderer contract tests can start in parallel with C. Every runtime milestone requires evidence from translated Undercover code at the relevant boundary.

| Milestone | Status and prerequisites | Implementation and acceptance |
|---|---|---|
| A Development preview | Individual preview controls work. Unified Play flow unverified. | Define explicit preview entry and test image, movie, graphics, missing-media fallback and skip on a clean browser. |
| B Authentic startup content | JPEG and EA bumper video demonstrated independently. | Preserve verified provenance and test physical LAN. Identify real startup ordering separately. |
| C First original startup execution | Blocked on module and boot state. | Produce reproducible Undercover module and trace a verified ordinary startup prefix in browser with ABI/import evidence and explicit stops. |
| D Authentic gameplay frame | Blocked on C, scene assets, scheduler/device and draw path. | Verify source geometry and transforms, prove translated submission and Present in the same frame, then validate rendered pixels and trace provenance. |
| E Basic gameplay | Requires D, streaming, game loop, input and vehicle/world state. | Demonstrate a controllable vehicle on a genuine track with repeatable input, simulation and collision traces. |
| F Substantially playable | Requires E plus game UI, progression, persistence, audio and robust streaming. | Start a session through real menus, complete a representative event, persist progress and reload. |

Short term, establish the browser startup slice and validate one authentic resource contract. Medium term, connect device initialization and one scheduled authentic scene submission. Long term, integrate input, simulation, streaming, real menus and audio with repeated sessions. Preview UX is separately testable.

## Next three recommended tasks

1. Define and deliver a minimal browser-callable Undercover startup slice. Start with an ordinary entry candidate and exact call/ABI trace, list globals and imports that must be initialized, produce the module/manifest from a reproducible build, and fail explicitly at the first unsupported dependency. Acceptance is an original translated Undercover prefix running in a browser with observable state.
2. Prove a bounded authentic payload and its ordinary consumer. Record archive directory and byte-span evidence for a boot texture or XP_SMOKEBALL resource, validate hash, format and dimensions or stride/index bounds, then make a reproducible decode/upload test with authorized bytes.
3. Close the scheduling evidence gap before implementing broader D3D9. Trace one lawful ordinary path from device setup and scene preparation to an indexed draw caller and the same frame's Present, with thread ownership and pointer lifetimes. Acceptance is a trace and testable renderer contract with explicit unresolved boundaries.

## Questions for Ghidra MCP

- What ordinary caller and state writes reach 0x0072E5D0 / 0x0072E340? Is there a verified callable provider for 0x00B615C4, and what are its four argument meanings and cleanup convention?
- Which ordinary stores initialize the graphics instance at 0x01318170 and globals 0x0189DA88 and 0x0189D0A0+8? At 0x00810259 establish register, argument and return use up to the opaque boundary.
- Can the 0x00770750 → 0x0076FC30 → 0x00757B80 chain be tied to 0x00752B14 on one thread and frame? At 0x00757C9A and the user-memory wrapper, recover caller-side buffer, count, stride and ownership evidence only.
- Where are the verified reader and exact spans for XP_SMOKEBALL_CURL/PUFF or named boot textures? Which ordinary consumer first reads their decoded fields?
- What supplies the descriptor at 0x0080E57D and dispatches the movie table +0x14 slot at 0x00807150? Can filename and startup ordering be proven from ordinary callers?

## Final verdict

1. Original intro content is already visible as the shipped EA bumper video derivative. Original audio and first-movie order remain unverified.
2. Real translated startup is at the execution-island stage. A browser-loadable module and an ordinary startup slice with initialized platform state are required.
3. An authentic gameplay frame is beyond the current frontier. Device setup, same-frame scheduling and real scene submission all need evidence.
4. A controllable car is several dependency milestones away. No credible schedule or overall percentage follows from current counts.
5. The highest-priority blocker is the absence of a verified browser-callable Undercover startup path with the guest state it requires.
6. Stop prioritizing isolated math coverage, synthetic frames as gameplay evidence, and phase-count or compile-percentage gains as measures of playability.
7. Phase 53 should establish the first verified translated startup slice in the browser, with a reproducible module build and an explicit stop at the first missing ordinary dependency.

