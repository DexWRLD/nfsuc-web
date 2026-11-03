# Undercover PC startup logos, movies, and frontend

**The best first browser milestone is a verified original EA logo image shown independently of the game frontend.** The executable names `LS_EALOGO.FNG` and references `FRONTEND\LOGOTEXTURES.BUN` in a data table. These are concrete leads, with no proven link between the package and a specific bundle entry yet. The video subsystem exposes a separate decode and timing path, but neither a concrete startup movie filename nor its source bytes were verified.

Target verified in Ghidra as `nfs.exe`, PE32 x86, base `0x00400000`, entry `0x01FCA510`. SHA-256 `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`. The analysis is static. The project progress and asset delivery setup came from the request and were used as integration assumptions.

## Resource inventory

These are executable addresses of strings, distinct from offsets in asset files.

| Address | String | Evidence and interpretation |
|---|---|---|
| 00B74F74 | LOADING.FNG | Frontend package name in the adjacent package-name range. |
| 00B74F80 | LS_SPLASH.FNG | Splash candidate. No direct reference reported. |
| 00B74F90 | LS_ATTRACTFMV.FNG | Attract-screen movie package candidate. No direct reference reported. |
| 00B74FA4 | LS_EALOGO.FNG | EA-logo frontend package candidate. No direct reference reported. |
| 00B74FB4 | LS_PSA.FNG | Confirmed in bounded static data beside the other LS packages. No direct reference reported. |
| 00B74FC0 | FEANYMOVIE.FNG | Generic movie-screen package candidate. No direct reference reported. |
| 00B74FD0 | MC_MAIN.FNG | Named package in the same range. Actual screen role unverified. |
| 00B73C5C | FeMainMenu.fng | Main menu package name. No direct reference reported. |
| 00B86420 | FRONTEND\\LOGOTEXTURES.BUN | Data pointer at 00CC5EAC in a list of bundle path pointers. No referencing function established for the entry. |
| 00B7FF3C | FRONTEND\\BOOTFLOWTEXTURES.BUN | Boot-flow bundle path. No direct reference reported. |
| 00B7EE48 | FRONTEND\\FRONTB1.BUN | Frontend bundle path. Screen membership unverified. |
| 00B76148 / 00B76158 | frontend.bin / frontend.vlt | Frontend resource names. No loader-to-screen edge established. |
| 00B74974 | %sMOVIES\\%s%s%s%s%s | Generic path template. No direct reference reported. |
| 00B7E850 | %sMOVIES\\%s%s%s%s.vp6 | Explicit VP6 extension in a movie path template. No concrete formatted filename or direct consumer verified. |
| 00B7E8BC | Attract | Adjacent string after the language suffix range. A candidate name, without proof it is interpolated into the VP6 path. |
| 00B7F8CC | SUBTITLES\\%s.sub | Subtitle path template. Association with any specific startup clip unverified. |
| 00B75060 / 00B7507C | LANGUAGES\\%s_SUBTITLES.BIN / LANGUAGES\\%s_FRONTEND.BIN | Localized resource path templates. |
| 00B8DFFC | SkipCareerIntro | Reference at 00B4BC62 in 00B4BC30. Career setting registration, with no verified boot-logo skip branch. |
| 00B73380 / 00B73394 | PLAY_SINGLE_MOVIE / PLAY_ALL_MOVIES | Movie command labels. First has a data reference at 00CC0F10. |
| 00BBBBC4 / 00B8802C | movie_done / MovieFinished | Completion-related strings. No direct references reported. |

Bounded bytes after `0x00B7E850` contain `_japanese`, `_english`, `_ru_english`, `_sp_english`, `_it_english`, `_ge_english`, and `_fr_english`. Their proximity suggests localization inputs. Language selection, precedence, fallback, and boot behavior remain unresolved. `Legal`, `FELegalScreen`, and `LegalCopyright` establish legal-screen naming evidence. No legal artwork was identified.

The Ghidra string searches found no defined matches for `.bik`, `bink`, `.avi`, `.wmv`, `rad game`, `skipintro`, `nointro`, or `nomovie`. The 633 listed imports had no name match for the video middleware filter used in the evidence index. These are search results with limited coverage. They do not establish the absence of linked, dynamically resolved, or unlabelled code. Apt “MovieClip” strings also describe UI objects and cannot by themselves identify full-motion video.

## Startup and frontend graph

The prior graphics branch is `0x0076CA20` supplying callback `0x00766730` at `0x0076CB40`, and the callback calling `0x0072E5D0` at `0x00766773`. The edge from PE entry `0x01FCA510` to boot flow, and the edge from graphics initialization to a named intro request, remain unverified.

`FEBootFlowState`, `PCBootFlowStateManager`, `AptManager::BootFlow`, `LoadUniqueBootflowTextures`, and `AddBootFlowEventsStage` give named boot-flow leads. The latter two strings and the boot manager label yielded no direct code references. This establishes boot-flow vocabulary, while the first state, screen order, movie-enable gate, skip input and transition into `FeMainMenu.fng` remain open. The `SkipCareerIntro` reference establishes only that this name participates in career setting initialization.

The data table at `0x00BBBB9C`, `0x00BBBBA0`, and `0x00BBBBBC` points to movie initialization, cleanup, and update functions respectively. These are dispatch references. No startup invocation is inferred from them. The known ordinary frontend drawing fragment `0x00766480` references `eRenderFrontEndRVM(...)` at `0x007666FB` and hands off to unresolved `0x00686290` at `0x00766700`. That path does not establish presentation for this specific movie or EA logo.

## Movie subsystem

### Initialization and object layout

`0x0080BD00` aliases ECX to ESI at `0x0080BD24` and returns with `RET 4` at `0x0080BF15`. Treat it as an ECX receiver with one stack slot. The decompiler drops the stack slot's semantics.

| Outer field | Role | Evidence |
|---|---|---|
| +0x1C0 | Core RW movie player, 0x310-byte allocation | Label at 0080BD2C, constructor call 0080BD55, store 0080BD5E |
| +0x1C4 | Video decoder, 0x20-byte allocation | Label at 0080BD6B, constructor call 0080BD95, store 0080BDAA |
| +0x1C8 | Video renderer, 0x14-byte allocation | Label at 0080BDCE, constructor call 0080BDEF, store 0080BE03 |
| +0x1CC | Renderable operations | Constructor call 0080BEE4, store 0080BEF8 |
| +0x25 | Audio enable byte | Comparison at 0080BE0E |
| +0x1D0 | Audio renderer | Store 0080BEB2, registration 0080BEB8 |
| +0x1D4 | Audio decoder | Constructor call 0080BE46, store 0080BE5A |

The core constructor `0x00981360` uses an ECX receiver with one stack argument and returns the object. It makes allocator-interface calls for internal decode coordinator, renderer coordinator, and timer storage. The component calls at `0x0098155F`, `0x00981592`, and `0x009815C5` construct these objects. Decode coordinator `0x00982B60` creates thread and semaphore-related objects and a named VideoRenderableManager. This is evidence of an asynchronous decode/queue design. It does not identify a confirmed OS thread import or prove worker execution. Timer wrapper `0x00982700` creates a named Stopwatch object.

Video decoder registration at `0x0080BDC2` calls `0x009807F0`, which writes core +0x3C while state at +0x17C is less than 2. Renderer registration at `0x0080BE09` calls `0x00980830`, which writes core +0x48 under the same guard. The outer renderer constructor target `0x00524F20` contains bad and overlapping instruction analysis. The trace stops there.

### Read, decode, and frame output

- **Resource open and compressed read.** The path template is known. No file-open or archive reader has a verified connection to a concrete startup movie. `0x0097B1A0` takes a queued packet descriptor under synchronization, updates available-byte counters and advances the queue. It is an in-memory packet consumer. The producer that supplies compressed bytes is unresolved.
- **Decode method.** Constructor `0x00985120` stores table `0x00C12A0C`. Table slot +0x14 at `0x00C12A20` points to `0x00985020`. The method takes its receiver in ECX, returns a status in AL, and ends in `RET 8`. Its decompilation presents additional parameters, so only the two callee-popped stack slots and observed operands should be used for ABI claims.
- **Decode path.** `0x0098502C` dequeues a descriptor. Nonzero packet length at descriptor +0x04 is passed along the decode-shaped path to `0x00985BD0` at `0x009850AC`. `0x00985BD0` forwards to `0x00985A90`. Packet recycle occurs at `0x009850BA`. A successful decode leads to a frame copy at `0x009850E9`. Zero-length and no-packet cases have separate paths. A zero-length descriptor is not by itself proof of end-of-movie.
- **CPU frame storage.** `0x00984D20` copies three planes, with the second and third using half dimensions in the observed path. This supports a planar 4:2:0-shaped CPU representation. The exact color space, channel order, bitstream container and bitstream version remain unverified. Frame +0x04/+0x08/+0x0C supply base or plane pointers, +0x1C/+0x20/+0x24 pitches, +0x28/+0x2C width and height, +0x34 ordinal, and +0x40/+0x50/+0x51 flags.
- **Presentation.** `0x00980E00` calls clock selection at `0x00980E1C` and frame selection at `0x00980E5D`. `0x00982F70` advances queued renderables by ordinal, checks readiness, and invokes renderer-related virtual callbacks. The update routine also calls an outer virtual method at `0x0080710B`. No verified connection from these callbacks to D3D texture upload, direct device Present, or DirectShow has been recovered. CPU frame data establishes an intermediate representation, while the native presentation contract stays open.

### Timing, audio and completion

The update-shaped `0x00807050` appears as a data pointer at `0x00BBBBBC`. Assembly shows an ECX receiver and plain RET. The routine gates activity on global `0x018732AC`, prepares streams at `0x008070B6`, checks terminal-like state at `0x008070F0`, and advances frame selection and completion at `0x008070FF` and `0x00807113`.

| Core +0x17C | Verified behavior |
|---|---|
| 1 | `0x00980A00` reads metadata and prepares stream/render interfaces. A flag controls whether the routine waits for a packet. |
| 2 | `0x00980A00` stores 2 after preparation. |
| 3 | `0x00981051` stores 3 when the previous state is 2 and initiates timer/related operations. |
| 4 | Frame selection accepts values 2 through 4. The transition into 4 was not recovered. |
| 5 | `0x009810DF` stores 5 after current ordinal +0x10C equals the frame-count-like value +0xB4 minus one and pending-queue checks permit completion. |
| 6 | `0x00981150` sets 6 during stop and cleanup. |

`0x009827A0` tries the timer's +0x08 object's virtual +0x0C and uses a fallback time routine if that value is unavailable or negative. `0x00980A00` derives a ratio at +0x104 from metadata. The ratio's exact units and timestamps are open. `0x00982F70` compares frame ordinals against the selected playback position and drops or recycles old entries. This is a verified scheduling contract at the ordinal level.

Audio allocation is gated by outer +0x25. The player can forward clock parameters through `0x009809B0` and `0x00982A00`. Progress handling calls `0x00982AC0` at `0x0098108C`, which forwards to separate virtual interfaces. This supports audio-aware playback. Audio codec, sample format, sample clock origin and synchronization tolerance remain unknown.

`0x00980DE0` reports states 5 and 6 as terminal-like. No edge from that result to `movie_done`, `MovieFinished`, or the first menu was established. Cleanup `0x00809270` calls stop at `0x00809280`, releases component pointers through virtual calls and zeroes them, calls core teardown at `0x008092F2`, then frees the core at `0x008092F8`. The original boot skip command and completion consumer remain unresolved.

## Ranked browser routes and provenance

| Rank | Milestone | Evidence available | Required before claiming authentic output |
|---|---|---|---|
| 1 | Original static EA logo | EA-logo FNG string and a separately referenced logo bundle path | One readable original image with an independently verified package or bundle association, encoding and dimensions. |
| 2 | Original intro video | VP6 path template, decoder and CPU frame path | Concrete startup clip name, readable source and verified container/codec, plus a supported decoding route. |
| 3 | Original title background | Splash and boot-flow resource names | A named background resource and its texture region or layout. No verified title-background identifier yet. |
| 4 | Original first menu | Main-menu package name and frontend rendering fragment | Asset resolution, fonts, localization, input, first state and transition ordering. |
| 5 | Original gameplay first frame | Prior verified scene fragments and device setup | Renderer, scene and submission dependencies described in the first-frame report. |

Ranks 2 and 3 are provisional. A readily identified title texture would move ahead of video. No source file bytes were examined. Source-file hash, asset offset, length, texture compression, movie container and decoded timing remain unverified for every candidate. The filename template is stronger evidence for a format lead than for a file's presence. `FRONTEND\\LOGOTEXTURES.BUN` is a source candidate, with membership of the EA logo still unverified.

For a standalone visual, a verified image can be rendered using the browser image path. For video, probe support for the actual container and codecs after identification. A VP6 suffix does not establish native browser support. If the original payload is readable and a suitable decoder is available for the project, use a supported offline decode/transcode route or an approved standalone decoder. Decoder availability and licensing were not established in this static investigation. The independent playback design avoids needing the game's unresolved renderer for this milestone. Native startup execution would require additional runtime edges.

## Cursor implementation specification

1. **Define a provenance manifest.** Add asset kind, exact original name or verified resource key, source identifier and SHA-256, verified source offset and length when an embedded span is used, payload digest, media format, and dimensions. For derived display assets, record original and derived digests separately and record the decoding or conversion step. Unknown spans remain absent. Never accept a name match as proof of membership.
2. **Add an independent startup asset viewer.** Reuse the existing manifest download, OPFS cache and VFS delivery. Resolve a digest-verified image, decode supported image bytes or use a separately verified conversion, then display it with preserved aspect ratio. Keep the viewer state separate from guest boot telemetry. First acceptance test is a recognizable original image with a verified source association.
3. **Add a video adapter after payload identification.** Require concrete filename, bytes, container and codec. Probe browser support, require a user gesture when playback needs one, and handle ready, playing, ended, skip, decode error and disposal. Use the browser media clock for browser-native playback. If an independently supported conversion is used, preserve timing and audio evidence and validate the result against the original payload metadata.
4. **Build an explicit preview sequence.** Use synthetic fixtures to exercise logo → clip → placeholder transitions, stale async completion, skip, error, cache digest mismatch and missing asset behavior. Treat this as a browser preview sequence. Promote a transition to verified original boot behavior only after tracing its original condition, callback consumer and resource dependencies.
5. **Gate menu work on additional evidence.** Verify the entry that activates the first frontend package, the original movie completion consumer, and the package's texture and localization dependencies. Keep unresolved decode, allocator and rendering boundaries explicit in the handoff.

The next highest-value verification is one readable logo image or atlas entry with independently established original provenance. If that cannot be identified, resolve one concrete movie filename and verify its readable source bytes. Those findings would let Cursor advance from synthetic fixtures to an authentic asset preview.

The companion JSON records 27 resource entries, 32 static call edges, table references, structure offsets and unknowns. It distinguishes direct call edges from dispatch references and unresolved presentation.

