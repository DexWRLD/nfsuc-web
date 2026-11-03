# Undercover Phase 52

The shipped EA bumper plays in the startup preview over the existing private HTTPS LAN pipeline. The 11.544643-second MP4 contains 346 H.264 frames at 1280 x 720 and no audio stream. FFmpeg 9.0.2 decoded the original VP6 video and the derivative with exit 0. EA audio revision2=23 was unsupported by that build. See ea-bumper.provenance.json for hashes and the conversion command.

## Readiness

- Authentic startup JPEG preview ready
- AUTHENTIC_MEDIA_SOURCE_IDENTIFIED
- ORIGINAL_MOVIE_VIDEO_DECODE_VERIFIED
- ORIGINAL_MOVIE_AUDIO_DECODE_UNVERIFIED
- AUTHENTIC_MOVIE_DERIVATIVE_VERIFIED
- BROWSER_MOVIE_PLAYBACK_VERIFIED over loopback HTTPS in Microsoft Edge Chromium
- FIRST_STARTUP_MOVIE_ORDER_UNVERIFIED
- ORIGINAL_GAME_BOOT_EXECUTING is false
- FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND

## Verification

The TypeScript compiler and node build.mjs exited 0. Node startup, asset and LAN tests passed 31/31. The opt-in Playwright test passed in the installed Edge channel. It observed metadata and advancing playback, pause and resume, end and skip cleanup, and a reload with one total MP4 request. Playwright's bundled Chromium executable was missing. Physical second-PC testing was unavailable.

## Private LAN

Use the existing private LAN HTTPS bind and certificate directory. Pass --asset-root with the authorized-startup directory and --manifest with phase52-manifest.json in that directory to web/tools/uc-lan-server.mjs. The existing local CA should be trusted on the second PC. Open the private HTTPS address and press Play in the startup panel. Reload and confirm there is no second MP4 request in the network panel. Keep both game media files outside Git.

The opt-in test uses UC_AUTHENTIC_ASSET_ROOT and UC_BROWSER_CHANNEL=msedge. Run node --test --test-name-pattern='authorized EA bumper' test/uc-lan-https-browser.test.mjs from web after building.
