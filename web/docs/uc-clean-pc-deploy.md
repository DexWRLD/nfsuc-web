# Undercover clean-PC delivery (Phase 48–49)

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC` · `TOOLING_ORIGIN=NFSU2-WEB`

For the **private two-PC LAN HTTPS workflow**, see [`uc-private-lan.md`](uc-private-lan.md) and `Start-UndercoverLAN.ps1`.

## What a clean Windows PC needs

1. A modern Chromium or Firefox browser with OPFS (preferred) or in-memory fallback.
2. Network access to the **static app origin** and the **configured asset base URL**.
3. No original Undercover install and no local game-folder picker.

## Server layout

| Path | Role |
|---|---|
| `/` (`index.html`, `main.js`, `main.css`, …) | Static SPA from `web/build.mjs` → `dist/` |
| `/uc-asset-manifest.json` | Versioned Undercover asset catalog |
| `/uc-fixtures/**` | Project-owned synthetic fixtures only |
| `/data-manifest`, `/data/**` | Inherited NFSU2 game-data host (separate) |

Do **not** hardcode `localhost`. Configure `source.baseUrl` in the manifest (path or absolute `https://` asset host).

## HTTPS / CORS

- Production should serve the app over HTTPS.
- If assets are on another origin, that origin must:
  - Be listed as `source.baseUrl` with `mode: "authorized"` only when rights-cleared.
  - Send CORS headers allowing the app origin for GET.
- Cross-origin asset URLs that are not under the configured base host are rejected by the downloader.

## Large files

- Downloads stream via `ReadableStream` when available; expected size is enforced.
- Cache commits are staged then published only after SHA-256 verification.
- Manifest updates prune obsolete entries without wiping unrelated OPFS trees (`save/`, etc.).

## Production Undercover data

`productionAssetsAuthorized` remains **false** until a lawful distribution endpoint exists.
`license: "copyrighted-unavailable"` entries return `UNSUPPORTED` from the `/uc/...` bridge.

## Minimum checks before calling a deploy “healthy”

1. App shell loads with an empty browser profile.
2. Fixture manifest downloads and verifies.
3. Reload reuses cache.
4. Offline reload works when fixtures are cached.
5. Authentic Play stays disabled while runtime/first-frame are blocked.
