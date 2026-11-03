# Undercover private LAN testing (Phase 49)

`GAME_CODE_TARGET=NFS_UNDERCOVER_PC` · `TOOLING_ORIGIN=NFSU2-WEB`

Private two-PC workflow: **main PC hosts** the SPA + authorized/curated assets; **second PC** opens the site, downloads missing resources, verifies hashes, and caches them. No original game install on the second PC. No public tunnels or port forwarding.

## Quick start (main PC, Windows)

```powershell
cd <repo>
.\Start-UndercoverLAN.ps1
```

Optional:

```powershell
.\Start-UndercoverLAN.ps1 -Bind 192.168.178.102 -Port 8443
.\Start-UndercoverLAN.ps1 -AssetRoot "D:\Authorized\UC-Curated" -ForceCert
```

The script builds `web/dist` if needed, writes certificates under `%USERPROFILE%\.nfsuc-web\lan-certs\` (outside the repo), and prints the `https://` URL.

Equivalent Node invocation:

```text
node web/tools/uc-lan-server.mjs --bind <LAN-IP> --port 8443
```

## Second PC

1. Copy **only** `ca.crt` from the main PC cert directory (never `ca.key` / `server.key`).
2. Install it into **Trusted Root Certification Authorities** (Local Machine or Current User).
3. Restart the browser.
4. Open the printed URL, e.g. `https://192.168.178.102:8443/`.
5. Confirm the Undercover asset panel reaches `READY_OR_BLOCKED` with Play still disabled.

## HTTPS / OPFS

LAN `http://` is **not** treated as a secure context. The boot UI shows a clear warning and falls back to in-memory cache (lost when the tab closes). Use the HTTPS LAN host so OPFS can persist.

Regenerate certificates:

```text
node web/tools/uc-lan-certs.mjs --force
```

## Asset root (`UC_ASSET_ROOT`)

- Default: fixtures from `web/dist` (`/uc-fixtures/`, shipped manifest).
- Optional: `--asset-root` / `UC_ASSET_ROOT` pointing **outside** the repository.
- Only paths listed in the active manifest are served under `/uc-assets/`.
- Directory browsing, traversal, and symlink escape are rejected.
- HTTP Range (206) is supported for large files.

### Manifest generation (curated allowlist)

Never scan an entire game install. Use an explicit allowlist:

```text
node web/tools/uc-manifest-gen.mjs ^
  --root D:\Authorized\UC-Curated ^
  --allowlist allowlist.json ^
  --out D:\Authorized\UC-Curated\uc-asset-manifest.json ^
  --base-url /uc-assets/
```

Pass `--authorized` only for private rights-cleared curated transfers. Do not commit copyrighted commercial assets.

## Firewall

Allow inbound TCP on the chosen port for the **Private** profile only. Example:

```powershell
New-NetFirewallRule -DisplayName 'NFSUC LAN HTTPS' -Direction Inbound `
  -Protocol TCP -LocalPort 8443 -Action Allow -Profile Private
```

## Shutdown

Ctrl-C in the host window. Browser caches on the second PC are not wiped by server shutdown.

## Honest runtime status

- Synthetic clear smoke ≠ authentic Undercover frame.
- `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND` remains in force.
- Authentic Play stays disabled until recompiled runtime + authorized data + non-opaque draw path exist.
