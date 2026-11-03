#Requires -Version 5.1
<#
.SYNOPSIS
  Host the Undercover browser app on this PC for private LAN testing (Phase 49).

.DESCRIPTION
  Builds the web SPA if needed, generates a local HTTPS certificate with the
  machine's LAN IP in the SAN, and starts a Node HTTPS server bound to one
  private interface (not every adapter by default).

  Second PC: trust the printed ca.crt, then open the printed https:// URL.
  Do not install the original game on the second PC. Do not port-forward.

.PARAMETER Bind
  IPv4 address to bind. Default: first private LAN IPv4 discovered by Node.

.PARAMETER Port
  HTTPS port (default 8443).

.PARAMETER AssetRoot
  Optional authorized asset directory OUTSIDE the repo (UC_ASSET_ROOT).
  Only files listed in the asset manifest are served from this root.

.PARAMETER Manifest
  Optional path to uc-asset-manifest.json (defaults to web/dist copy).

.PARAMETER CertDir
  Outside-repo certificate directory (default %USERPROFILE%\.nfsuc-web\lan-certs).

.PARAMETER NoBuild
  Skip npm run build.

.PARAMETER ForceCert
  Regenerate development certificates.

.EXAMPLE
  .\Start-UndercoverLAN.ps1
  .\Start-UndercoverLAN.ps1 -Bind 192.168.178.102 -Port 8443
  .\Start-UndercoverLAN.ps1 -AssetRoot "D:\Authorized\UC-Fixtures"
#>
[CmdletBinding()]
param(
  [string]$Bind = $env:UC_BIND,
  [int]$Port = $(if ($env:UC_PORT) { [int]$env:UC_PORT } else { 8443 }),
  [string]$AssetRoot = $env:UC_ASSET_ROOT,
  [string]$Manifest = '',
  [string]$CertDir = $(if ($env:UC_LAN_CERT_DIR) { $env:UC_LAN_CERT_DIR } else {
    Join-Path $env:USERPROFILE '.nfsuc-web\lan-certs'
  }),
  [switch]$NoBuild,
  [switch]$ForceCert,
  [switch]$BindAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
  $here = $PSScriptRoot
  if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
  return (Resolve-Path -LiteralPath $here).Path
}

function Find-NodeExe {
  $hint = Join-Path (Resolve-RepoRoot) 'tools\.node-path.txt'
  if (Test-Path -LiteralPath $hint) {
    $p = (Get-Content -LiteralPath $hint -Raw).Trim()
    if ($p -and (Test-Path -LiteralPath $p)) { return $p }
  }
  $cmd = Get-Command node -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  throw 'Node.js not found. Install Node LTS or write tools\.node-path.txt with the node.exe path.'
}

$Root = Resolve-RepoRoot
$Web = Join-Path $Root 'web'
$Node = Find-NodeExe
$env:Path = (Split-Path -Parent $Node) + ';' + $env:Path

Write-Host ''
Write-Host '=== NFS Undercover private LAN host ===' -ForegroundColor Cyan
Write-Host "Repo:  $Root"
Write-Host "Node:  $Node"
Write-Host "Certs: $CertDir  (outside repo; do not commit)"
Write-Host ''

if (-not $NoBuild) {
  Push-Location -LiteralPath $Web
  try {
    if (-not (Test-Path -LiteralPath (Join-Path $Web 'node_modules\esbuild'))) {
      Write-Host 'Installing web dependencies (npm install)…'
      & npm.cmd install --no-audit --no-fund
      if ($LASTEXITCODE -ne 0) { throw "npm install failed ($LASTEXITCODE)" }
    }
    Write-Host 'Building SPA (npm run build)…'
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed ($LASTEXITCODE)" }
  } finally {
    Pop-Location
  }
}

$server = Join-Path $Web 'tools\uc-lan-server.mjs'
if (-not (Test-Path -LiteralPath $server)) {
  throw "Missing $server"
}

$args = @($server, '--port', "$Port", '--cert-dir', $CertDir)
if ($Bind) { $args += @('--bind', $Bind) }
if ($BindAll) { $args += '--bind-all' }
if ($AssetRoot) {
  $AssetRoot = (Resolve-Path -LiteralPath $AssetRoot).Path
  $args += @('--asset-root', $AssetRoot)
}
if ($Manifest) {
  $Manifest = (Resolve-Path -LiteralPath $Manifest).Path
  $args += @('--manifest', $Manifest)
}
if ($ForceCert) { $args += '--force-cert' }

Write-Host ''
Write-Host 'Firewall guidance (run elevated once if needed):' -ForegroundColor Yellow
Write-Host ("  New-NetFirewallRule -DisplayName 'NFSUC LAN HTTPS' -Direction Inbound " +
  "-Protocol TCP -LocalPort $Port -Action Allow -Profile Private")
Write-Host 'Trust on second PC: install ca.crt from the cert directory into Trusted Root CAs.'
Write-Host 'Shutdown: Ctrl-C in this window.'
Write-Host ''

& $Node @args
exit $LASTEXITCODE
