#!/usr/bin/env node
// Private LAN HTTPS host for Undercover clean-PC testing (Phase 49).
// Serves the built SPA from web/dist plus manifest-listed assets from UC_ASSET_ROOT.
// Binds to a chosen private interface by default (not every adapter unless --bind 0.0.0.0).
//
//   node web/tools/uc-lan-server.mjs [--bind IP] [--port 8443] [--dist DIR]
//     [--asset-root DIR] [--manifest PATH] [--cert-dir DIR] [--access-log PATH]
//
// Env: UC_BIND, UC_PORT, UC_ASSET_ROOT, UC_LAN_CERT_DIR, UC_DIST
//
// No public tunnels. No directory browsing. Only paths listed in the asset manifest
// are served from UC_ASSET_ROOT (plus the SPA + shipped fixtures under dist).
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { makeLanCerts, discoverLanIpv4 } from './uc-lan-certs.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, '..');
const REPO = path.resolve(WEB, '..');

const CONTENT = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.mp4': 'video/mp4',
  '.json': 'application/json',
  '.txt': 'text/plain; charset=utf-8',
  '.wasm': 'application/wasm',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.bin': 'application/octet-stream',
  '.woff2': 'font/woff2',
};

function contentType(p) {
  return CONTENT[path.extname(p).toLowerCase()] || 'application/octet-stream';
}

function parseArgs(argv) {
  const lan = discoverLanIpv4();
  const a = {
    bind: process.env.UC_BIND || lan[0] || '127.0.0.1',
    port: Number(process.env.UC_PORT || 8443),
    dist: process.env.UC_DIST || path.join(WEB, 'dist'),
    assetRoot: process.env.UC_ASSET_ROOT || '',
    manifest: '',
    certDir: process.env.UC_LAN_CERT_DIR || '',
    accessLog: '',
    forceCert: false,
    allowAllBind: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const x = argv[i];
    if (x === '--bind') a.bind = argv[++i];
    else if (x === '--port') a.port = Number(argv[++i]);
    else if (x === '--dist') a.dist = path.resolve(argv[++i]);
    else if (x === '--asset-root') a.assetRoot = path.resolve(argv[++i]);
    else if (x === '--manifest') a.manifest = path.resolve(argv[++i]);
    else if (x === '--cert-dir') a.certDir = path.resolve(argv[++i]);
    else if (x === '--access-log') a.accessLog = path.resolve(argv[++i]);
    else if (x === '--force-cert') a.forceCert = true;
    else if (x === '--bind-all') { a.bind = '0.0.0.0'; a.allowAllBind = true; }
    else if (x === '-h' || x === '--help') {
      console.log(`Undercover private LAN HTTPS server

  node web/tools/uc-lan-server.mjs [options]

Options:
  --bind <ip>         Listen address (default: first private LAN IPv4, else 127.0.0.1)
  --bind-all          Explicitly bind 0.0.0.0 (discouraged; requires opt-in)
  --port <n>          HTTPS port (default 8443)
  --dist <dir>        Built SPA (default web/dist)
  --asset-root <dir>  Authorized asset directory outside the repo (UC_ASSET_ROOT)
  --manifest <file>   Asset manifest (default <dist>/uc-asset-manifest.json)
  --cert-dir <dir>    Outside-repo cert directory
  --access-log <file> Append access log lines
  --force-cert        Regenerate development certificates

Shutdown: Ctrl-C
Firewall: allow inbound TCP on --port from your private LAN only.`);
      process.exit(0);
    } else throw new Error(`unknown arg ${x}`);
  }
  if (!a.manifest) a.manifest = path.join(a.dist, 'uc-asset-manifest.json');
  a.dist = path.resolve(a.dist);
  if (a.assetRoot) a.assetRoot = path.resolve(a.assetRoot);
  return a;
}

function isPrivateIpv4(ip) {
  if (ip === '0.0.0.0' || ip === '::' || ip === '127.0.0.1' || ip === '::1') return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return false;
  const a = +m[1], b = +m[2];
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

function loadManifestAllowlist(manifestPath) {
  if (!fs.existsSync(manifestPath)) {
    return { assetsByUrl: new Map(), assetsByPath: new Map(), raw: null };
  }
  const raw = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const assetsByUrl = new Map();
  const assetsByPath = new Map();
  for (const a of raw.assets || []) {
    if (a.license === 'copyrighted-unavailable') continue;
    const rel = String(a.url || a.path || '').replace(/^\/+/, '').replace(/\\/g, '/');
    if (!rel || rel.includes('..')) continue;
    assetsByUrl.set(rel, a);
    assetsByPath.set(String(a.path || rel).replace(/^\/+/, ''), a);
  }
  return { assetsByUrl, assetsByPath, raw };
}

function safeJoinRoot(root, rel) {
  const cleaned = rel.replace(/^\/+/, '').replace(/\\/g, '/');
  if (!cleaned || cleaned.includes('\0') || cleaned.split('/').some(p => p === '..')) {
    return null;
  }
  const full = path.resolve(root, cleaned);
  const rootN = path.resolve(root) + path.sep;
  if (full !== path.resolve(root) && !full.startsWith(rootN)) return null;
  // Reject symlink escape
  try {
    const real = fs.realpathSync(full);
    const realRoot = fs.realpathSync(root);
    if (real !== realRoot && !real.startsWith(realRoot + path.sep)) return null;
    return real;
  } catch {
    return null;
  }
}

function etagFor(stat, filePath) {
  const h = crypto.createHash('sha1')
    .update(String(stat.size))
    .update('-')
    .update(String(stat.mtimeMs))
    .update('-')
    .update(filePath)
    .digest('hex');
  return `"${h}"`;
}

function parseRange(header, size) {
  if (!header || !header.startsWith('bytes=')) return null;
  const part = header.slice(6).split(',')[0].trim();
  const m = /^(\d*)-(\d*)$/.exec(part);
  if (!m) return null;
  let start = m[1] === '' ? null : Number(m[1]);
  let end = m[2] === '' ? null : Number(m[2]);
  if (start == null && end == null) return null;
  if (start == null) {
    // suffix: last N bytes
    const n = end;
    if (!Number.isFinite(n) || n <= 0) return null;
    start = Math.max(0, size - n);
    end = size - 1;
  } else {
    if (!Number.isFinite(start) || start < 0 || start >= size) return 'unsat';
    if (end == null || !Number.isFinite(end) || end >= size) end = size - 1;
    if (end < start) return 'unsat';
  }
  return { start, end };
}

function sendFile(req, res, filePath, { immutable = false } = {}) {
  let st;
  try { st = fs.statSync(filePath); } catch {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('missing');
    return;
  }
  if (!st.isFile()) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('missing');
    return;
  }
  const etag = etagFor(st, filePath);
  if (req.headers['if-none-match'] === etag) {
    res.writeHead(304);
    res.end();
    return;
  }
  const ctype = contentType(filePath);
  const range = parseRange(req.headers.range, st.size);
  const baseHeaders = {
    'content-type': ctype,
    'accept-ranges': 'bytes',
    etag,
    'cache-control': immutable ? 'public, max-age=31536000, immutable' : 'no-cache',
    'x-content-type-options': 'nosniff',
  };
  if (range === 'unsat') {
    res.writeHead(416, { ...baseHeaders, 'content-range': `bytes */${st.size}` });
    res.end();
    return;
  }
  if (range) {
    const len = range.end - range.start + 1;
    res.writeHead(206, {
      ...baseHeaders,
      'content-length': String(len),
      'content-range': `bytes ${range.start}-${range.end}/${st.size}`,
    });
    fs.createReadStream(filePath, { start: range.start, end: range.end }).pipe(res);
    return;
  }
  res.writeHead(200, { ...baseHeaders, 'content-length': String(st.size) });
  fs.createReadStream(filePath).pipe(res);
}

function logAccess(logPath, line) {
  const row = `${new Date().toISOString()} ${line}\n`;
  process.stdout.write(row);
  if (logPath) {
    try { fs.appendFileSync(logPath, row); } catch { /* ignore */ }
  }
}

export function createUcLanApp(opts) {
  const dist = path.resolve(opts.dist);
  const assetRoot = opts.assetRoot ? path.resolve(opts.assetRoot) : '';
  const manifestPath = path.resolve(opts.manifest);
  const allow = loadManifestAllowlist(manifestPath);
  const accessLog = opts.accessLog || '';

  if (assetRoot) {
    const repoN = path.resolve(REPO) + path.sep;
    if ((assetRoot + path.sep).toLowerCase().startsWith(repoN.toLowerCase())) {
      console.warn(
        '[uc-lan] WARNING: UC_ASSET_ROOT is inside the repository. '
        + 'Prefer a directory outside the repo for authorized game data.',
      );
    }
  }

  const handler = (req, res) => {
    const remote = String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
    const u = new URL(req.url || '/', `https://${req.headers.host || 'localhost'}`);
    logAccess(accessLog, `${remote} ${req.method} ${u.pathname}`);

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      res.end('method not allowed');
      return;
    }

    // Health / diagnostics
    if (u.pathname === '/uc-lan-status.json') {
      const body = JSON.stringify({
        game: 'NFS_UNDERCOVER_PC',
        toolingOrigin: 'NFSU2-WEB',
        secure: true,
        bind: opts.bind,
        port: opts.port,
        dist,
        assetRoot: assetRoot || null,
        manifestAssets: allow.assetsByUrl.size,
        productionAssetsAuthorized: !!(allow.raw?.source?.productionAssetsAuthorized),
        firstFrame: 'FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND',
        note: 'Private LAN development host. Not for public deployment.',
      }, null, 2);
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
      if (req.method === 'HEAD') { res.end(); return; }
      res.end(body);
      return;
    }

    if (u.pathname === '/uc-asset-manifest.json' && fs.existsSync(manifestPath)) {
      sendFile(req, res, manifestPath);
      return;
    }

    // Manifest-listed assets from UC_ASSET_ROOT under /uc-assets/
    if (u.pathname.startsWith('/uc-assets/')) {
      if (!assetRoot) {
        res.writeHead(503, { 'content-type': 'text/plain' });
        res.end('UC_ASSET_ROOT not configured');
        return;
      }
      const rel = decodeURIComponent(u.pathname.slice('/uc-assets/'.length));
      const entry = allow.assetsByUrl.get(rel) || allow.assetsByPath.get(rel);
      if (!entry) {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end('not in asset manifest allowlist');
        return;
      }
      const file = safeJoinRoot(assetRoot, rel);
      if (!file) {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end('path rejected');
        return;
      }
      if (req.method === 'HEAD') {
        try {
          const st = fs.statSync(file);
          res.writeHead(200, {
            'content-type': contentType(file),
            'content-length': String(st.size),
            'accept-ranges': 'bytes',
            etag: etagFor(st, file),
          });
        } catch {
          res.writeHead(404);
        }
        res.end();
        return;
      }
      sendFile(req, res, file);
      return;
    }

    // Static SPA + shipped fixtures from dist (no directory listing)
    let rel = decodeURIComponent(u.pathname);
    if (rel === '/') rel = '/index.html';
    const file = safeJoinRoot(dist, rel.replace(/^\/+/, ''));
    if (!file) {
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('path rejected');
      return;
    }
    if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('missing');
      return;
    }
    if (req.method === 'HEAD') {
      const st = fs.statSync(file);
      res.writeHead(200, {
        'content-type': contentType(file),
        'content-length': String(st.size),
        'accept-ranges': 'bytes',
        etag: etagFor(st, file),
      });
      res.end();
      return;
    }
    sendFile(req, res, file);
  };

  return { handler, allow, dist, assetRoot, manifestPath };
}

export async function startUcLanServer(opts) {
  if (!isPrivateIpv4(opts.bind) && opts.bind !== '0.0.0.0') {
    throw new Error(
      `Refusing non-private bind address ${opts.bind}. Use a RFC1918 address or 127.0.0.1.`,
    );
  }
  if (opts.bind === '0.0.0.0' && !opts.allowAllBind) {
    throw new Error('Binding 0.0.0.0 requires --bind-all (explicit opt-in). Prefer --bind <LAN-IP>.');
  }
  if (!fs.existsSync(opts.dist)) {
    throw new Error(`dist missing: ${opts.dist} (run: cd web && npm run build)`);
  }

  const certs = makeLanCerts({
    dir: opts.certDir || path.join(
      process.env.USERPROFILE || process.env.HOME || '.',
      '.nfsuc-web', 'lan-certs',
    ),
    ips: opts.bind !== '0.0.0.0' && opts.bind !== '127.0.0.1' ? [opts.bind] : [],
    force: opts.forceCert,
  });
  const app = createUcLanApp(opts);
  const server = https.createServer(
    { key: fs.readFileSync(certs.key), cert: fs.readFileSync(certs.cert) },
    app.handler,
  );

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, opts.bind, resolve);
  });

  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : opts.port;
  opts.port = port;

  const urls = [];
  if (opts.bind === '0.0.0.0') {
    for (const ip of discoverLanIpv4()) urls.push(`https://${ip}:${port}/`);
    urls.push(`https://127.0.0.1:${port}/`);
  } else {
    urls.push(`https://${opts.bind}:${port}/`);
  }

  return { server, certs, app, urls, port, close: () => new Promise(r => server.close(r)) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const opts = parseArgs(process.argv);
  const { server, certs, urls, app } = await startUcLanServer(opts);
  console.log('');
  console.log('=== Undercover private LAN host (Phase 49) ===');
  console.log(`GAME_CODE_TARGET=NFS_UNDERCOVER_PC  TOOLING_ORIGIN=NFSU2-WEB`);
  console.log(`Listening: ${opts.bind}:${opts.port}`);
  console.log(`Dist:      ${app.dist}`);
  console.log(`Assets:    ${app.assetRoot || '(none — fixtures from dist only)'}`);
  console.log(`Manifest:  ${app.manifestPath}`);
  console.log(`Cert CA:   ${certs.ca}`);
  console.log('');
  console.log('Open on the SECOND PC (after trusting ca.crt):');
  for (const u of urls) console.log(`  ${u}`);
  console.log('');
  console.log('Windows Firewall: allow inbound TCP', opts.port, 'from private LAN only.');
  console.log('Shutdown: Ctrl-C  (cached browser assets remain valid).');
  console.log('Status:   ' + urls[0] + 'uc-lan-status.json');
  console.log('');

  const shutdown = () => {
    console.log('\nShutting down LAN host…');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
