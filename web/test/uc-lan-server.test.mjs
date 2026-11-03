// Phase 49: private LAN HTTPS server + manifest generator + secure-context boot.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, '..');
const ROOT = path.resolve(WEB, '..');
const require = createRequire(import.meta.url);

function tmpDir(name) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `uc-lan-${name}-`));
  return d;
}

function httpsGet(url, { ca, headers, method = 'GET' } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      method,
      headers,
      ca,
      rejectUnauthorized: !!ca,
      servername: u.hostname === '127.0.0.1' ? 'localhost' : u.hostname,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks),
        });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function ensureDist() {
  const dist = path.join(WEB, 'dist');
  if (!fs.existsSync(path.join(dist, 'uc-asset-manifest.json'))) {
    const { execFileSync } = await import('node:child_process');
    execFileSync(process.execPath, ['build.mjs'], { cwd: WEB, stdio: 'pipe' });
  }
  return dist;
}

test('manifest generator hashes allowlisted files only', async () => {
  const { generateManifest } = await import('../tools/uc-manifest-gen.mjs');
  const root = tmpDir('root');
  const al = path.join(root, 'allow.json');
  fs.mkdirSync(path.join(root, 'startup'), { recursive: true });
  fs.writeFileSync(path.join(root, 'startup', 'a.txt'), 'hello-lan');
  fs.writeFileSync(path.join(root, 'secret.bin'), 'should-not-scan');
  fs.writeFileSync(al, JSON.stringify([
    { id: 'startup.a', path: 'startup/a.txt', required: true, license: 'synthetic-fixture' },
  ]));
  const m = generateManifest({
    root, allowlist: al, baseUrl: '/uc-assets/', authorized: false, version: 1,
  });
  assert.equal(m.assets.length, 1);
  assert.equal(m.assets[0].size, 9);
  assert.equal(m.assets[0].sha256.length, 64);
  assert.equal(m.source.totalDownloadBytes, 9);
  assert.equal(m.source.productionAssetsAuthorized, false);

  // traversal rejected
  fs.writeFileSync(al, JSON.stringify([{ id: 'x', path: '../secret.bin' }]));
  assert.throws(() => generateManifest({
    root, allowlist: al, baseUrl: '/uc-assets/', authorized: false, version: 1,
  }));
});

test('LAN HTTPS server: fixtures, range, allowlist, traversal', async () => {
  const dist = await ensureDist();
  const certDir = tmpDir('certs');
  const assetRoot = tmpDir('assets');
  fs.mkdirSync(path.join(assetRoot, 'startup'), { recursive: true });
  const payload = Buffer.from('authorized-fixture-bytes!!');
  fs.writeFileSync(path.join(assetRoot, 'startup', 'extra.txt'), payload);

  const { generateManifest } = await import('../tools/uc-manifest-gen.mjs');
  const allowlist = path.join(assetRoot, 'allow.json');
  fs.writeFileSync(allowlist, JSON.stringify([
    {
      id: 'startup.extra',
      path: 'startup/extra.txt',
      required: true,
      license: 'synthetic-fixture',
      contentType: 'text/plain',
    },
  ]));
  const manPath = path.join(assetRoot, 'manifest.json');
  const man = generateManifest({
    root: assetRoot,
    allowlist,
    baseUrl: '/uc-assets/',
    authorized: false,
    version: 2,
  });
  // Keep shipped fixture assets too by merging into a server-side allowlist copy
  // used only for /uc-assets/ — dist still serves /uc-fixtures/.
  fs.writeFileSync(manPath, JSON.stringify(man, null, 2));

  const { startUcLanServer } = await import('../tools/uc-lan-server.mjs');
  const { server, certs, urls, close } = await startUcLanServer({
    bind: '127.0.0.1',
    port: 0, // will fail — need real port. Use ephemeral via listen 0 manually.
    dist,
    assetRoot,
    manifest: manPath,
    certDir,
    allowAllBind: false,
  });
  // startUcLanServer uses opts.port directly; get actual port:
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 8443;
  const origin = `https://127.0.0.1:${port}`;
  try {
    const status = await httpsGet(`${origin}/uc-lan-status.json`, { ca: certs.caPem });
    assert.equal(status.status, 200);
    const j = JSON.parse(status.body.toString());
    assert.equal(j.game, 'NFS_UNDERCOVER_PC');
    assert.equal(j.secure, true);

    const fixture = await httpsGet(`${origin}/uc-asset-manifest.json`, { ca: certs.caPem });
    assert.equal(fixture.status, 200);

    const asset = await httpsGet(`${origin}/uc-assets/startup/extra.txt`, { ca: certs.caPem });
    assert.equal(asset.status, 200);
    assert.equal(asset.body.toString(), payload.toString());
    assert.ok(asset.headers['accept-ranges'] === 'bytes' || asset.headers['Accept-Ranges'] === 'bytes'
      || asset.headers.etag || asset.headers.ETag);

    const ranged = await httpsGet(`${origin}/uc-assets/startup/extra.txt`, {
      ca: certs.caPem,
      headers: { Range: 'bytes=0-9' },
    });
    assert.equal(ranged.status, 206);
    assert.equal(ranged.body.toString(), payload.subarray(0, 10).toString());
    assert.match(String(ranged.headers['content-range'] || ''), /bytes 0-9\//);

    const denied = await httpsGet(`${origin}/uc-assets/../package.json`, { ca: certs.caPem });
    assert.ok(denied.status === 403 || denied.status === 404);

    const notListed = await httpsGet(`${origin}/uc-assets/nope.bin`, { ca: certs.caPem });
    assert.equal(notListed.status, 403);
  } finally {
    await close();
  }
  assert.ok(urls[0].startsWith('https://'));
});

test('secure context report warns on LAN HTTP', async () => {
  // Load TS via esbuild bundle snippet
  const esbuild = await import('esbuild');
  const built = await esbuild.build({
    stdin: {
      contents: `export { reportSecureContext } from './web/src/app/uc-boot-stages.ts';`,
      resolveDir: ROOT,
      loader: 'ts',
    },
    bundle: true,
    format: 'esm',
    write: false,
    platform: 'neutral',
  });
  const out = path.join(os.tmpdir(), `uc-boot-stages-${process.pid}.mjs`);
  fs.writeFileSync(out, built.outputFiles[0].text);
  const mod = await import(pathToFileURL(out).href);
  const insecure = mod.reportSecureContext({ protocol: 'http:', hostname: '192.168.178.102' });
  assert.equal(insecure.isSecureContext, false);
  assert.match(insecure.message || '', /HTTPS/i);
  const secure = mod.reportSecureContext({ protocol: 'https:', hostname: '192.168.178.102' });
  assert.equal(secure.isSecureContext, true);
  assert.equal(secure.message, null);
  try { fs.unlinkSync(out); } catch { /* */ }
});

test('boot stages reach READY_OR_BLOCKED with fixtures', async () => {
  const esbuild = await import('esbuild');
  const built = await esbuild.build({
    stdin: {
      contents: `export { UcLaunchController } from './web/src/app/uc-launch.ts';`,
      resolveDir: ROOT,
      loader: 'ts',
    },
    bundle: true,
    format: 'esm',
    write: false,
    platform: 'node',
  });
  const out = path.join(os.tmpdir(), `uc-launch-${process.pid}.mjs`);
  fs.writeFileSync(out, built.outputFiles[0].text);
  const { UcLaunchController } = await import(pathToFileURL(out).href);

  const fixtures = path.join(WEB, 'src/static/uc-fixtures');
  const readme = fs.readFileSync(path.join(fixtures, 'startup/readme.txt'));
  const marker = fs.readFileSync(path.join(fixtures, 'startup/boot-marker.json'));
  const files = {
    'startup/readme.txt': readme,
    'startup/boot-marker.json': marker,
  };
  const fetchFn = async (url) => {
    if (url.includes('uc-asset-manifest') || url.endsWith('.json') && url.includes('manifest')) {
      const man = JSON.parse(fs.readFileSync(path.join(WEB, 'src/static/uc-asset-manifest.json'), 'utf8'));
      return new Response(JSON.stringify(man), { status: 200 });
    }
    const u = new URL(url, 'http://x/');
    const rel = u.pathname.replace(/^\/uc-fixtures\//, '').replace(/^\//, '');
    const body = files[rel];
    if (!body) return new Response('missing', { status: 404 });
    return new Response(body, { status: 200, headers: { 'content-length': String(body.length) } });
  };

  const ctl = new UcLaunchController({
    memoryOnly: true,
    fetch: fetchFn,
    location: { protocol: 'https:', hostname: '127.0.0.1' },
    developmentPreview: true,
  });
  const ui = await ctl.boot();
  assert.equal(ui.phase, 'ready_to_initialize');
  assert.equal(ui.playEnabled, false);
  assert.equal(ctl.stages.stage, 'READY_OR_BLOCKED');
  assert.ok(ctl.bridge);
  try { fs.unlinkSync(out); } catch { /* */ }
});
