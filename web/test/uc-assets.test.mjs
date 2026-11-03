// Undercover Phase 47: asset manifest, download manager, cache, FS bridge, clear smoke.
//   node --test web/test/uc-assets.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const STATIC = path.join(HERE, '../src/static');

const entry = `
export * as M from './web/src/app/uc-asset-manifest.ts';
export * as C from './web/src/app/uc-asset-cache.ts';
export * as D from './web/src/app/uc-download-manager.ts';
export * as F from './web/src/app/uc-fs-bridge.ts';
export * as S from './web/src/app/uc-clear-smoke.ts';
export * as L from './web/src/app/uc-launch.ts';
`;
const js = (await esbuild.build({
  stdin: { contents: entry, resolveDir: ROOT, loader: 'ts' },
  bundle: true, format: 'esm', write: false, platform: 'neutral',
})).outputFiles[0].text;
const { M, C, D, F, S, L } = await import(
  'data:text/javascript;base64,' + Buffer.from(js).toString('base64')
);

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

const fixtureReadme = fs.readFileSync(path.join(STATIC, 'uc-fixtures/startup/readme.txt'));
const fixtureMarker = fs.readFileSync(path.join(STATIC, 'uc-fixtures/startup/boot-marker.json'));
const fixtureMenu = fs.readFileSync(path.join(STATIC, 'uc-fixtures/menu/placeholder.bin'));
const shipped = JSON.parse(fs.readFileSync(path.join(STATIC, 'uc-asset-manifest.json'), 'utf8'));

function makeManifest(overrides = {}) {
  return M.parseManifest({ ...shipped, ...overrides, assets: overrides.assets ?? shipped.assets });
}

function mockFetch(files) {
  return async (url) => {
    const u = String(url);
    if (u.endsWith('uc-asset-manifest.json') || u.includes('manifest')) {
      const body = JSON.stringify(files.__manifest || shipped);
      return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
    }
    for (const [key, bytes] of Object.entries(files)) {
      if (key === '__manifest') continue;
      if (u.includes(key) || u.endsWith(key)) {
        return new Response(bytes, { status: 200 });
      }
    }
    return new Response('missing', { status: 404 });
  };
}

test('shipped manifest parses and marks production unauthorized', () => {
  const m = makeManifest();
  assert.equal(m.game, 'NFS_UNDERCOVER_PC');
  assert.equal(m.source.productionAssetsAuthorized, false);
  assert.equal(m.source.mode, 'fixtures');
  assert.ok(m.assets.some(a => a.license === 'copyrighted-unavailable'));
  assert.ok(M.requiredAssets(m).every(a => a.license === 'synthetic-fixture'));
});

test('invalid manifest rejected', () => {
  assert.throws(() => M.parseManifest({}), /manifestVersion/);
  assert.throws(() => M.parseManifest({ manifestVersion: 1, game: 'OTHER', source: { mode: 'fixtures', baseUrl: '/' }, assets: [] }), /game/);
});

test('copyrighted-unavailable refused without authorization', () => {
  const m = makeManifest();
  const bad = m.assets.find(a => a.license === 'copyrighted-unavailable');
  assert.throws(() => M.assertDownloadAllowed(m, bad), /SOURCE_UNAUTHORIZED|unavailable/);
});

test('download + hash verify + cache hit', async () => {
  const store = new C.MemoryAssetStore();
  const files = {
    'startup/readme.txt': fixtureReadme,
    'startup/boot-marker.json': fixtureMarker,
    'menu/placeholder.bin': fixtureMenu,
  };
  const mgr = new D.UcDownloadManager({
    store,
    fetch: mockFetch(files),
    concurrency: 2,
  });
  const manifest = makeManifest();
  const status = await mgr.ensureRequired(manifest);
  assert.equal(status.phase, 'ready_to_initialize');
  assert.equal(status.requiredReady, M.requiredAssets(manifest).length);

  // cache hit path
  const again = await mgr.ensureRequired(manifest);
  assert.equal(again.phase, 'ready_to_initialize');

  const bytes = await mgr.readAsset(manifest, 'startup.readme');
  assert.ok(bytes);
  assert.equal(sha256(Buffer.from(bytes)), sha256(fixtureReadme));
});

test('hash mismatch rejected', async () => {
  const store = new C.MemoryAssetStore();
  // Same length as fixture readme so size checks pass and SHA-256 fails.
  const bad = Buffer.alloc(fixtureReadme.length, 0x41);
  const files = {
    'startup/readme.txt': bad,
    'startup/boot-marker.json': fixtureMarker,
  };
  const mgr = new D.UcDownloadManager({ store, fetch: mockFetch(files), maxRetries: 0 });
  const status = await mgr.ensureRequired(makeManifest());
  assert.equal(status.phase, 'download_failed');
  assert.match(status.error || '', /hash mismatch|incomplete|CORRUPTED|HASH/i);
});

test('partial download rejected', async () => {
  const store = new C.MemoryAssetStore();
  const short = fixtureReadme.subarray(0, 10);
  const files = {
    'startup/readme.txt': short,
    'startup/boot-marker.json': fixtureMarker,
  };
  const mgr = new D.UcDownloadManager({ store, fetch: mockFetch(files), maxRetries: 0 });
  const status = await mgr.ensureRequired(makeManifest());
  assert.equal(status.phase, 'download_failed');
});

test('cancel aborts in-flight download', async () => {
  const store = new C.MemoryAssetStore();
  let resolveGate;
  const gate = new Promise(r => { resolveGate = r; });
  const fetch = async (url) => {
    if (String(url).includes('readme')) {
      await gate;
      return new Response(fixtureReadme, { status: 200 });
    }
    if (String(url).includes('boot-marker')) return new Response(fixtureMarker, { status: 200 });
    if (String(url).includes('manifest') || String(url).endsWith('.json') && !String(url).includes('boot')) {
      return new Response(JSON.stringify(shipped), { status: 200 });
    }
    return new Response('no', { status: 404 });
  };
  const mgr = new D.UcDownloadManager({ store, fetch, concurrency: 1 });
  const p = mgr.ensureRequired(makeManifest());
  mgr.cancel();
  resolveGate();
  const status = await p;
  assert.equal(status.phase, 'download_failed');
  assert.match(status.error || '', /cancel/i);
});

test('insufficient storage', async () => {
  const store = new C.MemoryAssetStore();
  const files = {
    'startup/readme.txt': fixtureReadme,
    'startup/boot-marker.json': fixtureMarker,
  };
  const mgr = new D.UcDownloadManager({
    store, fetch: mockFetch(files), quotaBytes: 10,
  });
  const status = await mgr.ensureRequired(makeManifest());
  assert.equal(status.phase, 'insufficient_storage');
});

test('offline cached', async () => {
  const store = new C.MemoryAssetStore();
  const files = {
    'startup/readme.txt': fixtureReadme,
    'startup/boot-marker.json': fixtureMarker,
    'menu/placeholder.bin': fixtureMenu,
  };
  const mgr = new D.UcDownloadManager({ store, fetch: mockFetch(files) });
  const manifest = makeManifest();
  await mgr.ensureRequired(manifest);
  const off = await mgr.checkOffline(manifest);
  assert.equal(off.phase, 'offline_cached');
});

test('changed manifest prunes stale and downloads new', async () => {
  const store = new C.MemoryAssetStore();
  const files = {
    'startup/readme.txt': fixtureReadme,
    'startup/boot-marker.json': fixtureMarker,
  };
  const mgr = new D.UcDownloadManager({ store, fetch: mockFetch(files) });
  const m1 = makeManifest();
  await mgr.ensureRequired(m1);

  const newBody = Buffer.from('updated fixture body for prune test\n');
  const newHash = sha256(newBody);
  files['startup/readme.txt'] = newBody;
  const assets = m1.assets.map(a => a.id === 'startup.readme'
    ? { ...a, size: newBody.length, sha256: newHash }
    : a);
  const m2 = M.parseManifest({ ...shipped, assets });
  const status = await mgr.ensureRequired(m2);
  assert.equal(status.phase, 'ready_to_initialize');
  const got = await mgr.readAsset(m2, 'startup.readme');
  assert.equal(sha256(Buffer.from(got)), newHash);
});

test('filesystem bridge maps virtual paths', async () => {
  const store = new C.MemoryAssetStore();
  const files = {
    'startup/readme.txt': fixtureReadme,
    'startup/boot-marker.json': fixtureMarker,
  };
  const mgr = new D.UcDownloadManager({ store, fetch: mockFetch(files) });
  const manifest = makeManifest();
  await mgr.ensureRequired(manifest);
  const bridge = new F.UcFilesystemBridge(manifest, mgr);
  const ok = await bridge.open('/uc/startup/readme.txt');
  assert.equal(ok.ok, true);
  assert.equal(sha256(Buffer.from(ok.bytes)), sha256(fixtureReadme));

  const missing = await bridge.open('/uc/no/such/file.dat');
  assert.equal(missing.ok, false);
  assert.equal(missing.code, 'NOT_FOUND');

  const prod = await bridge.open('/uc/production/UNDERCOVER_GAME_DATA.placeholder');
  assert.equal(prod.ok, false);
  assert.equal(prod.code, 'UNSUPPORTED');
});

test('clear smoke command sequence is BeginScene Clear EndScene Present', () => {
  assert.deepEqual(S.clearOnlyCommandSequence(), [
    'BeginScene',
    'Clear(flags=7,color=0,z=1,stencil=0)',
    'EndScene',
    'Present',
  ]);
  assert.equal(S.FIRST_FRAME_STATUS, 'FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND');
  assert.equal(S.CLEAR_SMOKE_CLASSIFICATION, 'SYNTHETIC_BROWSER_CLEAR_ONLY');
});

test('clear smoke with fake canvas2d', () => {
  const ops = [];
  const canvas = {
    width: 32, height: 18,
    getContext(id) {
      if (id === 'webgl') return null;
      if (id === '2d') {
        return {
          save() { ops.push('save'); },
          restore() { ops.push('restore'); },
          setTransform() { ops.push('setTransform'); },
          fillRect(x, y, w, h) { ops.push(`fillRect(${x},${y},${w},${h})`); },
          set fillStyle(v) { ops.push(`fillStyle=${v}`); },
        };
      }
      return null;
    },
  };
  const r = S.runClearSmoke(canvas);
  assert.equal(r.api, 'canvas2d');
  assert.equal(r.cleared, true);
  assert.deepEqual(r.commands, S.clearOnlyCommandSequence());
  assert.ok(ops.some(o => o.startsWith('fillRect')));
});

test('launch UI never enables authentic play', () => {
  const ui = L.uiStateFromProgress({
    phase: 'ready_to_initialize',
    haveBytes: 100,
    totalBytes: 100,
    requiredReady: 2,
    requiredTotal: 2,
  });
  assert.equal(ui.playEnabled, false);
  assert.equal(ui.phase, 'ready_to_initialize');
});

test('source unavailable mode', async () => {
  const store = new C.MemoryAssetStore();
  const manifest = makeManifest({
    source: {
      mode: 'unavailable',
      baseUrl: '/uc-fixtures/',
      productionAssetsAuthorized: false,
      note: 'no authorized source yet',
    },
  });
  const mgr = new D.UcDownloadManager({
    store,
    fetch: async () => new Response('no', { status: 500 }),
  });
  const status = await mgr.ensureRequired(manifest);
  assert.equal(status.phase, 'source_unavailable');
});

test('path traversal rejected in manifest', () => {
  assert.throws(() => M.parseManifest({
    ...shipped,
    assets: [{
      id: 'evil', path: '../secret', url: '../secret', size: 1,
      sha256: '0'.repeat(64), contentType: 'text/plain', category: 'fixture',
      required: false, license: 'synthetic-fixture',
    }],
  }), /PATH_TRAVERSAL|traversal/i);
});

test('duplicate asset id rejected', () => {
  const a = shipped.assets[0];
  assert.throws(() => M.parseManifest({
    ...shipped,
    assets: [a, { ...a, path: 'other/path.txt' }],
  }), /duplicate/i);
});

test('cross-origin absolute URL rejected with pageOrigin', () => {
  const m = makeManifest();
  const entry = {
    ...m.assets[0],
    url: 'https://evil.example/steal.bin',
  };
  assert.throws(
    () => M.resolveAssetUrl(m, entry, 'http://localhost:8080'),
    /URL_RESTRICTED|cross-origin|not allowed/i,
  );
});

test('filesystem rejects path traversal', async () => {
  const store = new C.MemoryAssetStore();
  const files = {
    'startup/readme.txt': fixtureReadme,
    'startup/boot-marker.json': fixtureMarker,
  };
  const mgr = new D.UcDownloadManager({ store, fetch: mockFetch(files) });
  const manifest = makeManifest();
  await mgr.ensureRequired(manifest);
  const bridge = new F.UcFilesystemBridge(manifest, mgr);
  const bad = await bridge.open('/uc/../startup/readme.txt');
  assert.equal(bad.ok, false);
  assert.ok(bad.code === 'PATH_TRAVERSAL' || bad.code === 'NOT_FOUND');
});

test('cache corruption detected on reverify', async () => {
  const store = new C.MemoryAssetStore();
  const files = {
    'startup/readme.txt': fixtureReadme,
    'startup/boot-marker.json': fixtureMarker,
  };
  const mgr = new D.UcDownloadManager({ store, fetch: mockFetch(files), reverifyCached: true });
  const manifest = makeManifest();
  await mgr.ensureRequired(manifest);
  // Corrupt cached bytes in place
  const key = C.dataKey('startup.readme', sha256(fixtureReadme));
  await store.put(key, Buffer.from('CORRUPTED-BYTES-XXXX'));
  const plan = await mgr.plan(manifest);
  assert.ok(plan.missing.some(a => a.id === 'startup.readme') || plan.stale.some(a => a.id === 'startup.readme'));
});
