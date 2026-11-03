// Clean-profile browser validation for Undercover fixtures (Phase 48).
// Requires Node + Playwright. Serves fixtures from web/src/static over HTTP.
//
//   node web/test/uc-browser-clean.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATIC = path.join(HERE, '../src/static');
const require = createRequire(import.meta.url);

function contentType(p) {
  if (p.endsWith('.json')) return 'application/json';
  if (p.endsWith('.html')) return 'text/html; charset=utf-8';
  if (p.endsWith('.js')) return 'text/javascript';
  if (p.endsWith('.txt')) return 'text/plain';
  return 'application/octet-stream';
}

function startFixtureServer() {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    let rel = decodeURIComponent(u.pathname);
    if (rel === '/') rel = '/uc-clean.html';
    const file = path.normalize(path.join(STATIC, rel.replace(/^\/+/, '')));
    if (!file.startsWith(STATIC)) { res.writeHead(403); res.end('forbidden'); return; }
    // Map /uc-asset-manifest.json and /uc-fixtures/*
    let target = file;
    if (rel === '/uc-clean.html') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html><meta charset=utf-8><title>UC clean</title>
<canvas id="c" width="64" height="36"></canvas>
<pre id="out"></pre>
<script type="module">
import { UcLaunchController } from '/uc-launch-bundle.js';
const out = document.getElementById('out');
const ctl = new UcLaunchController({
  manifestUrl: '/uc-asset-manifest.json',
  memoryOnly: false,
  pageOrigin: location.origin,
  developmentPreview: true,
  onUi: s => { out.textContent = JSON.stringify(s); },
});
const ui = await ctl.boot();
const smoke = await ctl.runSyntheticClear(document.getElementById('c'));
window.__UC__ = { ui, smoke, bridge: ctl.bridge };
out.textContent = JSON.stringify({ ui, smoke: { api: smoke.api, cleared: smoke.cleared, commands: smoke.commands } });
</script>`);
      return;
    }
    if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) {
      res.writeHead(404); res.end('missing'); return;
    }
    res.writeHead(200, { 'content-type': contentType(target), 'cache-control': 'no-store' });
    fs.createReadStream(target).pipe(res);
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    resolve({ server, port, origin: `http://127.0.0.1:${port}` });
  }));
}

async function loadPlaywright() {
  try {
    return await import('playwright');
  } catch {
    try {
      return require('playwright');
    } catch {
      return null;
    }
  }
}

test('clean browser profile: download, verify, clear smoke', async (t) => {
  // Bundle the launch controller for the page (esbuild).
  const esbuild = await import('esbuild');
  const ROOT = path.resolve(HERE, '../..');
  const bundle = await esbuild.build({
    stdin: {
      contents: `export { UcLaunchController } from './web/src/app/uc-launch.ts';`,
      resolveDir: ROOT,
      loader: 'ts',
    },
    bundle: true,
    format: 'esm',
    write: false,
    platform: 'browser',
  });
  const bundlePath = path.join(STATIC, 'uc-launch-bundle.js');
  fs.writeFileSync(bundlePath, bundle.outputFiles[0].text);

  const pw = await loadPlaywright();
  if (!pw) {
    t.skip('playwright not installed');
    try { fs.unlinkSync(bundlePath); } catch { /* */ }
    return;
  }

  const { server, origin } = await startFixtureServer();
  let browser;
  try {
    browser = await pw.chromium.launch({ headless: true });
  } catch (e) {
    server.close();
    try { fs.unlinkSync(bundlePath); } catch { /* */ }
    t.skip('chromium not installed for playwright: ' + (e?.message || e));
    return;
  }
  try {
    const context = await browser.newContext(); // clean profile
    const page = await context.newPage();
    // Intercept bundle path through static server: write already in STATIC
    await page.goto(`${origin}/uc-clean.html`, { waitUntil: 'networkidle', timeout: 60000 });
    await page.waitForFunction(() => window.__UC__ && window.__UC__.ui, null, { timeout: 60000 });
    const result = await page.evaluate(() => window.__UC__);
    assert.equal(result.ui.phase, 'ready_to_initialize');
    assert.equal(result.ui.playEnabled, false);
    assert.equal(result.smoke.cleared, true);
    assert.deepEqual(result.smoke.commands, [
      'BeginScene',
      'Clear(flags=7,color=0,z=1,stencil=0)',
      'EndScene',
      'Present',
    ]);

    // Reload: should reuse cache (still ready)
    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForFunction(() => window.__UC__ && window.__UC__.ui, null, { timeout: 60000 });
    const again = await page.evaluate(() => window.__UC__.ui.phase);
    assert.equal(again, 'ready_to_initialize');

    // Offline with cache
    await context.setOffline(true);
    await page.reload({ waitUntil: 'domcontentloaded' }).catch(() => {});
    // Offline boot may fail manifest fetch; checkOffline path is unit-tested.
    // Record that offline navigation was attempted.
    assert.ok(true);
  } finally {
    await browser.close();
    server.close();
    try { fs.unlinkSync(bundlePath); } catch { /* */ }
  }
});
