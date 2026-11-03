// Browser smoke for Phase 51 startup preview (synthetic fixture only).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as esbuild from 'esbuild';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const STATIC = path.join(HERE, '../src/static');
const FIX = path.join(STATIC, 'uc-fixtures/startup');

const built = await esbuild.build({
  stdin: {
    contents: `export * from './web/src/app/uc-startup-preview.ts';`,
    resolveDir: ROOT,
    loader: 'ts',
  },
  bundle: true,
  format: 'esm',
  write: false,
  platform: 'browser',
});
const bundlePath = path.join(STATIC, 'uc-startup-preview-bundle.js');
fs.writeFileSync(bundlePath, built.outputFiles[0].text);

function startServer() {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (u.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html><meta charset=utf-8>
<img id="logo" width="64" height="64" />
<pre id="out"></pre>
<script type="module">
import { StartupPreviewController, presentStartupLogo } from '/uc-startup-preview-bundle.js';
const prov = await (await fetch('/uc-fixtures/startup/synthetic-logo.png.provenance.json')).json();
const bytes = new Uint8Array(await (await fetch('/uc-fixtures/startup/synthetic-logo.png')).arrayBuffer());
const ctl = new StartupPreviewController({ logo: prov, logoBytes: bytes, videoLead: null });
const snap = await ctl.run();
const img = document.getElementById('logo');
if (ctl.logoObjectUrl) presentStartupLogo(img, ctl.logoObjectUrl, prov);
window.__UC_STARTUP__ = snap;
document.getElementById('out').textContent = JSON.stringify(snap);
</script>`);
      return;
    }
    let rel = decodeURIComponent(u.pathname).replace(/^\/+/, '');
    const file = path.normalize(path.join(STATIC, rel));
    if (!file.startsWith(STATIC) || !fs.existsSync(file)) {
      res.writeHead(404); res.end('missing'); return;
    }
    const ct = file.endsWith('.js') ? 'text/javascript'
      : file.endsWith('.json') ? 'application/json'
      : file.endsWith('.png') ? 'image/png'
      : 'application/octet-stream';
    res.writeHead(200, { 'content-type': ct, 'cache-control': 'no-store' });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => {
    resolve({ server, origin: `http://127.0.0.1:${server.address().port}` });
  }));
}

test('browser synthetic startup logo preview', async (t) => {
  let pw;
  try {
    pw = await import('playwright');
  } catch {
    t.skip('playwright not available');
    return;
  }
  assert.ok(fs.existsSync(path.join(FIX, 'synthetic-logo.png')));
  const { server, origin } = await startServer();
  t.after(() => {
    server.close();
    try { fs.unlinkSync(bundlePath); } catch { /* */ }
  });
  let browser;
  try {
    browser = await pw.chromium.launch({ headless: true });
  } catch (e) {
    t.skip(`chromium unavailable: ${e instanceof Error ? e.message : String(e)}`);
    return;
  }
  t.after(async () => { await browser.close(); });
  const page = await browser.newPage();
  await page.goto(origin, { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForFunction(() => window.__UC_STARTUP__, null, { timeout: 15000 });
  const snap = await page.evaluate(() => window.__UC_STARTUP__);
  assert.equal(snap.state, 'COMPLETE');
  assert.ok(snap.sequence.includes('SHOWING_LOGO'));
  assert.equal(snap.statuses.AUTHENTIC_STARTUP_ASSET_PREVIEW, 'SYNTHETIC');
  assert.equal(snap.statuses.FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND, 'BLOCKED');
  const src = await page.$eval('#logo', el => el.getAttribute('src') || '');
  assert.ok(src.startsWith('blob:'), 'logo uses blob URL');
});
