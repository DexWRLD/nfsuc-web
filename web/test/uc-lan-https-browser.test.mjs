// Playwright: HTTPS LAN host + clean profile OPFS/path boot (Phase 49).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(HERE, '..');
const require = createRequire(import.meta.url);

async function loadPlaywright() {
  try { return await import('playwright'); } catch {
    try { return require('playwright'); } catch { return null; }
  }
}

test('HTTPS LAN origin: secure context, assets ready, play disabled', async (t) => {
  const pw = await loadPlaywright();
  if (!pw) { t.skip('playwright not installed'); return; }

  const { execFileSync } = await import('node:child_process');
  if (!fs.existsSync(path.join(WEB, 'dist', 'index.html'))) {
    execFileSync(process.execPath, ['build.mjs'], { cwd: WEB, stdio: 'pipe' });
  }

  const certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'uc-lan-browser-certs-'));
  const { startUcLanServer } = await import('../tools/uc-lan-server.mjs');
  let handle;
  try {
    handle = await startUcLanServer({
      bind: '127.0.0.1',
      port: 0,
      dist: path.join(WEB, 'dist'),
      assetRoot: '',
      manifest: path.join(WEB, 'dist', 'uc-asset-manifest.json'),
      certDir,
    });
  } catch (e) {
    t.skip('LAN server failed to start: ' + (e?.message || e));
    return;
  }

  const origin = handle.urls[0].replace(/\/$/, '');
  let browser;
  try {
    browser = await pw.chromium.launch({
      headless: true,
      args: [`--ignore-certificate-errors-spki-list=${handle.certs.spki.join(',')}`],
    });
  } catch (e) {
    await handle.close();
    t.skip('chromium unavailable: ' + (e?.message || e));
    return;
  }

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await page.goto(origin + '/', { waitUntil: 'domcontentloaded', timeout: 60000 });

    const secure = await page.evaluate(() => ({
      secure: window.isSecureContext,
      protocol: location.protocol,
    }));
    assert.equal(secure.protocol, 'https:');
    assert.equal(secure.secure, true);

    // Wait for Undercover panel boot stage / status text
    await page.waitForFunction(() => {
      const st = document.getElementById('uc-boot-stage')?.textContent || '';
      const status = document.getElementById('uc-asset-status')?.textContent || '';
      return /READY_OR_BLOCKED|Ready to initialize|Runtime not yet playable/i.test(st + status);
    }, null, { timeout: 60000 }).catch(() => {});

    const panel = await page.evaluate(() => ({
      stage: document.getElementById('uc-boot-stage')?.textContent || '',
      status: document.getElementById('uc-asset-status')?.textContent || '',
      warn: document.getElementById('uc-secure-warning')?.textContent || '',
      warnHidden: document.getElementById('uc-secure-warning')?.hidden ?? true,
      note: document.getElementById('uc-asset-note')?.textContent || '',
    }));
    assert.match(panel.stage + panel.status, /READY_OR_BLOCKED|Ready to initialize|Runtime not/i);
    assert.equal(panel.warnHidden, true);
    assert.match(panel.note, /Play remains disabled|FIRST_FRAME/i);

    const statusJson = await page.evaluate(async () => {
      const r = await fetch('/uc-lan-status.json');
      return r.json();
    });
    assert.equal(statusJson.game, 'NFS_UNDERCOVER_PC');
    assert.equal(statusJson.firstFrame, 'FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND');
  } finally {
    await browser.close();
    await handle.close();
  }
});
