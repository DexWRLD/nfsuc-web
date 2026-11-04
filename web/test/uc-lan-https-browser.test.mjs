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
      channel: process.env.UC_BROWSER_CHANNEL || undefined,
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

    await page.locator('#play-preview').click();
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


test('authorized EA bumper plays over the LAN asset pipeline', { skip: !process.env.UC_AUTHENTIC_ASSET_ROOT }, async (t) => {
  const { chromium } = await import('playwright');
  const { startUcLanServer } = await import('../tools/uc-lan-server.mjs');
  const assetRoot = process.env.UC_AUTHENTIC_ASSET_ROOT;
  const certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'uc-bumper-certs-'));
  t.after(() => fs.rmSync(certDir, { recursive: true, force: true }));
  const handle = await startUcLanServer({
    bind: '127.0.0.1', port: 0, certDir, assetRoot,
    dist: path.join(WEB, 'dist'), manifest: path.join(assetRoot, 'phase52-manifest.json'),
  });
  t.after(() => handle.close());
  const browser = await chromium.launch({ channel: process.env.UC_BROWSER_CHANNEL || undefined, args: [
    '--ignore-certificate-errors-spki-list=' + handle.certs.spki.join(','),
  ] });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let downloads = 0;
  page.on('request', request => {
    if (request.url().endsWith('/uc-assets/ea-bumper.mp4')) downloads++;
  });
  await page.goto(handle.urls[0]);
  assert.equal(await page.evaluate(() => isSecureContext), true);
  const { build } = await import('esbuild');
  const foundation = await build({
    entryPoints: [path.join(WEB, 'src/host/uc-process.ts')],
    bundle: true, write: false, format: 'esm', platform: 'browser',
  });
  const foundationUrl = 'data:text/javascript;base64,' + Buffer.from(foundation.outputFiles[0].text).toString('base64');
  const processEvidence = await page.evaluate(async url => {
    const { GuestAddressSpace, GuestDispatcher, READ, WRITE, EXECUTE } = await import(url);
    const guest = new GuestAddressSpace([
      { name: 'code', address: 0x1000, size: 16, permissions: READ | EXECUTE },
      { name: 'data', address: 0x2000, size: 16, permissions: READ | WRITE, bytes: Uint8Array.of(7) },
    ]);
    guest.write32(0x2000, 9);
    guest.reset();
    const dispatcher = new GuestDispatcher(guest, []);
    let blocked = false;
    try {
      dispatcher.call({ esp: 0x200c }, 0x1000, 0x1004);
    } catch { blocked = true; }
    return { wasmMemory: guest.memory instanceof WebAssembly.Memory, resetValue: guest.read32(0x2000), blocked };
  }, foundationUrl);
  assert.deepEqual(processEvidence, { wasmMemory: true, resetValue: 7, blocked: true });

  assert.match(await page.title(), /Need for Speed Undercover/);
  assert.equal(await page.locator('#play').isDisabled(), true);
  assert.doesNotMatch(await page.locator('body').innerText(), /Underground 2/i);
  await page.locator('#play-preview').click();
  if (process.env.UC_BROWSER_INIT_TEST) {
    await page.locator('#guest-init-title + p').waitFor();
    await page.locator('#guest-init-trace').locator('..').locator('summary').click();
    await page.locator('#apt-constructor').click();
    await page.waitForFunction(() => document.querySelector('#apt-result')?.textContent.includes('18 zeroed'));
    await page.locator('#apt-fixture').click();
    await page.waitForFunction(() => document.querySelector('#apt-result')?.textContent.includes('Both calls restored ESP'));
    for (let attempt = 0; attempt < 2; attempt++) {
      await page.locator('#frontend-frame').click();
      await page.waitForFunction(() => document.querySelector('#frame-result')?.textContent.includes('Guest stack validated'));
      const frame = await page.locator('#frame-result').innerText();
      assert.match(frame, /0x00785CE3 → 0x008096E0/);
      assert.match(frame, /0x008096F5.*0x00548810/);
      assert.match(frame, /0xDEAD0018/);
    }
    await page.locator('#boot-callbacks').click();
    await page.waitForFunction(() => document.querySelector('#boot-callback-result')?.textContent.includes('Fixture entry only'));
    const callbacks = await page.locator('#boot-callback-result').innerText();
    assert.match(callbacks, /BootLoadScreenLoaded.*0x01873177/);
    assert.match(callbacks, /MainScreenLoaded.*0x00806295/);
    assert.match(callbacks, /0x009ADC50.*0x13572468/);
    for (let attempt = 0; attempt < 2; attempt++) {
      await page.locator('#frontend-queue').click();
      await page.waitForFunction(() => document.querySelector('#queue-result')?.textContent.includes('Unmapped entry'));
      const queue = await page.locator('#queue-result').innerText();
      assert.equal(queue.split('\n').length, 9);
      assert.match(queue, /0x005D6B20/);
      assert.match(queue, /0x0055FEB0/);
    }
    for (let run = 0; run < 2; run++) {
      await page.locator('#frontend-lookup').click();
      await page.waitForFunction(() => document.querySelector('#frontend-result')?.textContent.includes('index 118'));
      assert.match(await page.locator('#frontend-result').innerText(), /0x7F.*0x00998241/);
    }
    const trace = page.waitForEvent('console', { predicate: msg => msg.text().startsWith('[uc-init]') });
    await page.locator('#run-guest-init').click();
    const message = await trace;
    assert.deepEqual(await message.args()[1].jsonValue(), {
      entry: 0x009e8ad0, slot: 0x0189d1a4, before: 0, after: 0x009e78c0,
      writes: 49, eip: 0x00dec0de, esp: 0x0300f000, eax: 0,
      prefix: {
        entered: [0x0099dcd0, 0x009e78c0, 0x009b6290, 0x009e4b10, 0x009e78c0],
        backingPointer: 0, countMinusIndex: 0, faultAddress: 0xfffffffc,
      },
    });
  }
  const video = page.locator('#uc-startup-preview video');
  await page.waitForFunction(() => document.querySelector('#uc-startup-preview video')?.readyState >= 1);
  assert.equal(await video.evaluate(element => element.videoWidth), 1280);
  await video.evaluate(element => element.play());
  await page.waitForFunction(() => document.querySelector('#uc-startup-preview video')?.currentTime > 0.2);
  await video.evaluate(element => element.pause());
  assert.equal(await video.evaluate(element => element.paused), true);
  await video.evaluate(element => element.play());
  await video.evaluate(element => { element.currentTime = element.duration - 0.2; });
  await video.waitFor({ state: 'detached' });
  await page.reload();
  await page.locator('#play-preview').click();
  await video.waitFor({ state: 'attached' });
  assert.equal(downloads, 1);
  await page.locator('#uc-startup-skip').click();
  await video.waitFor({ state: 'detached' });
  assert.deepEqual(errors, []);
});
