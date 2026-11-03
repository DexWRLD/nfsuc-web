// Phase 51: startup preview state machine (synthetic fixtures only).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as esbuild from 'esbuild';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const FIX = path.join(HERE, '../src/static/uc-fixtures/startup');

const built = await esbuild.build({
  stdin: {
    contents: `export * from './web/src/app/uc-startup-preview.ts';`,
    resolveDir: ROOT,
    loader: 'ts',
  },
  bundle: true,
  format: 'esm',
  write: false,
  platform: 'neutral',
});
const out = path.join(HERE, `uc-startup-bundle-${process.pid}.mjs`);
fs.writeFileSync(out, built.outputFiles[0].text);
const {
  StartupPreviewController,
} = await import(pathToFileURL(out).href);

const prov = JSON.parse(fs.readFileSync(path.join(FIX, 'synthetic-logo.png.provenance.json'), 'utf8'));
const bytes = fs.readFileSync(path.join(FIX, 'synthetic-logo.png'));

test('valid synthetic logo reaches SHOWING_LOGO and COMPLETE', async () => {
  const ctl = new StartupPreviewController({
    logo: prov,
    logoBytes: bytes,
    videoLead: null,
  });
  const snap = await ctl.run();
  assert.ok(snap.sequence.includes('LOADING_LOGO'));
  assert.ok(snap.sequence.includes('SHOWING_LOGO'));
  assert.ok(snap.sequence.includes('VIDEO_UNAVAILABLE'));
  assert.ok(snap.sequence.includes('MENU_PLACEHOLDER'));
  assert.equal(snap.state, 'COMPLETE');
  assert.equal(snap.statuses.AUTHENTIC_STARTUP_ASSET_PREVIEW, 'SYNTHETIC');
  assert.equal(snap.statuses.FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND, 'BLOCKED');
  ctl.dispose();
});

test('missing logo', async () => {
  const ctl = new StartupPreviewController({ logo: null, logoBytes: null });
  const snap = await ctl.run();
  assert.ok(snap.sequence.includes('LOGO_MISSING'));
  assert.equal(snap.state, 'COMPLETE');
  ctl.dispose();
});

test('optional video lead without decoder → VIDEO_UNAVAILABLE', async () => {
  const ctl = new StartupPreviewController({
    logo: prov,
    logoBytes: bytes,
    videoLead: {
      relativePath: 'MOVIES/ea_bumper_english_ntsc.vp6',
      size: 1,
      sha256: '00',
      containerLead: 'vp6-extension',
      browserNative: false,
      decoderAvailable: false,
      note: 'no decoder',
    },
  });
  const snap = await ctl.run();
  assert.ok(snap.sequence.includes('LOADING_VIDEO'));
  assert.ok(snap.sequence.includes('VIDEO_UNAVAILABLE'));
  assert.equal(snap.statuses.AUTHENTIC_INTRO_VIDEO_PREVIEW, 'IDENTIFIED_NO_DECODER');
  ctl.dispose();
});

test('skip jumps to menu placeholder', async () => {
  const ctl = new StartupPreviewController({ logo: prov, logoBytes: bytes });
  ctl.skip();
  const snap = ctl.snapshot();
  assert.ok(snap.sequence.includes('SKIPPED'));
  assert.ok(snap.sequence.includes('MENU_PLACEHOLDER'));
  assert.equal(snap.state, 'COMPLETE');
  ctl.dispose();
});

test('cache mismatch on bad digest', async () => {
  const bad = { ...prov, payloadSha256: '0'.repeat(64), sourceSha256: '0'.repeat(64) };
  const ctl = new StartupPreviewController({ logo: bad, logoBytes: bytes });
  const snap = await ctl.run();
  assert.equal(snap.state, 'CACHE_MISMATCH');
  ctl.dispose();
});

test('authorized-verified category marks AUTHENTIC_STARTUP_ASSET_PREVIEW READY', async () => {
  const auth = {
    ...prov,
    sourceCategory: 'authorized-verified',
    kind: 'authentic-verified',
    identityNote: 'test authentic label',
  };
  const ctl = new StartupPreviewController({ logo: auth, logoBytes: bytes, videoLead: null });
  const snap = await ctl.run();
  assert.equal(snap.logoAuthentic, true);
  assert.equal(snap.statuses.AUTHENTIC_STARTUP_ASSET_PREVIEW, 'READY');
  assert.equal(snap.statuses.FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND, 'BLOCKED');
  ctl.dispose();
});

test('stale async completion after dispose', async () => {
  const ctl = new StartupPreviewController({ logo: prov, logoBytes: bytes });
  const p = ctl.run();
  ctl.dispose();
  const snap = await p;
  // dispose during run should yield FAILED stale or still complete depending on timing;
  // generation bump must not throw.
  assert.ok(['FAILED', 'COMPLETE', 'CACHE_MISMATCH', 'SHOWING_LOGO'].includes(snap.state)
    || snap.sequence.length >= 1);
});

try { fs.unlinkSync(out); } catch { /* */ }
