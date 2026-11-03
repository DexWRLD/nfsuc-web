// Wire Phase 51 startup preview panel (synthetic by default; authentic when
// authorized dialog logo is served from UC_ASSET_ROOT /uc-assets/).
// After digest verification, logo bytes are published into the OPFS/memory
// asset cache so a second PC can reuse them offline.

import {
  StartupPreviewController,
  presentStartupLogo,
  type StartupImageProvenance,
  type StartupVideoLead,
} from './uc-startup-preview';
import { AssetCache, MemoryAssetStore, openOpfsAssetStore } from './uc-asset-cache';

function $(sel: string): HTMLElement | null {
  return document.querySelector(sel);
}

async function loadJson(url: string): Promise<unknown | null> {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function loadBytes(url: string): Promise<Uint8Array | null> {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) return null;
    return new Uint8Array(await r.arrayBuffer());
  } catch {
    return null;
  }
}

async function openStartupCache(): Promise<AssetCache> {
  try {
    const store = await openOpfsAssetStore();
    return new AssetCache(store);
  } catch {
    return new AssetCache(new MemoryAssetStore());
  }
}

export async function bootUcStartupPreview(log: (line: string) => void): Promise<void> {
  const panel = $('#uc-startup-preview');
  if (!panel) return;

  const status = $('#uc-startup-status');
  const detail = $('#uc-startup-detail');
  const note = $('#uc-startup-note');
  const img = $('#uc-startup-logo') as HTMLImageElement | null;
  const flags = $('#uc-startup-flags');

  const setStatus = (s: string, d: string) => {
    if (status) status.textContent = s;
    if (detail) detail.textContent = d;
  };

  const cache = await openStartupCache();
  await cache.loadMeta();

  // Prefer authorized dialog logo from asset root; fall back to synthetic fixture.
  let prov = (await loadJson('/uc-assets/dialoglogo128x128.jpg.provenance.json')) as StartupImageProvenance | null;
  let bytes = prov ? await loadBytes('/uc-assets/dialoglogo128x128.jpg') : null;
  if (!prov || !bytes) {
    prov = (await loadJson('/uc-fixtures/startup/synthetic-logo.png.provenance.json')) as StartupImageProvenance | null;
    bytes = prov ? await loadBytes('/uc-fixtures/startup/synthetic-logo.png') : null;
  }

  // Prefer verified OPFS hit when present (second PC / reload).
  if (prov) {
    const cached = await cache.read(prov.resourceId, prov.payloadSha256);
    if (cached && cached.byteLength === prov.sourceByteLength) {
      bytes = cached;
      log(`[uc-startup] cache hit ${prov.resourceId}`);
    }
  }

  const videoLead: StartupVideoLead = {
    relativePath: 'MOVIES/ea_bumper_english_ntsc.vp6',
    size: 8306328,
    sha256: 'd4982c58fa09d35390b4b02f504035002e0ec665ced3cd13f9f92e413284012c',
    containerLead: 'vp6-extension',
    browserNative: false,
    decoderAvailable: false,
    note: 'Concrete VP6 file identified on install; no independent browser decoder in-repo.',
  };

  const ctl = new StartupPreviewController({
    logo: prov,
    logoBytes: bytes,
    videoLead,
    skipVideo: false,
    onState: (s, d) => setStatus(s, d),
  });

  const skipBtn = $('#uc-startup-skip');
  if (skipBtn) {
    skipBtn.onclick = () => {
      ctl.skip();
      const snap = ctl.snapshot();
      if (flags) flags.textContent = JSON.stringify(snap.statuses);
      log(`[uc-startup] skipped → ${snap.state}`);
    };
  }

  try {
    const snap = await ctl.run();
    if (img && ctl.logoObjectUrl && prov) {
      img.hidden = false;
      presentStartupLogo(img, ctl.logoObjectUrl, prov);
    }
    if (note) {
      note.hidden = false;
      note.textContent = prov
        ? `${prov.identityNote} Preview sequence is not original boot execution. FIRST_FRAME still blocked.`
        : 'No logo resource.';
    }
    if (flags) flags.textContent = JSON.stringify(snap.statuses, null, 0);

    // Publish only after controller digest verification (SHOWING_LOGO reached).
    if (prov && bytes && snap.sequence.includes('SHOWING_LOGO')) {
      try {
        await cache.write({
          id: prov.resourceId,
          path: prov.sourceRelativePath,
          sha256: prov.payloadSha256,
          size: prov.sourceByteLength,
          manifestVersion: 51,
        }, bytes);
        log(`[uc-startup] cached ${prov.resourceId}`);
      } catch (ce) {
        log(`[uc-startup] cache write skipped: ${ce instanceof Error ? ce.message : String(ce)}`);
      }
    }

    log(`[uc-startup] ${snap.state} authentic=${snap.logoAuthentic} id=${snap.logoIdentity}`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    setStatus('FAILED', msg);
    log(`[uc-startup] failed: ${msg}`);
  }
}
