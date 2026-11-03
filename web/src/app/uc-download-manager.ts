// Automatic Undercover asset download manager (Phase 47).
// Injectable fetch + cache. Verifies SHA-256 before marking available.
// Does not download copyrighted-unavailable assets.

import {
  type AssetEntry,
  type AssetManifest,
  assertDownloadAllowed,
  parseManifest,
  resolveAssetUrl,
  requiredAssets,
  ManifestError,
} from './uc-asset-manifest';
import { AssetCache, type AssetStore, dataKey } from './uc-asset-cache';

export type LaunchPhase =
  | 'idle'
  | 'checking'
  | 'downloading'
  | 'verifying'
  | 'ready_to_initialize'
  | 'runtime_not_playable'
  | 'download_failed'
  | 'insufficient_storage'
  | 'offline_cached'
  | 'source_unavailable';

export interface DownloadProgress {
  phase: LaunchPhase;
  haveBytes: number;
  totalBytes: number;
  currentId?: string;
  error?: string;
  /** required assets ready in cache */
  requiredReady: number;
  requiredTotal: number;
}

export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

export interface DownloadManagerOptions {
  fetch?: FetchFn;
  store: AssetStore;
  concurrency?: number;
  maxRetries?: number;
  /** Base backoff ms for retries (doubles each attempt). */
  retryBackoffMs?: number;
  /** Soft quota: refuse download when usage + remaining > this (bytes). */
  quotaBytes?: number | null;
  /** Page origin for cross-origin URL restrictions (browser). */
  pageOrigin?: string;
  /** Re-hash cached assets during plan (detect corruption). */
  reverifyCached?: boolean;
  onProgress?: (p: DownloadProgress) => void;
}

export class DownloadError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = 'DownloadError';
  }
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new DownloadError('cancelled', 'CANCELLED')); return; }
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(t); reject(new DownloadError('cancelled', 'CANCELLED')); }, { once: true });
  });
}

export class UcDownloadManager {
  private cache: AssetCache;
  private fetch: FetchFn;
  private concurrency: number;
  private maxRetries: number;
  private retryBackoffMs: number;
  private quotaBytes: number | null;
  private pageOrigin?: string;
  private reverifyCached: boolean;
  private onProgress?: (p: DownloadProgress) => void;
  private abort: AbortController | null = null;
  private progress: DownloadProgress = {
    phase: 'idle', haveBytes: 0, totalBytes: 0, requiredReady: 0, requiredTotal: 0,
  };

  constructor(opts: DownloadManagerOptions) {
    this.cache = new AssetCache(opts.store);
    this.fetch = opts.fetch ?? ((u, i) => fetch(u, i));
    this.concurrency = Math.max(1, Math.min(8, opts.concurrency ?? 3));
    this.maxRetries = Math.max(0, opts.maxRetries ?? 2);
    this.retryBackoffMs = Math.max(0, opts.retryBackoffMs ?? 200);
    this.quotaBytes = opts.quotaBytes ?? null;
    this.pageOrigin = opts.pageOrigin;
    this.reverifyCached = opts.reverifyCached !== false;
    this.onProgress = opts.onProgress;
  }

  get status(): DownloadProgress { return { ...this.progress }; }

  cancel(): void {
    this.abort?.abort();
    this.abort = null;
  }

  private set(partial: Partial<DownloadProgress>) {
    this.progress = { ...this.progress, ...partial };
    this.onProgress?.(this.status);
  }

  async loadManifest(url: string): Promise<AssetManifest> {
    const r = await this.fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new ManifestError(`manifest HTTP ${r.status}`, 'MANIFEST_HTTP');
    return parseManifest(await r.json());
  }

  async plan(manifest: AssetManifest): Promise<{
    missing: AssetEntry[];
    stale: AssetEntry[];
    present: AssetEntry[];
  }> {
    await this.cache.loadMeta();
    const missing: AssetEntry[] = [];
    const stale: AssetEntry[] = [];
    const present: AssetEntry[] = [];
    for (const a of manifest.assets) {
      let ok = await this.cache.hasValid(a.id, a.sha256, a.size);
      if (ok && this.reverifyCached) {
        ok = await this.cache.verifyStored(a.id, a.sha256, a.size, sha256Hex);
      }
      if (ok) present.push(a);
      else if (this.cache.getMeta(a.id)) stale.push(a);
      else missing.push(a);
    }
    return { missing, stale, present };
  }

  async ensureRequired(manifest: AssetManifest): Promise<DownloadProgress> {
    this.abort = new AbortController();
    const signal = this.abort.signal;
    try {
      this.set({ phase: 'checking', error: undefined });
      if (manifest.source.mode === 'unavailable') {
        this.set({ phase: 'source_unavailable', error: manifest.source.note || 'no authorized source' });
        return this.status;
      }

      const req = requiredAssets(manifest);
      this.set({ requiredTotal: req.length, requiredReady: 0 });

      const plan = await this.plan(manifest);
      const need = [...plan.missing, ...plan.stale].filter(a => a.required);
      // prune obsolete after plan
      await this.cache.prune(manifest.assets.map(a => ({ id: a.id, sha256: a.sha256 })));

      let have = 0;
      for (const a of plan.present.filter(x => x.required)) have += a.size;
      const total = req.reduce((s, a) => s + a.size, 0);
      this.set({
        haveBytes: have,
        totalBytes: total,
        requiredReady: plan.present.filter(a => a.required).length,
      });

      if (!need.length) {
        this.set({
          phase: 'ready_to_initialize',
          requiredReady: req.length,
          haveBytes: total,
        });
        return this.status;
      }

      if (this.quotaBytes != null) {
        const used = (await this.cache.store.usageBytes()) ?? 0;
        const remaining = need.reduce((s, a) => s + a.size, 0);
        if (used + remaining > this.quotaBytes) {
          this.set({
            phase: 'insufficient_storage',
            error: `need ${remaining} more bytes; quota ${this.quotaBytes}`,
          });
          return this.status;
        }
      }

      this.set({ phase: 'downloading' });
      await this.downloadAll(manifest, need, signal);

      // re-check required
      let ready = 0;
      for (const a of req) {
        if (await this.cache.hasValid(a.id, a.sha256, a.size)) ready++;
      }
      if (ready === req.length) {
        // Fixtures verified. Authentic Undercover play remains separately blocked.
        this.set({
          phase: 'ready_to_initialize',
          requiredReady: ready,
          haveBytes: total,
          error: undefined,
        });
      } else {
        this.set({
          phase: 'download_failed',
          requiredReady: ready,
          haveBytes: this.progress.haveBytes,
          error: 'required assets incomplete after download',
        });
      }
      return this.status;
    } catch (e) {
      if (signal.aborted) {
        this.set({ phase: 'download_failed', error: 'cancelled' });
      } else if (e instanceof ManifestError && e.code === 'SOURCE_UNAUTHORIZED') {
        this.set({ phase: 'source_unavailable', error: e.message });
      } else {
        this.set({
          phase: 'download_failed',
          error: e instanceof Error ? e.message : String(e),
        });
      }
      return this.status;
    } finally {
      this.abort = null;
    }
  }

  /** Offline: if all required assets are cached, report offline_cached. */
  async checkOffline(manifest: AssetManifest): Promise<DownloadProgress> {
    await this.cache.loadMeta();
    const req = requiredAssets(manifest);
    let ready = 0;
    let have = 0;
    const total = req.reduce((s, a) => s + a.size, 0);
    for (const a of req) {
      if (await this.cache.hasValid(a.id, a.sha256, a.size)) {
        ready++;
        have += a.size;
      }
    }
    this.set({
      phase: ready === req.length && req.length > 0 ? 'offline_cached' : 'download_failed',
      requiredReady: ready,
      requiredTotal: req.length,
      haveBytes: have,
      totalBytes: total,
      error: ready === req.length ? undefined : 'offline and required assets missing',
    });
    return this.status;
  }

  async readAsset(manifest: AssetManifest, id: string): Promise<Uint8Array | null> {
    const entry = manifest.assets.find(a => a.id === id);
    if (!entry) return null;
    await this.cache.loadMeta();
    return this.cache.read(id, entry.sha256);
  }

  getCache(): AssetCache { return this.cache; }

  private async downloadAll(
    manifest: AssetManifest,
    need: AssetEntry[],
    signal: AbortSignal,
  ): Promise<void> {
    let idx = 0;
    const workers = Array.from({ length: Math.min(this.concurrency, need.length) }, async () => {
      while (idx < need.length) {
        if (signal.aborted) throw new DownloadError('cancelled', 'CANCELLED');
        const a = need[idx++];
        assertDownloadAllowed(manifest, a);
        this.set({ currentId: a.id, phase: 'downloading' });
        await this.downloadOne(manifest, a, signal);
        this.set({
          haveBytes: this.progress.haveBytes + a.size,
          requiredReady: this.progress.requiredReady + (a.required ? 1 : 0),
        });
      }
    });
    await Promise.all(workers);
  }

  private async downloadOne(
    manifest: AssetManifest,
    entry: AssetEntry,
    signal: AbortSignal,
  ): Promise<void> {
    const url = resolveAssetUrl(manifest, entry, this.pageOrigin);
    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        if (attempt > 0 && this.retryBackoffMs > 0) {
          await sleep(this.retryBackoffMs * (2 ** (attempt - 1)), signal);
        }
        const data = await this.fetchBytes(url, entry.size, signal);
        this.set({ phase: 'verifying', currentId: entry.id });
        const hash = await sha256Hex(data);
        if (hash !== entry.sha256.toLowerCase()) {
          throw new DownloadError(
            `hash mismatch for ${entry.id}: got ${hash}`,
            'HASH_MISMATCH',
          );
        }
        if (data.byteLength !== entry.size) {
          throw new DownloadError(
            `size mismatch for ${entry.id}: got ${data.byteLength}`,
            'SIZE_MISMATCH',
          );
        }
        // Publish only after hash verification (cache.write stages atomically).
        await this.cache.write({
          id: entry.id,
          path: entry.path,
          sha256: entry.sha256,
          size: entry.size,
          manifestVersion: manifest.manifestVersion,
        }, data);
        return;
      } catch (e) {
        lastErr = e;
        if (signal.aborted) throw e;
        if (e instanceof DownloadError && (
          e.code === 'HASH_MISMATCH' || e.code === 'URL_RESTRICTED' || e.code === 'CANCELLED'
        )) throw e;
        if (e instanceof ManifestError) throw e;
      }
    }
    throw lastErr instanceof Error ? lastErr : new DownloadError(String(lastErr), 'NETWORK');
  }

  private async fetchBytes(url: string, expected: number, signal: AbortSignal): Promise<Uint8Array> {
    const r = await this.fetch(url, { signal, cache: 'no-store' });
    if (!r.ok) throw new DownloadError(`HTTP ${r.status} for ${url}`, 'HTTP');
    const cl = r.headers?.get?.('content-length');
    if (cl != null && cl !== '' && expected) {
      const n = Number(cl);
      if (Number.isFinite(n) && n !== expected) {
        throw new DownloadError(
          `content-length mismatch ${n}/${expected} for ${url}`,
          'CONTENT_LENGTH',
        );
      }
    }
    if (!r.body) {
      const buf = new Uint8Array(await r.arrayBuffer());
      if (expected && buf.byteLength !== expected) {
        throw new DownloadError(`partial download ${buf.byteLength}/${expected}`, 'PARTIAL');
      }
      return buf;
    }
    const reader = r.body.getReader();
    const chunks: Uint8Array[] = [];
    let got = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      got += value.byteLength;
      if (expected && got > expected) {
        throw new DownloadError(`oversized download ${got}/${expected}`, 'PARTIAL');
      }
    }
    const out = new Uint8Array(got);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.byteLength; }
    if (expected && out.byteLength !== expected) {
      throw new DownloadError(`partial download ${out.byteLength}/${expected}`, 'PARTIAL');
    }
    return out;
  }
}

export { dataKey };
