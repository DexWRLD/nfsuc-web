// Runtime filesystem bridge for downloaded Undercover assets (Phase 47).
// Maps stable virtual paths to cached bytes. Read-only for immutable game
// resources. Does not load or execute the original Windows nfs.exe.

import { sanitizeAssetPath, type AssetManifest, ManifestError } from './uc-asset-manifest';
import type { UcDownloadManager } from './uc-download-manager';

export type FsResult =
  | { ok: true; path: string; bytes: Uint8Array; contentType: string; size: number }
  | { ok: false; path: string; code: 'NOT_FOUND' | 'NOT_CACHED' | 'UNSUPPORTED' | 'PATH_TRAVERSAL' | 'SIZE_MISMATCH'; error: string };

export class UcFilesystemBridge {
  constructor(
    private manifest: AssetManifest,
    private manager: UcDownloadManager,
    /** Prefix for virtual paths, e.g. "/uc/" */
    readonly root = '/uc/',
  ) {}

  /** Normalize a guest/virtual path to a manifest path. */
  virtualToManifestPath(virtualPath: string): string | null {
    const p = virtualPath.replace(/\\/g, '/');
    let rel: string;
    if (p.startsWith(this.root)) rel = p.slice(this.root.length);
    else if (p.startsWith('/')) rel = p.slice(1);
    else rel = p;
    try {
      return sanitizeAssetPath(rel);
    } catch (e) {
      if (e instanceof ManifestError && e.code === 'PATH_TRAVERSAL') return null;
      throw e;
    }
  }

  listVirtualPaths(): string[] {
    return this.manifest.assets.map(a => this.root + a.path);
  }

  async open(virtualPath: string): Promise<FsResult> {
    if (virtualPath.includes('\0') || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(virtualPath)) {
      return { ok: false, path: virtualPath, code: 'PATH_TRAVERSAL', error: 'path escapes virtual root' };
    }
    const rel = this.virtualToManifestPath(virtualPath);
    if (rel == null) {
      return { ok: false, path: virtualPath, code: 'PATH_TRAVERSAL', error: 'invalid or escaping path' };
    }
    const entry = this.manifest.assets.find(
      a => a.path === rel || a.path.toLowerCase() === rel.toLowerCase(),
    );
    if (!entry) {
      return {
        ok: false,
        path: virtualPath,
        code: 'NOT_FOUND',
        error: `no manifest entry for ${rel}`,
      };
    }
    if (entry.license === 'copyrighted-unavailable') {
      return {
        ok: false,
        path: virtualPath,
        code: 'UNSUPPORTED',
        error: 'production Undercover asset not authorized for distribution',
      };
    }
    const bytes = await this.manager.readAsset(this.manifest, entry.id);
    if (!bytes) {
      return {
        ok: false,
        path: virtualPath,
        code: 'NOT_CACHED',
        error: `asset ${entry.id} not in cache`,
      };
    }
    if (bytes.byteLength !== entry.size) {
      return {
        ok: false,
        path: virtualPath,
        code: 'SIZE_MISMATCH',
        error: `cached ${bytes.byteLength} != expected ${entry.size}`,
      };
    }
    return {
      ok: true,
      path: this.root + entry.path,
      bytes,
      contentType: entry.contentType,
      size: bytes.byteLength,
    };
  }

  /** Writable save/config tree is separate (OPFS save overlay); this bridge is read-only. */
  readonly writable = false;
}
