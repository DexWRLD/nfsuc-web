// Undercover asset manifest (Phase 47).
// Versioned catalog for clean-PC automatic downloads. Distinguishes project
// fixtures from production game assets. Production downloads stay unavailable
// until an authorized endpoint is configured — never silently fall back to
// unauthorized commercial mirrors.

export type AssetCategory =
  | 'startup'
  | 'menu'
  | 'gameplay'
  | 'vehicle'
  | 'world'
  | 'texture'
  | 'shader'
  | 'audio'
  | 'video'
  | 'optional'
  | 'fixture';

export type AssetLicense =
  | 'project-owned'
  | 'synthetic-fixture'
  | 'redistributable-third-party'
  | 'copyrighted-authorized'
  | 'copyrighted-unavailable';

export interface AssetSourceConfig {
  /** fixtures = project-owned test bytes; authorized = rights-cleared remote */
  mode: 'fixtures' | 'authorized' | 'unavailable';
  /** Base URL for relative asset paths (trailing slash optional). */
  baseUrl: string;
  /** True only when a rights-authorized production endpoint is configured. */
  productionAssetsAuthorized: boolean;
  note: string;
}

export interface AssetEntry {
  id: string;
  path: string;
  /** Absolute URL, or path relative to source.baseUrl */
  url: string;
  size: number;
  sha256: string;
  contentType: string;
  category: AssetCategory;
  required: boolean;
  license: AssetLicense;
  compatibility?: { minManifest?: number; gameSha256?: string };
}

export interface AssetManifest {
  manifestVersion: number;
  game: 'NFS_UNDERCOVER_PC';
  toolingOrigin: 'NFSU2-WEB';
  targetSha256: string;
  source: AssetSourceConfig;
  assets: AssetEntry[];
}

export const UC_TARGET_SHA256 =
  '6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd';

export const DEFAULT_MANIFEST_URL = '/uc-asset-manifest.json';

export class ManifestError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = 'ManifestError';
  }
}

/** Reject path traversal and absolute escapes in asset paths. */
export function sanitizeAssetPath(path: string): string {
  const cleaned = path.replace(/\\/g, '/').replace(/^\/+/, '');
  const parts = cleaned.split('/').filter(p => p && p !== '.');
  if (parts.some(p => p === '..')) {
    throw new ManifestError(`path traversal rejected: ${path}`, 'PATH_TRAVERSAL');
  }
  if (parts.some(p => /[\0]/.test(p))) {
    throw new ManifestError(`invalid path byte: ${path}`, 'PATH_INVALID');
  }
  return parts.join('/');
}

export function parseManifest(raw: unknown): AssetManifest {
  if (!raw || typeof raw !== 'object') throw new ManifestError('manifest is not an object', 'MANIFEST_INVALID');
  const m = raw as Record<string, unknown>;
  if (typeof m.manifestVersion !== 'number' || m.manifestVersion < 1) {
    throw new ManifestError('manifestVersion missing or invalid', 'MANIFEST_INVALID');
  }
  if (m.game !== 'NFS_UNDERCOVER_PC') {
    throw new ManifestError(`unexpected game id ${String(m.game)}`, 'MANIFEST_GAME');
  }
  if (!Array.isArray(m.assets)) throw new ManifestError('assets must be an array', 'MANIFEST_INVALID');
  const source = m.source as AssetSourceConfig | undefined;
  if (!source || typeof source.mode !== 'string' || typeof source.baseUrl !== 'string') {
    throw new ManifestError('source.mode/baseUrl required', 'MANIFEST_SOURCE');
  }
  if (!['fixtures', 'authorized', 'unavailable'].includes(source.mode)) {
    throw new ManifestError(`unknown source.mode ${source.mode}`, 'MANIFEST_SOURCE');
  }
  const baseUrl = source.baseUrl.endsWith('/') ? source.baseUrl : source.baseUrl + '/';
  if (/^https?:\/\//i.test(baseUrl)) {
    try { new URL(baseUrl); } catch {
      throw new ManifestError('source.baseUrl is not a valid URL', 'MANIFEST_SOURCE');
    }
  } else if (!baseUrl.startsWith('/')) {
    throw new ManifestError('source.baseUrl must be absolute path or http(s) URL', 'MANIFEST_SOURCE');
  }

  const assets: AssetEntry[] = [];
  const ids = new Set<string>();
  const paths = new Set<string>();
  for (const a of m.assets as AssetEntry[]) {
    if (!a || typeof a.id !== 'string' || typeof a.path !== 'string') {
      throw new ManifestError('asset missing id/path', 'MANIFEST_ASSET');
    }
    if (!a.id.trim() || /[\/\\]/.test(a.id)) {
      throw new ManifestError(`asset id invalid: ${a.id}`, 'MANIFEST_ASSET');
    }
    if (ids.has(a.id)) throw new ManifestError(`duplicate asset id ${a.id}`, 'MANIFEST_DUP');
    if (typeof a.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(a.sha256)) {
      throw new ManifestError(`asset ${a.id}: sha256 required`, 'MANIFEST_HASH');
    }
    if (typeof a.size !== 'number' || !Number.isFinite(a.size) || a.size < 0 || a.size > 1 << 30) {
      throw new ManifestError(`asset ${a.id}: size invalid`, 'MANIFEST_SIZE');
    }
    if (typeof a.url !== 'string' || !a.url) {
      throw new ManifestError(`asset ${a.id}: url required`, 'MANIFEST_ASSET');
    }
    const path = sanitizeAssetPath(a.path);
    if (paths.has(path.toLowerCase())) {
      throw new ManifestError(`duplicate asset path ${path}`, 'MANIFEST_DUP');
    }
    // Relative urls must not traverse.
    if (!/^https?:\/\//i.test(a.url) && !a.url.startsWith('/')) {
      sanitizeAssetPath(a.url);
    }
    ids.add(a.id);
    paths.add(path.toLowerCase());
    assets.push({
      id: a.id,
      path,
      url: a.url,
      size: a.size,
      sha256: a.sha256.toLowerCase(),
      contentType: a.contentType || 'application/octet-stream',
      category: a.category || 'fixture',
      required: !!a.required,
      license: a.license || 'synthetic-fixture',
      compatibility: a.compatibility,
    });
  }
  return {
    manifestVersion: m.manifestVersion as number,
    game: 'NFS_UNDERCOVER_PC',
    toolingOrigin: 'NFSU2-WEB',
    targetSha256: String(m.targetSha256 || UC_TARGET_SHA256),
    source: {
      mode: source.mode as AssetSourceConfig['mode'],
      baseUrl,
      productionAssetsAuthorized: !!source.productionAssetsAuthorized,
      note: source.note || '',
    },
    assets,
  };
}

/** Resolve and validate asset URL against manifest base (same-origin or configured host). */
export function resolveAssetUrl(manifest: AssetManifest, entry: AssetEntry, pageOrigin?: string): string {
  let url: string;
  if (/^https?:\/\//i.test(entry.url)) url = entry.url;
  else if (entry.url.startsWith('/')) url = entry.url;
  else url = manifest.source.baseUrl + entry.url.replace(/^\.\//, '');

  if (/^https?:\/\//i.test(url)) {
    let parsed: URL;
    try { parsed = new URL(url); } catch {
      throw new ManifestError(`invalid asset URL ${url}`, 'URL_INVALID');
    }
    if (parsed.username || parsed.password) {
      throw new ManifestError('asset URL must not include credentials', 'URL_RESTRICTED');
    }
    if (pageOrigin) {
      const origin = new URL(pageOrigin);
      const baseIsHttp = /^https?:\/\//i.test(manifest.source.baseUrl);
      if (baseIsHttp) {
        const allowed = new URL(manifest.source.baseUrl);
        if (parsed.origin !== allowed.origin) {
          throw new ManifestError(`asset host ${parsed.origin} not allowed`, 'URL_RESTRICTED');
        }
      } else if (parsed.origin !== origin.origin) {
        throw new ManifestError(`cross-origin asset URL rejected: ${parsed.origin}`, 'URL_RESTRICTED');
      }
    }
  } else if (!url.startsWith('/')) {
    throw new ManifestError(`asset URL must be absolute: ${url}`, 'URL_INVALID');
  } else {
    // path-only: still reject traversal encoded in the URL path
    sanitizeAssetPath(url);
  }
  return url;
}

export function requiredAssets(manifest: AssetManifest): AssetEntry[] {
  return manifest.assets.filter(a => a.required);
}

export function productionDownloadsAllowed(manifest: AssetManifest): boolean {
  return (
    manifest.source.mode === 'authorized' &&
    manifest.source.productionAssetsAuthorized === true
  );
}

/** Refuse copyrighted-unavailable assets unless production is authorized. */
export function assertDownloadAllowed(manifest: AssetManifest, entry: AssetEntry): void {
  if (entry.license === 'copyrighted-unavailable') {
    throw new ManifestError(
      `asset ${entry.id}: production Undercover bytes unavailable (no authorized source)`,
      'SOURCE_UNAUTHORIZED',
    );
  }
  if (entry.license === 'copyrighted-authorized' && !productionDownloadsAllowed(manifest)) {
    throw new ManifestError(
      `asset ${entry.id}: copyrighted-authorized requires productionAssetsAuthorized`,
      'SOURCE_UNAUTHORIZED',
    );
  }
}
