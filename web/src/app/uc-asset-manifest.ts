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
  const assets: AssetEntry[] = [];
  for (const a of m.assets as AssetEntry[]) {
    if (!a || typeof a.id !== 'string' || typeof a.path !== 'string') {
      throw new ManifestError('asset missing id/path', 'MANIFEST_ASSET');
    }
    if (typeof a.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(a.sha256)) {
      throw new ManifestError(`asset ${a.id}: sha256 required`, 'MANIFEST_HASH');
    }
    if (typeof a.size !== 'number' || a.size < 0) {
      throw new ManifestError(`asset ${a.id}: size invalid`, 'MANIFEST_SIZE');
    }
    assets.push({
      id: a.id,
      path: a.path.replace(/^\/+/, ''),
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
      baseUrl: source.baseUrl.endsWith('/') ? source.baseUrl : source.baseUrl + '/',
      productionAssetsAuthorized: !!source.productionAssetsAuthorized,
      note: source.note || '',
    },
    assets,
  };
}

export function resolveAssetUrl(manifest: AssetManifest, entry: AssetEntry): string {
  if (/^https?:\/\//i.test(entry.url) || entry.url.startsWith('/')) return entry.url;
  return manifest.source.baseUrl + entry.url.replace(/^\.\//, '');
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
