// Persistent cache for Undercover assets (Phase 47).
// Prefers OPFS when available; falls back to an injectable MemoryStore for
// Node tests and browsers that decline persistent storage.

export interface CachedAssetMeta {
  id: string;
  path: string;
  sha256: string;
  size: number;
  manifestVersion: number;
}

export interface AssetStore {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, data: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  listKeys(): Promise<string[]>;
  /** Approximate bytes used; may be null if unknown. */
  usageBytes(): Promise<number | null>;
}

export class MemoryAssetStore implements AssetStore {
  private map = new Map<string, Uint8Array>();
  async get(key: string) { return this.map.get(key) ?? null; }
  async put(key: string, data: Uint8Array) { this.map.set(key, data.slice()); }
  async delete(key: string) { this.map.delete(key); }
  async listKeys() { return [...this.map.keys()]; }
  async usageBytes() {
    let n = 0;
    for (const v of this.map.values()) n += v.byteLength;
    return n;
  }
  clear() { this.map.clear(); }
}

const META_KEY = 'uc-asset-meta-v1';
const DATA_PREFIX = 'uc-asset:';

export function dataKey(id: string, sha256: string): string {
  return `${DATA_PREFIX}${id}:${sha256.toLowerCase()}`;
}

export class AssetCache {
  private meta = new Map<string, CachedAssetMeta>();

  constructor(readonly store: AssetStore) {}

  async loadMeta(): Promise<void> {
    const raw = await this.store.get(META_KEY);
    if (!raw) { this.meta.clear(); return; }
    try {
      const list = JSON.parse(new TextDecoder().decode(raw)) as CachedAssetMeta[];
      this.meta.clear();
      for (const m of list) this.meta.set(m.id, m);
    } catch {
      this.meta.clear();
    }
  }

  private async saveMeta(): Promise<void> {
    const enc = new TextEncoder();
    await this.store.put(META_KEY, enc.encode(JSON.stringify([...this.meta.values()])));
  }

  getMeta(id: string): CachedAssetMeta | undefined {
    return this.meta.get(id);
  }

  async hasValid(id: string, sha256: string, size: number): Promise<boolean> {
    const m = this.meta.get(id);
    if (!m || m.sha256 !== sha256.toLowerCase() || m.size !== size) return false;
    const bytes = await this.store.get(dataKey(id, sha256));
    return !!bytes && bytes.byteLength === size;
  }

  async read(id: string, sha256: string): Promise<Uint8Array | null> {
    return this.store.get(dataKey(id, sha256));
  }

  async write(meta: CachedAssetMeta, data: Uint8Array): Promise<void> {
    if (data.byteLength !== meta.size) {
      throw new Error(`cache write size mismatch for ${meta.id}`);
    }
    // Atomic publish: stage under a temp key, then swap to the canonical key
    // and only then update meta (so readers never see unverified bytes).
    const finalKey = dataKey(meta.id, meta.sha256);
    const stageKey = `${finalKey}.staging`;
    await this.store.put(stageKey, data);
    const staged = await this.store.get(stageKey);
    if (!staged || staged.byteLength !== meta.size) {
      await this.store.delete(stageKey);
      throw new Error(`staging failed for ${meta.id}`);
    }
    await this.store.put(finalKey, staged);
    await this.store.delete(stageKey);
    // Drop previous hash for this id if different.
    const prev = this.meta.get(meta.id);
    if (prev && prev.sha256 !== meta.sha256.toLowerCase()) {
      await this.store.delete(dataKey(meta.id, prev.sha256));
    }
    this.meta.set(meta.id, { ...meta, sha256: meta.sha256.toLowerCase() });
    await this.saveMeta();
  }

  /** Re-hash cached bytes; drop on mismatch (corruption). */
  async verifyStored(
    id: string,
    sha256: string,
    size: number,
    hashFn: (data: Uint8Array) => Promise<string>,
  ): Promise<boolean> {
    const bytes = await this.read(id, sha256);
    if (!bytes || bytes.byteLength !== size) {
      await this.invalidate(id, sha256);
      return false;
    }
    const got = await hashFn(bytes);
    if (got !== sha256.toLowerCase()) {
      await this.invalidate(id, sha256);
      return false;
    }
    return true;
  }

  async invalidate(id: string, sha256: string): Promise<void> {
    await this.store.delete(dataKey(id, sha256));
    const m = this.meta.get(id);
    if (m && m.sha256 === sha256.toLowerCase()) this.meta.delete(id);
    await this.saveMeta();
  }

  /** Drop entries whose id is absent from keepIds, or whose hash no longer matches. */
  async prune(keep: { id: string; sha256: string }[]): Promise<string[]> {
    const keepMap = new Map(keep.map(k => [k.id, k.sha256.toLowerCase()]));
    const removed: string[] = [];
    for (const [id, m] of [...this.meta.entries()]) {
      const want = keepMap.get(id);
      if (!want || want !== m.sha256) {
        await this.store.delete(dataKey(id, m.sha256));
        this.meta.delete(id);
        removed.push(id);
      }
    }
    // orphan data keys
    for (const key of await this.store.listKeys()) {
      if (!key.startsWith(DATA_PREFIX)) continue;
      const parts = key.slice(DATA_PREFIX.length).split(':');
      const id = parts[0];
      const sha = parts.slice(1).join(':');
      const m = this.meta.get(id);
      if (!m || m.sha256 !== sha) {
        await this.store.delete(key);
        if (!removed.includes(id)) removed.push(id);
      }
    }
    await this.saveMeta();
    return removed;
  }
}

/** Best-effort OPFS-backed store. Throws if OPFS is unavailable. */
export async function openOpfsAssetStore(dirName = 'uc-assets'): Promise<AssetStore> {
  const root = await navigator.storage.getDirectory();
  const dir = await root.getDirectoryHandle(dirName, { create: true });
  return {
    async get(key) {
      try {
        const fh = await dir.getFileHandle(encodeURIComponent(key));
        return new Uint8Array(await (await fh.getFile()).arrayBuffer());
      } catch { return null; }
    },
    async put(key, data) {
      const fh = await dir.getFileHandle(encodeURIComponent(key), { create: true });
      const w = await fh.createWritable();
      await w.write(data as BufferSource);
      await w.close();
    },
    async delete(key) {
      try { await dir.removeEntry(encodeURIComponent(key)); } catch { /* absent */ }
    },
    async listKeys() {
      const keys: string[] = [];
      for await (const [name] of (dir as any).entries() as AsyncIterable<[string, FileSystemHandle]>) {
        keys.push(decodeURIComponent(name));
      }
      return keys;
    },
    async usageBytes() {
      let n = 0;
      for await (const [, h] of (dir as any).entries() as AsyncIterable<[string, FileSystemHandle]>) {
        if (h.kind === 'file') n += (await (h as FileSystemFileHandle).getFile()).size;
      }
      return n;
    },
  };
}
