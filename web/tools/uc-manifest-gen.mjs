#!/usr/bin/env node
// Generate a versioned Undercover asset manifest from a curated allowlist.
// Scans ONLY paths listed in --allowlist (JSON array of relative paths), never
// a whole game install directory. Computes SHA-256 and sizes.
//
//   node web/tools/uc-manifest-gen.mjs \
//     --root <UC_ASSET_ROOT> \
//     --allowlist allowlist.json \
//     --out manifest.json \
//     [--base-url /uc-assets/] \
//     [--authorized]
//
// allowlist.json example:
//   [{ "id": "startup.readme", "path": "startup/readme.txt", "license": "synthetic-fixture", "required": true }]
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

function sha256File(p) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(p));
  return h.digest('hex');
}

function parseArgs(argv) {
  const a = {
    root: '',
    allowlist: '',
    out: '',
    baseUrl: '/uc-assets/',
    authorized: false,
    version: 1,
  };
  for (let i = 2; i < argv.length; i++) {
    const x = argv[i];
    if (x === '--root') a.root = path.resolve(argv[++i]);
    else if (x === '--allowlist') a.allowlist = path.resolve(argv[++i]);
    else if (x === '--out') a.out = path.resolve(argv[++i]);
    else if (x === '--base-url') a.baseUrl = argv[++i];
    else if (x === '--authorized') a.authorized = true;
    else if (x === '--version') a.version = Number(argv[++i]);
    else if (x === '-h' || x === '--help') {
      console.log('See header comment in uc-manifest-gen.mjs');
      process.exit(0);
    } else throw new Error(`unknown arg ${x}`);
  }
  if (!a.root || !a.allowlist || !a.out) {
    throw new Error('--root, --allowlist, and --out are required');
  }
  return a;
}

function assertSafeRel(rel) {
  const n = String(rel).replace(/\\/g, '/');
  if (!n || n.startsWith('/') || n.includes('\0') || n.split('/').some(p => p === '..' || p === '')) {
    throw new Error(`unsafe path in allowlist: ${rel}`);
  }
  return n;
}

export function generateManifest({ root, allowlist, baseUrl, authorized, version }) {
  const items = JSON.parse(fs.readFileSync(allowlist, 'utf8'));
  if (!Array.isArray(items)) throw new Error('allowlist must be a JSON array');

  const seenId = new Set();
  const seenPath = new Set();
  const assets = [];
  let totalBytes = 0;

  for (const it of items) {
    const id = String(it.id || '').trim();
    const rel = assertSafeRel(it.path || it.url);
    if (!id) throw new Error(`missing id for ${rel}`);
    if (seenId.has(id)) throw new Error(`duplicate id ${id}`);
    if (seenPath.has(rel)) throw new Error(`duplicate path ${rel}`);
    seenId.add(id);
    seenPath.add(rel);

    const full = path.resolve(root, rel);
    const rootN = path.resolve(root) + path.sep;
    if (!full.startsWith(rootN) && full !== path.resolve(root)) {
      throw new Error(`path escapes root: ${rel}`);
    }
    // Reject symlink escape
    const real = fs.realpathSync(full);
    const realRoot = fs.realpathSync(root);
    if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
      throw new Error(`symlink escape: ${rel}`);
    }
    const st = fs.statSync(real);
    if (!st.isFile()) throw new Error(`not a file: ${rel}`);

    const license = it.license || (authorized ? 'copyrighted-authorized-private' : 'synthetic-fixture');
    if (license === 'copyrighted-unavailable') {
      throw new Error(`refuse to publish copyrighted-unavailable entry ${id}`);
    }
    if (!authorized && /copyrighted/i.test(license) && license !== 'synthetic-fixture') {
      throw new Error(`pass --authorized to include license ${license} for ${id}`);
    }

    const sha = sha256File(real);
    const size = st.size;
    totalBytes += size;
    assets.push({
      id,
      path: rel,
      url: rel,
      size,
      sha256: sha,
      contentType: it.contentType || 'application/octet-stream',
      category: it.category || 'curated',
      required: it.required !== false,
      license,
    });
  }

  return {
    manifestVersion: version,
    game: 'NFS_UNDERCOVER_PC',
    toolingOrigin: 'NFSU2-WEB',
    targetSha256: '6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd',
    source: {
      mode: authorized ? 'authorized' : 'fixtures',
      baseUrl: baseUrl.endsWith('/') ? baseUrl : baseUrl + '/',
      productionAssetsAuthorized: !!authorized,
      note: authorized
        ? 'Private LAN transfer of user-authorized curated assets only. Not a public mirror.'
        : 'Curated fixtures / non-production assets.',
      totalDownloadBytes: totalBytes,
    },
    assets,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const a = parseArgs(process.argv);
  const m = generateManifest(a);
  fs.mkdirSync(path.dirname(a.out), { recursive: true });
  fs.writeFileSync(a.out, JSON.stringify(m, null, 2) + '\n');
  console.log(JSON.stringify({
    out: a.out,
    assets: m.assets.length,
    totalDownloadBytes: m.source.totalDownloadBytes,
    productionAssetsAuthorized: m.source.productionAssetsAuthorized,
  }, null, 2));
}
