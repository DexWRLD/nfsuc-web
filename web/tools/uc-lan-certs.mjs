#!/usr/bin/env node
// Generate a private development CA + server certificate for Undercover LAN HTTPS.
// Certs are written OUTSIDE the repository by default. Never commit private keys.
//
//   node web/tools/uc-lan-certs.mjs [--dir <out>] [--ip 192.168.x.y] [--dns hostname] [--force]
//
// Uses Git/OpenSSL when available. SAN includes localhost, 127.0.0.1, LAN IPs, optional DNS.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { networkInterfaces } from 'node:os';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../..');

function findOpenssl() {
  const candidates = [
    process.env.OPENSSL_BIN,
    'openssl',
    path.join(process.env['ProgramFiles'] || 'C:\\Program Files', 'Git', 'usr', 'bin', 'openssl.exe'),
    path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Git', 'usr', 'bin', 'openssl.exe'),
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      execFileSync(c, ['version'], { stdio: ['ignore', 'pipe', 'pipe'] });
      return c;
    } catch { /* try next */ }
  }
  return null;
}

/** Private IPv4 addresses on this host (excludes loopback / link-local APIPA). */
export function discoverLanIpv4() {
  const out = [];
  const ifs = networkInterfaces();
  for (const list of Object.values(ifs)) {
    for (const a of list || []) {
      if (a.family !== 'IPv4' && a.family !== 4) continue;
      if (a.internal) continue;
      const ip = a.address;
      if (ip.startsWith('169.254.')) continue;
      out.push(ip);
    }
  }
  return [...new Set(out)];
}

function defaultCertDir() {
  const base = process.env.UC_LAN_CERT_DIR
    || path.join(os.homedir(), '.nfsuc-web', 'lan-certs');
  return path.resolve(base);
}

function parseArgs(argv) {
  const a = { dir: defaultCertDir(), ips: [], dns: [], force: false };
  for (let i = 2; i < argv.length; i++) {
    const x = argv[i];
    if (x === '--dir') a.dir = path.resolve(argv[++i]);
    else if (x === '--ip') a.ips.push(argv[++i]);
    else if (x === '--dns') a.dns.push(argv[++i]);
    else if (x === '--force') a.force = true;
    else if (x === '-h' || x === '--help') {
      console.log(`Usage: node web/tools/uc-lan-certs.mjs [--dir DIR] [--ip IP]... [--dns NAME]... [--force]
Default dir: ${defaultCertDir()}
Discovered LAN IPs are always included.`);
      process.exit(0);
    } else throw new Error(`unknown arg ${x}`);
  }
  return a;
}

function ssl(bin, args) {
  return execFileSync(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
}

/**
 * @param {{ dir: string, ips?: string[], dns?: string[], force?: boolean }} opts
 * @returns {{ dir, ca, cert, key, caPem, spki, ips, dns }}
 */
export function makeLanCerts(opts) {
  const dir = path.resolve(opts.dir);
  // Refuse writing certs into the git repo tree.
  const repoNorm = path.resolve(REPO) + path.sep;
  if ((dir + path.sep).toLowerCase().startsWith(repoNorm.toLowerCase())) {
    throw new Error(
      `Refuse to write certificates inside the repository (${dir}). `
      + `Set UC_LAN_CERT_DIR or --dir to a path outside the repo (e.g. ~/.nfsuc-web/lan-certs).`,
    );
  }
  fs.mkdirSync(dir, { recursive: true });
  const f = n => path.join(dir, n);
  const ips = [...new Set([...(opts.ips || []), ...discoverLanIpv4(), '127.0.0.1'])];
  const dns = [...new Set([...(opts.dns || []), 'localhost', os.hostname()])];
  const need = opts.force || !fs.existsSync(f('server.crt')) || !fs.existsSync(f('server.key'));

  const openssl = findOpenssl();
  if (!openssl) {
    throw new Error(
      'openssl not found. Install Git for Windows (includes openssl) or set OPENSSL_BIN.',
    );
  }

  if (need) {
    const san = [
      ...dns.map(d => `DNS:${d}`),
      ...ips.map(ip => `IP:${ip}`),
    ].join(',');
    ssl(openssl, [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-nodes', '-keyout', f('ca.key'), '-out', f('ca.crt'),
      '-days', '825', '-subj', '/CN=NFSUC private LAN CA',
      '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
      '-addext', 'keyUsage=critical,keyCertSign',
    ]);
    fs.writeFileSync(
      f('server.ext'),
      `subjectAltName=${san}\nbasicConstraints=CA:FALSE\n`
      + 'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n',
    );
    ssl(openssl, [
      'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-nodes', '-keyout', f('server.key'), '-out', f('server.csr'),
      '-subj', `/CN=${dns[0] || 'nfsuc-lan'}`,
    ]);
    ssl(openssl, [
      'x509', '-req', '-in', f('server.csr'),
      '-CA', f('ca.crt'), '-CAkey', f('ca.key'), '-CAcreateserial',
      '-out', f('server.crt'), '-days', '825', '-extfile', f('server.ext'),
    ]);
    fs.writeFileSync(f('chain.crt'), fs.readFileSync(f('server.crt')) + fs.readFileSync(f('ca.crt')));
    fs.writeFileSync(
      f('README.txt'),
      [
        'NFSUC private LAN development certificates',
        '==========================================',
        '',
        'DO NOT commit these files. DO NOT share ca.key / server.key.',
        '',
        'On the SECOND PC (client):',
        '  1. Copy only ca.crt (the CA certificate).',
        '  2. Windows: double-click ca.crt → Install Certificate →',
        '     Local Machine → Trusted Root Certification Authorities.',
        '  3. Or for current user: Trusted Root Certification Authorities.',
        '  4. Restart the browser after trust.',
        '',
        `LAN IPs in SAN: ${ips.join(', ')}`,
        `DNS names in SAN: ${dns.join(', ')}`,
        '',
        'Regenerate: node web/tools/uc-lan-certs.mjs --force',
        '',
      ].join('\n'),
    );
  }

  const spki = (crt) => crypto.createHash('sha256')
    .update(new crypto.X509Certificate(fs.readFileSync(crt)).publicKey.export({ type: 'spki', format: 'der' }))
    .digest('base64');

  return {
    dir,
    ca: f('ca.crt'),
    cert: f('chain.crt'),
    key: f('server.key'),
    caPem: fs.readFileSync(f('ca.crt')),
    spki: [spki(f('server.crt')), spki(f('ca.crt'))],
    ips,
    dns,
    openssl,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const a = parseArgs(process.argv);
  const c = makeLanCerts(a);
  console.log(JSON.stringify({
    dir: c.dir,
    ca: c.ca,
    cert: c.cert,
    key: c.key,
    ips: c.ips,
    dns: c.dns,
    spki: c.spki,
  }, null, 2));
  console.error(`Wrote LAN certs under ${c.dir}`);
  console.error(`Trust on second PC: install ${c.ca}`);
}
