// Phase 50: strict Undercover BC1/DXT1 decoder + provenance + vertex/mesh contracts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as esbuild from 'esbuild';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const FIX = path.join(HERE, '../src/static/uc-fixtures/textures');

async function load() {
  const built = await esbuild.build({
    stdin: {
      contents: `
        export * from './web/src/app/uc-dxt1.ts';
        export * from './web/src/app/uc-texture-manifest.ts';
        export * from './web/src/app/uc-texture-preview.ts';
        export * from './web/src/app/uc-vertex-decl.ts';
        export * from './web/src/app/uc-mesh-validate.ts';
        export { makeSyntheticTriangle, drawValidatedMesh } from './web/src/app/uc-mesh-preview.ts';
      `,
      resolveDir: ROOT,
      loader: 'ts',
    },
    bundle: true,
    format: 'esm',
    write: false,
    platform: 'neutral',
  });
  const out = path.join(HERE, `uc-dxt1-bundle-${process.pid}.mjs`);
  fs.writeFileSync(out, built.outputFiles[0].text);
  const mod = await import(pathToFileURL(out).href);
  return { mod, out };
}

const { mod, out: bundleOut } = await load();
const {
  decodeDxt1, dxt1MipByteLength, Dxt1Error, assertDxt1Format,
  parseTextureProvenance, extractVerifiedPayload, TextureProvenanceError,
  decodeProvenanceTexture,
  convertVertexDeclaration, buildDescriptor, USAGE_TABLE, DECL_TERMINATOR, VertexDeclError,
  validateMeshPayloads, MeshValidationError,
  makeSyntheticTriangle,
} = mod;

const hex = s => Uint8Array.from(s.split(/\s+/).filter(Boolean).map(x => parseInt(x, 16)));
const rgbaAt = (rgba, i) => [rgba[i * 4], rgba[i * 4 + 1], rgba[i * 4 + 2], rgba[i * 4 + 3]];

test('solid-color block', () => {
  // c0=c1=red F800, all indices 0
  const r = decodeDxt1(hex('00 F8 00 F8 00 00 00 00'), { width: 4, height: 4 });
  assert.deepEqual(rgbaAt(r.rgba, 0), [255, 0, 0, 255]);
  assert.deepEqual(rgbaAt(r.rgba, 15), [255, 0, 0, 255]);
});

test('four-color interpolation', () => {
  const r = decodeDxt1(hex('00 F8 1F 00 E4 00 00 00'), { width: 4, height: 4 });
  assert.deepEqual(rgbaAt(r.rgba, 0), [255, 0, 0, 255]);
  assert.deepEqual(rgbaAt(r.rgba, 1), [0, 0, 255, 255]);
  assert.deepEqual(rgbaAt(r.rgba, 2), [170, 0, 85, 255]);
  assert.deepEqual(rgbaAt(r.rgba, 3), [85, 0, 170, 255]);
  assert.equal(r.transparentModeUsed, false);
});

test('transparent BC1 mode', () => {
  const r = decodeDxt1(hex('1F 00 00 F8 E4 00 00 00'), { width: 4, height: 4 });
  assert.deepEqual(rgbaAt(r.rgba, 3), [0, 0, 0, 0]);
  assert.equal(r.transparentModeUsed, true);
});

test('multiple blocks 8x8', () => {
  const block = hex('E0 07 E0 07 00 00 00 00');
  const src = new Uint8Array(32);
  for (let i = 0; i < 4; i++) src.set(block, i * 8);
  const r = decodeDxt1(src, { width: 8, height: 8 });
  assert.equal(r.rgba.length, 8 * 8 * 4);
  assert.deepEqual(rgbaAt(r.rgba, 0), [0, 255, 0, 255]);
});

test('non-multiple-of-four dimensions 6x6', () => {
  const solid = c => {
    const b = new Uint8Array(8);
    b[0] = c & 255; b[1] = c >> 8; b[2] = c & 255; b[3] = c >> 8;
    return b;
  };
  const src = new Uint8Array(4 * 8);
  src.set(solid(0xF800), 0);
  src.set(solid(0x07E0), 8);
  src.set(solid(0x001F), 16);
  src.set(solid(0x8410), 24);
  const r = decodeDxt1(src, { width: 6, height: 6 });
  assert.equal(r.rgba.length, 36 * 4);
  assert.deepEqual(rgbaAt(r.rgba, 0), [255, 0, 0, 255]);
  assert.deepEqual(rgbaAt(r.rgba, 5), [0, 255, 0, 255]); // x=5,y=0
});

test('truncated block rejected', () => {
  assert.throws(
    () => decodeDxt1(hex('00 F8 00 F8 00 00 00'), { width: 4, height: 4 }),
    e => e instanceof Dxt1Error && e.code === 'TRUNCATED',
  );
});

test('trailing bytes rejected', () => {
  const src = hex('00 F8 00 F8 00 00 00 00 FF');
  assert.throws(
    () => decodeDxt1(src, { width: 4, height: 4 }),
    e => e instanceof Dxt1Error && e.code === 'TRAILING',
  );
});

test('zero dimensions rejected', () => {
  assert.throws(() => dxt1MipByteLength(0, 4), e => e.code === 'BAD_DIM');
  assert.throws(() => dxt1MipByteLength(4, 0), e => e.code === 'BAD_DIM');
});

test('unsupported format', () => {
  assert.throws(() => assertDxt1Format('DXT5'), e => e.code === 'UNSUPPORTED_FORMAT');
});

test('invalid payload metadata via provenance length mismatch', () => {
  assert.throws(() => parseTextureProvenance({
    resourceId: 'x', sourceFilename: 'x', sourceSha256: '0'.repeat(64),
    sourceByteOffset: 0, sourceByteLength: 7, payloadSha256: '1'.repeat(64),
    width: 4, height: 4, format: 'DXT1', mipLevel: 0, textureKind: '2d',
    byteOrder: 'little-endian', blockLayout: 'dxt1-4x4-8bytes',
    evidenceRef: 't', sourceCategory: 'synthetic-fixture',
  }), e => e instanceof TextureProvenanceError && e.code === 'SIZE_MISMATCH');
});

test('fixture solid-red provenance decode is PREVIEW_SYNTHETIC', async () => {
  const bytes = fs.readFileSync(path.join(FIX, 'solid-red-4x4.dxt1'));
  const prov = JSON.parse(fs.readFileSync(path.join(FIX, 'solid-red-4x4.dxt1.provenance.json'), 'utf8'));
  const r = await decodeProvenanceTexture(bytes, prov);
  assert.equal(r.state, 'PREVIEW_SYNTHETIC');
  assert.equal(r.authentic, false);
  assert.deepEqual(rgbaAt(r.rgba, 0), [255, 0, 0, 255]);
});

test('unverified category rejected', () => {
  assert.throws(() => parseTextureProvenance({
    resourceId: 'x', sourceFilename: 'x', sourceSha256: '0'.repeat(64),
    sourceByteOffset: 0, sourceByteLength: 8, payloadSha256: '1'.repeat(64),
    width: 4, height: 4, format: 'DXT1', mipLevel: 0, textureKind: '2d',
    byteOrder: 'little-endian', blockLayout: 'dxt1-4x4-8bytes',
    evidenceRef: 't', sourceCategory: 'unverified',
  }), e => e.code === 'SOURCE_UNVERIFIED');
});

test('vertex decl: single stream position float3', () => {
  // usageLookup 0 → usage 0 (position); typeLookup 2 → type 2 width 12 (float3)
  const desc = buildDescriptor([
    { stream: 0, usageLookup: 0, typeLookup: 2, usageIndex: 0 },
  ]);
  const r = convertVertexDeclaration(desc);
  assert.equal(r.elements.length, 1);
  assert.equal(r.elements[0].offset, 0);
  assert.equal(r.elements[0].usage, USAGE_TABLE[0]);
  assert.equal(r.strides[0], 12);
  assert.deepEqual([...r.raw.slice(-8)], [...DECL_TERMINATOR]);
});

test('vertex decl: multiple streams accumulate offsets', () => {
  const desc = buildDescriptor([
    { stream: 0, usageLookup: 0, typeLookup: 2, usageIndex: 0 }, // pos 12
    { stream: 0, usageLookup: 5, typeLookup: 1, usageIndex: 0 }, // tex 8 (type 1 width 8)
    { stream: 1, usageLookup: 3, typeLookup: 0, usageIndex: 0 }, // normal? width 4
  ]);
  const r = convertVertexDeclaration(desc);
  assert.equal(r.strides[0], 20);
  assert.equal(r.strides[1], 4);
  assert.equal(r.elements[1].offset, 12);
});

test('vertex decl rejects bad stream / lookup / width 0', () => {
  assert.throws(
    () => convertVertexDeclaration(buildDescriptor([
      { stream: 3, usageLookup: 0, typeLookup: 0, usageIndex: 0 },
    ])),
    e => e instanceof VertexDeclError && e.code === 'BAD_STREAM',
  );
  assert.throws(
    () => convertVertexDeclaration(buildDescriptor([
      { stream: 0, usageLookup: 99, typeLookup: 0, usageIndex: 0 },
    ])),
    e => e.code === 'BAD_USAGE_IDX',
  );
  // typeLookup 18 → width 0
  assert.throws(
    () => convertVertexDeclaration(buildDescriptor([
      { stream: 0, usageLookup: 0, typeLookup: 18, usageIndex: 0 },
    ])),
    e => e.code === 'UNSUPPORTED_ENCODING',
  );
});

test('mesh: valid synthetic triangle', () => {
  const t = makeSyntheticTriangle();
  const v = validateMeshPayloads(t.contract, [t.vertices], t.indices);
  assert.equal(v.indices.length, 3);
  assert.equal(v.contract.vertexCount, 3);
});

test('mesh: out-of-range index', () => {
  const t = makeSyntheticTriangle();
  const bad = new Uint8Array(new Uint16Array([0, 1, 9]).buffer);
  assert.throws(
    () => validateMeshPayloads(t.contract, [t.vertices], bad),
    e => e instanceof MeshValidationError && e.code === 'INDEX_OOR',
  );
});

test('mesh: invalid stride / missing position / bad size', () => {
  const t = makeSyntheticTriangle();
  assert.throws(() => validateMeshPayloads({
    ...t.contract,
    streams: [{ stride: 0, vertexBytes: 0, vertexCount: 3 }],
  }, [t.vertices], t.indices), e => e.code === 'BAD_STRIDE');

  assert.throws(() => validateMeshPayloads({
    ...t.contract,
    attributes: [{ stream: 0, semantic: 'texcoord', offset: 0, encoding: 'float2', usageIndex: 0 }],
  }, [t.vertices], t.indices), e => e.code === 'MISSING_POSITION');

  assert.throws(() => validateMeshPayloads(t.contract, [t.vertices.subarray(0, 12)], t.indices),
    e => e.code === 'BAD_VERTEX_SIZE' || e.code === 'VERTEX_OOB');
});

test('mesh: unsupported encoding', () => {
  const t = makeSyntheticTriangle();
  assert.throws(() => validateMeshPayloads({
    ...t.contract,
    attributes: [{ stream: 0, semantic: 'position', offset: 0, encoding: 'half4', usageIndex: 0 }],
  }, [t.vertices], t.indices), e => e.code === 'UNSUPPORTED_ENCODING');
});

test('authentic preview state unreachable without authorized-verified category', async () => {
  const bytes = fs.readFileSync(path.join(FIX, 'solid-red-4x4.dxt1'));
  const prov = JSON.parse(fs.readFileSync(path.join(FIX, 'solid-red-4x4.dxt1.provenance.json'), 'utf8'));
  prov.sourceCategory = 'authorized-verified';
  // digests still match — would be PREVIEW_AUTHENTIC_VERIFIED if authorized
  const r = await decodeProvenanceTexture(bytes, prov);
  assert.equal(r.state, 'PREVIEW_AUTHENTIC_VERIFIED');
  // But no real Undercover payload is shipped; this only proves the state machine.
});

try { fs.unlinkSync(bundleOut); } catch { /* */ }
