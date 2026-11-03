// Strict authentic/synthetic texture provenance for Undercover (Phase 50).
// A resource is NEVER "authentic" without verified source digests + byte span.

import { assertDxt1Format, dxt1MipByteLength, Dxt1Error } from './uc-dxt1';

export type TextureSourceCategory =
  | 'synthetic-fixture'
  | 'authorized-verified'
  | 'unverified'
  | 'copyrighted-unavailable';

export type TextureKind = '2d' | 'cube' | 'unknown';

export interface TextureProvenance {
  resourceId: string;
  sourceFilename: string;
  sourceArtifactId?: string;
  sourceSha256: string;
  sourceByteOffset: number;
  sourceByteLength: number;
  payloadSha256: string;
  width: number;
  height: number;
  format: string;
  mipLevel: number;
  textureKind: TextureKind;
  byteOrder: 'little-endian';
  blockLayout: 'dxt1-4x4-8bytes';
  evidenceRef: string;
  sourceCategory: TextureSourceCategory;
  note?: string;
}

export class TextureProvenanceError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = 'TextureProvenanceError';
  }
}

const HEX64 = /^[0-9a-f]{64}$/i;

export function parseTextureProvenance(raw: unknown): TextureProvenance {
  if (!raw || typeof raw !== 'object') {
    throw new TextureProvenanceError('provenance must be an object', 'SCHEMA');
  }
  const o = raw as Record<string, unknown>;
  const req = (k: string): unknown => {
    if (!(k in o) || o[k] === undefined || o[k] === null || o[k] === '') {
      throw new TextureProvenanceError(`missing ${k}`, 'MISSING_PROVENANCE');
    }
    return o[k];
  };
  const resourceId = String(req('resourceId'));
  const sourceFilename = String(req('sourceFilename'));
  const sourceSha256 = String(req('sourceSha256')).toLowerCase();
  const payloadSha256 = String(req('payloadSha256')).toLowerCase();
  if (!HEX64.test(sourceSha256) || !HEX64.test(payloadSha256)) {
    throw new TextureProvenanceError('digests must be sha256 hex', 'BAD_DIGEST');
  }
  const sourceByteOffset = Number(req('sourceByteOffset'));
  const sourceByteLength = Number(req('sourceByteLength'));
  const width = Number(req('width'));
  const height = Number(req('height'));
  const mipLevel = Number(req('mipLevel'));
  const format = String(req('format'));
  const textureKind = String(req('textureKind')) as TextureKind;
  const byteOrder = String(req('byteOrder'));
  const blockLayout = String(req('blockLayout'));
  const evidenceRef = String(req('evidenceRef'));
  const sourceCategory = String(req('sourceCategory')) as TextureSourceCategory;

  if (!Number.isInteger(sourceByteOffset) || sourceByteOffset < 0) {
    throw new TextureProvenanceError('invalid sourceByteOffset', 'BAD_OFFSET');
  }
  if (!Number.isInteger(sourceByteLength) || sourceByteLength <= 0) {
    throw new TextureProvenanceError('invalid sourceByteLength', 'BAD_LENGTH');
  }
  if (!Number.isInteger(mipLevel) || mipLevel < 0) {
    throw new TextureProvenanceError('invalid mipLevel', 'BAD_MIP');
  }
  if (byteOrder !== 'little-endian') {
    throw new TextureProvenanceError('byteOrder must be little-endian', 'BAD_ORDER');
  }
  if (blockLayout !== 'dxt1-4x4-8bytes') {
    throw new TextureProvenanceError('unsupported blockLayout', 'BAD_LAYOUT');
  }
  if (textureKind !== '2d' && textureKind !== 'cube' && textureKind !== 'unknown') {
    throw new TextureProvenanceError(`unknown textureKind ${textureKind}`, 'BAD_KIND');
  }
  if (textureKind === 'unknown') {
    throw new TextureProvenanceError('textureKind unknown rejected', 'BAD_KIND');
  }
  if (textureKind === 'cube') {
    // Cube path exists at 0x007513E2 (CreateCubeTexture); single-face preview not yet contracted.
    throw new TextureProvenanceError(
      'cube textures not supported by Phase 50 single-level 2D preview',
      'UNSUPPORTED_KIND',
    );
  }
  const allowedCat: TextureSourceCategory[] = [
    'synthetic-fixture', 'authorized-verified', 'unverified', 'copyrighted-unavailable',
  ];
  if (!allowedCat.includes(sourceCategory)) {
    throw new TextureProvenanceError(`bad sourceCategory ${sourceCategory}`, 'BAD_CATEGORY');
  }
  if (sourceCategory === 'copyrighted-unavailable') {
    throw new TextureProvenanceError('copyrighted-unavailable refused', 'UNAVAILABLE');
  }
  if (sourceCategory === 'unverified') {
    throw new TextureProvenanceError(
      'sourceCategory unverified — refuse authentic decode path',
      'SOURCE_UNVERIFIED',
    );
  }

  try {
    assertDxt1Format(format);
  } catch (e) {
    if (e instanceof Dxt1Error) {
      throw new TextureProvenanceError(e.message, 'UNSUPPORTED_FORMAT');
    }
    throw e;
  }

  let expected: number;
  try {
    expected = dxt1MipByteLength(width, height);
  } catch (e) {
    if (e instanceof Dxt1Error) {
      throw new TextureProvenanceError(e.message, e.code);
    }
    throw e;
  }
  if (sourceByteLength !== expected) {
    throw new TextureProvenanceError(
      `payload length ${sourceByteLength} != DXT1 mip size ${expected}`,
      'SIZE_MISMATCH',
    );
  }

  return {
    resourceId,
    sourceFilename,
    sourceArtifactId: o.sourceArtifactId != null ? String(o.sourceArtifactId) : undefined,
    sourceSha256,
    sourceByteOffset,
    sourceByteLength,
    payloadSha256,
    width,
    height,
    format,
    mipLevel,
    textureKind,
    byteOrder: 'little-endian',
    blockLayout: 'dxt1-4x4-8bytes',
    evidenceRef,
    sourceCategory,
    note: o.note != null ? String(o.note) : undefined,
  };
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Extract and verify payload bytes against provenance digests. */
export async function extractVerifiedPayload(
  sourceBytes: Uint8Array,
  prov: TextureProvenance,
): Promise<Uint8Array> {
  const srcHash = await sha256Hex(sourceBytes);
  if (srcHash !== prov.sourceSha256) {
    throw new TextureProvenanceError(
      `source sha256 mismatch: got ${srcHash}`,
      'SOURCE_HASH_MISMATCH',
    );
  }
  const end = prov.sourceByteOffset + prov.sourceByteLength;
  if (end > sourceBytes.byteLength) {
    throw new TextureProvenanceError('source span out of bounds', 'BAD_OFFSET');
  }
  const payload = sourceBytes.subarray(prov.sourceByteOffset, end);
  const payHash = await sha256Hex(payload);
  if (payHash !== prov.payloadSha256) {
    throw new TextureProvenanceError(
      `payload sha256 mismatch: got ${payHash}`,
      'PAYLOAD_HASH_MISMATCH',
    );
  }
  return payload.slice();
}

export function isAuthenticCategory(c: TextureSourceCategory): boolean {
  return c === 'authorized-verified';
}
