// Strict mesh input contract for Undercover browser geometry previews (Phase 50).
// Runtime layout evidence: 0x00782570 / stream S fields. Named XP_SMOKEBALL_*
// remain unavailable until source spans + matching declaration are verified.

import {
  convertVertexDeclaration,
  hasPositionAttribute,
  type DeclOutputElement,
  VertexDeclError,
} from './uc-vertex-decl';

export class MeshValidationError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = 'MeshValidationError';
  }
}

export type MeshSourceCategory =
  | 'synthetic-fixture'
  | 'authorized-verified'
  | 'unverified'
  | 'named-unresolved';

export interface MeshProvenance {
  resourceId: string;
  sourceFilename: string;
  sourceSha256: string;
  evidenceRef: string;
  sourceCategory: MeshSourceCategory;
  /** Named candidates from 0x00782A50 — informational until spans verified. */
  namedCandidate?: string;
}

export interface MeshStreamSpec {
  stride: number;
  vertexBytes: number;
  vertexCount: number;
  /** Optional starting element (S+0x74); byte offset = start * stride. */
  startElement?: number;
}

export interface MeshAttribute {
  stream: number;
  semantic: string;
  offset: number;
  encoding: string;
  usageIndex: number;
}

export interface MeshContract {
  provenance: MeshProvenance;
  topology: 'triangle-list';
  indexWidth: 16;
  indexByteOrder: 'little-endian';
  indexCount: number;
  vertexCount: number;
  streams: MeshStreamSpec[];
  attributes: MeshAttribute[];
  /** Optional 0x50 descriptor bytes for conversion check. */
  descriptor?: Uint8Array;
}

export interface ValidatedMesh {
  contract: MeshContract;
  elements: DeclOutputElement[] | null;
  strides: number[];
  indices: Uint16Array;
  verticesByStream: Uint8Array[];
}

function requireProv(p: MeshProvenance): void {
  if (!p.resourceId || !p.sourceFilename || !p.sourceSha256 || !p.evidenceRef) {
    throw new MeshValidationError('missing mesh provenance fields', 'MISSING_PROVENANCE');
  }
  if (p.sourceCategory === 'unverified' || p.sourceCategory === 'named-unresolved') {
    throw new MeshValidationError(
      `mesh sourceCategory ${p.sourceCategory} is not previewable`,
      'SOURCE_UNVERIFIED',
    );
  }
  if (!/^[0-9a-f]{64}$/i.test(p.sourceSha256)) {
    throw new MeshValidationError('bad sourceSha256', 'BAD_DIGEST');
  }
}

export function validateMeshPayloads(
  contract: MeshContract,
  verticesByStream: Uint8Array[],
  indexBytes: Uint8Array,
): ValidatedMesh {
  requireProv(contract.provenance);
  if (contract.topology !== 'triangle-list') {
    throw new MeshValidationError('only triangle-list supported', 'BAD_TOPOLOGY');
  }
  if (contract.indexWidth !== 16 || contract.indexByteOrder !== 'little-endian') {
    throw new MeshValidationError('indices must be u16 LE', 'BAD_INDEX_FMT');
  }
  if (contract.indexCount <= 0 || contract.indexCount % 3 !== 0) {
    throw new MeshValidationError(
      `indexCount ${contract.indexCount} must be >0 and divisible by 3`,
      'BAD_INDEX_COUNT',
    );
  }
  if (contract.vertexCount <= 0) {
    throw new MeshValidationError('vertexCount must be >0', 'BAD_VERTEX_COUNT');
  }
  if (!contract.streams.length) {
    throw new MeshValidationError('no streams', 'BAD_STREAM');
  }
  if (verticesByStream.length !== contract.streams.length) {
    throw new MeshValidationError('stream buffer count mismatch', 'BAD_STREAM');
  }

  const strides: number[] = [];
  for (let i = 0; i < contract.streams.length; i++) {
    const s = contract.streams[i];
    if (!Number.isInteger(s.stride) || s.stride <= 0 || (s.stride & 0x7FFF) !== s.stride) {
      throw new MeshValidationError(`invalid stride ${s.stride}`, 'BAD_STRIDE');
    }
    if (s.vertexBytes !== s.stride * s.vertexCount) {
      throw new MeshValidationError(
        `stream ${i} vertexBytes ${s.vertexBytes} != stride*count`,
        'BAD_VERTEX_SIZE',
      );
    }
    if (s.vertexCount !== contract.vertexCount) {
      // Allow per-stream count only if equal for Phase 50 simple preview.
      throw new MeshValidationError('per-stream vertexCount must match mesh', 'BAD_VERTEX_COUNT');
    }
    const buf = verticesByStream[i];
    const start = (s.startElement ?? 0) * s.stride;
    if (start + s.vertexBytes > buf.byteLength) {
      throw new MeshValidationError(`stream ${i} payload out of bounds`, 'VERTEX_OOB');
    }
    if (buf.byteLength < s.vertexBytes) {
      throw new MeshValidationError(`stream ${i} buffer too small`, 'BAD_VERTEX_SIZE');
    }
    strides.push(s.stride);
  }

  const needIdx = contract.indexCount * 2;
  if (indexBytes.byteLength !== needIdx) {
    throw new MeshValidationError(
      `index bytes ${indexBytes.byteLength} != ${needIdx}`,
      'BAD_INDEX_SIZE',
    );
  }
  const indices = new Uint16Array(
    indexBytes.buffer,
    indexBytes.byteOffset,
    contract.indexCount,
  );
  for (let i = 0; i < indices.length; i++) {
    if (indices[i] >= contract.vertexCount) {
      throw new MeshValidationError(
        `index ${indices[i]} out of range (vertexCount ${contract.vertexCount})`,
        'INDEX_OOR',
      );
    }
  }

  let elements: DeclOutputElement[] | null = null;
  if (contract.descriptor) {
    try {
      const conv = convertVertexDeclaration(contract.descriptor);
      elements = conv.elements;
      for (let s = 0; s < 3; s++) {
        if (conv.strides[s] && strides[s] != null && conv.strides[s] > strides[s]) {
          throw new MeshValidationError(
            `attribute extent ${conv.strides[s]} exceeds stride ${strides[s]} on stream ${s}`,
            'ATTR_PAST_STRIDE',
          );
        }
      }
    } catch (e) {
      if (e instanceof VertexDeclError) {
        throw new MeshValidationError(e.message, e.code);
      }
      throw e;
    }
  }

  const hasPos = contract.attributes.some(a =>
    a.semantic.toLowerCase() === 'position' || a.semantic.toLowerCase() === 'positiont')
    || (elements != null && hasPositionAttribute(elements));
  if (!hasPos) {
    throw new MeshValidationError('missing position attribute', 'MISSING_POSITION');
  }

  for (const a of contract.attributes) {
    if (a.stream < 0 || a.stream >= contract.streams.length) {
      throw new MeshValidationError(`bad attribute stream ${a.stream}`, 'BAD_STREAM');
    }
    const stride = contract.streams[a.stream].stride;
    // Minimal encoding size heuristic for known float3
    const enc = a.encoding.toLowerCase();
    let width = 0;
    if (enc === 'float3' || enc === 'r32g32b32_float') width = 12;
    else if (enc === 'float2' || enc === 'r32g32_float') width = 8;
    else if (enc === 'float4' || enc === 'r32g32b32a32_float') width = 16;
    else if (enc === 'ubyte4n' || enc === 'd3dcolor') width = 4;
    else {
      throw new MeshValidationError(
        `unsupported attribute encoding ${a.encoding}`,
        'UNSUPPORTED_ENCODING',
      );
    }
    if (a.offset < 0 || a.offset + width > stride) {
      throw new MeshValidationError(
        `attribute ${a.semantic} extends beyond stride`,
        'ATTR_PAST_STRIDE',
      );
    }
  }

  return {
    contract,
    elements,
    strides,
    indices: indices.slice(),
    verticesByStream: verticesByStream.map((b, i) => {
      const s = contract.streams[i];
      const start = (s.startElement ?? 0) * s.stride;
      return b.subarray(start, start + s.vertexBytes).slice();
    }),
  };
}
