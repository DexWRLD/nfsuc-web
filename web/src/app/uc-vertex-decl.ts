// Verified vertex-declaration conversion from Ghidra 0x0073F300 (Phase 50).
// Observed lookup tables at 0x00CF0E6C / 0x00CF0E98 / 0x00CF0E20 only.
// Pure helper — does not invent complete Undercover vertex formats.

export class VertexDeclError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = 'VertexDeclError';
  }
}

/** DWORD usage table @ 0x00CF0E6C (evidence JSON). */
export const USAGE_TABLE = Object.freeze([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11,
] as const);

/** D3DDECLTYPE-shaped table @ 0x00CF0E98. */
export const TYPE_TABLE = Object.freeze([
  0, 1, 2, 3, 4, 15, 16, 17, 9, 10, 9, 10, 9, 10, 17, 5, 8, 17, 17,
] as const);

/** Element byte-width table @ 0x00CF0E20. */
export const WIDTH_TABLE = Object.freeze([
  4, 8, 12, 16, 4, 4, 8, 4, 4, 8, 4, 8, 4, 8, 4, 4, 4, 1, 0,
] as const);

/** Terminator written by 0x0073F300: FF 00 00 00 11 00 00 00 */
export const DECL_TERMINATOR = Object.freeze(
  [0xFF, 0, 0, 0, 0x11, 0, 0, 0] as const,
);

export interface DeclInputRecord {
  stream: number;
  usageLookup: number;
  typeLookup: number;
  usageIndex: number;
}

export interface DeclOutputElement {
  stream: number;
  offset: number;
  type: number;
  method: number;
  usage: number;
  usageIndex: number;
}

export interface ConvertDeclResult {
  elements: DeclOutputElement[];
  strides: [number, number, number];
  raw: Uint8Array;
}

/**
 * Convert a 0x50-byte descriptor (count at +0x40, records at +0) into D3D-shaped
 * 8-byte elements. Streams must be 0..2. Strides accumulate per stream.
 */
export function convertVertexDeclaration(descriptor: Uint8Array): ConvertDeclResult {
  if (descriptor.byteLength < 0x50) {
    throw new VertexDeclError(
      `descriptor must be at least 0x50 bytes, got ${descriptor.byteLength}`,
      'BAD_DESCRIPTOR',
    );
  }
  const count = descriptor[0x40] | (descriptor[0x41] << 8)
    | (descriptor[0x42] << 16) | (descriptor[0x43] << 24);
  if (!Number.isFinite(count) || count < 0 || count > 64) {
    throw new VertexDeclError(`malformed record count ${count}`, 'BAD_COUNT');
  }
  if (count * 4 > 0x40) {
    throw new VertexDeclError('records overflow descriptor header', 'BAD_COUNT');
  }

  const offsets = [0, 0, 0];
  const elements: DeclOutputElement[] = [];
  const rawParts: number[] = [];

  for (let i = 0; i < count; i++) {
    const base = i * 4;
    const stream = descriptor[base];
    const usageLookup = descriptor[base + 1];
    const typeLookup = descriptor[base + 2];
    const usageIndex = descriptor[base + 3];

    if (stream > 2) {
      throw new VertexDeclError(`invalid stream number ${stream}`, 'BAD_STREAM');
    }
    if (usageLookup >= USAGE_TABLE.length) {
      throw new VertexDeclError(`invalid usage lookup ${usageLookup}`, 'BAD_USAGE_IDX');
    }
    if (typeLookup >= TYPE_TABLE.length || typeLookup >= WIDTH_TABLE.length) {
      throw new VertexDeclError(`invalid type lookup ${typeLookup}`, 'BAD_TYPE_IDX');
    }
    const width = WIDTH_TABLE[typeLookup];
    if (width <= 0) {
      throw new VertexDeclError(
        `unsupported attribute encoding width 0 at typeLookup ${typeLookup}`,
        'UNSUPPORTED_ENCODING',
      );
    }
    const usage = USAGE_TABLE[usageLookup];
    const type = TYPE_TABLE[typeLookup];
    const offset = offsets[stream];
    elements.push({
      stream, offset, type, method: 0, usage, usageIndex,
    });
    rawParts.push(
      stream & 0xff, (stream >> 8) & 0xff,
      offset & 0xff, (offset >> 8) & 0xff,
      type & 0xff, 0, usage & 0xff, usageIndex & 0xff,
    );
    offsets[stream] += width;
  }

  rawParts.push(...DECL_TERMINATOR);
  const raw = new Uint8Array(rawParts);
  return {
    elements,
    strides: [offsets[0], offsets[1], offsets[2]],
    raw,
  };
}

/** Build a minimal 0x50 descriptor for tests. */
export function buildDescriptor(records: DeclInputRecord[]): Uint8Array {
  if (records.length * 4 > 0x40) {
    throw new VertexDeclError('too many records', 'BAD_COUNT');
  }
  const out = new Uint8Array(0x50);
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    out[i * 4] = r.stream;
    out[i * 4 + 1] = r.usageLookup;
    out[i * 4 + 2] = r.typeLookup;
    out[i * 4 + 3] = r.usageIndex;
  }
  out[0x40] = records.length & 0xff;
  out[0x41] = (records.length >> 8) & 0xff;
  out[0x42] = (records.length >> 16) & 0xff;
  out[0x43] = (records.length >> 24) & 0xff;
  return out;
}

/** D3DDECLUSAGE_POSITION = 0 in observed usage table index 0. */
export function hasPositionAttribute(elements: DeclOutputElement[]): boolean {
  return elements.some(e => e.usage === 0);
}
