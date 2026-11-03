// Strict standalone BC1/DXT1 decoder for Undercover asset previews (Phase 50).
// Independent of the inherited NFSU2 gpu/dxt.ts path; outputs RGBA8.
// D3D10 / WebGPU BC1 rules: c0 > c1 → four opaque colours; c0 <= c1 → three + transparent black.

export class Dxt1Error extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = 'Dxt1Error';
  }
}

/** 5-/6-bit channel expansion by bit replication (WebGPU bc1). */
export const C5 = new Uint8Array(32);
export const C6 = new Uint8Array(64);
for (let i = 0; i < 32; i++) C5[i] = (i << 3) | (i >> 2);
for (let i = 0; i < 64; i++) C6[i] = (i << 2) | (i >> 4);

export function dxt1MipByteLength(width: number, height: number): number {
  if (!Number.isInteger(width) || !Number.isInteger(height)) {
    throw new Dxt1Error('dimensions must be integers', 'BAD_DIM');
  }
  if (width <= 0 || height <= 0) {
    throw new Dxt1Error(`invalid dimensions ${width}x${height}`, 'BAD_DIM');
  }
  if (width > 16384 || height > 16384) {
    throw new Dxt1Error(`dimensions out of range ${width}x${height}`, 'BAD_DIM');
  }
  const bw = Math.ceil(width / 4);
  const bh = Math.ceil(height / 4);
  return bw * bh * 8;
}

export interface DecodeDxt1Options {
  width: number;
  height: number;
  /** Offset into `src` (default 0). */
  offset?: number;
  /** Exact expected payload length; defaults to dxt1MipByteLength. */
  expectedLength?: number;
  /** When true (default), reject trailing bytes past one mip. */
  rejectTrailing?: boolean;
}

export interface DecodeDxt1Result {
  width: number;
  height: number;
  /** RGBA8 tightly packed, row-major. */
  rgba: Uint8Array;
  format: 'DXT1';
  transparentModeUsed: boolean;
}

function rgb565(c: number): [number, number, number] {
  return [C5[c >> 11], C6[(c >> 5) & 63], C5[c & 31]];
}

/**
 * Decode one DXT1 mip level to RGBA8.
 * Expected length: ceil(w/4)*ceil(h/4)*8. Rejects truncated / trailing / bad dims.
 */
export function decodeDxt1(
  src: Uint8Array,
  opts: DecodeDxt1Options,
): DecodeDxt1Result {
  const { width, height } = opts;
  const offset = opts.offset ?? 0;
  const rejectTrailing = opts.rejectTrailing !== false;
  const need = opts.expectedLength ?? dxt1MipByteLength(width, height);

  if (offset < 0 || offset > src.byteLength) {
    throw new Dxt1Error(`bad offset ${offset}`, 'BAD_OFFSET');
  }
  const available = src.byteLength - offset;
  if (available < need) {
    throw new Dxt1Error(
      `truncated DXT1 payload: have ${available}, need ${need}`,
      'TRUNCATED',
    );
  }
  if (rejectTrailing && available !== need) {
    throw new Dxt1Error(
      `trailing bytes: have ${available}, expected ${need}`,
      'TRAILING',
    );
  }

  const rgba = new Uint8Array(width * height * 4);
  const bw = Math.ceil(width / 4);
  const bh = Math.ceil(height / 4);
  let transparentModeUsed = false;
  const palR = new Uint8Array(4);
  const palG = new Uint8Array(4);
  const palB = new Uint8Array(4);
  const palA = new Uint8Array(4);

  for (let by = 0; by < bh; by++) {
    for (let bx = 0; bx < bw; bx++) {
      const b = offset + (by * bw + bx) * 8;
      const c0 = src[b] | (src[b + 1] << 8);
      const c1 = src[b + 2] | (src[b + 3] << 8);
      const [r0, g0, b0] = rgb565(c0);
      const [r1, g1, b1] = rgb565(c1);
      palR[0] = r0; palG[0] = g0; palB[0] = b0; palA[0] = 255;
      palR[1] = r1; palG[1] = g1; palB[1] = b1; palA[1] = 255;
      if (c0 > c1) {
        palR[2] = (2 * r0 + r1) / 3 | 0;
        palG[2] = (2 * g0 + g1) / 3 | 0;
        palB[2] = (2 * b0 + b1) / 3 | 0;
        palA[2] = 255;
        palR[3] = (r0 + 2 * r1) / 3 | 0;
        palG[3] = (g0 + 2 * g1) / 3 | 0;
        palB[3] = (b0 + 2 * b1) / 3 | 0;
        palA[3] = 255;
      } else {
        transparentModeUsed = true;
        palR[2] = (r0 + r1) >> 1;
        palG[2] = (g0 + g1) >> 1;
        palB[2] = (b0 + b1) >> 1;
        palA[2] = 255;
        palR[3] = 0; palG[3] = 0; palB[3] = 0; palA[3] = 0;
      }
      const idx = (
        src[b + 4] | (src[b + 5] << 8) | (src[b + 6] << 16) | (src[b + 7] << 24)
      ) >>> 0;
      const ph = Math.min(4, height - by * 4);
      const pw = Math.min(4, width - bx * 4);
      for (let py = 0; py < ph; py++) {
        for (let px = 0; px < pw; px++) {
          const i = py * 4 + px;
          const code = (idx >>> (2 * i)) & 3;
          const o = ((by * 4 + py) * width + (bx * 4 + px)) * 4;
          rgba[o] = palR[code];
          rgba[o + 1] = palG[code];
          rgba[o + 2] = palB[code];
          rgba[o + 3] = palA[code];
        }
      }
    }
  }

  return { width, height, rgba, format: 'DXT1', transparentModeUsed };
}

/** Reject anything that is not explicitly DXT1 / BC1. */
export function assertDxt1Format(format: string): void {
  const f = format.trim().toUpperCase();
  if (f !== 'DXT1' && f !== 'BC1' && f !== 'BC1_UNORM' && f !== 'D3DFMT_DXT1') {
    throw new Dxt1Error(`unsupported format ${format}`, 'UNSUPPORTED_FORMAT');
  }
}
