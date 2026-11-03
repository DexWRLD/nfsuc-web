// Manifest-driven Undercover DXT1 texture preview (Phase 50).
// Distinct from authentic game-frame rendering.

import { decodeDxt1, Dxt1Error } from './uc-dxt1';
import {
  extractVerifiedPayload,
  isAuthenticCategory,
  parseTextureProvenance,
  type TextureProvenance,
  TextureProvenanceError,
} from './uc-texture-manifest';

export type TexturePreviewState =
  | 'NO_RESOURCE'
  | 'SOURCE_UNVERIFIED'
  | 'DOWNLOADING'
  | 'HASH_VERIFYING'
  | 'DECODING'
  | 'PREVIEW_SYNTHETIC'
  | 'PREVIEW_AUTHENTIC_VERIFIED'
  | 'UNSUPPORTED_FORMAT'
  | 'FAILED';

export interface TexturePreviewResult {
  state: TexturePreviewState;
  detail: string;
  provenance: TextureProvenance | null;
  width: number;
  height: number;
  rgba: Uint8Array | null;
  authentic: boolean;
}

function paintCheckerboard(
  ctx: CanvasRenderingContext2D,
  w: number,
  h: number,
  cell = 8,
): void {
  for (let y = 0; y < h; y += cell) {
    for (let x = 0; x < w; x += cell) {
      const on = ((x / cell) ^ (y / cell)) & 1;
      ctx.fillStyle = on ? '#c8c8c8' : '#8f8f8f';
      ctx.fillRect(x, y, cell, cell);
    }
  }
}

/** Draw RGBA8 onto a canvas with checkerboard under transparent texels. */
export function presentRgbaToCanvas(
  canvas: HTMLCanvasElement,
  rgba: Uint8Array,
  width: number,
  height: number,
  scale = 4,
): void {
  const tw = Math.max(1, Math.floor(width * scale));
  const th = Math.max(1, Math.floor(height * scale));
  canvas.width = tw;
  canvas.height = th;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('2d context unavailable');
  paintCheckerboard(ctx, tw, th, Math.max(4, Math.floor(4 * scale)));
  const img = document.createElement('canvas');
  img.width = width;
  img.height = height;
  const ictx = img.getContext('2d');
  if (!ictx) throw new Error('2d context unavailable');
  const imageData = ictx.createImageData(width, height);
  imageData.data.set(rgba);
  ictx.putImageData(imageData, 0, 0);
  ctx.imageSmoothingEnabled = false;
  ctx.drawImage(img, 0, 0, tw, th);
}

export async function decodeProvenanceTexture(
  sourceBytes: Uint8Array,
  provenanceRaw: unknown,
): Promise<TexturePreviewResult> {
  let provenance: TextureProvenance;
  try {
    provenance = parseTextureProvenance(provenanceRaw);
  } catch (e) {
    const code = e instanceof TextureProvenanceError ? e.code : 'FAILED';
    const state: TexturePreviewState =
      code === 'SOURCE_UNVERIFIED' ? 'SOURCE_UNVERIFIED'
        : code === 'UNSUPPORTED_FORMAT' ? 'UNSUPPORTED_FORMAT'
          : code === 'MISSING_PROVENANCE' ? 'NO_RESOURCE'
            : 'FAILED';
    return {
      state,
      detail: e instanceof Error ? e.message : String(e),
      provenance: null,
      width: 0,
      height: 0,
      rgba: null,
      authentic: false,
    };
  }

  try {
    // HASH_VERIFYING
    const payload = await extractVerifiedPayload(sourceBytes, provenance);
    const decoded = decodeDxt1(payload, {
      width: provenance.width,
      height: provenance.height,
    });
    const authentic = isAuthenticCategory(provenance.sourceCategory);
    return {
      state: authentic ? 'PREVIEW_AUTHENTIC_VERIFIED' : 'PREVIEW_SYNTHETIC',
      detail: authentic
        ? `Authentic verified DXT1 ${provenance.width}x${provenance.height} (${provenance.resourceId})`
        : `Synthetic DXT1 ${provenance.width}x${provenance.height} (${provenance.resourceId})`,
      provenance,
      width: decoded.width,
      height: decoded.height,
      rgba: decoded.rgba,
      authentic,
    };
  } catch (e) {
    if (e instanceof Dxt1Error && e.code === 'UNSUPPORTED_FORMAT') {
      return {
        state: 'UNSUPPORTED_FORMAT',
        detail: e.message,
        provenance,
        width: provenance.width,
        height: provenance.height,
        rgba: null,
        authentic: false,
      };
    }
    return {
      state: 'FAILED',
      detail: e instanceof Error ? e.message : String(e),
      provenance,
      width: provenance.width,
      height: provenance.height,
      rgba: null,
      authentic: false,
    };
  }
}

export interface TexturePreviewUi {
  state: TexturePreviewState;
  meta: string;
  note: string;
}

export function texturePreviewUi(r: TexturePreviewResult): TexturePreviewUi {
  const p = r.provenance;
  const meta = p
    ? [
      `id=${p.resourceId}`,
      `format=${p.format}`,
      `${p.width}x${p.height}`,
      `mip=${p.mipLevel}`,
      `kind=${p.textureKind}`,
      `category=${p.sourceCategory}`,
      `evidence=${p.evidenceRef}`,
      `source=${p.sourceFilename}`,
      `offset=${p.sourceByteOffset}`,
      `len=${p.sourceByteLength}`,
      `payloadSha256=${p.payloadSha256.slice(0, 12)}…`,
    ].join(' · ')
    : r.detail;
  const note = r.authentic
    ? 'AUTHENTIC texture preview — not an Undercover gameplay frame. FIRST_FRAME still blocked.'
    : 'SYNTHETIC / non-authentic texture preview — not Undercover gameplay.';
  return { state: r.state, meta, note };
}
