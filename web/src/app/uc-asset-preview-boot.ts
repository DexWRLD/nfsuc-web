// Wire Phase 50 texture + mesh diagnostic previews into the start page.

import {
  decodeProvenanceTexture,
  presentRgbaToCanvas,
  texturePreviewUi,
} from './uc-texture-preview';
import { makeSyntheticTriangle, drawValidatedMesh } from './uc-mesh-preview';
import { validateMeshPayloads } from './uc-mesh-validate';

function $(sel: string): HTMLElement | null {
  return document.querySelector(sel);
}

export async function bootUcAssetPreviews(log: (line: string) => void): Promise<void> {
  const texPanel = $('#uc-texture-preview');
  if (texPanel) {
    const status = $('#uc-tex-status');
    const meta = $('#uc-tex-meta');
    const note = $('#uc-tex-note');
    const canvas = $('#uc-tex-canvas') as HTMLCanvasElement | null;
    try {
      if (status) status.textContent = 'DECODING';
      const [bytes, provText] = await Promise.all([
        fetch('/uc-fixtures/textures/solid-red-4x4.dxt1').then(r => {
          if (!r.ok) throw new Error(`texture HTTP ${r.status}`);
          return r.arrayBuffer();
        }),
        fetch('/uc-fixtures/textures/solid-red-4x4.dxt1.provenance.json').then(r => {
          if (!r.ok) throw new Error(`provenance HTTP ${r.status}`);
          return r.json();
        }),
      ]);
      const result = await decodeProvenanceTexture(new Uint8Array(bytes), provText);
      const ui = texturePreviewUi(result);
      if (status) status.textContent = ui.state;
      if (meta) meta.textContent = ui.meta;
      if (note) {
        note.hidden = false;
        note.textContent = ui.note;
      }
      if (canvas && result.rgba) {
        canvas.hidden = false;
        presentRgbaToCanvas(canvas, result.rgba, result.width, result.height, 16);
      }
      log(`[uc-tex] ${result.state} ${result.detail}`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (status) status.textContent = 'FAILED';
      if (meta) meta.textContent = msg;
      log(`[uc-tex] failed: ${msg}`);
    }
  }

  const meshPanel = $('#uc-mesh-preview');
  if (meshPanel) {
    const status = $('#uc-mesh-status');
    const note = $('#uc-mesh-note');
    const canvas = $('#uc-mesh-canvas') as HTMLCanvasElement | null;
    try {
      const tri = makeSyntheticTriangle();
      const validated = validateMeshPayloads(tri.contract, [tri.vertices], tri.indices);
      if (canvas) {
        canvas.hidden = false;
        const drawn = drawValidatedMesh(canvas, validated, { synthetic: true });
        if (status) status.textContent = drawn.ok ? 'SYNTHETIC_MESH_OK' : 'FAILED';
        if (note) {
          note.hidden = false;
          note.textContent = (
            `${drawn.detail}. XP_SMOKEBALL_CURL/PUFF remain unresolved — `
            + 'no verified source spans. Not authentic gameplay.'
          );
        }
        log(`[uc-mesh] ${drawn.detail}`);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (status) status.textContent = 'FAILED';
      if (note) { note.hidden = false; note.textContent = msg; }
      log(`[uc-mesh] failed: ${msg}`);
    }
  }
}
