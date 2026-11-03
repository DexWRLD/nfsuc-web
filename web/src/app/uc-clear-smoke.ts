// Synthetic browser clear-only frame smoke test (Phase 47).
// Mirrors the verified D3D9 sequence shape BeginScene → Clear → EndScene → Present
// at 0x00725313 → 0x0072532F → 0x0072533F → 0x00725350, but this is NOT authentic
// Undercover rendering and must not change FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND.

export const CLEAR_SMOKE_CLASSIFICATION = 'SYNTHETIC_BROWSER_CLEAR_ONLY';
export const FIRST_FRAME_STATUS = 'FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND';

export interface ClearSmokeResult {
  classification: typeof CLEAR_SMOKE_CLASSIFICATION;
  firstFrameStatus: typeof FIRST_FRAME_STATUS;
  api: 'canvas2d' | 'webgl' | 'none';
  cleared: boolean;
  width: number;
  height: number;
  commands: string[];
  note: string;
}

/**
 * Clear a canvas to black and present (browser composite). Prefer WebGL clear
 * when available; otherwise Canvas2D fillRect(0,0,0,1).
 */
export function runClearSmoke(
  canvas: { width: number; height: number; getContext: (id: string, attrs?: object) => unknown },
): ClearSmokeResult {
  const commands: string[] = [];
  const base = {
    classification: CLEAR_SMOKE_CLASSIFICATION,
    firstFrameStatus: FIRST_FRAME_STATUS,
    width: canvas.width,
    height: canvas.height,
    note: (
      'Synthetic clear-only present. Not authentic Undercover geometry, shaders, '
      + 'or protected draw handoffs (0x006860F0 / 0x00686290).'
    ),
  } as const;

  // WebGL path
  try {
    const gl = canvas.getContext('webgl', { alpha: false, antialias: false }) as WebGLRenderingContext | null;
    if (gl) {
      commands.push('BeginScene');
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clearColor(0, 0, 0, 1);
      gl.clearDepth(1);
      gl.clearStencil(0);
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT | gl.STENCIL_BUFFER_BIT);
      commands.push('Clear(flags=7,color=0,z=1,stencil=0)');
      commands.push('EndScene');
      commands.push('Present');
      return { ...base, api: 'webgl', cleared: true, commands: [...commands] };
    }
  } catch { /* fall through */ }

  // Canvas2D fallback
  try {
    const ctx = canvas.getContext('2d') as CanvasRenderingContext2D | null;
    if (ctx) {
      commands.push('BeginScene');
      ctx.save();
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.restore();
      commands.push('Clear(flags=7,color=0,z=1,stencil=0)');
      commands.push('EndScene');
      commands.push('Present');
      return { ...base, api: 'canvas2d', cleared: true, commands: [...commands] };
    }
  } catch { /* fall through */ }

  return {
    ...base,
    api: 'none',
    cleared: false,
    commands: ['BeginScene', 'Clear-failed', 'EndScene', 'Present-skipped'],
  };
}

/** Pure command-sequence oracle used by Node tests (no DOM). */
export function clearOnlyCommandSequence(): string[] {
  return [
    'BeginScene',
    'Clear(flags=7,color=0,z=1,stencil=0)',
    'EndScene',
    'Present',
  ];
}
