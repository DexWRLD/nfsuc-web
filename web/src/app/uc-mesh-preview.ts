// Minimal diagnostic mesh preview (Phase 50). Browser-owned camera/shader.
// Does not use opaque draw backends. Not original material parity.

import type { ValidatedMesh } from './uc-mesh-validate';

export interface MeshPreviewResult {
  ok: boolean;
  api: 'webgl' | 'none';
  detail: string;
  vertexCount: number;
  indexCount: number;
  synthetic: boolean;
}

function compile(gl: WebGLRenderingContext, type: number, src: string): WebGLShader {
  const s = gl.createShader(type);
  if (!s) throw new Error('createShader failed');
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(s) || 'compile error';
    gl.deleteShader(s);
    throw new Error(log);
  }
  return s;
}

/**
 * Draw a validated mesh that has float3 position at attributes[0] offset on stream 0.
 * Uses a flat diagnostic color. Camera is a simple orthographic fit.
 */
export function drawValidatedMesh(
  canvas: HTMLCanvasElement,
  mesh: ValidatedMesh,
  opts?: { synthetic?: boolean; color?: [number, number, number, number] },
): MeshPreviewResult {
  const synthetic = opts?.synthetic !== false;
  const gl = canvas.getContext('webgl', { alpha: false, antialias: true }) as WebGLRenderingContext | null;
  if (!gl) {
    return {
      ok: false, api: 'none', detail: 'WebGL unavailable',
      vertexCount: mesh.contract.vertexCount,
      indexCount: mesh.contract.indexCount,
      synthetic,
    };
  }

  const posAttr = mesh.contract.attributes.find(
    a => a.semantic.toLowerCase() === 'position' && a.stream === 0,
  );
  if (!posAttr || !/float3/i.test(posAttr.encoding)) {
    return {
      ok: false, api: 'webgl',
      detail: 'preview requires stream-0 float3 position',
      vertexCount: mesh.contract.vertexCount,
      indexCount: mesh.contract.indexCount,
      synthetic,
    };
  }

  const stride = mesh.strides[0];
  const vboData = mesh.verticesByStream[0];
  const positions = new Float32Array(mesh.contract.vertexCount * 3);
  for (let i = 0; i < mesh.contract.vertexCount; i++) {
    const o = i * stride + posAttr.offset;
    const view = new DataView(vboData.buffer, vboData.byteOffset + o, 12);
    positions[i * 3] = view.getFloat32(0, true);
    positions[i * 3 + 1] = view.getFloat32(4, true);
    positions[i * 3 + 2] = view.getFloat32(8, true);
  }

  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (let i = 0; i < mesh.contract.vertexCount; i++) {
    const x = positions[i * 3], y = positions[i * 3 + 1];
    if (x < minX) minX = x; if (x > maxX) maxX = x;
    if (y < minY) minY = y; if (y > maxY) maxY = y;
  }
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  const span = Math.max(maxX - minX, maxY - minY, 1e-3) * 0.6;

  canvas.width = canvas.width || 160;
  canvas.height = canvas.height || 120;
  gl.viewport(0, 0, canvas.width, canvas.height);
  gl.clearColor(0.08, 0.09, 0.12, 1);
  gl.clear(gl.COLOR_BUFFER_BIT);
  gl.disable(gl.DEPTH_TEST);

  const vs = compile(gl, gl.VERTEX_SHADER, `
    attribute vec3 a_pos;
    uniform vec2 u_center;
    uniform float u_scale;
    void main() {
      vec2 p = (a_pos.xy - u_center) / u_scale;
      gl_Position = vec4(p, 0.0, 1.0);
    }
  `);
  const fs = compile(gl, gl.FRAGMENT_SHADER, `
    precision mediump float;
    uniform vec4 u_color;
    void main() { gl_FragColor = u_color; }
  `);
  const prog = gl.createProgram();
  if (!prog) throw new Error('createProgram failed');
  gl.attachShader(prog, vs);
  gl.attachShader(prog, fs);
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
    throw new Error(gl.getProgramInfoLog(prog) || 'link error');
  }
  gl.useProgram(prog);

  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, positions, gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, 'a_pos');
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 3, gl.FLOAT, false, 0, 0);

  const ibo = gl.createBuffer();
  gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, ibo);
  gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, mesh.indices, gl.STATIC_DRAW);

  gl.uniform2f(gl.getUniformLocation(prog, 'u_center'), cx, cy);
  gl.uniform1f(gl.getUniformLocation(prog, 'u_scale'), span);
  const color = opts?.color ?? (synthetic ? [0.2, 0.75, 0.55, 1] : [0.9, 0.55, 0.2, 1]);
  gl.uniform4f(gl.getUniformLocation(prog, 'u_color'), color[0], color[1], color[2], color[3]);

  gl.drawElements(gl.TRIANGLES, mesh.indices.length, gl.UNSIGNED_SHORT, 0);

  return {
    ok: true,
    api: 'webgl',
    detail: `drew ${mesh.indices.length / 3} triangles (${synthetic ? 'synthetic' : 'verified-source'})`,
    vertexCount: mesh.contract.vertexCount,
    indexCount: mesh.contract.indexCount,
    synthetic,
  };
}

/** Build a unit synthetic triangle mesh payload for tests / smoke. */
export function makeSyntheticTriangle(): {
  vertices: Uint8Array;
  indices: Uint8Array;
  contract: import('./uc-mesh-validate').MeshContract;
} {
  const vertices = new ArrayBuffer(3 * 12);
  const dv = new DataView(vertices);
  // three float3 positions
  const pts = [[-0.8, -0.7, 0], [0.8, -0.7, 0], [0, 0.85, 0]];
  pts.forEach((p, i) => {
    dv.setFloat32(i * 12, p[0], true);
    dv.setFloat32(i * 12 + 4, p[1], true);
    dv.setFloat32(i * 12 + 8, p[2], true);
  });
  const indices = new Uint8Array(new Uint16Array([0, 1, 2]).buffer);
  return {
    vertices: new Uint8Array(vertices),
    indices,
    contract: {
      provenance: {
        resourceId: 'synthetic.triangle',
        sourceFilename: 'synthetic-triangle.bin',
        sourceSha256: '0'.repeat(64),
        evidenceRef: 'phase50-synthetic',
        sourceCategory: 'synthetic-fixture',
      },
      topology: 'triangle-list',
      indexWidth: 16,
      indexByteOrder: 'little-endian',
      indexCount: 3,
      vertexCount: 3,
      streams: [{ stride: 12, vertexBytes: 36, vertexCount: 3 }],
      attributes: [
        { stream: 0, semantic: 'position', offset: 0, encoding: 'float3', usageIndex: 0 },
      ],
    },
  };
}
