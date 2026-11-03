// Independent Undercover startup asset preview (Phase 51 addendum).
// Sequence LOGO → OPTIONAL_VIDEO → MENU_PLACEHOLDER is a browser preview
// contract, not verified original boot order.
// Authentic images require digest-verified provenance; never invent offsets.

export type StartupPreviewState =
  | 'IDLE'
  | 'LOADING_LOGO'
  | 'SHOWING_LOGO'
  | 'LOGO_MISSING'
  | 'LOADING_VIDEO'
  | 'SHOWING_VIDEO'
  | 'VIDEO_UNAVAILABLE'
  | 'VIDEO_FAILED'
  | 'SKIPPED'
  | 'MENU_PLACEHOLDER'
  | 'CACHE_MISMATCH'
  | 'FAILED'
  | 'COMPLETE';

export type StartupAssetKind = 'synthetic' | 'authentic-verified';

export interface StartupImageProvenance {
  resourceId: string;
  originalName: string;
  sourceRelativePath: string;
  sourceSha256: string;
  payloadSha256: string;
  sourceByteOffset: number;
  sourceByteLength: number;
  mediaFormat: 'image/jpeg' | 'image/png' | 'image/webp';
  width: number;
  height: number;
  sourceCategory: 'synthetic-fixture' | 'authorized-verified';
  evidenceRef: string;
  /** Explicit disclaimer when not the FNG/BUN boot logo. */
  identityNote: string;
  kind: StartupAssetKind;
}

export interface StartupVideoLead {
  relativePath: string;
  size: number;
  sha256: string;
  containerLead: 'vp6-extension';
  browserNative: false;
  decoderAvailable: false;
  note: string;
}

export interface StartupPreviewOptions {
  logo?: StartupImageProvenance | null;
  logoBytes?: Uint8Array | null;
  videoLead?: StartupVideoLead | null;
  /** Prefer skipping video stage. */
  skipVideo?: boolean;
  onState?: (s: StartupPreviewState, detail: string) => void;
  /** Test hook: inject async completion after dispose. */
  ignoreStale?: boolean;
}

export interface StartupPreviewSnapshot {
  state: StartupPreviewState;
  detail: string;
  logoAuthentic: boolean;
  logoIdentity: string | null;
  videoAvailable: boolean;
  sequence: StartupPreviewState[];
  statuses: {
    AUTHENTIC_STARTUP_ASSET_PREVIEW: 'READY' | 'SYNTHETIC' | 'BLOCKED' | 'FAILED';
    AUTHENTIC_INTRO_VIDEO_PREVIEW: 'BLOCKED' | 'IDENTIFIED_NO_DECODER';
    FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND: 'BLOCKED';
  };
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export class StartupPreviewController {
  state: StartupPreviewState = 'IDLE';
  detail = '';
  sequence: StartupPreviewState[] = [];
  private generation = 0;
  private opts: StartupPreviewOptions;
  logoObjectUrl: string | null = null;
  disposed = false;

  constructor(opts: StartupPreviewOptions = {}) {
    this.opts = opts;
  }

  private set(state: StartupPreviewState, detail: string) {
    this.state = state;
    this.detail = detail;
    this.sequence.push(state);
    this.opts.onState?.(state, detail);
  }

  dispose() {
    this.disposed = true;
    this.generation++;
    if (this.logoObjectUrl) {
      URL.revokeObjectURL(this.logoObjectUrl);
      this.logoObjectUrl = null;
    }
  }

  skip() {
    this.set('SKIPPED', 'user skip');
    this.set('MENU_PLACEHOLDER', 'skipped to menu placeholder');
    this.set('COMPLETE', 'preview sequence complete (skipped)');
  }

  snapshot(): StartupPreviewSnapshot {
    const logo = this.opts.logo;
    const authentic = !!(logo && logo.sourceCategory === 'authorized-verified'
      && logo.kind === 'authentic-verified'
      && (this.state === 'SHOWING_LOGO' || this.sequence.includes('SHOWING_LOGO')));
    const video = this.opts.videoLead;
    return {
      state: this.state,
      detail: this.detail,
      logoAuthentic: authentic,
      logoIdentity: logo ? `${logo.originalName} (${logo.sourceRelativePath})` : null,
      videoAvailable: !!video,
      sequence: this.sequence.slice(),
      statuses: {
        AUTHENTIC_STARTUP_ASSET_PREVIEW: authentic
          ? 'READY'
          : logo?.sourceCategory === 'synthetic-fixture'
            ? 'SYNTHETIC'
            : this.state === 'FAILED' || this.state === 'LOGO_MISSING'
              ? 'FAILED'
              : 'BLOCKED',
        AUTHENTIC_INTRO_VIDEO_PREVIEW: video
          ? 'IDENTIFIED_NO_DECODER'
          : 'BLOCKED',
        FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND: 'BLOCKED',
      },
    };
  }

  async run(): Promise<StartupPreviewSnapshot> {
    const gen = ++this.generation;
    const stale = () => this.disposed || gen !== this.generation;

    this.set('LOADING_LOGO', 'resolving logo provenance');
    const logo = this.opts.logo;
    const bytes = this.opts.logoBytes;

    if (!logo || !bytes) {
      this.set('LOGO_MISSING', 'no logo resource configured');
      this.set('MENU_PLACEHOLDER', 'continuing without logo');
      this.set('COMPLETE', 'preview complete without logo');
      return this.snapshot();
    }

    try {
      if (bytes.byteLength !== logo.sourceByteLength) {
        this.set('CACHE_MISMATCH', `byte length ${bytes.byteLength} != ${logo.sourceByteLength}`);
        return this.snapshot();
      }
      if (stale()) {
        this.set('FAILED', 'stale async completion ignored');
        return this.snapshot();
      }
      if (logo.sourceByteOffset !== 0) {
        this.set('FAILED', 'embedded spans require extractVerifiedPayload (not whole-file)');
        return this.snapshot();
      }
      const hash = await sha256Hex(bytes);
      if (stale()) {
        this.set('FAILED', 'stale async completion ignored');
        return this.snapshot();
      }
      if (hash !== logo.payloadSha256 || hash !== logo.sourceSha256) {
        this.set('CACHE_MISMATCH', `sha256 mismatch got ${hash}`);
        return this.snapshot();
      }

      const blob = new Blob([bytes.slice()], { type: logo.mediaFormat });
      this.logoObjectUrl = URL.createObjectURL(blob);
      this.set(
        'SHOWING_LOGO',
        `${logo.kind}: ${logo.originalName} · ${logo.width}x${logo.height} · ${logo.identityNote}`,
      );
    } catch (e) {
      this.set('FAILED', e instanceof Error ? e.message : String(e));
      return this.snapshot();
    }

    if (this.opts.skipVideo) {
      this.set('SKIPPED', 'video stage skipped by option');
    } else if (!this.opts.videoLead) {
      this.set('VIDEO_UNAVAILABLE', 'no verified movie lead configured');
    } else {
      this.set('LOADING_VIDEO', this.opts.videoLead.relativePath);
      // VP6 identified but no decoder — do not speculate.
      this.set(
        'VIDEO_UNAVAILABLE',
        `${this.opts.videoLead.relativePath}: ${this.opts.videoLead.note}`,
      );
    }

    this.set('MENU_PLACEHOLDER', 'FeMainMenu.fng lead unresolved — placeholder only');
    this.set('COMPLETE', 'startup preview sequence finished');
    return this.snapshot();
  }
}

/** Present logo blob URL onto an img element preserving aspect ratio. */
export function presentStartupLogo(
  img: HTMLImageElement,
  objectUrl: string,
  provenance: StartupImageProvenance,
): void {
  img.src = objectUrl;
  img.alt = `${provenance.originalName} (${provenance.kind})`;
  img.style.objectFit = 'contain';
  img.style.width = '100%';
  img.style.height = '100%';
  img.dataset.resourceId = provenance.resourceId;
  img.dataset.kind = provenance.kind;
}
