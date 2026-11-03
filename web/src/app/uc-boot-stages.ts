// Explicit Undercover clean-PC boot state machine (Phase 49).
// BOOT → MANIFEST → CACHE_CHECK → DOWNLOAD → VERIFY → FS_MOUNT → RUNTIME_INIT → READY_OR_BLOCKED

export type BootStage =
  | 'BOOT'
  | 'MANIFEST'
  | 'CACHE_CHECK'
  | 'DOWNLOAD'
  | 'VERIFY'
  | 'FS_MOUNT'
  | 'RUNTIME_INIT'
  | 'READY_OR_BLOCKED'
  | 'ERROR';

export interface BootStageEvent {
  stage: BootStage;
  ok: boolean;
  detail: string;
  at: number;
}

export interface SecureContextReport {
  isSecureContext: boolean;
  protocol: string;
  hostname: string;
  opfsLikely: boolean;
  message: string | null;
}

/** Detect insecure origins that cannot offer OPFS (LAN HTTP, etc.). */
export function reportSecureContext(
  loc: { protocol: string; hostname: string; origin?: string } | undefined,
  opts?: { hasStorageGetDirectory?: boolean },
): SecureContextReport {
  const protocol = loc?.protocol || 'unknown:';
  const hostname = loc?.hostname || '';
  const isSecure =
    protocol === 'https:'
    || hostname === 'localhost'
    || hostname === '127.0.0.1'
    || hostname === '[::1]';
  const opfsLikely = isSecure && (opts?.hasStorageGetDirectory !== false);
  let message: string | null = null;
  if (!isSecure) {
    message = (
      'Insecure origin: OPFS persistent cache requires HTTPS (or localhost). '
      + 'Use Start-UndercoverLAN.ps1 / uc-lan-server.mjs so the second PC opens an https:// LAN URL. '
      + 'Falling back to in-memory storage (cleared when the tab closes).'
    );
  }
  return { isSecureContext: isSecure, protocol, hostname, opfsLikely, message };
}

export class BootStageTracker {
  readonly history: BootStageEvent[] = [];
  stage: BootStage = 'BOOT';

  enter(stage: BootStage, detail: string, ok = true): BootStageEvent {
    this.stage = stage;
    const ev: BootStageEvent = { stage, ok, detail, at: Date.now() };
    this.history.push(ev);
    return ev;
  }

  fail(detail: string): BootStageEvent {
    return this.enter('ERROR', detail, false);
  }

  snapshot() {
    return {
      stage: this.stage,
      history: this.history.slice(),
    };
  }
}
