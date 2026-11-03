// Clean-PC first-launch controller for Undercover assets (Phase 47).
// Orchestrates check → download → verify → initialize bridge. Play remains
// disabled until authentic runtime readiness is established separately.

import {
  DEFAULT_MANIFEST_URL,
  type AssetManifest,
  parseManifest,
} from './uc-asset-manifest';
import { MemoryAssetStore, openOpfsAssetStore } from './uc-asset-cache';
import {
  UcDownloadManager,
  type DownloadProgress,
  type FetchFn,
  type LaunchPhase,
} from './uc-download-manager';
import { UcFilesystemBridge } from './uc-fs-bridge';
import { runClearSmoke, type ClearSmokeResult } from './uc-clear-smoke';

export interface LaunchUiState {
  phase: LaunchPhase;
  label: string;
  detail: string;
  progressPct: number;
  playEnabled: boolean;
  developmentPreview: boolean;
}

const LABELS: Record<LaunchPhase, string> = {
  idle: 'Idle',
  checking: 'Checking files',
  downloading: 'Downloading',
  verifying: 'Verifying',
  ready_to_initialize: 'Ready to initialize',
  runtime_not_playable: 'Runtime not yet playable',
  download_failed: 'Download failed',
  insufficient_storage: 'Insufficient storage',
  offline_cached: 'Offline, cached resources available',
  source_unavailable: 'Authorized game assets unavailable',
};

export function uiStateFromProgress(p: DownloadProgress, opts?: {
  developmentPreview?: boolean;
}): LaunchUiState {
  const pct = p.totalBytes > 0 ? Math.min(100, Math.round(100 * p.haveBytes / p.totalBytes)) : 0;
  return {
    phase: p.phase,
    label: LABELS[p.phase] || p.phase,
    detail: p.error || (
      p.phase === 'ready_to_initialize'
        ? 'Fixture assets ready. Authentic Undercover play requires recompiled runtime + authorized game data.'
        : p.phase === 'runtime_not_playable'
        ? 'Runtime not yet playable. Asset pipeline may be ready; game frame remains blocked.'
        : p.phase === 'source_unavailable'
          ? 'Configure a rights-authorized asset endpoint. Synthetic fixtures may still load in development.'
          : `${p.requiredReady}/${p.requiredTotal} required · ${p.haveBytes}/${p.totalBytes} bytes`
    ),
    progressPct: pct,
    // Never enable authentic Play from this controller alone.
    playEnabled: false,
    developmentPreview: !!opts?.developmentPreview,
  };
}

export interface UcLaunchOptions {
  manifestUrl?: string;
  fetch?: FetchFn;
  /** Force memory store (Node / tests). */
  memoryOnly?: boolean;
  quotaBytes?: number | null;
  pageOrigin?: string;
  onUi?: (s: LaunchUiState) => void;
  developmentPreview?: boolean;
}

export class UcLaunchController {
  manifest: AssetManifest | null = null;
  manager: UcDownloadManager | null = null;
  bridge: UcFilesystemBridge | null = null;
  lastSmoke: ClearSmokeResult | null = null;
  private opts: UcLaunchOptions;

  constructor(opts: UcLaunchOptions = {}) {
    this.opts = opts;
  }

  private emit(p: DownloadProgress) {
    this.opts.onUi?.(uiStateFromProgress(p, {
      developmentPreview: this.opts.developmentPreview,
    }));
  }

  async boot(): Promise<LaunchUiState> {
    const store = this.opts.memoryOnly
      ? new MemoryAssetStore()
      : await openOpfsAssetStore().catch(() => new MemoryAssetStore());

    this.manager = new UcDownloadManager({
      store,
      fetch: this.opts.fetch,
      quotaBytes: this.opts.quotaBytes ?? null,
      pageOrigin: this.opts.pageOrigin,
      onProgress: p => this.emit(p),
    });

    const url = this.opts.manifestUrl || DEFAULT_MANIFEST_URL;
    try {
      this.manifest = await this.manager.loadManifest(url);
    } catch (e) {
      const failed: DownloadProgress = {
        phase: 'download_failed',
        haveBytes: 0,
        totalBytes: 0,
        requiredReady: 0,
        requiredTotal: 0,
        error: e instanceof Error ? e.message : String(e),
      };
      this.emit(failed);
      return uiStateFromProgress(failed, { developmentPreview: this.opts.developmentPreview });
    }

    // If production mode is unavailable but fixtures exist, still download fixtures.
    const status = await this.manager.ensureRequired(this.manifest);
    if (status.phase === 'ready_to_initialize' || status.phase === 'runtime_not_playable'
        || status.phase === 'offline_cached') {
      this.bridge = new UcFilesystemBridge(this.manifest, this.manager);
    }
    const ui = uiStateFromProgress(status, { developmentPreview: this.opts.developmentPreview });
    this.opts.onUi?.(ui);
    return ui;
  }

  async runSyntheticClear(
    canvas: { width: number; height: number; getContext: (id: string, attrs?: object) => unknown },
  ): Promise<ClearSmokeResult> {
    this.lastSmoke = runClearSmoke(canvas);
    return this.lastSmoke;
  }
}

export function parseManifestJson(text: string): AssetManifest {
  return parseManifest(JSON.parse(text));
}
