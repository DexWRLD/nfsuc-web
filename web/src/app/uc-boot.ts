// Wire Undercover clean-PC asset boot into the start page (Phase 47/48).

import { UcLaunchController, type LaunchUiState } from './uc-launch';

function $(sel: string): HTMLElement | null {
  return document.querySelector(sel);
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function applyUi(s: LaunchUiState, haveBytes?: number, totalBytes?: number): void {
  const status = $('#uc-asset-status');
  const detail = $('#uc-asset-detail');
  const bar = $('#uc-asset-progress');
  const fill = $('#uc-asset-progress-fill');
  const bytes = $('#uc-asset-bytes');
  const retry = $('#uc-asset-retry') as HTMLButtonElement | null;
  const cancel = $('#uc-asset-cancel') as HTMLButtonElement | null;
  if (status) status.textContent = s.label;
  if (detail) detail.textContent = s.detail;
  if (bar) bar.setAttribute('aria-valuenow', String(s.progressPct));
  if (fill) (fill as HTMLElement).style.width = `${s.progressPct}%`;
  if (bytes && totalBytes != null && haveBytes != null) {
    bytes.textContent = `${fmtBytes(haveBytes)} / ${fmtBytes(totalBytes)} · ${s.progressPct}%`;
  }
  if (retry) {
    retry.hidden = !(s.phase === 'download_failed' || s.phase === 'insufficient_storage'
      || s.phase === 'source_unavailable');
  }
  if (cancel) {
    cancel.hidden = !(s.phase === 'downloading' || s.phase === 'verifying' || s.phase === 'checking');
  }
}

/** Start fixture download + optional synthetic clear smoke. Never enables authentic Play. */
export async function bootUcAssets(log: (line: string) => void): Promise<UcLaunchController | null> {
  const panel = $('#uc-assets');
  if (!panel) return null;

  let ctl: UcLaunchController | null = null;

  const run = async () => {
    ctl = new UcLaunchController({
      developmentPreview: true,
      pageOrigin: typeof location !== 'undefined' ? location.origin : undefined,
      onUi: s => applyUi(s),
    });
    try {
      const ui = await ctl.boot();
      const st = ctl.manager?.status;
      applyUi(ui, st?.haveBytes, st?.totalBytes);
      log(`[uc-assets] phase=${ui.phase} ${ui.detail}`);

      const canvas = $('#uc-clear-smoke') as HTMLCanvasElement | null;
      const note = $('#uc-clear-smoke-note');
      if (canvas && (ui.phase === 'ready_to_initialize' || ui.phase === 'runtime_not_playable'
          || ui.phase === 'offline_cached')) {
        canvas.hidden = false;
        const smoke = await ctl.runSyntheticClear(canvas);
        if (note) {
          note.hidden = false;
          note.textContent = (
            `Development graphics smoke (${smoke.api}): ${smoke.commands.join(' → ')}. `
            + `SYNTHETIC — not Undercover gameplay. ${smoke.firstFrameStatus}.`
          );
        }
        log(`[uc-assets] clear-smoke api=${smoke.api} cleared=${smoke.cleared}`);
      }
      return ctl;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      applyUi({
        phase: 'download_failed',
        label: 'Download failed',
        detail: msg,
        progressPct: 0,
        playEnabled: false,
        developmentPreview: true,
      });
      log(`[uc-assets] failed: ${msg}`);
      return ctl;
    }
  };

  const retryBtn = $('#uc-asset-retry');
  const cancelBtn = $('#uc-asset-cancel');
  if (retryBtn) retryBtn.onclick = () => { void run(); };
  if (cancelBtn) {
    cancelBtn.onclick = () => {
      ctl?.manager?.cancel();
      log('[uc-assets] cancel requested');
    };
  }

  return run();
}
