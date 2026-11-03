// Wire Undercover clean-PC asset boot into the start page (Phase 47).

import { UcLaunchController, type LaunchUiState } from './uc-launch';

function $(sel: string): HTMLElement | null {
  return document.querySelector(sel);
}

function applyUi(s: LaunchUiState): void {
  const status = $('#uc-asset-status');
  const detail = $('#uc-asset-detail');
  const bar = $('#uc-asset-progress');
  const fill = $('#uc-asset-progress-fill');
  if (status) status.textContent = s.label;
  if (detail) detail.textContent = s.detail;
  if (bar) bar.setAttribute('aria-valuenow', String(s.progressPct));
  if (fill) (fill as HTMLElement).style.width = `${s.progressPct}%`;
}

/** Start fixture download + optional synthetic clear smoke. Never enables authentic Play. */
export async function bootUcAssets(log: (line: string) => void): Promise<UcLaunchController | null> {
  const panel = $('#uc-assets');
  if (!panel) return null;

  const ctl = new UcLaunchController({
    developmentPreview: true,
    onUi: applyUi,
  });

  try {
    const ui = await ctl.boot();
    log(`[uc-assets] phase=${ui.phase} ${ui.detail}`);
    applyUi(ui);

    const canvas = $('#uc-clear-smoke') as HTMLCanvasElement | null;
    const note = $('#uc-clear-smoke-note');
    if (canvas && (ui.phase === 'ready_to_initialize' || ui.phase === 'runtime_not_playable'
        || ui.phase === 'offline_cached')) {
      canvas.hidden = false;
      const smoke = await ctl.runSyntheticClear(canvas);
      if (note) {
        note.hidden = false;
        note.textContent = (
          `Synthetic clear smoke (${smoke.api}): ${smoke.commands.join(' → ')}. `
          + `${smoke.firstFrameStatus}. Not authentic Undercover rendering.`
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
}
