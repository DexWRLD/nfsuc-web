import './app/undercover-home.css';
import { runFrontendFrame, runBootCallbacks, runFrontendQueue, runFrontendLookup, runAptDiagnostic, runUndercoverInitializer } from './app/uc-browser-init';
import { bootUcAssets } from './app/uc-boot';
import { bootUcAssetPreviews } from './app/uc-asset-preview-boot';
import { bootUcStartupPreview } from './app/uc-startup-boot';

const play = document.querySelector<HTMLButtonElement>('#play-preview')!;
const content = document.querySelector<HTMLElement>('#preview-content')!;
play.addEventListener('click', () => {
  if (content.hidden) {
    content.hidden = false;
    play.setAttribute('aria-expanded', 'true');
    const log = (message: string) => console.info(message);
    void bootUcAssets(log).catch(log);
    void bootUcAssetPreviews(log).catch(log);
    void bootUcStartupPreview(log).catch(log);
  }
  document.querySelector('#preview')?.scrollIntoView({ block: 'start' });
});

void fetch('/uc-project-evidence.json').then(async response => {
  if (!response.ok) return;
  const evidence = await response.json();
  document.querySelector('#compile-metric')!.textContent =
    `${evidence.compiled.toLocaleString()} / ${evidence.targets.toLocaleString()} high-confidence targets`;
  document.querySelector('#guest-metric')!.textContent =
    `${evidence.unique} unique functions · ${evidence.enterable} enterable · ${evidence.runs} recorded runs`;
}).catch(() => {});

const runInit = document.querySelector<HTMLButtonElement>('#run-guest-init')!;
const initResult = document.querySelector<HTMLElement>('#guest-init-result')!;
const initTrace = document.querySelector<HTMLElement>('#guest-init-trace')!;
runInit.addEventListener('click', async () => {
  runInit.disabled = true;
  initTrace.textContent = '';
  try {
    const trace = await runUndercoverInitializer();
    initResult.textContent = 'Initializer completed. Historical Apt fixture failed its empty-stack precondition.';
    const hex = (value: number) => '0x' + value.toString(16).toUpperCase().padStart(8, '0');
    initTrace.textContent = [
      'Initializer ' + hex(trace.entry) + ' · ' + trace.writes + ' writes',
      hex(trace.slot) + ' → ' + hex(trace.after),
      'Verified return ESP ' + hex(trace.esp),
      'Entered in order: ' + trace.prefix.entered.map(hex).join(', '),
      'Last dispatch: 0x009E4B32 → 0x009E78C0 (diagnostic callback)',
      'Last successful instruction: 0x009E4B46 · backing pointer ' + hex(trace.prefix.backingPointer),
      'Count minus index: ' + trace.prefix.countMinusIndex,
      'Read at 0x009E4B49 → ' + hex(trace.prefix.faultAddress) + ' · rejected by guest bounds',
      'Fixture arguments were supplied by the harness. Original invocation is unverified.',
      'Missing producer: allocator-backed field 0x0189D0A8',
    ].join('\n');
    console.info('[uc-init]', trace);
  } catch (error) {
    initResult.textContent = error instanceof Error ? error.message : String(error);
  } finally {
    runInit.disabled = false;
  }
});

const aptResult = document.querySelector<HTMLElement>('#apt-result')!;
for (const mode of ['constructor', 'fixture'] as const) {
  const button = document.querySelector<HTMLButtonElement>('#apt-' + mode)!;
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      aptResult.textContent = await runAptDiagnostic(mode);
    } catch (error) {
      aptResult.textContent = error instanceof Error ? error.message : String(error);
    } finally {
      button.disabled = false;
    }
  });
}

const frontendLookup = document.querySelector<HTMLButtonElement>('#frontend-lookup')!;
const frontendResult = document.querySelector<HTMLElement>('#frontend-result')!;
frontendLookup.addEventListener('click', async () => {
  frontendLookup.disabled = true;
  frontendResult.textContent = 'Running lookup prefix…';
  try {
    const result = await runFrontendLookup();
    frontendResult.textContent = 'localToGlobal · index ' + result.index
      + ' · candidate native ID 0x' + result.nativeId.toString(16).toUpperCase()
      + ' · stopped at 0x00998241 before comparison thunk. Cache and argument stack untouched.';
  } catch (error) {
    frontendResult.textContent = error instanceof Error ? error.message : String(error);
  } finally {
    frontendLookup.disabled = false;
  }
});

const queueButton = document.querySelector<HTMLButtonElement>('#frontend-queue')!;
const queueResult = document.querySelector<HTMLElement>('#queue-result')!;
queueButton.addEventListener('click', async () => {
  queueButton.disabled = true;
  queueResult.textContent = 'Running queue diagnostics…';
  try {
    queueResult.textContent = (await runFrontendQueue()).join('\n');
  } catch (error) {
    queueResult.textContent = error instanceof Error ? error.message : String(error);
  } finally {
    queueButton.disabled = false;
  }
});

const bootButton = document.querySelector<HTMLButtonElement>('#boot-callbacks')!;
const bootResult = document.querySelector<HTMLElement>('#boot-callback-result')!;
bootButton.addEventListener('click', async () => {
  bootButton.disabled = true;
  bootResult.textContent = 'Running callback diagnostics…';
  try {
    bootResult.textContent = (await runBootCallbacks()).join('\n');
  } catch (error) {
    bootResult.textContent = error instanceof Error ? error.message : String(error);
  } finally {
    bootButton.disabled = false;
  }
});

const frameButton = document.querySelector<HTMLButtonElement>('#frontend-frame')!;
const frameResult = document.querySelector<HTMLElement>('#frame-result')!;
frameButton.addEventListener('click', async () => {
  frameButton.disabled = true;
  frameResult.textContent = 'Running frame diagnostics…';
  try {
    frameResult.textContent = (await runFrontendFrame()).join('\n');
  } catch (error) {
    frameResult.textContent = error instanceof Error ? error.message : String(error);
  } finally {
    frameButton.disabled = false;
  }
});
