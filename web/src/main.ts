import './app/undercover-home.css';
import { runUndercoverInitializer } from './app/uc-browser-init';
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
    initResult.textContent = 'Initializer completed. Startup probe stopped on an uninitialized object field.';
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
      'Phase 55: verified the publisher at 0x009E46A1. Allocation remains unresolved.',
      'Missing producer: allocator-backed field 0x0189D0A8',
    ].join('\n');
    console.info('[uc-init]', trace);
  } catch (error) {
    initResult.textContent = error instanceof Error ? error.message : String(error);
  } finally {
    runInit.disabled = false;
  }
});
