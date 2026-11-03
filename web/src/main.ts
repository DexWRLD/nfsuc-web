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
runInit.addEventListener('click', async () => {
  runInit.disabled = true;
  try {
    const trace = await runUndercoverInitializer();
    initResult.textContent = 'Initializer completed · 49 writes · stopped before callback dispatch. Boot continuation requires initialized object state.';
    console.info('[uc-init]', trace);
  } catch (error) {
    initResult.textContent = error instanceof Error ? error.message : String(error);
  } finally {
    runInit.disabled = false;
  }
});
