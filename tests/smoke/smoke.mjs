// Smoke test: attach Playwright to the Host's WebView2 over CDP and check the Dashboard renders.
// Requires the Host started with WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=<CDP_PORT>.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';

const port = process.env.CDP_PORT ?? '9222';
const outDir = process.env.ARTIFACT_DIR ?? 'artifacts';
const appPid = process.env.APP_PID ? Number(process.env.APP_PID) : undefined;
mkdirSync(outDir, { recursive: true });

const alive = () => { if (!appPid) return true; try { process.kill(appPid, 0); return true; } catch { return false; } };
const sleep = ms => new Promise(r => setTimeout(r, ms));

let browser;
for (let i = 0; i < 60 && !browser; i++) {
  if (!alive()) throw new Error('Host process exited before WebView2 became reachable');
  try { browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`); } catch { await sleep(1000); }
}
if (!browser) throw new Error(`Could not connect to WebView2 CDP on port ${port}`);

let page;
for (let i = 0; i < 30 && !page; i++) {
  const pages = browser.contexts().flatMap(c => c.pages());
  page = pages.find(p => p.url().startsWith('https://0.0.0.1') || p.url().startsWith('https://0.0.0.0') || p.url().includes('index.html'))
    ?? pages.find(p => p.url().startsWith('http'));
  if (!page) await sleep(1000);
}
if (!page) throw new Error('No WebView2 page found');
console.log('Attached to', page.url());

try {
  const title = page.getByTestId('dashboard-title');
  await title.waitFor({ state: 'visible', timeout: 60_000 });
  console.log('Dashboard visible:', await title.textContent());
  await page.screenshot({ path: `${outDir}/dashboard.png`, fullPage: true });

  // Stress suite buttons exist next to Run all tests (not clicked: they start long stress tests).
  for (const id of ['dashboard-runall', 'dashboard-runall-stress-short', 'dashboard-runall-stress-extended']) {
    await page.getByTestId(id).waitFor({ state: 'visible', timeout: 10_000 });
    console.log(`Button ${id}:`, (await page.getByTestId(id).textContent())?.trim());
  }

  // Theme switcher: each choice must update data-theme / data-theme-choice on <html>.
  const attr = n => page.evaluate(k => document.documentElement.getAttribute(k), n);
  const initialChoice = await attr('data-theme-choice');
  const restoreChoice = ['dark', 'light', 'system'].includes(initialChoice) ? initialChoice : 'system';
  try {
    for (const [choice, expected] of [['dark', 'dark'], ['light', 'light']]) {
      await page.getByTestId(`theme-${choice}`).click();
      await page.waitForFunction(t => document.documentElement.getAttribute('data-theme') === t, expected, { timeout: 10_000 });
      console.log(`Theme ${choice}: data-theme=${await attr('data-theme')}`);
      await page.screenshot({ path: `${outDir}/dashboard-${choice}.png`, fullPage: true });
    }
    await page.getByTestId('theme-system').click();
    await page.waitForFunction(() => document.documentElement.getAttribute('data-theme-choice') === 'system', null, { timeout: 10_000 });
    console.log(`Theme system: data-theme=${await attr('data-theme')}`);
  } finally {
    if ((await attr('data-theme-choice').catch(() => null)) !== restoreChoice) {
      await page.getByTestId(`theme-${restoreChoice}`).click().catch(() => {});
      await page.waitForFunction(c => document.documentElement.getAttribute('data-theme-choice') === c, restoreChoice, { timeout: 10_000 }).catch(() => {});
    }
  }

  // Sidebar: Checks, Stress tests and Security audit are separate items.
  for (const id of ['nav-checks', 'nav-stress', 'nav-security-audit']) await page.getByTestId(id).waitFor({ state: 'visible', timeout: 10_000 });

  // Checks screen: loads, the list expands/collapses, a row opens the detail pane, Run buttons enable correctly. Stress tests are never started here.
  await page.getByTestId('nav-checks').click();
  await page.getByTestId('checks-title').waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByTestId('checks-collapse-all').click();
  await page.locator('[data-testid^="checks-row-"]').first().waitFor({ state: 'detached', timeout: 10_000 });
  await page.getByTestId('checks-expand-all').click();
  const firstRow = page.locator('[data-testid="checks-group-checks"] [data-testid^="checks-row-"]').first();
  await firstRow.waitFor({ state: 'visible', timeout: 10_000 });
  await firstRow.click();
  await page.getByTestId('checks-detail-title').waitFor({ state: 'visible', timeout: 10_000 });
  console.log('Checks detail:', await page.getByTestId('checks-detail-title').innerText());
  if (await page.getByTestId('checks-group-stress').count()) throw new Error('Stress tests should not be listed on the Checks page');
  // Any startup checks must finish first; then the Run button is enabled (nothing running, items selected).
  await page.waitForFunction(() => !document.querySelector('[data-testid="checks-run-checks"]')?.disabled, null, { timeout: 180_000 });
  await page.waitForFunction(() => !document.querySelector('[data-testid="checks-run-one"]')?.disabled, null, { timeout: 60_000 });
  await page.screenshot({ path: `${outDir}/checks.png`, fullPage: true });

  // Stress tests screen: its own page; clearing the selection disables its Run button (tri-state: some -> all -> none).
  await page.getByTestId('nav-stress').click();
  await page.getByTestId('checks-group-stress').waitFor({ state: 'visible', timeout: 15_000 });
  if (await page.getByTestId('checks-group-checks').count()) throw new Error('System checks should not be listed on the Stress tests page');
  if (await page.getByTestId('checks-row-securityaudit').count()) throw new Error('The security audit has its own page');
  if (await page.getByTestId('checks-run-stress').isDisabled()) throw new Error('Run selected (stress) should be enabled when idle');
  for (let i = 0; i < 2 && !(await page.getByTestId('checks-run-stress').isDisabled()); i++) await page.getByTestId('checks-selectall-stress').click();
  await page.waitForFunction(() => document.querySelector('[data-testid="checks-run-stress"]')?.disabled === true, null, { timeout: 10_000 });
  console.log('Checks and Stress tests pages: run buttons OK');
  await page.screenshot({ path: `${outDir}/stress.png`, fullPage: true });

  // Security audit: own sidebar item and page (not started here).
  await page.getByTestId('nav-security-audit').click();
  await page.getByTestId('audit-title').waitFor({ state: 'visible', timeout: 15_000 });

  // Back to Checks for the resource hogs row.
  await page.getByTestId('nav-checks').click();
  await page.getByTestId('checks-expand-all').click();

  // Resource hogs: "Ways to use less memory" renders (suggestions, or the empty/error state). Actions are never clicked here.
  await page.getByTestId('checks-row-resourcehogs').click();
  await page.getByTestId('mem-suggest-title').waitFor({ state: 'visible', timeout: 60_000 });
  await page.locator('[data-testid^="mem-sug-"], [data-testid="mem-empty"], [data-testid="mem-error"]').first().waitFor({ state: 'visible', timeout: 120_000 });
  console.log(`Memory suggestions: ${await page.locator('[data-testid^="mem-sug-"]').count()} card(s); ${await page.getByTestId('mem-summary').innerText().catch(() => 'no summary')}`);
  await page.screenshot({ path: `${outDir}/memory-suggestions.png`, fullPage: true });

  // History page (reads the Windows Event Log): shows the results table, or the friendly empty/unavailable state when the source has no events.
  await page.getByTestId('nav-history').click();
  await page.getByTestId('history-title').waitFor({ state: 'visible', timeout: 15_000 });
  await page.locator('[data-testid="history-empty"], [data-testid="history-table"]').first().waitFor({ state: 'visible', timeout: 15_000 });
  console.log('History page:', await page.getByTestId('history-empty').count() ? 'empty state' : `${await page.getByTestId('history-row').count()} row(s)`);
  await page.screenshot({ path: `${outDir}/history.png`, fullPage: true });

  // QA Certificate & Shop Branding page: renders live 1-page QR certificate preview.
  await page.getByTestId('nav-certificates').click();
  await page.getByTestId('branding-title').waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByTestId('qa-preview-frame').waitFor({ state: 'visible', timeout: 15_000 });
  console.log('QA Certificate ID:', await page.getByTestId('qa-live-id').innerText());
  await page.screenshot({ path: `${outDir}/certificates.png`, fullPage: true });

  await page.getByTestId('nav-about').click();
  await page.getByTestId('about-title').waitFor({ state: 'visible', timeout: 15_000 });
  const buildVersion = await page.getByTestId('about-version').innerText();
  if (!/^\d+\.\d+\.\d+-(local|ci\.)/.test(buildVersion)) throw new Error(`Missing build identity: ${buildVersion}`);
  if (process.env.GITHUB_SHA && !buildVersion.includes(process.env.GITHUB_SHA)) throw new Error(`Wrong Git revision: ${buildVersion}`);
  if (process.env.GITHUB_RUN_NUMBER && !buildVersion.includes(`-ci.${process.env.GITHUB_RUN_NUMBER}.${process.env.GITHUB_RUN_ATTEMPT}`)) throw new Error(`Wrong CI build: ${buildVersion}`);
  console.log('About build:', buildVersion);
  await page.screenshot({ path: `${outDir}/about.png`, fullPage: true });
} catch (e) {
  await page.screenshot({ path: `${outDir}/failure.png`, fullPage: true }).catch(() => {});
  throw e;
}

await sleep(5000);
if (!alive()) throw new Error('Host process did not stay up');
console.log('Host process still running. Smoke test passed.');
await browser.close().catch(() => {}); // detaches only; does not close the app
