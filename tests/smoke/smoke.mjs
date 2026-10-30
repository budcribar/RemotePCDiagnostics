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
  page = browser.contexts().flatMap(c => c.pages()).find(p => p.url().startsWith('https://0.0.0.0') || p.url().includes('index.html') || p.url().startsWith('http'));
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
  for (const [choice, expected] of [['dark', 'dark'], ['light', 'light']]) {
    await page.getByTestId(`theme-${choice}`).click();
    await page.waitForFunction(t => document.documentElement.getAttribute('data-theme') === t, expected, { timeout: 10_000 });
    console.log(`Theme ${choice}: data-theme=${await attr('data-theme')}`);
    await page.screenshot({ path: `${outDir}/dashboard-${choice}.png`, fullPage: true });
  }
  await page.getByTestId('theme-system').click();
  await page.waitForFunction(() => document.documentElement.getAttribute('data-theme-choice') === 'system', null, { timeout: 10_000 });
  console.log(`Theme system: data-theme=${await attr('data-theme')}`);

  // History page: loads from the nav and shows either the empty state or the results table.
  await page.getByTestId('nav-history').click();
  await page.getByTestId('history-title').waitFor({ state: 'visible', timeout: 15_000 });
  await page.locator('[data-testid="history-empty"], [data-testid="history-table"]').first().waitFor({ state: 'visible', timeout: 15_000 });
  console.log('History page:', await page.getByTestId('history-empty').count() ? 'empty state' : `${await page.getByTestId('history-row').count()} row(s)`);
  await page.screenshot({ path: `${outDir}/history.png`, fullPage: true });
} catch (e) {
  await page.screenshot({ path: `${outDir}/failure.png`, fullPage: true }).catch(() => {});
  throw e;
}

await sleep(5000);
if (!alive()) throw new Error('Host process did not stay up');
console.log('Host process still running. Smoke test passed.');
await browser.close().catch(() => {}); // detaches only; does not close the app
