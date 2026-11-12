// Automated Microsoft Partner Center Store Screenshot Generator (1920x1080 PNGs).
// Attaches to the already-running Host WebView2 over CDP (--remote-debugging-port=9222)
// so CI produces ready-to-upload Partner Center desktop screenshots with zero extra startup overhead.
import { chromium } from 'playwright';
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const port = process.env.CDP_PORT ?? '9222';
const artifactDir = process.env.ARTIFACT_DIR ?? 'artifacts';
const screenshotDir = process.env.STORE_SCREENSHOT_DIR ?? join(artifactDir, 'store-screenshots');
const appPid = process.env.APP_PID ? Number(process.env.APP_PID) : undefined;

const WIDTH = 1920;
const HEIGHT = 1080;

mkdirSync(screenshotDir, { recursive: true });

const alive = () => {
  if (!appPid) return true;
  try { process.kill(appPid, 0); return true; } catch { return false; }
};
const sleep = ms => new Promise(r => setTimeout(r, ms));

function verifyPng1920x1080(filePath) {
  const buf = readFileSync(filePath);
  if (buf.length < 20_000) {
    throw new Error(`Store screenshot ${filePath} is unexpectedly small (${buf.length} bytes)`);
  }
  if (buf[0] !== 0x89 || buf[1] !== 0x50 || buf[2] !== 0x4e || buf[3] !== 0x47) {
    throw new Error(`Store screenshot ${filePath} does not have a valid PNG signature`);
  }
  const w = buf.readUInt32BE(16);
  const h = buf.readUInt32BE(20);
  if (w !== WIDTH || h !== HEIGHT) {
    throw new Error(`Store screenshot ${filePath} dimensions are ${w}x${h}, expected ${WIDTH}x${HEIGHT}`);
  }
  console.log(`Captured ${filePath} (${w}x${h}, ${(buf.length / 1024).toFixed(1)} KB)`);
}

let browser;
for (let i = 0; i < 30 && !browser; i++) {
  if (!alive()) throw new Error('Host process exited before store-screenshots connected');
  try { browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`); } catch { await sleep(1000); }
}
if (!browser) throw new Error(`Could not connect to WebView2 CDP on port ${port}`);

let page;
for (let i = 0; i < 20 && !page; i++) {
  const pages = browser.contexts().flatMap(c => c.pages());
  page = pages.find(p => p.url().startsWith('https://0.0.0.1') || p.url().startsWith('https://0.0.0.0') || p.url().includes('index.html'))
    ?? pages.find(p => p.url().startsWith('http'));
  if (!page) await sleep(500);
}
if (!page) throw new Error('No WebView2 page found for Store screenshots');

const cdp = await page.context().newCDPSession(page);
const attr = n => page.evaluate(k => document.documentElement.getAttribute(k), n);
const initialChoice = await attr('data-theme-choice').catch(() => 'system');
const restoreChoice = ['dark', 'light', 'system'].includes(initialChoice) ? initialChoice : 'system';

const resetMainScroll = () => page.evaluate(() => {
  const main = document.querySelector('main.content');
  if (main) main.scrollTop = 0;
  window.scrollTo(0, 0);
});

const capture1080p = async fileName => {
  const outPath = join(screenshotDir, fileName);
  await sleep(350);
  await page.screenshot({
    path: outPath,
    fullPage: false,
    clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT },
  });
  verifyPng1920x1080(outPath);
};

try {
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: WIDTH,
    height: HEIGHT,
    deviceScaleFactor: 1,
    mobile: false,
    screenWidth: WIDTH,
    screenHeight: HEIGHT,
  });

  // Use crisp dark desktop theme for Store listing screenshots.
  await page.getByTestId('theme-dark').click();
  await page.waitForFunction(() => document.documentElement.getAttribute('data-theme') === 'dark', null, { timeout: 10_000 });

  // 1) 01-dashboard-overview.png — Dashboard with 10-Minute Bench QA & diagnostic cards
  await page.locator('#main-navigation a[title="Dashboard"]').click();
  await page.getByTestId('dashboard-title').waitFor({ state: 'visible', timeout: 20_000 });
  await page.getByTestId('dashboard-runall').waitFor({ state: 'visible', timeout: 10_000 });
  await resetMainScroll();
  await capture1080p('01-dashboard-overview.png');

  // 2) 02-bench-qa-and-qr-certificate.png — /certificates showing Shop Branding, Physical Keyboard/Display QA, and Live Buyer QR Certificate preview
  await page.getByTestId('nav-certificates').click();
  await page.getByTestId('branding-title').waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByTestId('physical-qa-card').waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByTestId('branding-card').waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByTestId('qa-preview-frame').waitFor({ state: 'visible', timeout: 15_000 });

  await page.getByTestId('branding-shop-name').fill('Apex Refurb & PC Repair');
  await page.getByTestId('branding-tech-name').fill('Alex Rivera');
  await page.getByTestId('branding-phone').fill('(512) 555-0194');
  await page.getByTestId('branding-website').fill('https://apexrefurb.example');
  await page.getByTestId('branding-warranty').fill('Backed by our 90-Day Parts & Labor Hardware Warranty.');
  await sleep(300);

  // Frame Physical Keyboard/Display QA, Shop Branding, and Live Buyer QR Certificate preview together inside 1920x1080.
  await page.evaluate(() => {
    const main = document.querySelector('main.content');
    const phys = document.querySelector('[data-testid="physical-qa-card"]');
    const cert = document.querySelector('[data-testid="qa-cert-card"]');
    if (!main || !phys || !cert) return;
    main.scrollTop = 0;
    const mainRect = main.getBoundingClientRect();
    const physTop = phys.getBoundingClientRect().top - mainRect.top;
    const certTop = cert.getBoundingClientRect().top - mainRect.top;
    // Scroll so physical-qa-card starts near the top of main.content, maximizing visible height of qa-preview-frame while keeping Shop Branding & Physical QA in view.
    const desiredScroll = Math.max(0, Math.min(physTop - 8, certTop - 520));
    main.scrollTop = desiredScroll;
  });
  try {
    await capture1080p('02-bench-qa-and-qr-certificate.png');
  } finally {
    await page.getByTestId('branding-clear').click().catch(() => {});
    await resetMainScroll();
  }

  // 3) 03-connect-to-technician.png — Top-bar "Connect to Technician" modal open showing Shop Code (-g) verification
  await page.locator('#main-navigation a[title="Dashboard"]').click();
  await page.getByTestId('dashboard-title').waitFor({ state: 'visible', timeout: 15_000 });
  await resetMainScroll();
  await page.getByTestId('connect-tech-open').click();
  await page.getByTestId('connect-tech-dialog').waitFor({ state: 'visible', timeout: 10_000 });
  await page.getByTestId('connect-tech-group').fill('apex-pc-repair');
  try {
    await capture1080p('03-connect-to-technician.png');
  } finally {
    await page.getByTestId('connect-tech-close').click().catch(() => {});
    await page.getByTestId('connect-tech-dialog').waitFor({ state: 'detached', timeout: 10_000 }).catch(() => {});
  }

  // 4) 04-service-workflow-report.png — /workflow automated Before/After service report workflow
  await page.getByTestId('nav-workflow').click();
  await page.getByTestId('wf-title').waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByTestId('wf-steps').waitFor({ state: 'visible', timeout: 15_000 });
  await page.getByTestId('wf-start-checks').waitFor({ state: 'visible', timeout: 15_000 });
  await resetMainScroll();
  await capture1080p('04-service-workflow-report.png');

  console.log('All 4 Partner Center 1920x1080 Store screenshots generated successfully.');
} finally {
  await cdp.send('Emulation.clearDeviceMetricsOverride').catch(() => {});
  if ((await attr('data-theme-choice').catch(() => null)) !== restoreChoice) {
    await page.getByTestId(`theme-${restoreChoice}`).click().catch(() => {});
  }
  await cdp.detach().catch(() => {});
  await browser.close().catch(() => {});
}
