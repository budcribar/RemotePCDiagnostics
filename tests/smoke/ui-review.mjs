// Laptop-safe browser regression checks using production CSS/modal behavior, no Host or OS actions.
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const css = readFileSync(new URL('../../src/RemotePCDiagnostics.UI/wwwroot/app.css', import.meta.url), 'utf8');
const dialogs = readFileSync(new URL('../../src/RemotePCDiagnostics.UI/wwwroot/dialogs.js', import.meta.url), 'utf8');
// Blazor stops these bubbled events within its event delegation layer. Verify every action
// island declares both event boundaries; browser fixture tests below cover native modal behavior.
const area = readFileSync(new URL('../../src/RemotePCDiagnostics.UI/Pages/AreaPage.razor', import.meta.url), 'utf8');
const interactiveBlocks = [
  ...area.matchAll(/<SummaryCard\b[\s\S]*?<\/SummaryCard>/g),
  ...area.matchAll(/<tr\b(?:[^>"']|"[^"]*"|'[^']*')*@onclick(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?<\/tr>/g),
];
const nestedIslands = interactiveBlocks.flatMap(([block]) =>
  [...block.matchAll(/<(?:div|td)\b(?:[^>"']|"[^"]*"|'[^']*')*\bclass="[^"]*\bsvc-actions\b[^"]*"(?:[^>"']|"[^"]*"|'[^']*')*>/g)].map(m => m[0])
);
const stopPropIslands = [...area.matchAll(/<(?:div|td)\b(?:[^>"']|"[^"]*"|'[^']*')*@(?:onclick|onkeydown):stopPropagation="true"(?:[^>"']|"[^"]*"|'[^']*')*>/g)].map(m => m[0]);
const actionIslands = [...new Set([...nestedIslands, ...stopPropIslands])];
assert.ok(nestedIslands.length >= 3, 'AreaPage must contain nested action islands');
for (const island of actionIslands) {
  assert.match(island, /@onclick:stopPropagation="true"/, 'nested click actions must not activate their parent');
  assert.match(island, /@onkeydown:stopPropagation="true"/, 'nested keyboard actions must not activate their parent');
}
const checks = readFileSync(new URL('../../src/RemotePCDiagnostics.UI/Pages/ChecksPage.razor', import.meta.url), 'utf8');
const selectButtons = [...checks.matchAll(/<button\b(?:[^>"']|"[^"]*"|'[^']*')*data-testid="checks-select-@m\.Name\.ToLowerInvariant\(\)"(?:[^>"']|"[^"]*"|'[^']*')*>/g)].map(m => m[0]);
assert.equal(selectButtons.length, 1, 'ChecksPage must contain the row selection checkbox button');
assert.match(selectButtons[0], /@onclick:stopPropagation="true"/, 'click selection must not activate the enclosing check row');
assert.match(selectButtons[0], /@onkeydown:stopPropagation="true"/, 'keyboard selection must not activate the enclosing check row');
let browser;
try {
  browser = await chromium.launch({ channel: 'msedge', headless: true });
} catch {
  browser = await chromium.launch({ headless: true });
}
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
  await page.setContent(`<style>${css}</style><div class="app"><header class="topbar"><button class="nav-toggle">Menu</button><span class="title">RemotePCDiagnostics</span><span class="badge">Remote</span><span class="topbar-spacer"></span><div class="theme-switch"><button>Dark</button><button>System</button><button>Light</button></div><span class="pc">DESKTOP-TEST01</span></header><nav class="rail"><a href="#">Dashboard</a><a href="#">Checks &amp; tests</a></nav><main class="content"><div class="ct-detail-head"><strong>Services</strong><button>Run just this</button></div><button id="open">Open details</button><div class="cards"><div class="card"><div class="headline">IP, gateway, DNS &amp; proxy</div><button>Flush DNS &amp; renew IP</button></div></div><div id="confirm-slot"></div><div id="drawer-slot"></div></main></div>`);
  await page.addScriptTag({ content: dialogs });
  await page.locator('#open').focus();
  await page.evaluate(() => {
    document.querySelector('#drawer-slot').innerHTML = '<div class="drawer-backdrop"></div><aside class="drawer" role="dialog" aria-modal="true" tabindex="-1"><div class="drawer-head"><strong>Running services</strong><button id="close-drawer">Close</button></div><button id="nested">Inspect action</button></aside>';
  });
  await page.waitForFunction(() => document.activeElement.id === 'close-drawer');
  assert.equal(await page.locator('#open').evaluate(el => !!el.closest('[inert]')), true);
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'nested');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'close-drawer');
  assert.equal(await page.evaluate(() => document.elementFromPoint(900, 100).closest('.drawer') !== null), true, 'drawer covers sticky detail header');
  await page.locator('#nested').focus();
  await page.evaluate(() => {
    document.querySelector('#confirm-slot').innerHTML = '<div class="svc-modal-backdrop"></div><div class="svc-modal" role="dialog" aria-modal="true" tabindex="-1"><strong>Confirm action?</strong><p>No OS action is connected to this fixture.</p><div class="buttons"><button id="cancel">Cancel</button><button id="confirm">Confirm</button></div></div>';
  });
  await page.waitForFunction(() => document.activeElement.id === 'cancel');
  assert.equal(await page.locator('.drawer').evaluate(el => !!el.closest('[inert]')), true, 'outer dialog is inert while confirmation is open');
  assert.equal(await page.locator('.svc-modal').evaluate(el => { const r = el.getBoundingClientRect(); return el.contains(document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)); }), true, 'confirmation is hit-testable above backdrop');
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'confirm');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'cancel');
  await page.evaluate(() => document.querySelector('#confirm-slot').replaceChildren());
  await page.waitForFunction(() => document.activeElement.id === 'nested');
  await page.evaluate(() => document.querySelector('#drawer-slot').replaceChildren());
  await page.waitForFunction(() => document.activeElement.id === 'open');
  assert.equal(await page.locator('[inert]').count(), 0);
  for (const width of [390, 768]) {
    await page.setViewportSize({ width, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${width}px document has no horizontal overflow`);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.locator('.rail').isVisible(), false);
  assert.equal(await page.locator('.nav-toggle').isVisible(), true);
  await page.locator('.app').evaluate(el => el.classList.add('nav-open'));
  assert.equal(await page.locator('.rail').isVisible(), true);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  console.log('PASS: overlay hit-testing, focus containment/restoration, nested dialogs, inert cleanup, 390/768px layout and mobile navigation');
} finally { await browser.close(); }
