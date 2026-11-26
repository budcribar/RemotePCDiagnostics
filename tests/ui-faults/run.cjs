// Fault-injection UI tests (docs/fault-injection.md): the real RPCD pages run on a recorded PC in tools/RpcdReplayHost, each check's
// answers are broken one at a time, and every page must cope. Uses the Playwright installed globally (NODE_PATH=$(npm root -g)).
//
//   dotnet build tools/RpcdReplayHost
//   NODE_PATH=$(npm root -g) node tests/ui-faults/run.cjs --recording <folder> [--tier quick|full] [--out <dir>] [--check <Name>] [--store]
//
// Writes <out>/report.md (one line per problem), report.json, and a screenshot for each problem. Exit code 1 when anything failed.
'use strict';
const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const args = process.argv.slice(2);
const opt = (name, fallback) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : fallback; };
const flag = name => args.includes('--' + name);
const recording = opt('recording');
if (!recording) { console.error('--recording <folder> is required'); process.exit(2); }
const tier = opt('tier', 'quick');
const onlyCheck = opt('check');
const port = Number(opt('port', '5199'));
const out = path.resolve(opt('out', path.join('artifacts', 'ui-faults', path.basename(recording))));
const base = `http://127.0.0.1:${port}`;
const repo = path.resolve(__dirname, '..', '..');
const hostDll = opt('host', path.join(repo, 'tools', 'RpcdReplayHost', 'bin', 'Debug', 'net11.0', 'RpcdReplayHost.dll'));

function resolveDotnetExecutable() {
  const exeName = process.platform === 'win32' ? 'dotnet.exe' : 'dotnet';
  const candidates = [];
  if (process.env.DOTNET_ROOT) candidates.push(path.join(process.env.DOTNET_ROOT, exeName));
  if (process.platform === 'win32') {
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    candidates.push(path.join(programFiles, 'dotnet', exeName));
  } else {
    candidates.push('/usr/bin/dotnet', '/usr/local/bin/dotnet');
    if (process.env.HOME) candidates.push(path.join(process.env.HOME, '.dotnet', exeName));
  }
  const found = candidates.find(p => fs.existsSync(p));
  if (!found) throw new Error(`Could not locate ${exeName}; set DOTNET_ROOT to your .NET SDK directory.`);
  return found;
}

// A check that hasn't finished this long after it started is stuck. Timing faults wait TIMEOUT_MS before answering.
const RUN_BUDGET_MS = 30_000, TIMEOUT_MS = 1_500, STOP_BUDGET_MS = 5_000;
// What a page must never show: numbers no PC has, and text that is a broken value rather than a reading.
const NONSENSE = ['NaN', 'Infinity', '-Infinity', 'undefined', 'null', '4294967295', '9000000000000000000', '18446744073709551615', '-1', '-1%', '-1 %'];
const FAULTS_QUICK = ['access-denied', 'missing-class', 'timeout', 'empty', 'garbage'];
const FAULTS_FULL = ['access-denied', 'missing-class', 'missing-namespace', 'provider-failure', 'timeout', 'empty', 'garbage', 'cut-off', 'delay'];

const problems = [];
const seenMisses = new Set();
const notes = [];
fs.mkdirSync(out, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function api(method, p, body) {
  const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error(`${method} ${p}: ${r.status}`);
  const t = await r.text();
  return t ? JSON.parse(t) : null;
}

async function startHost() {
  const hostArgs = [hostDll, '--recording', recording, '--port', String(port)];
  if (flag('store')) hostArgs.push('--store');
  const proc = spawn(resolveDotnetExecutable(), hostArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  proc.stdout.on('data', d => { log += d; });
  proc.stderr.on('data', d => { log += d; });
  for (let i = 0; i < 60; i++) {
    if (proc.exitCode !== null) throw new Error('Replay host exited:\n' + log);
    try { if ((await fetch(base + '/_test/faults')).ok) return proc; } catch { }
    await sleep(500);
  }
  proc.kill();
  throw new Error('Replay host did not start:\n' + log);
}

// One page per check run, so a broken circuit from one fault can't hide the next.
async function newPage(browser) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.consoleErrors = [];
  page.on('pageerror', e => page.consoleErrors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') page.consoleErrors.push('console: ' + m.text()); });
  return page;
}

async function checkNames(page) {
  await page.goto(base + '/');
  await page.getByTestId('dashboard-runall').waitFor({ timeout: 30_000 });
  const ids = await page.evaluate(() => [...document.querySelectorAll('[data-testid^="dashboard-card-"]')].map(e => e.getAttribute('data-testid')));
  return ids.filter(id => !id.includes('-details-') && !id.includes('-refresh-')).map(id => id.slice('dashboard-card-'.length));
}

/** Opens the check's page, runs it, and waits until it finishes (or the budget runs out). */
async function runCheck(page, name, budget = RUN_BUDGET_MS) {
  await page.goto(`${base}/module/${name}`);
  await page.getByTestId('area-status').waitFor({ timeout: 15_000 });
  const before = (await api('GET', '/_test/questions?since=0')).count;
  const started = Date.now();
  await page.getByTestId('area-requery').click();
  // While the check runs, its "Check again" button is gone; it comes back when the result is in.
  await page.getByTestId('area-requery').waitFor({ state: 'detached', timeout: 500 }).catch(() => { });
  const finished = await page.getByTestId('area-requery').waitFor({ state: 'visible', timeout: budget }).then(() => true, () => false);
  const ms = Date.now() - started;
  const questions = (await api('GET', `/_test/questions?since=${before}`)).questions;
  return { finished, ms, questions };
}

/** What a technician sees on the check's page, with the parts that change on their own (times since) left out. */
async function readPage(page) {
  return page.evaluate(() => {
    const main = document.querySelector('main') ?? document.body;
    const status = document.querySelector('[data-testid="area-status"]')?.innerText.trim() ?? '';
    const visible = sel => { const e = document.querySelector(sel); return !!e && e.offsetParent !== null; };
    return {
      status,
      text: main.innerText,
      pageError: visible('[data-testid="page-error"]') || visible('[data-testid="page-fault-notice"]'),
      blazorError: visible('#blazor-error-ui'),
      jsErrors: window.rpdErrors ?? [],
      overflow: [...document.querySelectorAll('.card, .summary-card, section')].some(e => e.scrollWidth > e.clientWidth + 2),
    };
  });
}

const LEADING = '("\'[,:;', TRAILING = ')"\'],:;.';
function trimToken(t) {
  let a = 0, b = t.length;
  while (a < b && LEADING.includes(t[a])) a++;
  while (b > a && TRAILING.includes(t[b - 1])) b--;
  return t.slice(a, b);
}

function nonsenseIn(text) {
  const found = new Set();
  for (const raw of text.split(/\s+/)) {
    const token = trimToken(raw);
    // Garbage text in a text field ("@@ garbage ##" as a device name) is shown as Windows gave it; only numbers no PC has are nonsense.
    if (NONSENSE.includes(token)) found.add(token);
  }
  return [...found];
}

const normalize = text => text.split('\n').filter(l => !l.includes(' ago') && !l.includes('Last checked')).join('\n');

async function fail(page, where, what) {
  const file = `fail-${problems.length + 1}.png`;
  await page.screenshot({ path: path.join(out, file), fullPage: true }).catch(() => { });
  problems.push({ where, what, screenshot: file });
  console.log(`FAIL ${where}: ${what}`);
}

/** Every "graceful" rule that can be judged from one page (docs/fault-injection.md, "What handled gracefully means"). */
async function judge(page, where, run, seen, baseline) {
  if (!run.finished) { await fail(page, where, `still running after ${run.ms / 1000}s`); return; }
  if (seen.pageError) await fail(page, where, 'the page showed its error banner');
  if (seen.blazorError) await fail(page, where, 'Blazor error UI shown (the page crashed)');
  const js = [...seen.jsErrors, ...page.consoleErrors];
  if (js.length) await fail(page, where, 'browser errors: ' + js.join(' | '));
  const logged = await api('GET', '/_test/errors');
  if (logged.length) { await fail(page, where, 'host logged: ' + logged.join(' | ')); await api('DELETE', '/_test/errors'); }
  const bad = nonsenseIn(seen.text).filter(t => !baseline || !nonsenseIn(baseline.text).includes(t));
  if (bad.length) await fail(page, where, `nonsense on the page: ${bad.join(', ')}`);
  if (!seen.status && !where.startsWith('Dashboard')) await fail(page, where, 'no status line');
  if (seen.overflow && !(baseline?.overflow)) await fail(page, where, 'a card overflows its box');
}

/** Clicks Refresh (Run all) unless a run is already going (the Dashboard queries the hardware by itself when it opens). */
async function startRunAll(page) {
  await page.goto(base + '/');
  const runall = page.getByTestId('dashboard-runall'), stop = page.getByTestId('dashboard-checks-stop');
  await runall.or(stop).first().waitFor({ timeout: 15_000 });
  if (await runall.isVisible().catch(() => false)) await runall.click();
}

/** The Agent never connected, and every WMI read hanging, across all checks from the Dashboard; then a clean run to reset. */
async function dashboardFaults(browser, report) {
  for (const fault of ['disconnected', 'hang']) {
    // The Agent reads only WMI; a hang is tried on every source (the Store edition's readers run programs, not WMI).
    const source = fault === 'hang' ? '*' : 'wmi';
    await api('POST', '/_test/faults', { rules: [{ source, match: '*', fault }] });
    const page = await newPage(browser);
    await startRunAll(page);
    const where = `Dashboard Run all / every ${source === '*' ? '' : 'WMI '}answer / ${fault}`;
    const stop = page.getByTestId('dashboard-checks-stop'), runall = page.getByTestId('dashboard-runall');
    if (fault === 'hang') {
      // Nothing answers: the checks keep running until Stop, and Stop must end them promptly.
      await sleep(2_000);
      if (await stop.isVisible().catch(() => false)) {
        const t = Date.now();
        await stop.click();
        const stopped = await runall.waitFor({ timeout: STOP_BUDGET_MS }).then(() => true, () => false);
        if (!stopped) await fail(page, where, `Stop didn't end the run within ${STOP_BUDGET_MS / 1000}s`);
        else notes.push(`${where}: Stop ended the run in ${Date.now() - t} ms`);
      } else await fail(page, where, 'no Stop button while every check hangs');
    } else {
      await sleep(1_000);
      const done = await runall.waitFor({ timeout: RUN_BUDGET_MS * 2 }).then(() => true, () => false);
      if (!done) await fail(page, where, 'Run all never finished');
    }
    const seen = await readPage(page);
    await page.screenshot({ path: path.join(out, `dashboard-${fault}.png`), fullPage: true });
    await judge(page, where, { finished: true, ms: 0 }, seen, null);
    report[`dashboard-${fault}`] = {
      verdict: (await page.getByTestId('dashboard-verdict-title').innerText().catch(() => '')).trim(),
      status: (await page.getByTestId('dashboard-status').innerText().catch(() => '')).trim(),
    };
    await page.close();
    await api('DELETE', '/_test/faults');
    // Reset: a clean run, so the next step starts from the recorded PC's own results.
    const clean = await newPage(browser);
    await startRunAll(clean);
    await sleep(1_000);
    await clean.getByTestId('dashboard-runall').waitFor({ timeout: RUN_BUDGET_MS * 2 }).catch(() => { });
    await clean.close();
  }
}

(async () => {
  const host = await startHost();
  const browser = await chromium.launch();
  const report = { recording: path.basename(recording), tier, checks: {} };
  try {
    let page = await newPage(browser);
    const names = (await checkNames(page)).filter(n => !onlyCheck || n === onlyCheck.toLowerCase());
    await page.close();

    if (!onlyCheck) await dashboardFaults(browser, report);
    // Questions the Dashboard's runs asked that the recording doesn't hold belong to no one check: list them once.
    const early = await api('GET', '/_test/misses');
    early.forEach(m => seenMisses.add(m));
    if (early.length) notes.push(`The recording doesn't hold ${early.length} question(s) the checks now ask (record the PC again): ${early.join(' | ').slice(0, 400)}`);

    for (const name of names) {
      // Baseline: the check on the recorded answers, no faults.
      await api('DELETE', '/_test/faults');
      page = await newPage(browser);
      const run = await runCheck(page, name);
      const baseline = await readPage(page);
      await page.screenshot({ path: path.join(out, `baseline-${name}.png`), fullPage: true });
      await judge(page, `${name} (no faults)`, run, baseline, null);
      await page.close();
      const questions = [...new Set(run.questions)];
      const misses = (await api('GET', '/_test/misses')).filter(m => !seenMisses.has(m));
      misses.forEach(m => seenMisses.add(m));
      if (misses.length) notes.push(`${name}: the recording doesn't hold ${misses.length} question(s) the check now asks (record the PC again): ${misses.join(' | ').slice(0, 300)}`);
      report.checks[name] = { baselineStatus: baseline.status, questions: questions.length, faults: [] };
      console.log(`${name}: ${baseline.status.split('\n')[0]} (${questions.length} questions, ${run.ms} ms)`);
      if (!questions.length) { notes.push(`${name}: asked nothing through the replay (nothing to break)`); continue; }

      const targets = tier === 'full' ? questions : questions.slice(0, 2);
      const faults = tier === 'full' ? FAULTS_FULL : FAULTS_QUICK;
      for (const q of targets) {
        const source = q.split('\n')[0];
        const label = q.split('\n').slice(-1)[0].slice(0, 80);
        for (const fault of faults) {
          await api('POST', '/_test/faults', { rules: [{ source, match: q, fault, ms: TIMEOUT_MS }] });
          page = await newPage(browser);
          const where = `${name} / ${source} ${label} / ${fault}`;
          const r = await runCheck(page, name);
          const seen = await readPage(page);
          const hits = (await api('GET', '/_test/faults')).hits;
          await judge(page, where, r, seen, baseline);
          report.checks[name].faults.push({ question: q, fault, status: seen.status.split('\n')[0], hits: hits.length, ms: r.ms });
          if (!hits.length) notes.push(`${where}: never applied (the question wasn't asked again)`);
          else if (normalize(seen.text) === normalize(baseline.text)) notes.push(`${where}: page identical to the baseline (fault hidden or fallback used)`);
          await page.close();

          // Recovery: with the fault gone the check must give its baseline again.
          await api('DELETE', '/_test/faults');
          page = await newPage(browser);
          const again = await runCheck(page, name);
          const recovered = await readPage(page);
          if (!again.finished) await fail(page, `${where} / recovery`, 'still running after the fault was cleared');
          else if (normalize(recovered.text) !== normalize(baseline.text)) await fail(page, `${where} / recovery`, 'the page did not return to its baseline once the fault was cleared');
          await page.close();
        }
      }
    }

  } finally {
    await browser.close();
    host.kill();
  }

  report.problems = problems;
  report.notes = notes;
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
  const lines = [`# Fault-injection UI run: ${report.recording} (${tier})`, '', `${problems.length} problem(s).`, ''];
  for (const p of problems) lines.push(`- **${p.where}**: ${p.what} ([screenshot](${p.screenshot}))`);
  lines.push('', '## Notes (for review, not failures)', '');
  for (const n of notes) lines.push(`- ${n}`);
  lines.push('', '## Status line per fault', '');
  for (const [name, c] of Object.entries(report.checks)) {
    lines.push(`### ${name}`, '', `Baseline: ${c.baselineStatus.split('\n')[0]}`, '');
    for (const f of c.faults) lines.push(`- ${f.fault} on \`${f.question.split('\n').slice(-1)[0].slice(0, 90)}\`: ${f.status}`);
    lines.push('');
  }
  fs.writeFileSync(path.join(out, 'report.md'), lines.join('\n'));
  console.log(`\n${problems.length} problem(s). Report: ${path.join(out, 'report.md')}`);
  process.exit(problems.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
