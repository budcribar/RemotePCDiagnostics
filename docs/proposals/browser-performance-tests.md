# RemotePCDiagnostics browser performance tests

**Status:** Proposed. Not implemented.

Publishing this document grants no implementation approval. It is planning only: a one-minute browser responsiveness benchmark, two optional longer benchmarks, timed page loads, and a fast browser health check.

## Speedometer 3

The core test is Speedometer 3, the industry-standard browser responsiveness benchmark. It runs real web-app workloads (to-do lists, editors, charts, news sites, and similar) and finishes in about a minute. The same workload runs in each major browser, so a score compares across them. Higher is better.

1. Read-only and remote-safe. It changes no settings, bookmarks, history, or profile, and it writes no device state.
2. Launch the user's default browser as a new minimized window. Leave any window they already have open alone. Close the test window when the run finishes, including on cancel.
3. Use a temporary profile, then delete it. The score stays comparable, and their tabs and extensions stay untouched. Extension cost belongs to the health check.
4. When that browser cannot be launched, run the same page in a second WebView2 environment. The app already ships the WebView2 runtime for its own window. Give the test its own user-data folder, and leave the UI's WebView2 alone. Label that score `webview2`. It is the Edge engine, so keep it in its own baseline, apart from desktop Chrome and Firefox.
5. Record the score, the browser, the engine (`default-browser` or `webview2`), and the conditions the benchmark pass already keeps: on battery, power plan, and CPU temperature.
6. A low score points at a slow CPU, thermal throttling, or a battery-saver / power-saver plan. It does not certify the CPU. Send a power-saver result to the existing Battery & power plan check and its Balanced power-plan fix.

## MotionMark

Optional graphics and animation benchmark. Higher is better. A low MotionMark beside a good Speedometer suggests a GPU driver problem or hardware acceleration turned off. It loads the GPU. A low score can also be a hot chip or acceleration left off, so it is a clue, not proof the GPU is faulty.

## JetStream 2

Optional pure-JavaScript benchmark. Higher is better. It runs for several minutes and loads the CPU the whole time, so it belongs in the benchmark module, off unless someone asks for it. It says more about the JavaScript engine under a long run than about ordinary browsing.

## Page load timing

Time a fixed set of pages in the same minimized browser (WebView2 only as the fallback above). For each page record time to first byte, DOMContentLoaded, and full load.

1. The set is a few HTTPS pages checked in with the app: one tiny static page, one ordinary page, one script-heavy page. Choose the URLs before implementation. Store the set id with the result so an older run stays comparable after the list changes.
2. A slow time to first byte with a short remainder points at the network or DNS. A fast time to first byte with a slow full load points at the PC. Say which.
3. Read it next to the checks that already exist: Network & Wi-Fi, the DNS comparison (current DNS against Cloudflare and Google), and the benchmark's website-lookup time. This check does not run a second DNS test.
4. One slow page is a bad day for that site, not a slow PC. Judge the set. Offline, a captive portal, or a blocked network is "could not run", which is not a failure of the PC.
5. Load only the fixed pages. Record timings, not page contents, and never the user's history.

## Browser health check

A normal check: `ModuleKind.Check`, slug `BrowserHealth`, listed in the Programs group on Checks (group key `apps`), included in Run All. It finishes in seconds. That group is only where the row sits. The Chrome and Edge profile reader is shared Core code and today feeds the memory suggestions, not the Programs module (`Programs`, "Programs & updates"). See [Consolidating browser code](#consolidating-browser-code).

For each installed browser, record:

1. **Extensions.** Installed extensions. Flag a large extension folder, a high count, and known adware. The allowlist (Honey, MSN New Tab, Amazon Assistant) and the profile read live in Core. Firefox has no reader yet.
2. **Background running.** Whether the browser keeps running after it is closed, from `BrowserBackground` in Core. That is `background_mode.enabled` in Local State ("Continue running background apps when the browser is closed") and, for Edge, Startup Boost. A `BackgroundModeEnabled` policy, or an Edge Startup Boost policy under HKLM or HKCU, is reported as forced.
3. **Preferences.** Hardware acceleration on or off, per profile. When a policy forces it, say forced. Also whether Edge sleeping tabs and Efficiency mode, or Chrome Memory Saver, are on, from `BrowserPrefs`.
4. **Storage.** Cache size and profile size.
5. **Live load.** Open tab count, process count, and memory per browser process. Counts and bytes only. Leave tab titles and URLs out.

The check may offer these fixes. It lists them and applies none:

1. Clear cache. The browser has to be closed first, the same rule as the other browser-file writes. Confirm, journal, and keep undo.
2. Turn hardware acceleration on, where that preference exists and a policy does not force it. Browser closed, then confirm, journal, and undo.
3. Disable one extension. Known adware goes through the existing blocklist fix. Any other extension is one the person picks. A "heavy" flag alone never disables it.
4. Stop the browser running in the background. Reuse `StopBrowserBackground` (`BrowserSuggestions.StopBrowserBackgroundAsync`). It turns off "Continue running background apps" (`background_mode.enabled`) and, for Edge, Startup Boost when no policy is already set. Windows of that browser must be closed first. An open window is never closed. Windowless background processes may be ended so the Local State write can stick. Approval, journal (`ChangeKind.BrowserLocalStateValue`), and undo through `BrowserBackground.RestoreAsync` in `UndoService`. A policy that forces background mode or Startup Boost is reported as forced and left unchanged. Today's memory-suggestion card offers this only for the browser that is not the default (`BrowserBackground.Secondary`), and the action refuses the default browser. `BrowserHealth` uses the same writes for each installed browser whose preference is on and whose policy does not force it. That is the same fix, not a second one.

Edge sleeping tabs, Edge Efficiency mode, and Chrome Memory Saver stay advice on this check: turn the preference on. A one-click preference fix could come later. Core already has that write (`EnableBrowserMemorySaver` in `BrowserSuggestions`, journal `ChangeKind.BrowserSettings`, undo in `UndoService`, and only while the browser is closed). This proposal does not offer it.

Each fix needs the same explicit approval as every other repair, remote or local.

## Scoring

Health rows use the existing outcomes: passed, warning, and critical. A benchmark is a score plus conditions, judged against a baseline for that CPU class.

1. Compare a score only with the same benchmark, the same engine, and the same CPU class, on AC power, off a power-saver plan, and while the CPU is not thermally throttling. A run on battery, on a power-saver plan, or while throttling is the finding. Leave it out of the AC baseline, and do not fail it for missing that baseline.
2. CPU class comes from the hardware inventory (CPU name and core count), in coarse buckets such as mobile low-power, mobile mainstream, and desktop. A bucket is wider than one CPU model, so a new chip still lands somewhere. Store the CPU name on the sample so the buckets can be revised.
3. Each finished run appends one sample: benchmark, browser, engine, CPU class, CPU name, core count, on battery, power plan, score, and time. No computer name, account, serial, or profile path. Keep the file in the protected state folder, beside `benchmarks.json` and separate from it, so a before/after pass is left alone.
4. Bands wait until that class and engine have at least 30 AC samples. Before that, show the score and "no baseline yet". Starting point, to confirm on real scores before it ships: pass at or above the 25th percentile, warning from the 10th up to the 25th, fail below the 10th.
5. Samples stay on the diagnosed PC. A shop-wide baseline would be a later anonymous aggregate of those samples.

## Speed-up suggestions

A low score or a health flag names the next step on the same result. A one-click fix uses the existing remediation path: the result offers it, `list_fixes` lists it, and `apply_fix` runs that one fix after explicit approval, with a journal entry and undo. Advice is text the technician reads out. The check applies none of them.

1. **Low Speedometer 3.** One-click when the plan is a power saver, or the run was on one: the Battery & power plan check (`BatteryPower`) and its Balanced power-plan fix (`SetBalancedPowerPlan`, "Switch to Balanced power plan"). Review startup apps. There is no startup-apps check on the Checks page. The benchmark already counts enabled start-up apps, and the startup-app suggestions disable one app at a time (`DisableStartup`, approval, journal, undo). For throttling, run Temperatures & fans (`Sensors`). That check reads CPU temperature and fan speed through LibreHardwareMonitor. A hot or throttling CPU is the finding. It offers no cooling fix.
2. **Low MotionMark.** One-click: the hardware-acceleration fix on `BrowserHealth`, when that preference exists and a policy does not force it (browser closed, approval, journal, undo). A policy that forces it off leaves advice only. Also point at Device Manager & drivers (`DeviceDrivers`), which shows the GPU driver's version and date. Its "Check & install driver updates" fix (`CheckAndInstallDriverUpdates`) is offered from this result when that check shows a pending driver update or an old GPU driver. The technician still approves it.
3. **Too many tabs, or high memory per process.** Advice: close tabs. The result keeps the count and closes nothing. Also advice, from the preferences line: turn on Edge sleeping tabs and Efficiency mode, or Chrome Memory Saver. A one-click preference fix could come later, reusing `EnableBrowserMemorySaver`. This proposal does not offer that fix.
4. **Browser still running after it is closed.** One-click: the existing `StopBrowserBackground` fix on `BrowserHealth` (browser windows closed first, approval, journal, undo). A policy-forced setting is reported as forced and left unchanged. See the health check for the action and the undo path.
5. **Large cache or profile.** One-click for a large cache: the clear-cache fix on `BrowserHealth` (browser closed, approval, journal, undo). It clears cache files and leaves the profile, including bookmarks, history, and sign-in. Storage cleanup already removes Chrome and Edge Service Worker and Code Cache entries unused for 60 days. The health-check clear-cache is the action on this result, and running it does not also run that storage cleanup. A large profile whose cache is small is advice: say what is using the space, and offer no profile delete.
6. **Heavy or adware extensions.** One-click for known adware: the existing blocklist fix (Chrome and Edge `ExtensionInstallBlocklist`, limited to the allowlist: Honey, MSN New Tab, Amazon Assistant), one extension, approval, journal, undo. Any other extension is a person-picked disable. The result names it, and the fix appears only after that person chooses it. A heavy flag by itself adds no fix.
7. **Slow page loads with normal Speedometer and MotionMark scores.** Advice that points at the existing checks: Network & Wi-Fi (`Network`), the DNS comparison (current DNS against Cloudflare and Google), and the benchmark's website-lookup time (`DnsLookup`). This result changes neither DNS nor the adapter. When the DNS comparison already offers its own switch, that fix stays on the network check, and this row links to it.

Each row names the check or fix that produced it. One-click rows are actions on the result, so `list_fixes` returns them and `apply_fix` runs one after approval. Advice rows are text on the result.

## Where each test runs

1. Browser health is a normal check. It is in Run All and starts from `run_check`.
2. Speedometer, MotionMark, and JetStream take about a minute to several minutes and load the machine, so they stay out of Run All. Add them as optional benchmark kinds on the Benchmark screen, off by default, so today's before/after pass keeps its length. `run_benchmark` starts them when they are selected. They are benchmark scores, not stress-suite steps: a stress run looks for faults under sustained load.
3. Page load needs the network and is longer than a check, so it stays out of Run All. On-demand tests already list on the Stress tests page as separate steps (DISM, the large-file scan) and are left out of the stress suite. Put page load there, unticked. `run_check` starts it.

## Remote and local

1. All of these tests are software-only, so they are safe to run in a remote session the same way other read-only checks are.
2. The benchmarks still load the CPU, and MotionMark loads the GPU. A minimized window can spin the fans. Run them when the person is not working, and say so before starting. Leave them out of an unattended idle pass.
3. Hide a browser that is not installed, rather than showing it disabled. No Chrome installed means no Chrome block and no Chrome benchmark choice. When no browser is installed, omit the health check from the list, the same way a missing webcam is omitted, and do not call that a failure.
4. Fixes stay off the read-only run. Clear cache, turn on hardware acceleration, disable an extension, and stop background running go through the existing remediation path, one at a time, after explicit approval. A remote user who already has control can apply them, because remote control matches the person at the PC.

## Consolidating browser code

The Chrome and Edge profile reader lives in shared Core, under `src/RemotePCDiagnostics.Core/Optimizations/`:

- `BrowserExtensions.cs` reads installed extensions and the allowlist block.
- `BrowserPrefs.cs` reads and writes Memory Saver, sleeping tabs, and Efficiency mode.
- `BrowserBackground.cs` reads background mode and Startup Boost.
- `BrowserSuggestions.cs` applies those fixes (block an extension, stop background running, turn a pref on) with the journal and undo.

`WindowsMemorySystem` fills a `MemorySnapshot` from that reader. `MemorySuggestionEngine` builds the cards, and `MemorySuggestionService` runs them. Those cards are the memory suggestions. The Resource hogs check hosts that panel. The Programs module does not call this reader.

Phase 1 keeps the reader in Core so `BrowserHealth` and the memory suggestions can both use it. The new check calls it directly. These items move out of the memory suggestions and onto `BrowserHealth`, so they appear in one place:

1. Extension blocklist cards.
2. Background-running cards. The fix is the existing `StopBrowserBackground` action (`BrowserSuggestions`, undo in `UndoService` through `BrowserBackground.RestoreAsync`), not a new one.
3. The efficiency / sleeping-tabs readout (Edge sleeping tabs and Efficiency mode, Chrome Memory Saver). It stays advice. A one-click preference fix could come later, reusing `EnableBrowserMemorySaver`. This proposal does not offer that fix.

The memory suggestions then point at `BrowserHealth` for those items. They do not build the same cards again. Other memory suggestions (startup apps that are not a browser, Office, services, close-app) stay where they are.

`BrowserExtensionsTests` and `BrowserBackgroundTests` cover this reader and its fixes, and `BrowserContractTests` covers page markers. All three must keep passing. No code moves until implementation of this proposal is approved.

## Phased plan

1. **Phase 1.** Browser health and Speedometer, for Chrome and Edge. `BrowserHealth` calls the Core profile reader directly, including `BrowserBackground` (still running after close) and `BrowserPrefs` (hardware acceleration, Edge sleeping tabs and Efficiency mode, Chrome Memory Saver). Record the score and conditions and start saving samples. No pass/fail band until a class has enough runs. WebView2 is the labeled fallback. In the same phase, move the extension blocklist and the background-running suggestion onto `BrowserHealth`, reusing `StopBrowserBackground`, and leave a pointer in the memory suggestions. Efficiency and sleeping tabs stay advice. A one-click for that preference could come later. See [Consolidating browser code](#consolidating-browser-code). No code moves until implementation is approved, and `BrowserExtensionsTests`, `BrowserBackgroundTests`, and `BrowserContractTests` must keep passing.
2. **Phase 2.** Page-load timing, read next to the network and DNS results.
3. **Phase 3.** MotionMark and JetStream as further optional benchmark kinds, still off by default. Turn the percentile bands on only after the stored samples support them.

When a phase exists, the connector exposes it like this:

1. `run_check` and `get_check_result` with check id `BrowserHealth` (phase 1) and `PageLoad` (phase 2).
2. `run_benchmark`, `get_benchmark_results`, and `stop_benchmark` for Speedometer, MotionMark, and JetStream, only when those kinds are selected. A pass that leaves them unselected does not run them.
3. Offered fixes come back from `list_fixes`. `apply_fix` runs one, after approval. The check never applies a fix.

## Open questions

1. A temporary profile is the recommendation, because a real profile would mix in extensions and would use the user's browser data. Confirm that before implementation.
2. The CPU-class rules, and the 10th and 25th percentile cuts. Those cuts are a starting point.
3. The fixed page list, and the wording when a captive portal or a blocked network stops the run ("could not run").
4. Firefox in phase 1, or Chrome and Edge only until a Firefox reader exists. `BrowserKind` today is Chrome and Edge.
5. Whether a shop-wide baseline is in scope after local samples exist, and who may upload them.
6. Which preference key each browser uses for hardware acceleration, and reporting only when a policy forces it.
