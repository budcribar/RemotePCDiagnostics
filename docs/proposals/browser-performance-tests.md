# RemotePCDiagnostics browser performance tests

**Status:** Proposed. Not implemented.

Publishing this document grants no implementation approval. It is planning only: a one-minute browser responsiveness benchmark, two optional longer benchmarks, timed page loads, and a fast browser health check.

## Speedometer 3

The core test is Speedometer 3, the industry-standard browser responsiveness benchmark. It runs real web-app workloads (to-do lists, editors, charts, news sites, and similar) and finishes in about a minute. The same workload runs in each major browser, so a score compares across them. Higher is better.

1. Read-only and remote-safe. It changes no settings, bookmarks, history, or profile, and it writes no device state.
2. **On by default** on the Benchmark screen (one pass on the auto-selected default Chromium browser, labeled clearly as a clean-profile web responsiveness score). Because it runs in a fresh temporary profile, disabling extensions or clearing cache will not move the Speedometer score — only CPU, power-plan, thermal, and background-load fixes will. Extra installed browsers can be selected side by side in Customize tests; leave any window the user already has open alone.
3. A low score points at a slow CPU, thermal throttling, or a battery-saver / power-saver plan. It does not certify the CPU. Send a power-saver result to the existing Battery & power plan check and its Balanced power-plan fix.

### Implementation

1. **Packaging.** Pin one **pre-built** Speedometer 3 release asset from the open-source WebKit Speedometer repository (https://github.com/WebKit/Speedometer) that serves directly from `index.html` with no build step. The repo's `LICENSE` is the 2-clause BSD license, with copyrights held by Apple, Google, Mozilla, and Microsoft. Redistribution in binary form must keep that notice and the disclaimer, so the zip includes the `LICENSE` file. Record the zip's SHA-256 in the app and **bundle the zip in the installer** (~2–3 MB) so offline benches work out of the box with Speedometer on by default; if missing (e.g., portable copy), download the pinned release asset on first use, verify its SHA-256, and extract to `%LocalAppData%\RemotePCDiagnostics\benchmarks\speedometer\<version>` with Zip-Slip path validation (`Path.GetFullPath` confined inside the target directory). Later runs reuse that folder. A failed download or a hash mismatch is "could not run", with the reason. It is not a failed score.
2. **Serving.** For the length of the run, serve the extracted files from a small HTTP server on `127.0.0.1` and a random port. The page is that HTTP URL. It is not opened with `file://`.
3. **Browser selection.** Detect installed browsers RPCD can drive (Chromium: Chrome, Edge, Brave, and Opera). Anything else, including Firefox, is omitted until it can be driven, the same way a PC with no NPU omits the NPU test (`ModuleState.NotPresent`, not a disabled row). By default, auto-select the user's default driveable browser (falling back to Edge → Chrome → Brave → Opera) so a 1-click benchmark runs without a blocking picker. In Customize tests, the person may pick additional installed browsers; each gets its own score and baseline, shown side by side. When no driveable browser is installed, the run can use the WebView2 fallback, labeled `webview2`. Over the connector, the usable list comes back first and `run_benchmark` runs the caller's chosen browsers (or the auto-selected default when Speedometer is enabled without an override). Speedometer itself has to be in the confirmed enabled set before that call; see [Requested benchmark runs](#requested-benchmark-runs).
4. **Launch.** Do **not** launch minimized — Chromium throttles `requestAnimationFrame`, timers, and compositor paints in minimized or occluded windows, which depresses and destabilizes Speedometer scores. Launch with a fresh temporary profile and flags such as `--headless=new --user-data-dir=<temp> --no-first-run --no-default-browser-check --remote-debugging-address=127.0.0.1 --remote-debugging-port=0`, opening `http://127.0.0.1:<port>/?startAutomatically=true` (never pass `--remote-allow-origins=*`). Read the assigned ephemeral CDP port from `<temp>\DevToolsActivePort` to avoid port collisions. Confirm `--headless=new` parity against a visible window (with `--disable-backgrounding-occluded-windows --disable-renderer-backgrounding --disable-background-timer-throttling`) and confirm the automation query option for the pinned release before shipping. The temporary profile keeps the score comparable and leaves the user's tabs and extensions untouched. Extension cost belongs to the health check. Close the browser process when the run finishes.
5. **Result.** Read the score through the Chrome DevTools Protocol using a small built-in `ClientWebSocket` CDP client (~150 lines, zero extra NuGet dependencies — do not bundle Playwright for .NET into the customer desktop app). Poll until the run is done, then read the final score and the per-test breakdown. Do not scrape the screen. The WebView2 fallback uses its own user-data folder and reads the score with `ExecuteScriptAsync` (confirming it is not occlusion-throttled before shipping). Leave the UI's WebView2 alone. A `webview2` score is the Edge engine, so its baseline stays separate from desktop Chrome, Edge, Brave, and Opera.
6. **Cleanup.** Always close the browser process, delete the temporary profile, and stop the local HTTP server — including on cancel or timeout (**about 3 minutes per pass**, not per multi-browser job). Also sweep orphaned `%TEMP%\rpcd-speedometer-*` folders from prior crashed runs on startup.
7. **Who runs it, and what is kept.** The benchmark runs as the signed-in user, not as the admin agent. **One full pass** per selected browser is the default (Speedometer 3 already executes 10 internal iterations and reports a geomean plus confidence interval, taking ~60–90 seconds per pass). Record the score, the browser and its version, the engine (`chrome`, `edge`, `brave`, `opera`, or `webview2`), the power plan, whether the PC is on battery, and the CPU temperature from Temperatures & fans (`Sensors`, LibreHardwareMonitor).
8. **Still to confirm.** The exact JavaScript hook, the result object, `--headless=new` score parity, and the automation query option for the pinned Speedometer version. They have changed between releases.

## MotionMark

Optional graphics and animation benchmark. Higher is better. A low MotionMark beside a good Speedometer suggests a GPU driver problem or hardware acceleration turned off. It loads the GPU. A low score can also be a hot chip or acceleration left off, so it is a clue, not proof the GPU is faulty.

## JetStream 2

Optional pure-JavaScript benchmark. Higher is better. It runs for several minutes and loads the CPU the whole time, so it belongs in the benchmark module, off unless someone asks for it. It says more about the JavaScript engine under a long run than about ordinary browsing.

## Page load timing

Time a fixed set of pages in the browsers chosen for Speedometer. Use the labeled `webview2` fallback only when that is the run. For each page record time to first byte, DOMContentLoaded, and full load.

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
3. Each finished run appends one sample: benchmark, browser, browser version, engine, CPU class, CPU name, core count, on battery, power plan, score, and time. Compare browsers only with their own baselines. No computer name, account, serial, or profile path. Keep the file in the protected state folder, beside `benchmarks.json` and separate from it, so a before/after pass is left alone.
4. Ship a checked-in **seed baseline table** (per coarse CPU class, refreshed with RPCD releases) so a freshly diagnosed PC has immediate context on Day 1 instead of staying "no baseline yet" forever. Starting point, to confirm on real scores before it ships: pass at or above the 25th percentile, warning from the 10th up to the 25th, fail below the 10th. Local or shop-wide aggregates can refine or override the seed bands once a class and engine have at least 30 AC samples.
5. Samples stay on the diagnosed PC by default. An optional anonymous shop-wide aggregate in `RemoteWebViewAdmin` can refine the baselines later.

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
2. Speedometer 3 is **on by default** on the Benchmark screen (1 pass on the auto-selected default Chromium browser, adding ~60 seconds; extra browsers can be added in Customize tests). MotionMark and JetStream 2 take several minutes and load the GPU/CPU heavily, so they stay **off by default** on the Benchmark screen. None of them run in Checks `Run All`. That screen default is not the set to run when someone asks for a benchmark. Follow [Requested benchmark runs](#requested-benchmark-runs): turn every test off, enable only what was asked (or every available test for a run-all), confirm, then `run_benchmark`. They are benchmark scores, not stress-suite steps: a stress run looks for faults under sustained load.
3. Page load needs the network and is longer than a check, so it stays out of Run All. On-demand tests already list on the Stress tests page as separate steps (DISM, the large-file scan) and are left out of the stress suite. Put page load there, unticked. `run_check` starts it.

## Remote and local

1. All of these tests are software-only, so they are safe to run in a remote session the same way other read-only checks are.
2. The benchmarks still load the CPU, and MotionMark loads the GPU. A minimized window can spin the fans. Run them when the person is not working, and say so before starting. Leave them out of an unattended idle pass.
3. Hide a browser that is not installed, rather than showing it disabled. No Chrome installed means no Chrome block and no Chrome row on the health check. A browser RPCD cannot drive, such as Firefox today, is omitted from the Speedometer picker even when it is installed, the same way a missing NPU is omitted from the list. When no browser is installed, omit the health check from the list, the same way a missing webcam is omitted, and do not call that a failure.
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

1. **Phase 1.** Browser health and Speedometer. The health check is Chrome and Edge: `BrowserHealth` calls the Core profile reader directly, including `BrowserBackground` (still running after close) and `BrowserPrefs` (hardware acceleration, Edge sleeping tabs and Efficiency mode, Chrome Memory Saver). Speedometer 3 is **on by default** on the Benchmark screen using the browser selection in [Implementation](#implementation): auto-selects the default driveable Chromium browser (Edge, Chrome, Brave, or Opera) for **one full pass** (~60–90s) via `--headless=new` and a built-in `ClientWebSocket` CDP client; Firefox and any other undriveable browser stay hidden, and extra browsers can be added in Customize tests. Record the score and conditions, compare against the checked-in seed baseline table by CPU class, and start saving local samples. `webview2` is the labeled fallback when no driveable browser is installed, and only when the person or the connector asks for it. In the same phase, move the extension blocklist and the background-running suggestion onto `BrowserHealth`, reusing `StopBrowserBackground`, and leave a pointer in the memory suggestions. Efficiency and sleeping tabs stay advice. A one-click for that preference could come later. See [Consolidating browser code](#consolidating-browser-code). No code moves until implementation is approved, and `BrowserExtensionsTests`, `BrowserBackgroundTests`, and `BrowserContractTests` must keep passing.
2. **Phase 2.** Page-load timing, read next to the network and DNS results.
3. **Phase 3.** MotionMark and JetStream as further optional benchmark kinds, still off by default. Refine seed percentile bands with aggregated samples once enough AC runs exist.

## Requested benchmark runs

`run_benchmark` measures the tests already enabled on that PC. The tests named in the request take effect only after the sequence below. The saved list is often stale: Speedometer is on by default and DeveloperCSharp is off by default, so a pass can measure browsing speed and skip the C# build that was asked for.

When the person asks for specific tests, or to run all benchmarks, set the list and confirm it before starting. That request is the yes to change the saved enabled set.

1. `set_benchmark_tests` with `enabled` empty (`[]`). That turns every test off.
2. `set_benchmark_tests` again with `enabled` set to only the requested ids. For "run all benchmarks", that list is every id in `report.available` (every test with a checkbox). The saved default is not "all".
3. Confirm the enabled list matches that set exactly. `set_benchmark_tests` returns `tests_set` with `report.enabled`. The same fact is in `bench-report-data`: `settings.enabled`, and each `tests` row's `enabled`. On the page, contract 3 marks it on `bench-enable-{Kind}` (`data-bench-test`, `data-enabled`).
4. Call `run_benchmark` only when that list is exactly the requested ids. When it is not, leave the pass unstarted.

Example, C# clean build only:

```
set_benchmark_tests enabled=[]
set_benchmark_tests enabled=["DeveloperCSharp"]
confirm report.enabled is ["DeveloperCSharp"]
run_benchmark
```

Example, every available test:

```
set_benchmark_tests enabled=[]
set_benchmark_tests enabled=[<every id in report.available>]
confirm report.enabled equals that available list
run_benchmark
```

If a named test is unavailable (no checkbox; the page's `reason`), `set_benchmark_tests` returns `invalid_argument` and changes nothing. Say why and leave the pass unstarted.

When a phase exists, the connector exposes it like this:

1. `run_check` and `get_check_result` with check id `BrowserHealth` (phase 1) and `PageLoad` (phase 2).
2. `run_benchmark`, `get_benchmark_results`, and `stop_benchmark` for Speedometer (the auto-selected default Chromium browser, or the explicit browser list passed by the caller) and for MotionMark and JetStream, only after the enabled list has been cleared, set to the requested kinds, and confirmed, as in [Requested benchmark runs](#requested-benchmark-runs). The connector runs each of those kinds only when it is in the confirmed enabled list. The connector returns the usable browser list, and does not substitute `webview2` unless the caller names it.
3. Offered fixes come back from `list_fixes`. `apply_fix` runs one, after approval. The check never applies a fix.

## Open questions

1. The exact JavaScript hook, the result object, and the automation query option (`startAutomatically`, or whatever the pinned release uses) for the Speedometer 3 version we ship. They have changed between releases. Confirm them before the first pinned zip.
2. The CPU-class rules, and the 10th and 25th percentile cuts. Those cuts are a starting point.
3. The fixed page list, and the wording when a captive portal or a blocked network stops the run ("could not run").
4. Firefox in the health check, or Chrome and Edge only until a Firefox reader exists. `BrowserKind` today is Chrome and Edge. Speedometer hides Firefox until RPCD can drive it, which is separate from that reader.
5. Whether a shop-wide baseline is in scope after local samples exist, and who may upload them.
6. Which preference key each browser uses for hardware acceleration, and reporting only when a policy forces it.
