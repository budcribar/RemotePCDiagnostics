# RemotePCDiagnostics

One Blazor app that diagnoses a Windows PC, usable on the bench or remotely by a technician who is somewhere else.

## Vision

RemotePCDiagnostics is a single Windows desktop application (a WPF or WinForms host running a Blazor UI in a WebView) made of diagnostic modules. The same UI runs in two ways:

- **Locally, on the bench.** The technician runs the app on the machine in front of them and uses it like any desktop tool.
- **Remotely.** The app runs on the customer's PC and is hosted through [RemoteBlazorWebView](https://github.com/budcribar/RemoteBlazorWebView). The technician, in a browser elsewhere, points at a server and sees and drives the exact same UI: seeing output, triggering scans and reading results.

## Planned diagnostic modules

| Module | What it shows | Data source |
| --- | --- | --- |
| Hardware inventory | Machine model and serial, CPU, RAM, board, OS version, uptime | osquery |
| Disk space and health | Drives, free space, disk models and serials | osquery |
| Services | Services that should be running but are not, exit codes | osquery |
| Installed software and patches | Programs, versions, publishers, installed updates | osquery |
| Network adapter errors | Per-adapter errors and drops, DHCP and DNS settings | osquery |
| System errors | Recent System event log errors | osquery |
| Application crashes | Crash records with exception codes and stack traces | osquery |
| Live temperatures and fans | CPU/GPU temperatures, fan speeds, voltages | LibreHardwareMonitor (+ Windows GPU temperature fallback) |
| Security baseline audit (optional) | Windows hardening checks against published baselines | HardeningKitty |

## Architecture (intended)

- One Blazor host app (WPF or WinForms with BlazorWebView), with one component per module.
- A small collector layer that wraps each data source behind a .NET interface, so modules do not depend on how data is gathered. osquery runs as a bundled process and returns JSON. LibreHardwareMonitor is used as a library, and HardeningKitty runs as a PowerShell module.
- RemoteBlazorWebView hosts the UI so a remote technician can drive it from a browser.
- Admin rights are needed for some modules (event logs, sensors).

## Licensing notes

Planned components are used under their own licenses and need to be confirmed before shipping: osquery (Apache-2.0 or GPL-2.0, used under Apache-2.0), LibreHardwareMonitor (MPL-2.0), HardeningKitty (MIT). This is not legal advice.

## Safety

Running diagnostics on a customer's PC remotely needs the customer's consent, a clear audit log and read-only operations by default.

## Starting, stopping and restarting services

On the **Services** page, open any services list: each row has **Start** (when stopped) or **Stop** / **Restart** (when running).
A confirmation dialog explains what the service is (name and description) and what will happen, and names any running services
that depend on it and will also be stopped. Actions run through `ServiceActionService` (Core) over an injectable `IServiceControlBackend`
(Host: `WindowsServiceControlBackend`, System.ServiceProcess.ServiceController), wait up to 30 s with a Cancel button, then update only that row.
Results are plain ("Print Spooler restarted", "Couldn't stop Windows Update: it didn't respond in time."); technical detail and an
audit line (who/what/when/result) go to the log (RPD_LOG_FILE). A "Recent actions" list (last 20) is shown on the page.

Critical services (RPC, DCOM, LSM/SAM/LSA, Event Log, WMI, crypto, firewall/BFE, Defender/Security Center, DHCP/DNS client, NLA, NSI,
Power, Plug and Play, profiles, user manager, Group Policy, Task Scheduler, TrustedInstaller, Remote Desktop and others — see
`ServiceProtection.Protected`), drivers, and the app's own remote-session components show a lock and "Protected by Windows" with no
Stop/Restart; a stopped protected service may still be started. In Remote mode actions are attributed to "Remote technician" and the
person at the PC gets a pop-up notice; the app cannot tell whether a specific click came from the local window or the remote browser.

## Checks & tests screen

**Checks & tests** (sidebar, between Dashboard and History) puts everything that can be run on one screen, in two collapsible groups:

- **System checks** – the quick read-only checks (Windows error log, crashes, drives, services, programs, network…).
- **Hardware stress & deep scans** – CPU, memory, disk, GPU and network stress tests, plus the security audit (off by default; it runs on its own after the stress tests when ticked).

Each group has a select-all box, "N of M selected", status pills and a **Run selected** button that turns into **Stop** while running. The stress group has a **Quick / Extended** switch (about 1 min / 5 min per test); tests run one at a time and stop automatically if the PC gets too hot or a test fails. Clicking a row (or Enter/Space) opens its details on the right, with **Run just this**. Stopping a run never hides the previous result, and labels show which mode a result came from, e.g. "Passed (short run)". The divider between the list and the details can be dragged or moved with the arrow keys; its position is remembered. Below about 900 px the details stack under the list. Results are still written to the Windows Event Log and appear in History as before.

## Status

Idea stage. This repository currently holds only this README.

## Scaffold (foundation)

> Stubs only. No real diagnostics yet, and no installer exists yet.

### Layout

```
RemotePCDiagnostics.sln
src/
  RemotePCDiagnostics.Core/   net10.0 class library: IDiagnosticModule, DiagnosticResult/Status, DiagnosticsService,
                              ResultStore, ISessionContext (Local/Remote), OsqueryRunner + OsqueryModule (stubs)
  RemotePCDiagnostics.UI/     net10.0 Razor class library: Dashboard, Osquery placeholder page, nav rail, top bar, CSS
  RemotePCDiagnostics.Host/   net10.0-windows10.0.19041.0 WPF host with PeakSWC.RemoteBlazorWebView.Wpf, DI wiring, app.manifest
tests/
  RemotePCDiagnostics.Tests/  xUnit tests for DiagnosticsService and ResultStore
```

### Target framework

.NET 10 (LTS): `net10.0` for Core/UI/Tests, `net10.0-windows10.0.19041.0` for the WPF Host (versioned so the Windows SDK projection needed by WebView2 is included). Requires the .NET 10 SDK.

### How to run

- Tests (any OS): `dotnet test tests/RemotePCDiagnostics.Tests`
- App (Windows, WebView2 runtime required):
  - Local/bench mode: `dotnet run --project src/RemotePCDiagnostics.Host`
  - Remote mode: start a RemoteWebViewService (`dotnet tool update -g PeakSWC.RemoteWebViewService --version 10.*-*`, then `RemoteWebViewService`), and run
    `dotnet run --project src/RemotePCDiagnostics.Host -- -u=https://localhost:5001`. The window shows a link for the technician's browser.
- osquery: `osqueryi.exe` 5.24.0 is bundled from `third_party/osquery/` and copied to the Host output as `tools\osquery\osqueryi.exe` (override with `RPD_OSQUERYI_PATH`). Without it the Osquery module reports a clear "not found" error.
- HardeningKitty: PowerShell module 0.9.4 (MIT) is bundled from `third_party/HardeningKitty/module/` and copied to the Host output as `tools\HardeningKitty\` (override with `RPD_HARDENINGKITTY_PATH`); version/hashes in `third_party/HardeningKitty/README.md`. There is no installer yet — "installed" means it ships inside the Host build/publish folder. The **Security audit** page runs it on demand only (Start/Cancel, 5-minute timeout, not auto-run, not in Run All), in read-only `Audit` mode via `powershell.exe -NoProfile -ExecutionPolicy Bypass` for that process only. A complete audit needs administrator rights (the app manifest requests them).

### Local vs Remote mode

The Host has two Visual Studio launch profiles (`src/RemotePCDiagnostics.Host/Properties/launchSettings.json`); pick one in the Start button dropdown:

| Profile | Settings | Behavior |
|---|---|---|
| **Local** (default) | `REMOTEPC_MODE=Local` | UI renders in the app window only. Running the exe with no settings is also Local (CI uses this). |
| **Remote (Railway)** | `REMOTEPC_MODE=Remote`, `REMOTEPC_SERVER_URL=https://remoteblazor.pagetomovie.com:34544` | The app registers with the relay server (PeakSWC.RemoteWebViewService hosted on Railway) and a technician drives it from a browser. |

Configuration (resolved by `SessionLaunchOptions`, precedence top to bottom):
- `-u=<server url>` command-line arg: forces Remote with that server (the RemoteBlazorWebViewTutorial convention), e.g. `dotnet run --project src/RemotePCDiagnostics.Host -- -u=https://localhost:5001`.
- `REMOTEPC_MODE=Local|Remote` and `REMOTEPC_SERVER_URL` env vars. Remote with no URL uses the default `https://remoteblazor.pagetomovie.com:34544`.
- `-i=<guid>` or `REMOTEPC_ID`: fixed session id. Otherwise a new id is assigned each run.

Server address: the default is the Railway-direct address `https://remoteblazor.pagetomovie.com:34544` (Railway TCP proxy to the container's port 8443; Kestrel TLS with a Let's Encrypt cert, HTTP/2 gRPC). Alternative address: `https://server.remoteblazorwebview.com:34544` (same Railway proxy; the port is required, because plain 443 serves a `*.up.railway.app` cert that does not match). The cert on 34544 is issued to `server.remoteblazorwebview.com` and also covers `remoteblazor.pagetomovie.com` (Let's Encrypt, valid until 2027-01-27). `https://server.remoteblazorwebview.com` (no port) is the planned permanent name once Railway serves a matching cert on 443. Use either via `REMOTEPC_SERVER_URL` or `-u=`.

How a technician connects (per PeakSWC.RemoteBlazorWebView / RemoteBlazorWebViewTutorial):
1. On the customer PC, start the Host in Remote mode (elevated; UAC prompts).
2. The control registers with the server. A native **Remote session** panel at the top of the window shows "Connecting to server…", then "Ready. Share this link with the technician:" with a clickable link `<server>/app/<session-guid>` (opens in the default browser) and a **Copy link** button; it changes to "Technician connected" when the technician joins. If the server isn't reached within ~15 s it shows a friendly "Couldn't reach the server yet: host:port …" warning (details in the host log / `RPD_LOG_FILE`). The link is also shown in the web view, as in the tutorial. Note: the control's `Id`/`ServerUri` must be set before `HostPage` (which is why `HostPage` is set in code, not XAML).
3. The user sends that link to the technician, who opens it in a browser and gets the same Dashboard/Osquery UI, running on the customer PC.
The top bar badge shows Local or Remote. Consent prompt and audit log for remote sessions are still TODO (see Safety).

### Elevation

The Host's `app.manifest` sets `requestedExecutionLevel level="requireAdministrator"`, so Windows prompts for elevation (UAC) at launch. Event-log and sensor modules will need it.

### Stress suite (Dashboard)

Next to **Run all tests** (quick checks only; stress tests stay out of it) the Dashboard has
**Run all + stress tests (short, about 5 min)** and **Run all + stress tests (extended, about 25 min)**. One click, no
confirmation (also in Remote mode; the person at the PC already let the technician in). It runs the quick checks
(`RunAllAsync`), then `DiagnosticsService.RunStressSuiteAsync` runs the stress tests strictly one at a time: CPU,
Memory, Disk, GPU, Network. Short = 1 minute per test (memory in Quick mode); Extended = 5 minutes per test (memory in
Full mode). Each test's time limit/mode is set for the run and restored afterwards. A test that isn't available on this
PC (e.g. no graphics card) is skipped; an overheated or failed test stops the sequence and the rest are marked not run.
Cancel stops the current test and ends the run. Both run buttons are disabled meanwhile, progress reads
"Stress test 2 of 5: Memory", and results show "(short run)"/"(extended run)". The security audit is not included.
Who started it (local user or remote technician) goes to the app log. Times are approximate: quick checks and the
disk test's preparation/clean-up and the network test's capped transfers can add or trim a little; a test already
started from its own page is waited for rather than restarted.

### Network stability test

On-demand only (never auto-run, not part of Run All). It pings the default gateway and public hosts
(`1.1.1.1`, `8.8.8.8`; `NetworkTestSettings.DefaultPublicHosts`) every second for the chosen time limit
(1/2/5/10 min), runs one capped HTTPS download (25 MB) and upload (10 MB) against
`https://speed.cloudflare.com` (`/__down?bytes=N`, `/__up`), and compares Windows adapter error/drop
counters (`Get-NetAdapterStatistics`) before and after. Each transfer is limited to 20 s and to its byte cap.

To use your own speed server instead, set `REMOTEPC_SPEEDTEST_URL` to a base URL that implements the same two
endpoints (`GET {base}/__down?bytes=N` returns N bytes; `POST {base}/__up` accepts the body). No iperf3 is required.
Unit tests use fakes only; CI does not need internet access.

### GPU stress test

On-demand only (never auto-run, not part of Run All). Page: **Graphics (GPU) stress test**; time limit 1/2/5/10/15 min,
Start/Stop, live progress, answers checked, work rate, GPU temperature and fan.

**Approach: built-in Direct3D 11 compute shader via [Vortice.Direct3D11](https://github.com/amerkoleci/Vortice.Windows) (MIT).**
Why this instead of D3D12 or a bundled tool (FurMark/OCCT/etc.):
- D3D11 feature level 11_0 / `cs_5_0` runs on every DirectX 11 GPU including Intel UHD/Iris and AMD Vega/Radeon
  integrated graphics (e.g. Ryzen 7 5700U), with a much simpler, more forgiving API than D3D12 and clean device-removed reporting.
- It lets us *verify* the work: the kernel is integer-only (xorshift + FNV multiply + rotate, mod 2^32), so a healthy GPU must
  match the CPU reference (`GpuStressKernel.Reference`) bit for bit. Floating point is avoided on purpose (drivers may fuse or
  flush denormals legally). Each dispatch runs 262,144 threads; 512 values per dispatch, at a rotating offset, are checked on
  the CPU. Any mismatch = "Graphics errors found". Popular GPU burn-in tools either don't check results or aren't redistributable.
- Managed only: Vortice calls the `d3d11.dll` / `dxgi.dll` / `d3dcompiler_47.dll` that ship with Windows 10/11, so there are no
  native binaries to bundle. The shader is compiled at runtime from `GpuStressKernel.Hlsl`.

Safety and edge cases:
- **TDR:** dispatches are sized adaptively, starting at 64 loop iterations and scaling toward ~150 ms (at most ×2 per step,
  capped at 32,768 iterations); any dispatch over 500 ms halves the work immediately. Windows' TDR timeout is 2 s.
- **Device lost / driver reset:** `DXGI_ERROR_DEVICE_REMOVED/HUNG/RESET/DRIVER_INTERNAL_ERROR` or a failed `GetDeviceRemovedReason`
  ends the test as "Graphics driver stopped responding" (an error).
- **WARP / Microsoft Basic Render Driver** (software flag or vendor 0x1414) is never opened; if it is the only adapter (no driver,
  some Remote Desktop / VM sessions) the result is "No graphics chip could be tested" (warning), never a pass. The test also
  refuses a software device as defense in depth. No adapter at all gives the same headline with a different explanation.
- **Temperatures:** uses the shared sensor provider; shows the GPU temperature when reported (0/missing = no data, common on
  integrated GPUs; if LibreHardwareMonitor has none, the "GPU temperature (from Windows)" fallback below is used) and the GPU fan, else any fan. Stops automatically when any live temperature reaches the red level
  (`SensorLevel.Critical`), like the other stress modules.
- Technical details (adapters, vendor IDs, feature level, HRESULTs, dispatch timings) go only to the log (`RPD_LOG_FILE`).

Unit tests use a fake GPU that computes the CPU reference with scripted faults; CI has no GPU, so the D3D11 path is compiled in CI
but has not been exercised by automated tests.

### Themes

The top bar has a **Dark / System / Light** switch (default **System**, which follows the Windows light/dark setting live via `prefers-color-scheme`). The choice is stored in the web view's `localStorage` (key `rpd-theme`; falls back to an in-memory value if storage is unavailable). In remote mode the technician's browser keeps its own choice. An inline script in `index.html` sets `data-theme` on `<html>` before first paint, so there is no flash. All colors are CSS custom properties defined in `src/RemotePCDiagnostics.UI/wwwroot/app.css` under `:root, [data-theme="light"]` and `[data-theme="dark"]`; add new colors there rather than hard-coding them in markup. The parsing/resolution rules are mirrored in C# (`Core/Theming/ThemePreference.cs`) and unit-tested.

### CI

`.github/workflows/ci.yml` runs on `windows-latest` for push, pull request and manual dispatch: it builds the solution in Release with .NET 10, runs the unit tests, then launches the WPF Host with `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222` and uses Playwright (`tests/smoke/smoke.mjs`, `connectOverCDP`) to check the app stays up and the Dashboard renders. A screenshot, `host.log` (written when `RPD_LOG_FILE` is set) and test results are uploaded as the `ci-artifacts` artifact. Run locally on Windows: build, start the Host with that env var, then `cd tests/smoke && npm install && node smoke.mjs`.

### GPU temperature fallback (from Windows)

When LibreHardwareMonitor reports no valid GPU temperature (0/missing, e.g. AMD Ryzen APU integrated graphics), the app asks
Windows for it the same way Task Manager does: `D3DKMTQueryAdapterInfo(KMTQAITYPE_ADAPTERPERFDATA)` (gdi32, WDDM 2.7+,
Windows 10 2004+/11). The value comes from the GPU driver, so it is shown as "GPU temperature (from Windows)" (not
approximate) on the Temperatures GPU card and used by the GPU stress test; alerts use a conservative 85/95 °C. It only works
when the installed driver fills in the temperature (i.e. when Task Manager shows one). Each source and its result are logged
once to the `RPD_LOG_FILE` log.

### History

The **History** page (sidebar, right under Dashboard) lists past results newest first: Time, Test, Result, Summary,
Duration. Filter by test, result and time range (24 hours / 7 days / 30 days / all), sort by any column, click a row for
measurements (and suite mode, machine, app version). Stress tests with a key measurement (peak CPU/GPU temperature, disk
read speed, download speed) get a small trend of the last 12 runs. In Remote mode the technician sees the bench PC's history.

History is read from the **Windows Event Log** (Application, source RemotePCDiagnostics, event 1100; newest first, at most
5,000 events, XPath time filter for the chosen range) with `EventLogReader`; nothing is stored elsewhere. Retention follows
the Application log's size settings (Event Viewer > Application > Properties). The app never clears the log. If the log
can't be read or the source isn't registered yet, the page says so ("run the app once as administrator so it can register
the event source"). Events written by older builds are parsed as far as possible; unparseable ones are skipped.

### Windows Event Log

Results also go to the Windows Event Log: **Event Viewer > Windows Logs > Application**, filter by source
**RemotePCDiagnostics**. PowerShell:
`Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='RemotePCDiagnostics'} -MaxEvents 50 | Format-List TimeCreated,Id,LevelDisplayName,Message`

| ID | Content |
|----|---------|
| 1000 / 1001 | App start (version, machine model, admin yes/no, Local/Remote mode) / app exit |
| 1100 | One event per finished test (every module and stress test), stable `Key: value` lines: `Test result` (module), `Test`, `Outcome` (OK/Warning/Critical/Cancelled/Unavailable), `Summary`, `Duration`, `Stress suite`, `Finished` (ISO 8601), `Machine`, `App version`, `Format: 2`, then `Measurements:` (`  Name=value`, numbers only) and human-readable `Details:`; security audit lists only failed/warning item IDs and titles (max 25). The History page reads these back. |
| 1110 / 1111 | Stress suite started / finished (outcome and per-test states) |
| 1200 | Fan diagnostic (EC fan, IdeaPad 82R4) lines |
| 1300 | Sensor driver lines (PawnIO / LibreHardwareMonitor) |
| 1900 | Unhandled errors |

Levels: Information, Warning (warning, cancelled, unavailable), Error (critical). The live sensor page refreshes every 5 s,
so its result is logged at most every 10 minutes unless its status changes. The source is created on first run **as
administrator** (Windows requires admin to register an event source); if it can't be created or a write fails, event
logging switches off silently for that run (one note in the file log). Writes run on a background queue and never block the
UI; messages are truncated to 31,000 characters. No server URLs, session ids or raw audit output are written.
`RPD_LOG_FILE` file logging is unchanged and still contains everything (event lines are mirrored as `[event N] ...`).

### Laptop fan from the embedded controller (Lenovo IdeaPad 1 15ALC7 only, experimental)

On **one** model, Lenovo IdeaPad 1 15ALC7 (`Win32_ComputerSystemProduct.Name` = `82R4`), and only when PawnIO is installed,
the app reads two bytes from the laptop's embedded controller (EC): `0x06` (DSDT `FANS`) and `0xFE` (DSDT `FA2S`), plus
the flag bytes `0xAB` (FAN1/FAN2/FAOK) and `0xAD` (SPDN/FNUM) for the log. Access goes through LibreHardwareMonitorLib 0.9.6's
public `LpcAcpiEc` (PawnIO `LpcACPIEC` module, port I/O only) with our own read-only ACPI EC protocol (`AcpiEcReader`): only
the read command `0x80` to port `0x66` and an allowlisted address to `0x62`; nothing is ever written to EC RAM. The shared
`Global\Access_EC` mutex is held per sample (100 ms timeout); samples at most every 2 s; two failed samples => 30 s back-off.
The raw byte is assumed to be RPM/100 (as Linux `yogafan` does on the 15ALC6). **This is unverified on real hardware.**
A reading appears in the existing Fans card as "CPU fan (from laptop controller)" / "Fan 2 (from laptop controller)" only
when plausible (≤ 8000 RPM; 0 RPM only after a non-zero reading this session); a constant 0x00/0xFF stays hidden.
Raw bytes, a 30 s rolling summary and every sample during the CPU stress test are logged ("Fan diagnostic", `RPD_LOG_FILE`).

### CPU temperature fallbacks

LibreHardwareMonitorLib 0.9.5+ reads Ryzen/Intel CPU temperatures through the separately installed **PawnIO** driver
(https://pawnio.eu); it is not bundled (kernel driver, own installer). The app only detects it (logged) and, when no real CPU
temperature is available, shows "CPU temperature needs a sensor driver that isn't available on this PC." If LHM has no valid
CPU temperature: (1) on AMD APUs ("… with Radeon Graphics") the GPU temperature from Windows is shown as
"CPU temperature (approximate, from built-in graphics)" (same chip); (2) last resort, the ACPI thermal zone (approximate).
Approximate readings have no alert threshold. AMD ADL/ADLX expose GPU metrics only (no CPU temperature), so they are not used.
