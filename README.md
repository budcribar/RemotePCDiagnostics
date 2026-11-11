# RemotePCDiagnostics

One Blazor app that diagnoses a Windows PC, usable on the bench or remotely by someone who is somewhere else: a technician, a coworker, a friend.

## Vision

RemotePCDiagnostics is a single Windows desktop application (a WPF or WinForms host running a Blazor UI in a WebView) made of diagnostic modules. The same UI runs in two ways:

- **Locally, on the bench.** The technician runs the app on the machine in front of them and uses it like any desktop tool.
- **Remotely.** The app runs on the customer's PC and is hosted through [RemoteBlazorWebView](https://github.com/budcribar/RemoteBlazorWebView). The remote user, in a browser elsewhere, points at a server and sees and drives the exact same UI: seeing output, triggering scans and reading results.

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
| Speaker to microphone test (optional) | Plays a test tone and checks the speaker output and the microphone heard it | NAudio (WASAPI) |
| Microphone to speaker test (optional) | Plays the microphone through the speaker, mic level, "I heard it" answer | NAudio (WASAPI) |
| Webcam test (optional) | Opens the camera for a few seconds: frame rate, stalls, brightness, black/frozen/overexposed frames | Windows.Media.Capture (WinRT, part of Windows) |
| NPU test (optional) | Finds the NPU (AI accelerator), checks its driver, runs a short matrix-multiply on it vs the CPU | WMI, DXCore, Direct3D 12 (Vortice) |

## Architecture

See [docs/architecture.md](docs/architecture.md): the projects, how they layer, the plugin contract, the privilege model and logging.

## Windows installer

Run `.\publish.ps1` on Windows to build the self-contained Inno Setup installer (`RemotePCDiagnostics-Setup-<Version>-win-x64.exe`) and publish it as the single rolling GitHub pre-release (`.\publish.ps1 -LocalOnly` to build without uploading, or `-IncludePortable` to also build the single-file portable `.exe`). See [installer/README.md](installer/README.md) for prerequisites, WebView2 bootstrapping, silent deployment flags and uninstall options.

## License

RemotePCDiagnostics is released under the [MIT License](LICENSE). The bundled copy of HardeningKitty in `third_party/HardeningKitty` keeps its own license: see [third_party/HardeningKitty/module/LICENSE](third_party/HardeningKitty/module/LICENSE).

## Licensing notes

Planned components are used under their own licenses and need to be confirmed before shipping: osquery (Apache-2.0 or GPL-2.0, used under Apache-2.0), LibreHardwareMonitor (MPL-2.0), HardeningKitty (MIT), NAudio (MIT), Vortice.Direct3D12 (MIT; the NPU test). This is not legal advice.

## Safety

Running diagnostics on a customer's PC remotely needs the customer's consent, a clear audit log and read-only operations by default.

**Consent.** In a supervised session the person at the PC shares the link and gives control from the session bar; they can
take it back at any time, and the remote user cannot take it. Only this app's own window is the owner: the relay checks a
secret the app made for the session, so adding `?role=owner` to the link does nothing. An unattended session gives the remote
user control when they join; choosing that mode when the session is set up is the consent. On a relay that requires sign-in,
the remote user must be signed in and in the session's group.

**Session audit.** Every remote session is recorded in the app's own event log: **Event Viewer > Applications and Services
Logs > RemotePCDiagnostics** (see "Windows Event Log" below). PowerShell:
`Get-WinEvent -FilterHashtable @{LogName='RemotePCDiagnostics';Id=2000,2001,2002,2003,2004,2005,2006} -MaxEvents 50 | Format-List TimeCreated,Id,Message`

| ID | Content |
|----|---------|
| 2000 | Session started (supervised or unattended) |
| 2001 / 2002 | The remote user / a read-only viewer joined, with their signed-in name |
| 2003 / 2004 | Control moved to the remote user (name) / back to the person at this PC |
| 2005 | The remote user or a viewer left |
| 2006 | Session ended (reason) |

Names come from the relay's sign-in; without it they read "(not signed in)". What a remote user changes (services, fixes)
is in the same log's 1100 events, which say who did it. The same lines go to the file log as `[audit N]`.

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
Stop/Restart; a stopped protected service may still be started. In Remote mode actions are attributed to "Remote user" and the
person at the PC gets a pop-up notice; the app cannot tell whether a specific click came from the local window or the remote browser.

## Checks, Stress tests and Security audit pages

The sidebar has three separate items after Service workflow:

- **Checks** (`/checks`) – the quick read-only system checks (everything in Run all: hardware inventory, sensors, drives and disk health, services, programs and patches, network, Windows error log, crashes, resource hogs…).
- **Stress tests** (`/stress`) – CPU, memory, disk speed, GPU and network stability stress tests, then the on-demand audio tests (speaker to microphone, microphone to speaker), the webcam test and the NPU test (hidden entirely on PCs without an NPU). The on-demand tests are not ticked by default and run on their own after the stress tests when ticked.
- **Security audit** (`/security-audit`, also `/module/securityaudit`) – its own page and its own Start; it is not in either list.

Each list has a select-all box, "N of M selected", status pills and a **Run selected** button that turns into **Stop** while running. The Stress tests page has a **Short / Extended** switch (about 1 min / 5 min per test); tests run one at a time and stop automatically if the PC gets too hot or a test fails. Clicking a row (or Enter/Space) opens its details on the right, with **Run just this**. Stopping a run never hides the previous result, and labels show which mode a result came from, e.g. "Passed (short run)". The divider between the list and the details can be dragged or moved with the arrow keys; its position is remembered. Below about 900 px the details stack under the list. Results are still written to the Windows Event Log and appear in History as before.

## Ways to use less memory

On **Resource hogs & uptime** (and via "See ways to use less memory" in the *Top memory consumers* drawer) the app lists suggestions based on what is actually running and installed, sorted by estimated saving, with RAM in use, a "Potential savings" total (only the Close-app suggestions) and "Total freed this session".

| Suggestion | Kind |
|---|---|
| Close a large user app (grouped by name, instance count; one inline confirm; "Force close" only offered after a graceful close fails) | One click |
| Shut down idle .NET build servers (`dotnet build-server shutdown`, the only command allowed) | One click |
| Stop a heavy/Electron app from starting with Windows (HKCU Run / StartupApproved, your account only) | One click + Undo |
| Turn on Chrome Memory Saver / Edge sleeping tabs: browser closed → flips the existing setting in its Local State (Undo restores the file); browser open → opens its settings page | One click or Steps |
| Optional services (Print Spooler w/o printer, Fax, Search indexing, SysMain, DiagTrack, Xbox, Bluetooth w/o devices, Remote Registry, Biometric w/o reader, Geolocation, Retail Demo, Phone, Maps, Lenovo/Adobe/Google/Edge/VS updaters, TeamViewer/AnyDesk, Hyper-V/WSL/Docker when unused): Stop now, Don't start automatically (Manual), Disable — via the existing service control path, protected list enforced, original start-up type recorded for Undo | One click + Undo |
| Restart Visual Studio (over 1.5 GB or open 8+ hours), turn off Live Share, turn off unused extensions | Steps |
| Restart (not Shut down) when Fast Startup is on and the PC has run 4+ hours, or any 3+ days | Steps |
| Defender exclusions for code/build folders (only with dev tools running) | Steps |
| Transparency effects, Widgets | Steps |
| Memory almost full, page-file pressure, memory compression | Info |

After every action the app waits ~2.5 s and shows the measured change ("Freed about 1.0 GB. Available RAM 5.2 → 6.2 GB (used 62% → 52%)"), says so honestly when nothing changed, and says "Takes effect next launch or after a restart" for settings. Nothing is ever applied automatically; every change needs a click (local user or remote user) and is logged as Event 1400. Protected processes (Windows core, security, shell, this app and its WebView2) and protected services are never offered.

**Not yet verified on real hardware:** the Chrome/Edge Local State key names (`performance_tuning.high_efficiency_mode.state`, `performance_tuning.sleeping_tabs.enabled`) — if the key isn't present, only the settings page is offered; Visual Studio extension/Live Share detection paths; printer/Bluetooth/fingerprint detection; graceful close of every app; service start-type changes via the registry (take effect on next boot); the before/after numbers.

## Drive health: Optimize / Retrim SSD

Each SSD card on **Drive health** has a **Last optimized** row, e.g. "6 days ago (by Windows)", "today (by this app)" or "Not reported"
(per drive letter when an SSD has several volumes that differ). **Optimize / Retrim SSD** is offered, on the page and in the service
workflow's fix list, only when at least one of the SSD's volumes was not retrimmed in the last 30 days or the date is unknown.

The date is the newest of:

- **Windows' record:** Application log, provider `Microsoft-Windows-Defrag`, event **258** ("The storage optimizer successfully completed
  retrim on …"), last 60 days, at most 500 events, read-only. The drive letter is taken from the event data ("(C:)"), not the English
  message; events whose operation is defragmentation are skipped. Check on a PC with
  `Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Microsoft-Windows-Defrag';Id=258} -MaxEvents 5`.
- **This app's record:** every successful Optimize / Retrim SSD fix is saved per letter to `%LOCALAPPDATA%\RemotePCDiagnostics\retrim.json`,
  so the next check (e.g. the workflow's second pass) sees it at once, without waiting for Windows' event.

## Service workflow: Windows repair (DISM / SFC)

The workflow's Checking stage also runs the two integrity scans (DISM `/ScanHealth` and `sfc /verifyonly`), reusing results that already
finished on the Checks page. Repair fixes appear under **Windows repair** in Review only when a scan found corruption:

- **Repair Windows component store (DISM RestoreHealth):** `dism.exe /English /Online /Cleanup-Image /RestoreHealth` (45 min timeout,
  progress shown). Offered only when ScanHealth found corruption. If ScanHealth says the store "cannot be repaired", it is still offered,
  with a note that it needs a repair source or Windows Update.
- **Repair protected system files (SFC):** `sfc.exe /scannow`. Offered when `sfc /verifyonly` found violations, or whenever the DISM repair is offered.

Both are ticked by default, need administrator rights, are allowed in remote mode and cannot be undone. When both run, DISM goes first and SFC
second. If either asks for a restart (exit code 3010 or restart/pending text), this is recorded. The workflow's restart after the fixes then covers it,
and after the after-benchmark the scans run again. The client report has a **Windows repair** section with each result, its exit code, the command,
the cleaned output and, on failure, CBS/DISM log excerpts. Results:

- SFC "repaired" → OK, "unable to fix" → Error, nothing found → OK.
- DISM restore success → OK.
- `0x800f081f` (no source), `0x800f0906` (download failed), `0x800f0954` (blocked by policy) → Error with a plain explanation.

Localized SFC output is judged by the exit code plus CBS.log `[SR]` lines. **Not yet verified on real hardware:** the repairs have only
been exercised with fakes.

## Status

Idea stage. This repository currently holds only this README.

## Scaffold (foundation)

### Download a build for testing

After a successful GitHub Actions **CI** run, download the **RemotePCDiagnostics-win-x64** artifact from the run's **Artifacts** section. Extract GitHub's ZIP and run `RemotePCDiagnostics.Host.exe`. This is a single self-contained executable for Windows x64: testers do not need the .NET SDK or runtime. The Microsoft Edge WebView2 runtime is still required, and Windows requests administrator permission at launch.

The executable extracts its bundled runtime, helper programs, audit scripts and web assets to the .NET extraction cache on first launch. Keep the downloaded executable in a stable location while testing restart/resume workflows. CI verifies the bundled files and runs its UI smoke test against this published executable.

To create the same build locally:

```powershell
dotnet publish src/RemotePCDiagnostics.Host/RemotePCDiagnostics.Host.csproj -c Release -r win-x64 --self-contained true -p:PublishProfile=Portable -p:DebugType=None -p:DebugSymbols=false -o artifacts/RemotePCDiagnostics-win-x64
```

`RemotePCDiagnostics.Host.exe --verify-package` checks the extracted helper and web files and runs a one-second, 1 MB helper self-test, then exits without opening the UI or running machine scans. Exit code 0 means the package check passed.

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

- Tests (any OS): `dotnet test --project tests/RemotePCDiagnostics.Tests` (xunit.v3 on Microsoft.Testing.Platform, switched on in `global.json`)
- App (Windows, WebView2 runtime required):
  - Local/bench mode: `dotnet run --project src/RemotePCDiagnostics.Host`
  - Remote mode: start a RemoteWebViewService (`dotnet tool update -g PeakSWC.RemoteWebViewService --version 10.*-*`, then `RemoteWebViewService`), and run
    `dotnet run --project src/RemotePCDiagnostics.Host -- -u=https://localhost:5001`. The window shows the app; **Copy link** in its header gives the link for the remote user's browser.
- osquery: `osqueryi.exe` 5.24.0 is bundled from `third_party/osquery/` and copied to the Host output as `tools\osquery\osqueryi.exe` (override with `RPD_OSQUERYI_PATH`). Without it the Osquery module reports a clear "not found" error.
- HardeningKitty: PowerShell module 0.9.4 (MIT) is bundled from `third_party/HardeningKitty/module/` and copied to the Host output as `tools\HardeningKitty\` (override with `RPD_HARDENINGKITTY_PATH`); version/hashes in `third_party/HardeningKitty/README.md`. There is no installer yet — "installed" means it ships inside the Host build/publish folder. The **Security audit** page runs it on demand only (Start/Cancel, 5-minute timeout, not auto-run, not in Run All), in read-only `Audit` mode via `powershell.exe -NoProfile -ExecutionPolicy Bypass` for that process only. A complete audit needs administrator rights (the app manifest requests them).

### Local vs Remote mode

The Host has four Visual Studio launch profiles (`src/RemotePCDiagnostics.Host/Properties/launchSettings.json`). Visual Studio starts the first one unless you pick another in the Start button dropdown:

| Profile | Settings | Behavior |
|---|---|---|
| **Remote** (default in Visual Studio) | `REMOTEPC_MODE=Remote`, `REMOTEPC_SERVER_URL=https://remoteblazorwebview.com:34544` | The app registers with the relay server (PeakSWC.RemoteWebViewService hosted on Railway) and a remote user joins from a browser. This window opens the full app with the user in control; the shared link is the read-only `/mirror/<id>` page. The user gives control to the remote user and takes it back from the session bar in the header; whoever doesn't hold control sees a live, read-only view. |
| **Remote + voice** | Remote, plus `REMOTEPC_VOICE=1` (command line: `--voice`) | Same, with a voice call between the person at the PC and the remote user. |
| **Remote (unattended)** | Remote, plus `REMOTEPC_UNATTENDED=1` (command line: `--unattended`) | The remote user gets control as soon as they open the link, with nobody at the PC handing it over. The user can still take control back. The setting survives the app's own session restarts and a reboot-and-resume. Without this setting a session is supervised: the user starts in control and gives it. |
| **Local** | `REMOTEPC_MODE=Local` | UI renders in the app window only. Running the exe with no settings is also Local (CI uses this). |

A remote session has one user (this PC, the owner), one remote user and any number of read-only viewers, all on the same link. The first person to open the link is the remote user; anyone after that only watches, with no control and no voice. Module panels follow control too: they are usable for whoever has control and read-only for everyone else. Details: RemoteBlazorWebView README, "Sharing control".

Every remote session is shared in this way. The older one-way modes (`--reverse-mirror`, and Remote without `--mirror`) are gone; those switches are ignored if passed.

Configuration (resolved by `SessionLaunchOptions`, precedence top to bottom):
- `-u=<server url>` command-line arg: forces Remote with that server (the RemoteBlazorWebViewTutorial convention), e.g. `dotnet run --project src/RemotePCDiagnostics.Host -- -u=https://localhost:5001`.
- `REMOTEPC_MODE=Local|Remote` and `REMOTEPC_SERVER_URL` env vars. Remote with no URL uses the default `https://remoteblazorwebview.com:34544`.
- `-i=<guid>` or `REMOTEPC_ID`: fixed session id. Otherwise a new id is assigned each run.
- `--unattended` or `REMOTEPC_UNATTENDED=1`, and `--voice` or `REMOTEPC_VOICE=1`: see the profiles above.

Server address: the default is the Railway-direct address `https://remoteblazorwebview.com:34544` (Railway TCP proxy to the container's port 8443; Kestrel TLS with a Let's Encrypt cert, HTTP/2 gRPC). Alternative address: `https://server.remoteblazorwebview.com:34544` (same Railway proxy; the port is required, because plain 443 serves a `*.up.railway.app` cert that does not match). The cert on 34544 is issued to `server.remoteblazorwebview.com` and also covers `remoteblazorwebview.com` and `remoteblazor.pagetomovie.com` (Let's Encrypt, valid until 2027-01-27). `https://server.remoteblazorwebview.com` (no port) is the planned permanent name once Railway serves a matching cert on 443. Use either via `REMOTEPC_SERVER_URL` or `-u=`.

How a remote user connects (any remote session):
1. On the customer PC, start the Host in Remote mode (elevated; UAC prompts).
2. The window opens the full app with the person at the PC in control. The session bar in the header shows a dot (red while anyone is connected remotely), who has control, and **Copy link**. If the server isn't reached within ~15 s the window shows a short "Remote session not connected" notice instead (details in the host log / `RPD_LOG_FILE`). Note: the control's `Id`/`ServerUri` must be set before `HostPage` (which is why `HostPage` is set in code, not XAML).
3. The user presses **Copy link** and sends the link (`<server>/mirror/<session-guid>`) to the remote user, who opens it in a browser and sees the same UI, running on the customer PC, read-only at first.
4. The user presses **Give control** to let the remote user drive, and **Take control** to get it back. In an unattended session the remote user gets control as soon as they join.
The top bar badge shows Local or Remote. Consent prompt and audit log for remote sessions are still TODO (see Safety).

### Elevation

The Host's `app.manifest` sets `requestedExecutionLevel level="requireAdministrator"`, so Windows prompts for elevation (UAC) at launch. Event-log and sensor modules will need it.

### Stress suite (Dashboard)

The Dashboard banner is one compact row: health status on the left (problem names link to the page that shows that test),
**Run all checks** (quick checks only; stress tests stay out of it), **Run checks + stress tests (short)** (about 5 min) and
**Run checks + stress tests (extended)** (about 25 min) on the right; the times are in the buttons' tooltips. Under the status, small
text shows "Last checked …", "N on-demand tests not run" (links to Stress tests) and "security audit not run" (links to Security audit). One click, no
confirmation (also in Remote mode; the person at the PC already let the remote user in). It runs the quick checks
(`RunAllAsync`), then `DiagnosticsService.RunStressSuiteAsync` runs the stress tests strictly one at a time: CPU,
Memory, Disk, GPU, Network. Short = 1 minute per test (memory in Quick mode); Extended = 5 minutes per test (memory in
Full mode). Each test's time limit/mode is set for the run and restored afterwards. A test that isn't available on this
PC (e.g. no graphics card) is skipped; an overheated or failed test stops the sequence and the rest are marked not run.
Cancel stops the current test and ends the run. Both run buttons are disabled meanwhile, progress reads
"Stress test 2 of 5: Memory", and results show "(short run)"/"(extended run)". The security audit is not included.
Who started it (local user or remote user) goes to the app log. Times are approximate: quick checks and the
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

### Audio tests (speaker and microphone)

Two on-demand tests on the Stress tests page, listed after the stress tests. They are a separate step:
never auto-run, not in Run All, not part of the stress run (when ticked there, they run on their own after it), and not ticked by default.
No confirmation prompt; nothing needs a click at the PC (no Windows dialogs). Both pages list the speakers and microphones
(Windows default preselected, USB/Bluetooth marked where Windows reports it), can be cancelled, and stop on a timeout.
Audio access is behind `IAudioIo` (Core); the Windows implementation is `WasapiAudioIo` in the Host (NAudio.Wasapi, shared-mode WASAPI).

- **Speaker to microphone test** plays a 3 s, 1 kHz tone (at most -12 dBFS, 200 ms fade in and out) while recording the microphone
  and the speaker output (WASAPI loopback) at the same time. Each recording is checked for the tone (Goertzel, 50 ms blocks):
  tone level, noise, SNR, peak and RMS in dBFS are shown. The tone counts as found at 10 dB SNR and -75 dBFS or more.

  | Speaker output (loopback) | Microphone | Result |
  | --- | --- | --- |
  | tone | tone | Pass (Warning if the microphone clipped) |
  | tone | no tone | Fail: speaker dead or muted, volume too low, or microphone muted / level too low |
  | no tone | no tone | Fail: volume, mute, wrong output device or driver |
  | no tone | tone | Pass (loopback could not confirm) |
  | not available | tone / no tone | Pass / Fail (microphone only) |
  | Windows privacy blocks the microphone | – | "Microphone access is blocked by Windows privacy settings (Settings > Privacy & security > Microphone)." |

- **Microphone to speaker test** plays the microphone through the speaker live for 5–30 s (default 10 s) at a capped gain (-6 dB),
  with a fade-in. It measures the microphone peak/RMS; no sound at all is a fail. Whether it was heard is up to the person at the PC:
  "I heard it" / "I didn't hear it" sets Pass / Fail. Over a remote session the remote user can't hear the PC.

Caveats: full duplex can howl when the microphone hears the speaker. A brake stops the monitor when the peak stays above -3 dBFS for
250 ms or a tone-like signal keeps growing, and turns the gain down as soon as a loud tone-like signal appears; the mic-to-speaker test
then re-runs once in half-duplex (record, then play back). Both pages have a "Half-duplex (play, then record)" switch; for the speaker
test it plays the tone twice and records the speaker output and the microphone one at a time. Raw microphone mode
(`AUDCLNT_STREAMOPTIONS_RAW`, to skip echo cancellation and noise suppression) is requested and dropped quietly if the driver refuses.
No speaker or no microphone gives a "Skipped" warning, never a crash; CI machines have no audio devices, so unit tests use fakes and
synthetic signals. Real behaviour (levels, raw mode, feedback brake) still needs checking on hardware.

### Webcam test

On-demand, on the Stress tests page after the audio tests; same rules as the audio tests (never auto-run, not in Run All, not part of
the stress run, runs on its own after it when ticked, not ticked by default, no confirmation prompt, Stop/Cancel and app close cancel it).
Camera access is behind `IWebcamIo` (Core); the Windows implementation is `MediaCaptureWebcamIo` in the Host (`MediaCapture` +
`MediaFrameReader` from the Windows SDK projection the Host already targets, so no new package). The page lists the cameras
(built-in / USB marked where Windows reports it; built-in first and preselected) and captures for 3, 5 (default) or 10 s, hard-capped at 30 s.
The camera is opened at the largest format up to 1280×720 and 30 fps; each frame is reduced to a 160-pixel-wide luma thumbnail and only
running totals plus the previous thumbnail are kept. **No frame or image is saved, shown or sent** (no preview); the camera is always closed.

| Result | Status |
| --- | --- |
| No camera | Skipped (warning) |
| Windows camera privacy blocks it (ConsentStore `webcam`, or access denied) | Error: "Camera access is blocked by Windows privacy settings…" |
| Camera in use by another app (and shared read-only also fails) | Error: close the other app |
| Opened but no frames | Fail |
| ≥ 90 % black frames | Warning: covered lens or privacy shutter closed |
| ≥ 90 % identical consecutive frames | Fail: frozen picture |
| Effective frame rate < 10 fps | Warning |
| A gap of more than 1 s between frames | Warning: stall |
| ≥ 50 % of frames mostly blown out / mean brightness < 40 | Warning: overexposed / too dark |
| Otherwise | Pass |

Caveats: thresholds are first guesses and need checking on real cameras (IR/Windows Hello cameras, virtual cameras and some drivers
may behave differently). If another app holds the camera, the test reads it in shared mode at that app's format and says so.
A camera in a very dark room can count as "black". CI has no camera, so unit tests use synthetic frames.

### NPU test

On-demand, like the audio tests: listed after the security audit and the audio tests, never in Run All or the stress run (when ticked it
runs on its own after it), not ticked by default, no prompts. Page: **NPU (AI accelerator) test**, length 5/10/30/60 s (default 10 s,
capped at 60 s). Access is behind `INpuIo` (Core, `NullNpuIo` for CI); the Windows implementation is `WindowsNpuIo` in the Host.

**Shown only on PCs with an NPU.** At startup the app checks once, in the background, for an NPU (same detection as below, cached,
20 s cap). If none is found, or the check fails or times out, the NPU test is hidden everywhere: not in the Stress tests list, the
selection or the separate-step run, not on the dashboard or in navigation, and it can't be run. Opening its page directly says
"No NPU detected on this machine." There is no "Skipped: No NPU found" result in the app any more.

- **Detection**: `Win32_PnPEntity` devices in the `ComputeAccelerator` class or named like an NPU (Intel AI Boost, AMD IPU / NPU Compute
  Accelerator, Qualcomm Hexagon NPU), with status, problem code and driver version (`Win32_PnPSignedDriver`), merged with DXCore adapters
  (`dxcore.dll`, plain COM interop) that have the NPU hardware-type attribute (or, on older Windows, ML support without graphics).
- **Workload**: Direct3D 12 on the NPU's own DXCore adapter. NPUs with "core compute" run a 256×256 float32 matrix-multiply compute shader;
  the first result is compared with a CPU reference, then it repeats for the chosen length (GFLOPS, ms per run). ML-only NPUs
  (feature level 1_0_GENERIC, no shaders) get a buffer copy on their compute queue, checked byte for byte: this proves the driver accepts and
  completes work, but not the math. A watchdog (length + 15 s) abandons a hung driver call; Stop and closing the app cancel it.

| Situation | Result |
| --- | --- |
| No NPU | Test hidden (if run directly from code: Warning "Skipped: No NPU found.") |
| Driver problem code / status Error | Fail with the Device Manager problem text |
| Listed but no DirectX adapter (compute driver not loaded) | Fail |
| Workload throws, device removed, or times out | Fail |
| Max error vs CPU > 0.01 | Fail |
| More than 20× slower than one CPU core | Warning |
| ML-only NPU, copy round-trip OK | Warning (driver healthy, math not checked) |
| Matrix multiply matches, fast enough | Pass with GFLOPS |

Caveats: ONNX Runtime / DirectML is not used (its C# API selects DXGI adapters only, which NPUs are not, and the package adds ~20 MB of native
DLLs), so a real ML operator run on ML-only NPUs (Intel AI Boost is one) is not verified. Unit tests use fakes and synthetic matrices; the
DXCore/D3D12 path still needs checking on NPU hardware.

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

The top bar has a **Dark / System / Light** switch (default **System**, which follows the Windows light/dark setting live via `prefers-color-scheme`). The choice is stored in the web view's `localStorage` (key `rpd-theme`; falls back to an in-memory value if storage is unavailable). In remote mode the remote user's browser keeps its own choice. An inline script in `index.html` sets `data-theme` on `<html>` before first paint, so there is no flash. All colors are CSS custom properties defined in `src/RemotePCDiagnostics.UI/wwwroot/app.css` under `:root, [data-theme="light"]` and `[data-theme="dark"]`; add new colors there rather than hard-coding them in markup. The parsing/resolution rules are mirrored in C# (`Core/Theming/ThemePreference.cs`) and unit-tested.

### CI

An experimental [network usage history prototype](tools/prototypes/NetworkUsagePrototype/README.md) exports a top-25 HTML report and raw CSV/JSON from Windows' existing history. CI publishes `NetworkUsagePrototype.exe` in `ci-artifacts/NetworkUsagePrototype` and smoke-tests it with explicitly synthetic demo data. Real history collection is run by the user on the target laptop; it is not part of automated optimizations or the final client report yet.

The dedicated **Service workflow (simulated restarts)** job runs `WorkflowTests` separately and uploads `service-workflow-results`. It checks review/approval, restart sequencing, saved workflow and benchmark JSON loaded into fresh service instances after each simulated restart, client reporting, cancellation, and sign-in cleanup. OS actions and measurements use fakes: this job does not reboot the runner, configure automatic sign-in, install updates, or delete user files. It does not validate the real Windows restart/resume task or registry integration.

Run this coverage locally with `dotnet test --project tests/RemotePCDiagnostics.Tests/RemotePCDiagnostics.Tests.csproj -c Release --filter-class RemotePCDiagnostics.Tests.WorkflowTests`.

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
read speed, download speed) get a small trend of the last 12 runs. In Remote mode the remote user sees the bench PC's history.

History is read from the **Windows Event Log** (the RemotePCDiagnostics log, source RemotePCDiagnostics, event 1100; newest first, at most
5,000 events, XPath time filter for the chosen range) with `EventLogReader`; nothing is stored elsewhere. Retention follows
the log's size (20 MB). The app never clears the log. If the log
can't be read or the source isn't registered yet, the page says so ("run the app once as administrator so it can register
the event source"). Events written by older builds are parsed as far as possible; unparseable ones are skipped.

### Windows Event Log

Results also go to the Windows Event Log, in the app's own log: **Event Viewer > Applications and Services Logs >
RemotePCDiagnostics** (source **RemotePCDiagnostics**; 20 MB, oldest entries overwritten when full). PowerShell:
`Get-WinEvent -LogName RemotePCDiagnostics -MaxEvents 50 | Format-List TimeCreated,Id,LevelDisplayName,Message`

Earlier versions wrote to **Windows Logs > Application**. On a PC with such events the app moves once: it copies its events
into the new log (each keeps its original time in its text) and registers its source there. Windows may keep sending the
source's events to Application until the PC restarts; the app checks at each start, keeps reading History from Application
until then, and adds whatever was written in between. Nothing is cleared: the old copies stay in Application until Windows
overwrites them (Event Viewer shows them with a "description cannot be found" note). Progress is in the file log
("Event log move") and `%ProgramData%\RemotePCDiagnostics\migration\logmove.json`.

| ID | Content |
|----|---------|
| 1002 | Written during the one-time move to the app's own log, to see where Windows puts events |
| 2000 - 2006 | Session audit (see "Safety") |
| 1000 / 1001 | App start (version, machine model, admin yes/no, Local/Remote mode) / app exit |
| 1100 | One event per finished test (every module and stress test), stable `Key: value` lines: `Test result` (module), `Module id` (the module's permanent GUID), `Test`, `Instance id` and `Instance` (for a per-device test: the drive, GPU or webcam), `Outcome` (OK/Warning/Critical/Cancelled/Couldn't run/Skipped/Blocked), `Summary`, `Duration`, `Stress suite`, `Finished` (ISO 8601), `Machine`, `App version`, `Format: 3`, then `Measurements:` (`  Name=value`, numbers only) and human-readable `Details:`; security audit lists only failed/warning item IDs and titles (max 25). The History page reads these back. |
| 1110 / 1111 | Stress suite started / finished (outcome and per-test states) |
| 1200 | Fan diagnostic (EC fan, IdeaPad 82R4) lines |
| 1300 | Sensor driver lines (PawnIO / LibreHardwareMonitor) |
| 1400 | Memory suggestion applied / undone (actor, action, target, result, before/after memory) |
| 1800 | Module plugin found at startup: loaded, or disabled with the reason (unsigned, signature does not match, contract version, duplicate id) |
| 1900 | Unhandled errors |

Levels: Information, Warning (warning, cancelled, unavailable), Error (critical). The live sensor page refreshes every 5 s,
so its result is logged at most every 10 minutes unless its status changes. The source is created on first run **as
administrator** (Windows requires admin to register an event source); if it can't be created or a write fails, event
logging switches off silently for that run (one note in the file log). Writes run on a background queue and never block the
UI; messages are truncated to 31,000 characters. No server URLs, session ids or raw audit output are written.
**File log (on by default).** Everything the app logs goes to `%LOCALAPPDATA%\RemotePCDiagnostics\logs\RemotePCDiagnostics.log`
(event lines are mirrored as `[event N] ...`). It rolls over at 5 MB and keeps the five older files (`RemotePCDiagnostics.1.log` to `.5.log`),
so a technician can send that folder. Setting `RPD_LOG_FILE` writes to that path instead, without rolling (CI uses this).
Besides the categories above, any other line that reads as a warning or an error (for example "failed", "couldn't", "timed out",
"overran", an exception) is also written to the Event Log: warnings as event 1910, errors as event 1900. The same text is let
through once per five minutes and at most 30 entries per minute, so a repeating problem can't flood the Event Log.

**Stress-test cleanup is owned by the runner.** Each stress test registers what it holds (CPU worker threads, the memory-test helper process, the
disk test file, the GPU device, the network speed test) with a `StressCleanup` as soon as it has it. After every test, however it ended (finished,
stopped, failed, timed out and skipped by the hang watchdog), the runner calls the module's `CleanupAsync()` on its own thread with a 10 second
limit (a warning is logged if it takes longer). Cleanup runs newest first, each action once, never throws, and is safe to call twice.

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
