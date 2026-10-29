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
| Live temperatures and fans | CPU/GPU temperatures, fan speeds, voltages | LibreHardwareMonitor |
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
2. The control registers with the server and the window shows a link `<server>/app/<session-guid>`.
3. The user sends that link to the technician, who opens it in a browser and gets the same Dashboard/Osquery UI, running on the customer PC.
The top bar badge shows Local or Remote. Consent prompt and audit log for remote sessions are still TODO (see Safety).

### Elevation

The Host's `app.manifest` sets `requestedExecutionLevel level="requireAdministrator"`, so Windows prompts for elevation (UAC) at launch. Event-log and sensor modules will need it.

### CI

`.github/workflows/ci.yml` runs on `windows-latest` for push, pull request and manual dispatch: it builds the solution in Release with .NET 10, runs the unit tests, then launches the WPF Host with `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222` and uses Playwright (`tests/smoke/smoke.mjs`, `connectOverCDP`) to check the app stays up and the Dashboard renders. A screenshot, `host.log` (written when `RPD_LOG_FILE` is set) and test results are uploaded as the `ci-artifacts` artifact. Run locally on Windows: build, start the Host with that env var, then `cd tests/smoke && npm install && node smoke.mjs`.
