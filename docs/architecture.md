# Architecture

How the app is put together, as built. [module-plugins.md](module-plugins.md) covers plugins and host queries in detail,
[sensor-thresholds.md](sensor-thresholds.md) has the sources for the sensor alert limits, and [roadmap.md](roadmap.md) holds
everything that is planned but not built.

## Projects

`RemotePCDiagnostics.sln` holds the app, its helpers, the samples and the tests.

| Project | Target | What it is |
| --- | --- | --- |
| `src/RemotePCDiagnostics.Abstractions` | net10.0 | The plugin contract (version 2.0): `IDiagnosticModule`, `IModulePlugin`, `IPluginContext`, `DiagnosticResult`, `AreaReport`, `AreaModuleBase`, `StressModuleBase`, the logging helpers. References only the DI and logging abstractions. |
| `src/RemotePCDiagnostics.Core` | net10.0 | The engine, platform-neutral: `DiagnosticsService`, `ResultStore`, the built-in modules that need administrator and the types every module shares, fixes (`RemediationService`), undo (`UndoService`, change journal), the service workflow, optimizations, the module loader, and interfaces for everything the OS does (`IMemorySystem`, `ISystemSettings`, `IProcessLauncher`, …). Optimizations (`Core/Optimizations`) are one class per suggestion family (browser, Office, services, power, shell, Defender, startup apps, app removal) behind `MemorySuggestionService`. Fixed PowerShell scripts are embedded from `Core/Scripts`. |
| `src/Modules/*` | net10.0 | The built-in modules that don't need administrator, one project and one DLL each (code, page, `module.json`). Built into `builtin-modules\` next to the exe and loaded in process by `ModuleLoader.LoadBundled` (see [module-plugins.md](module-plugins.md#modules-that-ship-with-the-app)). The ones that need administrator stay in Core and Host (`BuiltInModulesPlugin.CompiledIn`). |
| `src/RemotePCDiagnostics.UI` | net10.0 Razor library | Pages and components. Takes optional host services through `AppServices`. |
| `src/RemotePCDiagnostics.Host` | net10.0-windows, WPF | The app: elevated entry point, `HostServices` (the composition root), the Windows adapters (registry, WMI, LibreHardwareMonitor, WASAPI, Direct3D, DXCore), RemoteBlazorWebView and the loopback relay for module UIs. |
| `src/RemotePCDiagnostics.ModuleHost` | net10.0 | Runs one unsigned module out of process (JSON lines over stdin/stdout). |
| `src/RemotePCDiagnostics.ModuleUi` | net10.0 | The `IModuleUi` remote-component contract between the module page and `ModuleUiHost`, and `IModuleUiFrames`. The RemoteComponents source generator writes `ModuleUiFrame` (the page's sandboxed iframe) and `ModuleUiReceiver` from it. |
| `src/RemotePCDiagnostics.ModuleUiHost` | net10.0-windows | Renders an unsigned module's own UI out of process (`RemoteComponentHost`), framed in the module page. Gets the module's latest result over stdin. |
| `src/RemotePCDiagnostics.MemTest` | net10.0 | The RAM stress helper process. |
| `src/RemotePCDiagnostics.Agent.Core` | net10.0 | The agent's pure logic (release manifest, signature, cache, launch rules, backoff); AOT-safe. The contract is `src/RemotePCDiagnostics.Agent/Protos/agent.proto`. |
| `samples/SampleModule`, `samples/SampleModuleUi` | net10.0 | Example plugins (a check, and a check with its own UI). |
| `tests/*` | | xUnit: `RemotePCDiagnostics.Tests` (Core and UI logic), `RemotePCDiagnostics.Host.Tests` (composition root, Windows reads), `RemotePCDiagnostics.Agent.Core.Tests`. |

Standalone tools that reference Core but aren't part of the app are in `tools/prototypes/Prototypes.slnx`: `OutlookBenchmark` and
`NetworkUsagePrototype`. CI builds that solution and publishes both as single exes.

## Layering

```
Abstractions  ←  Core  ←  UI  ←  Host
                  ↑               ↓ starts
                  └── ModuleHost, ModuleUiHost, MemTest (child processes)
```

- Abstractions knows nothing of the app. Core knows nothing of Windows APIs or the UI: it describes what it needs as interfaces, and the
  Host implements them. Tests use fakes for those interfaces, so almost all logic runs without Windows.
- Registry and WMI work happens in process through those interfaces. PowerShell is used only where there is no reasonable in-process
  replacement, from the embedded scripts (`PowerShellScripts.Get`); real Windows tools (dism, sfc, powercfg, pnputil, ipconfig, wevtutil,
  winget) go through `SystemCommandRunner`. The `WindowsReadOnly` test category runs every read-only script and query on a real PC.

## Plugin contract

Modules are DLLs in `%ProgramFiles%\RemotePCDiagnostics\modules` with an embedded `module.json`. The loader reads the manifest before
any code runs and checks the contract version (majors must match; the host's minor must be at least the plugin's).

- Signed with the project key: loaded into its own `AssemblyLoadContext` in the app. The contract assembly and the DI, logging and
  Components assemblies are shared with the host, so types match.
- Unsigned: never loaded into the elevated app. If the person at the PC turned unsigned modules on, the module runs in `ModuleHost`
  and its UI in `ModuleUiHost`, both with a restricted, Medium-integrity token. One-click fixes are stripped from their reports.
- A module's details UI gets `DiagnosticModule` and the latest result (`ModuleDetails.LastResult`, a cascading value).

## Privilege model

- The Host always runs elevated (`requireAdministrator`), because fixes, sensors and event logs need it.
- State the elevated app acts on (change journal, workflow, pending reboot, benchmarks) lives in `%ProgramData%\RemotePCDiagnostics\state`,
  which only Administrators and SYSTEM can write (`ProtectedState`); older copies in `%LOCALAPPDATA%` are moved once at start.
- Settings that belong to the signed-in user (the proxy) are read and written in that user's own registry hive, not the elevated
  account's, which differs when another account's password was typed at the UAC prompt.
- Child processes for untrusted code get a restricted token (Administrators deny-only, privileges removed, Medium integrity).
- Remote mode: a remote user drives the same UI through RemoteBlazorWebView (see [Remote sessions](#remote-sessions)). Actions are
  attributed to the actor ("Local user" or "Remote user") and the person at the PC is told. A remote user who has control has the
  same power as the person at the PC; there is no separate permission level yet ([roadmap](roadmap.md#4-remote-trust-model)).

## Logging

Every class takes an `ILogger` (one category per class from `AppLoggerFactory`), and each call says its level: `Info`, `Warn` or
`Error` (the `LoggerLines` helpers in Abstractions, so plugins use the same ones). Lines go to the app log file; warnings and errors also
go to the Windows Event Log (Application, source RemotePCDiagnostics). Text whose wording comes from elsewhere (a tool's output) uses
`Line`, which reads the level from the text.

## Remote sessions

The app runs once, on the PC, and RemoteBlazorWebView shows its UI in browsers through a relay server (`-u=<server>`). `SessionLaunchOptions`
(Core) reads the command line and environment; `MainWindow` (Host) starts the session.

- **Shared session** (`--mirror`, the default for the shortcuts): the app window opens the app's own page as the owner, in control. The
  join link is the read-only mirror page. The header's session bar (drawn by RemoteBlazorWebView in each browser, over the
  `rbwv-session-controls` placeholder in `MainLayout.razor`) shows a dot while anyone is connected remotely, who has control, and
  Give control / Take control / Copy link. One owner, one remote user (the first to join), any number of read-only viewers.
- **Unattended** (`--unattended`): the same, and the remote user is given control as soon as they join. The owner can take it back.
- **Voice** (`--voice`): a call between the person at the PC and the remote user; needs an https relay.
- **Older one-way modes**: `--reverse-mirror` (the browser only watches), and remote without `--mirror` (only the browser uses the app;
  the window shows a waiting page).
- Mirror, unattended and voice survive the app's own session restarts (`RestartArguments`) and a reboot-and-resume
  (`BuildResumeCommandLine`, `PendingRebootState`).
- A module's own UI is a separate small RemoteBlazorWebView session in an iframe (`ModuleUiHost`). Its control follows the page it is
  on: usable for whoever controls the app, read-only for everyone else.

## Agent

Download-on-demand sessions: a small agent on the PC holds a connection to the relay, and someone on the admin site's Computers page
asks it to start a session. Built so far: the relay side (`AgentHub` / `AgentAdmin` in RemoteBlazorWebView), the admin site's Computers
page (RemoteWebViewAdmin), the contract (`src/RemotePCDiagnostics.Agent/Protos/agent.proto`) and the agent's logic library
(`RemotePCDiagnostics.Agent.Core`: command line, config, release manifest and its signature, consent rule, cache, launch rules, backoff).
The agent program itself is not built; its design is in the [roadmap](roadmap.md#1-agent-program).

## Service workflow fixes

The service workflow (`WorkflowService`, `FixCatalog`) measures the PC, applies the fixes that were approved, restarts as needed and
writes a client report with before and after numbers. Changes go through the change journal so they can be undone (`UndoService`);
permanent ones are marked "can't be undone". Built fixes:

- **Storage cleanups** (`StorageCleanupCatalog`, permanent): developer and AI tool caches (NuGet with version and project-reference
  protection, Playwright, temp), old VS Code versions and superseded extensions, OneDrive logs, stale Chrome and Edge caches in every
  profile, stale Office lock files.
- **App removal**: preinstalled Store and OEM apps with the silent re-install setting, the Xbox group and Game DVR, Lenovo Now and
  Brother PowerENGAGE with their tasks. Store apps with a verified Store id are undone by reinstalling them.
- **Hibernation file**: shrink to the reduced size.
- **Memory and startup**: AI VM services to Manual and `wsl --shutdown`, Windows 11 Widgets off, Search highlights off, Office optional
  connected experiences off (opt-in), the non-default browser no longer running in the background, blocking selected browser extensions
  (opt-in), skipping the Office start screen, Teams not starting with Windows (opt-in), Adobe update services to Manual, vendor service
  candidates, and startup detection for HKCU, HKLM, 32-bit Run entries and packaged startup tasks.
- **Default printer**: Microsoft Print to PDF when the default is a network printer (opt-in).

Several of these were marked "Windows verification pending" when written; what is left to verify and to build is in the
[roadmap](roadmap.md#3-service-workflow-fixes-still-to-build).

## Build identification

The release version is maintained once in `Directory.Build.props` (currently 1.2.0). Bump it for each release.

GitHub Actions builds use `1.2.0-ci.<run-number>.<attempt>+<git-commit>`; the .NET SDK adds the source revision automatically. Developer builds use `1.2.0-local+<git-commit>`. Local builds can contain uncommitted changes; the commit alone does not describe those changes. Builds without Git metadata show an unavailable commit.

Open **About** from the navigation to see the release, full build identity, commit, session, computer, runtime, OS and process architecture. These values describe the app hosting the session, including in remote mode.

Every newly written text-log record includes the full build identity. Every Windows Event Log entry includes a Build field, and structured diagnostic/remediation history records use the full identity for App version (including CSV history exports). The network prototype records it in diagnostics.json. Older saved records keep their original version; no version is guessed retroactively.

CI's UI smoke test checks the About page against the Git commit and CI run that produced the executable.
