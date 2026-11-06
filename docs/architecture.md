# Architecture

One page on how the app is put together. Design detail lives next to it: [module plugins](module-plugins.md), [agent](agent-design.md),
[versioning](versioning.md), and the [architecture review](architecture-review.md) with the status of each finding.

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
| `src/RemotePCDiagnostics.ModuleUiHost` | net10.0-windows | Renders an unsigned module's own UI out of process, framed in the module page. Gets the module's latest result over stdin. |
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
- Remote mode: a technician drives the same UI through RemoteBlazorWebView. Actions are attributed to the actor and the person at the
  PC is told. There is no separate permission level for remote viewers yet (see the review, 4.2).

## Logging

Every class takes an `ILogger` (one category per class from `AppLoggerFactory`), and each call says its level: `Info`, `Warn` or
`Error` (the `LoggerLines` helpers in Abstractions, so plugins use the same ones). Lines go to the app log file; warnings and errors also
go to the Windows Event Log (Application, source RemotePCDiagnostics). Text whose wording comes from elsewhere (a tool's output) uses
`Line`, which reads the level from the text.
