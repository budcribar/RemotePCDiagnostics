# Architecture Review: `RemotePCDiagnostics`

Date: November 5, 2026

## 1. System Topology & Layering

```
                    ┌──────────────────────────────────────────────────────────┐
                    │         RemotePCDiagnostics.Abstractions (net10.0)       │
                    │  Contracts: IDiagnosticModule, IModulePlugin, AreaReport │
                    │  Zero OS/UI dependencies — shared across ALC boundaries  │
                    └────────────────────────────┬─────────────────────────────┘
                                                 │
                    ┌────────────────────────────▼─────────────────────────────┐
                    │             RemotePCDiagnostics.Core (net10.0)           │
                    │  DiagnosticsService, WorkflowService, RemediationService │
                    │  MemorySuggestionService, UndoService, ModuleLoader      │
                    │  Pure interfaces for OS I/O (IMemorySystem, INpuIo, etc.)│
                    └─────────────┬──────────────────────────────┬─────────────┘
                                  │                              │
            ┌─────────────────────▼────────────┐   ┌─────────────▼─────────────┐
            │   RemotePCDiagnostics.UI         │   │  Child / Helper Processes │
            │   (Razor Class Library)          │   │  • ModuleHost (stdin/out) │
            │   Pages, Shared components       │   │  • ModuleUiHost (WPF+RBWV)│
            └─────────────────────┬────────────┘   │  • MemTest (RAM stress)   │
                                  │                └─────────────▲─────────────┘
                    ┌─────────────▼──────────────────────────────┴─────────────┐
                    │       RemotePCDiagnostics.Host (net10.0-windows, WPF)    │
                    │  Elevated entry point, HostServices composition root,    │
                    │  Windows adapters (WMI/LHM/WASAPI/D3D11/D3D12),          │
                    │  RemoteBlazorWebView client + Embedded loopback relay    │
                    └──────────────────────────────────────────────────────────┘
```

Not shown: Core also references `RemotePCDiagnostics.Agent.Core` (used by `ModuleLoader`), and `OsqueryRunner` and `SystemCommandRunner` live in Core and start processes through `IProcessLauncher`. The two prototypes (`OutlookBenchmark`, `NetworkUsagePrototype`) reference Core and are in the main solution.

---

## 2. Key Architectural Strengths

1. **Strict Port/Adapter Separation Between `Core` and `Host`**:
   - `src/RemotePCDiagnostics.Core` targets plain `net10.0` (no `-windows` TFM, no WPF/WinRT/COM/WMI references). All OS-touching operations sit behind narrow interfaces (`IMemorySystem`, `IServiceControlBackend`, `ISensorProvider`, `IGpuDeviceFactory`, `IAudioIo`, `INpuIo`, `IProcessLauncher`).
   - This makes most of the domain logic fast and deterministically testable in `tests/RemotePCDiagnostics.Tests` without mocking frameworks or administrator privileges.

2. **Extracted Testable Composition Root (`HostServices`)**:
   - Moving container registration out of `src/RemotePCDiagnostics.Host/MainWindow.xaml.cs` into `HostServices.AddRemotePCDiagnosticsHost` (`src/RemotePCDiagnostics.Host/HostServices.cs`) allows `tests/RemotePCDiagnostics.Host.Tests/HostServicesTests.cs` to validate the entire DI graph with `ValidateOnBuild = true` and `ValidateScopes = true` without spinning up a WPF window.
   - Routing built-in modules through `BuiltInModulesPlugin` and `PluginRegistrar` ensures built-in and third-party modules exercise the exact same registration and catalog pipeline.

3. **Three-Tier Plugin & Check Extensibility Model (`docs/module-plugins.md`)**:
   - **Data-only checks (`JsonCheck`)**: Declarative JSON + read-only `osquery` SQL, requiring zero code execution.
   - **Signed plugins (`ModuleLoader`)**: Verified with ECDSA P-256 over the exact `byte[]`, then loaded from that in-memory `byte[]` (eliminating TOCTOU between signature verification and assembly load) into a per-module `ModuleLoadContext`. Two caveats: the manifest is parsed from every DLL's PE metadata in the elevated process, signed or not, so `ModuleManifest`'s bounds checks are part of the security boundary; and the load context isolates dependency versions only (anything not embedded resolves from the default context), so it is not a security boundary for signed code.
   - **Unsigned plugins (`RestrictedModuleHostLauncher` + `ModuleUiFrames`)**: Never loaded into the elevated process; executed out-of-process with a restricted LUA token (`BUILTIN\Administrators` deny-only, privileges stripped, Medium integrity) and rendered in an opaque-origin `<iframe sandbox="allow-scripts allow-forms">` via an in-process loopback `RemoteWebViewServer` relay.

4. **Per-Device Instance Model & Dependency Graph in `DiagnosticsService`**:
   - Multi-instance hardware detection (`IDetectableModule` for drives, GPUs, webcams, NPUs) is unified with per-device dependency gating (`GateForDependency`) and cycle rejection (`RejectDependencyCycles`).

---

## 3. Architectural Trade-Offs & Areas for Evolution

### 3.1 Dual Module Instantiation Between `ModuleHost` and `ModuleUiHost`
- **Where**: `src/RemotePCDiagnostics.Core/Plugins/UserModeModules.cs` (`UserModeModuleProxy`) vs. `src/RemotePCDiagnostics.ModuleUiHost/Program.cs`
- **Observation**: For an unsigned module with `"hasUi": true` (like `samples/SampleModuleUi`), two separate restricted child processes are spawned:
  1. `RemotePCDiagnostics.ModuleHost.exe` (headless JSON-over-stdio pipe) owns the `IDiagnosticModule` instance used by "Run check" / "Run All" and `ResultStore`.
  2. `moduleui\RemotePCDiagnostics.ModuleUiHost.exe` (off-screen WPF window + WebView2 + `RemoteBlazorWebView`) loads a **second, independent** instance of `IDiagnosticModule` solely to render `DetailsComponent`.
- **Impact**:
  - As noted in `docs/module-plugins.md`, the `DetailsComponent` inside `ModuleUiHost` does not receive the `DiagnosticResult` or `AreaReport` produced when the user clicks "Run check" in the main app, nor do actions in the custom UI update the main app's `ResultStore`.
  - Additionally, every unsigned module UI spins up its own off-screen WPF `Window` + full Chromium `WebView2` browser tree (`ModuleUiHost.exe` -> `msedgewebview2.exe` processes) plus a gRPC stream to the loopback relay just to HTML-project its Razor component back into an `<iframe>` in the main window's `WebView2`.
- **Recommendation**:
  - Pass the latest `DiagnosticResult` / `AreaReport` from the host to `ModuleUiHost` (either over stdin/pipe or as an initial state payload) so a custom `DetailsComponent` in `ModuleUiHost` can render the result of the host's diagnostic run rather than starting blank.

---

### 3.2 God-Object Growth in `IMemorySystem` / `WindowsMemorySystem`
- **Where**: `src/RemotePCDiagnostics.Core/Memory/MemorySuggestionService.cs` (`IMemorySystem`, about 55 members, about 40 of them default-implemented) and `src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs` (~1,630 lines across 3 partial files)
- **Observation**: Originally scoped to RAM and startup apps, `IMemorySystem` has become the catch-all OS abstraction for:
  - RAM & process working sets
  - Windows Services start types & delayed autostart
  - Browser Local State JSON & extension policy blocks
  - Storage cleanup scanning & execution (`StorageCleanupEngine`, DISM `/ResetBase`, `powercfg /h`)
  - Registry allowlist reads/writes (Search indexing, Widgets, Game DVR, Sticky Keys, delivery optimization, telemetry, Copilot, Bing search, Windows feeds, Office start screen)
  - Scheduled tasks, default printer, power plans, pagefile sizing, Win32/Store app uninstall & Store reinstall
- **Impact**: The default interface methods keep the 20 hand-written test doubles (across 16 files in `tests/RemotePCDiagnostics.Tests`) small, but they also mean a method the Windows adapter forgets to implement silently returns "Not supported on this PC" instead of failing to compile, and one interface spans six unrelated areas.
- **Recommendation**: Split `IMemorySystem` into cohesive role interfaces (`IRegistryTweaks`, `IStorageCleanupSystem`, `IAppManagementSystem`, `IServiceConfigSystem`) or group sub-facets onto properties while keeping `WindowsMemorySystem` as the adapter implementation.

---

### 3.3 Privilege Boundary of Persistent State in `%LOCALAPPDATA%` vs. `%ProgramData%`
- **Where**:
  - `%LOCALAPPDATA%\RemotePCDiagnostics`: `workflow.json`, `changes.json`, `benchmark.json`, `pending-reboot.json`, `preferences.json`, `retrim.json`, plus the app log, event reviews and `moduleui\<slug>\` (WebView2 data for unsigned module UIs)
  - `%ProgramData%\RemotePCDiagnostics`: `catalog\`, `migrations.json` and `migration\` (one-time migrations), `agent.json`
- **Observation**:
  - Because `RemotePCDiagnostics.Host.exe` always runs elevated (`requireAdministrator`), machine-wide actions (auto-logon workflow resume, post-reboot task resume, change journal undo) read state from `%LOCALAPPDATA%\RemotePCDiagnostics`.
  - This creates two architectural tensions:
    1. **Multi-Account / Split-Token UAC**: If a standard user launches `RemotePCDiagnostics.Host.exe` and enters a separate local Administrator's credentials at the UAC prompt, `%LOCALAPPDATA%` resolves to the **Administrator's** user profile rather than the interactive user's profile, and after an auto-logon reboot the profile may not match if accounts differ.
    2. **Integrity Boundary**: Files in `%LOCALAPPDATA%` are writable by Medium-integrity processes (including unsigned plugins in `ModuleHost` and `ModuleUiHost`), which is why `UndoService` has had to grow complex allowlists for every `ChangeKind`. This is an elevation path, not only a design tension; see 4.1.
- **Recommendation**: Store elevated operational state (`workflow.json`, `changes.json`, `pending-reboot.json`, `benchmark.json`) in an Administrator-ACL'd folder under `%ProgramData%\RemotePCDiagnostics\state` (just as `agent.json` and `catalog\` already use `%ProgramData%\RemotePCDiagnostics`).

---

### 3.4 Dual Service Locator Pattern in UI (`AppServices` vs. `IServiceProvider`)
- **Where**: `src/RemotePCDiagnostics.UI/AppServices.cs` vs. `@inject IServiceProvider Services` in `src/RemotePCDiagnostics.UI/Shared/UnsignedModuleFrame.razor`, `src/RemotePCDiagnostics.UI/Pages/ChecksPage.razor`, and `src/RemotePCDiagnostics.UI/Pages/ModulePage.razor`
- **Observation**: `AppServices` was introduced so Razor pages could take optional services (`RemediationService?`, `WorkflowService?`, `PluginRegistrar?`) without injecting `IServiceProvider` directly, allowing pages to render in unit/minimal hosts where only `DiagnosticsService` and `ResultStore` are registered. However, the newer `IModuleUiFrames` feature bypassed `AppServices` and injected `IServiceProvider` directly into `ChecksPage.razor`, `ModulePage.razor`, and `UnsignedModuleFrame.razor`.
- **Recommendation**: Add `IModuleUiFrames? ModuleUiFrames = null` to `AppServices` so all optional host capabilities follow a single injection pattern across `RemotePCDiagnostics.UI`.

---

### 3.5 PowerShell Process Spawning for WMI / Registry / NetAdapter Operations
- **Where**: `src/RemotePCDiagnostics.Core/Areas/RemediationService.cs`, `src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs`, `src/RemotePCDiagnostics.Host/DevProjects.cs`
- **Observation**: Several fast operations (e.g., reading/writing `HiberbootEnabled` or `ProxyEnable` registry values in `RemediationService`, or querying `Win32_PageFileSetting`) spawn a full `powershell.exe -NoProfile -NonInteractive` process (~300–800 ms cold start + string escaping concerns), whereas `WindowsMemorySystem` already performs direct `Microsoft.Win32.Registry` and `System.Management` WMI calls in-process for newer features.
- **Note**: `ProxyEnable` is written to the HKCU of the elevated user, so in the split-token case of 3.3 it changes the administrator's proxy setting, not the signed-in user's.
- **Recommendation**: Over time, migrate remaining registry and WMI one-liners in `RemediationService` and `UndoService` to typed methods on the host adapter (keeping `SystemCommandRunner` only for external CLI tools like `dism.exe`, `sfc.exe`, `ipconfig.exe`, `powercfg.exe`, and `pnputil.exe`).

---

## 4. What This Review Misses

### 4.1 State in `%LOCALAPPDATA%` Is an Elevation Path
- **Where**: `src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs`, `src/RemotePCDiagnostics.Core/Changes/UndoService.cs`, `src/RemotePCDiagnostics.Core/Workflow/WorkflowModels.cs`, `src/RemotePCDiagnostics.Core/Areas/RebootResumeCoordinator.cs`
- **Observation**: The elevated app reads `changes.json`, `workflow.json` and `pending-reboot.json` from `%LOCALAPPDATA%\RemotePCDiagnostics` and acts on them. The user owns that folder, so any program the user runs can rewrite these files without a UAC prompt, not only unsigned modules. Examples from the code:
  - A forged `AdapterDns` entry in `changes.json` makes Undo set any network adapter's DNS servers to addresses the attacker chooses (`UndoService.cs`, `ChangeKind.AdapterDns`; only wildcard characters are rejected).
  - A forged `ServiceStartType` entry sets any service that isn't on the protected list to Automatic.
  - `workflow.json` carries the `Approved` fix list and the `AutoLogonBackup` Winlogon values, which the workflow applies after a restart. A forged file can approve fixes the technician never approved, or change the sign-in settings it puts back.
- **Impact**: The allowlists added in f14cd66 narrow what a forged entry can do, but they can't close the hole, because the journal itself is untrusted input.
- **Recommendation**: Treat 3.3 as a security fix, ahead of the other items. Move these files to `%ProgramData%\RemotePCDiagnostics\state` with an ACL that allows only Administrators and SYSTEM, set when the folder is created (and checked on start). Move existing files once, using the existing `migrations.json` marker pattern. This also fixes the split-token case in 3.3.

### 4.2 Items Still Open From Earlier Reviews
These are not covered above and are still open at 67984a5:
- **Logging is a bare `Action<string>`**: 72 files take one, there is no `ILogger<T>`, and empty `catch { }` blocks have grown to about 136. Severity is still guessed from message text.
- **Result outcome is stringly typed**: `ResultEventLogger.Outcome` (`src/RemotePCDiagnostics.Core/Logging/EventLogging.cs`) still uses reflection to read a property named `Outcome` and compares it to `"NoGpu"`, `"StoppedByUser"` and `"Cancelled"`. `CouldNotRun` and `DependencyGate` cover part of this; the reflection should go.
- **UI branches on concrete module types**: 13 `is XModule` checks remain in `RemotePCDiagnostics.UI`, so each new area with actions means editing a generic page. This is the larger form of 3.4.
- **Remote mode has no authorization boundary**: every remote viewer has the same admin power as the person at the PC. The README asks for read-only by default; there is no written trust model or per-session "remote may change things" switch yet.


---

## 5. Status

Updated November 5, 2026 (branch `claude/project-thread-4v3j0l`).

| Item | Status | Where |
| --- | --- | --- |
| 3.3 / 4.1 State in `%LOCALAPPDATA%` | Fixed | `ProtectedState`, `ProtectedStateFolder`, `ProtectedStateMigration`: state lives in `%ProgramData%\RemotePCDiagnostics\state` (Administrators and SYSTEM only), moved once on first start |
| 3.4 Two service locator styles | Fixed | `AppServices.ModuleUiFrames`; no UI file injects `IServiceProvider` |
| 4.2 Stringly typed outcome | Fixed | `IRunEnd` (contract 1.2) on the stress reports, `StressSuiteResult` and `CouldNotRun`; no reflection in `ResultEventLogger` |
| Module-name constants | Fixed | Every `ModuleName` points at `ModuleSlugs` |
| 4.2 UI branches on concrete module types | Fixed | `IHasAreaPanels`, `IServiceRows`, `IHangEvidenceSource`, `ICancellableScan` in `Core/Areas/AreaCapabilities.cs` |
| 3.2 `IMemorySystem` | Split | Nine role interfaces, each registered to the one `WindowsMemorySystem`; the restore helpers take only their role. Larger consumers (`MemorySuggestionService`, `UndoService`) still take `IMemorySystem`, and default methods still return "Not supported" |
| 4.2 Logging | Done | Every class takes an `ILogger` (one category per class from `AppLoggerFactory`) and each call says its level (`Info`, `Warn`, `Error`). The plugin contract logs the same way: `AreaModuleBase`, `StressModuleBase`, `StressCleanup` and `IPluginContext.Log` take an `ILogger` (contract 2.0). The empty `catch { }` blocks are not reduced yet |
| 3.1 Two module instances | Open | |
| 3.5 PowerShell one-liners | Open | |
| 4.2 Remote trust model | Open | |
