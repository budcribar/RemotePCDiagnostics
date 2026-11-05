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
            └─────────────────────┬────────────┘   │  • MemTest (phys RAM lock)│
                                  │                └─────────────▲─────────────┘
                    ┌─────────────▼──────────────────────────────┴─────────────┐
                    │       RemotePCDiagnostics.Host (net10.0-windows, WPF)    │
                    │  Elevated entry point, HostServices composition root,    │
                    │  Windows adapters (WMI/LHM/WASAPI/D3D11/D3D12/osquery),  │
                    │  RemoteBlazorWebView client + Embedded loopback relay    │
                    └──────────────────────────────────────────────────────────┘
```

---

## 2. Key Architectural Strengths

1. **Strict Port/Adapter Separation Between `Core` and `Host`**:
   - `src/RemotePCDiagnostics.Core` targets plain `net10.0` (no `-windows` TFM, no WPF/WinRT/COM/WMI references). All OS-touching operations sit behind narrow interfaces (`IMemorySystem`, `IServiceControlBackend`, `ISensorProvider`, `IGpuDeviceFactory`, `IAudioIo`, `INpuIo`, `IProcessLauncher`).
   - This makes 95%+ of the domain logic fast and deterministically testable in `tests/RemotePCDiagnostics.Tests` without mocking frameworks or administrator privileges.

2. **Extracted Testable Composition Root (`HostServices`)**:
   - Moving container registration out of `src/RemotePCDiagnostics.Host/MainWindow.xaml.cs` into `HostServices.AddRemotePCDiagnosticsHost` (`src/RemotePCDiagnostics.Host/HostServices.cs`) allows `tests/RemotePCDiagnostics.Host.Tests/HostServicesTests.cs` to validate the entire DI graph with `ValidateOnBuild = true` and `ValidateScopes = true` without spinning up a WPF window.
   - Routing built-in modules through `BuiltInModulesPlugin` and `PluginRegistrar` ensures built-in and third-party modules exercise the exact same registration and catalog pipeline.

3. **Three-Tier Plugin & Check Extensibility Model (`docs/module-plugins.md`)**:
   - **Data-only checks (`JsonCheck`)**: Declarative JSON + read-only `osquery` SQL, requiring zero code execution.
   - **Signed plugins (`ModuleLoader`)**: Verified with ECDSA P-256 over the exact `byte[]` before PE metadata is parsed, then loaded from that in-memory `byte[]` (eliminating TOCTOU between signature verification and assembly load) into an isolated `ModuleLoadContext`.
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
- **Where**: `src/RemotePCDiagnostics.Core/Memory/MemoryModels.cs` (`IMemorySystem`, 37 methods) and `src/RemotePCDiagnostics.Host/WindowsMemorySystem.cs` (~1,500 lines across 3 partial files)
- **Observation**: Originally scoped to RAM and startup apps, `IMemorySystem` has become the catch-all OS abstraction for:
  - RAM & process working sets
  - Windows Services start types & delayed autostart
  - Browser Local State JSON & extension policy blocks
  - Storage cleanup scanning & execution (`StorageCleanupEngine`, DISM `/ResetBase`, `powercfg /h`)
  - Registry allowlist reads/writes (Search indexing, Widgets, Game DVR, Sticky Keys, delivery optimization, telemetry, Copilot, Bing search, Windows feeds, Office start screen)
  - Scheduled tasks, default printer, power plans, pagefile sizing, Win32/Store app uninstall & Store reinstall
- **Impact**: Every unit test that needs a fake `IMemorySystem` (12+ hand-written `class Sys : IMemorySystem` test doubles across `tests/RemotePCDiagnostics.Tests`) relies on dozens of default interface methods on `IMemorySystem`.
- **Recommendation**: Split `IMemorySystem` into cohesive role interfaces (`IRegistryTweaks`, `IStorageCleanupSystem`, `IAppManagementSystem`, `IServiceConfigSystem`) or group sub-facets onto properties while keeping `WindowsMemorySystem` as the adapter implementation.

---

### 3.3 Privilege Boundary of Persistent State in `%LOCALAPPDATA%` vs. `%ProgramData%`
- **Where**:
  - `%LOCALAPPDATA%\RemotePCDiagnostics`: `workflow.json`, `changes.json`, `benchmark.json`, `pending-reboot.json`, `preferences.json`, `retrim.json`
  - `%ProgramData%\RemotePCDiagnostics`: `catalog\`, `eventlog-v3-migration.json`, `agent.json`
- **Observation**:
  - Because `RemotePCDiagnostics.Host.exe` always runs elevated (`requireAdministrator`), machine-wide actions (auto-logon workflow resume, post-reboot task resume, change journal undo) read state from `%LOCALAPPDATA%\RemotePCDiagnostics`.
  - This creates two architectural tensions:
    1. **Multi-Account / Split-Token UAC**: If a standard user launches `RemotePCDiagnostics.Host.exe` and enters a separate local Administrator's credentials at the UAC prompt, `%LOCALAPPDATA%` resolves to the **Administrator's** user profile rather than the interactive user's profile, and after an auto-logon reboot the profile may not match if accounts differ.
    2. **Integrity Boundary**: Files in `%LOCALAPPDATA%` are writable by Medium-integrity processes (including unsigned plugins in `ModuleHost` and `ModuleUiHost`), which is why `UndoService` has had to grow complex allowlists for every `ChangeKind`.
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
- **Recommendation**: Over time, migrate remaining registry and WMI one-liners in `RemediationService` and `UndoService` to typed methods on the host adapter (keeping `SystemCommandRunner` only for external CLI tools like `dism.exe`, `sfc.exe`, `ipconfig.exe`, `powercfg.exe`, and `pnputil.exe`).
