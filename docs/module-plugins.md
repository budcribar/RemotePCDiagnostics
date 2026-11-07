# Module plugins

A module plugin is one .NET DLL that adds one diagnostic module (its code and its UI). The app looks for plugins once, at startup,
in `%ProgramFiles%\RemotePCDiagnostics\modules` (standard users can't write there) and nowhere else.

## Writing one

See `samples/SampleModule`. A module project:

- references only `src/RemotePCDiagnostics.Abstractions` (the contract), with `Private="false"`;
- imports `build/RemotePCDiagnostics.Module.props`, which embeds `module.json`, `strings/<culture>.json` and the module's own package
  DLLs (`lib/<name>.dll`);
- has an entry type implementing `IModulePlugin` that registers exactly one `IDiagnosticModule` whose `Id` is the manifest's `id`.

`module.json`:

| Field | |
|---|---|
| `id` | Permanent GUID. Never change it or reuse it: stored results key on it. |
| `slug` | `vendor.name`, unique. |
| `displayName`, `version` | Shown in the app and on the About page. |
| `contract` | The contract version built against (`1.0`). Loads when the major matches and the minor is at or below the app's. |
| `minHost` | Optional lowest app version. |
| `entryType` | Full name of the `IModulePlugin` type. |
| `kind`, `group`, `order` | `Check`, `OnDemand` or `StressTest`; the group key and order within it. |
| `dependsOn`, `runAfter` | Module ids that must run first (and pass), or only run first. |
| `changesSystem`, `needsAdmin` | A module with either set must be signed with the project key. |
| `hasUi` | The plugin sets its own details UI (`SetDetailsComponent`). Needed for an unsigned module's UI to be shown (see below). |
| `outOfProcess` | Only for a module that ships with the app: it runs out of process like an unsigned one (see below). Ignored for plugins. |

## Signing and trust

- `tools/New-ModuleSigningKey.ps1` creates the project key (once) and writes the public half into `ModuleSigningKey.PublicKeyPem`.
- `tools/Sign-Module.ps1 -Module X.dll -PrivateKeyPath key.pem` writes `X.dll.sig` (ECDSA P-256 / SHA-256 over the DLL's exact bytes).
- A signed module loads into the app process in its own `AssemblyLoadContext`. The loader reads the DLL once and verifies, reads and
  loads those same bytes.
- An unsigned module never loads into the app. It is listed on the About page; if the person at the PC turned unsigned modules on, it
  runs in the user-mode module host instead (out of process, restricted token). Unsigned modules that need administrator or change the
  PC are always disabled.
- The switch for unsigned modules is the file `allow-unsigned` in the modules folder, set from the About page by someone at the PC
  (the folder is admin-only, so neither a standard user, a remote session nor a module can turn it on). It takes effect at the next start.
- In user mode the app starts `RemotePCDiagnostics.ModuleHost.exe <module.dll>` with a restricted copy of its token (Administrators
  deny-only, privileges removed, Medium integrity). The two talk over the host's stdin and stdout, one JSON line per message
  (`availability`, `refresh`, `stop`, `exit` one way; `ready`, `availability`, `progress`, `result`, `error` the other). The module's
  report is shown in the generic view, under an "Unsigned module" banner the app draws, with every one-click fix removed.
- Admin modules are only ever signed with our key: they come in through a pull request and are reviewed and added by us.

## A module's own UI

A plugin can give its module a details UI: a Razor component with a `DiagnosticModule` parameter (`IDiagnosticModule`), set with
`context.SetDetailsComponent(id, typeof(MyDetails))`. See `samples/SampleModuleUi`, which references Components through
`<FrameworkReference Include="Microsoft.AspNetCore.App" />` so nothing of Components is copied or embedded.

- Signed: the component renders in the module page like a built-in one.
- Unsigned, with `"hasUi": true`, in Local mode: the app starts `moduleui\RemotePCDiagnostics.ModuleUiHost.exe` with the same restricted
  token as the module host. It loads the module and renders the component as a RemoteBlazorWebView client of a relay inside the app
  (loopback only, framed only by the app's page). The module page shows it in an iframe with `sandbox="allow-scripts allow-forms"`
  under the app's "Unsigned module" banner, above the generic report of the module's last run.
- The frame has an opaque origin: the module's page can't read the app's page, its own or anyone's storage and cookies, or another
  module's frame, and can't open popups or navigate the app. The only message the app accepts from it is its content height.
- The component gets the module's latest result in the app as a cascading value:
  `[CascadingParameter(Name = ModuleDetails.LastResult)] public DiagnosticResult? LastResult { get; set; }` ("not run yet" before the
  first run). For an unsigned module the module page sends it to the UI process over that process's stdin (the `IModuleUi` remote-component
  contract: one JSON `set` line, with one-click fixes removed) when the module page opens and again after every run, so the UI shows
  the app's run instead of starting blank. A signed module's component gets the same value. `samples/SampleModuleUi` shows the last
  run's time this way.
- `DiagnosticModule` is still the UI process's own instance of the module: a run the component starts itself is not the app's run and
  isn't stored.
- Keep styles inline or in the component: the module's static web assets (`_content/...`) aren't served. A fresh UI process starts each
  time the module page opens; its log is `%LOCALAPPDATA%\RemotePCDiagnostics\moduleui\<slug>\module-ui.log`.
- Remote sessions show the generic report only for now.

## Startup

For each DLL: verify the signature, read `module.json` without running code, check the contract and duplicates, save the manifest and
strings to `%ProgramData%\RemotePCDiagnostics\catalog\<id>`, then load (signed) or hand to the user-mode host (unsigned). A plugin that
fails anywhere is disabled with the reason (About page, Event Log 1800) and startup carries on. A plugin whose DLL was removed keeps its
catalog copy, so History can still name its results.

## Modules that ship with the app

The built-in modules that run without administrator are module DLLs too, one project each under `src/Modules` (hardware inventory,
device drivers, resource hogs, battery and power plan, network, Windows error log, programs, security essentials, the CPU, memory,
disk, GPU and network stress tests, both audio tests, the webcam test and the NPU test). The ones that need administrator (sensors and
fans, drive health, crashes, services, DISM, SFC, the security audit) stay compiled into the app (`BuiltInModulesPlugin.CompiledIn`).

- `src/Modules/Directory.Build.props` sets each one up: `module.json` embedded, Abstractions, Core and UI referenced with
  `Private="false"` (the app supplies them, so the DLL holds only the module's own code and page).
- `build/BundledModules.targets` (imported by the Host and Host.Tests) builds them into `builtin-modules\` next to the exe, and publishes
  them as ordinary files, so the single-file Portable exe bundles them.
- `ModuleLoader.LoadBundled` loads each into its own load context, in process and without a signature: the folder is part of the app's
  own install, like its other DLLs. Only an id the app already knows (`BuiltInModules.Descriptors`) with its usual slug loads from there;
  anything else is listed as disabled on the About page. A module's group, order and run order stay the app's descriptor, and History
  keeps naming the module even if its DLL is missing.
- Its plugin builds the module from the app's services (`OsqueryRunner`, `SystemCommandRunner`, `ISensorProvider`, `IAudioIo`,
  `IWebcamIo`, `INpuIo`, `IGpuDeviceFactory`, the logger factory via `ModuleServices.LoggerFor<T>`) and sets its page with
  `SetDetailsComponent`. The Windows adapters stay in the Host.
- `--verify-package` fails when a built-in module is neither compiled in nor in `builtin-modules\`.

### Built-in modules that run out of process

A module that ships with the app can set `"outOfProcess": true` in its `module.json`. Programs & updates, Battery & power plan and
Device Manager & drivers do. Then:

- `LoadBundled` doesn't load its code into the app. It registers a `UserModeModuleProxy` (`UserModeModule.Bundled = true`) and the check
  runs in `RemotePCDiagnostics.ModuleHost.exe` with the restricted, Medium-integrity token, in Local and Remote sessions. It doesn't need
  the unsigned-modules switch, because it is part of the app's own install.
- `UserModePlugin.Load` gives the plugin the app's read-only helpers (`OsqueryRunner` from the app folder's `tools\osquery`, and
  `SystemCommandRunner`), so its plugin code is unchanged. Adapters that need the Host (sensors, audio, webcam, NPU, GPU) aren't
  available there, so those modules stay in process.
- Unlike an unsigned module, its report keeps its one-click fixes (the app runs them, elevated, as before) and its page shows no
  "Unsigned module" banner. The app's descriptor (group, order, run order) still applies.
- With `"hasUi": true` its details UI runs in `moduleui\RemotePCDiagnostics.ModuleUiHost.exe` and is framed on the module page above the
  generic report (Local mode; Remote shows the generic report). That UI can use only Components and Core types and must style itself:
  the app's UI assembly and CSS aren't in that process. Programs adds a search over installed programs and updates; Battery adds
  health and charge gauges with a "Check now" that reads the battery in the UI process.
- Without a module host (tests and tools that pass no user-mode factory) it loads in process like the others.

## Checks written as data

A check that only reads can be a JSON file in `%ProgramFiles%\RemotePCDiagnostics\checks` instead of a DLL (see
`samples/checks/windows-update-service.json`): an `id`, `slug`, `displayName`, `group`, `order`, `dependsOn`/`runAfter`, one read-only
osquery `query` (a single SELECT; `curl` and `carves` are refused), the `columns` to show and `rules` on them (`eq`, `ne`, `lt`, `le`,
`gt`, `ge`, `contains`, `notContains`, `empty`, `notEmpty`, each with a `level` and a plain-text `message`). It carries no code, so it runs
in the app unsigned and shows in the standard report view. A check that would run a script is code: it must be a signed module, or it
runs in user mode.
