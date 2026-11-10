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
- The UI process serves the app's own `app.css` and follows the app's theme, so the app's classes work. The module's own static web
  assets (`_content/...`) aren't served, so anything else goes inline or in the component. A fresh UI process starts each time the
  module page opens; its log is `%LOCALAPPDATA%\RemotePCDiagnostics\moduleui\<slug>\module-ui.log`.
- In a remote session the frame of a module that ships with the app goes through the session's relay. An unsigned module's UI is
  Local mode only; remote sessions show its generic report.

## Startup

For each DLL: verify the signature, read `module.json` without running code, check the contract and duplicates, save the manifest and
strings to `%ProgramData%\RemotePCDiagnostics\catalog\<id>`, then load (signed) or hand to the user-mode host (unsigned). A plugin that
fails anywhere is disabled with the reason (About page, Event Log 1800) and startup carries on. A plugin whose DLL was removed keeps its
catalog copy, so History can still name its results.

## Modules that ship with the app

The built-in modules that run without administrator are module DLLs too, one project each under `src/Modules` (hardware inventory,
device drivers, resource hogs, battery and power plan, network, Windows error log, programs, security essentials, the CPU, memory,
disk, GPU and network stress tests, both audio tests, the webcam test and the NPU test), and so are the rest (sensors and fans, drive
health, crashes, services, osquery, DISM, SFC, the security audit). `BuiltInModulesPlugin.CompiledIn` is empty. Only DISM, SFC and the
security audit still need administrator; sensors, drive health, crashes and services read what needs administrator through host
queries ([Host queries](#host-queries) below).

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
Device Manager & drivers do. The About page overrides that for all modules or one module at a time (`process-mode.json` in the
admin-only modules folder, read at the next start); the module page lays itself out from the result (`ModuleHosting`), so a switch
needs no code or page changes. A module that needs administrator runs out of process with the app's own token (isolation only). Then:

- `LoadBundled` doesn't load its code into the app. It registers a `UserModeModuleProxy` (`UserModeModule.Bundled = true`) and the check
  runs in `RemotePCDiagnostics.ModuleHost.exe` with the restricted, Medium-integrity token, in Local and Remote sessions. It doesn't need
  the unsigned-modules switch, because it is part of the app's own install.
- `UserModePlugin.Load` gives the plugin the app's read-only helpers (`OsqueryRunner` from the app folder's `tools\osquery`, and
  `SystemCommandRunner`), so its plugin code is unchanged. Adapters that need the Host (sensors, audio, webcam, NPU, GPU) aren't
  available there, so those modules stay in process.
- Unlike an unsigned module, its report keeps its one-click fixes (the app runs them, elevated, as before) and its page shows no
  "Unsigned module" banner. The app's descriptor (group, order, run order) still applies.
- With `"hasUi": true` and `"portableUi": true` its details UI runs in `moduleui\RemotePCDiagnostics.ModuleUiHost.exe` and is framed on
  the module page above the generic report, in Local and Remote sessions. That UI can use only Components and Core types (no app
  services); the app's CSS and theme are there. Programs adds a search over installed programs and updates; Battery adds health and
  charge gauges with a "Check now" that reads the battery in the UI process. With `"resultOnlyUi": true` (Sensors) the app renders the
  module's own page from the host's results instead. One-click fixes aren't offered inside a framed UI yet; they stay in the generic
  report.
- The host exits 2 seconds after each run and starts again for the next one, unless `"keepAlive": true` (Sensors, which is read
  again and again). The app answers the module's host queries in the background, at most 4 at a time, so a slow one doesn't hold up
  progress or a stop; when the run is stopped, queries still waiting are answered "cancelled".
- The host gets only its own three pipe ends from the app (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), never another host's.
- Without a module host (tests and tools that pass no user-mode factory) it loads in process like the others.

## Checks written as data

A check that only reads can be a JSON file in `%ProgramFiles%\RemotePCDiagnostics\checks` instead of a DLL (see
`samples/checks/windows-update-service.json`): an `id`, `slug`, `displayName`, `group`, `order`, `dependsOn`/`runAfter`, one read-only
osquery `query` (a single SELECT; `curl` and `carves` are refused), the `columns` to show and `rules` on them (`eq`, `ne`, `lt`, `le`,
`gt`, `ge`, `contains`, `notContains`, `empty`, `notEmpty`, each with a `level` and a plain-text `message`). It carries no code, so it runs
in the app unsigned and shows in the standard report view. A check that would run a script is code: it must be a signed module, or it
runs in user mode.

## Host queries

What a module that ships with the app can ask the host for. The design for unsigned, third-party modules is not built; it is in
[roadmap.md](roadmap.md#2-host-queries-for-third-party-modules).

Five modules that need elevated or host-assisted reads can run out of process **in user mode** (`RemotePCDiagnostics.ModuleHost`,
restricted token, Medium integrity) by asking the app for those reads. They still ship in process;
the About page switches each one.

| Module | `capabilities` in its module.json | What the app reads for it |
|---|---|---|
| Temperatures & fans (`Sensors`) | `sensors.read` | Every temperature and fan reading (LibreHardwareMonitor in the app) |
| Drive health (`DriveHealth`) | `storage.drives`, `storage.retrims`, `osquery.select` | The drive health script's output, the last retrim per drive, `disk_info` |
| Services (`Services`) | `osquery.select` | The `services` statement, with every service's details |
| Crashes & unexpected restarts (`Crashes`) | `eventlog.query`, `crashes.minidumps`, `events.reviewed` | Application and System log events, the minidump list, the reviewed events |
| Windows error log (`EventLog`) | `eventlog.query`, `events.reviewed` | Application and System log events, the reviewed events |

How it works:

- **Code:** `IHostQueries` in `RemotePCDiagnostics.Core.Plugins` (`HostQueries.cs`). In the module host, `UserModePlugin.Load` registers a
  `HostQueriesClient` for a plugin whose manifest lists capabilities, and the plugin passes it to its module (for example
  `new ServicesModule(osquery, sp.GetService<IHostQueries>())`). In the app the service isn't registered, so the module reads directly,
  as before.
- **Wire:** on the module host's stdin and stdout, next to the existing messages:

  ```text
  host → app   {"type":"query","id":3,"capability":"osquery.select","args":{"sql":"SELECT name, ... FROM services WHERE ...;"}}
  app  → host  {"type":"answer","id":3,"ok":true,"value":{"sql":"...","rows":[...]}}
  app  → host  {"type":"answer","id":4,"ok":false,"error":"notAllowed","reason":"only the app's own osquery statements can run"}
  ```

- **Checks in the app** (`HostQueryServer`), before anything runs:
  - the module ships with the app (an unsigned module gets `notAllowed` for every query, until redaction exists);
  - its module.json lists the capability (`notDeclared` otherwise). An unknown capability name disables the module at load;
  - `osquery.select` runs only the app's own statements, verbatim (`HostCapabilities.AllowedSql`);
  - `eventlog.query` reads only the System and Application logs, at most 1,000 events, with a filter of at most 2,000 characters;
  - every query has a 2-minute limit.
- **Results:** a result whose payload isn't an `AreaReport` crosses only if its type is listed in `ModuleHostPayloads.Types`
  (`SensorReport`, `SecurityAuditReport`, `HardwareInventory`), so the Temperatures & fans, Security audit, and Hardware inventory pages
  get the same result in either process. Those pages have `"resultOnlyUi": true`: they read only the module's results, so out of process
  the app still renders them from the stand-in's results.
- **Page clicks** (`ModulePageCalls`): the Services page's Start, Stop and Restart buttons and the Crashes page's "Find related
  evidence" used to ask the module object in the app. Out of process that object is in the module host, so:
  - what the page reads from the last run travels with the result (`pageData` on the `result` line): `serviceRows` (the services
    behind the rows) and `hangEvidence` (`{"cardId":"hangs"}`, the card whose rows can look up evidence). The app's stand-in offers
    them to the page (`IModuleFeatures`; pages ask `module.Feature<IServiceRows>()` instead of `module as IServiceRows`). Starting or
    stopping a service still happens in the app, with its confirmation, as before;
  - a click that needs the module is a call: `{"type":"call","id":1,"name":"hangEvidence","args":[...]}` to the host, which runs it
    on the module (answering its host queries meanwhile) and sends `{"type":"return","id":1,"ok":true,"value":"..."}`. Calls wait for a
    run in progress, start a host when none is running, and are reset after 3 minutes;
  - both only for modules that ship with the app; an unsigned module's page data is ignored and its calls refused.
- **Security audit** renders its page in the app from results (`"resultOnlyUi": true`; `SecurityAuditReport` is in
  `ModuleHostPayloads.Types`), and its Cancel button asks the module host to stop the run (`IUserModeModule.Stop`, the `stop` line).
- **One run per device** (`"perDevice": true`, Drive health): the app's stand-in is a `PerDeviceModuleProxy` (`IPerDeviceModule`).
  It asks the host for the devices (`{"type":"detect"}` → `{"type":"detection","instances":[...]}`), runs each one
  (`{"type":"refresh","instance":{...}}`), and takes the one report of all drives from the host (`pageData.combined`, with the drive
  keys it covers). So the module keeps one result per drive in History and one card per drive on its page. Its storage clean-up panel
  comes as `pageData.panels`.
- **Not carried over out of process yet:** the Checks screen's Cancel for DISM and SFC (`ICancellableScan`).
