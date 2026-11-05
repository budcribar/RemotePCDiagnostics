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

## Startup

For each DLL: verify the signature, read `module.json` without running code, check the contract and duplicates, save the manifest and
strings to `%ProgramData%\RemotePCDiagnostics\catalog\<id>`, then load (signed) or hand to the user-mode host (unsigned). A plugin that
fails anywhere is disabled with the reason (About page, Event Log 1800) and startup carries on. A plugin whose DLL was removed keeps its
catalog copy, so History can still name its results.

## Checks written as data

A check that only reads can be a JSON file in `%ProgramFiles%\RemotePCDiagnostics\checks` instead of a DLL (see
`samples/checks/windows-update-service.json`): an `id`, `slug`, `displayName`, `group`, `order`, `dependsOn`/`runAfter`, one read-only
osquery `query` (a single SELECT; `curl` and `carves` are refused), the `columns` to show and `rules` on them (`eq`, `ne`, `lt`, `le`,
`gt`, `ge`, `contains`, `notContains`, `empty`, `notEmpty`, each with a `level` and a plain-text `message`). It carries no code, so it runs
in the app unsigned and shows in the standard report view. A check that would run a script is code: it must be a signed module, or it
runs in user mode.
