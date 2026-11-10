# Roadmap

Plans that are **not built yet**. They were moved here on 2026-11-10 from the design notes and proposals that used to sit in this
folder, mostly word for word, so nothing planned is lost; what is built is described in [architecture.md](architecture.md) and
[module-plugins.md](module-plugins.md). Each section keeps the status its source had when it was written, so check the code before
starting on one. The originals are in the Git history of `docs/`.

Contents: [1. Agent program](#1-agent-program) · [2. Host queries for third-party modules](#2-host-queries-for-third-party-modules) ·
[3. Service workflow fixes still to build](#3-service-workflow-fixes-still-to-build) · [4. Remote trust model](#4-remote-trust-model) ·
[5. Proposals](#5-proposals)

## 1. Agent program

From `agent-design.md`. Built: the relay side and the admin site's Computers page, the contract (`agent.proto`) and the agent's logic
library (`RemotePCDiagnostics.Agent.Core`). Not built: the agent program itself (service, install and uninstall, download, launch), the
release workflow and the manifest signing key script.


Status (November 3, 2026):
- **Done:** the relay side (`AgentHub` / `AgentAdmin` in RemoteBlazorWebView, branch `net10`; see its `doc/Agents.md`) and the admin site's **Computers** page (RemoteWebViewAdmin).
- **Here:** the contract (`src/RemotePCDiagnostics.Agent/Protos/agent.proto`) and the agent's pure logic library (`src/RemotePCDiagnostics.Agent.Core`: command line, config, manifest, signature, consent rule, cache, launch rules, backoff).
- **Not built yet:** the agent exe (service, install/uninstall, download, launch), `release.yml`, `tools/New-ManifestSigningKey.ps1`, and tests for the logic library.
- **Relay settings on Railway:** `PUBLIC_BASE_URL`, `AGENT_ADMIN_KEY` (without it every start asks the person at the PC), and optionally `AGENT_ENROLLMENT_KEYS`.

### Why

Today the full app (a ~300 MB single-file exe, 129 MB zipped) has to be copied to the client's PC before a remote user can help. Instead, a
small **agent** stays installed. It keeps an outbound connection to the relay on Railway. When a remote user picks that computer on the admin
site, the agent downloads the app (or uses its cached copy), checks it, and starts it on the signed-in user's desktop. The remote user then
drives it in the browser as before.

### Decisions

| Topic | Decision |
|---|---|
| Consent | Configurable. The installer sets the **ceiling** (`--consent=ask` or `--consent=unattended`), stored locally on the PC. The relay and remote users can only be stricter: a remote user may skip the prompt only when the ceiling is `unattended` and they tick "Don't ask". |
| Agent lifetime | Configurable at install: `--lifetime=persistent` (default) or `--lifetime=session`. A per-session agent uninstalls itself and deletes the cached app after one session. The change journal (`%LOCALAPPDATA%\RemotePCDiagnostics\changes.json`) is never deleted, so a later session can still undo. |
| Cache | One verified app version is kept under `%ProgramData%\RemotePCDiagnostics\app\<version>\`. It's replaced when a newer release is verified. |
| Distribution | GitHub Releases of the public RemotePCDiagnostics repo. Each release has `RemotePCDiagnostics-win-x64.zip`, `RemotePCDiagnostics.Agent.exe`, `manifest.json` and `manifest.sig`. |
| Integrity | The agent runs only an app whose zip matches the SHA-256 in `manifest.json`, and only when `manifest.json` carries a valid ECDSA P-256 signature (`manifest.sig`) from the release key built into the agent. Downloads come only from `github.com/budcribar/RemotePCDiagnostics/releases/...` (and GitHub's redirect host for release assets). |
| Code signing | For now: none / self-signed. A free trusted certificate (SignPath Foundation, which needs an OSI license; the repo is MIT) can be added later. The manifest signature is the actual security control. |
| License | MIT. |

### Pieces

1. **Agent** (`src/RemotePCDiagnostics.Agent`, this repo).
   - A NativeAOT, trimmed, single-file Windows exe. The same exe is the installer, the Windows service and the consent prompt. Target size: under 15 MB.
   - It connects to the relay's `AgentHub.Connect` gRPC stream (`src/RemotePCDiagnostics.Agent/Protos/agent.proto`, copied from the relay).
2. **Relay** (`RemoteWebViewService` in budcribar/RemoteBlazorWebView).
   - It implements `AgentHub` (for agents, native gRPC) and `AgentAdmin` (for the admin site, gRPC-Web).
   - The registry is in memory. Optionally, `AGENT_ENROLLMENT_KEYS` (comma-separated) restricts which installs may register; when it isn't set, any key is accepted.
3. **Admin site** (budcribar/RemoteWebViewAdmin).
   - A **Computers** page lists agents (online status, last seen, user, OS, versions, consent ceiling, session).
   - **Start diagnostics** shows live progress and opens `<server>/app/<session>` when the app is ready.
4. **Release workflow** (`.github/workflows/release.yml`, this repo).
   - Runs on tag `v*` or manually. It builds the app and the agent, writes and signs the manifest, and publishes the GitHub release.

### Session flow

1. The remote user clicks **Start diagnostics**, which calls `AgentAdmin.StartSession(machine_id, unattended)`.
2. The relay creates `session_id` (GUID) and `request_id`, and sends `LaunchCommand` down that agent's stream.
3. The agent asks for consent unless allowed to skip it. It runs `RemotePCDiagnostics.Agent.exe consent ...` in the user's session, and the person clicks Allow/Deny within 2 minutes.
4. The agent fetches `releases/latest/download/manifest.json` and `manifest.sig`, verifies the signature, then uses the cached app or downloads the zip and checks its SHA-256. Each step is reported as `LaunchProgress`.
5. The agent starts `RemotePCDiagnostics.Host.exe -u=<server_url> -i=<session_id>` as the signed-in user with their **elevated** token (no UAC prompt). If nobody is signed in, it reports FAILED with "Nobody is signed in".
6. When the app shows up on the relay under `session_id`, the relay reports READY (or the agent does, once the process is up and the relay's `/status/<id>` answers). The admin site opens `/app/<session_id>`.
7. When the app exits, the agent reports ENDED. A per-session agent then removes itself.

### Manifest

`manifest.json` (UTF-8, signed byte-for-byte; the signature is base64 IEEE P1363 ECDSA P-256 / SHA-256 in `manifest.sig`):

```json
{
  "product": "RemotePCDiagnostics",
  "version": "1.2.0",
  "file": "RemotePCDiagnostics-win-x64.zip",
  "url": "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.2.0/RemotePCDiagnostics-win-x64.zip",
  "size": 129342616,
  "sha256": "<64 hex>",
  "entry": "RemotePCDiagnostics.Host.exe",
  "published": "2026-11-03T22:00:00Z"
}
```

### Agent command line

```
RemotePCDiagnostics.Agent.exe install [--server=https://server.remoteblazorwebview.com:34544] [--key=<enrollment key>]
                                      [--consent=ask|unattended] [--lifetime=persistent|session]
RemotePCDiagnostics.Agent.exe uninstall
RemotePCDiagnostics.Agent.exe status
RemotePCDiagnostics.Agent.exe run            (what the service runs; also usable in a console for testing)
RemotePCDiagnostics.Agent.exe consent ...    (internal: the prompt shown on the user's desktop)
```

`install` needs administrator rights (it relaunches itself elevated). It:
- copies itself to `%ProgramFiles%\RemotePCDiagnostics Agent\`
- writes `%ProgramData%\RemotePCDiagnostics\agent.json` (machine id, server, key, consent, lifetime), with write access limited to Administrators and SYSTEM
- registers and starts the `RemotePCDiagnosticsAgent` service (automatic, delayed start, restart on failure)

### One-time setup (owner)

1. Make the repo public (GitHub → Settings → General → Danger Zone → Change visibility → Public).
2. Create the release signing key: run `tools/New-ManifestSigningKey.ps1` on your PC, from the repo folder.
   - It creates the key, stores the private key as the `MANIFEST_SIGNING_KEY` Actions secret (with `gh` if it's installed, otherwise it copies the key to the clipboard and opens the secrets page), and writes the public key into `src/RemotePCDiagnostics.Agent/ManifestKey.cs`.
   - Commit that file. The private key is never written to disk.
3. Tag a release (`git tag v1.2.0 && git push origin v1.2.0`) or run the Release workflow manually.

Until step 2 is done, the agent registers and shows up on the admin site, but it refuses to start the app ("release signing key not set up").

### Phases

1. **(this)**
   - The agent service with install/uninstall and consent.
   - Download, verify and cache, then launch as the signed-in user.
   - The relay registry, the admin Computers page, and the release workflow.
2. Credentials per install instead of shared enrollment keys, remote user permissions per PC, an audit log, and the agent updating itself.
3. Restarts during a session: the agent relaunches the app after boot when the workflow is mid-restart, instead of the app's RunOnce entry. Also undo through the agent (`--undo-all` with the cached app).


## 2. Host queries for third-party modules

From `host-queries.md`. Host queries are built for the modules that ship with the app (see
[module-plugins.md](module-plugins.md#host-queries)). Everything below is the design for unsigned, third-party modules and is not built.

### Why

Most diagnostics only *read*, but some of what they read needs administrator rights: fan speeds, drive wear and error counters, the
DISM and SFC scans. Today such a module has to be signed with the project key, which only we can do. With host queries, a third-party
module can stay **unsigned, in user mode** and still get those readings: it asks the app, and the app, which is already elevated, does
the privileged read and returns the data. The module never gets administrator rights, never runs anything elevated, and never decides
what runs elevated.

The same goes for fixes. A user-mode module can't change the PC, but it can *propose* one of the app's own one-click fixes. The app
checks the request, shows its usual confirmation and undo, and carries it out.

### Where your module runs

| | Signed with the project key | Unsigned (third party) | Check written as JSON |
|---|---|---|---|
| Process | Inside the app (elevated) | `RemotePCDiagnostics.ModuleHost.exe`: restricted token, Medium integrity, no admin | Inside the app |
| Who can ship it | Us, through a reviewed pull request | Anyone | Anyone |
| Needs `allow-unsigned` on the PC | No | Yes (set on the About page by someone at the PC) | No |
| Host queries | Yes (direct calls) | Yes (over the module host pipe) | No (one osquery SELECT only) |
| One-click fixes | Its own, through the change journal | Only by requesting app-owned fixes (below) | No |
| Own UI | Rendered in the app | Sandboxed frame (see module-plugins.md) | No |

You write the module the same way for both: code against `IHostQueries`. Signed, the calls go straight to the app's services. Unsigned,
the app gives the module a proxy that sends each call over the pipe. Your code doesn't change.

### What a user-mode module can read without asking

The module host runs as the signed-in user at Medium integrity, so the normal user APIs work. We verified each of these from a
non-elevated process on Windows 11:

- Hardware inventory, programs and updates, services, drivers, processes and uptime (osquery tables or WMI user classes).
- Network adapters, Wi-Fi and connectivity.
- Battery and power plan (`powercfg /getactivescheme`, osquery `battery`).
- CPU and GPU temperatures from most sensors. Fan speeds and some storage sensors don't work this way.
- Cameras (MediaCapture), microphones and speakers, the NPU.
- Files in the user's profile and `%TEMP%`. Writes to `Program Files`, `Windows` or another user's profile fail.

Use these directly. Host queries are only for what a user can't read.

The **event logs are the exception**: a normal user can read the System and Application logs, but the module host can't, and a module
gets events only through `eventlog.read`, redacted (see [Event logs: redacted only](#event-logs-redacted-only)).

### Host queries

Each query has a **capability name**. A module must list every capability it uses in `module.json`, and the app refuses any call to a
capability that isn't listed. The About page and the module's "Unsigned module" banner show the list, so the person at the PC can see
what a module reads.

| Capability | Returns | Needs the app elevated | Sensitivity |
|---|---|---|---|
| `sensors.read` | Every temperature and fan reading (`SensorSnapshot`) | For fans and some storage sensors | Low |
| `storage.drives` | Per physical drive: health, temperature, wear, read/write errors, power-on hours (`DriveHealth`) | Yes | Low |
| `storage.drives.identifiers` | Adds serial numbers and unique ids to `storage.drives` | Yes | Medium: identifies the hardware |
| `osquery.select` | Rows from one read-only osquery SELECT on allowlisted tables | Some tables | Depends on the tables |
| `eventlog.read` | Redacted events from the System or Application log, filtered by level and age | No (Security log is never offered) | Medium: personal data is replaced, but redacting free text is best effort |
| `windows.repairScan` | Summary of DISM `/ScanHealth` or `sfc /verifyonly` (read-only scans) | Yes | Low |

The app never offers:

- running a command, script, PowerShell, WMI method or executable, elevated or not;
- reading or writing arbitrary files or registry keys;
- the Security event log, credentials, browser data, or anything from another user's profile;
- unredacted events from any log;
- anything that changes the PC, except through a fix request.

#### `sensors.read`

```csharp
SensorSnapshot snap = await queries.ReadSensorsAsync(ct);
```

- `Readings`: list of `SensorReading(HardwareName, HardwareType, SensorName, SensorType, Value, Min, Max, Unit)`.
  - `HardwareType`: `Cpu`, `Gpu`, `Motherboard`, `Storage`, `Memory`, `Controller`, `Other`.
  - `SensorType`: `Temperature` (°C) or `Fan` (RPM).
  - `Value`, `Min` and `Max` are `null` when the sensor reports nothing.
- `IsElevated`: `false` when the app itself runs without admin (for example in a test). Fan readings are then usually missing, and
  `Note` says why.
- At most one call per second per module. The app caches the readings for that second.

#### `storage.drives`

```csharp
IReadOnlyList<DriveHealth> drives = await queries.ReadDrivesAsync(ct);
```

Per physical drive: `Name`, `MediaType` (SSD/HDD), `BusType` (NVMe, SATA, USB, …), `Health`, `Operational`, `SizeBytes`,
`TemperatureC`, `Wear` (% used), `ReadErrors`, `WriteErrors`, `PowerOnHours` and `Letters` (its volumes). Any counter the drive
doesn't report is `null`. `Serial` and `UniqueId` are empty unless the module also declares `storage.drives.identifiers`. Each drive
has an `InstanceKey`, an opaque key made for your module (see [Instance keys](#instance-keys)), which you can use as the
`ModuleInstance.Key` of a per-device module.

#### `osquery.select`

```csharp
OsqueryRows rows = await queries.SelectAsync("SELECT name, status FROM services WHERE start_type = 'AUTO_START'", ct);
```

- One `SELECT` statement only, on tables from the allowlist (see [Risky queries](#risky-queries)). `curl`, `carves` and any table that
  changes state are never on it.
- The tables that return raw events (`windows_eventlog`, `windows_events`, `powershell_events`) are refused too, here and in JSON
  checks, since both run in the elevated app and would get round the redaction. (JSON checks don't refuse them yet: that is a code
  change to `JsonCheck.DeniedTables`.)
- At most 2,000 rows and 1 MB per answer, and 30 seconds per query.
- Runs in the app, which is elevated, so tables a user can't read fully (for example `services` descriptions) come back complete.

#### `eventlog.read`

```csharp
IReadOnlyList<EventRecordInfo> events = await queries.ReadEventsAsync(
    new EventQuery(Log: "System", MaxLevel: EventLevel.Error, Since: TimeSpan.FromDays(7), Max: 300), ct);
```

- `Log`: `System` or `Application` only.
- Returns at most 1,000 events, newest first, each an `EventRecordInfo`:
  - `Time`, `Log`, `Provider`, `EventId`, `Level`: as recorded.
  - `Message`: the rendered message, redacted.
  - `Data`: the named `EventData` fields, each kept, redacted or dropped by the rules below.
  - `Redactions`: how many values were replaced, so a module can tell an empty field from a removed one.
- Every event goes through the redaction below. There is no option to turn it off, and no capability that returns raw events.

### Event logs: redacted only

Event messages can name the user, their files, the sites they visit, the PC and its network. Instead of asking every module that reads
them to be signed, the app makes the redacted `eventlog.read` the **only** way a user-mode module can see an event.

#### Closing the direct route

Today the module host's restricted token keeps the user's groups, so a module could call `wevtutil` or `EventLogReader` itself and
get every event unredacted. The System and Application logs grant read access to `INTERACTIVE` (`IU`), and a normal user's token has
that group. The launcher (`RestrictedModuleHostLauncher.RestrictedToken`, shared by the module host and the module UI host) adds these
to the SIDs it makes deny-only, next to `Administrators`:

| SID | Group | Why |
|---|---|---|
| `S-1-5-4` | INTERACTIVE | The group the logs grant read to (`(A;;0x3;;;IU)` on Application, `(A;;0x1;;;IU)` on System). |
| `S-1-5-32-573` | Event Log Readers | Grants read to every log, if the user is a member. |
| `S-1-5-32-551` | Backup Operators | Has read on the System log. |
| `S-1-5-32-549` | Server Operators | Has read on both logs. |

Checked on a Windows 11 laptop (non-elevated, a process started with each token):

| What the module tries | Today's token | Tightened token |
|---|---|---|
| `wevtutil qe Application` | Reads | Access denied |
| `Get-WinEvent -LogName System` / `EventLogReader` | Reads | Access denied |
| WMI `Win32_NTLogEvent` (Application) | Reads | Access denied |
| `Microsoft-Windows-PowerShell/Operational` log | Reads | Access denied |
| `Application.evtx` file in `System32\winevt\Logs` | Access denied | Access denied |
| `Report.wer` files in `ProgramData\Microsoft\Windows\WER\ReportArchive` | Access denied | Access denied |
| WMI `Win32_ReliabilityRecords` (Reliability Monitor) | Reads | **Still reads** (see below) |
| Folder names in `WER\ReportArchive` (e.g. `AppCrash_<exe>_…`) | Lists | **Still lists** |

Still to check before this ships: that nothing else a module legitimately uses (WMI user classes, osquery, cameras, audio, the NPU,
WebView2 in the module UI host) depends on `INTERACTIVE`. The sample modules are the test.

What's left open:

- **Reliability Monitor records** repeat the messages of app crashes, hangs and installs (app names, versions, sometimes paths). They
  are less personal than the full logs, but not redacted. Options: accept it and list it in the notice, or find a way to deny the WMI
  class to the module host.
- **WER folder names** give the names of crashed programs. Low sensitivity, so accepted.
- **osquery** runs in the elevated app, so the event tables are refused for `osquery.select` and JSON checks (see `osquery.select`).

#### What is redacted

The app redacts after reading and before anything leaves the app process.

Each personal value becomes a placeholder: `<kind:xxxx>`. Here `xxxx` is the first 4 bytes, in hex, of
`HMAC-SHA256(installSecret, moduleId + kind + value)`, the same secret used for [instance keys](#instance-keys). A placeholder:

- is the same every time for the same value, the same module and the same PC, so grouping events by message and trends across runs
  still work;
- is different for another module or another PC, so placeholders can't be matched up across modules or installs;
- can't be reversed by guessing likely names.

| Kind | What is replaced | Example |
|---|---|---|
| `user` | Account names: every profile under `C:\Users` and in the registry's `ProfileList`, `DOMAIN\name`, and UPNs | `Bud` → `<user:3f9a01c2>` |
| `path` | The part of a path inside a user profile after the profile folder. The extension is kept. | `C:\Users\Bud\Documents\taxes.xlsx` → `C:\Users\<user:3f9a01c2>\<path:91be20aa>.xlsx` |
| `sid` | Account SIDs (`S-1-5-21-…`). Well-known SIDs such as `S-1-5-18` are kept. | `<sid:0c7e5d11>` |
| `computer` | The computer name, its DNS name and the domain name | `<computer:5aa0e3b9>` |
| `email` | Email addresses | `<email:77d2c410>` |
| `ip` | IPv4 and IPv6 addresses, except loopback, `0.0.0.0` and link-local | `<ip:e13b9c02>` |
| `mac` | MAC addresses | `<mac:2b6f8d40>` |
| `wifi` | Names of the Wi-Fi networks the PC has profiles for | `<wifi:c84e1f03>` |
| `url` | URLs and bare host names that aren't on a short list of Windows and Microsoft service hosts | `<url:4d09ab7e>` |
| `serial` | Drive, GPU and device serial numbers the app knows | `<serial:f0326a5c>` |

Structured fields:

- The event's `Computer` is replaced and its `Security UserID` is dropped.
- `EventData` fields on a **keep list** are passed unchanged, because the built-in modules match on them and they hold no personal
  data: `BugcheckCode`, `param1` (bugcheck code), `AppName`, `AppVersion`, `ModuleName`, `ModuleVersion`, `ExceptionCode`,
  `FaultOffset`, `ProcessId`, `ReportId`, `HangType`, `PackageFullName`. The keep list is per provider and event id.
- Fields that hold a path (`ExeFileName`, `AppPath`, `param2` dump path, …) go through the `user` and `path` rules.
- Every other text field goes through all the rules above. Binary data is dropped.

#### What this keeps working

The built-in modules (Event Log, Crashes, BSOD history) would still work on redacted events:

- The Event Log page groups by message. Redacted messages group the same way, since a placeholder is stable.
- Crashes matches on `AppName`, `AppVersion`, `ModuleName`, `ExceptionCode` and `ReportId`, which are all on the keep list. It finds
  nearby events by searching their text for the report id, which isn't redacted.
- BSOD history reads the bugcheck code (`param1` / `BugcheckCode`, kept) and matches the dump file by its path. Dumps are under
  `C:\Windows`, so the path rules don't change it.

The built-in modules keep reading the logs directly in the app. Redaction is for user-mode modules only.

#### Limits

Redacting free text is best effort. A name the app can't recognise as personal (a document title that isn't a path, a contact name in
an app's own message) passes through. That is why `eventlog.read` stays on the About page list and in the remote-session notice, at
Medium sensitivity.

#### `windows.repairScan`

```csharp
RepairScanSummary s = await queries.RunRepairScanAsync(RepairScan.Dism, progress, ct);
```

- `Dism` runs `DISM /Online /Cleanup-Image /ScanHealth`. `Sfc` runs `sfc /verifyonly`. Both scans read only, and the repair itself is
  a fix (below).
- One scan at a time across the whole app, and it can take minutes. `progress` receives the app's progress lines, and cancelling `ct`
  stops the scan.
- Returns `Healthy`, `RepairableCorruption`, `NotRepairable` or `CouldNotRun`, plus the app's one-line summary.

### Risky queries

Every query above runs in the elevated app on a module's behalf. These are the ones that could hurt the person at the PC, worst first,
with what the design should do about each.

1. **`osquery.select`** is the most dangerous. It runs elevated, so a module sees more than the signed-in user could:
   - `file`, `hash` and `yara` can find and fingerprint any file on the PC, including other users' profiles, and `yara` can test file
     contents against a pattern (enough to learn a file a few bits at a time).
   - `registry` reads all of HKLM and every loaded user hive.
   - `shell_history`, `userassist`, `shellbags`, `prefetch` and `background_activities_moderator` show what the user ran and browsed.
   - `chrome_extensions`, `firefox_addons` and similar list browser data.
   - The event tables (`windows_eventlog`, `windows_events`, `powershell_events`) would get round the redaction.
   - **Decision:** replace the JSON-check denylist with an **allowlist** of hardware, OS, program, service, driver and network tables
     for `osquery.select`. A table not on the list is refused. JSON checks should move to the same allowlist.
2. **Fix requests.** The app runs the fix, but the module picks the target and writes the button text:
   - `EnableDevice` could turn a disabled camera or microphone back on. **Decision:** cameras, microphones and other capture devices
     are never a valid target for a module's fix request.
   - `EndProcessGroup` can close apps with unsaved work, and `ScheduleCleanRestart` restarts the PC.
   - `DisableSystemProxy` can take a work laptop off its company proxy or filtering. **Decision:** not offered to user-mode modules.
   - A module could label a button "Fix speakers" while the action restarts the PC. **Decision:** the app writes the button and
     confirmation text itself, from the fix kind and the validated target. The module's own label isn't shown.
3. **`storage.drives.identifiers`.** Serial numbers identify the drive and the PC, and can track it across installs and modules. It
   stays a separate capability, named on the About page, and is never needed for per-device history (use instance keys).
4. **`windows.repairScan`.** It isn't a privacy risk, but a module that keeps starting it ties up the disk and CPU for minutes each
   time and blocks the app's own repair. **Decision:** at most one scan per module per app session, unless the person at the PC
   starts it.
5. **`sensors.read`** is low risk: readings say little about the person, and the rate limit stops it being used to load the PC.

#### The bigger risk is outside host queries

An unsigned module runs as the signed-in user. Even with every rule above, it can read the user's documents and browser profiles,
decrypt what the user can decrypt with DPAPI (saved browser passwords, cookies), use the camera and microphone, and send all of it over
the network. Host queries add little to that. What would reduce it most:

- running the module host in an **AppContainer** with no capabilities, which blocks the user's files, the network, the camera and the
  microphone unless granted (the module would then need host queries for most of what "What a user-mode module can read without
  asking" lists);
- or, short of that, a Windows Firewall rule blocking outbound traffic from `RemotePCDiagnostics.ModuleHost.exe` and
  `RemotePCDiagnostics.ModuleUiHost.exe`, so what a module reads can't leave the PC.

### Instance keys

A per-device module needs a key for each drive, GPU or camera that stays the same across reboots, so its results and trends stay with
the right device. Hardware ids that do that (serial numbers, WWNs) also identify the device and the PC, so modules never get them as
keys. Each module gets its own opaque key instead:

```text
moduleKey = HMAC-SHA256(installSecret, moduleId + rawId)   (first 16 bytes, hex)
```

- `installSecret`: 32 random bytes the app creates once per install, in `%ProgramData%\RemotePCDiagnostics` with an admin-only ACL.
  A module, even a signed one, never reads it.
- `rawId`: the most stable id the app can read for the device, in this order:

  | Device | `rawId`, best first |
  |---|---|
  | Drive | serial number → WWN / storage `UniqueId` → GPT disk GUID → PCI location (last resort) |
  | GPU | PCI vendor/device/subsystem ids + PCI location |
  | Camera | PnP container id → device instance path |

What this gives a module, and why:

- **Stable:** the same device gets the same key for your module through reboots, port or slot moves and updates of your module.
- **Not reversible:** a plain hash of a serial number can be reversed by guessing (serial formats are predictable). With the secret it
  can't.
- **Not correlatable:** two modules get different keys for the same device, and two PCs give different keys. A vendor can't use keys to
  track a device or a PC across modules or installs.
- **No prompt:** keys carry no identity, so they need no permission. Only a module that needs the real serial (for example a warranty
  lookup) declares `storage.drives.identifiers`.

Why not the alternatives on their own (examples from a Windows 11 laptop with one NVMe SSD):

| Id | Example | Problem as the only key |
|---|---|---|
| PCI location / parent device | `Integrated : Bus 3 : Device 0 : Function 0` | It names the slot, not the drive: a replacement SSD inherits the old drive's history and wear trend. USB drives get a new key on every port. |
| GPT disk GUID | `{3b78f2d2-97b8-48d7-8cf4-3a696e9b0294}` | Changes when the disk is wiped or re-partitioned (a Windows reinstall). Clones share it. Blank and MBR disks have none. |
| PnP container id | `{00000000-0000-0000-FFFF-FFFFFFFFFFFF}` | Internal drives all report this placeholder. |
| Serial number / WWN | (20 characters) | Stable, but identifies the drive and the PC. Fine as `rawId` inside the app, but never given to a module. |

Notes:

- The app's own History keeps its current keys (`InstanceKeys.From`, a SHA-256 of `rawId`), so nothing already stored changes.
  Built-in modules aren't affected.
- If the install secret is lost (a reinstall that wipes `%ProgramData%`), every module key changes once, and third-party modules' per-device
  history starts over. That is acceptable. The app's own History isn't affected.
- When a better `rawId` becomes readable later (for example the app now runs elevated and can read the serial where it previously used
  the GPT GUID), the key changes. To avoid that, the app stores which `rawId` source it used for each device and keeps using it.

### Requesting a fix

A user-mode module never changes the PC, but its report can carry the app's own fixes. Put an `AreaAction` on a card or row, as a
built-in module does:

```csharp
new AreaAction(RemediationKind.OptimizeSsd, "Optimize this SSD", Target: drive.Letters, TargetLabel: drive.Label)
```

Today, the app strips every action from an unsigned module's report. With contract 1.2 the app keeps an action when:

1. its `Kind` is listed in the module's `fixes` in `module.json`;
2. its `Kind` is in the list below, which the app allows for user-mode modules; and
3. the app validates its `Target` (the drive, service, device or process must exist and must be a kind of target the fix accepts).

When the person clicks the button, the app runs the fix exactly as it does for a built-in module: confirmation, the change journal,
undo where possible, actor attribution and, in a remote session, the notice to the person at the PC. The module is told the outcome
(`FixOutcome`: `Done`, `Declined`, `Failed`, with a message) through `IDiagnosticModule.OnFixCompleted` (new in 1.2, optional), and can
re-run its check.

Fixes a user-mode module may request:

| Area | `RemediationKind` | Target |
|---|---|---|
| Drivers & updates | `CheckAndInstallDriverUpdates`, `CheckAndInstallWindowsUpdates`, `ScanHardwareChanges` | none |
| | `RestartDevice`, `EnableDevice` | a device instance id the app can see, never a camera, microphone or other capture device |
| Performance & power | `SetBalancedPowerPlan`, `DisableFastStartup`, `ScheduleCleanRestart`, `CancelScheduledRestart` | none |
| | `EndProcessGroup` | a process name currently running in the user's session (never a system process) |
| Network | `FlushDnsAndRenewIp`, `ResetDhcpDns`, `SetPublicDns` | an adapter name, or none |
| Storage | `CleanTempFiles` | none |
| | `OptimizeSsd` | a drive letter of an SSD |
| Windows repair | `RepairComponentStore`, `RepairSystemFiles` | none. Offered only after a `windows.repairScan` found repairable corruption in this run |

A module can't add new kinds of fixes. A new kind is code that runs elevated, so it goes into the app through a reviewed pull request.

### Declaring it in `module.json`

```json
{
  "id": "6f0b6c1e-1d0e-4c41-9a43-0a7f2f6d7a10",
  "slug": "contoso.ssdcare",
  "displayName": "SSD care (Contoso)",
  "version": "1.0.0",
  "contract": "1.2",
  "entryType": "Contoso.SsdCare.Plugin",
  "kind": "Check",
  "group": "storage",
  "capabilities": [ "storage.drives", "sensors.read" ],
  "fixes": [ "OptimizeSsd" ],
  "changesSystem": false,
  "needsAdmin": false
}
```

- `capabilities` and `fixes` are new in contract 1.2. Leave them out if you don't use them.
- Keep `needsAdmin` and `changesSystem` `false`. A module that gets its admin data through host queries and changes the PC only
  through fix requests doesn't need admin itself. Setting either flag on an unsigned module still disables it.
- An unknown capability or fix name disables the module at startup, with the reason on the About page and in Event Log 1800.

### Writing the module

`IHostQueries` lives in `RemotePCDiagnostics.Abstractions`, the only assembly a module references. Ask for it in your module's
constructor; the app registers it for your plugin:

```csharp
public sealed class SsdCarePlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddSingleton<IDiagnosticModule>(sp => new SsdCareModule(sp.GetRequiredService<IHostQueries>()));
}

public sealed class SsdCareModule(IHostQueries queries) : IDiagnosticModule
{
    public Guid Id { get; } = Guid.Parse("6f0b6c1e-1d0e-4c41-9a43-0a7f2f6d7a10");
    public string Name => "contoso.ssdcare";
    public string DisplayName => "SSD care (Contoso)";

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) =>
        Task.FromResult(ModuleAvailability.Available);

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken ct = default)
    {
        HostAnswer<IReadOnlyList<DriveHealth>> answer = await queries.TryReadDrivesAsync(ct);
        if (!answer.Ok)
            return CouldNotRun.Result(Name, answer.Reason);   // e.g. "The app isn't running as administrator"

        var worn = answer.Value!.Where(d => d.MediaType == "SSD" && d.Wear is >= 80).ToList();
        return worn.Count == 0
            ? new DiagnosticResult(Name, DiagnosticStatus.Ok, "All SSDs have plenty of life left", DateTimeOffset.Now)
            : new DiagnosticResult(Name, DiagnosticStatus.Warning, $"{worn.Count} SSD(s) over 80% worn", DateTimeOffset.Now);
    }
}
```

- Every query has a `Try…` form that returns `HostAnswer<T>` (`Ok`, `Value`, `Error`, `Reason`) and a plain form that throws
  `HostQueryException`. Use the `Try…` form in checks, so an unavailable reading becomes "Couldn't run" instead of a failed check.
- `Error` is one of the following:
  - `NotDeclared`: the capability isn't in `module.json`. This is a bug in the module.
  - `Unavailable`: no such hardware, or the app isn't elevated.
  - `Denied`: the person at the PC turned this capability off for your module.
  - `RateLimited`, `TooLarge`, `TimedOut`, `BadRequest`.
- Queries are async and can be cancelled. Cancelling your `RefreshAsync` cancels the queries it is waiting on.

### Testing

- **Unit tests:** use `FakeHostQueries` from the `RemotePCDiagnostics.Abstractions.Testing` package, setting the readings and errors
  your tests need. Your module never touches the pipe.
- **On a real PC:**
  1. Build the DLL and copy it into `%ProgramFiles%\RemotePCDiagnostics\modules` (admin).
  2. Turn on unsigned modules on the About page and restart the app.
  3. Run your check from the Checks page.
  4. Every query and its outcome is logged in the app log (`%LOCALAPPDATA%\RemotePCDiagnostics\logs\RemotePCDiagnostics.log`, lines
     starting with `Module host [<slug>]: query`).
- **Without admin:** start the app non-elevated to see how your module handles `Unavailable`. Fans and drive counters will be
  missing.

### Wire protocol (reference)

You don't need this if you use `IHostQueries`. The module host speaks it for you. It extends the existing JSON-lines protocol on the
host's stdin and stdout:

```text
host → app   {"type":"query","id":7,"capability":"storage.drives","args":{}}
app  → host  {"type":"answer","id":7,"ok":true,"value":[{"name":"SAMSUNG MZAL8512HDLU-00BL2","mediaType":"SSD", ...}]}
app  → host  {"type":"answer","id":8,"ok":false,"error":"notDeclared","reason":"storage.drives.identifiers isn't in module.json"}
```

- `id` is chosen by the host and is unique per message. Several queries can be in flight while a `refresh` runs. Answers can come back
  in any order.
- Limits:
  - 8 queries in flight per module and 1 MB per answer.
  - Each capability has its own rate limit and timeout (shown above).
  - A module that keeps exceeding them is stopped for this app session, and the About page says why.
- The app validates every `args` object against the capability's schema before doing anything, and ignores unknown fields.

### Remote sessions

Queries work the same way in a remote session. Fix requests follow the remote rules every fix follows: the actor is recorded, and the
person at the PC gets the notice. `eventlog.read` is named in that notice.

### Versioning

- Contract **1.2** adds `IHostQueries`, `HostAnswer<T>`, the `capabilities` and `fixes` manifest fields, and
  `IDiagnosticModule.OnFixCompleted`. These are additions, so 1.0 and 1.1 modules keep loading.
- New capabilities and fix kinds come in later minor versions. A module that lists a capability the running app doesn't know is
  disabled with a clear reason, so set `minHost` if you depend on a newer one.

### Open questions

- Should the person at the PC approve capabilities one by one (`eventlog.read` in particular) per module, rather than only seeing
  them listed?
- Reliability Monitor records: accept that a module can read them, or find a way to deny them to the module host?
- Which tables go on the `osquery.select` allowlist (see [Risky queries](#risky-queries))?
- AppContainer or a firewall rule for the module host: which one, and what do modules lose with an AppContainer?
- Do we want a `sensors.watch` stream, for stress-style modules that sample every second, instead of polling `sensors.read`?
- Signed third-party modules: is there ever a case for a partner key, or does everything go through host queries?


## 3. Service workflow fixes still to build

From `potential_performance_improvements.md`. Most of that backlog is built (the list is in
[architecture.md](architecture.md#service-workflow-fixes)); this is what is left.

### Leftovers noted under built items

- **2. Clean Old VS Code Commit Versions** — Not implemented here: `rootfs.vhdx.zst`, `OneDrive\ListSync`, `ProgramData\...\WER`.
- **3. Remove Pre-Installed OEM & Windows Consumer Store Bloatware** — **Status:** Store app removal + `ContentDeliveryManager` Implemented ✅ (service workflow, admin for removal; see App removal (#3, #8, #10)). **Narrator add-ons:** Implemented ✅ — one ticked card removes the 5 packages (publisher `cw5n1h2txyewy`, names checked on a test laptop) and sets `HKCU\Software\Microsoft\Narrator\NoRoam\WinEnterLaunchEnabled = 0` (undoable), only when Narrator isn't running and isn't in the Accessibility `Configuration` value (HKCU/HKLM). **Dropbox OEM promo** (`C27EB4BA.DropboxOEM_xbfy0k16fey96`, publisher id seen on a test laptop) is opt-in. **Not done:** `MapsBroker` / `MapsToastTask`, `Lenovo\UserGuide` and `McAfee\WPS` folders, Paint, the unused third-party Store app, VidyoConnect.
- **7. Optimize Common Heavy Collaboration, PDF & Media Apps Across Client PCs** — **Not done:** reschedule `\Adobe Acrobat Update Task` to night-only, `bAcroSuppressUpsell = 1`.
- **8. Remove / Disable Unused Xbox, Solitaire & Gaming Subsystem** — **Status:** Implemented ✅ as one opt-in card "Remove the Xbox apps and turn off Game DVR" (see App removal): 6 packages (`GamingApp`, `XboxGamingOverlay`, `XboxGameOverlay`, `XboxSpeechToTextOverlay`, `Xbox.TCUI`, `XboxIdentityProvider`), `GameDVR_Enabled` / `AppCaptureEnabled = 0`, the 4 services to **Manual** (not Disabled; only when they're Automatic now), `\Microsoft\XblGameSave\XblGameSaveTask` off. Solitaire is a separate opt-in consumer card; Mixed Reality Portal a ticked retired card. **Not done:** `Edge.GameAssist`, the `PresenceWriter` `ActivationType` / IFEO block.
- **10. Uninstall `Brother PowerENGAGE` & `Lenovo Now` Bloatware** — **Status:** `Lenovo Now` and `Brother PowerENGAGE` uninstall + their tasks Implemented ✅ (ticked; see App removal). **Not done:** `\GoogleUserPEH\*` and `\SoftLanding\*` tasks.
- **14. Shut Down Idle WSL 2 / AI Sandbox Virtual Machine** — **Not done:** stopping Claude Desktop's own VM (`vmmem` / `vmwp.exe`) directly; the service change keeps it from starting at sign-in instead.
- **20. Expand `ServiceCandidates` & Uninstaller Targets for Lenovo `NotifyMe` Telemetry & Brother Background Daemons** — service candidate detection is built; uninstall detection is pending.
- **Clean Stale Office Lock Files and Reset Bloated Excel15.xlb** — the lock files are built; backing up and resetting `Excel15.xlb` when it is over 1 MB is not.

#### 1a. Review Unused Agent Worktrees and Checkouts (Opt-In, Separate Deletion Approval)

* **Default:** Unchecked. Global **Select all** must not approve worktree deletion or bypass its separate confirmation. All candidate folders also begin unchecked.
* **Decision:** Reject age-only automatic deletion. Use Git checks to explain what exists, then let the user decide which unused project copies may be discarded. A dirty checkout can still be unwanted; a clean checkout is not automatically disposable.
* **Discovery:** Scan known agent worktree locations, including the AI agent CLI's `.grok/worktrees` and repository-local `.claude/worktrees`. Distinguish registered linked worktrees from standalone repositories and folders with broken Git metadata. Do not include the main project checkout automatically.
* **Review evidence:** Show the absolute path, project, branch or detached HEAD, estimated size, latest file write, tracked changes, untracked and ignored files, stashes, local-only commits, remote verification, active-session evidence, and unfinished Git operations. Report failed checks as unknown, never as clean or zero. Age is a sorting aid only.
* **Approval 1 — Select:** The user selects **Review unused agent worktrees and checkouts**, then individually selects folders from the evidence list. Selection alone schedules no deletion.
* **Approval 2 — Confirm deletion:** Show the exact paths and total estimated space with: **I confirm these selected project copies are unused and approve permanently deleting them, including any listed local changes or files not verified on the remote.** Require a separate unchecked confirmation and an explicit **Approve deletion of selected folders** action. Record the approved paths and disclosed findings before the unattended workflow begins. Confirmation applies only to those folders and that reviewed state; newly discovered folders never inherit approval.
* **Execution constraints:** Recheck paths, Git state, and active-session/operation status before deletion. Changed findings require renewed approval. Skip active, locked, inaccessible, or unresolved folders. Resolve broken Git metadata before offering deletion. Do not follow junctions or symlinks outside the approved folder. Preserve shared repository metadata and branches. Normally remove linked worktrees with `git worktree remove` without force; any discard requiring force must be specifically disclosed and approved. Standalone repository folders require their own explicit deletion handling.
* **Undo/reporting:** Deletion is irreversible unless an actual backup was made. Never claim that recreating a checkout restores deleted local files. Log deleted/skipped paths, reasons, and measured space reclaimed; exclude unapproved candidates from projected savings.
* **Implementation status:** Review and deletion are still planned for Phase 3. The detection split is done: `storage-grok` now covers only `sessions` and `downloads`, and `~/.grok/worktrees` is measured on its own as `storage-grok-worktrees` (category `Review`, unticked). It has no cleanup executor and no workflow fix; the Storage page lists it as *not deleted automatically*. No worktree deletion was performed during the scan or this backlog update.


#### 12. Visual Studio & `.NET` Build Speed: Automated Full-Path Defender Exclusions, Night-Only Updates & Cache Cleanup (`178 MB`)
* **Disk Space Saved:** **`178.0 MB`** (`WebView2Cache`) | **Speed/RAM Gain:** 20–40% faster `dotnet build` & lower `MsMpEng.exe` (`380 MB`) CPU/RAM spikes
* **Automated Remediation (Opt-In):**
  * From the elevated Admin Host, run `Add-MpPreference` for `-ExclusionPath` (`%USERPROFILE%\source\repos`, `%USERPROFILE%\.nuget\packages`) and `-ExclusionProcess` using verified full paths (`C:\Program Files\dotnet\dotnet.exe`, `MSBuild.exe`, `VBCSCompiler.exe`, `devenv.exe`).
  * Reschedule `\Microsoft\VisualStudio\Updates\BackgroundDownload` to night-only (`02:30 AM`) and clean `%LOCALAPPDATA%\Microsoft\VisualStudio\WebView2Cache` (`178 MB`).
* **Undo Support:** Run `Remove-MpPreference` and restore task XML via [`ChangeJournal`](../src/RemotePCDiagnostics.Core/Changes/ChangeJournal.cs).


Status of item 12 when this was moved: finding the code folders for the Defender exclusions is built; check the rest against the code.

### ⏳ Phase 2 — Hardware, Startup, Service & Storage Detection *(Partially Implemented; Windows Verification Pending)*

The models and several detectors are implemented. Phase 2 is not complete: the current storage scan covers only part of the detailed catalog, and automated Core tests do not verify live Windows registry or filesystem behavior.

| Area | Current coverage | Remaining work |
| :--- | :--- | :--- |
| Browser caches | Chrome and Edge, every profile (`Preferences` present); stale-cache rules covered by temp-folder tests | Verify on Windows with real profiles. |
| VS Code extensions | Superseded versions by version ordering, protected by `extensions.json`; GUID staging folders >7 days | Verify on Windows against a real `extensions.json`. |
| NuGet packages | Highest NuGet version and project-assets references under `source/repos` are protected; incomplete scans suppress package candidates | Validate on representative Windows installations; keep projects outside the configured scan root explicitly out of coverage. Deletion is implemented (`storage-nuget`) and re-runs these protections right before deleting. |
| Worktrees | Split out: measured as `storage-grok-worktrees` (review only, never deleted); the AI agent CLI cache category `storage-grok` covers sessions and downloads only | Implement item 1a's unchecked selection and separate approval before adding an executor. |
| Hardware, services, startup | Device facts, expanded service candidates, HKCU/HKLM/32-bit Run entries, and UWP startup tasks are implemented | Verify registry reads, permissions, startup changes, and restoration on Windows; service candidates do not imply uninstall detection or executors. |

### Undo rules for new fixes
* Every fix declares its [`UndoSupport`](../src/RemotePCDiagnostics.Core/Changes/Undoability.cs): `Full` (previous setting journaled and restored), `NothingToUndo`, `Reinstall` (undo reinstalls a removed Store app from the Microsoft Store; needs internet), or `None` (permanent, including deleted temporary files and emptied Recycle Bin items). Cleanup undo never creates replacement files. The legacy `PlaceholdersOnly` serialized value is retained for compatibility and displayed as permanent.
* `None` covers `Remove-AppxPackage` / `Remove-AppxProvisionedPackage` of packages without a verified Store id, program uninstalls, installed updates, and cache/package deletions. These are journaled as `ChangeKind.NotUndoable`; the workflow shows a **"can't be undone"** chip, and "Undo all" / `--undo-all` lists them as *left as is* instead of failing.
* `Reinstall` covers removed Store apps whose **every** removed package has a verified `RemovableAppx.StoreId` (a mixed removal stays `None`). Journaled as `ChangeKind.StoreReinstall` (Target = package family name, Previous = Store id, plus the label); the workflow chip is **"undo reinstalls from Store"**, the step-8 report lists them under *Removed apps that undo reinstalls from the Microsoft Store* (with "their settings and data aren't restored"), and a failed reinstall stays in the journal so it can be retried (see App removal).
* The storage scan (`ScanStorageCleanupsAsync`) is not part of the memory snapshot; it runs on demand and is cached for 5 minutes.
* **Storage cleanups** ([`StorageCleanupCatalog`](../src/RemotePCDiagnostics.Core/Storage/StorageCleanupCatalog.cs), [`StorageCleanupEngine`](../src/RemotePCDiagnostics.Core/Storage/StorageCleanupEngine.cs), Host [`StorageCleaner`](../src/RemotePCDiagnostics.Host/StorageCleaner.cs)): the workflow and the Storage page pass only a category id (`MemoryActionType.CleanStorage`); folders are rebuilt from the account's profile/AppData and the rule is evaluated on disk again right before deleting, never from saved state or the journal. Deletes only inside the category's exact allowlisted roots (under the account folders), refuses any target reached through a junction/symlink and never enters or deletes one, skips files in use and carries on, skips the whole category while its app runs (an unreadable process list counts as running), and never deletes browser cookies/logins/history/bookmarks/preferences or `.pst`. Each run that deletes something journals one `ChangeKind.NotUndoable` record (*"…: N files deleted, X freed (can't be undone)"*); the outcome says **Freed X**. Nothing deleted → nothing journaled. An open app → listed as skipped.
* **Registry values use one generic journal kind, `ChangeKind.RegistryValue`:** Target = `"HKLM\SOFTWARE\Policies\Microsoft\Dsh|AllowNewsAndInterests"`, Previous = the old DWORD as text, or null when the value was absent (undo deletes it). Every write, delete and restore goes through [`RegistryAllowlist`](../src/RemotePCDiagnostics.Core/Changes/RegistrySettings.cs), the exact values this app may change; a journal record whose target isn't listed is refused, never written. Read back after writing: if the value didn't stick (access denied, UCPD, organization policy), report failure and journal nothing. Labels include the old value (*"… (policy was not set)"*). New registry fixes add their value to the allowlist and reuse this kind.
* **Keys the app creates are removed again on undo:** before writing a value (`RegistryValue`, and the browser extension blocklist entry `ExtensionBlock`) the app records the topmost key in its path that didn't exist (`ChangeRecord.CreatedKey`, an optional JSON field; older journals simply don't have it), e.g. `SOFTWARE\Policies\Google` for the Chrome blocklist or `Software\Policies\Microsoft\Office` for the Office privacy policy. After undo deletes the value, [`RegistryKeyCleanup`](../src/RemotePCDiagnostics.Core/Changes/RegistryKeyCleanup.cs) deletes that key and the ones below it, deepest first, each only while it has no values and no subkeys (a key that still holds anything, and its parents, are kept). Only an allowlisted value's own key or its ancestors, two or more levels deep, are ever deleted. An empty Chrome / Edge policy key therefore doesn't linger (it can keep "Managed by your organization" showing). If a write fails, the keys it created are removed right away (best effort, logged).
* **Side-effect values are put back exactly (`ChangeRecord.PreviousExtra`):** a start-type change records whether the service's `DelayedAutostart` existed and its value; undo restores the start type, then deletes `DelayedAutostart` if it was absent or writes the old value (setting *Automatic* also no longer writes `DelayedAutostart = 0` where the value doesn't exist). Shrinking hiberfil.sys records whether `HiberFileType` and `HibernateEnabled` existed under `HKLM\SYSTEM\CurrentControlSet\Control\Power`; after undo's `powercfg /h /type full`, the ones that were absent are deleted again (the defaults are the same). Journals without this field are undone as before.
* **Default printer (#24) uses `ChangeKind.DefaultPrinter`:** the one non-DWORD value so far. Target is fixed (`HKCU|DefaultPrinter`), Previous = the old printer's name; undo accepts only that target and a plain or `\\server\printer` name of a printer that is still installed (see [`DefaultPrinter.Restore`](../src/RemotePCDiagnostics.Core/Optimizations/DefaultPrinter.cs)).


### ⏳ Phase 3 — Unattended Fix Executors & Undo Support *(Next Step)*
* **Worktree cleanup (item 1a):** Split worktree detection from auto-checked AI agent CLI cache cleanup; add an unchecked review item, unchecked per-folder selection, and a separate explicit deletion approval. Preserve the approved paths and findings across restarts, invalidate approval when findings change, and prevent Select all from bypassing approval. Implement linked-worktree and standalone-checkout handling separately, with truthful irreversible-deletion reporting.
* **Still to wire:** worktree cleanup (#1a, needs its two-step approval), and the smaller leftovers noted under each item (classic Teams leftovers, MapsBroker/Maps tasks, Excel15.xlb reset, OneDrive ListSync, ProgramData WER).
* **Done:** Storage cleanups (#1 without worktrees, #2, #5, #6, #13 lock files) are permanent fixes in the service workflow, one per measured category, ticked per `AutoCheckedByDefault` (Playwright and the classic `.ost` are opt-in), plus a **Caches and leftovers you can delete** card on the Storage page. Measured by `ScanStorageAsync` during the checks and again after the restart, before applying. Verify on Windows: VS Code commit-folder layout, real Chrome/Edge profiles, Store app caches, OneDrive/Olk log folders, and that locked files and junctions are skipped.
* **Done:** Teams startup (#7, all three Teams variants, opt-in) and Adobe update/licensing services to Manual plus Adobe startup helpers (#7, ticked) are in the service workflow with undo; verify on Windows that the Teams task ids and Adobe Run values match client PCs and that undo turns them back on. **Left in #7:** dead classic Teams leftovers, Teams `EBWebView` and Zoom `asr` cache pruning, the Acrobat update task and upsell setting, Electron app cache pruning. Rescheduling Zoom's hourly updater was dropped (not measurable).
* **Done:** Windows 11 Widgets (#16) and Search highlights (#17) are one-click admin memory fixes in the service workflow (full undo through `ChangeKind.RegistryValue`); verify on Windows that the policies take effect after a restart and that undo brings both back.
* **Done:** Office optional connected experiences (#18) is a one-click per-account (admin) memory fix in the service workflow, opt-in/unticked (full undo through `ChangeKind.RegistryValue`); Copilot is not included (no documented per-user setting). Verify on Windows (Microsoft 365 personal and work accounts) that Insert > Online Pictures and Smart Lookup are unavailable next launch, OneDrive saving and co-authoring still work, and undo brings them back.
* **Done:** Block junk / discontinued browser extensions (#22) is an opt-in admin memory fix, one card per allowlisted extension found in any Chrome/Edge profile (full undo through the new `ChangeKind.ExtensionBlock`, which removes only the blocklist entry this app added); verify on Windows that the browsers disable the extension, show "Managed by your organization", and re-enable it after undo.
* **Done:** Stop the non-default browser running in the background (#19): Local State `background_mode.enabled = false` for Chrome or Edge, Edge's `StartupBoostEnabled = 0` policy (managed banner noted on the card), and the browser's `--no-startup-window` auto-launch entries as startup apps; ticked, full undo (`ChangeKind.BrowserLocalStateValue` + `RegistryValue` + `StartupApp`). Verify on Windows that Edge's settings page reflects the change and Startup Boost stops at the next sign-in.
* **Done:** App removal (#3 Store/OEM apps + ContentDeliveryManager, #8 Xbox group, #10 Lenovo Now / PowerENGAGE + tasks) is in the service workflow: removed Store apps with a verified Store id are undone by reinstalling them from the Microsoft Store with winget (`ChangeKind.StoreReinstall`, `UndoSupport.Reinstall`); other removals are permanent (`NotUndoable`, admin); ContentDeliveryManager / Game DVR / Xbox services / tasks undo; see App removal.
* **Done:** Skip the Office start screen (#23) is a one-click per-account memory fix in the service workflow, ticked by default (full undo through `ChangeKind.RegistryValue`); verify on Windows that Word, Excel and PowerPoint open to a blank document next launch and that undo brings the start screen back.
* **Done:** Make Microsoft Print to PDF the default printer when the default is a network/WSD printer (#24) is a one-click per-account memory fix in the service workflow, opt-in (full undo through `ChangeKind.RegistryValue` for `LegacyDefaultPrinterMode` and the new `ChangeKind.DefaultPrinter` for the old printer's name); verify on Windows that `SetDefaultPrinter` sticks from the elevated Host, that Word/Excel no longer stall with the network printer asleep, and that undo restores the old default. The Office/Zoom night-only task rescheduling from #24 was dropped.
* **Done:** Idle WSL 2 / AI VM (#14): `CoworkVMService` (Claude Desktop) and `CodexSandboxService*` (OpenAI Codex) to Manual are in the service workflow, ticked when Automatic and a signed-in user may start them (full undo through `ChangeKind.ServiceStartType`); `wsl --shutdown` is one click on the live memory page only (allowlisted `System32\wsl.exe --shutdown`, nothing to undo). Verify on Windows the two services' security descriptors, that the apps start them on demand, and that `wsl --shutdown` from the elevated app reaches the signed-in user's WSL.
* **[`UndoService.cs`](../src/RemotePCDiagnostics.Core/Changes/UndoService.cs)**: Reuse the existing `ChangeKind.StartupApp` handler for UWP StartupTask state and HKCU/HKLM/WOW6432Node `StartupApproved`; verify restoration on Windows. New registry policy toggles reuse the generic `ChangeKind.RegistryValue` handler (add the value to `RegistryAllowlist`); add handlers for scheduled task XML restoration, and `powercfg /h` hibernate mode restoration as their executors are implemented.

## 4. Remote trust model

From `architecture-review.md` (the one finding still open). Every remote viewer who is given control has the same administrator power as
the person at the PC. There is no written trust model and no per-session "remote may change things" switch. Sharing control (the person
at the PC starts in control and hands it over; see [architecture.md](architecture.md#remote-sessions)) narrows this, but a remote user
who has control can still run every fix.

## 5. Proposals

None of these is built unless a note says otherwise.

### Proposal: Startup cleanup targets

| | |
|---|---|
| **Status** | Proposed |
| **Date** | 2026-11-02 |
| **Author** | Bud Cribar (drafted via assistant) |
| **Scope** | Disable (not uninstall) startup entries, services, and scheduled tasks |
| **Related** | [Application optimization modules](#proposal-application-optimization-modules), module 2 |

#### Summary

Many popular Windows programs leave behind Run keys, auto-start services, and scheduled tasks (mostly updaters and tray helpers) that add load at boot and sign-in. This proposal defines a **startup cleanup** feature that detects these items and lets a remote user **disable** them, reversibly. Nothing is uninstalled.

All service, task, and Run-entry names below are **typical** and must be **verified on a real machine**; names change between versions, installers (per-user vs per-machine), and vendors' rebrands. Nothing here comes from measurement.

#### Principles

1. **Detection is read-only by default.** A scan only reports.
2. **Disable is a separate, explicit remote user action.** No confirmation prompts; remote users have admin rights. The exact change is shown and logged.
3. **Always reversible.** Before any change, export prior state (service start type and status, task enabled state, Run value name/data, `StartupApproved` bytes) to an **undo file**. One-click undo restores it.
4. **Log every change** in the report: item, before, after, who/when.
5. **Exact matching only.** Match by exact service name / task path + publisher (Authenticode signer). Never loose name or substring matching.
6. **Per-user context.** For HKCU Run keys, report which user (SID and account name) the entry belongs to; offline user hives are reported, not edited, unless loaded explicitly.
7. **Verify after.** Re-read state after the change to confirm it stuck.
8. **Report failures honestly.** Protected services, tamper protection, access denied, or a vendor watchdog reverting the change are reported as failures, never as success.
9. **Flag re-enablers.** Items known to re-enable themselves after app updates or repairs are marked so the remote user knows the change may not last.

#### Rating key

- **Safe** – Safe and reversible; the app keeps working, only auto-start/background update is lost.
- **Caveats** – Safe with caveats; some feature (auto-update, sync, notifications, warranty tooling) stops until re-enabled.
- **Do not** – Do not disable by default; report only.

#### Targets

| Program | Typically leaves behind (verify) | Rating | Note |
|---|---|---|---|
| Adobe Acrobat / Reader | Service `AdobeARMservice`; task "Adobe Acrobat Update Task"; HKLM Run entry for update/notification helper (e.g. `AdobeAAMUpdater`/ARM tray, varies) | Caveats | Lose auto-update; Reader is a frequent exploit target, so advise manual updates. Repair/update may re-enable. |
| Adobe Creative Cloud | Run entry for Creative Cloud Desktop app; service `AdobeUpdateService`; Adobe Genuine services (`AGSService`, Adobe Genuine Monitor) | Caveats | CC app needed for sign-in/licensing/updates; Genuine services likely re-enable on update. |
| CCleaner | Tasks "CCleaner Update" / monitoring ("CCleanerSkipUAC" etc.); Run entry for monitoring/tray | Safe | Re-enables on update is common; flag. |
| Java (Oracle JRE) | Run entry `SunJavaUpdateSched` (`jusched.exe`) | Caveats | Lose auto-update; old Java is a security risk. |
| Lenovo Vantage | Services "Lenovo Vantage Service", "Lenovo System Interface Foundation" (`ImControllerService`, varies); tasks under `\Lenovo\` | Caveats | Provides driver/BIOS updates and battery/conservation settings; disabling the interface service can break hotkeys/features. |
| HP Support Assistant | Service "HP Support Solutions Framework" (`HPSupportSolutionsFrameworkService`); HP Telemetry/Analytics (`HpTouchpointAnalyticsClientService`); tasks under `\HP\`; promo/launcher shortcuts (e.g. Dropbox/trial offers) | Caveats | Telemetry and promo launchers: Safe. Support framework: drivers/BIOS/warranty tooling stops. |
| Dell SupportAssist | Services `SupportAssistAgent`, `DellClientManagementService`, Dell Update (`DellUpdate`/`DellTechHub`, varies); tasks under `\Dell\` | Caveats | Driver/BIOS/warranty tooling stops; Dell has shipped SupportAssist security fixes, so keep it updated if kept. |
| ASUS / Acer / MSI helpers | Armoury Crate/ MyASUS services (`ArmouryCrateService`, `ASUSOptimization`), Acer Care Center / Quick Access, MSI Center services | Caveats | Some control fans, keyboard lighting, or hotkeys; review per item. Trialware launchers: Safe. |
| Google Update (Chrome) | Services `GoogleUpdaterService…`/`GoogleUpdaterInternalService…` (new) or `gupdate`/`gupdatem` (legacy); tasks `GoogleUpdateTaskMachineCore`/`UA` or `GoogleUpdaterTaskSystem…` | Caveats | Chrome stops auto-updating (security). Re-created by Chrome on launch/update. |
| Microsoft Edge Update | Services `edgeupdate`, `edgeupdatem`; tasks `MicrosoftEdgeUpdateTaskMachineCore`/`UA` | Do not | Edge is part of Windows servicing; report only. |
| Firefox | Service `MozillaMaintenance` (Mozilla Maintenance Service); task "Firefox Default Browser Agent" | Caveats | Maintenance service enables silent updates; Firefox still updates in-app. Agent task: Safe. |
| OneDrive | HKCU Run `OneDrive`; tasks "OneDrive Standalone Update Task-S-…", "OneDrive Reporting Task" | Caveats | Sync and Known Folder Move stop; confirm user doesn't rely on it. |
| Dropbox | Tasks `DropboxUpdateTaskMachineCore`/`UA`; services `dbupdate`, `dbupdatem`; Run entry `Dropbox` | Caveats | Updater: Safe. Run entry: sync stops. |
| Google Drive | HKCU/HKLM Run `GoogleDriveFS` | Caveats | Drive letter/streaming files unavailable until launched. |
| iCloud | Run entries for iCloud / iCloudServices, `iCloudDrive` (Store version uses StartupTask) | Caveats | Photos/Drive sync stops. |
| Microsoft Teams | Classic: HKCU Run `com.squirrel.Teams.Teams`; new: StartupTask for `MSTeams` (Store package) | Safe | Lose auto-launch only; for work machines check policy. |
| Zoom | HKCU Run `ZoomIt`/Zoom autostart (setting-driven) | Safe | App may re-add it if "start with Windows" is on. |
| Slack | HKCU Run `com.squirrel.slack.slack` | Safe | Setting-driven; may re-add. |
| Discord | HKCU Run `Discord` (`Update.exe --processStart Discord.exe`) | Safe | Setting-driven; may re-add. |
| Spotify | HKCU Run `Spotify` | Safe | Setting-driven. |
| Steam | HKCU Run `Steam` (Steam Client Bootstrapper) | Safe | Service "Steam Client Service": leave (installs games). |
| Epic Games Launcher | HKCU Run `EpicGamesLauncher` | Safe | Setting-driven. |
| Skype | HKCU Run `Skype for Desktop` / StartupTask | Safe | Mostly legacy. |
| McAfee / Norton / Avast / AVG | Vendor services, tasks, Run tray entries | Do not | Security products: report only. Tamper protection will block or revert changes. Removal of trial AV is an uninstall decision, out of scope. |
| Microsoft Office (Click-to-Run) | Service `ClickToRunSvc` ("OfficeClickToRun"); task `\Microsoft\Office\Office Automatic Updates 2.0` | Do not | Service needed for Office to run. Updates task: report only. |
| Apple Software Update / Bonjour / iTunes | Task "AppleSoftwareUpdate"; service "Bonjour Service" (`mDNSResponder`); HKLM Run `iTunesHelper` | Caveats | iTunesHelper and updater: Safe. Bonjour: printer/AirPlay discovery may break. |
| VMware / VirtualBox | VMware: `VMAuthdService`, `VMUSBArbService`, `VMnetDHCP`, `VMware NAT Service`, tray Run entry; VirtualBox: `VBoxSDS`, drivers | Caveats | Set to Manual rather than Disabled; VMs/networking/USB passthrough need them. Never touch drivers. |
| NVIDIA | Service `NVDisplay.ContainerLocalSystem` (do not), telemetry tasks `NvTmRep_*`, `NvTmMon_*`, `NvProfileUpdater*` (older drivers), NVIDIA App/GeForce Experience Run entries | Caveats | Telemetry tasks and overlay launchers: Safe-ish. Display container: Do not (control panel breaks). Driver updates re-create tasks. |
| AMD / Realtek | AMD Software Run entry (`RadeonSoftware`), `AMD External Events Utility`; Realtek audio console / `RtkAudUService` | Do not | Hotkeys, audio jack detection, display events may break; report only. |
| qBittorrent / uTorrent | HKCU Run `qBittorrent` / `uTorrent` | Safe | uTorrent bundles adware; flag for review. |

#### Never disable

- Microsoft Defender (`WinDefend`, `WdNisSvc`, `Sense`) and Security Center (`wscsvc`).
- Windows Update (`wuauserv`, `UsoSvc`, `WaaSMedicSvc`, `BITS`) and related tasks.
- Real-time protection of any installed security vendor.
- Drivers and services critical for input, display, network, audio, storage (touchpad, Wi-Fi, GPU display container).
- `ClickToRunSvc` (OfficeClickToRun).
- BitLocker (`BDESVC`) and TPM/credential services.
- OEM firmware/BIOS update services: arguably optional, but default to report-only since disabling may break warranty and support tooling.

#### Proposed test: Adobe Reader on a GitHub-hosted runner

A CI job on `windows-latest` exercising detect → disable → undo end to end:

1. **Install** in its own step/job: `choco install adobereader -y --no-progress`, with retry (Chocolatey CDN and Adobe downloads can be flaky); pin a version (`--version x.y.z`) if latest drifts. No sign-in.
2. **Detect** and assert **at least one** Adobe update item: service `AdobeARMservice`, the "Adobe Acrobat Update Task" scheduled task, or an Adobe Run entry. Version-dependent, so assert "at least one", not an exact list.
3. **Disable**, then re-read state: service start type Disabled and stopped; task disabled; Run entry removed or `StartupApproved` set disabled. Assert an undo file exists and contains prior state.
4. **Undo**, then assert state equals the original.
5. *(Optional)* Trigger the updater or a repair and check whether it re-enables itself; record the result rather than failing the build.

**Limitations.** Fresh image with no user history; shared hosted runner; only proves the logic. Repeat on a real laptop or a self-hosted runner before trusting ratings.

**Complement: seeded fixtures.** A more reliable test creates its own fakes: HKCU/HKLM Run values, a dummy service (`sc.exe create RPDTestSvc …`), and a dummy scheduled task (`Register-ScheduledTask`), then runs detect/disable/undo against them and cleans up. Deterministic and independent of third-party installers.

#### Implementation notes (hypotheses to verify)

- **Services:** osquery `services` table or `Win32_Service` (name, start mode, state, path); change via `Set-Service`/`ChangeStartMode`. Capture original start type including delayed auto-start (`DelayedAutostart` registry value) for exact undo.
- **Scheduled tasks:** osquery `scheduled_tasks`; Task Scheduler COM (`Schedule.Service`) or PowerShell `Get-ScheduledTask` / `Disable-ScheduledTask` / `Enable-ScheduledTask`. Match by full task path.
- **Run keys:** `HKLM`/`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`, plus `WOW6432Node`; osquery `startup_items`. Prefer disabling via `...\Explorer\StartupApproved\Run` (as Task Manager does) over deleting values; if a value is deleted, store it in the undo file. *Hypothesis:* StartupApproved first byte `02` = enabled, `03` = disabled.
- **Store apps** (new Teams, iCloud): StartupTask state; *hypothesis:* readable via `HKCU\...\AppModel\SystemAppData\<pkg>\<task>\State`.
- **Publisher:** Authenticode signer of the target binary, compared with the data list.
- **Undo file:** JSON per run, stored with the report; undo applies entries in reverse order and re-verifies.
- **Data list:** ship targets as a data file (name, kind, signer, rating, note) so it can be updated without code changes.

#### Open questions for Bud

1. Disable Run entries via `StartupApproved` only, or also delete values (with undo)?
2. Services: Disabled or Manual as the default "off" state?
3. Should OEM support services be Caveats (disableable) or report-only by default?
4. Where should undo files live, and how long are they kept?
5. Is the Chocolatey Adobe Reader job worth the CI time, or fixtures-only with manual real-machine runs?

### Draft proposal for security in Service workflow

#### Review before applying fixes

Run the existing Security audit as an explicit option during workflow checks. Carry each finding into the review with the observed state, the affected scope, the collection time, and the source. Keep separate outcomes for passed, needs attention, managed by policy, and unable to verify.

| Finding | Proposed workflow behavior |
| --- | --- |
| Antivirus disabled, out of date, or unable to verify | Show the registered provider and its status. Offer a signature update for Microsoft Defender when it is the active provider. |
| Firewall profile disabled | Show the affected profile and policy ownership. Offer an opt-in fix only when local policy permits it and the remote user can assess remote connectivity. |
| Security updates pending | Show available evidence and offer the existing Windows Update action. Flag a pending restart in the service report. |
| BitLocker or device encryption, Secure Boot, and TPM | Report current state and refer policy or firmware changes to the remote user. |
| Suspicious exclusions or weakened protections | List the observed settings and explain the risk. Require explicit review before any change. |

#### Applying and verifying

Use the existing workflow approval and action results for supported changes. Leave security fixes unchecked by default. Re-read the relevant setting just before execution and skip a fix if the condition is already resolved or now managed by policy. After the action, rerun the affected check and log the verified outcome, including any restart requirement. Keep recovery keys and other secrets out of reports.

#### First increment

Start with Security audit findings and a read-only review summary. Add Defender signature updates and Windows Update as explicit actions after verifying the detection and post-action checks. Add firewall remediation after testing policy enforcement and remote session behavior.

### RemotePCDiagnostics hardware test proposals

**Status:** Proposed. Not implemented.

Publishing this document grants no implementation approval. This proposal covers USB and Bluetooth diagnostics, bounded local device history, video-memory integrity testing, and headless display checks.

#### USB diagnostic scope

1. Inventory USB controllers, hubs, connected devices, device classes, and available topology through Windows device APIs/WMI, supplemented by osquery where supported.
2. Show current device problem codes and relevant Windows event-log errors, separating historical errors from current faults.
3. Offer a small transfer check when a writable USB drive is present: create a unique test file, read it back, verify contents, and delete it afterward, including cancellation cleanup. Never overwrite existing files. This validates that drive's connection, not every port or maximum throughput.
4. Display USB-C power-delivery or charging information only where reliably exposed. Missing information is not a failed port.

#### Bluetooth diagnostic scope

1. **First release, alongside USB inventory.** Show detected Bluetooth adapters, radio state where available, driver version, and Windows device problem codes. Distinguish an absent adapter, a disabled radio, and a driver fault. Show paired peripherals and their current connection state where Windows exposes it. A paired device can be disconnected normally when asleep or out of range. [Windows Bluetooth connection status](https://learn.microsoft.com/windows/uwp/api/windows.devices.bluetooth.bluetoothdevice.connectionstatus)
2. **Follow-up for intermittent faults.** Correlate observable disconnects and reconnects with adapter or driver errors. Reuse the bounded local history design below. Report monitoring gaps and avoid storing device addresses or names unless needed locally for diagnosis.
3. **Optional functional test.** Let the user choose a known-good device and verify a profile-specific action, such as audio playback or an input event. A generic inventory check cannot certify range, audio quality, or every Bluetooth profile. Keep pairing, unpairing, and radio resets out of the read-only diagnostic.

#### Bounded local device history

1. Record connection and disconnection times, device class, available identifiers, controller/hub location, and associated errors. Aggregate repeated events into reconnect counts.
2. Store changes rather than constant snapshots. Retain records for 30 days and apply a finite size cap, removing oldest records first; the cap value remains to be chosen before implementation.
3. Mark monitoring gaps explicitly. Do not infer precise disconnect times from missing snapshots; snapshots can miss brief reconnects.
4. Keep history on the diagnosed PC by default, with controls to clear individual device history or delete all history.
5. Treat device names and serial numbers as sensitive. Collect no file contents and omit identifying details from exports by default.
6. Use history to highlight frequent reconnects, enumeration failures, and devices no longer detected. These are diagnostic clues, not proof of a bad port.

#### Blazor presentation

Retain the existing colors, fonts, and sidebar. Present current devices, current problems, historical errors, and transfer-test results distinctly. Add a history section beside current devices, highlighting frequent reconnects and newly reported errors. Show monitoring gaps and unavailable fields clearly.

#### Physical limits

Software cannot certify signal integrity, connector damage, actual power output, or whether an unused port works. A person must connect a known-good device to each port; cable and charging faults may require a USB power meter. A device disappearing from history may simply mean it was unplugged.

#### Video-memory integrity proposal

1. **Automatic inventory:** read GPU identity, driver version, dedicated/shared memory and memory budgets through DXGI/Windows APIs, supplemented by WMI/osquery where supported. Memory type may be unavailable; do not rely solely on WMI memory-size values.
2. **Automatic context:** collect GPU resets, display-driver errors, and relevant hardware errors from Windows event logs. Compare exact GPU/driver versions against documented known issues; version matching alone does not diagnose a defect.
3. **Controlled offscreen workload:** allocate a bounded portion of available GPU memory, write known patterns, read them back, and count mismatches. Report the amount actually tested, duration, errors, and device resets. No screen observation is required for these comparisons.
4. Keep an optional visible artifact test separate from the automatic integrity test. It requires a person to observe the physical display.
5. On the Lenovo integrated GPU, explain that graphics memory shares system RAM rather than being separate VRAM, so results overlap with RAM testing.
6. **Safety:** start with a short run, retain memory headroom, support cancellation and runner-owned cleanup, enforce a watchdog, monitor temperature when available, and stop on overheating or device errors. A GPU reset may interrupt the remote session.
7. **Limits:** a pass covers only allocated memory and the patterns exercised. Software cannot certify the GPU chip, solder joints, cooling hardware, or every memory location. Physical diagnosis remains necessary for those.

#### Headless display checks

Prioritize checks that explain reported symptoms. Most checks on a working laptop will return normal data; no measured detection or false-negative rates are available.

1. **Top priority — configuration:** inspect active resolution, refresh rate, HDR state/capability, scaling, enabled monitors, primary display, and arrangement. Distinguish physical displays from virtual or remote-session displays. Useful for configuration complaints, but an unwanted supported setting is not necessarily a hardware fault.
2. **Top priority — stability correlation:** correlate display connection/mode changes with recorded driver crashes, GPU resets, and disconnects. This offers useful evidence for intermittent failures, but cannot conclusively distinguish driver, cable, dock, power, or hardware causes, or prove the physical panel went black.
3. **Supporting information — identity/EDID:** collect available model identity, supported modes, and reported HDMI/DisplayPort/eDP connection type. Missing or malformed EDID can be a clue; docks/adapters may alter results. Identity has low standalone fault-finding yield.
4. **Next — load/throttling:** reuse existing GPU-load telemetry rather than duplicate it. Observe supported temperatures, clocks, throttling indicators, and resets during bounded workloads. Useful for load-triggered symptoms; normal laptop power limits can also reduce clocks and are not inherently faults.
5. **Lower priority — brightness readout:** read supported WMI brightness values; contrast may require supported DDC/CI controls. Low fault-finding yield: a reported value cannot establish physical brightness or backlight condition.
6. **Optional — active refresh-rate/brightness switching:** exercise supported changes and restore original settings. Useful mainly to reproduce a reported problem; may blank the display or disrupt remote access. Successful API calls do not prove correct physical output.
7. Driver versions are context, not a diagnosis: an old driver alone is not a fault. Documented issues matching the installed version and observed symptoms provide stronger evidence.

False negatives remain a major limitation: clean logs and successful checks can miss dead pixels, backlight defects, visible flicker, color faults, and black screens without a driver signal. Short workloads can miss intermittent faults. Physical image quality still needs human observation or controlled camera measurements; do not label it passed from headless checks.

#### Additional device tests in priority order

1. **Keyboard, touchpad, and touchscreen.** Add a guided local test for key presses, clicks, scrolling, gestures, and touch across the panel. Show which inputs were observed and identify untested areas. Require local participation and distinguish physical input from remote or injected input where Windows exposes the source. If the source cannot be established, report that the physical device could not be verified.
2. **Sleep, wake, and resume.** Add a standalone read-only check for the last wake source, sleep blockers, and abnormal standby drain on supported systems. Correlate recorded resume times with USB, Bluetooth, display, and network failures. Use existing evidence during a remote session. [Windows power diagnostics](https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options)
3. **Dock and USB-C connection health.** Combine USB, display, network, and audio observations in one view. During a guided connection, show which displays, Ethernet adapters, audio endpoints, and hubs appeared. Flag missing functions only when the expected dock capabilities are known, and highlight multiple devices dropping around the same time.
4. **External storage and card readers.** Check whether Windows sees the reader, detects inserted media, and reports I/O errors. Extend the USB transfer-integrity check to removable media on a user-selected writable volume, using the same temporary-file and cancellation cleanup rules.
5. **Charging and AC adapter stability.** Extend Battery & power plan with a guided plug/unplug check and an AC-to-battery transition timeline. Show whether the PC detected external power and whether the battery began charging. Report adapter wattage only when Windows exposes it.
6. **Ethernet and Wi-Fi adapter diagnostics.** Extend the network checks with negotiated Ethernet speed, local link drops, adapter resets, and Wi-Fi reconnects. Correlate adapter events with connectivity loss to help separate a local link fault from an upstream problem.

#### Working-set tradeoffs when splitting tests into executables

A separate executable lets a diagnostic run under a restricted user token while the main application stays elevated. It also adds a process and a .NET runtime while the test runs. The experiments used one module DLL per `ModuleHost.exe` worker as a proxy for a standalone test executable. The current app shares workers across bundled modules at the same privilege level, so the per-worker measurements below do not predict the current cost per bundled module. Module connections close after two idle seconds by default. A module can opt into a persistent connection with `keepAlive` in its manifest. See [the bundled module design](roadmap.md#implemented-modules-that-ship-with-the-app).

##### In-process versus out-of-process

The same lightweight sample uptime check ran three times per configuration. A small .NET parent loaded the module directly in one configuration. In the other, `ModuleHost.exe` loaded it and returned a result over stdout, then exited on request. The table shows median increases over the parent baseline. The loaded measurement was taken after the result arrived, while the code or worker was still resident.

| Execution model | Added working set while loaded | Added private working set while loaded | Added private working set after completion and any worker exit |
|---|---:|---:|---:|
| Module loaded in the parent | 15.5 MiB | 3.7 MiB | 3.7 MiB |
| Separate worker, then exit | 38.6 MiB | 7.5 MiB | 0 MiB measured |

Keeping idle workers connected after the same check accumulated private working set. Across three trials, the medians were:

| Idle workers | Combined working set | Combined private working set |
|---:|---:|---:|
| 1 | 39 MiB | 8 MiB |
| 4 | 156 MiB | 31 MiB |
| 8 | 311 MiB | 61 MiB |

All workers exited cleanly on `exit`. A fresh worker took 274 ms median to start, run the sample, and exit. A warm worker returned the same result in 0.3 ms median. Combined working set can count the same shared pages in each process. Private working set measures resident pages private to each process.

##### Shared DLLs and custom UI

- The Host and ModuleUiHost build directories contained 18 byte-identical DLLs totaling 29.6 MiB. `Microsoft.Windows.SDK.NET.dll` accounted for 23.7 MiB. These are unpacked file sizes. A page-sharing probe returned the maximum share count for both separate copies and shared files, so it could not quantify physical RAM savings.
- Two `ModuleUiHost` instances rendered the same sample clock through a local relay. After warm-up, separate folders measured 291.77–291.81 MiB total and 76.71–76.79 MiB private working set. A shared folder measured 291.51–292.28 MiB total and 76.52–77.27 MiB private. The file layout made no measurable difference to these counters in this workload. Production instances of ModuleUiHost already launch from the same folder.
- In a separate navigation trial, one rendered module UI host used 168 MiB working set, including 56 MiB private, and exited cleanly when the browser navigated away. The UI measurements cover the host processes alone. WebView2 children, the browser, and the relay were outside those totals.

##### Implications for the conversion

Use on-demand workers where restricted execution matters. Use the default short idle exit for finite hardware tests. Reserve `keepAlive` for modules that need a persistent process, and account for those workers in the memory budget. Limit concurrency so active workers cannot accumulate across a batch. Keep the result in the main application for display. Sharing DLLs can reduce deployment duplication, but the experiments found no working-set improvement from moving the same workload to one DLL folder.

Before estimating the effect of converting all modules, compare the same representative heavy checks in the full WPF app and in restricted workers. Measure peak private working set during each run and idle private working set after completion across the full process tree, including subprocesses started by the checks. The sample established the direction of the tradeoff for a lightweight module. It did not measure the full application's peak or unique physical RAM.

### Proposal: Application optimization modules

Some of this may already exist in part (a `ResourceHogs` module, and the browser background and extension fixes in the service workflow). Check the code before starting.

| | |
|---|---|
| **Status** | Proposed |
| **Date** | 2026-11-02 |
| **Author** | Bud Cribar (drafted via assistant) |
| **Scope** | New on-demand diagnostic modules for RemotePCDiagnostics |

#### Summary

RemotePCDiagnostics already tells a remote user whether the *hardware* is healthy: osquery inventory, LibreHardwareMonitor sensors, CPU/disk/memory/network/GPU stress tests, a security audit, and speaker/microphone audio tests, with webcam and NPU tests in progress. Many "my laptop is slow" complaints, however, are caused by *software*: a browser with dozens of tabs and extensions, a cloud sync client stuck re-indexing, two antivirus products fighting, OEM utilities at startup, or WSL holding gigabytes of memory.

This proposal adds a set of **application optimization modules** that identify which applications are consuming resources on a typical Windows laptop, explain why it matters, and point the remote user at a fix. Detection is read-only. Fixes are always a separate, explicit remote user action. The work is split into three phases, starting with three general-purpose modules that cover most cases.

Statements in this document about how much resource a given application typically uses are **general observations**, not measurements. No figures here come from profiling; any thresholds must be established and validated during implementation.

#### Goals

- Name the application (not just the process) responsible for high CPU, memory, or disk use.
- Show what starts with Windows and estimate its impact, flagging OEM bloatware.
- Detect background activity that commonly makes a machine feel slow: antivirus scans, cloud sync problems, indexing, updates.
- Give app-specific guidance for the most common heavy applications (browsers, Office/Outlook).
- Work on typical Windows laptops from any vendor, not only the Lenovo IdeaPad 1 15ALC7 (Ryzen 7 5700U) used for development.
- Work identically in local and remote (RemoteBlazorWebView) mode.

#### Non-goals

- Automatic remediation. No module changes system state during a scan.
- Replacing the security audit. Antivirus *health* stays in the security audit; this proposal only looks at antivirus *performance impact*.
- Uninstalling software, editing user content, or changing app settings without a remote user action.
- Telemetry, cloud lookups, or uploading any collected data.
- Restyling the existing UI.

#### Design principles

1. **No confirmation prompts before tests.** Remote users already have admin rights; modules run when selected.
2. **Read-only by default.** Every module produces findings only. Any fix (disable a startup item, disable an add-in, restart a sync client) is a separate button the remote user presses deliberately, with the exact change shown, and is logged in the report.
3. **Security audit stays separate.** It is not part of the stress run, and these modules do not merge into it.
4. **On-demand and unticked by default.** New modules appear in the module list *after* the security audit and are not selected by default, so the existing stress run is unchanged.
5. **No UI restyling.** New modules reuse existing result components and layout.
6. **Privacy and minimal collection.** Collect process names, publishers, counts, and sizes, not document titles, URLs, browsing history, email content, or file names inside user folders. Nothing is uploaded. In remote mode, only the summarized findings are shown to the remote user.
7. **Core logic behind interfaces; Windows-only code in the host.** As with the audio tests: classification and verdict rules live in `RemotePCDiagnostics.Core` behind interfaces (e.g. `IProcessSnapshotSource`, `IStartupItemSource`), with Windows data collection (WMI, performance counters, registry, osquery) in `RemotePCDiagnostics.Host`.
8. **Unit tests on synthetic data.** Rules are tested in `RemotePCDiagnostics.Tests` against synthetic snapshots (fake process trees, startup lists, sync states). CI (`.github/workflows/ci.yml`) is the build check; no tests require a live Windows session.
9. **Rules as data.** Known apps, publishers, and thresholds are kept in a data file (similar in spirit to `docs/sensor-thresholds.md`) so lists can grow without code changes.

#### Priority roadmap

| # | Module | Phase | Priority | Depends on | Notes |
|---|---|---|---|---|---|
| 1 | Top resource consumers report | 1 | High | osquery, perf counters | Foundation for most later modules |
| 2 | Startup items with impact | 1 | High | osquery, registry | Includes OEM bloatware flags |
| 3 | Antivirus and cloud sync activity | 1 | High | #1, WMI/Defender | AV health remains in security audit |
| 4 | Browser check | 2 | Medium | #1, osquery browser tables | |
| 5 | Office and email add-in check | 2 | Medium | registry, file sizes | Relates to existing `OutlookBenchmark` |
| 6 | Communication and meeting apps | 3 | Low | #1, webcam/audio tests | |
| 7 | Media apps | 3 | Low | #1, GPU sensors | |
| 8 | Developer tools | 3 | Low | #1 | WSL2/vmmem, Docker |
| 9 | Gaming launchers and overlays | 3 | Low | #1, #2 | |
| 10 | Manufacturer tools and bloatware | 3 | Low | #2 | Likely folded into #2 |
| 11 | Background system activity | 3 | Low | #1, #3 | Likely folded into #1/#3 |

Several Phase 3 items overlap with modules 1 and 2. Where that happens, they should be implemented as **rule sets** (data) consumed by modules 1–3 rather than separate modules.

#### Common output format

Each module returns the same shape as existing modules:

- **Verdict:** `Pass`, `Warning`, or `Fail`.
- **Findings:** a list of items, each with
  - `Severity` (Info / Warning / Fail)
  - `Application` (friendly name and publisher)
  - `Observation` (what was seen, e.g. "17 processes, rolled up to Google Chrome")
  - `Why it matters` (one sentence)
  - `Suggested action` (text; optional link to an explicit fix action)
  - `Evidence` (minimal raw values: process count, working set, CPU %, file size)
- **Collection notes:** what could not be read (e.g. per-user data for another user, access denied), so a missing finding is not mistaken for a clean result.

Verdict rule of thumb: `Fail` only for clear, actionable problems (e.g. two real-time AV products active); `Warning` for likely contributors; `Pass` otherwise.

---

#### Phase 1

##### 1. Top resource consumers report

**What it checks.** Samples CPU, memory (working set and private bytes), and disk I/O per process over a short window, groups processes into applications using the process tree and executable path, and reports the top applications by each resource.

**Why it matters.** Task Manager shows dozens of `chrome.exe`, `msedgewebview2.exe`, or Electron helper processes separately; the user and remote user need "Chrome is using most of the memory", not 30 lines. This is also the data foundation for modules 3–11.

**Implementation notes.**
- osquery `processes` (pid, parent, path, resident size, user/system time) for the snapshot; two samples a few seconds apart give CPU deltas.
- Windows Performance Counters (`Process` category: `% Processor Time`, `Working Set - Private`, `IO Read/Write Bytes/sec`) as an alternative or cross-check. *Hypothesis to verify:* whether perf counters or osquery deltas are more reliable on low-core laptops without disturbing the result.
- Grouping: walk parent PIDs up to the top-level app process; fall back to grouping by executable path and file version `ProductName`/`CompanyName`. WebView2 hosts (`msedgewebview2.exe`) should be attributed to their parent app where possible. *Hypothesis:* parent-PID chains are sometimes broken when parents exit; path-based grouping is the fallback.
- Report system totals (commit charge vs installed RAM, pagefile use) so per-app numbers have context.
- Do not collect command lines or window titles by default (they can contain URLs and file names).
- Testability: `IProcessSnapshotSource` returning synthetic trees; tests cover rollup, orphaned children, and ranking.

##### 2. Startup items list with impact

**What it checks.** Enumerates everything that starts at sign-in or boot, whether it is enabled, its publisher, and an estimated impact; flags known OEM bloatware and unsigned or unknown entries.

**Why it matters.** Startup load is a common cause of slow boot and sluggish first minutes after sign-in, especially on laptops with modest RAM and pre-installed OEM software.

**Implementation notes.**
- Sources: registry Run/RunOnce keys (HKLM and HKCU, including `WOW6432Node`), user and common Startup folders, `Win32_StartupCommand` (WMI), osquery `startup_items`, `scheduled_tasks` (logon/boot triggers), and `services` (auto-start, non-Microsoft).
- Enabled state: `HKCU/HKLM\...\Explorer\StartupApproved\Run` and `StartupFolder` values, which reflect Task Manager's enable/disable toggles.
- Impact: use Windows' own startup impact data where available. *Hypothesis to verify:* Task Manager's "Startup impact" is derived from boot diagnostics data that may not be exposed through a stable API; if not readable, estimate impact from binary publisher, process size at runtime (module 1), and whether it stays running.
- Publisher from Authenticode signature and file version info; classify Microsoft / OEM / third-party / unsigned.
- OEM bloatware: a data list (Lenovo, HP, Dell, ASUS, Acer, MSI utilities, trialware) with "keep / review / optional" guidance; some vendor utilities provide firmware and driver updates and should not be blindly flagged.
- Fix action (separate, explicit): disable via `StartupApproved` the same way Task Manager does, so it is reversible.
- Target list and safety ratings: see [Startup cleanup targets](#proposal-startup-cleanup-targets).

##### 3. Antivirus and cloud sync activity check

**What it checks.** Whether antivirus or cloud sync is actively consuming resources *right now*, and whether either is in a bad state.

- Antivirus: real-time protection active, a quick/full scan running, AV process CPU/disk use, and more than one real-time AV product registered.
- Cloud sync: OneDrive, Dropbox, Google Drive, iCloud running; signs of stuck sync, re-indexing, or error state; high sustained CPU/disk.

**Why it matters.** A scheduled full scan or a sync client re-indexing a large folder can saturate disk and CPU on a laptop and is easy to mistake for a hardware fault, which can also skew stress-test results. Two real-time AV products often conflict.

**Implementation notes.**
- Defender: `Get-MpComputerStatus` (or `MSFT_MpComputerStatus` in `root\Microsoft\Windows\Defender`) for real-time state, last scan times, and scan in progress. *Hypothesis to verify:* which field reliably indicates a scan *currently* running versus last scan.
- Third-party AV: `root\SecurityCenter2` `AntiVirusProduct` (workstation only; not present on Server); decode `productState` for enabled/up-to-date. Report two enabled products as `Fail`.
- AV process load from module 1 (e.g. `MsMpEng.exe`, vendor engines).
- OneDrive: process presence and load; per-user registry under `HKCU\Software\Microsoft\OneDrive\Accounts`; sync state. *Hypothesis:* sync status is not exposed via a public API; logs under `%LOCALAPPDATA%\Microsoft\OneDrive\logs` are binary/obfuscated, so detection may be limited to process load over time plus account configuration.
- Dropbox / Google Drive / iCloud: process presence and sustained load; vendor status files where documented. Treat state detection beyond "sustained high load" as a hypothesis.
- This module reports performance impact only. AV configuration and health remain in the security audit.

#### Phase 2

##### 4. Browser check

**What it checks.** For Chrome, Edge, and Firefox: process count, total memory (rolled up from module 1), number of installed extensions, hardware acceleration setting, and flags for extensions known to be heavy or suspicious.

**Why it matters.** Browsers are commonly the largest memory consumer on a laptop. Extensions run on every page, and disabled hardware acceleration shifts video decode to the CPU.

**Implementation notes.**
- osquery `chrome_extensions` (covers Chromium-based browsers including Edge, per profile), `firefox_addons`, `browser_plugins`.
- Hardware acceleration: Chromium `Local State` (`hardware_acceleration_mode`) and Firefox `prefs.js`. *Hypothesis:* key names and defaults vary by version; verify on current builds.
- Extensions are reported by name and ID only. No history, bookmarks, URLs, or tab titles.
- Heavy-extension list maintained as data; start small and conservative.
- Policy-managed settings (`HKLM\Software\Policies\...`) noted, since the remote user may not be able to change them.

##### 5. Office and email add-in check

**What it checks.** Outlook data file sizes (OST/PST), COM add-ins for Outlook/Word/Excel with load behavior and load time, and Outlook options that commonly slow startup.

**Why it matters.** Large OST files, slow add-ins, and caching shared mailboxes are common causes of slow Outlook startup. The repo already contains `tools/prototypes/OutlookBenchmark`; this module should reuse or align with it.

**Implementation notes.**
- COM add-ins: `HKCU`/`HKLM\Software\Microsoft\Office\<App>\Addins\*` (`LoadBehavior`, `FriendlyName`), plus `WOW6432Node`. Disabled-item and slow-add-in data under `...\Office\16.0\<App>\Resiliency`. *Hypothesis:* Office records add-in load times in Resiliency keys; format to verify.
- OST/PST size: file sizes in `%LOCALAPPDATA%\Microsoft\Outlook` (size only, never content).
- Cached Exchange settings from the Outlook profile registry. *Hypothesis:* "Download shared folders" and "Download headers only" flags are readable from the profile; verify, otherwise report as guidance only.
- Reference tips (from Bud) to surface as guidance where detection supports them:
  - Outlook › File › Options › Advanced: turn off **Download shared folders** on cached Exchange accounts if not needed.
  - Outlook: turn off **Download headers only** on the cached Exchange account.
  - Disable unneeded COM add-ins in Outlook, Word, and Excel.
  - Word: turn off **Open e-mail attachments in Full Screen Reading view** if not needed.
- Fix action (explicit): set `LoadBehavior` to disable a selected add-in, reversible.

#### Phase 3 (lower priority)

##### 6. Communication and meeting apps

**Checks.** Teams, Zoom, Slack, Discord: running state, rolled-up memory, and CPU/GPU during a call.
**Why.** These are often Electron/WebView2 apps that stay resident; call-time video encoding is CPU/GPU heavy on entry-level laptops.
**Notes.** Mostly rules on module 1 data. Optional "call load" sample while the remote user runs a test call; link findings to the webcam and audio tests so device and app problems are separated.

##### 7. Media apps

**Checks.** Spotify, VLC, browser streaming: whether video decode is hardware-accelerated.
**Why.** Software decode raises CPU use, heat, and battery drain.
**Notes.** GPU engine counters (`GPU Engine` category, `engtype_VideoDecode`) per process. *Hypothesis:* per-process video decode counters are reliable on AMD/Intel integrated GPUs; verify.

##### 8. Developer tools

**Checks.** Visual Studio, VS Code, Docker Desktop, WSL2 (`vmmem`/`vmmemWSL`), Node, Android emulators; memory held after use.
**Why.** WSL2 and emulators can hold large amounts of memory after work is finished.
**Notes.** `wsl --status` / `wsl --list --verbose` for running distros; `vmmem` working set from module 1; `.wslconfig` memory limit presence. Fix action (explicit): `wsl --shutdown`.

##### 9. Gaming launchers and overlays

**Checks.** Steam, Epic, Xbox Game Bar, Discord and GeForce/Radeon overlays, RGB/peripheral software.
**Why.** Launchers and overlays often start with Windows and hook into rendering.
**Notes.** Mostly startup rules (module 2) plus Game Bar/Game DVR registry settings.

##### 10. Manufacturer tools and bloatware

**Checks.** Lenovo Vantage, HP Support Assistant, Dell SupportAssist, ASUS/Acer/MSI utilities, trialware.
**Why.** Common on new laptops; some are useful (firmware/driver updates), some are not.
**Notes.** Best implemented as the OEM rule list inside module 2, with osquery `programs` for installed software.

##### 11. Background system activity

**Checks.** Windows Search indexing, Windows Update downloads/installs, Delivery Optimization, maintenance tasks, `TiWorker`/`SearchIndexer` load.
**Why.** Temporary but heavy; a remote user should know to wait rather than diagnose hardware.
**Notes.** Rules on module 1 plus service state. Likely folded into module 3 as a general "busy in background" finding.

---

#### Risks

- **False positives.** Flagging a needed OEM utility or a legitimate extension erodes trust. Mitigation: conservative rule lists, "review" rather than "remove" wording, `Warning` not `Fail` unless clear.
- **Point-in-time sampling.** A short sample can miss or exaggerate intermittent load. Mitigation: report sample duration; allow a longer sample on request.
- **Remote-mode privacy.** Remote users see findings from the user's machine. Mitigation: no command lines, URLs, titles, or file names; summarized output only; nothing uploaded.
- **Per-user vs per-machine data.** HKCU, browser profiles, OneDrive, and Outlook data belong to the signed-in user; the host may run elevated or as a different account. Mitigation: resolve the interactive user's hive/profile explicitly and record what could not be read in collection notes.
- **Undocumented sources.** Startup impact, sync state, and some Office settings may rely on undocumented data that changes between versions. Mitigation: mark as best-effort and degrade to "not available".
- **Fix actions.** Any change must be explicit, reversible where possible, and logged.

#### Open questions for Bud

1. Should module output appear only in the on-screen results, or also in the saved client report?
2. Should fix actions ship in the first release, or detection only at first?
3. Is a separate list of "approved" OEM utilities per vendor wanted (e.g. keep Lenovo Vantage for firmware updates)?
4. How long a sampling window is acceptable for module 1 (seconds vs a minute)?
5. Should `OutlookBenchmark` and `NetworkUsagePrototype` be merged into these modules or stay standalone?
6. Is there a target set of test laptops beyond the IdeaPad 1 15ALC7 for validating rules?

#### Rough sequencing

1. Shared contracts in Core: process snapshot, app grouping, finding/verdict types; synthetic-data tests.
2. Module 1 (top consumers) end to end, wired into the module list after the security audit, unticked by default.
3. Module 2 (startup items) including OEM rule list; then its explicit disable action.
4. Module 3 (AV and cloud sync), reusing module 1 data.
5. Phase 2: browser check, then Office/email add-in check (aligned with `OutlookBenchmark`).
6. Phase 3 items as rule sets on modules 1–3, promoting any to a standalone module only if it needs its own data collection (e.g. call-time sampling, WSL).
7. After each step: CI build green, unit tests on synthetic data, manual verification on at least one non-Lenovo laptop.
