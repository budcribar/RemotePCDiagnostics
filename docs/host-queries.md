# Host queries: what a user-mode module can use (design)

> **Status: implemented for modules that ship with the app (2026-11-07); the rest is still a proposal.**
>
> What exists today is in [Implemented: modules that ship with the app](#implemented-modules-that-ship-with-the-app). Everything after
> that section (unsigned modules, redaction, fix requests, instance keys) is the design for third-party modules and is **not**
> implemented. Read [module-plugins.md](module-plugins.md) first: it covers how a module is built, signed, installed and loaded today.
>
> **Updated 2026-11-05:** modules no longer read the event logs themselves. The module host's token is tightened so it can't, and
> `eventlog.read` returns redacted events only. See [Event logs: redacted only](#event-logs-redacted-only). The token change is in
> code (2026-11-08): an unsigned module's host has INTERACTIVE and Event Log Readers deny-only
> (`RestrictedModuleHostLauncher.UnsignedDenyOnly`); `eventlog.read` and redaction are still a proposal, so for now an unsigned
> module gets no event log data at all.

## Implemented: modules that ship with the app

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

## Why

Most diagnostics only *read*, but some of what they read needs administrator rights: fan speeds, drive wear and error counters, the
DISM and SFC scans. Today such a module has to be signed with the project key, which only we can do. With host queries, a third-party
module can stay **unsigned, in user mode** and still get those readings: it asks the app, and the app, which is already elevated, does
the privileged read and returns the data. The module never gets administrator rights, never runs anything elevated, and never decides
what runs elevated.

The same goes for fixes. A user-mode module can't change the PC, but it can *propose* one of the app's own one-click fixes. The app
checks the request, shows its usual confirmation and undo, and carries it out.

## Where your module runs

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

## What a user-mode module can read without asking

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

## Host queries

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

### `sensors.read`

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

### `storage.drives`

```csharp
IReadOnlyList<DriveHealth> drives = await queries.ReadDrivesAsync(ct);
```

Per physical drive: `Name`, `MediaType` (SSD/HDD), `BusType` (NVMe, SATA, USB, …), `Health`, `Operational`, `SizeBytes`,
`TemperatureC`, `Wear` (% used), `ReadErrors`, `WriteErrors`, `PowerOnHours` and `Letters` (its volumes). Any counter the drive
doesn't report is `null`. `Serial` and `UniqueId` are empty unless the module also declares `storage.drives.identifiers`. Each drive
has an `InstanceKey`, an opaque key made for your module (see [Instance keys](#instance-keys)), which you can use as the
`ModuleInstance.Key` of a per-device module.

### `osquery.select`

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

### `eventlog.read`

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

## Event logs: redacted only

Event messages can name the user, their files, the sites they visit, the PC and its network. Instead of asking every module that reads
them to be signed, the app makes the redacted `eventlog.read` the **only** way a user-mode module can see an event.

### Closing the direct route

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

### What is redacted

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

### What this keeps working

The built-in modules (Event Log, Crashes, BSOD history) would still work on redacted events:

- The Event Log page groups by message. Redacted messages group the same way, since a placeholder is stable.
- Crashes matches on `AppName`, `AppVersion`, `ModuleName`, `ExceptionCode` and `ReportId`, which are all on the keep list. It finds
  nearby events by searching their text for the report id, which isn't redacted.
- BSOD history reads the bugcheck code (`param1` / `BugcheckCode`, kept) and matches the dump file by its path. Dumps are under
  `C:\Windows`, so the path rules don't change it.

The built-in modules keep reading the logs directly in the app. Redaction is for user-mode modules only.

### Limits

Redacting free text is best effort. A name the app can't recognise as personal (a document title that isn't a path, a contact name in
an app's own message) passes through. That is why `eventlog.read` stays on the About page list and in the remote-session notice, at
Medium sensitivity.

### `windows.repairScan`

```csharp
RepairScanSummary s = await queries.RunRepairScanAsync(RepairScan.Dism, progress, ct);
```

- `Dism` runs `DISM /Online /Cleanup-Image /ScanHealth`. `Sfc` runs `sfc /verifyonly`. Both scans read only, and the repair itself is
  a fix (below).
- One scan at a time across the whole app, and it can take minutes. `progress` receives the app's progress lines, and cancelling `ct`
  stops the scan.
- Returns `Healthy`, `RepairableCorruption`, `NotRepairable` or `CouldNotRun`, plus the app's one-line summary.

## Risky queries

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

### The bigger risk is outside host queries

An unsigned module runs as the signed-in user. Even with every rule above, it can read the user's documents and browser profiles,
decrypt what the user can decrypt with DPAPI (saved browser passwords, cookies), use the camera and microphone, and send all of it over
the network. Host queries add little to that. What would reduce it most:

- running the module host in an **AppContainer** with no capabilities, which blocks the user's files, the network, the camera and the
  microphone unless granted (the module would then need host queries for most of what "What a user-mode module can read without
  asking" lists);
- or, short of that, a Windows Firewall rule blocking outbound traffic from `RemotePCDiagnostics.ModuleHost.exe` and
  `RemotePCDiagnostics.ModuleUiHost.exe`, so what a module reads can't leave the PC.

## Instance keys

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

## Requesting a fix

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

## Declaring it in `module.json`

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

## Writing the module

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

## Testing

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

## Wire protocol (reference)

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

## Remote sessions

Queries work the same way in a remote session. Fix requests follow the remote rules every fix follows: the actor is recorded, and the
person at the PC gets the notice. `eventlog.read` is named in that notice.

## Versioning

- Contract **1.2** adds `IHostQueries`, `HostAnswer<T>`, the `capabilities` and `fixes` manifest fields, and
  `IDiagnosticModule.OnFixCompleted`. These are additions, so 1.0 and 1.1 modules keep loading.
- New capabilities and fix kinds come in later minor versions. A module that lists a capability the running app doesn't know is
  disabled with a clear reason, so set `minHost` if you depend on a newer one.

## Open questions

- Should the person at the PC approve capabilities one by one (`eventlog.read` in particular) per module, rather than only seeing
  them listed?
- Reliability Monitor records: accept that a module can read them, or find a way to deny them to the module host?
- Which tables go on the `osquery.select` allowlist (see [Risky queries](#risky-queries))?
- AppContainer or a firewall rule for the module host: which one, and what do modules lose with an AppContainer?
- Do we want a `sensors.watch` stream, for stress-style modules that sample every second, instead of polling `sensors.read`?
- Signed third-party modules: is there ever a case for a partner key, or does everything go through host queries?
