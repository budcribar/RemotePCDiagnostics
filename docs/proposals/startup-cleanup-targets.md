# Proposal: Startup cleanup targets

| | |
|---|---|
| **Status** | Proposed |
| **Date** | 2026-11-02 |
| **Author** | Bud Cribar (drafted via assistant) |
| **Scope** | Disable (not uninstall) startup entries, services, and scheduled tasks |
| **Related** | [Application optimization modules](application-optimization-modules.md), module 2 |

## Summary

Many popular Windows programs leave behind Run keys, auto-start services, and scheduled tasks (mostly updaters and tray helpers) that add load at boot and sign-in. This proposal defines a **startup cleanup** feature that detects these items and lets a technician **disable** them, reversibly. Nothing is uninstalled.

All service, task, and Run-entry names below are **typical** and must be **verified on a real machine**; names change between versions, installers (per-user vs per-machine), and vendors' rebrands. Nothing here comes from measurement.

## Principles

1. **Detection is read-only by default.** A scan only reports.
2. **Disable is a separate, explicit technician action.** No confirmation prompts; technicians have admin rights. The exact change is shown and logged.
3. **Always reversible.** Before any change, export prior state (service start type and status, task enabled state, Run value name/data, `StartupApproved` bytes) to an **undo file**. One-click undo restores it.
4. **Log every change** in the report: item, before, after, who/when.
5. **Exact matching only.** Match by exact service name / task path + publisher (Authenticode signer). Never loose name or substring matching.
6. **Per-user context.** For HKCU Run keys, report which user (SID and account name) the entry belongs to; offline user hives are reported, not edited, unless loaded explicitly.
7. **Verify after.** Re-read state after the change to confirm it stuck.
8. **Report failures honestly.** Protected services, tamper protection, access denied, or a vendor watchdog reverting the change are reported as failures, never as success.
9. **Flag re-enablers.** Items known to re-enable themselves after app updates or repairs are marked so the technician knows the change may not last.

## Rating key

- **Safe** – Safe and reversible; the app keeps working, only auto-start/background update is lost.
- **Caveats** – Safe with caveats; some feature (auto-update, sync, notifications, warranty tooling) stops until re-enabled.
- **Do not** – Do not disable by default; report only.

## Targets

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

## Never disable

- Microsoft Defender (`WinDefend`, `WdNisSvc`, `Sense`) and Security Center (`wscsvc`).
- Windows Update (`wuauserv`, `UsoSvc`, `WaaSMedicSvc`, `BITS`) and related tasks.
- Real-time protection of any installed security vendor.
- Drivers and services critical for input, display, network, audio, storage (touchpad, Wi-Fi, GPU display container).
- `ClickToRunSvc` (OfficeClickToRun).
- BitLocker (`BDESVC`) and TPM/credential services.
- OEM firmware/BIOS update services: arguably optional, but default to report-only since disabling may break warranty and support tooling.

## Proposed test: Adobe Reader on a GitHub-hosted runner

A CI job on `windows-latest` exercising detect → disable → undo end to end:

1. **Install** in its own step/job: `choco install adobereader -y --no-progress`, with retry (Chocolatey CDN and Adobe downloads can be flaky); pin a version (`--version x.y.z`) if latest drifts. No sign-in.
2. **Detect** and assert **at least one** Adobe update item: service `AdobeARMservice`, the "Adobe Acrobat Update Task" scheduled task, or an Adobe Run entry. Version-dependent, so assert "at least one", not an exact list.
3. **Disable**, then re-read state: service start type Disabled and stopped; task disabled; Run entry removed or `StartupApproved` set disabled. Assert an undo file exists and contains prior state.
4. **Undo**, then assert state equals the original.
5. *(Optional)* Trigger the updater or a repair and check whether it re-enables itself; record the result rather than failing the build.

**Limitations.** Fresh image with no user history; shared hosted runner; only proves the logic. Repeat on a real laptop or a self-hosted runner before trusting ratings.

**Complement: seeded fixtures.** A more reliable test creates its own fakes: HKCU/HKLM Run values, a dummy service (`sc.exe create RPDTestSvc …`), and a dummy scheduled task (`Register-ScheduledTask`), then runs detect/disable/undo against them and cleans up. Deterministic and independent of third-party installers.

## Implementation notes (hypotheses to verify)

- **Services:** osquery `services` table or `Win32_Service` (name, start mode, state, path); change via `Set-Service`/`ChangeStartMode`. Capture original start type including delayed auto-start (`DelayedAutostart` registry value) for exact undo.
- **Scheduled tasks:** osquery `scheduled_tasks`; Task Scheduler COM (`Schedule.Service`) or PowerShell `Get-ScheduledTask` / `Disable-ScheduledTask` / `Enable-ScheduledTask`. Match by full task path.
- **Run keys:** `HKLM`/`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`, plus `WOW6432Node`; osquery `startup_items`. Prefer disabling via `...\Explorer\StartupApproved\Run` (as Task Manager does) over deleting values; if a value is deleted, store it in the undo file. *Hypothesis:* StartupApproved first byte `02` = enabled, `03` = disabled.
- **Store apps** (new Teams, iCloud): StartupTask state; *hypothesis:* readable via `HKCU\...\AppModel\SystemAppData\<pkg>\<task>\State`.
- **Publisher:** Authenticode signer of the target binary, compared with the data list.
- **Undo file:** JSON per run, stored with the report; undo applies entries in reverse order and re-verifies.
- **Data list:** ship targets as a data file (name, kind, signer, rating, note) so it can be updated without code changes.

## Open questions for Bud

1. Disable Run entries via `StartupApproved` only, or also delete values (with undo)?
2. Services: Disabled or Manual as the default "off" state?
3. Should OEM support services be Caveats (disableable) or report-only by default?
4. Where should undo files live, and how long are they kept?
5. Is the Chocolatey Adobe Reader job worth the CI time, or fixtures-only with manual real-machine runs?
