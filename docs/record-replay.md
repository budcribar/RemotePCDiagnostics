# Record and replay testing

Each PC answers the checks a little differently. Record and replay tests run the checks against the raw answers real PCs gave, so a
change that breaks one make or model shows up in the tests rather than on that PC.

## Recording a PC

On the PC, from an administrator prompt (the app reads WMI through the Agent, which runs as administrator; nothing is changed):

```
dotnet run --project tools/RpcdRecorder -c Release -- --out <folder> [--osquery <path to osqueryi.exe>] [--note "text"]
```

It writes `<folder>/<product id>-<date>/` with:

- `machine.json`: which PC (the BIOS product identifier, make, model, SKU, board, BIOS, Windows build, app version).
- `calls.json`: every answer the checks got, in order (WMI rows, registry values, osquery and command output).
- `scrub-report.txt`: what was replaced before saving.

Since v9 it also records Security Center's antivirus list and a few WMI reads meant to fail (`ErrorProbes`: a class, a namespace and a
property that don't exist), so the fault-injection tests answer with the errors that PC's WMI really gives.

Since v10 it also records what the Agent itself reads for its alerts (the watched System and Application events of the last 30 days, free
space on each fixed drive, memory commit charge and power: `IAlertReadings`) and one security audit run as the Agent makes it (HardeningKitty's
output and report: `SecurityAuditRecording`). `AgentAlertsReplayTests` and `SecurityAuditReplayTests` replay them, with each reading broken
in turn. The audit takes a few minutes, and needs HardeningKitty: the installed app's copy, one next to the recorder, or `--hardeningkitty`.

The PC name, user names and serial numbers are replaced with placeholders (`<pc:…>`, `<user:…>`, `<serial:…>`) before the files are
written, and so is the SMBIOS UUID. Even so, a recording lists the PC's hardware and software, so real recordings stay out of this public
repo: they are kept in the private Admin repo under `test-data/rpcd-recordings`. Point `RPD_RECORDINGS_DIR` at that folder.

## Recording and replaying in the app

Two environment variables do the same in the real app, without the recorder tool:

- `RPCD_LOG=<folder>` records what the checks read from this PC (WMI through the Agent, the registry, Store packages, Security Center's
  antivirus list, the audio state and the tools the checks run) while the app runs. It saves a scrubbed recording folder
  (`<product id>-<start time>`, with `machine.json`, `calls.json` and `scrub-report.txt`) under that folder every 10 seconds while new
  answers arrive, and when the app exits. Checks behave exactly as without it. Use it to capture a problem a person sees, then replay it.
- `RPCD_REPLAY=<recording folder>` (Debug builds only) makes the checks read that recording instead of this PC, so you can see another
  PC's results, or a recording made with `RPCD_LOG`, in the real pages. `RPCD_LOG` is ignored while replaying.

Not covered yet: fixes (never recorded or replayed), the battery report file and the crash dump folders (read from disk), and the clock
(replayed events are compared with today's date, and finished checks still write history to this PC's Event Log).

## Running the tests

The tests in `tests/RemotePCDiagnostics.Tests/Replay` run every recording in `Replay/Recordings` (hand-made samples) and, when it is set,
every recording under `RPD_RECORDINGS_DIR`. For each one they check:

- **Snapshot:** the check's result matches `snapshots/<Check>.json` in the recording's folder. On a difference the new result is
  written as `.received.json`; rerun with `RPD_ACCEPT_SNAPSHOTS=1` to approve it.
- **Parity:** while a check moves from osquery or PowerShell to WMI, the capture records both, and the old and new code must agree. It
  compares what a technician would see: each card's level and headline and its rows. The processor's load and current clock
  change from second to second, so the hardware inventory leaves those out.
- **Damaged answers:** each answer the check asks for is broken one at a time (fails, times out, empty, garbage, each value missing,
  null, zero, negative, 0xFFFFFFFF, huge or garbage). The check must not crash, show nonsense numbers, or call something good without a
  reading. Long lists (services, drivers, programs) have values broken in their first three rows only.
- **Known failures:** a recording edited to a known bad state must give the known verdict: a worn battery, power saver, a stopped automatic
  service, a Device Manager error, no Windows update in 90 days, an unsigned driver, a failed memory read. An app or driver made old shows
  its old version (nothing flags age yet). The edits (`SetWmi`, `SetRows`, `AddWmiRow`, `FailWmi`) work on any recording, so troubleshooting
  replays can start from a real PC in a known bad state.

A question the recording doesn't hold fails the snapshot test: the check now asks something new, so record the PC again.

A check whose answers a recording doesn't hold (a recording made before the recorder knew it) skips its tests on that recording.

## What is recorded

| Check | New path (Setup edition) | Old path (Store edition without an Agent) |
| --- | --- | --- |
| Battery & power plan | WMI | osquery, powercfg |
| Drive health | WMI (Storage namespace) | PowerShell `Get-PhysicalDisk`, osquery |
| Hardware inventory | WMI (`Win32_ComputerSystem`, `Win32_Processor`, `Win32_PhysicalMemory`, …) | osquery |
| Services | WMI (`Win32_Service`) | osquery |
| Device Manager & drivers | WMI (`Win32_PnPEntity`, `Win32_PnPSignedDriver`) | PowerShell, osquery |
| Programs & updates | WMI (`Win32_OperatingSystem`, `Win32_QuickFixEngineering`), the registry's Uninstall keys, Store apps from Windows' package API | osquery |
| Network (adapters, IP configuration) | WMI (`Win32_NetworkAdapter`, `MSFT_NetAdapterStatisticsSettingData`, `Win32_NetworkAdapterConfiguration`), the registry (DNS set by hand, proxy) | osquery `interface_details`, PowerShell (`Get-NetAdapterStatistics`, `Get-NetIPConfiguration`) |
| Security essentials | WMI (Defender, Security Center, BitLocker, firewall profiles, `Win32_LogicalDisk`), the registry (Secure Boot, firmware type, edition, policies), tpmtool | PowerShell probe, tpmtool |
| Resource hogs & uptime | WMI (`Win32_OperatingSystem`, `Win32_Process`, `Win32_PhysicalMemory`, `Win32_PageFileUsage`), Fast Startup from the registry | osquery, PowerShell |
| Crashes & unexpected restarts | The event logs (wevtutil), the dump files from WMI (`CIM_DataFile`, `Win32_Directory`), the graphics drivers from `Win32_PnPSignedDriver` | The event logs (wevtutil), the dump folders listed by the app, osquery `drivers` |
| Windows error log | The event logs (wevtutil) | The same |
| Sleep, wake & standby drain | powercfg, the System log (wevtutil), the battery report (`powercfg /batteryreport`, kept by name) | The same |
| Sound | Core Audio (`IAudioStateSource`, kept as one JSON answer, `RecordedCall.AudioKind`), WMI (`Win32_Service`, `Win32_PnPEntity`, `Win32_PnPSignedDriver` for MEDIA, `BatteryStaticData`), the registry (microphone privacy, mono audio) | None (no Store edition fallback; without Core Audio its device cards say they couldn't be read) |
| Disk surface scan | The disk list from WMI (`MSFT_PhysicalDisk`, the same answer as Drive health), and each answer the Agent gave to `disk_read_scan` (start, every status, stop) as JSON (`RecordedCall.DiskScanKind`) | None: without the Agent the scan is Skipped ("Needs the Agent") |

The event log checks are built at the time the PC was recorded, in UTC (`ReportClock`, `FixedClock`), so "in the last 7 days" and the
times shown stay the same wherever and whenever the tests run. The battery report is a file powercfg writes under a new name each run, so it
is kept as a file answer (`RecordedCall.FileKind`) under a fixed name; its serial number and the PC's name are replaced like any other.
The legacy dump lists are kept the same way, as JSON. Event messages are kept as Windows wrote them, with the PC's and users' names
replaced, which is one more reason real recordings stay in the private Admin repo.

Sound endpoints on Bluetooth are named after the headset, which people often name after themselves, so the scrubber replaces their names
(`<bluetooth:…>`). Device instance paths of Bluetooth and USB devices (`DeviceID`, `InstanceId`) hold a MAC address or serial and are
replaced too, with the same placeholder wherever the same path appears.

The Network check (`INetworkSource`) is recorded without `netsh wlan` and the network event logs, whose answers hold the Wi-Fi network's name
and its router's address, and offline: the reachability probes and the DNS speed comparison ask the live network, so they aren't replayed.

## Readers and editions

Each check reads through an interface (`IBatteryPowerSource`, `IDriveSource`, `IHardwareInventorySource`, `IServiceSource`,
`IDeviceDriverSource`, `IProgramsSource`, `ISecurityEssentialsSource`, `IResourceHogsSource`, `ICrashDumpSource`), so a build carries only the
readers it uses:

- The Setup edition (the default build) reads WMI through the Agent (`AgentWmiSource`), never in the app. Run out of process (in the module
  host), a module asks the app for its WMI (the `wmi.query` capability), and the app asks the Agent. The registry keys Programs reads, and the
  signed-in user's Store apps (`PackageManager`), need no administrator rights, so the app reads them itself (`packages.list` out of process).
  Programs lists only the apps among the packages: no frameworks, language resources or parts of Windows. The crash dump folders are for
  administrators only, so Crashes lists them through the Agent too, and takes its graphics drivers from the drivers reader.
- The Store edition (`-p:RpcdEdition=Store`) may run without an Agent. It also ships `RemotePCDiagnostics.Legacy` (osquery, powercfg,
  PowerShell, all as a standard user) and uses it whenever no Agent is connected.

The recorder runs both, and the replay tests compare them on every recording, so the Store edition's readers stay checked against real PCs.

## Fault injection on the real pages

[fault-injection.md](fault-injection.md) runs the real pages on a recording (tools/RpcdReplayHost), breaks the answers one at a time while
Playwright drives them, and checks every page copes.
