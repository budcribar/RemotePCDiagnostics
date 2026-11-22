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

The PC name, user names and serial numbers are replaced with placeholders (`<pc:…>`, `<user:…>`, `<serial:…>`) before the files are
written, and so is the SMBIOS UUID. Even so, a recording lists the PC's hardware and software, so real recordings stay out of this public
repo: they are kept in the private Admin repo under `test-data/rpcd-recordings`. Point `RPD_RECORDINGS_DIR` at that folder.

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

The Network check (`INetworkSource`) is recorded without `netsh wlan` and the network event logs, whose answers hold the Wi-Fi network's name
and its router's address, and offline: the reachability probes and the DNS speed comparison ask the live network, so they aren't replayed.

## Readers and editions

Each check reads through an interface (`IBatteryPowerSource`, `IDriveSource`, `IHardwareInventorySource`, `IServiceSource`,
`IDeviceDriverSource`, `IProgramsSource`, `ISecurityEssentialsSource`, `IResourceHogsSource`), so a build carries only the readers it uses:

- The Setup edition (the default build) reads WMI through the Agent (`AgentWmiSource`), never in the app. Run out of process (in the module
  host), a module asks the app for its WMI (the `wmi.query` capability), and the app asks the Agent. The registry keys Programs reads, and the
  signed-in user's Store apps (`PackageManager`), need no administrator rights, so the app reads them itself (`packages.list` out of process).
  Programs lists only the apps among the packages: no frameworks, language resources or parts of Windows.
- The Store edition (`-p:RpcdEdition=Store`) may run without an Agent. It also ships `RemotePCDiagnostics.Legacy` (osquery, powercfg,
  PowerShell, all as a standard user) and uses it whenever no Agent is connected.

The recorder runs both, and the replay tests compare them on every recording, so the Store edition's readers stay checked against real PCs.
