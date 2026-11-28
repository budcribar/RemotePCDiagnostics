// Records the raw answers this PC gives to the checks that support record and replay, scrubs personal details, and saves a recording
// folder for the replay tests (docs/record-replay.md). It only reads: no fix runs, nothing on the PC changes.
//
//   dotnet run --project tools/RpcdRecorder -- --out <folder>   (from an admin prompt, as the Agent runs) [--osquery <path to osqueryi.exe>] [--note "text"]
//
// v9 (Nov 26): also records Security Center's antivirus list and WMI error probes (ErrorProbes), and WMI errors carry their code.
// v10 (Nov 26): also records what the Agent's alerts read (the watched events of the last 30 days, free space, memory, power) and one
// security audit run (HardeningKitty, as the Agent runs it), for the Agent's replay tests. The audit takes a few minutes.
// Nov 27: also records the motion, light and presence sensors (Sensor API) for Motion, light & presence sensors.
//
// Each check runs twice: once on the new WMI path and once on the old osquery / powercfg / PowerShell path, so the tests can check the two agree.


using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Legacy;
using RpcdRecorder;

var outRoot = Arg("--out") ?? Path.Combine(Environment.CurrentDirectory, "recordings");
var osqueryPath = Arg("--osquery") ?? Environment.GetEnvironmentVariable(OsqueryRunner.PathEnvironmentVariable)
    ?? FirstExisting(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RemotePCDiagnostics", "tools", "osquery", "osqueryi.exe"),
        Path.Combine(AppContext.BaseDirectory, OsqueryRunner.RelativePath));
var note = Arg("--note");
var hardeningKitty = Arg("--hardeningkitty") ?? FirstExisting(
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RemotePCDiagnostics", SecurityAuditModule.RelativeFolder, SecurityAuditModule.ManifestFile),
    Path.Combine(AppContext.BaseDirectory, SecurityAuditModule.RelativeFolder, SecurityAuditModule.ManifestFile),
    Path.Combine(Environment.CurrentDirectory, "HardeningKitty", SecurityAuditModule.ManifestFile));

if (!OperatingSystem.IsWindows()) { await Console.Error.WriteLineAsync("Run this on the Windows PC to record."); return 2; }
// The app reads WMI through the Agent, which runs as administrator: record from an admin prompt so the answers match.
if (!Environment.IsPrivilegedProcess)
    Console.WriteLine("Not running as administrator. The Agent reads WMI as administrator, so some answers (the power plan) will differ. Run from an admin prompt.");

var recorder = new CallRecorder();
var liveWmi = new SystemWmiSource();
var wmi = new RecordingWmiSource(liveWmi, recorder);
var registry = new RecordingRegistrySource(new SystemRegistrySource(), recorder);
var packages = new RecordingPackageSource(new RemotePCDiagnostics.Host.Platform.SystemPackageSource(), recorder);
var launcher = new RecordingProcessLauncher(new SystemProcessLauncher(), recorder);
var osquery = new OsqueryRunner(options: new OsqueryOptions { ExecutablePath = osqueryPath }, launcher: launcher);
var commands = new SystemCommandRunner(launcher);
var files = new FileRecorder(recorder);
// Core Audio (endpoints, defaults, mute, volume, formats, app sessions), read as the app does in the signed-in user's session.
var audio = new RecordingAudioStateSource(new RemotePCDiagnostics.Host.WasapiAudioStateSource(), recorder);
// The motion, light and presence sensors (the Windows Sensor API), read as the app does.
var deviceSensors = new RecordingDeviceSensorSource(new RemotePCDiagnostics.Core.DeviceSensors.WindowsDeviceSensorSource(), recorder);
// Security Center's antivirus list (third-party antivirus and Defender), as the app's Security essentials reads it.
var antivirus = new RecordingAntivirusProductSource(new RemotePCDiagnostics.Host.WindowsAntivirusProductSource(), recorder);
if (!osquery.Exists) Console.WriteLine($"osqueryi.exe not found ({osqueryPath}); the old osquery path won't be recorded. Pass --osquery <path>.");

var machine = await MachineDescription.DescribeAsync(liveWmi, typeof(BatteryPowerModule).Assembly.GetName().Version?.ToString() ?? "", Environment.IsPrivilegedProcess);
Console.WriteLine($"Recording {machine.Manufacturer} {machine.Model} (product id {machine.ProductId}), Windows {machine.WindowsVersion} build {machine.WindowsBuild}");

// Nothing is saved on this PC: drive history is kept in memory, and free space and retrim history aren't part of a recording yet.
DriveHealthModule Drives(IDriveSource source) => new(source, historyStore: new DriveHealthHistoryStore(), volumes: () => []);
// The commands go through the recording launcher, so they count as scripted: the legacy problem devices come from the PowerShell script
// (which can be replayed), not WMI read in this process.
var checks = new (string Label, IDiagnosticModule Module)[]
{
    ("BatteryPower (WMI)", new BatteryPowerModule(new WmiBatteryPowerSource(wmi))),
    ("BatteryPower (legacy: osquery + powercfg)", new BatteryPowerModule(new OsqueryBatteryPowerSource(osquery, commands))),
    ("DriveHealth (WMI)", Drives(new WmiDriveSource(wmi))),
    ("DriveHealth (legacy: PowerShell)", Drives(new PowerShellDriveSource(commands, osquery))),
    ("Hardware inventory (WMI)", new OsqueryModule(new WmiHardwareInventorySource(wmi))),
    ("Hardware inventory (legacy: osquery)", new OsqueryModule(new OsqueryHardwareInventorySource(osquery))),
    ("Services (WMI)", new ServicesModule(new WmiServiceSource(wmi))),
    ("Services (legacy: osquery)", new ServicesModule(new OsqueryServiceSource(osquery))),
    ("Device Manager & drivers (WMI)", new DeviceDriversModule(new WmiDeviceDriverSource(wmi))),
    ("Device Manager & drivers (legacy: PowerShell + osquery)", new DeviceDriversModule(new OsqueryDeviceDriverSource(osquery, commands))),
    ("Programs & updates (WMI + registry)", new ProgramsModule(new WmiProgramsSource(wmi, registry, packages))),
    ("Programs & updates (legacy: osquery)", new ProgramsModule(new OsqueryProgramsSource(osquery))),
    // Without netsh and the event logs (Wi-Fi and event names hold the network's name and its router's address) and offline (no probes or DNS timing).
    ("Network (WMI + registry)", new NetworkModule(new WmiNetworkSource(wmi, registry), includeWifiAndIpConfig: true, offline: true)),
    ("Network (legacy: osquery + PowerShell)", new NetworkModule(new OsqueryNetworkSource(osquery, commands), includeWifiAndIpConfig: true, offline: true)),
    ("Security essentials (WMI + registry + tpmtool)", new SecurityEssentialsModule(new WmiSecurityEssentialsSource(wmi, registry, commands, antivirus))),
    ("Security essentials (legacy: PowerShell + tpmtool)", new SecurityEssentialsModule(new PowerShellSecurityEssentialsSource(commands))),
    // A restart this app scheduled isn't part of a recording. Each path takes its two process snapshots 2 s apart, as in the app.
    ("Resource hogs & uptime (WMI + registry)", new ResourceHogsModule(new WmiResourceHogsSource(wmi, registry), restartPending: () => false)),
    ("Resource hogs & uptime (legacy: osquery + PowerShell)", new ResourceHogsModule(new OsqueryResourceHogsSource(osquery, commands), restartPending: () => false)),
    // The event logs come from wevtutil on both paths; the dump files and graphics drivers from WMI, or listed here and from osquery.
    ("Crashes & unexpected restarts (WMI + wevtutil)", new CrashesModule(commands, includeSystemCrashes: true, new WmiCrashDumpSource(wmi), new WmiDeviceDriverSource(wmi))),
    ("Crashes & unexpected restarts (legacy: files + osquery + wevtutil)", new CrashesModule(commands, includeSystemCrashes: true,
        new RecordedFileCrashDumps(files), new OsqueryDeviceDriverSource(osquery, commands))),
    ("Windows error log (wevtutil)", new EventLogModule(commands, excludeCrashEvents: true)),
    // The battery report's own powercfg run isn't recorded (its file name changes every run); the report is, by name.
    ("Sleep, wake & standby drain (powercfg + wevtutil)", new SleepWakeModule(commands,
        batteryReport: new RecordedBatteryReport(files, new PowerCfgBatteryReport(new SystemCommandRunner())))),
    ("Sound (Core Audio + WMI + registry)", new RemotePCDiagnostics.Modules.Sound.SoundModule(audio, new WmiServiceSource(wmi),
        new WmiDeviceDriverSource(wmi), wmi, registry)),
    ("Motion, light & presence sensors (Sensor API + WMI)", new RemotePCDiagnostics.Modules.DeviceSensors.DeviceSensorsModule(deviceSensors, wmi)),
};
foreach (var (label, module) in checks)
{
    var r = await module.RefreshAsync(null);
    Console.WriteLine($"  {label}: {r.Status} - {r.Message}");
    // Long lists (services, drivers, programs) print only their size.
    if (r.Payload is AreaReport report)
        foreach (var card in report.Cards)
        {
            if (card.Rows.Count > 12) { Console.WriteLine($"      {card.Title}: {card.Rows.Count} rows"); continue; }
            foreach (var row in card.Rows)
                Console.WriteLine($"      {string.Join(": ", row.Values)}");
        }
}

// What the Agent's alerts read: each watched channel's events (30 days rather than the Agent's 1-day catch-up, for more to replay), then
// the levels. Event messages are scrubbed like everything else.
var alerts = new RecordingAlertReadings(new RemotePCDiagnostics.Agent.WindowsAlertReadings(), recorder);
foreach (var channel in RemotePCDiagnostics.Core.Alerts.AlertRules.EventIds.Keys)
{
    var r = await alerts.ReadAsync(RemotePCDiagnostics.Core.Alerts.AlertReadings.Events(channel), 0, TimeSpan.FromDays(30), CancellationToken.None);
    Console.WriteLine($"  Alerts {channel} events: {r.Error ?? $"{r.Rows?.Count} in 30 days"}");
}
foreach (var level in new[] { RemotePCDiagnostics.Core.Alerts.AlertReadings.Disks, RemotePCDiagnostics.Core.Alerts.AlertReadings.Memory, RemotePCDiagnostics.Core.Alerts.AlertReadings.Power })
{
    var r = await alerts.ReadAsync(level, 0, TimeSpan.Zero, CancellationToken.None);
    Console.WriteLine($"  Alerts {level}: {r.Error ?? $"{r.Rows?.Count} row(s)"}");
}

// One security audit, as the Agent runs it (administrator, the report in a temp folder removed afterwards).
if (File.Exists(hardeningKitty))
{
    Console.WriteLine("  Security audit: running HardeningKitty (a few minutes)…");
    var reportPath = SecurityAuditModule.DefaultReportPath();
    try
    {
        var run = await SecurityAuditModule.RunProcessAsync(new SystemProcessLauncher(), SystemCommandRunner.PowerShell, hardeningKitty, reportPath,
            TimeSpan.FromMinutes(10), CancellationToken.None);
        foreach (var call in SecurityAuditRecording.Calls(run)) recorder.Add(call);
        Console.WriteLine($"  Security audit: exit {run.Process.ExitCode}, report {(run.ReportCsv is { } csv ? $"{HardeningKittyCsv.Parse(csv).Count} findings" : "not made")}");
    }
    catch (Exception ex) { Console.WriteLine($"  Security audit: failed ({ex.Message})"); }
    finally { try { Directory.Delete(Path.GetDirectoryName(reportPath)!, recursive: true); } catch { } }
}
else Console.WriteLine($"  Security audit: HardeningKitty not found ({hardeningKitty}); not recorded. Pass --hardeningkitty <path to HardeningKitty.psd1>.");

// WMI reads meant to fail (a class, a namespace, a property that don't exist), so the fault-injection tests answer with this PC's real errors.
await ErrorProbes.RunAsync(wmi);
foreach (var (fault, ns, query) in ErrorProbes.Wmi)
    Console.WriteLine($"  Error probe {fault}: {recorder.Snapshot().LastOrDefault(c => c.Query == query)?.Error ?? "(no error)"}");

var scrubber = new RecordingScrubber(Environment.MachineName, MachineDescription.UserNames());
var recording = scrubber.Scrub(new MachineRecording
{
    Machine = machine with { Notes = note },
    CapturedAt = DateTimeOffset.Now,
    Calls = recorder.Snapshot(),
});
var folder = Path.Combine(outRoot, MachineDescription.Safe(machine.ProductId) + "-" + recording.CapturedAt.ToString("yyyyMMdd-HHmm"));
recording.Save(folder);
await File.WriteAllLinesAsync(Path.Combine(folder, "scrub-report.txt"),
    ["Replaced before saving (placeholder kind: count):", .. scrubber.Counts.Select(c => $"  {c.Key}: {c.Value}")]);
Console.WriteLine($"Saved {recording.Calls.Count} answers to {folder}");
return 0;

string? Arg(string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static string FirstExisting(params string[] paths) => paths.FirstOrDefault(File.Exists) ?? paths[0];

namespace RpcdRecorder
{
    /// <summary>The legacy reader's dump file lists, recorded as JSON under <see cref="CrashDumpFiles"/>'s names.</summary>
    sealed class RecordedFileCrashDumps(FileRecorder files) : ICrashDumpSource
    {
        private readonly FileCrashDumpSource _inner = new();
        public async Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct) =>
            CrashDumpFiles.Parse(await files.ReadAsync(CrashDumpFiles.Minidumps, async () => CrashDumpFiles.Json(await _inner.ReadMinidumpsAsync(ct))));
        public async Task<IReadOnlyList<MinidumpFile>> ReadLiveKernelReportsAsync(CancellationToken ct) =>
            CrashDumpFiles.Parse(await files.ReadAsync(CrashDumpFiles.LiveKernelReports, async () => CrashDumpFiles.Json(await _inner.ReadLiveKernelReportsAsync(ct))));
    }

    sealed class RecordedBatteryReport(FileRecorder files, IBatteryReportSource inner) : IBatteryReportSource
    {
        public Task<string?> ReadXmlAsync(CancellationToken ct) => files.ReadAsync(PowerCfgBatteryReport.RecordingName, () => inner.ReadXmlAsync(ct));
    }
}
