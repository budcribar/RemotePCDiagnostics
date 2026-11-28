using RemotePCDiagnostics.Core;
using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// Builds checks whose every question is answered from a recording. With a <see cref="FaultPlan"/>, each answer passes through it first (the
/// replay host's fault-injection UI tests); this file is compiled into tools/RpcdReplayHost too.
/// </summary>
internal sealed class ReplayedPc(MachineRecording recording, FaultPlan? faults = null)
{
    private readonly FaultingSources? _faults = faults is null ? null : new(UsingRecordedErrors(faults, recording));

    private static FaultPlan UsingRecordedErrors(FaultPlan plan, MachineRecording recording)
    {
        plan.UseRecordedErrors(recording);
        return plan;
    }

    public RecordingReplay Replay { get; } = new(recording);
    public MachineRecording Recording => recording;

    public IProcessLauncher Launcher => _faults?.Launcher(Replay.Launcher) ?? Replay.Launcher;
    public OsqueryRunner Osquery => new(options: new OsqueryOptions { ExecutablePath = "osqueryi.exe" }, launcher: Launcher, fileExists: _ => true);
    public SystemCommandRunner Commands => new(Launcher, isProcessElevated: () => false);
    /// <summary>Noting failed answers as the app's WMI source does, so a missing class reads "Not available on this PC" here too.</summary>
    public IWmiSource Wmi => new NotingWmiSource(_faults?.Wmi(Replay.Wmi) ?? Replay.Wmi);
    public IRegistrySource Registry => _faults?.Registry(Replay.Registry) ?? Replay.Registry;
    public IPackageSource Packages => _faults?.Packages(Replay.Packages) ?? Replay.Packages;
    public Core.Security.IAntivirusProductSource AntivirusProducts => _faults?.Antivirus(Replay.AntivirusProducts) ?? Replay.AntivirusProducts;
    public Core.Audio.IAudioStateSource Audio => _faults?.Audio(Replay.Audio) ?? Replay.Audio;
    public Core.DeviceSensors.IDeviceSensorSource DeviceSensors => _faults?.DeviceSensors(Replay.DeviceSensors) ?? Replay.DeviceSensors;
    /// <summary>What the Agent's alerts read: the recorded events and levels (recorder v10 on).</summary>
    public Core.Alerts.IAlertReadings Alerts => _faults?.Alerts(Replay.Alerts) ?? Replay.Alerts;
    public bool HasAlerts => Has(c => c.Kind == RecordedCall.AlertsKind);
    public bool HasSecurityAudit => HasFile(SecurityAuditRecording.ReportName);

    /// <summary>
    /// The security audit as the app runs it in the Agent: the recorded HardeningKitty run (recorder v10 on), through the fault plan.
    /// The tool's files are taken as there; nothing runs.
    /// </summary>
    public SecurityAuditModule SecurityAudit() => new(new SecurityAuditOptions
    {
        FileExists = _ => true,
        ElevatedBridge = new ReplayedAuditBridge(this),
        Timeout = TimeSpan.FromMinutes(5),
    });

    /// <summary>The Agent, connected, giving the recorded audit run; it has nothing else to offer.</summary>
    private sealed class ReplayedAuditBridge(ReplayedPc pc) : Core.Session.IElevatedCommandBridge
    {
        public bool IsConnected => true;
        public async Task<SecurityAuditRun?> RunSecurityAuditAsync(TimeSpan timeout, CancellationToken ct = default)
        {
            var process = await pc.Launcher.RunAsync(SecurityAuditRecording.Program, SecurityAuditRecording.Arguments, timeout, ct).ConfigureAwait(false);
            return new SecurityAuditRun(process, await pc.FileAsync(SecurityAuditRecording.ReportName, ct).ConfigureAwait(false));
        }
        /// <summary>A re-check gives the recorded run too (the recording holds one full audit); the module merges it in.</summary>
        public Task<SecurityAuditRun?> RunSecurityAuditAsync(TimeSpan timeout, IReadOnlyList<string> onlyIds, CancellationToken ct = default) =>
            RunSecurityAuditAsync(timeout, ct);
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct,
            Action<string>? outputLine = null) => Task.FromResult<ProcessResult?>(null);
        public Task<Core.Sensors.SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<Core.Sensors.SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
    }

    /// <summary>A report file kept by name, through the fault plan when there is one.</summary>
    public Task<string?> FileAsync(string name, CancellationToken ct) =>
        _faults?.FileAsync(name, () => Replay.FileText(name), ct) ?? Task.FromResult(Replay.FileText(name));

    /// <summary>The check as the app runs it (WMI, through the Agent).</summary>
    public BatteryPowerModule BatteryPower() => new(new WmiBatteryPowerSource(Wmi, readPowerPolicy: () => null, isHp: () => false, isLenovo: () => false),
        delay: NoWait);
    /// <summary>The Store edition without an Agent (osquery and powercfg).</summary>
    public BatteryPowerModule BatteryPowerOld() => new(new OsqueryBatteryPowerSource(Osquery, Commands), delay: NoWait);
    /// <summary>A recording answers the same every time, so waiting between readings only slows the test.</summary>
    private static Task NoWait(TimeSpan _, CancellationToken __) => Task.CompletedTask;

    /// <summary>DriveHealth on WMI (in the app, the Agent's). The clock is the recording's, and nothing is saved.</summary>
    public DriveHealthModule DriveHealth() => Drives(new WmiDriveSource(Wmi));
    /// <summary>The Store edition without an Agent: the Get-PhysicalDisk PowerShell script, then osquery disk_info.</summary>
    public DriveHealthModule DriveHealthOld() => Drives(new PowerShellDriveSource(Commands, Osquery));
    private DriveHealthModule Drives(IDriveSource source) =>
        // The clock stands still at the recording's time, so a 20 s reuse would share the first read forever: read afresh each time.
        new(source, clock: () => recording.CapturedAt, historyStore: new DriveHealthHistoryStore(), volumes: () => [], reuseReadFor: TimeSpan.Zero);

    /// <summary>Hardware inventory on WMI (the Agent's).</summary>
    public OsqueryModule Inventory() => new(new WmiHardwareInventorySource(Wmi));
    /// <summary>The Store edition without an Agent: osquery.</summary>
    public OsqueryModule InventoryOld() => new(new OsqueryHardwareInventorySource(Osquery));

    public ServicesModule Services() => new(new WmiServiceSource(Wmi));

    /// <summary>Sound: Core Audio from the recording (recorder v9 on), services, drivers, WMI and the registry as the module host gives them.</summary>
    public Modules.Sound.SoundModule Sound() =>
        new(Audio, new WmiServiceSource(Wmi), new WmiDeviceDriverSource(Wmi), Wmi, Registry, pendingRecheck: TimeSpan.Zero);
    public bool HasAudio => Has(c => c.Kind == RecordedCall.AudioKind);

    /// <summary>Motion, light &amp; presence sensors: the Sensor API answer from the recording, Device Manager from WMI.</summary>
    public Modules.DeviceSensors.DeviceSensorsModule DeviceSensorsCheck() => new(DeviceSensors, Wmi);
    public bool HasDeviceSensors => Has(c => c.Kind == RecordedCall.DeviceSensorsKind);
    public ServicesModule ServicesOld() => new(new OsqueryServiceSource(Osquery));

    /// <summary>Device Manager and drivers on WMI. Pending driver updates aren't recorded, so they aren't asked.</summary>
    public DeviceDriversModule DeviceDrivers() => new(new WmiDeviceDriverSource(Wmi));
    /// <summary>The Store edition: the ProblemDevices PowerShell script and the osquery drivers table.</summary>
    public DeviceDriversModule DeviceDriversOld() => new(new OsqueryDeviceDriverSource(Osquery, Commands));

    /// <summary>Programs and updates on WMI and the registry; "today" is the day the PC was recorded.</summary>
    public ProgramsModule Programs() => new(new WmiProgramsSource(Wmi, Registry, HasPackages ? Packages : null), today: Today);
    /// <summary>Recordings before v5 have no Store-app list; replaying one, Programs lists the Uninstall keys only.</summary>
    private bool HasPackages => Has(c => c.Kind == RecordedCall.PackagesKind);
    public ProgramsModule ProgramsOld() => new(new OsqueryProgramsSource(Osquery), today: Today);
    private DateOnly Today() => DateOnly.FromDateTime(recording.CapturedAt.DateTime);

    /// <summary>Resource hogs on WMI (the Agent's) and the registry. The 2 s wait between process snapshots takes no time; no restart is pending.</summary>
    public ResourceHogsModule ResourceHogs() => new(new WmiResourceHogsSource(Wmi, Registry), timer: SampleTimer.Instant(), restartPending: () => false);
    /// <summary>The Store edition without an Agent: osquery and the FastStartupState script, with CPU % a share of the recorded PC's processors.</summary>
    public ResourceHogsModule ResourceHogsOld() => new(new OsqueryResourceHogsSource(Osquery, Commands, LogicalProcessors), timer: SampleTimer.Instant(),
        restartPending: () => false);
    private int LogicalProcessors() => recording.Calls
        .Where(c => c.Kind == RecordedCall.WmiKind && c.Query == WmiResourceHogsSource.ProcessorsSql && c.Rows is { Count: > 0 })
        .Select(c => c.ToWmiResult().Rows![0].Long("NumberOfLogicalProcessors")).FirstOrDefault(n => n is > 0) is { } n ? (int)n : 4;

    /// <summary>The checks that show event times: "now" is when the PC was recorded, and times are shown in UTC, wherever the tests run.</summary>
    public TimeProvider Clock => new FixedClock(recording.CapturedAt);

    /// <summary>Crashes with the dump files and graphics drivers on WMI (the Agent's); the event logs from wevtutil on both paths.</summary>
    public CrashesModule Crashes() => new(Commands, includeSystemCrashes: true, new WmiCrashDumpSource(Wmi, @"C:\Windows"), new WmiDeviceDriverSource(Wmi), clock: Clock);
    /// <summary>The Store edition without an Agent: the folders listed by the app itself (recorded as lists), and the osquery drivers table.</summary>
    public CrashesModule CrashesOld() => new(Commands, includeSystemCrashes: true, new ReplayedFileDumps(this), new OsqueryDeviceDriverSource(Osquery, Commands), clock: Clock);
    public EventLogModule EventLog() => new(Commands, excludeCrashEvents: true, clock: Clock);
    public SleepWakeModule SleepWake() => new(Commands, batteryReport: new ReplayedBatteryReport(this), clock: Clock);

    /// <summary>
    /// Network adapters and IP configuration on WMI and the registry, offline (the live probes aren't replayed). The Wi-Fi radio and scan
    /// come from the recording when it holds them (recorder v11 on).
    /// </summary>
    public NetworkModule Network() => new(new WmiNetworkSource(Wmi, Registry), includeWifiAndIpConfig: true, offline: true,
        radio: Has(c => c.Kind == RecordedCall.WifiKind) ? Replay.Wifi : null);
    /// <summary>The Store edition without an Agent: osquery interface_details and the NetAdapterStatistics and IpConfig scripts.</summary>
    public NetworkModule NetworkOld() => new(new OsqueryNetworkSource(Osquery, Commands), includeWifiAndIpConfig: true, offline: true);

    /// <summary>With Security Center's antivirus list when the recording holds it (recorder v9 on), as the app reads it.</summary>
    public SecurityEssentialsModule SecurityEssentials() => new(new Core.Security.WmiSecurityEssentialsSource(Wmi, Registry, Commands,
        antivirusProducts: Has(c => c.Kind == RecordedCall.AntivirusKind) ? AntivirusProducts : null));
    public SecurityEssentialsModule SecurityEssentialsOld() => new(new PowerShellSecurityEssentialsSource(Commands));

    public bool HasFile(string name) => Has(c => c.Kind == RecordedCall.FileKind && c.File == name);

    private sealed class ReplayedFileDumps(ReplayedPc pc) : ICrashDumpSource
    {
        public async Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct) =>
            CrashDumpFiles.Parse(await pc.FileAsync(CrashDumpFiles.Minidumps, ct));
        public async Task<IReadOnlyList<MinidumpFile>> ReadLiveKernelReportsAsync(CancellationToken ct) =>
            CrashDumpFiles.Parse(await pc.FileAsync(CrashDumpFiles.LiveKernelReports, ct));
    }

    private sealed class ReplayedBatteryReport(ReplayedPc pc) : IBatteryReportSource
    {
        public Task<string?> ReadXmlAsync(CancellationToken ct) => pc.FileAsync(PowerCfgBatteryReport.RecordingName, ct);
    }

    public bool Has(Func<RecordedCall, bool> match) => recording.Calls.Any(match);
    public bool HasWmi(string query) => Has(c => c.Kind == RecordedCall.WmiKind && c.Query == query);
    public bool HasOsquery(string sql) => Has(c => c.Kind == RecordedCall.ProcessKind && c.Args?.LastOrDefault() == sql);

    /// <summary>The <see cref="RecordingReplay.Key"/> of every answer these checks ask for on this recording.</summary>
    public static async Task<HashSet<string>> AskedByAsync(MachineRecording rec, CancellationToken ct, params Func<ReplayedPc, IDiagnosticModule>[] checks)
    {
        var asked = new HashSet<string>(StringComparer.Ordinal);
        foreach (var make in checks)
        {
            var pc = new ReplayedPc(rec);
            await make(pc).RefreshAsync(null, ct);
            asked.UnionWith(pc.Replay.Asked);
        }
        return asked;
    }
}

