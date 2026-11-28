using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Battery;

/// <summary>
/// <see cref="AgentScripts.BatteryDrainPower"/>: one fixed verb, no other argument. <c>apply</c> saves the active plan's on-battery sleep,
/// display and battery-action settings and sets the drain test's; <c>renew</c> keeps them for another <see cref="AgentBatteryDrainPower.Lease"/>;
/// <c>restore</c> puts the saved ones back; <c>shutdown</c> restores them and shuts the PC down in a minute; <c>status</c> says whether
/// the test's settings are in place.
/// </summary>
public sealed record BatteryDrainPowerAction(string Verb) : AgentNativeAction
{
    public const string Apply = "apply", Renew = "renew", Restore = "restore", Shutdown = "shutdown", Status = "status";

    public static bool IsVerb(string? v) => v is Apply or Renew or Restore or Shutdown or Status;
}

/// <summary>One power setting the drain test changes: where it is in the plan, what it is set to for the run, and its name.</summary>
public sealed record DrainPowerSetting(string Name, Guid Subgroup, Guid Setting, uint DrainValue);

/// <summary>The active power plan's on-battery (DC) values, read and written through powrprof (the Agent has administrator rights).</summary>
public interface IPowerPlanValues
{
    Guid? ActiveScheme();
    uint? ReadDc(Guid scheme, Guid subgroup, Guid setting);
    bool WriteDc(Guid scheme, Guid subgroup, Guid setting, uint value);
    /// <summary>Makes the plan's new values take effect (sets it active again).</summary>
    void Activate(Guid scheme);
}

/// <summary>What the Agent answers to every verb, as JSON.</summary>
public sealed record BatteryDrainPowerAnswer(
    [property: JsonPropertyName("applied")] bool Applied,
    [property: JsonPropertyName("settings")] IReadOnlyList<BatteryDrainPowerAnswer.Item> Settings,
    [property: JsonPropertyName("leaseUntilUtc")] DateTimeOffset? LeaseUntilUtc = null,
    [property: JsonPropertyName("shutdownIn")] int? ShutdownInSeconds = null,
    [property: JsonPropertyName("note")] string? Note = null)
{
    public sealed record Item(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("previous")] uint? Previous,
        [property: JsonPropertyName("now")] uint? Now);

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static BatteryDrainPowerAnswer? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<BatteryDrainPowerAnswer>(json, Json); }
        catch (JsonException) { return null; }
    }
}

/// <summary>
/// The Agent's half of the battery drain test: the power plan settings it changes for a run and the shutdown at the end. Before changing
/// anything it writes the old values to a journal in the protected state folder; a run that stops renewing its lease (the app closed or
/// crashed, the PC restarted) gets them back from the journal at the next call, the helper's timer, or the next Agent start.
/// </summary>
public sealed class AgentBatteryDrainPower(IPowerPlanValues plan, string journalPath, Func<DateTimeOffset>? now = null,
    Func<DateTimeOffset>? bootTime = null, Func<int, string, string?>? startShutdown = null, ILogger? log = null)
{
    public const string JournalFile = "battery-drain-power.json";
    /// <summary>How long the test's settings stay without a renew (the app renews every 30 s).</summary>
    public static readonly TimeSpan Lease = TimeSpan.FromMinutes(3);
    public const int ShutdownDelaySeconds = 60;
    public const string ShutdownMessage = "Remote PC Diagnostics: the battery test reached 5 %. This PC shuts down in 1 minute.";

    private static readonly Guid SubSleep = new("238c9fa8-0aad-41ed-83f4-97be242c8f20");
    private static readonly Guid SubVideo = new("7516b95f-f776-4464-8c53-06167f40cc99");
    private static readonly Guid SubBattery = new("e73a048d-bf27-4f12-9731-8b2076e8891f");
    private static readonly Guid SubEnergySaver = new("de830923-a562-41af-a086-e3a2c6bad2da");

    /// <summary>
    /// The settings a run changes, on battery only, and the values it uses: never sleep, hibernate, dim or turn off the display; no
    /// energy saver; nothing at low battery; and at critical battery (3 %, below the test's own 5 % stop) shut down, so a run whose app
    /// went away still ends with a clean shutdown instead of the battery running flat.
    /// </summary>
    public static readonly IReadOnlyList<DrainPowerSetting> Settings =
    [
        new("Sleep after", SubSleep, new("29f6c1db-86da-48c5-9fdb-f2b67b1f44da"), 0),
        new("Hibernate after", SubSleep, new("9d7815a6-7ee4-497e-8888-515a05f02364"), 0),
        new("Turn off the display after", SubVideo, new("3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"), 0),
        new("Dim the display after", SubVideo, new("17aaa29b-8b43-4b94-aafe-35f64daaf1ee"), 0),
        new("Turn on energy saver at", SubEnergySaver, new("e69653ca-cf7f-4f05-aa73-cb833fa90ad4"), 0),
        new("Low battery action", SubBattery, new("d8742dcb-3e6a-4b3c-b3fe-374623cdcf06"), 0),
        new("Critical battery level", SubBattery, new("9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469"), 3),
        new("Critical battery action", SubBattery, new("637ea02f-bbcb-4015-8e2c-a1c7b9c0b546"), 3),
    ];

    /// <summary>The journal: the plan the values were read from, each setting's old value, and how long the run's lease lasts.</summary>
    public sealed record Journal(
        [property: JsonPropertyName("scheme")] Guid Scheme,
        [property: JsonPropertyName("previous")] IReadOnlyDictionary<string, uint?> Previous,
        [property: JsonPropertyName("renewedUtc")] DateTimeOffset RenewedUtc,
        [property: JsonPropertyName("leaseUntilUtc")] DateTimeOffset LeaseUntilUtc);

    private readonly object _gate = new();
    private DateTimeOffset Now() => (now ?? (() => DateTimeOffset.UtcNow))();
    private DateTimeOffset Boot() => (bootTime ?? (() => DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64)))();

    private static string Key(DrainPowerSetting s) => s.Setting.ToString("D");

    public ProcessResult Run(BatteryDrainPowerAction a)
    {
        lock (_gate)
        {
            if (a.Verb != BatteryDrainPowerAction.Apply && a.Verb != BatteryDrainPowerAction.Renew) RestoreIfAbandoned();
            return a.Verb switch
            {
                BatteryDrainPowerAction.Apply => ApplySettings(),
                BatteryDrainPowerAction.Renew => RenewLease(),
                BatteryDrainPowerAction.Restore => RestoreSettings(null),
                BatteryDrainPowerAction.Shutdown => ShutdownPc(),
                _ => CurrentStatus(),
            };
        }
    }

    /// <summary>Puts the old values back when the lease ran out or was renewed before Windows last started. True when it restored.</summary>
    public bool RestoreIfAbandoned()
    {
        lock (_gate)
        {
            if (ReadJournal() is not { } j) return false;
            if (j.LeaseUntilUtc > Now() && j.RenewedUtc >= Boot() - TimeSpan.FromMinutes(1)) return false;
            log.Info("[battery-drain] The drain test's power settings were left behind (lease ended or the PC restarted): putting them back.");
            return RestoreSettings(j).ExitCode == 0;
        }
    }

    private ProcessResult ApplySettings()
    {
        // Already applied (asked again, or a second run started while one runs): keep the journal's old values, renew the lease.
        if (ReadJournal() is { } existing) return Renewed(existing);
        if (plan.ActiveScheme() is not { } scheme) return WindowsAgentNativeOps.Failed("Windows didn't say which power plan is active.");

        var previous = Settings.ToDictionary(Key, s => plan.ReadDc(scheme, s.Subgroup, s.Setting));
        var at = Now();
        var journal = new Journal(scheme, previous, at, at + Lease);
        // The old values are on disk before the first one changes: whatever happens next, they can be put back.
        if (!WriteJournal(journal)) return WindowsAgentNativeOps.Failed("The Agent couldn't save the power settings before changing them, so it left them as they are.");

        var items = new List<BatteryDrainPowerAnswer.Item>();
        var failed = new List<string>();
        foreach (var s in Settings)
        {
            var old = previous[Key(s)];
            // A setting this plan doesn't have (energy saver on older Windows) is left alone.
            if (old is null) { items.Add(new(s.Name, null, null)); continue; }
            if (old != s.DrainValue && !plan.WriteDc(scheme, s.Subgroup, s.Setting, s.DrainValue)) failed.Add(s.Name);
            items.Add(new(s.Name, old, plan.ReadDc(scheme, s.Subgroup, s.Setting)));
        }
        plan.Activate(scheme);
        log.Info($"[battery-drain] Power settings set for the drain test on plan {scheme:D}" + (failed.Count > 0 ? $"; not changed: {string.Join(", ", failed)}" : ""));
        return Answer(new(true, items, journal.LeaseUntilUtc, Note: failed.Count > 0 ? "Windows didn't take: " + string.Join(", ", failed) : null));
    }

    private ProcessResult RenewLease() =>
        ReadJournal() is { } j ? Renewed(j) : WindowsAgentNativeOps.Failed("The drain test's power settings aren't in place (they were put back).");

    private ProcessResult Renewed(Journal j)
    {
        var at = Now();
        var renewed = j with { RenewedUtc = at, LeaseUntilUtc = at + Lease };
        WriteJournal(renewed);
        return Answer(new(true, [], renewed.LeaseUntilUtc));
    }

    private ProcessResult RestoreSettings(Journal? journal)
    {
        var j = journal ?? ReadJournal();
        if (j is null) return Answer(new(false, [], Note: "Nothing to put back."));
        var items = new List<BatteryDrainPowerAnswer.Item>();
        var failed = new List<string>();
        foreach (var s in Settings)
        {
            if (!j.Previous.TryGetValue(Key(s), out var old) || old is not { } value) continue;
            if (plan.ReadDc(j.Scheme, s.Subgroup, s.Setting) != value && !plan.WriteDc(j.Scheme, s.Subgroup, s.Setting, value)) failed.Add(s.Name);
            items.Add(new(s.Name, value, plan.ReadDc(j.Scheme, s.Subgroup, s.Setting)));
        }
        if (plan.ActiveScheme() == j.Scheme) plan.Activate(j.Scheme);
        if (failed.Count > 0)
        {
            log.Warn($"[battery-drain] Couldn't put back: {string.Join(", ", failed)}; the journal is kept to try again.");
            return WindowsAgentNativeOps.Failed("Windows didn't take back: " + string.Join(", ", failed));
        }
        DeleteJournal();
        log.Info($"[battery-drain] Power settings put back on plan {j.Scheme:D}.");
        return Answer(new(false, items));
    }

    private ProcessResult ShutdownPc()
    {
        var restored = RestoreSettings(null);
        var why = (startShutdown ?? StartWindowsShutdown)(ShutdownDelaySeconds, ShutdownMessage);
        if (why is not null) return WindowsAgentNativeOps.Failed(why);
        log.Info($"[battery-drain] Shutdown in {ShutdownDelaySeconds} s at the end of the drain test.");
        var answer = BatteryDrainPowerAnswer.Parse(restored.StdOut) ?? new(false, []);
        return Answer(answer with { ShutdownInSeconds = ShutdownDelaySeconds, Note = restored.ExitCode == 0 ? null : restored.StdErr });
    }

    private ProcessResult CurrentStatus() =>
        ReadJournal() is { } j ? Answer(new(true, [], j.LeaseUntilUtc)) : Answer(new(false, []));

    private static ProcessResult Answer(BatteryDrainPowerAnswer a) => new(0, a.ToJson(), "");

    public Journal? ReadJournal()
    {
        try { return File.Exists(journalPath) ? JsonSerializer.Deserialize<Journal>(File.ReadAllText(journalPath)) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            log.Warn($"[battery-drain] Couldn't read {journalPath}: {ex.Message}");
            return null;
        }
    }

    private bool WriteJournal(Journal j)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(journalPath)!);
            var tmp = journalPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(j));
            File.Move(tmp, journalPath, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Warn($"[battery-drain] Couldn't save {journalPath}: {ex.Message}");
            return false;
        }
    }

    private void DeleteJournal()
    {
        try { File.Delete(journalPath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"[battery-drain] Couldn't delete {journalPath}: {ex.Message}"); }
    }

    /// <summary>shutdown.exe from System32 with a fixed delay and message: a normal shutdown that apps are asked to close for.</summary>
    private static string? StartWindowsShutdown(int seconds, string message)
    {
        if (!OperatingSystem.IsWindows()) return "Shutting down needs Windows.";
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "shutdown.exe"))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var arg in new[] { "/s", "/t", seconds.ToString(System.Globalization.CultureInfo.InvariantCulture), "/c", message }) psi.ArgumentList.Add(arg);
            using var p = System.Diagnostics.Process.Start(psi);
            if (p is null) return "shutdown.exe didn't start.";
            p.WaitForExit(10_000);
            return p.HasExited && p.ExitCode != 0 ? $"shutdown.exe exited with code {p.ExitCode}." : null;
        }
        catch (Exception ex) { return ex.Message; }
    }

    private static AgentBatteryDrainPower? _windows;
    private static Timer? _sweep;
    private static readonly object WindowsGate = new();

    /// <summary>The PC's (powrprof, the protected state folder). Its first use also starts a timer that puts abandoned settings back.</summary>
    public static AgentBatteryDrainPower Windows(ILogger? log = null)
    {
        lock (WindowsGate)
        {
            _windows ??= new(OperatingSystem.IsWindows() ? new WindowsPowerPlanValues() : new NoPowerPlanValues(), ProtectedState.PathFor(JournalFile), log: log);
            _sweep ??= new Timer(_ => { try { _windows.RestoreIfAbandoned(); } catch { } }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
            return _windows;
        }
    }

    /// <summary>At the Agent's start: puts back settings a run left behind (the PC restarted, or the app's Agent went away mid-run).</summary>
    public static void RecoverAtStart(ILogger? log)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            if (!File.Exists(ProtectedState.PathFor(JournalFile))) return;
            Windows(log).RestoreIfAbandoned();
        }
        catch (Exception ex) { log.Warn($"[battery-drain] Start-up check of the drain test's power settings failed: {ex.Message}"); }
    }

    private sealed class NoPowerPlanValues : IPowerPlanValues
    {
        public Guid? ActiveScheme() => null;
        public uint? ReadDc(Guid scheme, Guid subgroup, Guid setting) => null;
        public bool WriteDc(Guid scheme, Guid subgroup, Guid setting, uint value) => false;
        public void Activate(Guid scheme) { }
    }
}

/// <summary>powrprof's PowerReadDCValueIndex / PowerWriteDCValueIndex on the plan, and PowerSetActiveScheme to apply them.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPowerPlanValues : IPowerPlanValues
{
    public Guid? ActiveScheme()
    {
        if (PowerGetActiveScheme(IntPtr.Zero, out var ptr) != 0 || ptr == IntPtr.Zero) return null;
        try { return Marshal.PtrToStructure<Guid>(ptr); }
        finally { LocalFree(ptr); }
    }

    public uint? ReadDc(Guid scheme, Guid subgroup, Guid setting) =>
        PowerReadDCValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, out var v) == 0 ? v : null;

    public bool WriteDc(Guid scheme, Guid subgroup, Guid setting, uint value) =>
        PowerWriteDCValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, value) == 0;

    public void Activate(Guid scheme) => PowerSetActiveScheme(IntPtr.Zero, ref scheme);

    [DllImport("powrprof.dll")] private static extern uint PowerGetActiveScheme(IntPtr userRootPowerKey, out IntPtr activePolicyGuid);
    [DllImport("powrprof.dll")] private static extern uint PowerReadDCValueIndex(IntPtr rootPowerKey, ref Guid schemeGuid, ref Guid subGroupOfPowerSettingsGuid, ref Guid powerSettingGuid, out uint value);
    [DllImport("powrprof.dll")] private static extern uint PowerWriteDCValueIndex(IntPtr rootPowerKey, ref Guid schemeGuid, ref Guid subGroupOfPowerSettingsGuid, ref Guid powerSettingGuid, uint value);
    [DllImport("powrprof.dll")] private static extern uint PowerSetActiveScheme(IntPtr userRootPowerKey, ref Guid schemeGuid);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr hMem);
}
