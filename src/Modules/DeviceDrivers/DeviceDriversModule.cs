using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One device in Device Manager that has a non-zero <c>ConfigManagerErrorCode</c> (<c>Win32_PnPEntity</c>).</summary>
public sealed record ProblemDevice(string Name, string Class, string DeviceId, int ErrorCode, string Status)
{
    public static ProblemDevice FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("Name").Length > 0 ? r.Str("Name") : "Unknown device",
        r.Str("Class"), r.Str("DeviceId"), r.Int("ErrorCode") ?? 0, r.Str("Status"));

    public bool IsDisabledOnly => ErrorCode == 22;

    public string FriendlyError => ErrorCode switch
    {
        1 => "Not configured correctly (Code 1)",
        10 => "Cannot start (Code 10)",
        12 => "Not enough free resources (Code 12)",
        14 => "Restart required (Code 14)",
        18 => "Reinstall drivers (Code 18)",
        19 => "Registry configuration damaged (Code 19)",
        22 => "Disabled (Code 22)",
        24 => "Not present or not working (Code 24)",
        28 => "Drivers not installed (Code 28)",
        31 => "Cannot load required drivers (Code 31)",
        32 => "Driver service disabled (Code 32)",
        37 => "Driver initialization failed (Code 37)",
        39 => "Driver corrupted or missing (Code 39)",
        43 => "Device reported a problem and was stopped (Code 43)",
        45 => "Not connected (Code 45)",
        47 => "Prepared for safe removal (Code 47)",
        48 => "Blocked from starting (Code 48)",
        52 => "Unsigned driver signature (Code 52)",
        _ => $"Problem code {ErrorCode}",
    };
}

/// <summary>One installed hardware driver from osquery <c>drivers</c>.</summary>
public sealed record DriverEntry(string DeviceName, string Class, string Provider, string Version, DateOnly? Date, bool Signed)
{
    public static DriverEntry FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("device_name").Length > 0 ? r.Str("device_name") : r.Str("description"),
        r.Str("class"),
        r.Str("provider").Length > 0 ? r.Str("provider") : r.Str("manufacturer"),
        r.Str("version"),
        OsqueryDates.Parse(r.Str("date")),
        r.Str("signed") != "0");
}

/// <summary>
/// Device Manager problems (<c>Win32_PnPEntity</c> where <c>ConfigManagerErrorCode &lt;&gt; 0</c>) and hardware driver versions
/// (osquery <c>drivers</c>).
/// </summary>
public sealed class DeviceDriversModule(OsqueryRunner runner, SystemCommandRunner commands) : OsqueryAreaModuleBase(runner)
{
    public const string ModuleName = ModuleSlugs.DeviceDrivers;
    public const string DriversSql = "SELECT device_name, description, class, provider, manufacturer, version, date, signed FROM drivers WHERE device_name != '';";
    public static string ProblemDevicesScript => Scripts.PowerShellScripts.Get("ProblemDevices");

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DeviceDrivers;
    public override string DisplayName => "Device Manager & drivers";
    protected override string FailedMessage => "Couldn't check Device Manager and drivers on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Checking Device Manager for problem devices…");
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ProblemDevicesScript], ct).ConfigureAwait(false);
        List<ProblemDevice>? problems = null;
        if (pr is { ExitCode: 0 })
        {
            if (string.IsNullOrWhiteSpace(pr.StdOut) || pr.StdOut.Trim() == "[]") problems = [];
            else
            {
                try { problems = OsqueryJson.ParseRows(pr.StdOut).Select(ProblemDevice.FromRow).ToList(); }
                catch (FormatException ex) { LogWarn($"{Name}: problem devices output unreadable: {ex.Message}"); }
            }
        }

        progress.ReportStep(2, 2, "Reading hardware drivers…");
        var drvQ = await QueryAsync(DriversSql, ct).ConfigureAwait(false);
        var drivers = drvQ.Success ? drvQ.Rows!.Select(DriverEntry.FromRow).ToList() : null;
        return Build(problems, drivers);
    }

    private static readonly HashSet<string> KeyClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "DISPLAY", "NET", "MEDIA", "HDC", "SCSIADAPTER", "NVME", "USB", "BLUETOOTH", "CAMERA", "IMAGE", "BIOMETRIC", "HIDCLASS",
    };

    public static AreaReport Build(IReadOnlyList<ProblemDevice>? problems, IReadOnlyList<DriverEntry>? drivers)
    {
        if (problems is null && drivers is null) return AreaReport.Failed("Couldn't check Device Manager and drivers on this PC.");
        var cards = new List<AreaCard>();
        var parts = new List<string>();

        if (problems is null)
            cards.Add(AreaCard.Failed("problems", "Device Manager problems", "Couldn't read Device Manager status."));
        else
        {
            var faulting = problems.Where(p => !p.IsDisabledOnly).ToList();
            var disabled = problems.Where(p => p.IsDisabledOnly).ToList();
            var level = faulting.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok;
            var headline = problems.Count == 0 ? "All devices working"
                : faulting.Count > 0 ? $"{Plural(faulting.Count, "device")} with a problem"
                : $"{Plural(disabled.Count, "disabled device")}";
            var meta = problems.Count == 0 ? "No Device Manager errors or missing drivers"
                : string.Join(", ", problems.Take(2).Select(p => $"{p.Name} ({p.FriendlyError})"));

            var rows = problems.OrderBy(p => p.IsDisabledOnly).ThenBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase)
                .Select(p => new AreaRow(
                    p.IsDisabledOnly ? AreaLevel.Neutral : AreaLevel.Warning,
                    [p.Name, p.Class.Length > 0 ? p.Class : "Other", p.FriendlyError],
                    Actions: p.DeviceId.Length > 0
                        ? [new AreaAction(p.IsDisabledOnly ? RemediationKind.EnableDevice : RemediationKind.RestartDevice,
                            p.IsDisabledOnly ? "Enable device" : "Restart device", p.DeviceId, p.Name)]
                        : null)).ToList();
            cards.Add(new("problems", "Device Manager problems", level, headline, meta,
                ["Device", "Category", "Problem"], rows,
                EmptyText: "No devices with problems were reported by Windows.",
                Actions:
                [
                    new(RemediationKind.CheckAndInstallDriverUpdates, "Check & install driver updates"),
                    new(RemediationKind.ScanHardwareChanges, "Scan for hardware changes"),
                ]));

            parts.Add(problems.Count == 0 ? "All devices working"
                : faulting.Count > 0 ? $"{Plural(faulting.Count, "device problem")}"
                : $"{Plural(disabled.Count, "disabled device")}");
        }

        if (drivers is null)
            cards.Add(AreaCard.Failed("drivers", "Hardware drivers", "Couldn't read installed drivers."));
        else
        {
            var distinct = drivers.Where(d => d.DeviceName.Length > 0)
                .DistinctBy(d => (d.DeviceName.ToUpperInvariant(), d.Version))
                .OrderByDescending(d => KeyClasses.Contains(d.Class))
                .ThenBy(d => d.Class, StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(d => d.DeviceName, StringComparer.CurrentCultureIgnoreCase).ToList();
            var unsigned = distinct.Where(d => !d.Signed).ToList();
            var level = unsigned.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok;

            cards.Add(new("drivers", "Hardware drivers", level,
                Plural(distinct.Count, "driver"),
                unsigned.Count > 0 ? $"{Plural(unsigned.Count, "unsigned driver")} · click to inspect" : "All reported drivers are signed",
                ["Device", "Category", "Provider", "Version", "Date"],
                distinct.Select(d => new AreaRow(d.Signed ? AreaLevel.Neutral : AreaLevel.Warning,
                    [d.DeviceName, d.Class, d.Provider, d.Version, OsqueryDates.Format(d.Date)],
                    [null, null, null, null, OsqueryDates.SortKey(d.Date)])).ToList(),
                EmptyText: "No drivers were reported.",
                Actions: [new(RemediationKind.CheckAndInstallDriverUpdates, "Check & install driver updates")]));

            parts.Add(Plural(distinct.Count, "driver") + (unsigned.Count > 0 ? $" ({unsigned.Count} unsigned)" : ""));
        }

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status);
    }
}
