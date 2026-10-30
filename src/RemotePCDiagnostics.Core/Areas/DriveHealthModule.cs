using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One physical drive's health (Windows Storage: MSFT_PhysicalDisk + storage reliability counters). Strings as reported.</summary>
public sealed record DriveHealth(
    string Name, string Serial, string MediaType, string BusType, string Health, string Operational,
    long? SizeBytes, int? TemperatureC, int? Wear, long? ReadErrors, long? WriteErrors, long? PowerOnHours)
{
    public static DriveHealth FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("Name"), r.Str("Serial"), r.Str("MediaType"), r.Str("BusType"), r.Str("Health"), r.Str("Operational"),
        r.Long("Size"), r.Int("Temperature"), r.Int("Wear"), r.Long("ReadErrors"), r.Long("WriteErrors"), r.Long("PowerOnHours"));

    public const int HotC = 60, WornPercent = 90;

    public AreaLevel Level
    {
        get
        {
            if (Health.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase)) return AreaLevel.Error;
            if (Health.Equals("Warning", StringComparison.OrdinalIgnoreCase)) return AreaLevel.Warning;
            if (ReadErrors is > 0 || WriteErrors is > 0 || Wear >= WornPercent || TemperatureC >= HotC) return AreaLevel.Warning;
            return Health.Equals("Healthy", StringComparison.OrdinalIgnoreCase) ? AreaLevel.Ok : AreaLevel.Neutral;
        }
    }

    public string Verdict => Level switch
    {
        AreaLevel.Error => "Failing – back up your files now",
        AreaLevel.Warning => "Needs attention",
        AreaLevel.Ok => "Healthy",
        _ => "Health not reported",
    };

    public IEnumerable<string> Reasons()
    {
        if (Health.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase)) yield return "Windows reports this drive as failing";
        else if (Health.Equals("Warning", StringComparison.OrdinalIgnoreCase)) yield return "Windows reports a warning for this drive";
        if (ReadErrors is > 0 || WriteErrors is > 0) yield return "it has had read/write errors it couldn't correct";
        if (Wear >= WornPercent) yield return $"about {Wear}% of its rated life is used";
        if (TemperatureC >= HotC) yield return $"it is running hot ({TemperatureC}°C)";
    }

    public string Kind => MediaType switch
    {
        "SSD" => "SSD", "HDD" => "Hard drive", "SCM" => "Storage-class memory", _ => BusType.Equals("NVMe", StringComparison.OrdinalIgnoreCase) ? "SSD" : "Drive",
    };
}

/// <summary>
/// Drive health. osquery has no SMART table on Windows, so health comes from Windows Storage
/// (Get-PhysicalDisk HealthStatus/OperationalStatus + Get-StorageReliabilityCounter) via PowerShell.
/// If that fails, drives are listed from osquery disk_info with health marked as not reported.
/// </summary>
public sealed class DriveHealthModule(SystemCommandRunner commands, OsqueryRunner osquery) : AreaModuleBase(commands.Log ?? osquery.Options.Log)
{
    public const string ModuleName = "DriveHealth";
    public override string Name => ModuleName;
    public override string DisplayName => "Drive health";
    protected override string FailedMessage => "Couldn't check drive health on this PC.";

    public const string Script =
        "$ErrorActionPreference='SilentlyContinue';" +
        "$d=@(Get-PhysicalDisk | ForEach-Object { $r=$_ | Get-StorageReliabilityCounter; [pscustomobject]@{" +
        "Name=[string]$_.FriendlyName;Serial=[string]$_.SerialNumber;MediaType=[string]$_.MediaType;BusType=[string]$_.BusType;" +
        "Health=[string]$_.HealthStatus;Operational=[string]($_.OperationalStatus -join ', ');Size=[string]$_.Size;" +
        "Temperature=[string]$r.Temperature;Wear=[string]$r.Wear;ReadErrors=[string]$r.ReadErrorsUncorrected;" +
        "WriteErrors=[string]$r.WriteErrorsUncorrected;PowerOnHours=[string]$r.PowerOnHours } });" +
        "ConvertTo-Json -InputObject $d -Compress";

    public static IReadOnlyList<string> Arguments => ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", Script];

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking drives…");
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell, Arguments, ct).ConfigureAwait(false);
        List<DriveHealth>? drives = null;
        if (pr is { ExitCode: 0 })
        {
            try { drives = OsqueryJson.ParseRows(pr.StdOut).Select(DriveHealth.FromRow).ToList(); }
            catch (FormatException ex) { Log($"{Name}: storage health output unreadable: {ex.Message}"); }
        }
        if (drives is { Count: > 0 }) return Build(drives);

        Log($"{Name}: Windows storage health unavailable; falling back to osquery disk_info (no health data)");
        var q = await osquery.RunQueryAsync(HardwareInventory.DiskSql, ct).ConfigureAwait(false);
        if (!q.Success) return AreaReport.Failed(FailedMessage);
        var fallback = q.Rows!.Select(DiskInfo.FromRow)
            .Select(d => new DriveHealth(d.HardwareModel, d.Serial, "", d.Type, "", "", d.SizeBytes, null, null, null, null, null)).ToList();
        return Build(fallback) with { Notice = "Windows didn't report drive health on this PC, so only the drive list is shown." };
    }

    public static AreaReport Build(IReadOnlyList<DriveHealth> drives)
    {
        if (drives.Count == 0)
            return new([], "No drives were found to check.", DiagnosticStatus.Warning);
        string[] cols = ["Detail", "Value"];
        var cards = drives.Select((d, i) =>
        {
            var meta = string.Join(" · ", new[]
            {
                d.Kind, d.SizeBytes is > 0 ? HardwareInventory.FormatBytes(d.SizeBytes) : null,
                d.TemperatureC is > 0 ? $"{d.TemperatureC}°C" : null, d.Wear is not null ? $"{d.Wear}% worn" : null,
            }.Where(x => x is not null));
            var rows = new List<AreaRow>();
            void Add(string label, string? v, AreaLevel l = AreaLevel.Neutral) { if (!string.IsNullOrWhiteSpace(v)) rows.Add(new(l, [label, v])); }
            Add("Overall", d.Verdict + (d.Reasons().Any() ? ": " + string.Join("; ", d.Reasons()) : ""), d.Level);
            Add("Status reported by Windows", d.Health.Length > 0 ? $"{d.Health}{(d.Operational.Length > 0 && d.Operational != "OK" ? $" ({d.Operational})" : "")}" : "Not reported");
            Add("Type", d.Kind);
            Add("Connection", d.BusType);
            Add("Size", d.SizeBytes is > 0 ? HardwareInventory.FormatBytes(d.SizeBytes) : null);
            Add("Temperature", d.TemperatureC is > 0 ? $"{d.TemperatureC}°C" : "Not reported", d.TemperatureC >= DriveHealth.HotC ? AreaLevel.Warning : AreaLevel.Neutral);
            Add("Life used", d.Wear is not null ? $"{d.Wear}%" : "Not reported", d.Wear >= DriveHealth.WornPercent ? AreaLevel.Warning : AreaLevel.Neutral);
            Add("Uncorrected read errors", d.ReadErrors?.ToString(CultureInfo.InvariantCulture) ?? "Not reported", d.ReadErrors is > 0 ? AreaLevel.Warning : AreaLevel.Neutral);
            Add("Uncorrected write errors", d.WriteErrors?.ToString(CultureInfo.InvariantCulture) ?? "Not reported", d.WriteErrors is > 0 ? AreaLevel.Warning : AreaLevel.Neutral);
            Add("Hours powered on", d.PowerOnHours is >= 0 ? d.PowerOnHours.Value.ToString("N0", CultureInfo.InvariantCulture) : "Not reported");
            Add("Serial number", d.Serial);
            var actions = new List<AreaAction>();
            if (i == 0)
                actions.Add(new(RemediationKind.CleanTempFiles, "Clean up temporary files", "", "Temporary files & Recycle Bin"));
            if (d.Kind == "SSD")
                actions.Add(new(RemediationKind.OptimizeSsd, "Optimize / Retrim SSD", "C", d.Name.Length > 0 ? d.Name : "SSD"));
            return new AreaCard($"drive{i}", d.Name.Length > 0 ? d.Name : $"Drive {i + 1}", d.Level, d.Verdict, meta, cols, rows,
                Actions: actions.Count > 0 ? actions : null);
        }).ToList();

        var bad = drives.Count(d => d.Level is AreaLevel.Warning or AreaLevel.Error);
        var unknown = drives.All(d => d.Level == AreaLevel.Neutral);
        var summary = bad > 0 ? $"{bad} of {Plural(drives.Count, "drive")} need{(bad == 1 ? "s" : "")} attention"
            : unknown ? $"{Plural(drives.Count, "drive")} found · health not reported"
            : drives.Count == 1 ? "1 drive · healthy" : $"{drives.Count} drives · all healthy";
        return new(cards, summary, AreaReport.Worst(drives.Select(d => d.Level)));
    }
}
