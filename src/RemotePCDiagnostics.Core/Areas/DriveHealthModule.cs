using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One physical drive's health (Windows Storage: MSFT_PhysicalDisk + storage reliability counters). Strings as reported.</summary>
public sealed record DriveHealth(
    string Name, string Serial, string MediaType, string BusType, string Health, string Operational,
    long? SizeBytes, int? TemperatureC, int? Wear, long? ReadErrors, long? WriteErrors, long? PowerOnHours, string Letters = "")
{
    public static DriveHealth FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("Name"), r.Str("Serial"), r.Str("MediaType"), r.Str("BusType"), r.Str("Health"), r.Str("Operational"),
        r.Long("Size"), r.Int("Temperature"), r.Int("Wear"), r.Long("ReadErrors"), r.Long("WriteErrors"), r.Long("PowerOnHours"), r.Str("Letters"));

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
public sealed class DriveHealthModule(SystemCommandRunner commands, OsqueryRunner osquery, IRetrimHistory? retrims = null, Func<DateTimeOffset>? clock = null)
    : AreaModuleBase(commands.Log ?? osquery.Options.Log)
{
    /// <summary>"Optimize / Retrim SSD" is offered only when a volume of the SSD wasn't retrimmed in this long (or the date is unknown).</summary>
    public static readonly TimeSpan RetrimFreshFor = TimeSpan.FromDays(30);

    public const string ModuleName = "DriveHealth";
    public override string Name => ModuleName;
    public override string DisplayName => "Drive health";
    protected override string FailedMessage => "Couldn't check drive health on this PC.";

    public const string Script =
        "$ErrorActionPreference='SilentlyContinue';" +
        "$d=@(Get-PhysicalDisk | ForEach-Object { $r=$_ | Get-StorageReliabilityCounter;" +
        "$l=(@(Get-Partition -DiskNumber $_.DeviceId | Where-Object { $_.DriveLetter } | ForEach-Object { [string]$_.DriveLetter }) -join '');" +
        "[pscustomobject]@{Letters=$l;" +
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
        if (drives is { Count: > 0 }) return Build(drives, await ReadRetrimsAsync(ct).ConfigureAwait(false), (clock ?? (() => DateTimeOffset.Now))());

        Log($"{Name}: Windows storage health unavailable; falling back to osquery disk_info (no health data)");
        var q = await osquery.RunQueryAsync(HardwareInventory.DiskSql, ct).ConfigureAwait(false);
        if (!q.Success) return AreaReport.Failed(FailedMessage);
        var fallback = q.Rows!.Select(DiskInfo.FromRow)
            .Select(d => new DriveHealth(d.HardwareModel, d.Serial, "", d.Type, "", "", d.SizeBytes, null, null, null, null, null)).ToList();
        return Build(fallback) with { Notice = "Windows didn't report drive health on this PC, so only the drive list is shown." };
    }

    private async Task<IReadOnlyDictionary<char, RetrimRecord>?> ReadRetrimsAsync(CancellationToken ct)
    {
        if (retrims is null) return null;
        try { return await retrims.LatestAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log($"{Name}: last retrim unknown: {ex.Message}"); return null; }
    }

    /// <summary>True when every letter was retrimmed within <see cref="RetrimFreshFor"/>; unknown letters count as not recent.</summary>
    public static bool RecentlyRetrimmed(string letters, IReadOnlyDictionary<char, RetrimRecord>? retrims, DateTimeOffset now) =>
        letters.Length > 0 && retrims is not null && letters.All(c => retrims.TryGetValue(c, out var r) && now - r.When < RetrimFreshFor);

    /// <summary>"6 days ago (by Windows)"; per letter when they differ ("C: today (by this app); D: Not reported").</summary>
    public static string LastOptimizedText(string letters, IReadOnlyDictionary<char, RetrimRecord>? retrims, DateTimeOffset now)
    {
        string One(char c) => retrims is not null && retrims.TryGetValue(c, out var r) ? $"{Ago(r.When, now)} ({r.SourceText})" : "Not reported";
        var parts = letters.Select(c => (c, t: One(c))).ToList();
        return parts.Select(p => p.t).Distinct().Count() <= 1 ? parts.FirstOrDefault().t ?? "Not reported" : string.Join("; ", parts.Select(p => $"{p.c}: {p.t}"));
    }

    private static string Ago(DateTimeOffset when, DateTimeOffset now)
    {
        var days = (int)Math.Floor((now - when).TotalDays);
        return days <= 0 ? "today" : days == 1 ? "yesterday" : $"{days} days ago";
    }

    public static AreaReport Build(IReadOnlyList<DriveHealth> drives) => Build(drives, null, DateTimeOffset.Now);

    public static AreaReport Build(IReadOnlyList<DriveHealth> drives, IReadOnlyDictionary<char, RetrimRecord>? retrims, DateTimeOffset now)
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
            var ssdLetters = d.Kind == "SSD" ? RemediationService.DriveLetters(d.Letters) : "";
            if (ssdLetters.Length > 0) Add("Last optimized", LastOptimizedText(ssdLetters, retrims, now));
            Add("Serial number", d.Serial);
            var actions = new List<AreaAction>();
            if (i == 0)
                actions.Add(new(RemediationKind.CleanTempFiles, "Clean up temporary files", "", "Temporary files & Recycle Bin"));
            // Not offered when Windows or this app retrimmed every volume of this SSD in the last 30 days.
            if (ssdLetters.Length > 0 && !RecentlyRetrimmed(ssdLetters, retrims, now))
                actions.Add(new(RemediationKind.OptimizeSsd, "Optimize / Retrim SSD", ssdLetters, d.Name.Length > 0 ? d.Name : "SSD"));
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
