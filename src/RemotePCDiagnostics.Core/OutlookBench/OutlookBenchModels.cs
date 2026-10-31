using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.OutlookBench;

// Data collected by OutlookBenchmark.exe on each PC. Kept free of personal data: no mail, no account names, no user name.

public sealed record CpuInfo(string Name, int Cores, int Threads, int MaxMhz);
public sealed record RamInfo(long TotalBytes, long AvailableBytes, int Modules, int Slots, int? SpeedMhz, long? MaxSupportedBytes);
public sealed record DiskInfo(string Model, string MediaType, string BusType, long SizeBytes, long FreeBytes);

public sealed record SystemProfile(
    string Machine, string Manufacturer, string Model, CpuInfo Cpu, RamInfo Ram, DiskInfo SystemDisk,
    string Os, string OsBuild, double UptimeHours, long PageFileBytes, int ProcessCount, bool? OnBattery, string? PowerPlan,
    IReadOnlyList<string> Antivirus, string? NetworkType, double? Office365ConnectMs, double? CpuSingleScore, double? CpuMultiScore, double? DiskReadLatencyMs);

public sealed record MailFile(string Kind, double SizeGb, bool OnNetwork, DateTimeOffset? LastWrite);

/// <param name="LoadBehavior">3 = loads at start-up, 2 = off, 0/1 = not loaded on demand.</param>
/// <param name="RecordedLoadMs">Outlook's own recent load times for this add-in (from AddInLoadTimes), newest first where known.</param>
public sealed record AddinInfo(string ProgId, string Name, string Scope, int? LoadBehavior, IReadOnlyList<int> RecordedLoadMs, string? RawLoadTimes, bool DisabledByOutlook)
{
    public bool LoadsAtStartup => LoadBehavior is 3 or 9 or 16;
}

public sealed record OutlookProfile(
    bool Installed, string? Version, string? Bitness, string? Channel, bool NewOutlookDefault, bool NewOutlookInstalled, bool HasDefaultProfile,
    int? SyncWindowMonths, IReadOnlyList<MailFile> Files, IReadOnlyList<AddinInfo> Addins)
{
    public double OstGb => Files.Where(f => f.Kind == "ost").Sum(f => f.SizeGb);
    public double PstGb => Files.Where(f => f.Kind == "pst").Sum(f => f.SizeGb);
    public int AddinsAtStartup => Addins.Count(a => a.LoadsAtStartup && !a.DisabledByOutlook);
    public int RecordedAddinMs => Addins.Where(a => a.LoadsAtStartup).Sum(a => a.RecordedLoadMs.Count > 0 ? a.RecordedLoadMs[0] : 0);
}

public enum StartMode { Normal, Safe }

/// <param name="ReadyMs">Window shown and Outlook's processor use settled (null = didn't settle in time / prompt shown).</param>
public sealed record StartRun(int Index, StartMode Mode, bool First, double? WindowMs, double? ReadyMs, long PeakWorkingSetBytes, long PeakPrivateBytes,
    long ReadBytes, double PagesPerSec, long MinAvailableBytes, bool ClosedCleanly, string? Note);

public sealed record StartSummary(double? FirstStartS, double? NormalMedianS, double? SafeMedianS, double? AddinCostS, double? PeakWorkingSetMb, double? PagesPerSec, double? MinAvailableMb, double? ReadMb)
{
    public static StartSummary From(IReadOnlyList<StartRun> runs)
    {
        static double? Med(IEnumerable<double> v) { var s = v.OrderBy(x => x).ToList(); return s.Count == 0 ? null : s.Count % 2 == 1 ? s[s.Count / 2] : (s[s.Count / 2 - 1] + s[s.Count / 2]) / 2; }
        var first = runs.FirstOrDefault(r => r.First)?.ReadyMs;
        var normal = Med(runs.Where(r => r.Mode == StartMode.Normal && !r.First && r.ReadyMs is not null).Select(r => r.ReadyMs!.Value / 1000));
        var safe = Med(runs.Where(r => r.Mode == StartMode.Safe && r.ReadyMs is not null).Select(r => r.ReadyMs!.Value / 1000));
        var normalRuns = runs.Where(r => r.Mode == StartMode.Normal && r.ReadyMs is not null).ToList();
        return new(first / 1000, normal, safe, normal is { } n && safe is { } s ? Math.Round(n - s, 2) : null,
            normalRuns.Count == 0 ? null : normalRuns.Max(r => r.PeakWorkingSetBytes) / 1048576.0,
            Med(normalRuns.Select(r => r.PagesPerSec)), normalRuns.Count == 0 ? null : normalRuns.Min(r => r.MinAvailableBytes) / 1048576.0,
            Med(normalRuns.Select(r => r.ReadBytes / 1048576.0)));
    }
}

public sealed record BenchResult(string ToolVersion, DateTimeOffset TimeUtc, SystemProfile System, OutlookProfile Outlook, IReadOnlyList<StartRun> Runs, StartSummary Start, IReadOnlyList<string> Notes)
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static readonly string[] CsvColumns =
    [
        "time_utc", "machine", "manufacturer", "model", "cpu", "cores", "threads", "cpu_max_mhz", "ram_gb", "ram_available_gb", "ram_modules", "ram_slots", "ram_speed_mhz",
        "disk_model", "disk_media", "disk_bus", "disk_free_gb", "os", "os_build", "uptime_h", "pagefile_gb", "processes", "on_battery", "power_plan", "antivirus",
        "network", "o365_connect_ms", "cpu_single", "cpu_multi", "disk_read_latency_ms",
        "outlook_version", "outlook_bitness", "outlook_channel", "new_outlook_default", "sync_window_months", "ost_gb", "pst_gb", "pst_on_network",
        "addins_at_startup", "addins_recorded_ms", "first_start_s", "normal_start_s", "safe_start_s", "addin_cost_s",
        "peak_working_set_mb", "pages_per_sec", "min_available_mb", "start_read_mb", "runs_ok", "runs_total", "tool_version",
    ];

    private static string F(double? v, string fmt = "0.##") => v?.ToString(fmt, CultureInfo.InvariantCulture) ?? "";
    private static string Q(string? s) => s is null ? "" : s.Contains(',') || s.Contains('"') || s.Contains('\n') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    private const double Gb = 1024d * 1024 * 1024;

    public string ToCsvRow()
    {
        var sy = System; var o = Outlook; var st = Start;
        string[] v =
        [
            TimeUtc.ToString("O", CultureInfo.InvariantCulture), sy.Machine, sy.Manufacturer, sy.Model, sy.Cpu.Name, sy.Cpu.Cores.ToString(CultureInfo.InvariantCulture), sy.Cpu.Threads.ToString(CultureInfo.InvariantCulture), sy.Cpu.MaxMhz.ToString(CultureInfo.InvariantCulture),
            F(sy.Ram.TotalBytes / Gb), F(sy.Ram.AvailableBytes / Gb), sy.Ram.Modules.ToString(CultureInfo.InvariantCulture), sy.Ram.Slots.ToString(CultureInfo.InvariantCulture), F(sy.Ram.SpeedMhz, "0"),
            sy.SystemDisk.Model, sy.SystemDisk.MediaType, sy.SystemDisk.BusType, F(sy.SystemDisk.FreeBytes / Gb, "0.#"), sy.Os, sy.OsBuild, F(sy.UptimeHours, "0.#"), F(sy.PageFileBytes / Gb), sy.ProcessCount.ToString(CultureInfo.InvariantCulture),
            sy.OnBattery?.ToString() ?? "", sy.PowerPlan ?? "", string.Join(" + ", sy.Antivirus), sy.NetworkType ?? "", F(sy.Office365ConnectMs, "0"), F(sy.CpuSingleScore, "0"), F(sy.CpuMultiScore, "0"), F(sy.DiskReadLatencyMs, "0.000"),
            o.Version ?? "", o.Bitness ?? "", o.Channel ?? "", o.NewOutlookDefault.ToString(), F(o.SyncWindowMonths, "0"), F(o.OstGb), F(o.PstGb), o.Files.Any(f => f.Kind == "pst" && f.OnNetwork).ToString(),
            o.AddinsAtStartup.ToString(CultureInfo.InvariantCulture), o.RecordedAddinMs.ToString(CultureInfo.InvariantCulture), F(st.FirstStartS), F(st.NormalMedianS), F(st.SafeMedianS), F(st.AddinCostS),
            F(st.PeakWorkingSetMb, "0"), F(st.PagesPerSec, "0"), F(st.MinAvailableMb, "0"), F(st.ReadMb, "0"),
            Runs.Count(r => r.ReadyMs is not null).ToString(CultureInfo.InvariantCulture), Runs.Count.ToString(CultureInfo.InvariantCulture), ToolVersion,
        ];
        return string.Join(",", v.Select(Q));
    }
}

/// <summary>Pure helpers (tested): when Outlook counts as "ready", and Outlook's recorded add-in load times.</summary>
public static class OutlookBenchMath
{
    /// <summary>
    /// Ready = first moment after the main window appeared when Outlook's processor use stayed below <paramref name="busyPercentOfOneCore"/>
    /// of one core for <paramref name="quietSamples"/> consecutive samples. Returns the start of that quiet stretch (ms), or null.
    /// </summary>
    /// <param name="samples">(elapsed ms at end of sample, CPU ms used during the sample).</param>
    public static double? ReadyAt(IReadOnlyList<(double ElapsedMs, double CpuMs)> samples, double windowMs, double intervalMs, double busyPercentOfOneCore = 10, int quietSamples = 3)
    {
        var quiet = 0; double? start = null;
        foreach (var (t, cpu) in samples)
        {
            if (t < windowMs) continue;
            if (cpu / intervalMs * 100 < busyPercentOfOneCore)
            {
                if (quiet++ == 0) start = Math.Max(windowMs, t - intervalMs);
                if (quiet >= quietSamples) return start;
            }
            else quiet = 0;
        }
        return null;
    }

    /// <summary>
    /// Outlook keeps recent load times per add-in as a binary list of 32-bit values (ms). When the first value looks like a count of the
    /// rest, it's skipped. The raw bytes are logged too, so the format can be re-checked against the data later.
    /// </summary>
    public static IReadOnlyList<int> ParseLoadTimes(byte[]? raw)
    {
        if (raw is null || raw.Length < 4 || raw.Length % 4 != 0) return [];
        var v = Enumerable.Range(0, raw.Length / 4).Select(i => BitConverter.ToInt32(raw, i * 4)).ToList();
        if (v.Count > 1 && v[0] == v.Count - 1) v.RemoveAt(0);
        return v.Where(x => x is >= 0 and < 600_000).ToList();
    }

    public static string Hex(byte[]? raw) => raw is null ? "" : Convert.ToHexString(raw);

    /// <summary>Short stable id for a machine name when results are shared anonymously.</summary>
    public static string Anonymize(string machine) =>
        "PC-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(machine.ToUpperInvariant())))[..8];
}
