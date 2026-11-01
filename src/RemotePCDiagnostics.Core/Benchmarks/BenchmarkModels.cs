using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>What each benchmark measures. Chosen for things a client feels, and that the fixes this app makes actually move.</summary>
public enum BenchmarkKind
{
    BootTime, ProgramStart, IdleCpu, Paging, CpuSingle, CpuMulti, DiskLatency, DnsLookup,
    MemoryUsedMb, BackgroundProcesses, DiskFreeGb, EnabledStartupApps, AutoVendorServices, ActiveScheduledTasks, InstalledBloatwareApps,
}

public enum BenchmarkPhase { Before, After }

/// <summary>How a benchmark is shown and judged.</summary>
/// <param name="LowerIsBetter">Times and loads: lower is better. Processor scores: higher is better.</param>
/// <param name="MinRelativeChange">Smallest change (fraction) that counts as real, on top of the measured run-to-run spread.</param>
/// <param name="MinAbsoluteChange">Smallest change in the unit that counts (stops 0.4% → 0.2% CPU reading as "2× better").</param>
/// <param name="Weight">Share in the overall score.</param>
public sealed record BenchmarkInfo(BenchmarkKind Kind, string Title, string ClientMeaning, string Unit, bool LowerIsBetter,
    double MinRelativeChange, double MinAbsoluteChange, double Weight, string Format = "0.#", string BetterWord = "faster", string WorseWord = "slower")
{
    public string Show(double v) => v.ToString(Format, CultureInfo.InvariantCulture) + (Unit.Length > 0 ? " " + Unit : "");
}

public static class Benchmarks
{
    public static readonly IReadOnlyList<BenchmarkInfo> All =
    [
        new(BenchmarkKind.BootTime, "Start-up time", "How long Windows takes to start until the desktop is ready", "s", true, 0.08, 2, 2.0, "0.0"),
        new(BenchmarkKind.ProgramStart, "Program start time", "How quickly programs open (Windows' own programs, timed)", "ms", true, 0.08, 15, 2.0, "0"),
        // Memory and process count are the median of several idle samples (see BenchmarkSettings.ResourceSamples). Memory in use drifts by a
        // few hundred MB between restarts on its own, so it needs 5% and 200 MB to count and carries little weight; the process count is an
        // inventory figure ("N fewer"), like start-up apps, and doesn't move the overall score.
        new(BenchmarkKind.MemoryUsedMb, "Memory in use at idle", "RAM in use after Windows finishes starting up", "MB", true, 0.05, 200, 0.5, "0", "less", "more"),
        new(BenchmarkKind.BackgroundProcesses, "Background processes", "Processes running in the background at idle (not counting this app and what it starts)", "processes", true, 0.03, 5, 0.0, "0", "fewer", "more"),
        new(BenchmarkKind.DiskFreeGb, "Free disk space", "Available storage space on the system drive", "GB", false, 0.005, 0.2, 0.0, "0.0", "more", "less"),
        new(BenchmarkKind.IdleCpu, "Background processor use", "Processor busy with background work while nobody is using the PC", "%", true, 0.15, 1.5, 1.0, "0.0", "lower", "higher"),
        new(BenchmarkKind.Paging, "Memory swapping to disk", "How often Windows has to swap memory to the much slower disk", "pages/s", true, 0.20, 20, 1.0, "0", "less", "more"),
        new(BenchmarkKind.CpuSingle, "Processor speed (one core)", "Speed of everyday single-threaded work, like opening a web page", "points", false, 0.05, 0, 1.0, "0"),
        new(BenchmarkKind.CpuMulti, "Processor speed (all cores)", "Speed of heavy work that uses every core", "points", false, 0.05, 0, 1.5, "0"),
        new(BenchmarkKind.DiskLatency, "Disk response time", "How fast the drive answers small reads (opening files, searching)", "ms", true, 0.10, 0.02, 1.5, "0.00"),
        new(BenchmarkKind.DnsLookup, "Website lookup time", "How long it takes to find a website before it starts loading", "ms", true, 0.15, 5, 0.5, "0"),
        new(BenchmarkKind.EnabledStartupApps, "Enabled start-up apps", "Apps and tasks set to launch automatically when you sign in", "apps", true, 0.01, 1, 0.0, "0", "fewer", "more"),
        new(BenchmarkKind.AutoVendorServices, "Automatic background services", "Non-Windows background services set to start automatically", "services", true, 0.01, 1, 0.0, "0", "fewer", "more"),
        new(BenchmarkKind.ActiveScheduledTasks, "Active background tasks", "Non-Windows scheduled tasks enabled to run in the background", "tasks", true, 0.01, 1, 0.0, "0", "fewer", "more"),
        new(BenchmarkKind.InstalledBloatwareApps, "Pre-installed bloatware apps", "Unsupported or unneeded pre-installed apps on the PC", "apps", true, 0.01, 1, 0.0, "0", "fewer", "more"),
    ];

    /// <summary>Read several times over the idle sampling window (they wander from second to second).</summary>
    public static readonly IReadOnlyList<BenchmarkKind> IdleResourceKinds = [BenchmarkKind.MemoryUsedMb, BenchmarkKind.BackgroundProcesses];

    /// <summary>Read once (they only change when something is installed, removed or switched off).</summary>
    public static readonly IReadOnlyList<BenchmarkKind> ResourceSnapshotKinds =
    [
        BenchmarkKind.DiskFreeGb, BenchmarkKind.EnabledStartupApps, BenchmarkKind.AutoVendorServices, BenchmarkKind.ActiveScheduledTasks, BenchmarkKind.InstalledBloatwareApps,
    ];

    public static BenchmarkInfo Info(BenchmarkKind k) => All.First(i => i.Kind == k);
}

/// <summary>Which benchmarks run and how. Saved with the results so before/after use the same settings.</summary>
public sealed record BenchmarkSettings
{
    public IReadOnlyList<BenchmarkKind> Enabled { get; init; } = [.. Enum.GetValues<BenchmarkKind>()];
    /// <summary>Runs per benchmark; the middle value is used.</summary>
    public int Runs { get; init; } = 3;
    /// <summary>Restart the PC before the "after" benchmark (needed to measure start-up time).</summary>
    public bool RestartBeforeAfter { get; init; } = true;
    public TimeSpan IdleSample { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan CpuSingleRun { get; init; } = TimeSpan.FromSeconds(4);
    public TimeSpan CpuMultiRun { get; init; } = TimeSpan.FromSeconds(8);
    public TimeSpan DiskRun { get; init; } = TimeSpan.FromSeconds(12);
    /// <summary>Memory in use and the background-process count are read this many times, <see cref="ResourceSampleInterval"/> apart (median used).</summary>
    public int ResourceSamples { get; init; } = 5;
    public TimeSpan ResourceSampleInterval { get; init; } = TimeSpan.FromSeconds(5);
    /// <summary>After a restart, wait this long before benchmarking so start-up work has settled.</summary>
    public TimeSpan SettleAfterRestart { get; init; } = TimeSpan.FromMinutes(3);

    /// <summary>Time spent between the first and last idle resource sample.</summary>
    public double ResourceSampleSeconds => Math.Max(0, ResourceSamples - 1) * ResourceSampleInterval.TotalSeconds;

    public static readonly int[] RunChoices = [1, 3, 5];
    public bool IsEnabled(BenchmarkKind k) => Enabled.Contains(k);

    /// <summary>Rough length of one pass (seconds), shown before starting.</summary>
    public int EstimatedSeconds()
    {
        double s = 0;
        if (IsEnabled(BenchmarkKind.IdleCpu) || IsEnabled(BenchmarkKind.Paging)) s += IdleSample.TotalSeconds;
        if (Benchmarks.IdleResourceKinds.Any(IsEnabled)) s += ResourceSampleSeconds;
        if (IsEnabled(BenchmarkKind.ProgramStart)) s += Runs * BuiltInPrograms.All.Count * 1.5;
        if (IsEnabled(BenchmarkKind.CpuSingle)) s += Runs * CpuSingleRun.TotalSeconds;
        if (IsEnabled(BenchmarkKind.CpuMulti)) s += Runs * CpuMultiRun.TotalSeconds;
        if (IsEnabled(BenchmarkKind.DiskLatency)) s += Runs * DiskRun.TotalSeconds;
        if (IsEnabled(BenchmarkKind.DnsLookup)) s += Runs * 3;
        return (int)Math.Ceiling(s);
    }
}

/// <summary>A Windows program used for "program start time" (only programs that ship with Windows).</summary>
/// <param name="HasWindow">True: timed until its window is ready for input; false: console program timed until it exits.</param>
public sealed record BuiltInProgram(string Name, string FileName, IReadOnlyList<string> Arguments, bool HasWindow);

public static class BuiltInPrograms
{
    public static readonly IReadOnlyList<BuiltInProgram> All =
    [
        new("Command Prompt", "cmd.exe", ["/c", "exit"], false),
        new("Windows PowerShell", @"WindowsPowerShell\v1.0\powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "exit"], false),
        new("Character Map", "charmap.exe", [], true),
    ];
}

/// <summary>One benchmark's runs. The median is the result; the spread tells how noisy it was.</summary>
public sealed record BenchmarkMeasurement(BenchmarkKind Kind, IReadOnlyList<double> Samples, string? Note = null)
{
    public double? Median
    {
        get
        {
            if (Samples.Count == 0) return null;
            var s = Samples.OrderBy(x => x).ToList();
            return s.Count % 2 == 1 ? s[s.Count / 2] : (s[s.Count / 2 - 1] + s[s.Count / 2]) / 2;
        }
    }

    /// <summary>(max − min) / median; 0 for one run.</summary>
    public double Spread => Samples.Count < 2 || Median is not > 0 ? 0 : (Samples.Max() - Samples.Min()) / Median!.Value;
}

/// <summary>Conditions that change results a lot; compared between before and after.</summary>
public sealed record BenchmarkConditions(bool? OnBattery, double? CpuTemperatureC, string? PowerPlan = null);

public sealed record BenchmarkRun(BenchmarkPhase Phase, DateTimeOffset TimeUtc, BenchmarkConditions Conditions, IReadOnlyList<BenchmarkMeasurement> Measurements, bool Completed = true)
{
    public BenchmarkMeasurement? Get(BenchmarkKind k) => Measurements.FirstOrDefault(m => m.Kind == k);
}

/// <summary>Everything kept between app restarts (so a "before" survives the restart for the "after").</summary>
public sealed record BenchmarkState(BenchmarkSettings Settings, BenchmarkRun? Before = null, BenchmarkRun? After = null, bool RunAfterOnStartup = false)
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    public string ToJson() => JsonSerializer.Serialize(this, Json);
    public static BenchmarkState? FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<BenchmarkState>(json, Json); }
        catch (JsonException) { return null; }
    }
}

public interface IBenchmarkStore
{
    BenchmarkState? Load();
    void Save(BenchmarkState state);
}

/// <summary>JSON file next to the app's other per-user state (%LOCALAPPDATA%\RemotePCDiagnostics).</summary>
public sealed class FileBenchmarkStore(string path, Action<string>? log = null) : IBenchmarkStore
{
    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "benchmarks.json");

    public BenchmarkState? Load()
    {
        try { return File.Exists(path) ? BenchmarkState.FromJson(File.ReadAllText(path)) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log?.Invoke($"Benchmark state read failed: {ex.Message}"); return null; }
    }

    public void Save(BenchmarkState state)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, state.ToJson());
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log?.Invoke($"Benchmark state write failed: {ex.Message}"); }
    }
}

public enum BenchmarkVerdict { Better, Worse, NoChange, NotMeasured }

public sealed record BenchmarkDelta(BenchmarkInfo Info, double? Before, double? After, BenchmarkVerdict Verdict, double? ImprovementPercent, string? Note)
{
    public double? AbsoluteChange => Before is { } b && After is { } a ? (Info.LowerIsBetter ? b - a : a - b) : null;

    public string ChangeSummary => Verdict switch
    {
        BenchmarkVerdict.NotMeasured => "Not compared",
        BenchmarkVerdict.NoChange => "No real change",
        _ when Info.Kind == BenchmarkKind.DiskFreeGb && AbsoluteChange is { } gb =>
            string.Create(CultureInfo.InvariantCulture, $"{(Verdict == BenchmarkVerdict.Better ? "+" : "-")}{Math.Abs(gb):0.0} GB {(Verdict == BenchmarkVerdict.Better ? "freed" : "used")}"),
        _ when Info.Kind == BenchmarkKind.MemoryUsedMb && AbsoluteChange is { } mb =>
            string.Create(CultureInfo.InvariantCulture, $"{Math.Abs(mb):0} MB {(Verdict == BenchmarkVerdict.Better ? "freed" : "more")} ({Math.Abs(ImprovementPercent!.Value):0}% {(Verdict == BenchmarkVerdict.Better ? Info.BetterWord : Info.WorseWord)})"),
        _ when Info.Weight == 0 && AbsoluteChange is { } n =>
            string.Create(CultureInfo.InvariantCulture, $"{Math.Abs(n):0} {(Verdict == BenchmarkVerdict.Better ? Info.BetterWord : Info.WorseWord)}"),
        _ => string.Create(CultureInfo.InvariantCulture, $"{Math.Abs(ImprovementPercent!.Value):0}% {(Verdict == BenchmarkVerdict.Better ? Info.BetterWord : Info.WorseWord)}"),
    };

    /// <summary>Plain-language line for the client, e.g. "Start-up time: 41.2 s → 29.8 s (28% faster)".</summary>
    public string Sentence => Verdict switch
    {
        BenchmarkVerdict.NotMeasured => $"{Info.Title}: not measured{(Note is null ? "" : " (" + Note + ")")}",
        BenchmarkVerdict.NoChange => $"{Info.Title}: {Info.Show(Before!.Value)} → {Info.Show(After!.Value)} (no measurable change)",
        _ => $"{Info.Title}: {Info.Show(Before!.Value)} → {Info.Show(After!.Value)} ({ChangeSummary})",
    };
}

/// <summary>Before/after comparison with noise-aware verdicts and one overall number.</summary>
public sealed record BenchmarkComparison(IReadOnlyList<BenchmarkDelta> Deltas, double? OverallPercent, IReadOnlyList<string> Warnings)
{
    /// <summary>Each metric's ratio is capped so one dramatic number can't carry the overall score.</summary>
    public const double MaxRatio = 2.0, MinRatio = 0.5;

    public string OverallText => OverallPercent switch
    {
        null => "Not enough measurements to compare yet.",
        >= 2 and var p => $"Overall about {p:0}% faster",
        <= -2 and var p => $"Overall about {-p:0}% slower",
        _ => "Overall about the same speed",
    };

    public static BenchmarkComparison Build(BenchmarkRun? before, BenchmarkRun? after)
    {
        var deltas = new List<BenchmarkDelta>();
        double logSum = 0, weightSum = 0;
        foreach (var info in Benchmarks.All)
        {
            var b = before?.Get(info.Kind);
            var a = after?.Get(info.Kind);
            if (b?.Median is not { } bv || a?.Median is not { } av)
            {
                if (b is not null || a is not null)
                    deltas.Add(new(info, b?.Median, a?.Median, BenchmarkVerdict.NotMeasured, null, a?.Note ?? b?.Note ?? (b is null ? "no before result" : "no after result")));
                continue;
            }
            var diff = info.LowerIsBetter ? bv - av : av - bv;           // > 0 means better
            var basis = Math.Max(Math.Abs(bv), 1e-9);
            var rel = diff / basis;
            var noise = Math.Max(info.MinRelativeChange, Math.Max(b.Spread, a.Spread));
            var verdict = Math.Abs(diff) < info.MinAbsoluteChange || Math.Abs(rel) < noise ? BenchmarkVerdict.NoChange
                : diff > 0 ? BenchmarkVerdict.Better : BenchmarkVerdict.Worse;
            // Improvement as "x% faster/less": for lower-is-better, relative to before (time saved).
            double pct = rel * 100;
            deltas.Add(new(info, bv, av, verdict, pct, null));

            var ratio = verdict == BenchmarkVerdict.NoChange ? 1.0
                : info.LowerIsBetter ? (av <= 0 ? MaxRatio : bv / av) : (bv <= 0 ? MaxRatio : av / bv);
            ratio = Math.Clamp(ratio, MinRatio, MaxRatio);
            logSum += info.Weight * Math.Log(ratio);
            weightSum += info.Weight;
        }
        double? overall = weightSum > 0 ? (Math.Exp(logSum / weightSum) - 1) * 100 : null;

        var warnings = new List<string>();
        if (before?.Conditions is { } bc && after?.Conditions is { } ac)
        {
            if (bc.OnBattery is { } bb && ac.OnBattery is { } ab && bb != ab)
                warnings.Add($"The PC was {(bb ? "on battery" : "plugged in")} before and {(ab ? "on battery" : "plugged in")} after; that alone changes results a lot. Run both plugged in for a fair comparison.");
            if (bc.CpuTemperatureC is { } bt && ac.CpuTemperatureC is { } at && Math.Abs(bt - at) >= 10)
                warnings.Add($"The processor was {bt:0}°C before and {at:0}°C after; a hot processor slows itself down.");
            if (bc.PowerPlan is { Length: > 0 } bp && ac.PowerPlan is { Length: > 0 } ap && bp != ap)
                warnings.Add($"Power plan changed from {bp} to {ap} (part of the fixes, or changed meanwhile).");
        }
        if (deltas.Any(d => d.Info.Kind == BenchmarkKind.ProgramStart && d.Verdict == BenchmarkVerdict.Better))
            warnings.Add("If apps were closed as part of the fixes, part of the faster program starts comes from that; reopening them gives some of it back.");
        return new(deltas, overall, warnings);
    }
}
