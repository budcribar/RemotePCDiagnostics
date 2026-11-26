using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Stress;

[JsonConverter(typeof(JsonStringEnumConverter<CpuStressOutcome>))]
public enum CpuStressOutcome { Passed, Overheated, StoppedByUser, ComputationErrors, Throttled }

public sealed record CpuStressOptions
{
    public static readonly ImmutableArray<TimeSpan> DurationChoices = [.. new[] { 1, 2, 3, 5, 10 }.Select(m => TimeSpan.FromMinutes(m))];
    public static TimeSpan MaxDuration => DurationChoices[^1];

    public TimeSpan Duration { get; init; } = TimeSpan.FromMinutes(1);
    public int Threads { get; init; } = Environment.ProcessorCount;
    /// <summary>Iterations per work chunk; each chunk's checksum is verified.</summary>
    public int ChunkIterations { get; init; } = 200_000;
    /// <summary>How often temperature, progress and throughput are sampled.</summary>
    public TimeSpan SampleInterval { get; init; } = TimeSpan.FromSeconds(1);
    /// <summary>Late throughput below this fraction of early throughput counts as slowing down.</summary>
    public double ThrottleRatio { get; init; } = 0.85;
    /// <summary>Distinct seeds (with precomputed expected checksums) cycled by each worker.</summary>
    public int SeedCount { get; init; } = 16;
}

/// <summary>Live progress pushed while the test runs.</summary>
public sealed record CpuStressProgress(
    TimeSpan Elapsed, TimeSpan Duration, long ChunksDone, long Errors,
    double? CpuTemperatureC, double? FanRpm, double? CpuCriticalC, bool SensorsAvailable) : StressProgressBase(Elapsed, Duration);

public sealed record CpuStressReport(
    CpuStressOutcome Outcome, TimeSpan Ran, TimeSpan Requested, int Threads,
    long ChunksDone, long Errors, double? MaxCpuTemperatureC, double? EarlyThroughput, double? LateThroughput,
    bool SensorsAvailable, IReadOnlyList<CpuProcessorResult>? Processors = null) : IStressReport
{
    /// <summary>A pinned processor counts as slow below this fraction of the median work of its own kind of core.</summary>
    public const double SlowRatio = 0.7;
    /// <summary>Fewer chunks than this per processor (median) is too short a run to call any processor slow.</summary>
    public const long MinChunksForSlow = 50;

    [JsonIgnore] public RunEnd RunEnd => Outcome == CpuStressOutcome.StoppedByUser ? RunEnd.Cancelled : RunEnd.Finished;
    [JsonIgnore] public DiagnosticStatus Status => CpuStressModule.ToStatus(Outcome);
    [JsonIgnore] public bool IsOverheated => Outcome == CpuStressOutcome.Overheated;

    /// <summary>Late vs early throughput, e.g. 0.8 = 20% slower at the end.</summary>
    public double? ThroughputRatio => EarlyThroughput is > 0 && LateThroughput is { } l ? l / EarlyThroughput : null;

    public string Headline => Outcome switch
    {
        CpuStressOutcome.Passed => "Passed",
        CpuStressOutcome.Overheated => "Stopped: CPU got too hot",
        CpuStressOutcome.StoppedByUser => "Stopped by you",
        CpuStressOutcome.ComputationErrors => "Possible CPU errors found",
        CpuStressOutcome.Throttled => "Slowed down under load",
        _ => Outcome.ToString(),
    };

    public string Explanation => Outcome switch
    {
        CpuStressOutcome.Passed => "Your processor ran at full load without mistakes or slowing down.",
        CpuStressOutcome.Overheated => "The test stopped early to protect your PC. Check that the fans are spinning and the vents aren't blocked.",
        CpuStressOutcome.StoppedByUser => "The test was stopped before it finished.",
        CpuStressOutcome.ComputationErrors => "Your processor gave wrong answers under load. This can mean overheating, unstable overclocking or a hardware fault." + (FaultyNote is { } f ? " " + f : ""),
        CpuStressOutcome.Throttled => $"Your processor got noticeably slower as the test went on{(ThroughputRatio is { } r ? $" (about {(1 - r) * 100:0}% slower)" : "")}. This usually means it's running hot.",
        _ => "",
    };

    /// <summary>Where the wrong answers came from, when the threads were pinned: one core points to that core, many cores to heat,
    /// power or overclocking. Null without pinned results or without errors.</summary>
    public string? FaultyNote
    {
        get
        {
            var bad = Processors?.Where(p => p.Errors > 0).ToList();
            if (bad is not { Count: > 0 }) return null;
            var cores = bad.Select(p => p.Core).Distinct().Count();
            if (cores == 1) return $"All of them came from {Describe(bad[0])}, which points to that core.";
            if (cores <= 3) return $"They came from {Join(bad.Select(Describe).ToList())}.";
            return $"They came from {cores} different cores, which points to heat, power or overclocking rather than one bad core.";
        }
    }

    /// <summary>Processors that did far less work than the others of their kind (pinned runs only). Informational: never fails the test.</summary>
    public IReadOnlyList<CpuProcessorResult> SlowProcessors() => FindSlow(Processors);

    /// <summary>One line for the result card naming the slow processors, or null.</summary>
    public string? SlowNote
    {
        get
        {
            var slow = SlowProcessors();
            if (slow.Count == 0) return null;
            var names = slow.Count <= 3 ? Join(slow.Select(Describe).ToList()) : $"{slow.Count} processor threads";
            return $"{char.ToUpperInvariant(names[0])}{names[1..]} did much less work than similar cores";
        }
    }

    public static IReadOnlyList<CpuProcessorResult> FindSlow(IReadOnlyList<CpuProcessorResult>? processors)
    {
        if (processors is not { Count: > 1 }) return [];
        var slow = new List<CpuProcessorResult>();
        foreach (var kind in processors.GroupBy(p => p.EfficiencyClass))
        {
            var sorted = kind.Select(p => p.Chunks).Order().ToList();
            if (sorted.Count < 2) continue;
            var median = sorted.Count % 2 == 1 ? sorted[sorted.Count / 2] : (sorted[sorted.Count / 2 - 1] + sorted[sorted.Count / 2]) / 2.0;
            if (median < MinChunksForSlow) continue;
            slow.AddRange(kind.Where(p => p.Chunks < median * SlowRatio));
        }
        return slow.OrderBy(p => p.Cpu).ToList();
    }

    /// <summary>"CPU 5 (core 3)", with ", an efficiency core" on a hybrid CPU.</summary>
    private string Describe(CpuProcessorResult p)
    {
        var hybrid = Processors is { } all && all.Select(x => x.EfficiencyClass).Distinct().Count() > 1;
        var efficiency = hybrid && p.EfficiencyClass == Processors!.Min(x => x.EfficiencyClass);
        return $"CPU {p.Cpu} (core {p.Core}{(efficiency ? ", an efficiency core" : "")})";
    }

    private static string Join(IReadOnlyList<string> items) =>
        items.Count == 1 ? items[0] : string.Join(", ", items.Take(items.Count - 1)) + " and " + items[^1];
}

/// <summary>Work and errors of one pinned stress thread: <paramref name="Cpu"/> is the logical processor as Task Manager numbers it,
/// <paramref name="Core"/> its physical core, <paramref name="EfficiencyClass"/> 0 for efficiency cores on a hybrid CPU.</summary>
public sealed record CpuProcessorResult(int Cpu, int Core, byte EfficiencyClass, long Chunks, long Errors);
