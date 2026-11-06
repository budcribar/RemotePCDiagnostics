using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Stress;

[JsonConverter(typeof(JsonStringEnumConverter<CpuStressOutcome>))]
public enum CpuStressOutcome { Passed, Overheated, StoppedByUser, ComputationErrors, Throttled }

public sealed record CpuStressOptions
{
    public static readonly TimeSpan[] DurationChoices = new[] { 1, 2, 3, 5, 10 }.Select(m => TimeSpan.FromMinutes(m)).ToArray();
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
    double? CpuTemperatureC, double? FanRpm, double? CpuCriticalC, bool SensorsAvailable)
{
    public double Fraction => Duration <= TimeSpan.Zero ? 1 : Math.Clamp(Elapsed / Duration, 0, 1);
}

public sealed record CpuStressReport(
    CpuStressOutcome Outcome, TimeSpan Ran, TimeSpan Requested, int Threads,
    long ChunksDone, long Errors, double? MaxCpuTemperatureC, double? EarlyThroughput, double? LateThroughput,
    bool SensorsAvailable) : IRunEnd
{
    [System.Text.Json.Serialization.JsonIgnore] public RunEnd RunEnd => Outcome == CpuStressOutcome.StoppedByUser ? RunEnd.Cancelled : RunEnd.Finished;

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
        CpuStressOutcome.ComputationErrors => "Your processor gave wrong answers under load. This can mean overheating, unstable overclocking or a hardware fault.",
        CpuStressOutcome.Throttled => $"Your processor got noticeably slower as the test went on{(ThroughputRatio is { } r ? $" (about {(1 - r) * 100:0}% slower)" : "")}. This usually means it's running hot.",
        _ => "",
    };
}
