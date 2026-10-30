using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Stress;

[JsonConverter(typeof(JsonStringEnumConverter<MemoryTestOutcome>))]
public enum MemoryTestOutcome { Passed, MemoryErrors, StoppedByUser, Overheated, Failed }

public sealed record MemoryTestOptions
{
    public static readonly TimeSpan[] DurationChoices = new[] { 1, 2, 5, 10, 20, 30 }.Select(m => TimeSpan.FromMinutes(m)).ToArray();
    public static TimeSpan MaxDuration => DurationChoices[^1];
    public static TimeSpan DefaultDuration(MemoryTestMode m) => m == MemoryTestMode.Quick ? TimeSpan.FromMinutes(2) : TimeSpan.FromMinutes(10);

    public MemoryTestMode Mode { get; init; } = MemoryTestMode.Quick;
    public TimeSpan Duration { get; init; } = TimeSpan.FromMinutes(2);
    public TimeSpan SampleInterval { get; init; } = TimeSpan.FromSeconds(1);
    /// <summary>Extra time the helper gets past the limit (allocation, finishing a block) before it is killed.</summary>
    public TimeSpan Grace { get; init; } = TimeSpan.FromSeconds(60);
}

public sealed record MemoryTestProgress(
    TimeSpan Elapsed, TimeSpan Duration, long TestBytes, int Pass, double PassFraction, long Errors,
    double? CpuTemperatureC, double? FanRpm, bool SensorsAvailable)
{
    public double Fraction => Duration <= TimeSpan.Zero ? 1 : Math.Clamp(Elapsed / Duration, 0, 1);
}

public sealed record MemoryTestReport(
    MemoryTestOutcome Outcome, MemoryTestMode Mode, long TestBytes, int Passes, long Errors, TimeSpan Ran, double? MaxCpuTemperatureC)
{
    public string Headline => Outcome switch
    {
        MemoryTestOutcome.Passed => "Passed",
        MemoryTestOutcome.MemoryErrors => "Memory errors found",
        MemoryTestOutcome.StoppedByUser => "Stopped by you",
        MemoryTestOutcome.Overheated => "Stopped: too hot",
        _ => "Couldn't finish the test",
    };

    public string Explanation => Outcome switch
    {
        MemoryTestOutcome.Passed => "No problems were found in the memory that was tested.",
        MemoryTestOutcome.MemoryErrors => $"{(Errors == 1 ? "One spot" : $"{Errors:N0} spots")} in memory didn't keep the data written to it. Faulty memory can cause crashes and lost work; consider having the memory checked or replaced.",
        MemoryTestOutcome.StoppedByUser => "The test was stopped before it finished.",
        MemoryTestOutcome.Overheated => "The test stopped early to protect your PC. Make sure the PC has good airflow.",
        _ => "The memory test couldn't run to the end. Close some programs and try again, or use the Quick test.",
    };
}
