using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Stress;

[JsonConverter(typeof(JsonStringEnumConverter<GpuStressOutcome>))]
public enum GpuStressOutcome { Passed, ErrorsFound, DriverReset, NoGpu, SoftwareOnly, StoppedByUser, Overheated, Failed }

public sealed record GpuStressOptions
{
    public static readonly TimeSpan[] DurationChoices = new[] { 1, 2, 5, 10, 15 }.Select(m => TimeSpan.FromMinutes(m)).ToArray();
    public static TimeSpan MaxDuration => DurationChoices[^1];

    public TimeSpan Duration { get; init; } = TimeSpan.FromMinutes(1);
    /// <summary>The adapter to stress (<see cref="GpuAdapterInfo.Id"/>); null = the first hardware adapter.</summary>
    public string? AdapterId { get; init; }
    /// <summary>Aim for dispatches this long: busy enough to load the GPU, far below Windows' 2-second TDR timeout.</summary>
    public TimeSpan TargetDispatch { get; init; } = TimeSpan.FromMilliseconds(150);
    /// <summary>A dispatch slower than this is cut back hard (half) right away.</summary>
    public TimeSpan SlowDispatch { get; init; } = TimeSpan.FromMilliseconds(500);
    public uint StartIterations { get; init; } = 64;
    public uint MaxIterations { get; init; } = 1 << 15;
    /// <summary>Values verified against the CPU reference per dispatch (rotating through the buffer).</summary>
    public int ChecksPerBatch { get; init; } = 512;
    /// <summary>Pause between dispatches (keeps the desktop responsive; also where Stop/temperature are checked).</summary>
    public TimeSpan Gap { get; init; } = TimeSpan.FromMilliseconds(5);
    public TimeSpan SensorInterval { get; init; } = TimeSpan.FromSeconds(1);
}

public sealed record GpuStressProgress(
    TimeSpan Elapsed, TimeSpan Duration, string? AdapterName, long Batches, long ValuesChecked, long Mismatches,
    double? GpuTemperatureC, double? FanRpm, bool SensorsAvailable, double? BillionOpsPerSecond) : StressProgressBase(Elapsed, Duration);

public sealed record GpuStressReport(
    GpuStressOutcome Outcome, TimeSpan Ran, string? AdapterName, long Batches, long ValuesChecked, long Mismatches,
    double? MaxGpuTemperatureC, double? BillionOpsPerSecond) : IStressReport
{
    [JsonIgnore] public RunEnd RunEnd => Outcome == GpuStressOutcome.StoppedByUser ? RunEnd.Cancelled : Outcome == GpuStressOutcome.NoGpu ? RunEnd.CouldNotRun : RunEnd.Finished;
    [JsonIgnore] public DiagnosticStatus Status => Outcome switch
    {
        GpuStressOutcome.Passed => DiagnosticStatus.Ok,
        GpuStressOutcome.StoppedByUser or GpuStressOutcome.NoGpu or GpuStressOutcome.SoftwareOnly => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };
    [JsonIgnore] public bool IsUnavailable => Outcome == GpuStressOutcome.NoGpu;
    [JsonIgnore] public bool IsCouldNotRun => Outcome == GpuStressOutcome.Failed;
    [JsonIgnore] public bool IsOverheated => Outcome == GpuStressOutcome.Overheated;

    public string Headline => Outcome switch
    {
        GpuStressOutcome.Passed => "Passed",
        GpuStressOutcome.ErrorsFound => "Graphics errors found",
        GpuStressOutcome.DriverReset => "Graphics driver stopped responding",
        GpuStressOutcome.NoGpu => "No graphics chip could be tested",
        GpuStressOutcome.SoftwareOnly => "No graphics chip could be tested",
        GpuStressOutcome.StoppedByUser => "Stopped by you",
        GpuStressOutcome.Overheated => "Stopped: PC got too hot",
        _ => "Couldn't finish the test",
    };

    public string Explanation => Outcome switch
    {
        GpuStressOutcome.Passed => "Your graphics chip worked hard for the whole test and every answer it gave was correct.",
        GpuStressOutcome.ErrorsFound => "Your graphics chip gave wrong answers under load. This can cause crashes, glitches or freezes. Try updating the graphics driver; if it keeps happening the hardware may be faulty.",
        GpuStressOutcome.DriverReset => "The screen may have flickered while Windows restarted the graphics driver. This can be caused by an outdated driver, overheating or a hardware problem. Try updating the graphics driver and run the test again.",
        GpuStressOutcome.NoGpu => "Windows didn't make a graphics chip available to this app. If you're connected through Remote Desktop, run the test on the PC itself. Otherwise, try updating the graphics driver.",
        GpuStressOutcome.SoftwareOnly => "Windows is using its basic display driver instead of a real graphics driver, so there is no graphics chip to test. Install or update the graphics driver and try again.",
        GpuStressOutcome.StoppedByUser => "The test was stopped before it finished.",
        GpuStressOutcome.Overheated => "The test stopped early to protect your PC. Make sure the PC has good airflow.",
        _ => "Something went wrong while testing the graphics chip. Please try again.",
    };
}
