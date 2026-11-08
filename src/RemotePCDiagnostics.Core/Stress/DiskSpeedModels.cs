using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Stress;

[JsonConverter(typeof(JsonStringEnumConverter<DiskSpeedOutcome>))]
public enum DiskSpeedOutcome { Passed, SlowDrive, DataErrors, NotEnoughSpace, Overheated, StoppedByUser, Failed }

public enum DiskSpeedPhase { Preparing, SequentialWrite, SequentialRead, RandomWrite, RandomRead, CleaningUp }

public sealed record DiskSpeedOptions
{
    public const long MB = 1024L * 1024, GB = 1024 * MB;
    public static readonly TimeSpan[] DurationChoices = new[] { 1, 2, 5, 10 }.Select(m => TimeSpan.FromMinutes(m)).ToArray();
    public static readonly long[] SizeChoices = [256 * MB, 512 * MB, 1 * GB, 4 * GB];
    public static TimeSpan MaxDuration => DurationChoices[^1];

    /// <summary>Drive root to test; null = system drive.</summary>
    public string? DriveRoot { get; init; }
    public TimeSpan Duration { get; init; } = TimeSpan.FromMinutes(1);
    public long RequestedSizeBytes { get; init; } = 1 * GB;
    public int SequentialBlockBytes { get; init; } = (int)MB;
    public int RandomBlockBytes { get; init; } = 4096;
    public double MaxFreeFraction { get; init; } = 0.10;
    public long MinFreeLeftBytes { get; init; } = 2 * GB;
    public long MinTestBytes { get; init; } = 64 * MB;
    /// <summary>Upper bound for each random phase (the remaining time limit is split between them).</summary>
    public TimeSpan MaxRandomPhase { get; init; } = TimeSpan.FromSeconds(20);
    public TimeSpan SampleInterval { get; init; } = TimeSpan.FromSeconds(1);
    // "Slow drive" heuristics (well below typical hard drives: ~100+ MB/s sequential, ~75+ random IOPS).
    public double SlowSequentialReadMBps { get; init; } = 50;
    public double SlowSequentialWriteMBps { get; init; } = 30;
    public double SlowRandomReadIops { get; init; } = 40;
}

public sealed record DiskSpeedProgress(
    DiskSpeedPhase Phase, TimeSpan Elapsed, TimeSpan Duration, double PhaseFraction,
    double? DriveTemperatureC, double? FanRpm, bool SensorsAvailable) : StressProgressBase(Elapsed, Duration)
{
    public string PhaseText => Phase switch
    {
        DiskSpeedPhase.Preparing => "Getting ready",
        DiskSpeedPhase.SequentialWrite => "Writing large blocks",
        DiskSpeedPhase.SequentialRead => "Reading large blocks",
        DiskSpeedPhase.RandomWrite => "Writing small blocks",
        DiskSpeedPhase.RandomRead => "Reading small blocks",
        _ => "Cleaning up",
    };
}

/// <summary>Speeds are in decimal MB/s (10^6 bytes per second) and IOPS (operations per second).</summary>
public sealed record DiskSpeedReport(
    DiskSpeedOutcome Outcome, string Drive, long TestBytes, TimeSpan Ran,
    double? SequentialWriteMBps, double? SequentialReadMBps, double? RandomWriteIops, double? RandomReadIops,
    long BlocksVerified, long DataErrors, double? MaxDriveTemperatureC, bool CleanedUp) : IStressReport
{
    [JsonIgnore] public RunEnd RunEnd => Outcome == DiskSpeedOutcome.StoppedByUser ? RunEnd.Cancelled : RunEnd.Finished;
    [JsonIgnore] public DiagnosticStatus Status => Outcome switch
    {
        DiskSpeedOutcome.Passed => DiagnosticStatus.Ok,
        DiskSpeedOutcome.SlowDrive or DiskSpeedOutcome.StoppedByUser or DiskSpeedOutcome.NotEnoughSpace => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };
    [JsonIgnore] public bool IsCouldNotRun => Outcome == DiskSpeedOutcome.Failed;
    [JsonIgnore] public bool IsOverheated => Outcome == DiskSpeedOutcome.Overheated;

    public string Headline => Outcome switch
    {
        DiskSpeedOutcome.Passed => "Passed",
        DiskSpeedOutcome.SlowDrive => "Slow drive",
        DiskSpeedOutcome.DataErrors => "Data errors found",
        DiskSpeedOutcome.NotEnoughSpace => "Not enough free space to test",
        DiskSpeedOutcome.Overheated => "Stopped: drive got too hot",
        DiskSpeedOutcome.StoppedByUser => "Stopped by you",
        _ => "Couldn't finish the test",
    };

    public string Explanation => Outcome switch
    {
        DiskSpeedOutcome.Passed => "The drive read and wrote data correctly at normal speed.",
        DiskSpeedOutcome.SlowDrive => "The drive works, but it is slower than expected. This is normal for some older hard drives; otherwise it may be worn out or very full.",
        DiskSpeedOutcome.DataErrors => "Data read back from the drive didn't match what was written. Back up your files and have the drive checked.",
        DiskSpeedOutcome.NotEnoughSpace => "The drive is too full to test safely. Free up some space and try again.",
        DiskSpeedOutcome.Overheated => "The test stopped early to protect your PC. Make sure the PC has good airflow.",
        DiskSpeedOutcome.StoppedByUser => "The test was stopped before it finished.",
        _ => "Something went wrong while testing the drive. Try again, or pick a different drive.",
    };

    public static string Speed(double? mbps) => mbps is { } v ? $"{v:N0} MB/s" : "—";
    public static string Ops(double? iops) => iops is { } v ? $"{v:N0} operations per second" : "—";
}
