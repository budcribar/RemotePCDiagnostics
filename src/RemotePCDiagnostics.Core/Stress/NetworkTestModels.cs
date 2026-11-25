using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Stress;

[JsonConverter(typeof(JsonStringEnumConverter<NetworkTestOutcome>))]
public enum NetworkTestOutcome { Stable, SomeLoss, Unstable, NoInternet, StoppedByUser, Overheated, Failed }

public sealed record NetworkTestOptions
{
    public static readonly TimeSpan[] DurationChoices = new[] { 1, 2, 5, 10 }.Select(m => TimeSpan.FromMinutes(m)).ToArray();
    public static TimeSpan MaxDuration => DurationChoices[^1];

    public TimeSpan Duration { get; init; } = TimeSpan.FromMinutes(1);
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan PingTimeout { get; init; } = TimeSpan.FromSeconds(1);
    /// <summary>Start the speed test after this many seconds of pinging (so the timeline has a calm baseline).</summary>
    public TimeSpan SpeedTestDelay { get; init; } = TimeSpan.FromSeconds(5);
    public bool RunSpeedTest { get; init; } = true;
    /// <summary>Cadence of internet-only latency probes during bufferbloat load phases.</summary>
    public TimeSpan BufferbloatProbeInterval { get; init; } = TimeSpan.FromMilliseconds(200);
    /// <summary>Maximum number of concurrent in-flight bufferbloat latency probes.</summary>
    public int MaxInFlightBufferbloatProbes { get; init; } = 4;
    // Verdict thresholds.
    public double SomeLossPercent { get; init; } = 0.5;
    public double UnstableLossPercent { get; init; } = 5;
    public double UnstableJitterMs { get; init; } = 30;
}

/// <summary>Bufferbloat measurement from internet-only probes during idle, download, and upload phases.</summary>
public sealed record BufferbloatResult(
    string? Grade,
    bool IsPartial,
    string? MeasuredDirection,
    string? UngradedReason,
    double? IdleMedianMs,
    double? DownloadLoadedMedianMs,
    double? UploadLoadedMedianMs,
    double? DownloadAddedMs,
    double? UploadAddedMs,
    int IdleSamples,
    int DownloadSamples,
    int UploadSamples)
{
    public const int MinSamplesPerPhase = 5;

    /// <summary>Existing A/B/C/D/F boundaries at 30 / 60 / 200 / 400 ms added latency.</summary>
    public static string GradeForAddedMs(double addedMs) => addedMs switch
    {
        < 30 => "A",
        < 60 => "B",
        < 200 => "C",
        < 400 => "D",
        _ => "F",
    };

    public static double? Median(IReadOnlyList<double> values)
    {
        if (values.Count == 0) return null;
        var sorted = values.OrderBy(v => v).ToArray();
        var mid = sorted.Length / 2;
        return sorted.Length % 2 == 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2.0;
    }

    public static BufferbloatResult Evaluate(
        IReadOnlyList<double> idleSamples,
        IReadOnlyList<double> downloadSamples,
        IReadOnlyList<double> uploadSamples,
        bool downloadBudgetExhausted = false,
        bool uploadBudgetExhausted = false)
    {
        var idleMedian = idleSamples.Count >= MinSamplesPerPhase ? Median(idleSamples) : null;
        var dlMedian = downloadSamples.Count >= MinSamplesPerPhase ? Median(downloadSamples) : null;
        var ulMedian = uploadSamples.Count >= MinSamplesPerPhase ? Median(uploadSamples) : null;

        var dlAdded = idleMedian is { } im && dlMedian is { } dm ? Math.Max(0, dm - im) : (double?)null;
        var ulAdded = idleMedian is { } im2 && ulMedian is { } um ? Math.Max(0, um - im2) : (double?)null;

        if (idleMedian is null)
        {
            return new BufferbloatResult(
                Grade: null,
                IsPartial: false,
                MeasuredDirection: null,
                UngradedReason: "Not enough idle baseline latency samples (ICMP may be blocked).",
                IdleMedianMs: null,
                DownloadLoadedMedianMs: dlMedian,
                UploadLoadedMedianMs: ulMedian,
                DownloadAddedMs: null,
                UploadAddedMs: null,
                IdleSamples: idleSamples.Count,
                DownloadSamples: downloadSamples.Count,
                UploadSamples: uploadSamples.Count);
        }

        if (dlAdded is not null && ulAdded is not null)
        {
            return new BufferbloatResult(
                Grade: GradeForAddedMs(Math.Max(dlAdded.Value, ulAdded.Value)),
                IsPartial: false,
                MeasuredDirection: "Download & Upload",
                UngradedReason: null,
                IdleMedianMs: idleMedian,
                DownloadLoadedMedianMs: dlMedian,
                UploadLoadedMedianMs: ulMedian,
                DownloadAddedMs: dlAdded,
                UploadAddedMs: ulAdded,
                IdleSamples: idleSamples.Count,
                DownloadSamples: downloadSamples.Count,
                UploadSamples: uploadSamples.Count);
        }

        if (dlAdded is not null)
        {
            return new BufferbloatResult(
                Grade: GradeForAddedMs(dlAdded.Value),
                IsPartial: true,
                MeasuredDirection: "Download",
                UngradedReason: uploadBudgetExhausted
                    ? "Upload byte budget was reached before enough loaded probes completed."
                    : "Not enough qualified loaded probes completed during upload.",
                IdleMedianMs: idleMedian,
                DownloadLoadedMedianMs: dlMedian,
                UploadLoadedMedianMs: ulMedian,
                DownloadAddedMs: dlAdded,
                UploadAddedMs: null,
                IdleSamples: idleSamples.Count,
                DownloadSamples: downloadSamples.Count,
                UploadSamples: uploadSamples.Count);
        }

        if (ulAdded is not null)
        {
            return new BufferbloatResult(
                Grade: GradeForAddedMs(ulAdded.Value),
                IsPartial: true,
                MeasuredDirection: "Upload",
                UngradedReason: downloadBudgetExhausted
                    ? "Download byte budget was reached before enough loaded probes completed."
                    : "Not enough qualified loaded probes completed during download.",
                IdleMedianMs: idleMedian,
                DownloadLoadedMedianMs: dlMedian,
                UploadLoadedMedianMs: ulMedian,
                DownloadAddedMs: null,
                UploadAddedMs: ulAdded,
                IdleSamples: idleSamples.Count,
                DownloadSamples: downloadSamples.Count,
                UploadSamples: uploadSamples.Count);
        }

        return new BufferbloatResult(
            Grade: null,
            IsPartial: false,
            MeasuredDirection: null,
            UngradedReason: downloadBudgetExhausted || uploadBudgetExhausted
                ? "Transfer byte budget was reached before enough loaded probes completed."
                : "Not enough qualified loaded latency probes completed during transfer.",
            IdleMedianMs: idleMedian,
            DownloadLoadedMedianMs: dlMedian,
            UploadLoadedMedianMs: ulMedian,
            DownloadAddedMs: null,
            UploadAddedMs: null,
            IdleSamples: idleSamples.Count,
            DownloadSamples: downloadSamples.Count,
            UploadSamples: uploadSamples.Count);
    }

    public string HeadlineText => Grade is null
        ? "Not graded"
        : IsPartial ? $"Grade {Grade} (partial — {MeasuredDirection})" : $"Grade {Grade}";
}

/// <summary>One interval on the timeline. Null latency = no reply (lost).</summary>
public sealed record NetworkSample(TimeSpan At, double? GatewayMs, double? InternetMs, bool GatewayTried)
{
    public bool InternetLost => InternetMs is null;
    public bool GatewayLost => GatewayTried && GatewayMs is null;
}

public sealed record PingStats(int Sent, int Received, double? AverageMs, double? JitterMs, double? WorstMs)
{
    public double? LossPercent => Sent == 0 ? null : 100.0 * (Sent - Received) / Sent;

    public static PingStats From(IEnumerable<double?> replies)
    {
        var all = replies.ToList();
        var ok = all.Where(v => v.HasValue).Select(v => v!.Value).ToList();
        double? jitter = ok.Count < 2 ? null : ok.Zip(ok.Skip(1), (a, b) => Math.Abs(b - a)).Average();
        return new PingStats(all.Count, ok.Count, ok.Count == 0 ? null : ok.Average(), jitter, ok.Count == 0 ? null : ok.Max());
    }
}

public sealed record NetworkTestProgress(
    TimeSpan Elapsed, TimeSpan Duration, string Step, IReadOnlyList<NetworkSample> Samples,
    double? CpuTemperatureC, double? FanRpm, bool SensorsAvailable) : StressProgressBase(Elapsed, Duration);

public sealed record NetworkTestReport(
    NetworkTestOutcome Outcome, TimeSpan Ran, bool HasGateway, PingStats Gateway, PingStats Internet,
    double? DownloadMbps, double? UploadMbps, long? NewAdapterErrors, long? NewAdapterDrops,
    IReadOnlyList<NetworkSample> Samples, double? MaxCpuTemperatureC,
    BufferbloatResult? Bufferbloat = null, string? WifiLinkRateText = null) : IStressReport
{
    [JsonIgnore] public RunEnd RunEnd => Outcome == NetworkTestOutcome.StoppedByUser ? RunEnd.Cancelled : RunEnd.Finished;
    [JsonIgnore] public DiagnosticStatus Status => Outcome switch
    {
        NetworkTestOutcome.Stable => DiagnosticStatus.Ok,
        NetworkTestOutcome.SomeLoss or NetworkTestOutcome.StoppedByUser => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };
    [JsonIgnore] public bool IsCouldNotRun => Outcome == NetworkTestOutcome.Failed;
    [JsonIgnore] public bool IsOverheated => Outcome == NetworkTestOutcome.Overheated;

    public string Headline => Outcome switch
    {
        NetworkTestOutcome.Stable => "Stable",
        NetworkTestOutcome.SomeLoss => "Some packet loss",
        NetworkTestOutcome.Unstable => "Unstable connection",
        NetworkTestOutcome.NoInternet => "No internet connection",
        NetworkTestOutcome.StoppedByUser => "Stopped by you",
        NetworkTestOutcome.Overheated => "Stopped: PC got too hot",
        _ => "Couldn't finish the test",
    };

    public string Explanation => Outcome is NetworkTestOutcome.Stable or NetworkTestOutcome.SomeLoss or NetworkTestOutcome.Unstable && Internet.Sent > 0 && Internet.Received == 0
        ? "Your PC can reach the internet, but this network blocks the checks used to measure how steady the connection is, so only speed and adapter errors were measured."
        : Outcome switch
    {
        NetworkTestOutcome.Stable => "Your connection stayed steady for the whole test.",
        NetworkTestOutcome.SomeLoss => "A few messages didn't make it through. You may notice brief hiccups in video calls or games.",
        NetworkTestOutcome.Unstable => "Your connection dropped out or slowed down a lot during the test. Try moving closer to the router, using a cable, or restarting the router.",
        NetworkTestOutcome.NoInternet => HasGateway && Gateway.Received > 0
            ? "Your PC can reach the router, but not the internet. Try restarting the router, or contact your internet provider."
            : "Your PC isn't connected to a network. Check Wi-Fi or the network cable.",
        NetworkTestOutcome.StoppedByUser => "The test was stopped before it finished.",
        NetworkTestOutcome.Overheated => "The test stopped early to protect your PC. Make sure the PC has good airflow.",
        _ => "Something went wrong while testing the connection. Please try again.",
    };

    public static string Ms(double? v) => v is { } x ? $"{x:0} ms" : "—";
    public static string Pct(double? v) => v is { } x ? (x == 0 ? "None" : $"{x:0.#}%") : "—";
    public static string Speed(double? mbps) => mbps is { } x ? $"{x:0.#} Mbps" : "—";
}
