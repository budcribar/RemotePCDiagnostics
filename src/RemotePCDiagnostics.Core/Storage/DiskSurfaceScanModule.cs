using System.Globalization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>One <c>disk_read_scan</c> request: the verb, the disk, and for start the mode and the time limit.</summary>
public sealed record DiskScanRequest(string Verb, int Disk, DiskScanMode Mode = DiskScanMode.Quick, int TimeLimitMinutes = 0)
{
    public IReadOnlyList<string> Args() => Verb == DiskReadScanAction.Start
        ? [Verb, Disk.ToString(CultureInfo.InvariantCulture), DiskReadScanAction.ModeArg(Mode), TimeLimitMinutes.ToString(CultureInfo.InvariantCulture)]
        : [Verb, Disk.ToString(CultureInfo.InvariantCulture)];

    public string Key => string.Join(' ', Args());
}

/// <param name="NeedsAgent">No Agent (or one too old to know the scan): the check is Skipped, not failed.</param>
public sealed record DiskScanAnswer(DiskScanStatus? Status, string? Error = null, bool NeedsAgent = false)
{
    public static DiskScanAnswer Of(DiskScanStatus status) => new(status);
}

/// <summary>Where the app's surface scan check sends its requests: the Agent on the PC, a recording in tests.</summary>
public interface IDiskScanSource
{
    Task<DiskScanAnswer> SendAsync(DiskScanRequest request, CancellationToken ct);
}

/// <summary>The Agent's <see cref="AgentScripts.DiskReadScan"/> over the admin pipe. The app itself never opens a raw disk.</summary>
public sealed class AgentDiskScanSource(SystemCommandRunner commands) : IDiskScanSource
{
    public static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(30);
    public const string TooOldText = "The Agent on this PC is too old for the surface scan. Update RPCD, then run it again.";

    public async Task<DiskScanAnswer> SendAsync(DiskScanRequest request, CancellationToken ct)
    {
        var pr = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.DiskReadScan, [.. request.Args()]), CallTimeout, ct).ConfigureAwait(false);
        return Read(pr);
    }

    /// <summary>The answer in <paramref name="pr"/>: a status, the Agent missing (or too old), or why it failed.</summary>
    public static DiskScanAnswer Read(ProcessResult? pr)
    {
        if (pr is null) return new(null, "The Agent didn't answer in time.");
        if (SystemCommandRunner.AgentFailure(pr) is { } missing)
            return missing.StartsWith("Unknown script", StringComparison.Ordinal) ? new(null, TooOldText, NeedsAgent: true) : new(null, missing, NeedsAgent: true);
        if (pr.ExitCode != 0)
        {
            var why = pr.StdErr.Trim();
            return why.StartsWith("Unknown script", StringComparison.Ordinal) ? new(null, TooOldText, NeedsAgent: true)
                : new(null, why.Length > 0 ? why : $"The Agent's scan failed (exit code {pr.ExitCode}).");
        }
        return DiskScanStatus.Parse(pr.StdOut) is { } status ? DiskScanAnswer.Of(status) : new(null, "The Agent's answer wasn't a scan status.");
    }
}

/// <summary>
/// Disk surface read scan: reads the raw surface of each physical disk through the Agent (it needs administrator) and reports unreadable
/// and slow blocks, a surface map, and the first bad LBAs with their partition. Read-only, never part of Run all, cancellable. One run per
/// disk, keyed like Drive health so History lines the two up.
/// </summary>
public sealed class DiskSurfaceScanModule(IWmiSource wmi, IDiskScanSource scans, ILogger? log = null, TimeSpan? pollEvery = null)
    : AreaModuleBase(log), IPerDeviceModule, IInstanceSummary, ICancellableScan
{
    public const string ModuleName = ModuleSlugs.DiskSurfaceScan;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DiskSurfaceScan;
    public override string DisplayName => "Disk surface scan";
    protected override string FailedMessage => "Couldn't scan the disk surface on this PC.";
    public bool IncludeInRunAll => false;

    /// <summary>Card row keys the page and Admin read.</summary>
    public const string MapRowKey = "surface-map", AllDisksKey = "all";
    public const string NeedsAgentSummary = "Needs the Agent";
    public static readonly TimeSpan PollEvery = TimeSpan.FromSeconds(1);
    /// <summary>Status calls that may fail in a row (a busy pipe) before the run gives up.</summary>
    public const int MaxPollFailures = 5;

    /// <summary>The next run's mode (the page sets it; Quick otherwise, which is what Admin's run_check gets).</summary>
    public DiskScanMode Mode { get; set; } = DiskScanMode.Quick;
    /// <summary>Full mode only: stop after this many minutes, 0 for no limit.</summary>
    public int TimeLimitMinutes { get; set; }
    public static readonly IReadOnlyList<int> TimeLimitChoices = [0, 15, 30, 60, 120, 240];

    /// <summary>A disk the scan can read: its number for the Agent, its drive facts, and its instance.</summary>
    public sealed record ScanDisk(int? Number, DriveHealth Drive, ModuleInstance Instance);

    private readonly object _cancelGate = new();
    private CancellationTokenSource? _scan;

    public void Cancel()
    {
        lock (_cancelGate) _scan?.Cancel();
    }

    public async Task<IReadOnlyList<ScanDisk>?> ReadDisksAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(DriveReader.StorageNamespace, DriveReader.DiskSql, ct).ConfigureAwait(false);
        if (q.Rows is null) return null;
        var drives = q.Rows.Select(r => (Number: int.TryParse(r.Str("DeviceId"), NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n <= DiskReadScanAction.MaxDisk ? n : (int?)null,
            Drive: new DriveHealth(r.Str("FriendlyName"), r.Str("SerialNumber"), DriveReader.MediaType(r.Long("MediaType")), DriveReader.BusType(r.Long("BusType")),
                "", "", r.Long("Size") is > 0 and var size ? size : null, null, null, null, null, null, UniqueId: r.Str("UniqueId"),
                SpindleSpeedRpm: r.Long("SpindleSpeed") is > 0 and <= int.MaxValue and var rpm ? (int)rpm : null))).ToList();
        var instances = DriveHealthModule.Instances(drives.Select(d => d.Drive).ToList());
        return drives.Select((d, i) => new ScanDisk(d.Number, d.Drive, d.Number is null
            ? instances[i].Instance with { NotApplicableReason = "Windows gives this drive no disk number to read." }
            : instances[i].Instance with { Details = $"Disk {d.Number}" })).OrderBy(d => d.Number ?? int.MaxValue).ToList();
    }

    public async Task<ModuleDetection> DetectAsync(CancellationToken ct = default)
    {
        IReadOnlyList<ScanDisk>? disks;
        try { disks = await ReadDisksAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            LogWarn($"{Name}: disk list failed: {ex.Message}");
            disks = null;
        }
        if (disks is null) return ModuleDetection.For([new ModuleInstance(AllDisksKey, "All disks")]);
        return disks.Count == 0 ? ModuleDetection.NotApplicable("No disks found") : ModuleDetection.For(disks.Select(d => d.Instance));
    }

    public async Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken ct = default)
    {
        if (instance.Key == AllDisksKey) return await RefreshAsync(progress, ct).ConfigureAwait(false);
        AreaReport report;
        try
        {
            var disks = await ReadDisksAsync(ct).ConfigureAwait(false);
            if (disks is null) report = AreaReport.Failed("Couldn't list this PC's disks.");
            else if (disks.FirstOrDefault(d => d.Instance.Key == instance.Key) is not { } disk) return CouldNotRun.Result(Name, $"{instance.Label} is no longer connected.");
            else report = await ScanAsync(disk, 0, progress, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            LogError($"{Name}: scan failed: {ex}");
            report = AreaReport.Failed(FailedMessage);
        }
        var card = report.Cards.FirstOrDefault();
        return new DiagnosticResult<AreaReport>(Name, report.Status, card?.Headline ?? report.Summary, DateTimeOffset.Now, report) { Cancelled = report.Cancelled };
    }

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var disks = await ReadDisksAsync(ct).ConfigureAwait(false);
        if (disks is null) return AreaReport.Failed("Couldn't list this PC's disks.");
        var reports = new List<AreaReport>();
        foreach (var (disk, i) in disks.Where(d => d.Instance.Applies).Select((d, i) => (d, i)))
        {
            var r = await ScanAsync(disk, i, progress, ct).ConfigureAwait(false);
            reports.Add(r);
            if (r.Cancelled || r.NotOnThisPc) break;
        }
        return Merge(reports) ?? AreaReport.Failed("No disk could be scanned.");
    }

    public object? Combine(IReadOnlyList<DiagnosticResult> instanceResults) =>
        Merge(instanceResults.Select(r => r.Payload).OfType<AreaReport>().ToList());

    /// <summary>One report with every disk's card (ids made unique in order).</summary>
    public static AreaReport? Merge(IReadOnlyList<AreaReport> reports)
    {
        if (reports.Count == 0) return null;
        if (reports.Count == 1) return reports[0];
        var cards = reports.SelectMany(r => r.Cards).Select((c, i) => c with { Id = $"{c.Id}-{i}" }).ToList();
        var status = reports.Select(r => r.Status).Max();
        var bad = reports.Count(r => r.Status == DiagnosticStatus.Error);
        var summary = bad > 0 ? $"{Plural(bad, "disk")} with problems" : reports.All(r => r.NotOnThisPc) ? NeedsAgentSummary
            : status == DiagnosticStatus.Warning ? "Some disks have slow or weak spots" : "Every disk read cleanly";
        return new AreaReport(cards, summary, status, Cancelled: reports.Any(r => r.Cancelled))
        {
            NotOnThisPc = reports.All(r => r.NotOnThisPc),
            CouldNotRunReason = reports.All(r => r.CouldNotRunReason is not null) ? reports[0].CouldNotRunReason : null,
        };
    }

    private async Task<AreaReport> ScanAsync(ScanDisk disk, int index, IProgress<string>? progress, CancellationToken ct)
    {
        if (disk.Number is not { } number) return CouldNotRunReport(disk, disk.Instance.NotApplicableReason ?? "No disk number.");
        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_cancelGate) _scan = scan;
        try
        {
            progress.ReportStep(0, 1000, $"Starting the surface scan of disk {number}…");
            var limit = Mode == DiskScanMode.Full ? Math.Clamp(TimeLimitMinutes, 0, DiskReadScanAction.MaxTimeLimitMinutes) : 0;
            var answer = await scans.SendAsync(new(DiskReadScanAction.Start, number, Mode, limit), scan.Token).ConfigureAwait(false);
            if (answer.NeedsAgent) return NeedsAgentReport(disk, answer.Error);
            if (answer.Status is not { } status) return CouldNotRunReport(disk, answer.Error ?? "The scan didn't start.");

            var failures = 0;
            while (status.IsRunning)
            {
                Report(progress, number, status);
                try { await Task.Delay(pollEvery ?? PollEvery, scan.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                answer = await scans.SendAsync(new(DiskReadScanAction.Status, number), CancellationToken.None).ConfigureAwait(false);
                if (answer.Status is { } next) { status = next; failures = 0; }
                else if (++failures >= MaxPollFailures) return CouldNotRunReport(disk, answer.Error ?? "The Agent stopped answering about the scan.");
            }
            if (status.IsRunning)
            {
                // Stopped from the page, the Checks screen or the caller: the Agent stops between blocks and answers with what was read.
                var stopped = await scans.SendAsync(new(DiskReadScanAction.Stop, number), CancellationToken.None).ConfigureAwait(false);
                status = stopped.Status ?? status with { State = DiskScanStatus.Stopped };
                if (status.IsRunning) status = status with { State = DiskScanStatus.Stopped };
            }
            Report(progress, number, status);
            Log($"{Name}: disk {number} {status.State}: {status.Read}/{status.Planned} blocks, {status.Unreadable} unreadable, {status.Retried} retried, {status.Slow} slow");
            return BuildReport(status, disk.Drive.Label, $"disk{number}");
        }
        finally
        {
            lock (_cancelGate) if (ReferenceEquals(_scan, scan)) _scan = null;
        }
    }

    private static void Report(IProgress<string>? progress, int disk, DiskScanStatus s) =>
        progress.ReportStep((int)(s.Fraction * 1000), 1000,
            $"Reading disk {disk}: {s.Read:N0} of {s.Planned:N0} blocks · {s.Unreadable:N0} unreadable · {s.Slow:N0} slow" + (s.Throttle is { } t && s.IsRunning ? $" · {t}" : ""));

    public static AreaReport NeedsAgentReport(ScanDisk disk, string? why)
    {
        var text = why is { Length: > 0 } && why.Contains("too old", StringComparison.Ordinal) ? why
            : "The surface scan reads the raw disk, which needs administrator rights. " + ElevationService.AdminRepairHint;
        var card = new AreaCard($"disk{disk.Number}", disk.Drive.Label, AreaLevel.Neutral, NeedsAgentSummary, "Skipped", ["Reading", "Value"],
            [new(AreaLevel.Neutral, ["Why", text])]);
        return new AreaReport([card], NeedsAgentSummary, DiagnosticStatus.Warning) { NotOnThisPc = true };
    }

    public static AreaReport CouldNotRunReport(ScanDisk disk, string why)
    {
        var card = new AreaCard($"disk{disk.Number}", disk.Drive.Label, AreaLevel.Neutral, CouldNotRun.OutcomeText, "", ["Reading", "Value"],
            [new(AreaLevel.Neutral, ["Why", why])]);
        return new AreaReport([card], why, DiagnosticStatus.Error) { CouldNotRunReason = why };
    }

    /// <summary>Slow blocks over this share of the blocks read make a warning.</summary>
    public const double SlowWarnFraction = 0.001;

    /// <summary>Failed on any unreadable block; Warning on slow blocks over 0.1 % of those read, or a read that needed a second try.</summary>
    public static AreaLevel Verdict(DiskScanStatus s) =>
        s.Unreadable > 0 ? AreaLevel.Error
        : s.Retried > 0 || (s.Read > 0 && s.Slow > s.Read * SlowWarnFraction) ? AreaLevel.Warning
        : AreaLevel.Ok;

    /// <summary>The report for one disk's scan, from the Agent's status alone.</summary>
    public static AreaReport BuildReport(DiskScanStatus s, string label, string cardId)
    {
        var level = Verdict(s);
        var failedEarly = s.State == DiskScanStatus.Failed && level != AreaLevel.Error;
        var headline = level switch
        {
            AreaLevel.Error => $"{Plural((int)Math.Min(s.Unreadable, int.MaxValue), "unreadable block")}",
            AreaLevel.Warning when s.Retried > 0 => $"{Plural((int)Math.Min(s.Retried, int.MaxValue), "block")} read only on the second try",
            AreaLevel.Warning => $"{Plural((int)Math.Min(s.Slow, int.MaxValue), "slow block")} (over {s.SlowMs} ms)",
            _ => "No unreadable or slow blocks",
        };
        var partial = s.State switch
        {
            DiskScanStatus.TimeLimit => $" · time limit reached at {s.Fraction:P0}",
            DiskScanStatus.Stopped => $" · stopped at {s.Fraction:P0}",
            DiskScanStatus.Failed => $" · ended at {s.Fraction:P0}",
            _ => "",
        };
        var mode = s.Mode == "full" ? "Full scan" : "Quick scan";
        var meta = $"{mode} · {s.Read:N0} of {s.Planned:N0} blocks · {Duration(s.ElapsedSeconds)}";

        var slowShare = s.Read > 0 ? (double)s.Slow / s.Read : 0;
        var rows = new List<AreaRow>
        {
            new(AreaLevel.Neutral, ["Mode", mode + (s.Mode == "full" ? ": every block in order" : ": first, middle and last sectors, and blocks spread over the whole disk")]),
            new(AreaLevel.Neutral, ["Disk size", HardwareInventory.FormatBytes(s.SizeBytes) + $" ({s.SectorBytes:N0}-byte sectors" + (s.Media.Length > 0 ? ", " + s.Media : "") + ")"]),
            new(AreaLevel.Neutral, ["Blocks read", $"{s.Read:N0} of {s.Planned:N0}" + partial]),
            new(s.Unreadable > 0 ? AreaLevel.Error : AreaLevel.Ok, ["Unreadable blocks", $"{s.Unreadable:N0}"]),
            new(s.Retried > 0 ? AreaLevel.Warning : AreaLevel.Ok, ["Read on the second try", $"{s.Retried:N0}"]),
            new(s.Read > 0 && s.Slow > s.Read * SlowWarnFraction ? AreaLevel.Warning : AreaLevel.Ok,
                [$"Slow blocks (over {s.SlowMs} ms)", $"{s.Slow:N0} ({slowShare.ToString("0.00 %", CultureInfo.InvariantCulture)})"]),
            new(AreaLevel.Neutral, ["Slowest read", $"{s.MaxLatencyMs:N1} ms"]),
            new(AreaLevel.Neutral, ["Average read", $"{s.AverageLatencyMs:N2} ms"]),
            new(AreaLevel.Neutral, ["Data read", HardwareInventory.FormatBytes(s.BytesRead)]),
            new(AreaLevel.Neutral, ["Time", Duration(s.ElapsedSeconds)]),
        };
        if (s.ThrottledSeconds > 0 || s.Throttle is not null)
            rows.Add(new(AreaLevel.Neutral, ["Slowed down", $"{Duration(s.ThrottledSeconds)}" + (s.Throttle is { } t ? $": {t}" : "")]));
        rows.Add(new(level == AreaLevel.Ok ? AreaLevel.Neutral : level, ["Surface map", s.Map], Key: MapRowKey,
            Detail: $"{DiskSurfaceMap.Bins} parts of the disk from start to end, each shown as its worst block: o read fine, s slow, r read on the second try, x unreadable, . not read."));
        if (s.Error is { Length: > 0 } error) rows.Add(new(AreaLevel.Neutral, ["Scan ended", error]));
        foreach (var b in s.BadBlocks.Take(DiskScanOptions.MaxBadLbas))
            rows.Add(new(AreaLevel.Error, [$"Bad LBA {b.Lba:N0}" + (b.Sectors > 1 ? $" ({b.Sectors:N0} sectors)" : ""), $"{b.ErrorText} (Windows error {b.Error}) · {b.Where}"],
                Key: "lba-" + b.Lba.ToString(CultureInfo.InvariantCulture)));

        var card = new AreaCard(cardId, label, failedEarly ? AreaLevel.Neutral : level, (failedEarly ? CouldNotRun.OutcomeText : headline) + partial, meta,
            ["Reading", "Value"], rows, PreserveRowOrder: true,
            Note: "Read-only: the scan never writes to the disk, and reads past Windows' cache so the cache can't hide an error.");
        var status = level switch { AreaLevel.Error => DiagnosticStatus.Error, AreaLevel.Warning => DiagnosticStatus.Warning, _ => DiagnosticStatus.Ok };
        var report = new AreaReport([card], card.Headline, failedEarly ? DiagnosticStatus.Error : status, Cancelled: s.State == DiskScanStatus.Stopped && level != AreaLevel.Error);
        return failedEarly ? report with { CouldNotRunReason = s.Error ?? "The scan stopped before it finished." } : report;
    }

    private static string Duration(double seconds) =>
        seconds < 60 ? $"{seconds:0} s" : seconds < 3600 ? $"{(int)(seconds / 60)} min {(int)(seconds % 60)} s" : $"{(int)(seconds / 3600)} h {(int)(seconds % 3600 / 60)} min";
}
