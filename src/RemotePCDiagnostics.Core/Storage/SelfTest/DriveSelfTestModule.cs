using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>
/// Drive self-test: asks every drive that supports it (ATA SMART and NVMe Device Self-test) to run its own built-in short or extended
/// test, follows the drive's percent-complete, and reports the drive's result code and its self-test log. An on-demand scan: never part of
/// Run all, cancelled with the drive's abort command. Talking to the drives needs administrator rights, so every request goes to the Agent
/// (<see cref="IDriveSelfTestSource"/>), which also keeps the PC and disks awake while a test runs and puts the power plan back after.
/// Several drives test at once, one test per drive.
/// </summary>
public sealed class DriveSelfTestModule(
    IDriveSelfTestSource source,
    Func<bool>? noAgent = null,
    ILogger? log = null,
    TimeSpan? pollEvery = null,
    Func<TimeSpan, CancellationToken, Task>? delay = null,
    Func<DateTimeOffset>? now = null) : AreaModuleBase(log), ICancellableScan
{
    public const string ModuleName = ModuleSlugs.DriveSelfTest;
    public static readonly TimeSpan DefaultPollEvery = TimeSpan.FromSeconds(5);
    /// <summary>Status reads in a row that may fail before a drive's test is reported as lost.</summary>
    public const int MaxFailedPolls = 6;
    public const string NeedsAgentText = "Needs the Agent: the drive's self-test needs administrator rights, which only the Agent has. Install the Agent (or turn on Admin Repair Mode) and run it again.";

    private readonly TimeSpan _pollEvery = pollEvery ?? DefaultPollEvery;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? ((t, c) => Task.Delay(t, c));
    private readonly Func<DateTimeOffset> _now = now ?? (() => DateTimeOffset.Now);
    private readonly object _scanGate = new();
    private CancellationTokenSource? _scan;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DriveSelfTest;
    public override string DisplayName => "Drive self-test";
    public bool IncludeInRunAll => false;
    protected override string FailedMessage => "The drive self-test couldn't run.";

    /// <summary>Short (about 2 minutes) or extended (the drive's own time, often an hour or more). Set before the run starts.</summary>
    public SelfTestKind Mode { get; set; } = SelfTestKind.Short;

    /// <summary>The disk numbers to test; null tests every drive that supports a self-test.</summary>
    public IReadOnlySet<int>? Disks { get; set; }

    /// <summary>The drives as last read (the page's preview, and each run). Null before the first read.</summary>
    public IReadOnlyList<SelfTestDriveState>? LastDrives { get; private set; }

    /// <summary>Why the last preview had no drives (no Agent, the Agent's error), or null.</summary>
    public string? LastPreviewError { get; private set; }

    public void Cancel()
    {
        lock (_scanGate) _scan?.Cancel();
    }

    /// <summary>Reads the drives without testing them: support, the drive's estimated times, a test already running, the log.</summary>
    public async Task<IReadOnlyList<SelfTestDriveState>> PreviewAsync(CancellationToken ct)
    {
        if (noAgent?.Invoke() == true) { LastPreviewError = NeedsAgentText; return LastDrives = []; }
        var r = await source.ListAsync(ct).ConfigureAwait(false);
        if (!r.Ok) { LastPreviewError = r.NoAgent ? NeedsAgentText : r.Error; return LastDrives ?? []; }
        LastPreviewError = null;
        return LastDrives = r.Answer!.Drives.Select(SelfTestDecoder.Decode).OrderBy(d => d.Disk).ToList();
    }

    private sealed class DriveRun(SelfTestDriveState before)
    {
        public SelfTestDriveState Before { get; } = before;
        public SelfTestDriveState Now { get; set; } = before;
        public bool FollowingOther { get; init; }
        public bool SawRunning { get; set; }
        public string? StartError { get; set; }
        public int FailedPolls { get; set; }
        public bool Lost { get; set; }
        public bool Done { get; set; }
        public bool Aborted { get; set; }
        public bool Active => StartError is null && !Done && !Lost;
    }

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var kind = Mode;
        progress.ReportStep(0, 100, "Reading the drives…");
        if (noAgent?.Invoke() == true) return NeedsAgent();
        var listed = await source.ListAsync(ct).ConfigureAwait(false);
        if (listed.NoAgent) return NeedsAgent();
        if (!listed.Ok)
        {
            var why = "The drives couldn't be read: " + listed.Error;
            return new AreaReport([], why, DiagnosticStatus.Error) { CouldNotRunReason = why };
        }
        var drives = listed.Answer!.Drives.Select(SelfTestDecoder.Decode).OrderBy(d => d.Disk).ToList();
        LastDrives = drives;
        if (drives.Count == 0)
        {
            var none = "Windows reported no drives to test.";
            return new AreaReport([], none, DiagnosticStatus.Warning) { CouldNotRunReason = none };
        }
        if (!drives.Any(d => d.Supported))
            return new AreaReport(drives.Select(d => Card(d, null, kind)).ToList(),
                "Not supported: " + string.Join(" · ", drives.Select(d => $"{d.Label}: {d.Unsupported}")), DiagnosticStatus.Warning) { NotOnThisPc = true };

        var targets = drives.Where(d => d.Supported && (Disks is null || Disks.Contains(d.Disk))).ToList();
        if (targets.Count == 0)
        {
            var none = "None of the chosen drives can run a self-test.";
            return new AreaReport(drives.Select(d => Card(d, null, kind)).ToList(), none, DiagnosticStatus.Warning) { CouldNotRunReason = none };
        }

        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_scanGate) _scan = scan;
        var runs = new Dictionary<int, DriveRun>();
        var started = _now();
        try
        {
            foreach (var d in targets)
            {
                if (d.IsRunning)
                {
                    // Started earlier (by this app before a restart of the page, or another tool): follow it rather than abort it.
                    runs[d.Disk] = new DriveRun(d) { FollowingOther = true, SawRunning = true };
                    Log($"[selftest] {d.Label}: a self-test is already running ({d.PercentDone ?? 0}%); following it.");
                    continue;
                }
                var run = new DriveRun(d);
                runs[d.Disk] = run;
                var s = await source.StartAsync(d.Disk, kind, scan.Token).ConfigureAwait(false);
                if (!s.Ok) { run.StartError = s.Error; LogWarn($"[selftest] {d.Label}: couldn't start: {s.Error}"); continue; }
                if (s.Answer!.Drives.FirstOrDefault(x => x.Disk == d.Disk) is { } a)
                {
                    run.Now = SelfTestDecoder.Decode(a);
                    if (run.Now.IsRunning) run.SawRunning = true;
                }
                Log($"[selftest] {d.Label}: {Kind(kind)} self-test started.");
            }
            await FollowAsync(runs, kind, started, progress, scan.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (scan.IsCancellationRequested)
        {
            await AbortAllAsync(runs).ConfigureAwait(false);
            if (ct.IsCancellationRequested) throw;
            return AreaReport.ScanCancelled() with { Summary = $"{Kind(kind, capital: true)} self-test cancelled: the drives were asked to stop" };
        }
        finally
        {
            lock (_scanGate) { if (ReferenceEquals(_scan, scan)) _scan = null; }
        }
        LastDrives = drives.Select(d => runs.TryGetValue(d.Disk, out var r) ? r.Now : d).ToList();
        return Report(drives, runs, kind);
    }

    private async Task FollowAsync(Dictionary<int, DriveRun> runs, SelfTestKind kind, DateTimeOffset started, IProgress<string>? progress, CancellationToken ct)
    {
        var longest = runs.Values.Where(r => r.Active).Select(r => r.Before.MinutesFor(kind) ?? (kind == SelfTestKind.Short ? 2 : 120)).DefaultIfEmpty(2).Max();
        // A drive that never reports finishing (firmware that loses the test) mustn't hold the run forever.
        var giveUpAfter = TimeSpan.FromMinutes(longest * 3 + 30);
        while (runs.Values.Any(r => r.Active))
        {
            Report(runs, kind, started, progress);
            await _delay(_pollEvery, ct).ConfigureAwait(false);
            foreach (var run in runs.Values.Where(r => r.Active))
            {
                var s = await source.StatusAsync(run.Before.Disk, ct).ConfigureAwait(false);
                var answer = s.Answer?.Drives.FirstOrDefault(x => x.Disk == run.Before.Disk);
                if (answer is null)
                {
                    if (++run.FailedPolls >= MaxFailedPolls) { run.Lost = true; LogWarn($"[selftest] {run.Before.Label}: status unreadable: {s.Error}"); }
                    continue;
                }
                run.FailedPolls = 0;
                run.Now = SelfTestDecoder.Decode(answer);
                if (run.Now.IsRunning) run.SawRunning = true;
                else run.Done = true;
            }
            if (_now() - started > giveUpAfter)
            {
                var timedOut = runs.Values.Where(r => r.Active).ToList();
                foreach (var run in timedOut)
                {
                    run.Lost = true;
                    LogWarn($"[selftest] {run.Before.Label}: timed out after {FormatMinutes(giveUpAfter.TotalMinutes)}; sending abort.");
                }
                await AbortRunsAsync(timedOut).ConfigureAwait(false);
            }
        }
    }

    private void Report(Dictionary<int, DriveRun> runs, SelfTestKind kind, DateTimeOffset started, IProgress<string>? progress)
    {
        var active = runs.Values.Where(r => r.Active).ToList();
        if (active.Count == 0) return;
        var percent = active.Average(r => (double)(r.Now.PercentDone ?? 0));
        var left = active.Select(r => MinutesLeft(r, kind, started)).Where(m => m is not null).Select(m => m!.Value).DefaultIfEmpty(-1).Max();
        var who = active.Count == 1 ? active[0].Now.Label : $"{active.Count} drives";
        var eta = left < 0 ? "" : left < 1 ? ", less than a minute left" : $", about {FormatMinutes(left)} left";
        var text = $"{Kind(kind, capital: true)} self-test on {who}: {percent:0}% done{eta}";
        progress.ReportStep((int)Math.Round(percent), 100, text);
        RaiseUpdated(new DiagnosticResult<double>(Name, DiagnosticStatus.Running, text, started, percent));
    }

    /// <summary>Minutes left for a drive: from its own estimate and percent done, or from how fast it went so far.</summary>
    private double? MinutesLeft(DriveRun r, SelfTestKind kind, DateTimeOffset started)
    {
        var pct = r.Now.PercentDone ?? 0;
        if (r.Before.MinutesFor(kind) is { } est && !r.FollowingOther) return Math.Max(0, est - (_now() - started).TotalMinutes);
        if (pct <= 0) return r.Before.MinutesFor(kind);
        var elapsed = (_now() - started).TotalMinutes;
        return elapsed * (100 - pct) / pct;
    }

    private Task AbortAllAsync(Dictionary<int, DriveRun> runs) => AbortRunsAsync(runs.Values.Where(r => r.Active));

    private async Task AbortRunsAsync(IEnumerable<DriveRun> runs)
    {
        foreach (var run in runs)
        {
            try
            {
                var r = await source.AbortAsync(run.Before.Disk, CancellationToken.None).ConfigureAwait(false);
                run.Aborted = r.Ok;
                if (!r.Ok) LogWarn($"[selftest] {run.Before.Label}: abort failed: {r.Error}");
                else Log($"[selftest] {run.Before.Label}: aborted.");
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"[selftest] {run.Before.Label}: abort failed: {ex.Message}"); }
        }
    }

    private AreaReport NeedsAgent() => new([], NeedsAgentText, DiagnosticStatus.Warning) { NotOnThisPc = true };

    private static AreaReport Report(IReadOnlyList<SelfTestDriveState> drives, Dictionary<int, DriveRun> runs, SelfTestKind kind)
    {
        var cards = drives.Select(d => Card(runs.TryGetValue(d.Disk, out var r) ? r.Now : d, runs.GetValueOrDefault(d.Disk), kind)).ToList();
        var tested = cards.Where(c => runs.ContainsKey(DiskOf(c))).ToList();
        var status = AreaReport.Worst(cards.Select(c => c.Level));
        var summary = string.Join(" · ", tested.Select(c => c.Headline));
        var report = new AreaReport(cards, summary, status);
        // Nothing started: no verdict on any drive, so "Couldn't run" rather than a failure of the drives.
        return runs.Values.All(r => r.StartError is not null)
            ? report with { Status = DiagnosticStatus.Error, CouldNotRunReason = "No drive started its self-test: " + string.Join(" · ", runs.Values.Select(r => $"{r.Before.Label}: {r.StartError}")) }
            : report;
    }

    private static int DiskOf(AreaCard c) => int.TryParse(c.Id.AsSpan("disk-".Length), NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : -1;

    /// <summary>The result of this run: the newest log entry when the log has a new one, else (ATA) the SMART data's last result.</summary>
    private static SelfTestLogEntry? ThisRun(DriveRun run)
    {
        var before = run.Before.Log.FirstOrDefault();
        var after = run.Now.Log.FirstOrDefault();
        if (after is not null && (run.FollowingOther || !Equals(after, before) || run.Now.Log.Count > run.Before.Log.Count || (run.Done && run.SawRunning))) return after;
        if (run.Now.ExecOutcome is { } exec and not SelfTestOutcome.InProgress && run.Done)
            return new(null, "Last test", exec, 0, 0, null);
        return null;
    }

    private static AreaCard Card(SelfTestDriveState d, DriveRun? run, SelfTestKind kind)
    {
        var id = "disk-" + d.Disk.ToString(CultureInfo.InvariantCulture);
        var meta = Meta(d);
        var columns = new[] { "Run", "Test", "Result", "Power-on hours", "Failing LBA" };
        var thisRun = run is null ? null : ThisRun(run);
        var rows = LogRows(d.Log, thisRun);
        var earlierFailure = d.Log.Where(e => !ReferenceEquals(e, thisRun) && !Equals(e, thisRun)).FirstOrDefault(e => SelfTestDecoder.IsFailure(e.Outcome));

        if (!d.Supported)
            return new(id, d.Label, AreaLevel.Neutral, "Not supported: " + d.Unsupported, meta, columns, rows,
                EmptyText: "The drive keeps no self-test log that Windows can read.");

        if (run is null)
        {
            var level = earlierFailure is null ? AreaLevel.Neutral : AreaLevel.Warning;
            var headline = earlierFailure is null ? "Not tested this time" : $"Not tested this time; its log shows a failed {earlierFailure.TestName.ToLowerInvariant()} self-test at {Hours(earlierFailure)}";
            return new(id, d.Label, level, headline, meta, columns, rows, EmptyText: "No self-test has run on this drive yet.");
        }

        var what = run.FollowingOther ? "self-test (started earlier)" : Kind(kind) + " self-test";
        if (run.StartError is { } startError)
            return new(id, d.Label, AreaLevel.Warning, $"Couldn't start the {what}: {startError}", meta, columns, rows, Note: "Run the test again; if it keeps failing, the drive's controller may not pass the command through.");
        if (run.Lost)
            return new(id, d.Label, AreaLevel.Warning, $"The {what} didn't report finishing; run it again", meta, columns, rows);
        if (thisRun is null)
            return new(id, d.Label, AreaLevel.Warning, $"The {what} ended without a result in the drive's log; run it again", meta, columns, rows);

        var o = thisRun.Outcome;
        if (SelfTestDecoder.IsFailure(o))
        {
            var lba = thisRun.FailingLba is { } l ? $" at LBA {l.ToString(CultureInfo.InvariantCulture)}" : "";
            var seg = thisRun.Segment is { } sg ? $" (segment {sg})" : "";
            return new(id, d.Label, AreaLevel.Error, $"{Cap(what)} failed: {SelfTestDecoder.Describe(o).Replace("Failed: ", "").Replace("Failed ", "").ToLowerInvariant()}{seg}{lba}", meta, columns, rows,
                Note: "The drive found a fault in itself. Back up this drive now, then replace it. Drive health shows its SMART details.")
            { RunCheck = new AreaCheckLink(ModuleSlugs.DriveHealth, "Check drive health") };
        }
        if (SelfTestDecoder.IsInterrupted(o) || o == SelfTestOutcome.Unknown)
            return new(id, d.Label, AreaLevel.Warning, $"{Cap(what)} {(o == SelfTestOutcome.Unknown ? "ended with an unknown result code" : SelfTestDecoder.Describe(o).ToLowerInvariant())}; run it again",
                meta, columns, rows, Note: o == SelfTestOutcome.InterruptedByReset ? "A restart, sleep, or the drive being reset stops a self-test. Keep the PC on and awake while it runs." : null);
        if (earlierFailure is not null)
            return new(id, d.Label, AreaLevel.Warning, $"{Cap(what)} passed, but the drive's log shows a failed {earlierFailure.TestName.ToLowerInvariant()} self-test at {Hours(earlierFailure)}",
                meta, columns, rows, Note: "An earlier failure can mean the fault comes and goes. Back up the drive and run the extended test.")
            { RunCheck = new AreaCheckLink(ModuleSlugs.DriveHealth, "Check drive health") };
        return new(id, d.Label, AreaLevel.Ok, $"{Cap(what)} passed: completed without error", meta, columns, rows);
    }

    private static List<AreaRow> LogRows(IReadOnlyList<SelfTestLogEntry> log, SelfTestLogEntry? thisRun)
    {
        var rows = new List<AreaRow>();
        for (var i = 0; i < log.Count; i++)
        {
            var e = log[i];
            var level = SelfTestDecoder.IsFailure(e.Outcome) ? AreaLevel.Error
                : SelfTestDecoder.IsInterrupted(e.Outcome) || e.Outcome == SelfTestOutcome.Unknown ? AreaLevel.Warning
                : e.Outcome == SelfTestOutcome.InProgress ? AreaLevel.Neutral : AreaLevel.Ok;
            var result = SelfTestDecoder.Describe(e.Outcome) + (e.Segment is { } s ? $" (segment {s})" : "") + (e.StatusCode is { } sc ? $" (status {sc})" : "");
            var label = i == 0 && thisRun is not null && Equals(e, thisRun) ? "This run" : $"#{i + 1}";
            rows.Add(new(level, [label, e.TestName, result, e.PowerOnHours.ToString(CultureInfo.InvariantCulture),
                e.FailingLba is { } lba ? lba.ToString(CultureInfo.InvariantCulture) : ""],
                SortKeys: [i.ToString("D2", CultureInfo.InvariantCulture), null, null, e.PowerOnHours.ToString("D12", CultureInfo.InvariantCulture), null]));
        }
        return rows;
    }

    private static string Meta(SelfTestDriveState d)
    {
        var parts = new List<string>();
        if (d.Bus.Length > 0) parts.Add(d.Bus == "Nvme" ? "NVMe" : d.Bus.ToUpperInvariant() is "SATA" or "ATA" or "USB" or "RAID" or "SAS" or "SCSI" ? d.Bus.ToUpperInvariant() : d.Bus);
        if (d.Supported)
        {
            parts.Add(d.ShortMinutes is { } s ? $"short about {FormatMinutes(s)}" : "short about 2 min");
            parts.Add(d.ExtendedMinutes is { } x ? $"extended about {FormatMinutes(x)}" : "extended time not reported");
        }
        return string.Join(" · ", parts);
    }

    private static string Hours(SelfTestLogEntry e) => $"{e.PowerOnHours.ToString(CultureInfo.InvariantCulture)} power-on hours";

    public static string FormatMinutes(double minutes)
    {
        var m = (int)Math.Ceiling(minutes);
        if (m < 60) return $"{m} min";
        var h = m / 60;
        var rest = m % 60;
        return rest == 0 ? $"{h} h" : $"{h} h {rest} min";
    }

    public static string Kind(SelfTestKind kind, bool capital = false) => (kind, capital) switch
    {
        (SelfTestKind.Extended, false) => "extended",
        (SelfTestKind.Extended, true) => "Extended",
        (_, false) => "short",
        _ => "Short",
    };

    private static string Cap(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];
}
