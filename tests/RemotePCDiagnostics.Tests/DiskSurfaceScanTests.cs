using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Storage;
using RemotePCDiagnostics.Tests.Replay;

namespace RemotePCDiagnostics.Tests;

/// <summary>The disk surface scan (#280): a fake disk with injected read errors and latency, the Agent's action, and the app's check.</summary>
public sealed class DiskSurfaceScanTests
{
    private const long GB = 1L << 30;

    /// <summary>The fake disk's clock: reads move it forward by their latency, a throttle pause by its length.</summary>
    private sealed class FakeClock : IScanClock
    {
        private long _ticks;
        public TimeSpan Elapsed => TimeSpan.FromTicks(Interlocked.Read(ref _ticks));
        public void Sleep(TimeSpan time) => Advance(time);
        public void Advance(TimeSpan time) => Interlocked.Add(ref _ticks, time.Ticks);
    }

    private sealed class FakeDisk(long size, FakeClock clock, bool? seekPenalty = false, int sector = 512) : IDiskBlockDevice
    {
        public long SizeBytes => size;
        public int SectorBytes => sector;
        public bool? IncursSeekPenalty => seekPenalty;
        public IReadOnlyList<DiskPartitionInfo> Partitions { get; init; } = [];
        /// <summary>Sectors that never read (with this error).</summary>
        public Dictionary<long, int> BadSectors { get; } = [];
        /// <summary>Byte offsets of blocks that fail once, then read.</summary>
        public HashSet<long> FlakyBlocks { get; } = [];
        /// <summary>Byte offsets of blocks that take this long.</summary>
        public Dictionary<long, TimeSpan> SlowBlocks { get; } = [];
        public TimeSpan Latency { get; init; } = TimeSpan.FromMilliseconds(2);
        public int? GoneAfterReads { get; init; }
        public int Reads;
        public bool Disposed;
        public ManualResetEventSlim? Hold { get; init; }

        public int Read(long offset, int length)
        {
            Hold?.Wait(TimeSpan.FromSeconds(10));
            var n = Interlocked.Increment(ref Reads);
            clock.Advance(SlowBlocks.TryGetValue(offset, out var slow) ? slow : Latency);
            if (GoneAfterReads is { } g && n > g) return DiskReadErrors.DeviceNotConnected;
            if (length > sector && FlakyBlocks.Remove(offset)) return DiskReadErrors.Crc;
            for (var s = offset / sector; s < (offset + length) / sector; s++)
                if (BadSectors.TryGetValue(s, out var e)) return e;
            return 0;
        }

        public void Dispose() => Disposed = true;
    }

    private sealed class Conditions(Func<string?> reason) : IDiskScanConditions
    {
        public string? ThrottleReason() => reason();
    }

    private static DiskScanStatus Scan(FakeDisk disk, FakeClock clock, DiskScanMode mode = DiskScanMode.Quick, TimeSpan? limit = null, IDiskScanConditions? conditions = null) =>
        new DiskSurfaceScanner(disk, new DiskScanOptions(0, mode, limit), conditions, clock).Run(CancellationToken.None);

    [Fact]
    public void Quick_plan_reads_first_middle_last_sector_then_a_thousand_aligned_blocks_across_the_disk()
    {
        var size = 500 * GB + 12345 * 512L;
        var blocks = DiskScanPlan.Blocks(size, 512, DiskScanMode.Quick).ToList();
        Assert.Equal(1003, blocks.Count);
        Assert.Equal(DiskScanPlan.Count(size, 512, DiskScanMode.Quick), blocks.Count);
        Assert.Equal((0L, 512), blocks[0]);
        Assert.Equal(size / 2 / 512 * 512, blocks[1].Offset);
        Assert.Equal(size - 512, blocks[2].Offset);
        Assert.All(blocks, b => Assert.True(b.Offset % 512 == 0 && b.Offset >= 0 && b.Offset + b.Length <= size));
        // Spread over the whole disk: every one of the 100 map parts gets samples.
        Assert.Equal(DiskSurfaceMap.Bins, blocks.Skip(3).Select(b => DiskSurfaceMap.BinOf(b.Offset, size)).Distinct().Count());
    }

    [Fact]
    public void Full_plan_reads_every_block_in_order_and_the_last_partial_one()
    {
        var size = 10L * (1 << 20) + 4096;
        var blocks = DiskScanPlan.Blocks(size, 4096, DiskScanMode.Full).ToList();
        Assert.Equal(11, blocks.Count);
        Assert.Equal(DiskScanPlan.Count(size, 4096, DiskScanMode.Full), blocks.Count);
        Assert.Equal(4096, blocks[^1].Length);
        Assert.Equal(size, blocks.Sum(b => (long)b.Length));
        Assert.True(blocks.Zip(blocks.Skip(1)).All(p => p.First.Offset + p.First.Length == p.Second.Offset));
    }

    [Fact]
    public void A_clean_disk_passes_with_every_part_of_the_map_read()
    {
        var clock = new FakeClock();
        var s = Scan(new FakeDisk(64 * GB, clock), clock);
        Assert.Equal(DiskScanStatus.Finished, s.State);
        Assert.Equal(1003, s.Read);
        Assert.Equal(0, s.Unreadable + s.Retried + s.Slow);
        Assert.Equal(new string(DiskSurfaceMap.Ok, DiskSurfaceMap.Bins), s.Map);
        Assert.Equal("SSD", s.Media);
        Assert.Equal(DiskScanOptions.SlowSsdMs, s.SlowMs);
        Assert.Equal(AreaLevel.Ok, DiskSurfaceScanModule.Verdict(s));
        var report = DiskSurfaceScanModule.BuildReport(s, "Disk A", "disk0");
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Equal("No unreadable or slow blocks", report.Cards[0].Headline);
    }

    [Fact]
    public void An_unreadable_sector_fails_the_scan_and_is_listed_by_lba_and_partition()
    {
        var clock = new FakeClock();
        var size = 64 * GB;
        var sampleOffset = DiskScanPlan.Blocks(size, 512, DiskScanMode.Quick).ElementAt(503).Offset;
        var badLba = sampleOffset / 512 + 77;
        var disk = new FakeDisk(size, clock)
        {
            Partitions = [new(1, 1 << 20, 100 << 20), new(3, 200 << 20, size - (400 << 20), "C:")],
        };
        disk.BadSectors[badLba] = DiskReadErrors.Crc;
        var s = Scan(disk, clock);

        Assert.Equal(1, s.Unreadable);
        var bad = Assert.Single(s.BadBlocks);
        Assert.Equal(badLba, bad.Lba);
        Assert.Equal(1, bad.Sectors);
        Assert.Equal(DiskReadErrors.Crc, bad.Error);
        Assert.Equal("Partition 3 (C:)", bad.Where);
        Assert.Equal(DiskSurfaceMap.Unreadable, s.Map[DiskSurfaceMap.BinOf(sampleOffset, size)]);

        var report = DiskSurfaceScanModule.BuildReport(s, "Disk A", "disk0");
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Equal("1 unreadable block", report.Cards[0].Headline);
        var row = Assert.Single(report.Cards[0].Rows, r => r.Key == "lba-" + badLba);
        Assert.Contains("data error (CRC) (Windows error 23) · Partition 3 (C:)", row.Values[1]);
    }

    [Fact]
    public void A_block_that_reads_on_the_second_try_is_a_warning()
    {
        var clock = new FakeClock();
        var disk = new FakeDisk(64 * GB, clock);
        disk.FlakyBlocks.Add(DiskScanPlan.Blocks(64 * GB, 512, DiskScanMode.Quick).ElementAt(10).Offset);
        var s = Scan(disk, clock);
        Assert.Equal(1, s.Retried);
        Assert.Equal(0, s.Unreadable);
        Assert.Empty(s.BadBlocks);
        Assert.Contains(DiskSurfaceMap.Retried, s.Map);
        Assert.Equal(AreaLevel.Warning, DiskSurfaceScanModule.Verdict(s));
        Assert.Equal("1 block read only on the second try", DiskSurfaceScanModule.BuildReport(s, "Disk A", "disk0").Cards[0].Headline);
    }

    [Theory]
    [InlineData(false, 60, 1, AreaLevel.Ok)]       // 1 of 1,003 slow is under 0.1 %
    [InlineData(false, 60, 2, AreaLevel.Warning)]  // 2 of 1,003 is over it
    [InlineData(true, 60, 2, AreaLevel.Ok)]        // an HDD allows 150 ms
    [InlineData(true, 200, 2, AreaLevel.Warning)]
    [InlineData(null, 120, 5, AreaLevel.Ok)]       // unknown media: the HDD threshold
    public void Slow_blocks_warn_over_a_tenth_of_a_percent_with_the_threshold_for_the_drive(bool? hdd, int ms, int slowBlocks, AreaLevel expected)
    {
        var clock = new FakeClock();
        var disk = new FakeDisk(64 * GB, clock, seekPenalty: hdd);
        foreach (var b in DiskScanPlan.Blocks(64 * GB, 512, DiskScanMode.Quick).Skip(3).Take(slowBlocks))
            disk.SlowBlocks[b.Offset] = TimeSpan.FromMilliseconds(ms);
        var s = Scan(disk, clock);
        Assert.Equal(expected, DiskSurfaceScanModule.Verdict(s));
        Assert.Equal(hdd == false ? 50 : 150, s.SlowMs);
        Assert.Equal(ms, s.MaxLatencyMs);
    }

    [Fact]
    public void Full_mode_stops_at_its_time_limit_and_is_judged_on_what_it_read()
    {
        var clock = new FakeClock();
        var disk = new FakeDisk(GB, clock) { Latency = TimeSpan.FromMilliseconds(100) };
        var s = Scan(disk, clock, DiskScanMode.Full, TimeSpan.FromSeconds(30));
        Assert.Equal(DiskScanStatus.TimeLimit, s.State);
        Assert.Equal(1024, s.Planned);
        Assert.Equal(300, s.Read);
        Assert.Contains(DiskSurfaceMap.NotRead, s.Map);
        var report = DiskSurfaceScanModule.BuildReport(s, "Disk A", "disk0");
        Assert.Contains("time limit reached at", report.Cards[0].Headline);
        Assert.False(report.Cancelled);
    }

    [Fact]
    public void On_battery_or_hot_the_scan_slows_down_and_says_why()
    {
        var clock = new FakeClock();
        var s = Scan(new FakeDisk(8 * GB, clock), clock, conditions: new Conditions(() => "On battery at 20 %"));
        Assert.Equal(DiskScanStatus.Finished, s.State);
        Assert.Equal("On battery at 20 %", s.Throttle);
        Assert.Equal(s.Read * DiskScanOptions.ThrottlePause.TotalSeconds, s.ThrottledSeconds, 1);
        // The pauses are between reads, never counted as read latency.
        Assert.Equal(0, s.Slow);
    }

    [Fact]
    public void A_disk_that_disconnects_ends_the_scan_as_failed_without_calling_every_block_bad()
    {
        var clock = new FakeClock();
        var s = Scan(new FakeDisk(64 * GB, clock) { GoneAfterReads = 20 }, clock);
        Assert.Equal(DiskScanStatus.Failed, s.State);
        Assert.Equal(0, s.Unreadable);
        Assert.Contains("device disconnected", s.Error);
        var report = DiskSurfaceScanModule.BuildReport(s, "Disk A", "disk0");
        Assert.NotNull(report.CouldNotRunReason);
        Assert.Equal(RunEnd.CouldNotRun, report.RunEnd);
    }

    [Fact]
    public void The_status_round_trips_as_json()
    {
        var clock = new FakeClock();
        var disk = new FakeDisk(8 * GB, clock);
        disk.BadSectors[5000] = DiskReadErrors.SectorNotFound;
        var s = Scan(disk, clock, DiskScanMode.Full, TimeSpan.FromSeconds(1));
        var back = DiskScanStatus.Parse(s.ToJson());
        Assert.NotNull(back);
        Assert.Equal(s.ToJson(), back.ToJson());
        Assert.Null(DiskScanStatus.Parse("not json"));
    }

    // ---- The Agent's action: a fixed argument list ----

    [Theory]
    [InlineData(new[] { "start", "0", "quick", "0" }, true)]
    [InlineData(new[] { "start", "3", "full", "60" }, true)]
    [InlineData(new[] { "status", "1" }, true)]
    [InlineData(new[] { "stop", "255" }, true)]
    [InlineData(new[] { "start", "0", "quick" }, false)]
    [InlineData(new[] { "start", "0", "write", "0" }, false)]
    [InlineData(new[] { "start", "-1", "quick", "0" }, false)]
    [InlineData(new[] { "start", "256", "quick", "0" }, false)]
    [InlineData(new[] { "start", "0", "full", "99999" }, false)]
    [InlineData(new[] { "status", @"\\.\C:" }, false)]
    [InlineData(new[] { "status", "1", "extra" }, false)]
    [InlineData(new[] { "wipe", "0" }, false)]
    public void Agent_plans_only_the_allowed_arguments(string[] args, bool allowed)
    {
        var plan = AgentScripts.Plan(AgentScripts.Of(AgentScripts.DiskReadScan, args), null, out var refusal);
        Assert.Equal(allowed, plan?.Native is DiskReadScanAction);
        if (!allowed) Assert.NotNull(refusal);
    }

    [Fact]
    public void Agent_runs_one_scan_per_disk_on_its_own_thread_and_stops_it_on_request()
    {
        var clock = new FakeClock();
        var hold = new ManualResetEventSlim(false);
        FakeDisk? opened = null;
        var scans = new AgentDiskScans(n => opened = new FakeDisk(GB, clock) { Hold = hold }, clock: () => clock);

        var started = DiskScanStatus.Parse(scans.Run(new(DiskReadScanAction.Start, 2, DiskScanMode.Full, 0)).StdOut)!;
        Assert.Equal(DiskScanStatus.Running, started.State);
        Assert.Equal(2, started.Disk);
        // Asking again while it runs answers with the same scan rather than opening the disk twice.
        var firstDisk = opened;
        Assert.Equal(DiskScanStatus.Running, DiskScanStatus.Parse(scans.Run(new(DiskReadScanAction.Start, 2, DiskScanMode.Full, 0)).StdOut)!.State);
        Assert.Same(firstDisk, opened);

        hold.Set();
        var stopped = DiskScanStatus.Parse(scans.Run(new(DiskReadScanAction.Stop, 2, DiskScanMode.Quick, 0)).StdOut)!;
        Assert.True(scans.WaitFor(2, TimeSpan.FromSeconds(10)));
        var final = DiskScanStatus.Parse(scans.Run(new(DiskReadScanAction.Status, 2, DiskScanMode.Quick, 0)).StdOut)!;
        Assert.Contains(final.State, new[] { DiskScanStatus.Stopped, DiskScanStatus.Finished });
        Assert.True(opened!.Disposed);
        Assert.NotNull(stopped);

        Assert.NotEqual(0, scans.Run(new(DiskReadScanAction.Status, 7, DiskScanMode.Quick, 0)).ExitCode);
    }

    [Fact]
    public void Agent_stops_a_scan_nobody_asks_about()
    {
        var clock = new FakeClock();
        var now = new DateTime(2026, 11, 27, 12, 0, 0, DateTimeKind.Utc);
        var hold = new ManualResetEventSlim(false);
        var scans = new AgentDiskScans(_ => new FakeDisk(GB, clock) { Hold = hold }, clock: () => clock, now: () => now);
        scans.Run(new(DiskReadScanAction.Start, 0, DiskScanMode.Full, 0));
        now += AgentDiskScans.AbandonAfter + TimeSpan.FromSeconds(1);
        // Any call checks for abandoned scans first.
        scans.Run(new(DiskReadScanAction.Status, 1, DiskScanMode.Quick, 0));
        hold.Set();
        Assert.True(scans.WaitFor(0, TimeSpan.FromSeconds(10)));
        Assert.Equal(DiskScanStatus.Stopped, DiskScanStatus.Parse(scans.Run(new(DiskReadScanAction.Status, 0, DiskScanMode.Quick, 0)).StdOut)!.State);
    }

    [Fact]
    public void Agent_answers_with_why_a_disk_cannot_be_opened()
    {
        var scans = new AgentDiskScans(n => throw new IOException($"There's no disk {n}."));
        var r = scans.Run(new(DiskReadScanAction.Start, 9, DiskScanMode.Quick, 0));
        Assert.Equal(1, r.ExitCode);
        Assert.Equal("There's no disk 9.", r.StdErr);
    }

    // ---- The app's check ----

    /// <summary>The Agent's side in process: <see cref="AgentDiskScans"/> answering as it would over the pipe.</summary>
    private sealed class InProcessAgent(AgentDiskScans scans) : IDiskScanSource
    {
        public List<string> Sent { get; } = [];
        public Task<DiskScanAnswer> SendAsync(DiskScanRequest request, CancellationToken ct)
        {
            lock (Sent) Sent.Add(request.Key);
            var action = DiskReadScanAction.Parse(request.Args())!;
            return Task.FromResult(AgentDiskScanSource.Read(scans.Run(action)));
        }
    }

    private sealed class FixedSource(DiskScanAnswer answer) : IDiskScanSource
    {
        public Task<DiskScanAnswer> SendAsync(DiskScanRequest request, CancellationToken ct) => Task.FromResult(answer);
    }

    private static IWmiSource Disks(params (string Id, string Name, string Serial, long MediaType, long Bus, long Size)[] disks)
    {
        var rows = disks.Select(d => new Dictionary<string, object?>
        {
            ["ObjectId"] = "obj" + d.Id, ["DeviceId"] = d.Id, ["UniqueId"] = "", ["FriendlyName"] = d.Name, ["SerialNumber"] = d.Serial,
            ["MediaType"] = d.MediaType, ["SpindleSpeed"] = 0, ["BusType"] = d.Bus, ["HealthStatus"] = 0, ["OperationalStatus"] = new[] { 2 }, ["Size"] = d.Size,
        }).Select(r => System.Text.Json.JsonSerializer.SerializeToElement(r)).Select(e =>
            e.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone())).ToList();
        var calls = new List<RecordedCall>
        {
            new() { Kind = RecordedCall.WmiKind, Namespace = DriveReader.StorageNamespace, Query = DriveReader.DiskSql, Rows = rows },
        };
        return new RecordingReplay(calls).Wmi;
    }

    private static readonly IWmiSource TwoDisks = Disks(("0", "NVMe SSD", "S1", 4, 17, 64 * GB), ("1", "USB stick", "U9", 0, 7, 8 * GB));

    [Fact]
    public async Task One_run_per_disk_keyed_like_drive_health_and_never_in_run_all()
    {
        var module = new DiskSurfaceScanModule(TwoDisks, new FixedSource(new(null, "x")));
        Assert.False(module.IncludeInRunAll);
        var found = await module.DetectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, found.Instances.Count);
        Assert.Equal(InstanceKeys.From("serial:S1"), found.Instances[0].Key);
        Assert.Equal("Disk 1", found.Instances[1].Details);
        Assert.All(found.Instances, i => Assert.True(i.Applies));
    }

    [Fact]
    public async Task Without_the_agent_the_check_is_skipped_not_failed()
    {
        var module = new DiskSurfaceScanModule(TwoDisks, new FixedSource(new(null, "The Agent isn't connected.", NeedsAgent: true)));
        var ct = TestContext.Current.CancellationToken;
        var instance = (await module.DetectAsync(ct)).Instances[0];
        var r = await module.RefreshAsync(instance, null, ct);
        Assert.Equal("Skipped", ResultEventLogger.Outcome(r));
        Assert.Equal(DiskSurfaceScanModule.NeedsAgentSummary, r.Message);
        Assert.Contains(ElevationService.AdminRepairHint, ((AreaReport)r.Payload!).Cards[0].Rows[0].Values[1]);
    }

    [Fact]
    public void An_agent_too_old_for_the_scan_is_also_a_skip()
    {
        var a = AgentDiskScanSource.Read(new ProcessResult(1, "", "Unknown script 'disk_read_scan'."));
        Assert.True(a.NeedsAgent);
        Assert.Equal(AgentDiskScanSource.TooOldText, a.Error);
        Assert.Null(AgentDiskScanSource.Read(null).Status);
        Assert.True(AgentDiskScanSource.Read(new ProcessResult(SystemCommandRunner.AgentFailedExitCode, "", "The Agent isn't connected.")).NeedsAgent);
        Assert.False(AgentDiskScanSource.Read(new ProcessResult(1, "", "There's no disk 4.")).NeedsAgent);
    }

    [Fact]
    public async Task The_check_starts_the_agent_scan_follows_it_and_reports_it()
    {
        var clock = new FakeClock();
        var disk = new FakeDisk(64 * GB, clock);
        disk.BadSectors[DiskScanPlan.Blocks(64 * GB, 512, DiskScanMode.Quick).ElementAt(900).Offset / 512] = DiskReadErrors.IoDevice;
        var agent = new InProcessAgent(new AgentDiskScans(_ => disk, clock: () => clock));
        var module = new DiskSurfaceScanModule(TwoDisks, agent, pollEvery: TimeSpan.FromMilliseconds(5));
        var ct = TestContext.Current.CancellationToken;
        var progress = new List<CheckProgress>();
        var instance = (await module.DetectAsync(ct)).Instances[0];

        var r = await module.RefreshAsync(instance, CheckProgressExtensions.Create(p => { lock (progress) progress.Add(p); }), ct);

        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("1 unreadable block", r.Message);
        Assert.Equal("start 0 quick 0", agent.Sent[0]);
        Assert.All(agent.Sent.Skip(1), s => Assert.Equal("status 0", s));
        var card = ((AreaReport)r.Payload!).Cards[0];
        Assert.Equal("disk0", card.Id);
        Assert.Equal(DiskSurfaceMap.Bins, card.Rows.Single(x => x.Key == DiskSurfaceScanModule.MapRowKey).Values[1].Length);
        Assert.Contains(progress, p => p.Message.StartsWith("Reading disk 0:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cancel_stops_the_agent_scan_and_the_run_counts_as_cancelled()
    {
        var clock = new FakeClock();
        var hold = new ManualResetEventSlim(false);
        var scans = new AgentDiskScans(_ => new FakeDisk(64 * GB, clock) { Hold = hold }, clock: () => clock);
        var agent = new InProcessAgent(scans);
        var module = new DiskSurfaceScanModule(TwoDisks, agent, pollEvery: TimeSpan.FromMilliseconds(5));
        var ct = TestContext.Current.CancellationToken;
        var instance = (await module.DetectAsync(ct)).Instances[0];

        var run = module.RefreshAsync(instance, null, ct);
        while (!agent.Sent.Contains("status 0")) await Task.Delay(5, ct);
        module.Cancel();
        hold.Set();
        var r = await run;

        Assert.Contains("stop 0", agent.Sent);
        Assert.Equal(RunEnd.Cancelled, ((AreaReport)r.Payload!).RunEnd);
        Assert.Contains("stopped at", r.Message);
    }

    [Fact]
    public async Task A_recorded_clean_quick_scan_replays_to_the_same_report()
    {
        var clock = new FakeClock();
        var recorder = new CallRecorder();
        var live = new RecordingDiskScanSource(new InProcessAgent(new AgentDiskScans(_ => new FakeDisk(64 * GB, clock), clock: () => clock)), recorder);
        var ct = TestContext.Current.CancellationToken;
        var liveModule = new DiskSurfaceScanModule(TwoDisks, live, pollEvery: TimeSpan.FromMilliseconds(5));
        var instance = (await liveModule.DetectAsync(ct)).Instances[0];
        var first = await liveModule.RefreshAsync(instance, null, ct);
        Assert.Equal(DiagnosticStatus.Ok, first.Status);

        var calls = recorder.Snapshot();
        Assert.All(calls, c => Assert.Equal(RecordedCall.DiskScanKind, c.Kind));
        var replay = new RecordingReplay(calls);
        var replayed = await new DiskSurfaceScanModule(TwoDisks, replay.DiskScans, pollEvery: TimeSpan.Zero).RefreshAsync(instance, null, ct);
        Assert.Empty(replay.Misses);
        Assert.Equal(Snapshot.Normalize(first), Snapshot.Normalize(replayed));
    }

    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    /// <summary>Every recorded PC lists its disks for the scan from the same Storage WMI answer Drive health reads.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Recorded_pcs_list_their_disks_for_the_scan(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(pc.Has(c => c.Query == DriveReader.DiskSql), "This recording has no drive answers.");
        var module = new DiskSurfaceScanModule(pc.Wmi, new FixedSource(new(null, "x")));
        var found = await module.DetectAsync(TestContext.Current.CancellationToken);
        Assert.True(found.Applies);
        Assert.Empty(pc.Replay.Misses);
    }

    [Fact]
    public void Combined_report_has_a_card_per_disk_and_the_worst_verdict()
    {
        var clock = new FakeClock();
        var good = DiskSurfaceScanModule.BuildReport(Scan(new FakeDisk(8 * GB, clock), clock), "A", "disk0");
        var badDisk = new FakeDisk(8 * GB, clock);
        badDisk.BadSectors[0] = DiskReadErrors.Crc;
        var bad = DiskSurfaceScanModule.BuildReport(Scan(badDisk, clock), "B", "disk1");
        var merged = DiskSurfaceScanModule.Merge([good, bad])!;
        Assert.Equal(2, merged.Cards.Select(c => c.Id).Distinct().Count());
        Assert.Equal(DiagnosticStatus.Error, merged.Status);
        Assert.Equal("1 disk with problems", merged.Summary);
    }
}
