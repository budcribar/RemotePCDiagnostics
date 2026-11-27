using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.GpuMemory;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// A simulated graphics chip: each block remembers the pattern last written to it (writes cover a whole block), so a check knows exactly
/// what every word holds. Faults are stuck bits at byte offsets, a driver reset after N dispatches, a dispatch that never returns, and
/// running out of memory after N blocks. A check that doesn't match what was last written (the test got its own sequence wrong) reports
/// every word as wrong, so the tests also prove the write/check order.
/// </summary>
internal sealed class SimulatedGpuMemory(params GpuMemoryAdapter[] adapters) : IGpuMemorySource
{
    public List<(long ByteOffset, int Bit, bool StuckHigh)> StuckBits { get; } = [];
    public int? LoseAfterRuns { get; set; }
    public int? HangOnRun { get; set; }
    public int? MaxBlocks { get; set; }
    public FakeStressClock Clock { get; } = new();
    public TimeSpan PerRun { get; set; } = TimeSpan.FromMilliseconds(50);
    public ManualResetEventSlim Release { get; } = new(false);
    public int Runs;
    public int Opened, Disposed;
    public List<(GpuMemoryOp Op, GpuMemoryPattern Pattern, bool Inverted, int Block)> Log { get; } = [];

    public IReadOnlyList<GpuMemoryAdapter> ListAdapters() => adapters;

    public IGpuMemoryDevice Open(string adapterId)
    {
        Opened++;
        return new Device(this, adapters.Single(a => a.Id == adapterId));
    }

    private sealed class Device(SimulatedGpuMemory sim, GpuMemoryAdapter adapter) : IGpuMemoryDevice
    {
        private readonly List<long> _blocks = [];
        private readonly List<(GpuMemoryPattern P, uint Seed, bool Inv, bool Written)> _state = [];
        public GpuMemoryAdapter Adapter => adapter;
        public IReadOnlyList<long> Blocks => _blocks;

        public bool TryAllocateBlock(long bytes)
        {
            if (sim.MaxBlocks is { } max && _blocks.Count >= max) return false;
            _blocks.Add(bytes);
            _state.Add(default);
            return true;
        }

        public GpuBlockResult Run(int block, GpuMemoryOp op, GpuMemoryPattern pattern, uint seed, bool inverted, uint baseWord)
        {
            var n = Interlocked.Increment(ref sim.Runs);
            sim.Clock.Advance(sim.PerRun);
            lock (sim.Log) sim.Log.Add((op, pattern, inverted, block));
            if (sim.HangOnRun == n) sim.Release.Wait();
            if (sim.LoseAfterRuns is { } lose && n > lose) throw new GpuDeviceLostException("device removed, reason DXGI_ERROR_DEVICE_HUNG (0x887A0006)");
            if (op == GpuMemoryOp.Write) { _state[block] = (pattern, seed, inverted, true); return GpuBlockResult.Clean; }

            var s = _state[block];
            var words = _blocks[block] / 4;
            if (!s.Written || s.P != pattern || s.Seed != seed || s.Inv != inverted) return new(words, []);
            var start = _blocks.Take(block).Sum();
            var first = new List<GpuWordError>();
            long errors = 0;
            foreach (var (offset, bit, high) in sim.StuckBits.Where(f => f.ByteOffset >= start && f.ByteOffset < start + _blocks[block]))
            {
                var word = (uint)((offset - start) / 4);
                var e = GpuMemoryKernel.Expected(pattern, baseWord + word, seed);
                if (inverted) e = ~e;
                var a = high ? e | (1u << bit) : e & ~(1u << bit);
                if (a == e) continue;
                errors++;
                if (first.Count < GpuMemoryKernel.MaxRecords) first.Add(new(word, e, a));
            }
            if (op == GpuMemoryOp.VerifyThenInvert) _state[block] = (pattern, seed, !inverted, true);
            return new(errors, first);
        }

        public void Dispose() => Interlocked.Increment(ref sim.Disposed);
    }
}

public sealed class GpuMemoryTests
{
    private const long MB = GpuMemoryPlan.MB, GB = 1024 * MB;

    internal static GpuMemoryAdapter Discrete(long dedicated = 8 * GB, long? free = 6 * GB, string id = "PCI\\VEN_10DE&DEV_2786&SUBSYS_00000000&REV_A1") =>
        new(id, "NVIDIA GeForce RTX 4070", 0x10DE, dedicated, 16 * GB, false, free is null ? null : dedicated, free is null ? null : dedicated - free);

    internal static GpuMemoryAdapter Integrated(long budget = 8 * GB, long usage = 1 * GB) =>
        new("PCI\\VEN_8086&DEV_A7A0&SUBSYS_00000000&REV_04", "Intel(R) Iris(R) Xe Graphics", 0x8086, 128 * MB, 8 * GB, true, budget, usage);

    private static GpuMemoryModule Module(SimulatedGpuMemory sim, ISensorProvider? sensors = null, GpuMemoryOptions? o = null) =>
        new(sim, sensors, clockFactory: () => sim.Clock, options: o ?? new GpuMemoryOptions { OpWatchdog = TimeSpan.FromSeconds(10) });

    private static async Task<(AreaReport Report, DiagnosticResult Result)> RunAsync(GpuMemoryModule m)
    {
        var r = await m.RefreshAsync(null, CancellationToken.None);
        return ((AreaReport)r.Payload!, r);
    }

    [Fact]
    public void Kernel_patterns_match_their_definitions()
    {
        Assert.Equal(1u, GpuMemoryKernel.Expected(GpuMemoryPattern.WalkingOnes, 0, 0));
        Assert.Equal(1u << 5, GpuMemoryKernel.Expected(GpuMemoryPattern.WalkingOnes, 3, 2));
        Assert.Equal(1u, GpuMemoryKernel.Expected(GpuMemoryPattern.WalkingOnes, 32, 0));
        Assert.Equal(~(1u << 7), GpuMemoryKernel.Expected(GpuMemoryPattern.WalkingZeros, 7, 0));
        Assert.Equal(0x40u, GpuMemoryKernel.Expected(GpuMemoryPattern.OwnAddress, 0x10, 0));
        Assert.Equal(0x55555555u, GpuMemoryKernel.Expected(GpuMemoryPattern.Solid, 123, 0x55555555u));
        // The random pattern differs by word and by seed.
        Assert.NotEqual(GpuMemoryKernel.Expected(GpuMemoryPattern.Random, 1, 9), GpuMemoryKernel.Expected(GpuMemoryPattern.Random, 2, 9));
        Assert.NotEqual(GpuMemoryKernel.Expected(GpuMemoryPattern.Random, 1, 9), GpuMemoryKernel.Expected(GpuMemoryPattern.Random, 1, 10));
        Assert.Equal(GpuMemoryKernel.FlagVerify | GpuMemoryKernel.FlagInverted | GpuMemoryKernel.FlagThenInvert, GpuMemoryKernel.Flags(GpuMemoryOp.VerifyThenInvert, true));
        Assert.Equal(0u, GpuMemoryKernel.Flags(GpuMemoryOp.Write, false));
    }

    [Fact]
    public void Kernel_dispatch_covers_a_block_and_the_error_buffer_decodes()
    {
        var (groups, stride) = GpuMemoryKernel.Dispatch(64 * MB / 4);
        Assert.Equal((uint)GpuMemoryKernel.MaxGroups, groups);
        Assert.Equal(groups * GpuMemoryKernel.GroupSize, stride);
        Assert.Equal((1u, 256u), GpuMemoryKernel.Dispatch(10));

        var err = new uint[GpuMemoryKernel.ErrorBufferLength];
        Assert.Same(GpuBlockResult.Clean, GpuMemoryKernel.Decode(err));
        err[0] = 40; err[1] = 7; err[2] = 0xFF; err[3] = 0xFE;
        var r = GpuMemoryKernel.Decode(err);
        Assert.Equal(40, r.Errors);
        Assert.Equal(GpuMemoryKernel.MaxRecords, r.First.Count);
        Assert.Equal(new GpuWordError(7, 0xFF, 0xFE), r.First[0]);
        Assert.Contains("InterlockedAdd", GpuMemoryKernel.Hlsl);
    }

    [Fact]
    public void Plan_takes_80_percent_of_free_memory_in_whole_blocks_and_caps_integrated_graphics()
    {
        Assert.Equal(4864 * MB, GpuMemoryPlan.Target(Discrete(8 * GB, 6 * GB), 64 * MB)); // 6 GB * 0.8 = 4915 MB -> 76 blocks
        Assert.Equal(8 * GB, GpuMemoryPlan.MemoryBytes(Discrete()));
        // Integrated: measured against the shared budget, capped at 2 GB.
        Assert.Equal(GpuMemoryPlan.IntegratedCap, GpuMemoryPlan.MemoryBytes(Integrated()));
        Assert.Equal(1600 * MB, GpuMemoryPlan.Target(Integrated(), 64 * MB));
        // Too little free: nothing to test.
        Assert.Equal(0, GpuMemoryPlan.Target(Discrete(8 * GB, 40 * MB), 64 * MB));
        // No budget from Windows: assume a third is in use.
        Assert.True(GpuMemoryPlan.Target(Discrete(8 * GB, free: null), 64 * MB) is > 0 and < 8 * GB);
    }

    [Fact]
    public void Extended_passes_add_moving_inversions_and_vary_their_backgrounds()
    {
        var quick = GpuMemoryStep.ForPass(GpuMemoryMode.Quick, 0);
        Assert.Equal([GpuMemoryPattern.WalkingOnes, GpuMemoryPattern.WalkingZeros, GpuMemoryPattern.OwnAddress, GpuMemoryPattern.Random], quick.Select(s => s.Pattern));
        Assert.DoesNotContain(quick, s => s.MovingInversion);
        var ext0 = GpuMemoryStep.ForPass(GpuMemoryMode.Extended, 0);
        var ext1 = GpuMemoryStep.ForPass(GpuMemoryMode.Extended, 1);
        Assert.Equal(2, ext0.Count(s => s.MovingInversion));
        Assert.NotEqual(ext0.First(s => s.MovingInversion).Seed, ext1.First(s => s.MovingInversion).Seed);
        Assert.NotEqual(ext0.Single(s => s.Pattern == GpuMemoryPattern.Random && !s.MovingInversion).Seed, ext1.Single(s => s.Pattern == GpuMemoryPattern.Random && !s.MovingInversion).Seed);
    }

    [Fact]
    public async Task A_healthy_card_passes_with_mb_tested_passes_and_temperature()
    {
        var sim = new SimulatedGpuMemory(Discrete());
        var sensors = new SequenceSensorProvider(n => Gpu(55 + Math.Min(n, 10)));
        var m = Module(sim, sensors);
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Ok, result.Status);
        var card = Assert.Single(report.Cards);
        Assert.Equal("gpu-0", card.Id);
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.StartsWith("Passed: 4.8 GB (59%) tested", card.Headline);
        Assert.Contains("8 GB dedicated memory", card.Meta);
        Assert.Contains("GPU up to 65°C (started at 56°C)", card.Meta);
        Assert.Empty(card.Rows);
        Assert.Equal(1, sim.Opened);
        Assert.Equal(1, sim.Disposed);
        var r = Assert.Single(m.LastResults!);
        Assert.Equal(GpuMemoryOutcome.Passed, r.Outcome);
        Assert.True(r.Passes >= 2, $"passes={r.Passes}");
        Assert.Equal(4864L, r.TestedMb);
        Assert.Equal(4864, report.KeyMetrics!.Single(k => k.Id == "TestedMb").Value);
        // Every block is written before any block is checked, so a check reads memory, not the chip's cache.
        var firstStep = sim.Log.TakeWhile(l => l.Pattern == GpuMemoryPattern.WalkingOnes).ToList();
        Assert.Equal(76, firstStep.TakeWhile(l => l.Op == GpuMemoryOp.Write).Count());
        Assert.All(firstStep.Skip(76), l => Assert.Equal(GpuMemoryOp.Verify, l.Op));
    }

    [Fact]
    public async Task A_stuck_bit_fails_with_its_offset_the_wrong_bit_and_the_pattern()
    {
        var sim = new SimulatedGpuMemory(Discrete());
        var offset = 100 * MB + 0x1234 * 4;
        sim.StuckBits.Add((offset, 3, false));
        var m = Module(sim);
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Error, result.Status);
        var card = Assert.Single(report.Cards);
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.StartsWith("Failed: ", card.Headline);
        Assert.Contains("wrong value", card.Headline);
        var row = card.Rows[0];
        Assert.Equal("0x" + offset.ToString("X"), row.Values[0]);
        Assert.Equal("bit 3", row.Values[3]);
        // Walking ones only sets that bit in one word of 32; walking zeros sets it in this word, so it finds the bit stuck at 0.
        Assert.Equal("Walking zeros", row.Values[4]);
        var r = Assert.Single(m.LastResults!);
        Assert.Equal(GpuMemoryOutcome.ErrorsFound, r.Outcome);
        Assert.Equal(1, r.Passes);
        Assert.Equal(1u << 3, r.FlippedBits);
        Assert.All(r.FirstErrors, e => Assert.Equal(offset, e.ByteOffset));
        Assert.Equal(1, sim.Disposed);
    }

    [Fact]
    public async Task The_extended_test_finds_a_stuck_bit_and_says_it_was_extended()
    {
        var sim = new SimulatedGpuMemory(Discrete(2 * GB, 2 * GB));
        sim.StuckBits.Add((640 * MB, 31, true));
        var m = Module(sim, o: new GpuMemoryOptions { Mode = GpuMemoryMode.Extended, OpWatchdog = TimeSpan.FromSeconds(10) });
        m.Mode = GpuMemoryMode.Extended;
        var (report, _) = await RunAsync(m);

        Assert.Equal(AreaLevel.Error, report.Cards[0].Level);
        Assert.Contains("extended test", report.Cards[0].Meta);
        // The test's own write/check order matched what it wrote: only the stuck word was ever wrong.
        Assert.All(m.LastResults![0].FirstErrors, e => Assert.Equal(640 * MB, e.ByteOffset));
    }

    [Fact]
    public async Task Extended_runs_moving_inversions_up_and_down_without_false_errors()
    {
        var sim = new SimulatedGpuMemory(Discrete(1 * GB, 1 * GB));
        var m = Module(sim, o: new GpuMemoryOptions { OpWatchdog = TimeSpan.FromSeconds(10) });
        m.Mode = GpuMemoryMode.Extended;
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Ok, result.Status);
        Assert.Contains(sim.Log, l => l.Op == GpuMemoryOp.VerifyThenInvert && l.Inverted);
        var r = m.LastResults![0];
        Assert.Equal(0, r.Errors);
        Assert.True(r.Ran >= TimeSpan.FromMinutes(10), $"ran {r.Ran}");
        Assert.Contains("passes", report.Cards[0].Headline);
    }

    [Fact]
    public async Task A_driver_reset_fails_and_points_to_the_crashes_check()
    {
        var sim = new SimulatedGpuMemory(Discrete()) { LoseAfterRuns = 100 };
        var m = Module(sim);
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Error, result.Status);
        var card = report.Cards[0];
        Assert.Contains("graphics driver stopped responding", card.Headline);
        Assert.Contains("DXGI_ERROR_DEVICE_HUNG", card.Note);
        Assert.Equal(ModuleSlugs.Crashes, card.RunCheck?.CheckId);
        Assert.Equal(GpuMemoryOutcome.DriverReset, m.LastResults![0].Outcome);
        Assert.Equal(1, sim.Disposed);
    }

    [Fact]
    public async Task A_dispatch_that_never_returns_is_caught_by_the_watchdog_and_the_memory_freed_when_it_does()
    {
        var sim = new SimulatedGpuMemory(Discrete()) { HangOnRun = 5 };
        var m = Module(sim, o: new GpuMemoryOptions { OpWatchdog = TimeSpan.FromMilliseconds(200) });
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Error, result.Status);
        Assert.Equal(GpuMemoryOutcome.Hung, m.LastResults![0].Outcome);
        Assert.Contains("stopped responding", report.Cards[0].Headline);
        Assert.Equal(0, sim.Disposed); // still held by the stuck dispatch
        sim.Release.Set();
        await WaitUntil(() => sim.Disposed == 1);
    }

    [Fact]
    public async Task Testing_under_a_quarter_of_the_memory_is_a_warning()
    {
        var sim = new SimulatedGpuMemory(Discrete(8 * GB, 1 * GB));
        var (report, result) = await RunAsync(Module(sim));

        Assert.Equal(DiagnosticStatus.Warning, result.Status);
        Assert.Contains("only 768 MB (9% of 8 GB) could be tested", report.Cards[0].Headline);
    }

    [Fact]
    public async Task Running_out_of_memory_early_tests_what_it_got()
    {
        var sim = new SimulatedGpuMemory(Discrete()) { MaxBlocks = 40 };
        var m = Module(sim);
        var (_, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Ok, result.Status);
        Assert.Equal(40 * 64L, m.LastResults![0].TestedMb);
        Assert.Equal(4864L, m.LastResults![0].PlannedBytes / MB);
    }

    [Fact]
    public async Task No_memory_at_all_is_couldnt_run_not_a_failure()
    {
        var sim = new SimulatedGpuMemory(Discrete()) { MaxBlocks = 0 };
        var (report, _) = await RunAsync(Module(sim));

        Assert.NotNull(report.CouldNotRunReason);
        Assert.Equal(RunEnd.CouldNotRun, report.RunEnd);
        Assert.Equal(AreaLevel.Warning, report.Cards[0].Level);
    }

    [Fact]
    public async Task A_critical_temperature_stops_the_test_as_a_warning()
    {
        var sim = new SimulatedGpuMemory(Discrete());
        var sensors = new SequenceSensorProvider(n => Gpu(n < 4 ? 70 : 110));
        var m = Module(sim, sensors);
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Warning, result.Status);
        Assert.Equal(GpuMemoryOutcome.Overheated, m.LastResults![0].Outcome);
        Assert.Contains("too hot", report.Cards[0].Headline);
        Assert.Equal(1, sim.Disposed);
    }

    [Fact]
    public async Task A_critical_temperature_aborts_mid_moving_inversion()
    {
        var sim = new SimulatedGpuMemory(Discrete(1 * GB, 1 * GB));
        var sensors = new SequenceSensorProvider(_ => Gpu(sim.Log.Any(l => l.Op == GpuMemoryOp.VerifyThenInvert) ? 110 : 70));
        var m = Module(sim, sensors, new GpuMemoryOptions { OpWatchdog = TimeSpan.FromSeconds(10), SensorInterval = sim.PerRun });
        m.Mode = GpuMemoryMode.Extended;
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Warning, result.Status);
        Assert.Equal(GpuMemoryOutcome.Overheated, m.LastResults![0].Outcome);
        Assert.Equal(1, sim.Log.Count(l => l.Op == GpuMemoryOp.VerifyThenInvert && !l.Inverted));
        Assert.DoesNotContain(sim.Log, l => l.Op == GpuMemoryOp.VerifyThenInvert && l.Inverted);
        Assert.Contains("too hot", report.Cards[0].Headline);
        Assert.Equal(1, sim.Disposed);
    }

    [Fact]
    public async Task Bit_errors_with_overheat_report_errors_found_not_overheated()
    {
        var sim = new SimulatedGpuMemory(Discrete(1 * GB, 1 * GB));
        sim.StuckBits.Add((0, 0, false));
        var sensors = new SequenceSensorProvider(_ => Gpu(sim.Log.Any(l => l.Op == GpuMemoryOp.Verify) ? 110 : 70));
        var m = Module(sim, sensors, new GpuMemoryOptions { OpWatchdog = TimeSpan.FromSeconds(10), SensorInterval = sim.PerRun });
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Error, result.Status);
        Assert.Equal(AreaLevel.Error, report.Cards[0].Level);
        Assert.Equal(GpuMemoryOutcome.ErrorsFound, m.LastResults![0].Outcome);
        Assert.True(m.LastResults![0].Errors > 0);
        Assert.DoesNotContain("no errors so far", report.Cards[0].Headline);
        Assert.Equal(1, sim.Disposed);
    }

    [Fact]
    public void Zero_budget_falls_back_to_dedicated_and_shared_sizing()
    {
        var discreteZero = new GpuMemoryAdapter("D0", "Virtual GPU", 0x10DE, 8 * GB, 16 * GB, Integrated: false, BudgetBytes: 0, UsageBytes: 0);
        Assert.Null(discreteZero.FreeBytes);
        Assert.Equal(8 * GB, GpuMemoryPlan.MemoryBytes(discreteZero));
        Assert.Equal(GpuMemoryPlan.Target(Discrete(8 * GB, free: null), 64 * MB), GpuMemoryPlan.Target(discreteZero, 64 * MB));
        Assert.True(GpuMemoryPlan.Target(discreteZero, 64 * MB) > 0);

        var integratedZero = new GpuMemoryAdapter("I0", "Virtual iGPU", 0x8086, 128 * MB, 8 * GB, Integrated: true, BudgetBytes: 0, UsageBytes: 0);
        Assert.Null(integratedZero.FreeBytes);
        Assert.Equal(GpuMemoryPlan.IntegratedCap, GpuMemoryPlan.MemoryBytes(integratedZero));
        Assert.True(GpuMemoryPlan.Target(integratedZero, 64 * MB) > 0);
    }

    [Fact]
    public async Task Slow_pass_zero_that_verified_patterns_cleanly_passes_instead_of_could_not_run()
    {
        var sim = new SimulatedGpuMemory(Discrete(1 * GB, 1 * GB)) { PerRun = TimeSpan.FromSeconds(1) };
        var m = Module(sim, o: new GpuMemoryOptions { Duration = TimeSpan.FromSeconds(10), OpWatchdog = TimeSpan.FromSeconds(10) });
        var (report, result) = await RunAsync(m);

        Assert.Equal(DiagnosticStatus.Ok, result.Status);
        Assert.Equal(GpuMemoryOutcome.Passed, m.LastResults![0].Outcome);
        Assert.Equal(1, m.LastResults![0].Passes);
        Assert.Null(report.CouldNotRunReason);
    }

    [Fact]
    public async Task Cancel_stops_the_test_frees_the_memory_and_reports_cancelled()
    {
        var sim = new SimulatedGpuMemory(Discrete());
        var m = Module(sim);
        sim.PerRun = TimeSpan.FromMilliseconds(1);
        var run = m.RefreshAsync(null, CancellationToken.None);
        await WaitUntil(() => sim.Runs > 20);
        m.Cancel();
        var r = await run;

        Assert.True(r.Cancelled);
        Assert.Contains("cancelled", r.Message);
        Assert.Equal(1, sim.Disposed);
    }

    [Fact]
    public async Task Each_graphics_chip_gets_its_own_card_and_the_worst_sets_the_status()
    {
        var bad = Discrete(id: "B");
        var sim = new SimulatedGpuMemory(Integrated(), bad);
        sim.StuckBits.Add((0, 0, true)); // block 0 of both chips: walking ones at word 0 has bit 0 set, so the walking zeros catch it
        var (report, result) = await RunAsync(Module(sim));

        Assert.Equal(2, report.Cards.Count);
        Assert.Equal(["gpu-0", "gpu-1"], report.Cards.Select(c => c.Id));
        Assert.Contains("Built-in graphics", report.Cards[0].Meta);
        Assert.Equal(DiagnosticStatus.Error, result.Status);
        Assert.StartsWith("Intel(R) Iris(R) Xe Graphics: ", report.Summary);
        Assert.Equal(2, sim.Opened);
        Assert.Equal(2, sim.Disposed);
    }

    [Fact]
    public async Task No_graphics_chip_is_not_on_this_pc()
    {
        var (report, result) = await RunAsync(new GpuMemoryModule(new NoGpuMemorySource()));
        Assert.True(report.NotOnThisPc);
        Assert.Equal(DiagnosticStatus.Warning, result.Status);
    }

    [Fact]
    public void The_module_is_on_demand_and_never_in_run_all()
    {
        var m = new GpuMemoryModule(new NoGpuMemorySource());
        Assert.False(m.IncludeInRunAll);
        Assert.IsAssignableFrom<ICancellableScan>(m);
        Assert.Equal(ModuleKind.OnDemand, BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.GpuMemory).Kind);
    }

    [Fact]
    public async Task A_recorded_faulty_run_replays_to_the_same_verdict()
    {
        var sim = new SimulatedGpuMemory(Discrete());
        sim.StuckBits.Add((200 * MB, 9, false));
        var calls = new CallRecorder();
        var live = new GpuMemoryModule(new RecordingGpuMemorySource(sim, calls), clockFactory: () => sim.Clock,
            options: new GpuMemoryOptions { OpWatchdog = TimeSpan.FromSeconds(10) });
        var (liveReport, _) = await RunAsync(live);

        var replayClock = new FakeStressClock();
        var replay = new RecordingReplay(calls.Snapshot());
        var replayed = new GpuMemoryModule(new TickingSource(replay.GpuMemorySource, replayClock), clockFactory: () => replayClock,
            options: new GpuMemoryOptions { OpWatchdog = TimeSpan.FromSeconds(10) });
        var (replayReport, _) = await RunAsync(replayed);

        Assert.Equal(liveReport.Status, replayReport.Status);
        Assert.Equal(liveReport.Cards[0].Rows[0].Values, replayReport.Cards[0].Rows[0].Values);
        Assert.Equal(live.LastResults![0].TestedBytes, replayed.LastResults![0].TestedBytes);
        Assert.True(calls.Snapshot().Count < 200, $"{calls.Snapshot().Count} calls recorded");
    }

    [Fact]
    public async Task A_recorded_driver_reset_replays_as_a_driver_reset()
    {
        var sim = new SimulatedGpuMemory(Discrete()) { LoseAfterRuns = 10 };
        var calls = new CallRecorder();
        await RunAsync(new GpuMemoryModule(new RecordingGpuMemorySource(sim, calls), clockFactory: () => sim.Clock));
        var clock = new FakeStressClock();
        var replayed = new GpuMemoryModule(new TickingSource(new RecordingReplay(calls.Snapshot()).GpuMemorySource, clock), clockFactory: () => clock);
        await RunAsync(replayed);
        Assert.Equal(GpuMemoryOutcome.DriverReset, replayed.LastResults![0].Outcome);
    }

    /// <summary>Advances a fake clock on each dispatch, so a replayed run ends.</summary>
    private sealed class TickingSource(IGpuMemorySource inner, FakeStressClock clock) : IGpuMemorySource
    {
        public IReadOnlyList<GpuMemoryAdapter> ListAdapters() => inner.ListAdapters();
        public IGpuMemoryDevice Open(string adapterId) => new D(inner.Open(adapterId), clock);
        private sealed class D(IGpuMemoryDevice inner, FakeStressClock clock) : IGpuMemoryDevice
        {
            public GpuMemoryAdapter Adapter => inner.Adapter;
            public IReadOnlyList<long> Blocks => inner.Blocks;
            public bool TryAllocateBlock(long bytes) => inner.TryAllocateBlock(bytes);
            public GpuBlockResult Run(int block, GpuMemoryOp op, GpuMemoryPattern pattern, uint seed, bool inverted, uint baseWord)
            {
                clock.Advance(TimeSpan.FromMilliseconds(50));
                return inner.Run(block, op, pattern, seed, inverted, baseWord);
            }
            public void Dispose() => inner.Dispose();
        }
    }

    internal static SensorSnapshot Gpu(double temp) => new(
    [
        new("NVIDIA GeForce RTX 4070", HardwareKind.Gpu, "GPU Core", SensorKind.Temperature, temp, temp, temp, "°C"),
    ], IsElevated: false);

    private static async Task WaitUntil(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++) await Task.Delay(10);
        Assert.True(condition());
    }
}
