using System.Threading.Channels;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

internal sealed class FakeMemoryInfo(long available, long total = 16 * MemorySizing.GB) : IMemoryInfo
{
    public (long Available, long Total) Read() => (available, total);
}

/// <summary>Scripted helper: lines are pushed by the test; Kill closes the output like a killed process.</summary>
internal sealed class FakeHelper : IMemTestHelperProcess
{
    public readonly Channel<string> Lines = Channel.CreateUnbounded<string>();
    public bool Killed;
    public void Send(MemTestMessage m) => Lines.Writer.TryWrite(m.Format());
    public void Exit() => Lines.Writer.TryComplete();
    public async Task<string?> ReadLineAsync(CancellationToken ct)
    {
        while (await Lines.Reader.WaitToReadAsync(ct)) if (Lines.Reader.TryRead(out var l)) return l;
        return null;
    }
    public void Kill() { Killed = true; Exit(); }
    public int? ExitCode => Killed ? -1 : 0;
    public void Dispose() { }
}

internal sealed class FakeHelperLauncher(Action<FakeHelper>? script = null) : IMemTestHelperLauncher
{
    public readonly FakeHelper Helper = new();
    public long? Bytes; public TimeSpan? Duration;
    public bool Throw;
    public IMemTestHelperProcess Start(long bytes, TimeSpan duration)
    {
        if (Throw) throw new FileNotFoundException("helper missing");
        Bytes = bytes; Duration = duration;
        script?.Invoke(Helper);
        return Helper;
    }
}

internal sealed class FakeMdsched : IWindowsMemoryDiagnosticLauncher { public int Calls; public bool Launch() { Calls++; return true; } }

public class MemoryTestTests
{
    private const long MB = MemorySizing.MB, GB = MemorySizing.GB;
    private static readonly MemoryTestOptions Opts = new() { Duration = TimeSpan.FromMinutes(1), SampleInterval = TimeSpan.FromSeconds(1), Grace = TimeSpan.FromSeconds(30) };
    private static SequenceSensorProvider NoSensors() => new(_ => throw new PlatformNotSupportedException(), available: false);

    // ---- patterns ----
    [Theory]
    [InlineData(MemoryPattern.Zeros)] [InlineData(MemoryPattern.Ones)] [InlineData(MemoryPattern.Alternating10)]
    [InlineData(MemoryPattern.Alternating01)] [InlineData(MemoryPattern.WalkingOnes)]
    public void Pattern_VerifiesClean_AndCatchesFlippedBit(MemoryPattern p)
    {
        var w = new ulong[1000];
        MemoryPatterns.Fill(w, p, 128);
        Assert.Equal(0, MemoryPatterns.Verify(w, p, 128));
        w[517] ^= 1UL << 33;
        var bad = new List<(long, ulong, ulong)>();
        Assert.Equal(1, MemoryPatterns.Verify(w, p, 128, (i, e, a) => bad.Add((i, e, a))));
        Assert.Equal(128 + 517, bad[0].Item1);
        Assert.Equal(MemoryPatterns.Expected(p, 128 + 517), bad[0].Item2);
    }

    [Fact]
    public void Patterns_HaveExpectedValues()
    {
        Assert.Equal(0UL, MemoryPatterns.Expected(MemoryPattern.Zeros, 5));
        Assert.Equal(ulong.MaxValue, MemoryPatterns.Expected(MemoryPattern.Ones, 5));
        Assert.Equal(0xAAAAAAAAAAAAAAAAUL, MemoryPatterns.Expected(MemoryPattern.Alternating10, 5));
        Assert.Equal(0x5555555555555555UL, MemoryPatterns.Expected(MemoryPattern.Alternating01, 5));
        Assert.Equal(1UL << 5, MemoryPatterns.Expected(MemoryPattern.WalkingOnes, 69));
        var w = new ulong[64]; MemoryPatterns.Fill(w, MemoryPattern.WalkingOnes, 0);
        Assert.All(Enumerable.Range(0, 64), i => Assert.Equal(1UL << i, w[i]));
    }

    [Fact]
    public void Sweep_CatchesFlippedBit_AndReportsOffset()
    {
        var blocks = new IMemoryBlock[] { new ArrayMemoryBlock(4096), new ArrayMemoryBlock(4096) };
        var msgs = new List<MemTestMessage>();
        int fills = 0;
        var sweep = new MemorySweep(blocks, () => fills >= 5, msgs.Add)
        {
            AfterFill = p => { fills++; if (p == MemoryPattern.Alternating10) blocks[1].Words[10] ^= 4; },
        };
        var done = sweep.Run();
        Assert.Equal(1, done.Errors);
        Assert.Equal(1, done.Passes);
        Assert.Equal(2 * 4096 * 8, done.Bytes);
        var bad = Assert.Single(msgs.OfType<MemTestMessage.BadWord>());
        Assert.Equal((4096 + 10) * 8, bad.Offset);
        Assert.Same(done, msgs[^1]);
    }

    [Fact]
    public void Sweep_StopsAtDeadline()
    {
        int checks = 0;
        var done = new MemorySweep([new ArrayMemoryBlock(1024)], () => ++checks > 2, _ => { }).Run();
        Assert.Equal(0, done.Passes); // stopped mid first pattern: nothing fully checked
        Assert.Equal(0, done.Errors);
    }

    // ---- sizing ----
    [Theory]
    [InlineData(16L * GB, MemoryTestMode.Quick, 1600L * MB)]      // 10% of available, below 2 GB cap: 1638.4 MB → 1600 MB (64 MB chunks)
    [InlineData(64L * GB, MemoryTestMode.Quick, 2048L * MB)]      // capped at 2 GB
    [InlineData(16L * GB, MemoryTestMode.Full, 13056L * MB)]      // 80%: 13107 MB → 13056 MB
    [InlineData(4L * GB, MemoryTestMode.Full, 2048L * MB)]        // leave 2 GB free wins over 80%
    [InlineData(2L * GB, MemoryTestMode.Full, 256L * MB)]         // nothing left after the reserve → low-memory floor
    [InlineData(1050L * MB, MemoryTestMode.Quick, 256L * MB)]     // quick reserve leaves too little → floor
    [InlineData(400L * MB, MemoryTestMode.Quick, 256L * MB)]      // IdeaPad case (~400 MB free): still tests 256 MB
    [InlineData(384L * MB, MemoryTestMode.Full, 256L * MB)]       // exactly floor + 128 MB reserve
    [InlineData(383L * MB, MemoryTestMode.Quick, null)]           // below that: can't run
    [InlineData(0L, MemoryTestMode.Quick, null)]
    public void Sizing(long available, MemoryTestMode mode, long? expected)
    {
        var s = MemorySizing.Plan(available, mode);
        Assert.Equal(expected, s);
        if (s is { } v) { Assert.Equal(0, v % MemorySizing.ChunkBytes); Assert.True(available - v >= (v == MemorySizing.FloorBytes ? MemorySizing.LowMemoryReserve : mode == MemoryTestMode.Full ? 2 * GB : GB)); }
    }

    // ---- protocol ----
    [Fact]
    public void Protocol_RoundTrips_AndIgnoresGarbage()
    {
        MemTestMessage[] all =
        [
            new MemTestMessage.Allocated(123456), new MemTestMessage.Progress(2, "WalkingOnes", 0.5, 3),
            new MemTestMessage.BadWord(4096, 0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAE), new MemTestMessage.Done(1 << 30, 4, 0), new MemTestMessage.Fail("could not allocate memory"),
        ];
        foreach (var m in all) Assert.Equal(m, MemTestMessage.Parse(m.Format()));
        Assert.Equal("MT DONE 1073741824 4 0", new MemTestMessage.Done(1 << 30, 4, 0).Format());
        Assert.Null(MemTestMessage.Parse(null));
        Assert.Null(MemTestMessage.Parse("hello"));
        Assert.Null(MemTestMessage.Parse("MT PROGRESS x y"));
        Assert.Null(MemTestMessage.Parse("MT DONE 1 2 notanumber"));
        Assert.Null(MemTestMessage.Parse("MT WHAT 1"));
        Assert.Equal("--bytes 1024 --seconds 61", ProcessMemTestHelperLauncher.Arguments(1024, TimeSpan.FromSeconds(60.5)));
    }

    // ---- orchestration ----
    [Fact]
    public async Task HelperDone_Passes()
    {
        var launcher = new FakeHelperLauncher(h => { h.Send(new MemTestMessage.Allocated(1600 * MB)); h.Send(new MemTestMessage.Progress(0, "Zeros", 0.5, 0)); h.Send(new MemTestMessage.Done(1600 * MB, 3, 0)); h.Exit(); });
        var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, NoSensors(), new FakeStressClock()).RunAsync(Opts);
        Assert.Equal(MemoryTestOutcome.Passed, r.Outcome);
        Assert.Equal("Passed", r.Headline);
        Assert.Equal(1600 * MB, launcher.Bytes);
        Assert.Equal(TimeSpan.FromMinutes(1), launcher.Duration);
        Assert.Equal(3, r.Passes);
        Assert.False(launcher.Helper.Killed);
    }

    [Fact]
    public async Task HelperReportsErrors_MemoryErrorsFound()
    {
        var launcher = new FakeHelperLauncher(h => { h.Send(new MemTestMessage.BadWord(8, 0, 4)); h.Send(new MemTestMessage.Done(GB, 1, 2)); h.Exit(); });
        var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, NoSensors(), new FakeStressClock()).RunAsync(Opts);
        Assert.Equal(MemoryTestOutcome.MemoryErrors, r.Outcome);
        Assert.Equal("Memory errors found", r.Headline);
        Assert.Contains("2 spots", r.Explanation);
        Assert.Equal(DiagnosticStatus.Error, MemoryTestModule.ToStatus(r.Outcome));
    }

    [Fact]
    public async Task HelperCrash_CouldNotFinish()
    {
        var launcher = new FakeHelperLauncher(h => { h.Send(new MemTestMessage.Progress(0, "Ones", 0.2, 0)); h.Exit(); });
        var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, NoSensors(), new FakeStressClock()).RunAsync(Opts);
        Assert.Equal(MemoryTestOutcome.Failed, r.Outcome);
        Assert.Equal("Couldn't finish the test", r.Headline);
    }

    [Fact]
    public async Task HelperMissing_OrTooLittleMemory_CouldNotRun_NotAHardwareProblem()
    {
        var r1 = await new MemoryTest(new FakeMemoryInfo(16 * GB), new FakeHelperLauncher { Throw = true }, NoSensors(), new FakeStressClock()).RunAsync(Opts);
        Assert.Equal(MemoryTestOutcome.CouldNotRun, r1.Outcome);
        Assert.Contains("helper couldn't start", r1.Notice);
        Assert.Equal(DiagnosticStatus.Warning, MemoryTestModule.ToStatus(r1.Outcome));
        var launcher = new FakeHelperLauncher();
        var r2 = await new MemoryTest(new FakeMemoryInfo(300 * MB, 16 * GB), launcher, NoSensors(), new FakeStressClock()).RunAsync(Opts);
        Assert.Equal(MemoryTestOutcome.CouldNotRun, r2.Outcome);
        Assert.True(r2.LowMemory);
        Assert.Null(launcher.Bytes); // never started
        Assert.Equal("Couldn't run: not enough free memory", r2.Headline);
        Assert.StartsWith("The memory test couldn't run: not enough free memory. Close some programs and try again.", r2.Explanation);
        Assert.DoesNotContain("problem", r2.Headline + r2.Explanation);
        Assert.Equal(300 * MB, r2.AvailableBytes);
        Assert.Equal(16 * GB, r2.TotalBytes);
        Assert.Contains("300 MB free of 16,384 MB", r2.Notice);
    }

    [Fact]
    public async Task HelperCouldNotAllocate_IsLowMemory_CouldNotRun()
    {
        var launcher = new FakeHelperLauncher(h => { h.Send(new MemTestMessage.Fail("could not allocate memory")); h.Exit(); });
        var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, NoSensors(), new FakeStressClock()).RunAsync(Opts);
        Assert.Equal(MemoryTestOutcome.CouldNotRun, r.Outcome);
        Assert.True(r.LowMemory);
        Assert.Contains("could not allocate memory", r.Notice);
    }

    [Fact]
    public async Task EventLogMeasurements_CarryTheExactReason()
    {
        var r = await new MemoryTest(new FakeMemoryInfo(300 * MB, 16 * GB), new FakeHelperLauncher(), NoSensors(), new FakeStressClock()).RunAsync(Opts);
        var ms = RemotePCDiagnostics.Core.Logging.ResultEventLogger.Measurements(r).ToDictionary(x => x.Name, x => x.Value);
        Assert.Equal("CouldNotRun", ms["Outcome"]);
        Assert.Equal((300 * MB).ToString(), ms["AvailableBytes"]);
        Assert.Equal((16 * GB).ToString(), ms["TotalBytes"]);
        Assert.Equal("0", ms["PlannedBytes"]);
        Assert.Contains("not enough free memory", ms["Notice"]);

        var crash = await new MemoryTest(new FakeMemoryInfo(16 * GB), new FakeHelperLauncher(h => { h.Send(new MemTestMessage.Progress(0, "Ones", 0.2, 0)); h.Exit(); }),
            NoSensors(), new FakeStressClock()).RunAsync(Opts);
        var cm = RemotePCDiagnostics.Core.Logging.ResultEventLogger.Measurements(crash).ToDictionary(x => x.Name, x => x.Value);
        Assert.Equal(MemorySizing.Plan(16 * GB, MemoryTestMode.Quick).ToString(), cm["PlannedBytes"]);
        Assert.Contains("exited before finishing", cm["Notice"]);
    }

    [Fact]
    public async Task Stop_KillsHelper()
    {
        var launcher = new FakeHelperLauncher(h => h.Send(new MemTestMessage.Allocated(GB)));
        using var cts = new CancellationTokenSource();
        int n = 0;
        var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, NoSensors(), new FakeStressClock())
            .RunAsync(Opts, new SyncProgress<MemoryTestProgress>(_ => { if (++n == 3) cts.Cancel(); }), cts.Token);
        Assert.Equal(MemoryTestOutcome.StoppedByUser, r.Outcome);
        Assert.Equal("Stopped by you", r.Headline);
        Assert.True(launcher.Helper.Killed);
    }

    [Fact]
    public async Task TimeLimitOverrun_KillsHelper()
    {
        var launcher = new FakeHelperLauncher(); // helper never finishes on its own
        var clock = new FakeStressClock();
        var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, NoSensors(), clock).RunAsync(Opts);
        Assert.True(launcher.Helper.Killed);
        Assert.Equal(MemoryTestOutcome.Failed, r.Outcome);
        Assert.InRange(r.Ran, TimeSpan.FromSeconds(90), TimeSpan.FromSeconds(92));
    }

    [Fact]
    public async Task CriticalTemperature_KillsHelper()
    {
        var sensors = new SequenceSensorProvider(i => SequenceSensorProvider.Cpu(i >= 3 ? 99 : 70));
        var launcher = new FakeHelperLauncher(h => h.Send(new MemTestMessage.Allocated(GB)));
        var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, sensors, new FakeStressClock()).RunAsync(Opts);
        Assert.Equal(MemoryTestOutcome.Overheated, r.Outcome);
        Assert.Equal("Stopped: too hot", r.Headline);
        Assert.Equal(99, r.MaxCpuTemperatureC);
        Assert.True(launcher.Helper.Killed);
    }

    [Fact]
    public async Task Module_ExcludedFromRunAll_AndWindowsDiagnosticOnlyOnRequest()
    {
        var mdsched = new FakeMdsched();
        var launcher = new FakeHelperLauncher(h => { h.Send(new MemTestMessage.Done(GB, 1, 0)); h.Exit(); });
        var m = new MemoryTestModule(new FakeMemoryInfo(64 * GB), launcher, NoSensors(), mdsched, clockFactory: () => new FakeStressClock()) { Options = Opts };
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m, new FakeModule("Other", _ => Task.FromResult(FakeModule.Ok("Other")))]);
        Assert.Single(await svc.RunAllAsync());
        Assert.Equal(DiagnosticStatus.NotRun, store.Get(MemoryTestModule.ModuleName).Status);
        Assert.Null(launcher.Bytes);
        Assert.Equal(0, mdsched.Calls);

        m.Mode = MemoryTestMode.Full;
        Assert.Equal(MemorySizing.Plan(64 * GB, MemoryTestMode.Full), m.PlannedBytes(MemoryTestMode.Full));
        var r = await svc.RunAsync(MemoryTestModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(MemorySizing.Plan(64 * GB, MemoryTestMode.Full), launcher.Bytes);
        Assert.Equal(0, mdsched.Calls);

        Assert.True(m.LaunchWindowsMemoryDiagnostic());
        Assert.Equal(1, mdsched.Calls);
    }

    [Fact]
    public async Task RealHelperLauncher_MissingHelper_IsFriendlyFailure()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), new ProcessMemTestHelperLauncher(dir), NoSensors(), new FakeStressClock()).RunAsync(Opts);
            Assert.Equal(MemoryTestOutcome.CouldNotRun, r.Outcome);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task RealHelperProcess_RunsSweep_AndReportsDone()
    {
        // 1.2 GB "available" → Quick's plan is under the floor, so it tests 256 MB; the real helper runs for ~3 s.
        var logs = new List<string>();
        var test = new MemoryTest(new FakeMemoryInfo(1229 * MB), new ProcessMemTestHelperLauncher(AppContext.BaseDirectory), NoSensors(), log: new LineLogger(l => { lock (logs) logs.Add(l); }));
        var r = await test.RunAsync(new MemoryTestOptions { Mode = MemoryTestMode.Quick, Duration = TimeSpan.FromSeconds(3), SampleInterval = TimeSpan.FromMilliseconds(200) });
        Assert.True(r.Outcome == MemoryTestOutcome.Passed, string.Join("\n", logs));
        Assert.Equal(256 * MB, r.TestBytes);
        Assert.True(r.Passes >= 1);
        Assert.Equal(0, r.Errors);
    }

    [Fact]
    public async Task RealHelperProcess_StopKillsIt()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var test = new MemoryTest(new FakeMemoryInfo(1229 * MB), new ProcessMemTestHelperLauncher(AppContext.BaseDirectory), NoSensors());
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = await test.RunAsync(new MemoryTestOptions { Mode = MemoryTestMode.Quick, Duration = TimeSpan.FromMinutes(5), SampleInterval = TimeSpan.FromMilliseconds(200) }, null, cts.Token);
        Assert.Equal(MemoryTestOutcome.StoppedByUser, r.Outcome);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20));
    }
}
