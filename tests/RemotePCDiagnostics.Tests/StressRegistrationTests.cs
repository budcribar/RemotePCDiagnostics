using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>Each stress test registers what it holds with the <see cref="StressCleanup"/> the runner calls afterwards.</summary>
public class StressRegistrationTests
{
    [Fact]
    public async Task MemoryTest_RegistersHelperKill()
    {
        const long MB = 1024 * 1024, GB = 1024 * MB;
        var launcher = new FakeHelperLauncher(h => { h.Send(new MemTestMessage.Allocated(1600 * MB)); h.Send(new MemTestMessage.Done(1600 * MB, 3, 0)); h.Exit(); });
        var cleanup = new StressCleanup();
        var o = new MemoryTestOptions { Duration = TimeSpan.FromMinutes(1), SampleInterval = TimeSpan.FromSeconds(1), Grace = TimeSpan.FromSeconds(30) };
        await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false), new FakeStressClock(), null, cleanup).RunAsync(o);
        Assert.False(launcher.Helper.Killed);
        await cleanup.RunAsync();
        Assert.True(launcher.Helper.Killed);
    }

    [Fact]
    public async Task DiskTest_RegistersTestFileDelete()
    {
        var fs = new FakeDiskFs();
        var cleanup = new StressCleanup();
        var o = new DiskSpeedOptions { Duration = TimeSpan.FromMinutes(1), RequestedSizeBytes = 64 * DiskSpeedOptions.MB, MinTestBytes = 64 * DiskSpeedOptions.MB };
        await new DiskSpeedTest(fs, new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false), new FakeStressClock(), null, cleanup).RunAsync(o);
        var path = fs.Touched.Last();
        fs.Files[path] = new KeepOpenStream(); // as if a hung test never got to delete it
        await cleanup.RunAsync();
        Assert.False(fs.Files.ContainsKey(path));
    }

    [Fact]
    public async Task CpuTest_RegistersWorkerStop_AndCleanupIsHarmless()
    {
        var cleanup = new StressCleanup();
        var o = new CpuStressOptions { Duration = TimeSpan.FromSeconds(5), Threads = 1, SampleInterval = TimeSpan.FromSeconds(1) };
        await new CpuStressTest(SequenceSensorProvider.Unavail(), new FakeStressClock(), null, null, cleanup).RunAsync(o);
        Assert.Equal(1, cleanup.Pending);
        await cleanup.RunAsync();
        Assert.Equal(0, cleanup.Pending);
    }

    [Fact]
    public async Task NetworkTest_RegistersCleanup_StopsActiveTransfers_AndPostRunCleanupIsHarmless()
    {
        var cleanup = new StressCleanup();
        var o = new NetworkTestOptions { Duration = TimeSpan.FromSeconds(10), Interval = TimeSpan.FromSeconds(1), SpeedTestDelay = TimeSpan.FromSeconds(1) };
        var test = new NetworkTest(new FakePinger((_, _) => 10), new FakeGateway("192.168.1.1"), new FakeSpeed(),
            new FakeCounters(new AdapterTotals(0, 0), new AdapterTotals(0, 0)), SequenceSensorProvider.Unavail(), null, new FakeStressClock(), null, cleanup);
        var finished = await test.RunAsync(o);
        Assert.Equal(NetworkTestOutcome.Stable, finished.Outcome);
        Assert.Equal(1, cleanup.Pending);
        await cleanup.RunAsync();
        Assert.Equal(0, cleanup.Pending);

        var downloadStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blockingSpeed = new BlockingSpeedTester(downloadStarted);
        var activeCleanup = new StressCleanup();
        var running = new NetworkTest(new FakePinger((_, _) => 10), new FakeGateway("192.168.1.1"), blockingSpeed,
            new FakeCounters(new AdapterTotals(0, 0)), SequenceSensorProvider.Unavail(), null, new FakeStressClock(), null, activeCleanup)
            .RunAsync(o with { Duration = TimeSpan.FromMinutes(1), SpeedTestDelay = TimeSpan.Zero });
        await downloadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await activeCleanup.RunAsync();
        var cancelled = await running.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(NetworkTestOutcome.StoppedByUser, cancelled.Outcome);
        Assert.True(blockingSpeed.DownloadCancelled);
    }

    private sealed class BlockingSpeedTester(TaskCompletionSource started) : ISpeedTester
    {
        public bool DownloadCancelled;
        public async Task<TransferResult> DownloadAsync(long maxBytes, TimeSpan timeout, CancellationToken ct)
        {
            started.TrySetResult();
            try { await Task.Delay(Timeout.Infinite, ct); }
            catch (OperationCanceledException) { DownloadCancelled = true; throw; }
            return new TransferResult(0, TimeSpan.Zero);
        }
        public Task<TransferResult> UploadAsync(long bytes, TimeSpan timeout, CancellationToken ct) =>
            Task.FromResult(new TransferResult(0, TimeSpan.Zero));
    }
}
