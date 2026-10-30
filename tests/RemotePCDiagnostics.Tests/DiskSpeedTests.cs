using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>In-memory file system. Records every path touched so tests can prove only the test file/folder are used.</summary>
internal sealed class FakeDiskFs : IDiskTestFileSystem
{
    public const long MB = DiskSpeedOptions.MB, GB = DiskSpeedOptions.GB;
    public long Free = 100 * GB;
    public readonly Dictionary<string, MemoryStream> Files = new(StringComparer.OrdinalIgnoreCase);
    public readonly List<string> Touched = [];
    public readonly List<string> Deleted = [];
    public Func<Stream, Stream>? Wrap;
    public bool ThrowOnOpen;
    public string Folder => Path.Combine("C:", "Temp", "RemotePCDiagnostics.SpeedTest");

    public IReadOnlyList<TestDrive> GetFixedDrives() => [new("C:\\", "Windows", Free, 500 * GB, true), new("D:\\", "Data", Free, 1000 * GB, false)];
    public string GetTestFolder(TestDrive drive) => drive.Root == "C:\\" ? Folder : Path.Combine(drive.Root.TrimEnd('\\'), "RemotePCDiagnostics.SpeedTest");
    public long GetFreeBytes(string driveRoot) => Free;
    public void CreateDirectory(string path) => Touched.Add(path);
    public IEnumerable<string> FindFiles(string directory, string searchPattern) =>
        Files.Keys.Where(k => k.StartsWith(directory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) && Path.GetFileName(k).StartsWith("rpd-speedtest-") && k.EndsWith(".tmp")).ToList();
    public bool FileExists(string path) => Files.ContainsKey(path);
    public void DeleteFile(string path) { Deleted.Add(path); Files.Remove(path); }
    public void DeleteDirectoryIfEmpty(string path) { }
    public Stream OpenTestFile(string path, long length)
    {
        Touched.Add(path);
        if (ThrowOnOpen) throw new IOException("device not ready");
        var ms = new KeepOpenStream(); ms.SetLength(length); Files[path] = ms;
        return Wrap?.Invoke(ms) ?? ms;
    }
}

internal sealed class KeepOpenStream : MemoryStream { protected override void Dispose(bool disposing) { } }

/// <summary>Flips one bit in whatever is read at <paramref name="corruptOffset"/>.</summary>
internal sealed class CorruptingStream(Stream inner, long corruptOffset) : Stream
{
    public override bool CanRead => true; public override bool CanSeek => true; public override bool CanWrite => true;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set => inner.Position = value; }
    public override void Flush() => inner.Flush();
    public override long Seek(long o, SeekOrigin s) => inner.Seek(o, s);
    public override void SetLength(long v) => inner.SetLength(v);
    public override void Write(byte[] b, int o, int c) => inner.Write(b, o, c);
    public override int Read(byte[] b, int o, int c)
    {
        var pos = inner.Position;
        var n = inner.Read(b, o, c);
        if (corruptOffset >= pos && corruptOffset < pos + n) b[o + (int)(corruptOffset - pos)] ^= 0x10;
        return n;
    }
}

public class DiskSpeedTests
{
    private const long MB = DiskSpeedOptions.MB, GB = DiskSpeedOptions.GB;

    private static DiskSpeedOptions Opts(int minutes = 1) => new()
    {
        Duration = TimeSpan.FromMinutes(minutes), RequestedSizeBytes = 64 * MB, MinTestBytes = 4 * MB, SequentialBlockBytes = (int)MB,
        MaxRandomPhase = TimeSpan.FromSeconds(5), SampleInterval = TimeSpan.FromSeconds(1),
        SlowSequentialReadMBps = 0, SlowSequentialWriteMBps = 0, SlowRandomReadIops = 0,
    };

    private static SequenceSensorProvider NoSensors() => new(_ => throw new PlatformNotSupportedException(), available: false);

    private static void AssertCleaned(FakeDiskFs fs, DiskSpeedReport r)
    {
        Assert.Empty(fs.Files);
        Assert.True(r.CleanedUp);
        // Only the dedicated folder and test files inside it were touched.
        Assert.All(fs.Touched.Concat(fs.Deleted), p => Assert.StartsWith(fs.Folder, p));
        Assert.All(fs.Touched.Where(p => p != fs.Folder), p => Assert.Matches(@"[\\/]rpd-speedtest-[0-9a-f]{32}\.tmp$", p));
    }

    [Theory]
    [InlineData(100L * GB, 1L * GB, 1L * GB)]         // plenty of space: requested size
    [InlineData(5L * GB, 1L * GB, 512L * MB)]          // 10% of free
    [InlineData(2304L * MB, 1L * GB, 230L * MB)]       // 10% of 2.25 GB (2 GB reserve leaves 256 MB)
    [InlineData(2100L * MB, 1L * GB, null)]           // keeping 2 GB free leaves under the 64 MB minimum
    [InlineData(1L * GB, 1L * GB, null)]               // below the 2 GB reserve
    public void FreeSpaceGuard(long free, long requested, long? expected)
    {
        var o = new DiskSpeedOptions { RequestedSizeBytes = requested };
        var size = DiskSpeedTest.PlanSize(free, o);
        Assert.Equal(expected, size);
        if (size is { } s) { Assert.True(free - s >= 2 * GB); Assert.True(s <= free / 10); Assert.Equal(0, s % MB); }
    }

    [Fact]
    public void SpeedCalculation()
    {
        Assert.Equal(500, DiskSpeedTest.MBps(1_000_000_000, TimeSpan.FromSeconds(2)));
        Assert.Equal(2000, DiskSpeedTest.Iops(10_000, TimeSpan.FromSeconds(5)));
        Assert.Null(DiskSpeedTest.MBps(100, TimeSpan.Zero));
        Assert.Null(DiskSpeedTest.Iops(0, TimeSpan.FromSeconds(1)));
        Assert.Equal("1,234 MB/s", DiskSpeedReport.Speed(1234.4));
        var o = new DiskSpeedOptions();
        Assert.True(DiskSpeedTest.IsSlow(o, 200, 20, 5000));
        Assert.True(DiskSpeedTest.IsSlow(o, 200, 500, 10));
        Assert.False(DiskSpeedTest.IsSlow(o, 150, 160, 90));
        Assert.False(DiskSpeedTest.IsSlow(o, null, null, null));
    }

    [Fact]
    public void FillPage_IsDeterministicPerPageAndGeneration()
    {
        byte[] a = new byte[4096], b = new byte[4096], c = new byte[4096];
        DiskSpeedTest.FillPage(a, 7, 3, 0); DiskSpeedTest.FillPage(b, 7, 3, 0); DiskSpeedTest.FillPage(c, 7, 3, 1);
        Assert.Equal(a, b); Assert.NotEqual(a, c);
    }

    [Fact]
    public async Task FullRun_Passes_VerifiesData_AndCleansUp()
    {
        var fs = new FakeDiskFs();
        var r = await new DiskSpeedTest(fs, NoSensors(), new FakeStressClock()).RunAsync(Opts());
        Assert.Equal(DiskSpeedOutcome.Passed, r.Outcome);
        Assert.Equal("Passed", r.Headline);
        Assert.Equal(64 * MB, r.TestBytes);
        Assert.True(r.BlocksVerified >= 64 * MB / 4096);
        Assert.Equal(0, r.DataErrors);
        AssertCleaned(fs, r);
    }

    [Fact]
    public async Task Corruption_IsDetected_AndFileStillDeleted()
    {
        var fs = new FakeDiskFs { Wrap = s => new CorruptingStream(s, 5 * MB + 123) };
        var r = await new DiskSpeedTest(fs, NoSensors(), new FakeStressClock()).RunAsync(Opts());
        Assert.Equal(DiskSpeedOutcome.DataErrors, r.Outcome);
        Assert.Equal("Data errors found", r.Headline);
        Assert.True(r.DataErrors >= 1);
        Assert.Equal(DiagnosticStatus.Error, DiskSpeedModule.ToStatus(r.Outcome));
        AssertCleaned(fs, r);
    }

    [Fact]
    public async Task LowFreeSpace_RefusesWithoutCreatingAnything()
    {
        var fs = new FakeDiskFs { Free = 2 * GB };
        var r = await new DiskSpeedTest(fs, NoSensors(), new FakeStressClock()).RunAsync(Opts() with { RequestedSizeBytes = GB, MinTestBytes = 64 * MB });
        Assert.Equal(DiskSpeedOutcome.NotEnoughSpace, r.Outcome);
        Assert.Equal("Not enough free space to test", r.Headline);
        Assert.Empty(fs.Touched);
    }

    [Fact]
    public async Task StaleLeftovers_AreRemoved_OtherFilesUntouched()
    {
        var fs = new FakeDiskFs();
        var stale = Path.Combine(fs.Folder, "rpd-speedtest-0123456789abcdef0123456789abcdef.tmp");
        var other = Path.Combine(fs.Folder, "notes.txt");
        fs.Files[stale] = new KeepOpenStream(); fs.Files[other] = new KeepOpenStream();
        await new DiskSpeedTest(fs, NoSensors(), new FakeStressClock()).RunAsync(Opts());
        Assert.False(fs.Files.ContainsKey(stale));
        Assert.True(fs.Files.ContainsKey(other));
        Assert.DoesNotContain(other, fs.Deleted);
    }

    [Fact]
    public async Task IoError_IsFailed_AndCleanupStillRuns()
    {
        var fs = new FakeDiskFs { ThrowOnOpen = true };
        var r = await new DiskSpeedTest(fs, NoSensors(), new FakeStressClock()).RunAsync(Opts());
        Assert.Equal(DiskSpeedOutcome.Failed, r.Outcome);
        Assert.Equal("Couldn't finish the test", r.Headline);
        AssertCleaned(fs, r);
    }

    [Fact]
    public async Task StopToken_StopsEarly_AndCleansUp()
    {
        var fs = new FakeDiskFs();
        using var cts = new CancellationTokenSource();
        int n = 0;
        var r = await new DiskSpeedTest(fs, NoSensors(), new FakeStressClock())
            .RunAsync(Opts() with { RequestedSizeBytes = 256 * MB, MinTestBytes = 4 * MB }, new SyncProgress<DiskSpeedProgress>(_ => { if (++n == 2) cts.Cancel(); }), cts.Token);
        Assert.Equal(DiskSpeedOutcome.StoppedByUser, r.Outcome);
        Assert.Equal("Stopped by you", r.Headline);
        AssertCleaned(fs, r);
    }

    [Fact]
    public async Task CriticalTemperature_Aborts_AndCleansUp()
    {
        var fs = new FakeDiskFs();
        // Samsung 990 PRO critical is 70°C (SensorThresholds.Ssd); second read is critical.
        var sensors = new SequenceSensorProvider(i => new SensorSnapshot(
        [
            new("Samsung SSD 990 PRO 2TB NVMe", HardwareKind.Storage, "Temperature", SensorKind.Temperature, i >= 2 ? 71 : 45, 40, 71, "°C"),
            new("Nuvoton", HardwareKind.Motherboard, "Fan #1", SensorKind.Fan, 900, 900, 900, "RPM"),
        ], true));
        var r = await new DiskSpeedTest(fs, sensors, new FakeStressClock()).RunAsync(Opts() with { RequestedSizeBytes = 256 * MB, MinTestBytes = 4 * MB });
        Assert.Equal(DiskSpeedOutcome.Overheated, r.Outcome);
        Assert.Equal("Stopped: drive got too hot", r.Headline);
        Assert.Equal(71, r.MaxDriveTemperatureC);
        AssertCleaned(fs, r);
    }

    [Fact]
    public async Task TimeLimit_EndsRun()
    {
        var fs = new FakeDiskFs();
        var clock = new FakeStressClock();
        var r = await new DiskSpeedTest(fs, NoSensors(), clock).RunAsync(Opts() with { MaxRandomPhase = TimeSpan.FromMinutes(10) });
        Assert.NotEqual(DiskSpeedOutcome.StoppedByUser, r.Outcome);
        Assert.InRange(r.Ran, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(2));
        AssertCleaned(fs, r);
    }

    [Fact]
    public async Task Module_IsExcludedFromRunAll_AndUsesChosenDrive()
    {
        var fs = new FakeDiskFs();
        var m = new DiskSpeedModule(fs, NoSensors(), clockFactory: () => new FakeStressClock()) { Options = Opts() };
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m, new FakeModule("Other", _ => Task.FromResult(FakeModule.Ok("Other")))]);
        Assert.Single(await svc.RunAllAsync());
        Assert.Equal(DiagnosticStatus.NotRun, store.Get(DiskSpeedModule.ModuleName).Status);
        Assert.Equal(2, m.ListDrives().Count);

        m.DriveRoot = "D:\\"; m.SizeBytes = 8 * MB;
        var r = await svc.RunAsync(DiskSpeedModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("Data (D:)", ((DiskSpeedReport)r.Payload!).Drive);
        Assert.Contains(fs.Touched, p => p.StartsWith(Path.Combine("D:", "RemotePCDiagnostics.SpeedTest") + Path.DirectorySeparatorChar));
        Assert.Empty(fs.Files);
    }
}
