using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Tests;

public class AppLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpd-log-" + Guid.NewGuid().ToString("N"));
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public void Write_CreatesFolderAndAppendsLines()
    {
        var log = new RollingFileLog(Path.Combine(_dir, "sub", "app.log"));
        log.Write("one"); log.Write("two");
        Assert.Equal(["one", "two"], File.ReadAllLines(log.Path));
    }

    [Fact]
    public void Rolls_WhenFull_KeepsOnlyTheNewestBackups()
    {
        var log = new RollingFileLog(Path.Combine(_dir, "app.log"), maxBytes: 100, keep: 2);
        for (int i = 0; i < 40; i++) log.Write($"line {i:D3} " + new string('x', 30));
        Assert.True(File.Exists(log.Path));
        Assert.True(File.Exists(log.BackupPath(1)));
        Assert.True(File.Exists(log.BackupPath(2)));
        Assert.False(File.Exists(log.BackupPath(3)));
        Assert.Contains("line 039", File.ReadAllText(log.Path));
        Assert.True(new FileInfo(log.Path).Length < 400);
    }

    [Fact]
    public void Write_NeverThrows_OnBadPath()
    {
        var blocker = Path.Combine(_dir, "file");
        Directory.CreateDirectory(_dir);
        File.WriteAllText(blocker, "x");
        new RollingFileLog(Path.Combine(blocker, "sub", "app.log")).Write("hello");
    }

    [Theory]
    [InlineData("Unhandled: boom", LogLevel.Error)]
    [InlineData("Stress suite: MemoryTest skipped (The test stopped responding)", LogLevel.Warning)]
    [InlineData("LibreHardwareMonitor open failed: x", LogLevel.Warning)]
    [InlineData("Memory test: helper overran the time limit; killing it", LogLevel.Warning)]
    [InlineData("CPU stress: checksum mismatch thread=1", LogLevel.Warning)]
    [InlineData("System.InvalidOperationException: bad", LogLevel.Error)]
    [InlineData("Stress suite: CpuStress skipped (unavailable: no)", LogLevel.Information)]
    [InlineData("Memory test: start bytes=1 duration=00:01:00", LogLevel.Information)]
    [InlineData("", LogLevel.Information)]
    public void Classify_ReadsLevelFromText(string text, LogLevel expected) => Assert.Equal(expected, LogLevels.Classify(text));

    [Fact]
    public void Gate_LetsSameTextThroughOncePerWindow_AndCapsPerMinute()
    {
        var t = DateTimeOffset.Parse("2026-11-04T12:00:00Z");
        var gate = new EventLogGate(() => t, TimeSpan.FromMinutes(5), maxPerMinute: 3);
        Assert.True(gate.Allow("a"));
        Assert.False(gate.Allow("a"));
        Assert.True(gate.Allow("b")); Assert.True(gate.Allow("c"));
        Assert.False(gate.Allow("d"));
        t = t.AddSeconds(61);
        Assert.True(gate.Allow("d"));
        Assert.False(gate.Allow("a"));
        t = t.AddMinutes(6);
        Assert.True(gate.Allow("a"));
    }
}
