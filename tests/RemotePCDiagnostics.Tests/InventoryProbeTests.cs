using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

public class InventoryProbeTests
{
    [Theory]
    [InlineData(1, "0", "access denied", false)]
    [InlineData(0, "0", "partial enumeration failed", false)]
    [InlineData(0, "0", "", true)]
    [InlineData(0, "", "", false)]
    [InlineData(0, "-1", "", false)]
    [InlineData(0, "0\n12", "", false)]
    public async Task FailedCategoryIsUnknownWhileOtherCategoriesRemainMeasured(int exit, string output, string error, bool timedOut)
    {
        var launcher = new ScriptedLauncher((_, args) => args[^1].Contains("Get-ScheduledTask")
            ? new ProcessResult(exit, output, error, timedOut) : ScriptedLauncher.Ok("7"));
        var snapshot = await InventoryProbe.ReadAsync(new SystemCommandRunner(launcher), default);
        Assert.Null(snapshot.ActiveScheduledTasks);
        Assert.Equal(7, snapshot.AutoVendorServices);
        Assert.Equal(7, snapshot.InstalledBloatwareApps);
        var before = new BenchmarkRun(BenchmarkPhase.Before, DateTimeOffset.UtcNow, new(null, null),
            [new(BenchmarkKind.ActiveScheduledTasks, [12])]);
        var after = new BenchmarkRun(BenchmarkPhase.After, DateTimeOffset.UtcNow, new(null, null),
            [new(BenchmarkKind.ActiveScheduledTasks, snapshot.ActiveScheduledTasks is { } n ? [n] : [], "not available")]);
        Assert.Equal(BenchmarkVerdict.NotMeasured, BenchmarkComparison.Build(before, after).Deltas.Single().Verdict);
    }

    [Theory]
    [InlineData("0", 0)]
    [InlineData("1\r\n", 1)]
    public async Task SuccessfulEmptyAndSingletonQueriesAreValidCounts(string output, int expected)
    {
        var launcher = new ScriptedLauncher((_, args) =>
        {
            Assert.Contains("$ErrorActionPreference='Stop'", args[^1]);
            Assert.Contains("$items=@(", args[^1]);
            Assert.Contains("-ErrorAction Stop", args[^1]);
            return ScriptedLauncher.Ok(output);
        });
        var snapshot = await InventoryProbe.ReadAsync(new SystemCommandRunner(launcher), default);
        Assert.Equal(expected, snapshot.AutoVendorServices);
        Assert.Equal(expected, snapshot.ActiveScheduledTasks);
        Assert.Equal(expected, snapshot.InstalledBloatwareApps);
    }

    [Fact]
    public async Task CancellationPropagates()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var launcher = new ScriptedLauncher((_, _) => throw new Exception("Must not launch"));
        await Assert.ThrowsAsync<OperationCanceledException>(() => InventoryProbe.ReadAsync(new SystemCommandRunner(launcher), cts.Token));
        Assert.Empty(launcher.Calls);
    }
}
