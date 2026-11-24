using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios;

/// <summary>Windows Update's local cache answers the BIOS check only while it's recent; an old one never reads as "up to date".</summary>
public sealed class WindowsUpdateCacheAgeTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);

    private static WindowsUpdateBiosProvider Provider(FakeWindowsUpdateClient wua) => new(wua, now: () => Now);

    private static Task<BiosLatestInfo> CheckAsync(WindowsUpdateBiosProvider provider)
    {
        var system = BiosIdentityFactory.GenericUefi();
        return provider.GetLatestVersionAsync(system, system.CurrentBios);
    }

    [Fact]
    public async Task RecentScan_UsesTheCacheOnly()
    {
        var wua = new FakeWindowsUpdateClient { LastScanUtc = Now.AddDays(-2) };
        var latest = await CheckAsync(Provider(wua));
        Assert.Equal(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Equal([false], wua.SearchModes);
    }

    [Fact]
    public async Task OldScan_SearchesOnline_AndTrustsThatAnswer()
    {
        var wua = new FakeWindowsUpdateClient { LastScanUtc = Now.AddDays(-30) };
        var latest = await CheckAsync(Provider(wua));
        Assert.Equal(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Equal([true], wua.SearchModes);
    }

    [Fact]
    public async Task OldScan_OnlineSearchFails_SaysHowOldTheCacheIsInsteadOfUpToDate()
    {
        var wua = new FakeWindowsUpdateClient
        {
            LastScanUtc = Now.AddDays(-23),
            OnlineSearchHandler = _ => throw new TimeoutException("search timed out"),
        };
        var latest = await CheckAsync(Provider(wua));
        Assert.NotEqual(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Contains("23 days ago", latest.Message, StringComparison.Ordinal);
        Assert.Equal("true", latest.Metadata![WindowsUpdateBiosProvider.StaleCacheMetadataKey]);
        Assert.Equal([true, false], wua.SearchModes);
    }

    [Fact]
    public async Task UnknownScanTime_OnlineSearchFails_StillNotUpToDate()
    {
        var wua = new FakeWindowsUpdateClient { OnlineSearchHandler = _ => throw new TimeoutException("search timed out") };
        var latest = await CheckAsync(Provider(wua));
        Assert.NotEqual(BiosCheckStatus.UpToDate, latest.Status);
        Assert.Contains("hasn't reported a finished scan", latest.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SerializedSearch_ThatTimesOut_HoldsTheLockUntilItReallyEnds()
    {
        using var gate = new SemaphoreSlim(1, 1);
        using var release = new ManualResetEventSlim();
        var first = AgentWindowsUpdate.RunSerializedSearchAsync(() => { release.Wait(TimeSpan.FromSeconds(10)); return 1; },
            TimeSpan.FromMilliseconds(100), CancellationToken.None, gate);

        await Assert.ThrowsAsync<TimeoutException>(() => first);
        // The COM search is still running: a second search must wait, not overlap it.
        Assert.Equal(0, gate.CurrentCount);
        await Assert.ThrowsAsync<TimeoutException>(() =>
            AgentWindowsUpdate.RunSerializedSearchAsync(() => 2, TimeSpan.FromMilliseconds(100), CancellationToken.None, gate));

        release.Set();
        Assert.Equal(3, await AgentWindowsUpdate.RunSerializedSearchAsync(() => 3, TimeSpan.FromSeconds(5), CancellationToken.None, gate));
        Assert.Equal(1, gate.CurrentCount);
    }
}
