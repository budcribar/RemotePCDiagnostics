using Bunit;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Storage;
using RemotePCDiagnostics.Modules.DiskSurfaceScan;

namespace RemotePCDiagnostics.Tests;

/// <summary>The surface scan's page part: the mode for the next run, and each disk's surface map from the last run's report.</summary>
public sealed class DiskSurfaceScanDetailsTests : BunitContext
{
    private sealed class NoWmi : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string ns, string wql, CancellationToken ct = default) => Task.FromResult(WmiQueryResult.Failed(ns, wql, "none"));
    }

    private sealed class NoScans : IDiskScanSource
    {
        public Task<DiskScanAnswer> SendAsync(DiskScanRequest request, CancellationToken ct) => Task.FromResult(new DiskScanAnswer(null, "none"));
    }

    private static DiagnosticResult Result()
    {
        var map = new string('o', 40) + "s" + new string('o', 20) + "x" + "r" + new string('o', 37);
        var status = new DiskScanStatus
        {
            Disk = 0, Mode = "quick", State = DiskScanStatus.Finished, SizeBytes = 512L << 30, SectorBytes = 512, Media = "SSD", SlowMs = 50,
            Planned = 1003, Read = 1003, Unreadable = 1, Retried = 1, Slow = 1, MaxLatencyMs = 61, AverageLatencyMs = 2.4, BytesRead = 1000L << 20,
            ElapsedSeconds = 41, Map = map,
            BadBlocks = [new(523_456_789, 8, 23, "data error (CRC)", "Partition 3 (C:)")],
        };
        var report = DiskSurfaceScanModule.BuildReport(status, "Samsung SSD 980, 512 GB (C:)", "disk0");
        return new DiagnosticResult<AreaReport>(DiskSurfaceScanModule.ModuleName, report.Status, report.Summary, DateTimeOffset.Now, report);
    }

    [Fact]
    public void Draws_each_disks_surface_map_from_the_report_and_sets_the_next_runs_mode()
    {
        var module = new DiskSurfaceScanModule(new NoWmi(), new NoScans());
        var cut = Render<DiskSurfaceScanDetails>(p => p.Add(x => x.DiagnosticModule, module).AddCascadingValue(ModuleDetails.LastResult, Result()));

        var map = cut.Find("[data-testid='surface-map-disk0'] .surface-map");
        Assert.Equal(DiskSurfaceMap.Bins, map.QuerySelectorAll(".surface-bin").Length);
        Assert.Single(map.QuerySelectorAll(".bin-bad"));
        Assert.Single(map.QuerySelectorAll(".bin-retried"));
        Assert.Single(map.QuerySelectorAll(".bin-slow"));
        Assert.Empty(cut.FindAll("[data-testid='surface-scan-limit']"));

        cut.Find("[data-testid='surface-scan-mode']").Change("full");
        Assert.Equal(DiskScanMode.Full, module.Mode);
        cut.Find("[data-testid='surface-scan-limit']").Change("60");
        Assert.Equal(60, module.TimeLimitMinutes);

        if (Environment.GetEnvironmentVariable("RPCD_SURFACE_MARKUP") is { Length: > 0 } path) File.WriteAllText(path, cut.Markup);
    }
}
