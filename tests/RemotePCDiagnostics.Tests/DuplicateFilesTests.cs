using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public sealed class DuplicateFilesTests : IDisposable
{
    private readonly string _tmp = Path.Combine(Path.GetTempPath(), "rpcd-duplicate-tests-" + Guid.NewGuid().ToString("N"));

    public DuplicateFilesTests()
    {
        Directory.CreateDirectory(_tmp);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmp, true); } catch { }
    }

    private sealed class MockRecycleBin : IRecycleBinDeleter
    {
        public readonly List<string> Deleted = [];
        public bool SendToRecycleBin(string path, out string? error)
        {
            Deleted.Add(path);
            error = null;
            return true;
        }
    }

    [Fact]
    public void Module_Attributes_Are_Expected()
    {
        var m = new DuplicateFilesModule();
        Assert.Equal("DuplicateFiles", m.Name);
        Assert.Equal(ModuleIds.DuplicateFiles, m.Id);
        Assert.Equal("Duplicate files", m.DisplayName);
    }

    [Fact]
    public void Scan_Identifies_Exact_Duplicates_And_Filters_Collisions()
    {
        var recycle = new MockRecycleBin();
        var m = new DuplicateFilesModule(recycleBin: recycle, searchRoots: [_tmp], minFileSizeBytes: 5000);

        // Two identical 10 KB files
        byte[] payloadA = new byte[10_000];
        Array.Fill(payloadA, (byte)0x42);
        var fileA1 = Path.Combine(_tmp, "copy1.dat");
        var fileA2 = Path.Combine(_tmp, "copy2.dat");
        File.WriteAllBytes(fileA1, payloadA);
        File.WriteAllBytes(fileA2, payloadA);

        // Third file with exact same size (10 KB) but different content
        byte[] payloadB = new byte[10_000];
        Array.Fill(payloadB, (byte)0x99);
        var fileB = Path.Combine(_tmp, "different_same_size.dat");
        File.WriteAllBytes(fileB, payloadB);

        // Tiny identical files (under min 5000 bytes)
        var tiny1 = Path.Combine(_tmp, "tiny1.txt");
        var tiny2 = Path.Combine(_tmp, "tiny2.txt");
        File.WriteAllText(tiny1, "same text");
        File.WriteAllText(tiny2, "same text");

        var report = m.Scan([_tmp], minSizeBytes: 5000, progress: null, CancellationToken.None);

        var card = Assert.Single(report.Cards);
        Assert.Equal("duplicates", card.Id);
        Assert.Single(card.Rows); // Exactly one duplicate group found

        var row = card.Rows[0];
        Assert.Contains("copy", row.Values[0]);
        Assert.Equal("2", row.Values[2]); // 2 copies

        Assert.Contains("Found 1 duplicate set", report.Summary);

        // Test deletion to recycle bin with safety revalidation against surviving duplicate
        bool ok = m.DeleteToRecycleBin(fileA2, fileA1, out var err);
        Assert.True(ok);
        Assert.Null(err);
        Assert.Contains(fileA2, recycle.Deleted);

        // Revalidation failure: target and surviving are identical path
        bool failSame = m.DeleteToRecycleBin(fileA1, fileA1, out var errSame);
        Assert.False(failSame);
        Assert.Contains("cannot be the same file", errSame);

        // Revalidation failure: target content changed after scan
        var fileModified = Path.Combine(_tmp, "modified.dat");
        var fileSurviving = Path.Combine(_tmp, "surviving.dat");
        File.WriteAllBytes(fileSurviving, payloadA);
        File.WriteAllBytes(fileModified, payloadB); // different content
        bool failMismatch = m.DeleteToRecycleBin(fileModified, fileSurviving, out var errMismatch);
        Assert.False(failMismatch);
        Assert.Contains("File contents no longer match", errMismatch);
    }

    [Fact]
    public void Scan_Can_Be_Cancelled()
    {
        var m = new DuplicateFilesModule();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => m.Scan([_tmp], 1024, null, cts.Token));
    }

    [Fact]
    public async Task Cancelled_Scan_Is_Reported_As_Cancelled_Not_Failed()
    {
        var m = new DuplicateFilesModule(recycleBin: new MockRecycleBin(), searchRoots: [_tmp], minFileSizeBytes: 1024);

        var r = await m.RefreshAsync(new CancelOnFirstReport(m));

        Assert.True(r.Cancelled);
        Assert.NotEqual(DiagnosticStatus.Error, r.Status);
        Assert.Equal("Cancelled", ResultEventLogger.Outcome(r));
        Assert.DoesNotContain("Couldn't scan", r.Message);
    }

    [Fact]
    public async Task BuildReport_AttachesDeleteActions_AndRemediationServiceMovesExtrasToRecycleBin()
    {
        var recycle = new MockRecycleBin();
        var m = new DuplicateFilesModule(recycleBin: recycle, searchRoots: [_tmp], minFileSizeBytes: 5000);

        byte[] payloadA = new byte[8_000];
        Array.Fill(payloadA, (byte)0x11);
        var origA = Path.Combine(_tmp, "installer.msi");
        var copyA = Path.Combine(_tmp, "installer (1).msi");
        File.WriteAllBytes(origA, payloadA);
        File.WriteAllBytes(copyA, payloadA);
        File.SetLastWriteTimeUtc(origA, new DateTime(2026, 11, 23, 12, 0, 0, DateTimeKind.Utc));
        File.SetLastWriteTimeUtc(copyA, new DateTime(2026, 11, 23, 12, 5, 0, DateTimeKind.Utc));

        byte[] payloadB = new byte[6_000];
        Array.Fill(payloadB, (byte)0x22);
        var origB = Path.Combine(_tmp, "archive.zip");
        var copyB1 = Path.Combine(_tmp, "archive (1).zip");
        var copyB2 = Path.Combine(_tmp, "archive (2).zip");
        File.WriteAllBytes(origB, payloadB);
        File.WriteAllBytes(copyB1, payloadB);
        File.WriteAllBytes(copyB2, payloadB);
        File.SetLastWriteTimeUtc(origB, new DateTime(2026, 11, 23, 10, 0, 0, DateTimeKind.Utc));
        File.SetLastWriteTimeUtc(copyB1, new DateTime(2026, 11, 23, 10, 1, 0, DateTimeKind.Utc));
        File.SetLastWriteTimeUtc(copyB2, new DateTime(2026, 11, 23, 10, 2, 0, DateTimeKind.Utc));

        var report = m.Scan([_tmp], minSizeBytes: 5000, progress: null, CancellationToken.None);
        var card = Assert.Single(report.Cards);
        Assert.Equal(2, card.Rows.Count);

        // Card-level action appears when there are multiple duplicate sets.
        var cardAction = Assert.Single(card.Actions!);
        Assert.Equal(RemediationKind.DeleteDuplicateFiles, cardAction.Kind);
        Assert.Equal("Delete all 3 extra copies", cardAction.ButtonText);

        // Per-row action on the 2-copy set keeps the older file and targets the newer copy.
        var rowA = card.Rows.Single(r => r.Values[0] == "installer.msi");
        Assert.Contains("[1 · keep]", rowA.Detail);
        var rowAction = Assert.Single(rowA.Actions!);
        Assert.Equal(RemediationKind.DeleteDuplicateFiles, rowAction.Kind);
        Assert.Equal("Delete extra copy", rowAction.ButtonText);

        var svc = new RemediationService(new SystemCommandRunner(), recycleBin: recycle);
        var plan = svc.Plan(rowAction);
        Assert.True(plan.Allowed);
        Assert.Contains(origA, plan.WhatItIs);
        Assert.Contains(copyA, plan.WhatItIs);

        var res = await svc.ExecuteAsync(rowAction);
        Assert.True(res.Success);
        Assert.Equal(1, res.RemovedFiles);
        Assert.Equal(8_000, res.FreedDiskBytes);
        Assert.Equal([copyA], recycle.Deleted);

        // Unattended workflow must skip DeleteDuplicateFiles.
        Assert.Contains(RemediationKind.DeleteDuplicateFiles, RemotePCDiagnostics.Core.Workflow.FixCatalog.SkippedRemediation);
        Assert.Equal("deleteduplicatefiles", RemotePCDiagnostics.Core.Workflow.FixKeys.Of(RemediationKind.DeleteDuplicateFiles));
    }

    /// <summary>Calls <c>Cancel()</c> on the module the first time the scan reports progress, as cancel_check does mid-scan.</summary>
    private sealed class CancelOnFirstReport(ICancellableScan scan) : IProgress<string>
    {
        public void Report(string value) => scan.Cancel();
    }
}
