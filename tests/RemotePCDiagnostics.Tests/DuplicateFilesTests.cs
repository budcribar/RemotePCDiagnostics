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
}
