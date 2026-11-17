using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public sealed class DiskSpaceTests : IDisposable
{
    private readonly string _tmp = Path.Combine(Path.GetTempPath(), "rpcd-diskspace-tests-" + Guid.NewGuid().ToString("N"));

    public DiskSpaceTests()
    {
        Directory.CreateDirectory(_tmp);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmp, true); } catch { }
    }

    [Fact]
    public void Module_Attributes_Are_Expected()
    {
        var m = new DiskSpaceModule();
        Assert.Equal("DiskSpace", m.Name);
        Assert.Equal(ModuleIds.DiskSpace, m.Id);
        Assert.Equal("Large files & folders", m.DisplayName);
    }

    [Theory]
    [InlineData(".mp4", "Video")]
    [InlineData(".mkv", "Video")]
    [InlineData(".iso", "Disc / VM Image")]
    [InlineData(".vhdx", "Disc / VM Image")]
    [InlineData(".zip", "Archive / Backup")]
    [InlineData(".7z", "Archive / Backup")]
    [InlineData(".dmp", "Crash dump / System")]
    [InlineData(".exe", "Installer")]
    [InlineData(".msi", "Installer")]
    [InlineData(".pst", "Database / Mail")]
    [InlineData(".txt", "Other file")]
    public void Extension_Classification_Matches(string ext, string expected)
    {
        Assert.Equal(expected, LargeFileInfo.Classify(ext));
    }

    [Fact]
    public void Scan_Finds_Large_Files_And_Aggregates_Folders()
    {
        var folderA = Path.Combine(_tmp, "Media");
        var folderB = Path.Combine(_tmp, "Docs");
        Directory.CreateDirectory(folderA);
        Directory.CreateDirectory(folderB);

        var largeVideo = Path.Combine(folderA, "movie.mp4");
        File.WriteAllBytes(largeVideo, new byte[20_000]);

        var largeArchive = Path.Combine(folderB, "backup.zip");
        File.WriteAllBytes(largeArchive, new byte[15_000]);

        var smallFile = Path.Combine(folderB, "readme.txt");
        File.WriteAllBytes(smallFile, new byte[500]);

        var m = new DiskSpaceModule(targetRoot: _tmp, minFileSizeBytes: 10_000);
        var report = m.Scan(_tmp, minSizeBytes: 10_000, progress: null, CancellationToken.None);

        Assert.Equal(2, report.Cards.Count);
        Assert.Contains("2 large files", report.Summary);

        var filesCard = Assert.Single(report.Cards, c => c.Id == "files");
        Assert.Equal(2, filesCard.Rows.Count);
        Assert.Contains(filesCard.Rows, r => r.Values[0] == "movie.mp4" && r.Values[2] == "Video");
        Assert.Contains(filesCard.Rows, r => r.Values[0] == "backup.zip" && r.Values[2] == "Archive / Backup");
        Assert.DoesNotContain(filesCard.Rows, r => r.Values[0] == "readme.txt");

        var foldersCard = Assert.Single(report.Cards, c => c.Id == "folders");
        Assert.True(foldersCard.Rows.Count > 0);
    }

    [Fact]
    public void Scan_Can_Be_Cancelled()
    {
        var m = new DiskSpaceModule(targetRoot: _tmp);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => m.Scan(_tmp, 1024, null, cts.Token));
    }

    [Fact]
    public void Cancel_Method_Does_Not_Throw_When_Not_Scanning()
    {
        var m = new DiskSpaceModule(targetRoot: _tmp);
        m.Cancel(); // Should be a safe no-op
    }
}
