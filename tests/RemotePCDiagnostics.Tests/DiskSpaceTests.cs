using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

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

        Assert.Equal(3, report.Cards.Count);
        Assert.Contains("2 large files", report.Summary);

        var drivesCard = Assert.Single(report.Cards, c => c.Id == "drives");
        Assert.True(drivesCard.Rows.Count > 0);
        Assert.Contains("Total", drivesCard.Columns);
        Assert.Contains("Used", drivesCard.Columns);
        Assert.Contains("Free", drivesCard.Columns);

        var filesCard = Assert.Single(report.Cards, c => c.Id == "files");
        Assert.Equal(["File", "Size", "Type", "Modified", "Folder"], filesCard.Columns);
        Assert.Equal(2, filesCard.Rows.Count);
        Assert.Contains(filesCard.Rows, r => r.Values[0] == "movie.mp4" && r.Values[2] == "Video" && r.Actions is [{ Kind: RemediationKind.DeleteLargeFile, ButtonText: "Delete" }]);
        Assert.Contains(filesCard.Rows, r => r.Values[0] == "backup.zip" && r.Values[2] == "Archive / Backup" && r.Actions is [{ Kind: RemediationKind.DeleteLargeFile, ButtonText: "Delete" }]);
        Assert.DoesNotContain(filesCard.Rows, r => r.Values[0] == "readme.txt");

        var foldersCard = Assert.Single(report.Cards, c => c.Id == "folders");
        Assert.True(foldersCard.Rows.Count > 0);
    }

    [Fact]
    public void Scan_Ignores_Vhdx_And_User_Ignored_Files()
    {
        var folder = Path.Combine(_tmp, "Disks");
        Directory.CreateDirectory(folder);

        var vhdx = Path.Combine(folder, "devdrive.vhdx");
        File.WriteAllBytes(vhdx, new byte[40_000]);

        var movie = Path.Combine(folder, "movie.mp4");
        File.WriteAllBytes(movie, new byte[20_000]);

        var archive = Path.Combine(folder, "backup.zip");
        File.WriteAllBytes(archive, new byte[15_000]);

        var ignoreStore = new LargeFileIgnoreStore(Path.Combine(_tmp, "ignored.json"));
        ignoreStore.Ignore(archive);

        var m = new DiskSpaceModule(targetRoot: _tmp, minFileSizeBytes: 10_000, ignoreStore: ignoreStore);
        var report = m.Scan(_tmp, minSizeBytes: 10_000, progress: null, CancellationToken.None);

        var filesCard = Assert.Single(report.Cards, c => c.Id == "files");
        var only = Assert.Single(filesCard.Rows);
        Assert.Equal("movie.mp4", only.Values[0]);
        Assert.DoesNotContain(filesCard.Rows, r => r.Values[0] == "devdrive.vhdx");
        Assert.DoesNotContain(filesCard.Rows, r => r.Values[0] == "backup.zip");

        // Unignoring brings backup.zip back on the next scan while .vhdx stays ignored.
        ignoreStore.Unignore(archive);
        var report2 = m.Scan(_tmp, minSizeBytes: 10_000, progress: null, CancellationToken.None);
        var filesCard2 = Assert.Single(report2.Cards, c => c.Id == "files");
        Assert.Equal(2, filesCard2.Rows.Count);
        Assert.Contains(filesCard2.Rows, r => r.Values[0] == "backup.zip");
        Assert.DoesNotContain(filesCard2.Rows, r => r.Values[0] == "devdrive.vhdx");
    }

    [Fact]
    public async Task DeleteLargeFile_Sends_Regular_File_To_RecycleBin_And_Refuses_Vhdx()
    {
        var video = Path.Combine(_tmp, "clip.mp4");
        File.WriteAllBytes(video, new byte[12_345]);
        var vhdx = Path.Combine(_tmp, "dev.vhdx");
        File.WriteAllBytes(vhdx, new byte[12_345]);

        var recycled = new List<string>();
        var deleter = new FakeRecycleBin(recycled);
        var rem = new RemediationService(
            new SystemCommandRunner(new FakeLauncher()),
            recycleBin: deleter);

        var vhdxAction = new AreaAction(RemediationKind.DeleteLargeFile, "Delete", vhdx, "dev.vhdx");
        Assert.False(rem.Plan(vhdxAction).Allowed);
        var vhdxRes = await rem.ExecuteAsync(vhdxAction);
        Assert.False(vhdxRes.Success);
        Assert.Empty(recycled);

        var videoAction = new AreaAction(RemediationKind.DeleteLargeFile, "Delete", video, "clip.mp4");
        Assert.True(rem.Plan(videoAction).Allowed);
        var videoRes = await rem.ExecuteAsync(videoAction);
        Assert.True(videoRes.Success, videoRes.Message);
        Assert.Equal([video], recycled);
        Assert.Equal(1, videoRes.RemovedFiles);
        Assert.Equal(12_345, videoRes.FreedDiskBytes);
    }

    private sealed class FakeRecycleBin(List<string> recycled) : IRecycleBinDeleter
    {
        public bool SendToRecycleBin(string path, out string? error)
        {
            recycled.Add(path);
            File.Delete(path);
            error = null;
            return true;
        }
    }

    private sealed class FakeLauncher : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken ct = default)
            => Task.FromResult(new ProcessResult(0, "", "", false));
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

    [Theory]
    [InlineData("C:\\pagefile.sys", true)]
    [InlineData("C:\\hiberfil.sys", true)]
    [InlineData("C:\\swapfile.sys", true)]
    [InlineData("C:\\dumpstack.log.tmp", true)]
    [InlineData("C:\\bootmgr", true)]
    [InlineData("C:\\Drivers\\display.sys", true)]
    [InlineData("C:\\Windows\\System32\\largefile.bin", true)]
    [InlineData("C:\\System Volume Information\\SPP\\test.dat", true)]
    [InlineData("C:\\$Recycle.Bin\\S-1-5-21\\test.dat", true)]
    [InlineData("C:\\Users\\User\\Videos\\movie.mp4", false)]
    [InlineData("C:\\Projects\\repo.zip", false)]
    public void IsSystemFilePath_Filters_Expected_Paths(string path, bool expectedSystem)
    {
        Assert.Equal(expectedSystem, DiskSpaceModule.IsSystemFilePath(path, windowsDir: "C:\\Windows"));
    }

    [Theory]
    [InlineData(0x1000L, true)] // FILE_ATTRIBUTE_OFFLINE
    [InlineData(0x00040000L, true)] // FILE_ATTRIBUTE_RECALL_ON_OPEN
    [InlineData(0x00400000L, true)] // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    [InlineData(0x00441000L, true)] // Combination
    [InlineData(0x20L, false)] // FILE_ATTRIBUTE_ARCHIVE
    [InlineData(0x80L, false)] // FILE_ATTRIBUTE_NORMAL
    public void IsCloudOnlyAttributes_Detects_Offline_And_Recall_Attributes(long attrs, bool expected)
    {
        Assert.Equal(expected, DiskSpaceModule.IsCloudOnlyAttributes(attrs));
    }

    [Theory]
    [InlineData("C:\\Users\\User\\Phone Link\\Photos\\pic.jpg", true)]
    [InlineData("C:\\Users\\User\\Your Phone\\Videos\\vid.mp4", true)]
    [InlineData("C:\\Users\\User\\CrossDevice\\file.dat", true)]
    [InlineData("C:\\Users\\User\\Documents\\local.pdf", false)]
    public void IsCloudOnlyPath_Detects_PhoneLink_And_Virtual_Paths(string path, bool expected)
    {
        Assert.Equal(expected, DiskSpaceModule.IsCloudOnlyPath(path));
    }

    [Fact]
    public void CloudOnly_Files_Have_Zero_Disk_Bytes_And_Are_Excluded_From_Top_Large_Files()
    {
        var localFile = new LargeFileInfo("local.mp4", "C:\\Videos\\local.mp4", 5_000_000_000, DateTime.UtcNow, "Video", IsCloudOnly: false, DiskSizeBytes: 5_000_000_000);
        var cloudFile = new LargeFileInfo("cloud.mp4", "C:\\Users\\User\\Phone Link\\cloud.mp4", 10_000_000_000, DateTime.UtcNow, "Video", IsCloudOnly: true, DiskSizeBytes: 0);

        Assert.Equal(5_000_000_000, localFile.ActualDiskBytes);
        Assert.Equal("Local", localFile.StorageState);

        Assert.Equal(0, cloudFile.ActualDiskBytes);
        Assert.Equal("Cloud-only", cloudFile.StorageState);

        var report = DiskSpaceModule.BuildReport("C:\\", 1_000_000, [localFile, cloudFile], []);
        var filesCard = Assert.Single(report.Cards, c => c.Id == "files");
        Assert.DoesNotContain("Storage", filesCard.Columns);
        var only = Assert.Single(filesCard.Rows);
        Assert.Equal("local.mp4", only.Values[0]);
    }

    [Fact]
    public void FolderSpaceInfo_Tracks_Disk_And_Logical_Size()
    {
        var folder = new FolderSpaceInfo("OneDrive", "C:\\Users\\User\\OneDrive", TotalSizeBytes: 2_000_000_000, FileCount: 100, LogicalSizeBytes: 50_000_000_000);
        Assert.Equal(2_000_000_000, folder.TotalSizeBytes);
        Assert.Equal(50_000_000_000, folder.TotalLogicalBytes);

        var report = DiskSpaceModule.BuildReport("C:\\", 1_000_000, [], [folder]);
        var foldersCard = Assert.Single(report.Cards, c => c.Id == "folders");
        Assert.Single(foldersCard.Rows);
        Assert.Contains("on disk", foldersCard.Rows[0].Detail);
        Assert.Contains("including cloud-only", foldersCard.Rows[0].Detail);
    }

    [Fact]
    public void DriveCapacityInfo_Calculates_Used_Space_And_Percentage()
    {
        var drive = new DriveCapacityInfo("C:\\", "Windows", "NTFS", TotalBytes: 500_000_000_000, FreeBytes: 200_000_000_000);
        Assert.Equal(300_000_000_000, drive.UsedBytes);
        Assert.Equal(60.0, drive.UsedPercent, 1);

        var report = DiskSpaceModule.BuildReport("C:\\", 1_000_000, [], [], [drive]);
        var drivesCard = Assert.Single(report.Cards, c => c.Id == "drives");
        Assert.Single(drivesCard.Rows);
        Assert.Equal("C:\\", drivesCard.Rows[0].Values[0]);
        Assert.Contains("60%", drivesCard.Rows[0].Values[4]);
        Assert.Contains("NTFS", drivesCard.Rows[0].Values[5]);
        Assert.Contains($"{HardwareInventory.FormatBytes(300_000_000_000)} used of {HardwareInventory.FormatBytes(500_000_000_000)}", report.Summary);
        Assert.Contains($"{HardwareInventory.FormatBytes(200_000_000_000)} free", report.Summary);
    }

    [Fact]
    public void Capacity_card_carries_byte_totals_and_warns_only_when_a_volume_is_nearly_full()
    {
        const long gb = 1024L * 1024 * 1024;
        var roomy = new DriveCapacityInfo("C:\\", "Windows", "NTFS", 4000 * gb, 320 * gb); // 92% used, 320 GB free
        var full = new DriveCapacityInfo("D:\\", "Data", "NTFS", 100 * gb, 5 * gb);

        var one = DiskSpaceModule.BuildDriveCapacityCard([roomy]);
        Assert.Equal(DiskSpaceModule.CapacityCardId, one.Id);
        Assert.Equal(AreaLevel.Neutral, one.Level);
        Assert.Equal($"C:\\ {HardwareInventory.FormatBytes(320 * gb)} free of {HardwareInventory.FormatBytes(4000 * gb)}", one.Headline);
        Assert.Equal("92% used · NTFS file system", one.Meta);
        Assert.Equal((4000 * gb, 320 * gb, 3680 * gb), (one.TotalBytes, one.FreeBytes, one.UsedBytes));

        var two = DiskSpaceModule.BuildDriveCapacityCard([roomy, full]);
        Assert.Equal(AreaLevel.Warning, two.Level);
        Assert.Equal(new[] { AreaLevel.Neutral, AreaLevel.Warning }, two.Rows.Select(r => r.Level));
        Assert.Equal($"{HardwareInventory.FormatBytes(325 * gb)} free across 2 drives", two.Headline);
        Assert.Equal($"Nearly full: D: · {HardwareInventory.FormatBytes(4100 * gb)} total capacity", two.Meta);
        Assert.Equal((4100 * gb, 325 * gb, 3775 * gb), (two.TotalBytes, two.FreeBytes, two.UsedBytes));
    }

    [Fact]
    public void Scan_Filters_Out_System_Files()
    {
        var folderA = Path.Combine(_tmp, "Media");
        Directory.CreateDirectory(folderA);

        var largeVideo = Path.Combine(folderA, "movie.mp4");
        File.WriteAllBytes(largeVideo, new byte[20_000]);

        var largeSysFile = Path.Combine(folderA, "driver.sys");
        File.WriteAllBytes(largeSysFile, new byte[30_000]);

        var m = new DiskSpaceModule(targetRoot: _tmp, minFileSizeBytes: 10_000);
        var report = m.Scan(_tmp, minSizeBytes: 10_000, progress: null, CancellationToken.None);

        var filesCard = Assert.Single(report.Cards, c => c.Id == "files");
        // Should only contain movie.mp4, not driver.sys
        Assert.Single(filesCard.Rows);
        Assert.Equal("movie.mp4", filesCard.Rows[0].Values[0]);
    }

    [Fact]
    public void BuildReport_Populates_FilePath_On_Rows()
    {
        var files = new List<LargeFileInfo>
        {
            new("movie.mp4", "/path/to/movie.mp4", 500_000_000, DateTime.UtcNow, "Video")
        };
        var folders = new List<FolderSpaceInfo>
        {
            new("Media", "/path/to/Media", 1_000_000_000, 5)
        };

        var report = DiskSpaceModule.BuildReport("/path/to", 100_000_000, files, folders);

        var folderCard = Assert.Single(report.Cards, c => c.Id == "folders");
        Assert.Equal("/path/to/Media", folderCard.Rows[0].FilePath);

        var filesCard = Assert.Single(report.Cards, c => c.Id == "files");
        Assert.Equal("/path/to/movie.mp4", filesCard.Rows[0].FilePath);
    }

    [Fact]
    public void FileManagerLauncher_RevealFile_Uses_CustomOpener()
    {
        string? opened = null;
        FileManagerLauncher.CustomOpener = path =>
        {
            opened = path;
            return true;
        };

        try
        {
            var result = FileManagerLauncher.RevealFile("/test/path/file.mp4");
            Assert.True(result);
            Assert.Equal("/test/path/file.mp4", opened);
        }
        finally
        {
            FileManagerLauncher.CustomOpener = null;
        }
    }

    [Fact]
    public async Task Cancelled_Scan_Is_Reported_As_Cancelled_Not_Failed()
    {
        Directory.CreateDirectory(Path.Combine(_tmp, "Media"));
        var m = new DiskSpaceModule(targetRoot: _tmp, minFileSizeBytes: 10_000);

        var r = await m.RefreshAsync(new CancelOnFirstReport(m));

        Assert.True(r.Cancelled);
        Assert.NotEqual(DiagnosticStatus.Error, r.Status);
        Assert.Equal("Cancelled", ResultEventLogger.Outcome(r));
        Assert.DoesNotContain("Couldn't scan", r.Message);
    }

    [Fact]
    public async Task Cancelling_The_Callers_Token_Still_Throws()
    {
        var m = new DiskSpaceModule(targetRoot: _tmp);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => m.RefreshAsync(null, cts.Token));
    }

    /// <summary>Calls <c>Cancel()</c> on the module the first time the scan reports progress, as cancel_check does mid-scan.</summary>
    private sealed class CancelOnFirstReport(ICancellableScan scan) : IProgress<string>
    {
        public void Report(string value) => scan.Cancel();
    }
}
