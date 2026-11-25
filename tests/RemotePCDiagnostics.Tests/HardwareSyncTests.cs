using RemotePCDiagnostics.Core.Benchmarks;

namespace RemotePCDiagnostics.Tests;

public class HardwareSyncTests
{
    private static string TempFolder()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpcd-hwsync-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public async Task SyncIfChanged_uploads_once_skips_unchanged_and_reuploads_on_hardware_change()
    {
        var dir = TempFolder();
        try
        {
            var relay = new Uri("https://server.remoteblazorwebview.com:34544");
            var hw = new BenchmarkHardware(
                Manufacturer: "Lenovo", Model: "21ML", SystemSku: "LENOVO_MT_21ML",
                Processor: "Ryzen 7 PRO 8840U", MaxClockMhz: 3300, MemoryGb: 16, MemoryType: "DDR5");

            var uploads = 0;
            Task<bool> Upload(Uri u, string k, string id, string name, BenchmarkHardware h, CancellationToken ct)
            {
                uploads++;
                return Task.FromResult(true);
            }

            // 1. First connect uploads once.
            var r1 = await HardwareSyncService.SyncIfChangedAsync(relay, "rpd_live_testkey", "pc-1", "DEV1", dir, () => hw, Upload);
            Assert.Equal(HardwareSyncOutcome.Uploaded, r1);
            Assert.Equal(1, uploads);

            // 2. Subsequent reconnect with identical hardware skips upload.
            var r2 = await HardwareSyncService.SyncIfChangedAsync(relay, "rpd_live_testkey", "pc-1", "DEV1", dir, () => hw, Upload);
            Assert.Equal(HardwareSyncOutcome.Unchanged, r2);
            Assert.Equal(1, uploads);

            // 3. Hardware change (RAM upgraded 16 GB -> 32 GB) uploads again.
            var upgraded = hw with { MemoryGb = 32 };
            var r3 = await HardwareSyncService.SyncIfChangedAsync(relay, "rpd_live_testkey", "pc-1", "DEV1", dir, () => upgraded, Upload);
            Assert.Equal(HardwareSyncOutcome.Uploaded, r3);
            Assert.Equal(2, uploads);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task SyncIfChanged_does_not_stamp_on_failed_upload_and_skips_without_shop_key()
    {
        var dir = TempFolder();
        try
        {
            var relay = new Uri("https://server.remoteblazorwebview.com:34544");
            var hw = new BenchmarkHardware(Manufacturer: "Dell", Model: "XPS 15", Processor: "i7-13700H", MemoryGb: 32);

            // Non-shop key -> skipped without uploading.
            var skipped = await HardwareSyncService.SyncIfChangedAsync(relay, "not-a-shop-key", "pc-1", "DEV1", dir, () => hw,
                (_, _, _, _, _, _) => throw new InvalidOperationException("must not upload"));
            Assert.Equal(HardwareSyncOutcome.Skipped, skipped);

            // Failed upload does not write stamp, so next connect retries.
            var failed = await HardwareSyncService.SyncIfChangedAsync(relay, "rpd_live_testkey", "pc-1", "DEV1", dir, () => hw,
                (_, _, _, _, _, _) => Task.FromResult(false));
            Assert.Equal(HardwareSyncOutcome.Failed, failed);
            Assert.False(File.Exists(Path.Combine(dir, HardwareSyncService.StampFileName)));

            var succeeded = await HardwareSyncService.SyncIfChangedAsync(relay, "rpd_live_testkey", "pc-1", "DEV1", dir, () => hw,
                (_, _, _, _, _, _) => Task.FromResult(true));
            Assert.Equal(HardwareSyncOutcome.Uploaded, succeeded);
            Assert.True(File.Exists(Path.Combine(dir, HardwareSyncService.StampFileName)));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
