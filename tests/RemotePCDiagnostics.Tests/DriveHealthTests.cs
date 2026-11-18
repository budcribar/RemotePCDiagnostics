using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

public class DriveHealthTests
{
    private const string Healthy = """
    [{"Name":"Samsung SSD 980 1TB","Serial":"S1","MediaType":"SSD","BusType":"NVMe","Health":"Healthy","Operational":"OK","Size":"1000204886016",
      "Temperature":"38","Wear":"3","ReadErrors":"0","WriteErrors":"0","PowerOnHours":"4120"}]
    """;

    /// <param name="volumes">The PC's volumes as the module reads them. None by default: a test never reads this machine's disks.</param>
    private static (DriveHealthModule M, ScriptedLauncher L, List<string> Log) Make(Func<string, IReadOnlyList<string>, ProcessResult> run,
        Func<IReadOnlyList<DriveCapacityInfo>>? volumes = null)
    {
        var log = new List<string>();
        var l = new ScriptedLauncher(run);
        return (new DriveHealthModule(new SystemCommandRunner(l, new LineLogger(s => log.Add(s))), ScriptedLauncher.Osquery(l, log),
            volumes: volumes ?? (() => [])), l, log);
    }

    private const long GB = 1024L * 1024 * 1024;
    private static DriveCapacityInfo Volume(string letter, long totalGb, long freeGb, bool removable = false) =>
        new(letter + ":\\", letter, "NTFS", totalGb * GB, freeGb * GB, removable);
    private static string Size(long gb) => HardwareInventory.FormatBytes(gb * GB);

    [Fact]
    public async Task Healthy_Drive_IsOk_WithFriendlySummary()
    {
        var (m, l, log) = Make((f, a) => ScriptedLauncher.Ok(Healthy));
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("1 drive · healthy", r.Message);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        var card = Assert.Single(rep.Cards);
        Assert.Equal("Samsung SSD 980 1TB", card.Title);
        Assert.Equal("Healthy", card.Headline);
        Assert.Contains("38°C", card.Meta);
        Assert.Contains("powershell.exe", l.Calls[0].File);
        Assert.Contains(log, s => s.Contains("exit=0"));
    }

    [Theory]
    [InlineData("Unhealthy", "0", "0", AreaLevel.Error)]
    [InlineData("Warning", "0", "0", AreaLevel.Warning)]
    [InlineData("Healthy", "5", "0", AreaLevel.Warning)]
    [InlineData("Healthy", "0", "95", AreaLevel.Warning)]
    [InlineData("", "", "", AreaLevel.Neutral)]
    public void Level_FromHealthErrorsAndWear(string health, string readErr, string wear, AreaLevel expected)
    {
        var d = DriveHealth.FromRow(new Dictionary<string, string> { ["Health"] = health, ["ReadErrors"] = readErr, ["Wear"] = wear });
        Assert.Equal(expected, d.Level);
    }

    [Fact]
    public void Failing_Drive_ReportsError_AndBackupAdvice()
    {
        var rep = DriveHealthModule.Build([DriveHealth.FromRow(new Dictionary<string, string> { ["Name"] = "Old HDD", ["Health"] = "Unhealthy" }),
                                           DriveHealth.FromRow(new Dictionary<string, string> { ["Name"] = "SSD", ["Health"] = "Healthy" })]);
        Assert.Equal(DiagnosticStatus.Error, rep.Status);
        Assert.Equal("1 of 2 drives needs attention", rep.Summary);
        Assert.Contains("back up", rep.Cards[0].Headline);
    }

    [Fact]
    public async Task PowerShellFails_FallsBackToDriveList_WithNotice()
    {
        var (m, _, log) = Make((f, a) => f.StartsWith("osqueryi")
            ? ScriptedLauncher.Ok("""[{"hardware_model":"VirtualDisk","disk_size":"137438953472","type":"SCSI","serial":"X"}]""")
            : ScriptedLauncher.Fail("Get-PhysicalDisk : Access denied"));
        var r = await m.RefreshAsync(null);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal("VirtualDisk", Assert.Single(rep.Cards).Title);
        Assert.Equal("Health not reported", rep.Cards[0].Headline);
        Assert.NotNull(rep.Notice);
        Assert.DoesNotContain("Access denied", r.Message);
        Assert.Contains(log, s => s.Contains("Access denied"));
    }

    [Fact]
    public async Task EverythingFails_FriendlyError()
    {
        var (m, _, _) = Make((f, a) => ScriptedLauncher.Fail());
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("Couldn't check drive health on this PC.", r.Message);
    }

    [Fact]
    public async Task RegisteredInService_StoresTypedReport()
    {
        var (m, _, _) = Make((f, a) => ScriptedLauncher.Ok(Healthy));
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);
        await svc.RunAsync(DriveHealthModule.ModuleName);
        Assert.IsType<AreaReport>(store.Get("DriveHealth").Report());
        Assert.Equal("Samsung SSD 980 1TB, 931.5 GB", Assert.Single(store.InstancesOf("DriveHealth")).InstanceLabel);
        Assert.Equal("Drive health & free space", svc.Modules.Single().DisplayName);
    }

    private const string TwoDrives = """
    [{"Name":"Samsung SSD 980 1TB","Serial":"S1","MediaType":"SSD","BusType":"NVMe","Health":"Healthy","Operational":"OK","Size":"1000204886016","Letters":"C"},
     {"Name":"WD Blue","Serial":"W2","MediaType":"HDD","BusType":"SATA","Health":"Warning","Operational":"OK","Size":"2000398934016","Letters":"D"}]
    """;

    [Fact]
    public async Task Each_drive_is_its_own_instance_from_one_read_and_the_page_still_gets_one_report()
    {
        var reads = 0;
        var (m, _, _) = Make((f, a) => { Interlocked.Increment(ref reads); return ScriptedLauncher.Ok(TwoDrives); });
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);
        var r = await svc.RunAsync(DriveHealthModule.ModuleName);

        var perDrive = store.InstancesOf(DriveHealthModule.ModuleName);
        Assert.Equal(2, perDrive.Count);
        Assert.Equal(DiagnosticStatus.Ok, perDrive.Single(x => x.InstanceLabel!.StartsWith("Samsung")).Status);
        Assert.Equal(DiagnosticStatus.Warning, perDrive.Single(x => x.InstanceLabel!.StartsWith("WD")).Status);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        var report = Assert.IsType<AreaReport>(r.Report());
        Assert.Equal(2, report.Cards.Count);
        Assert.Single(report.Cards.SelectMany(c => c.Actions ?? []), a => a.Kind == RemediationKind.CleanTempFiles); // once, not per drive
        Assert.True(reads <= 2, $"read the drives {reads} times"); // detection, then one shared read for both drives
    }

    [Fact]
    public void Instance_keys_come_from_the_serial_and_stay_unique_when_serials_repeat()
    {
        DriveHealth D(string serial, string id = "") => new("USB disk", serial, "", "USB", "", "", null, null, null, null, null, null, "", id);
        var keys = DriveHealthModule.Instances([D("SAME"), D("SAME"), D("", "eui.1"), D("X")]).Select(x => x.Instance.Key).ToList();
        Assert.Equal(4, keys.Distinct().Count());
        Assert.Equal(InstanceKeys.From("serial:X"), keys[3]);
        Assert.Equal(InstanceKeys.From("id:eui.1"), keys[2]);
    }

    [Fact]
    public async Task When_no_drive_can_be_read_the_test_stays_listed_and_reports_why()
    {
        var (m, _, _) = Make((f, a) => ScriptedLauncher.Fail());
        var detection = await m.DetectAsync();
        Assert.True(detection.Applies);
        var store = new ResultStore();
        var r = await new DiagnosticsService(store, [m]).RunAsync(DriveHealthModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("Couldn't check drive health on this PC.", r.Message);
    }

    [Fact]
    public async Task CancellingOneCaller_DoesNotPoisonConcurrentSharedRead()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<ProcessResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reads = 0;
        var launcher = new DelegateLauncher((_, _, _, ct) =>
        {
            Interlocked.Increment(ref reads);
            started.TrySetResult();
            return release.Task.WaitAsync(ct);
        });
        var m = new DriveHealthModule(new SystemCommandRunner(launcher), new OsqueryRunner(Path.GetTempPath(), launcher: launcher, fileExists: _ => true),
            volumes: () => []);
        var instance = DriveHealthModule.Instances([DriveHealth.FromRow(new Dictionary<string, string> { ["Name"] = "Samsung SSD 980 1TB", ["Serial"] = "S1" })])[0].Instance;

        using var ctsA = new CancellationTokenSource();
        var detectTask = m.DetectAsync(ctsA.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var refreshTask = m.RefreshAsync(instance, null, CancellationToken.None);

        ctsA.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => detectTask);

        release.SetResult(ScriptedLauncher.Ok(Healthy));
        var r = await refreshTask.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(1, reads);
    }

    [Fact]
    public void Trend_flags_drive_when_read_errors_increase()
    {
        var store = new DriveHealthHistoryStore();
        var now1 = DateTimeOffset.UtcNow.AddDays(-7);
        var now2 = DateTimeOffset.UtcNow;

        var d1 = new DriveHealth("SSD", "SN123", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 35, 10, ReadErrors: 0, WriteErrors: 0, PowerOnHours: 1000);
        store.Record([d1], now1);

        var d2 = new DriveHealth("SSD", "SN123", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 36, 10, ReadErrors: 3, WriteErrors: 0, PowerOnHours: 1168);
        var analysis = store.AnalyzeTrend(d2.RawId, d2, now2);

        Assert.True(analysis.HasHistory);
        Assert.True(analysis.IsDegrading);
        Assert.Equal(3, analysis.ReadErrorDelta);
        Assert.Contains("read errors increased by +3", analysis.SummaryText);

        var rep = DriveHealthModule.Build([d2], null, now2, store);
        var card = Assert.Single(rep.Cards);
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Contains("Degrading", card.Headline);
        Assert.Contains("getting worse", rep.Summary);
    }

    [Fact]
    public void Trend_shows_stable_when_errors_do_not_increase()
    {
        var store = new DriveHealthHistoryStore();
        var now1 = DateTimeOffset.UtcNow.AddDays(-14);
        var now2 = DateTimeOffset.UtcNow;

        var d1 = new DriveHealth("SSD", "SN123", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 35, 10, ReadErrors: 0, WriteErrors: 0, PowerOnHours: 1000);
        store.Record([d1], now1);

        var d2 = new DriveHealth("SSD", "SN123", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 36, 10, ReadErrors: 0, WriteErrors: 0, PowerOnHours: 1336);
        var analysis = store.AnalyzeTrend(d2.RawId, d2, now2);

        Assert.True(analysis.HasHistory);
        Assert.False(analysis.IsDegrading);
        Assert.Contains("Stable", analysis.SummaryText);

        var rep = DriveHealthModule.Build([d2], null, now2, store);
        var card = Assert.Single(rep.Cards);
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.Equal("Healthy", card.Headline);
        Assert.DoesNotContain("getting worse", rep.Summary);
    }

    [Fact]
    public void Replaced_drive_with_different_serial_does_not_inherit_baseline()
    {
        var store = new DriveHealthHistoryStore();
        var now1 = DateTimeOffset.UtcNow.AddDays(-30);
        var now2 = DateTimeOffset.UtcNow;

        // Old drive recorded earlier with 0 read errors
        var oldDrive = new DriveHealth("Samsung 980", "SN-OLD-111", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 35, 10, ReadErrors: 0, WriteErrors: 0, PowerOnHours: 5000);
        store.Record([oldDrive], now1);

        // Replacement drive installed later; has different serial number and 2 uncorrected read errors
        var newDrive = new DriveHealth("Samsung 980", "SN-NEW-999", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 36, 1, ReadErrors: 2, WriteErrors: 0, PowerOnHours: 10);
        var analysis = store.AnalyzeTrend(newDrive.RawId, newDrive, now2);

        // Must not compare against SN-OLD-111 baseline:
        Assert.False(analysis.HasHistory);
        Assert.False(analysis.IsDegrading);
        Assert.Contains("First recorded health check", analysis.SummaryText);
    }

    [Fact]
    public void Replaced_drive_with_reset_power_on_hours_does_not_inherit_baseline()
    {
        var store = new DriveHealthHistoryStore();
        var now1 = DateTimeOffset.UtcNow.AddDays(-30);
        var now2 = DateTimeOffset.UtcNow;

        // Old drive without serial reported, 10,000 hours, 0 errors
        var oldDrive = new DriveHealth("Generic SSD", "", "SSD", "SATA", "Healthy", "OK", 500_000_000_000, 35, 10, ReadErrors: 0, WriteErrors: 0, PowerOnHours: 10_000);
        store.Record([oldDrive], now1);

        // Replacement drive with same name but reset power-on hours (10 hours) and 1 read error
        var newDrive = new DriveHealth("Generic SSD", "", "SSD", "SATA", "Healthy", "OK", 500_000_000_000, 35, 1, ReadErrors: 1, WriteErrors: 0, PowerOnHours: 10);
        var analysis = store.AnalyzeTrend(newDrive.RawId, newDrive, now2);

        // Must detect reset power-on hours and not inherit old baseline
        Assert.False(analysis.HasHistory);
        Assert.False(analysis.IsDegrading);
        Assert.Contains("First recorded health check", analysis.SummaryText);
    }

    private static DriveHealth Drive(string name, string letters, string health = "Healthy") =>
        new(name, "SN-" + name, "SSD", "NVMe", health, "OK", 500 * GB, 35, 10, ReadErrors: 0, WriteErrors: 0, PowerOnHours: 1000, Letters: letters);

    [Theory]
    [InlineData(4000, 200, false, false)] // 5% free, but 200 GB: plenty
    [InlineData(100, 15, false, false)]   // under 20 GB, but 15% free
    [InlineData(100, 5, false, true)]     // 5% and 5 GB
    [InlineData(1000, 19, false, true)]   // 1.9% and 19 GB
    [InlineData(1000, 20, false, false)]  // exactly 20 GB is not under it
    [InlineData(100, 10, false, false)]   // exactly 10% is not under it
    [InlineData(32, 1, true, false)]      // a full USB stick is normal
    public void A_volume_is_low_on_space_under_10_percent_and_under_20_GB_free(long totalGb, long freeGb, bool removable, bool low) =>
        Assert.Equal(low, Volume("C", totalGb, freeGb, removable).IsLowOnSpace);

    [Fact]
    public void Volumes_are_listed_on_a_capacity_card_and_free_space_is_in_the_summary()
    {
        var rep = DriveHealthModule.Build([Drive("Samsung 980", "CD")], capacities: [Volume("D", 1000, 600), Volume("C", 500, 200)]);

        Assert.Equal(DiagnosticStatus.Ok, rep.Status);
        Assert.Equal($"1 drive · healthy · {Size(800)} free across 2 volumes", rep.Summary);
        Assert.Equal(2, rep.Cards.Count);
        var capacity = rep.Cards[0];
        Assert.Equal(DriveHealthModule.CapacityCardId, capacity.Id);
        Assert.Equal("Drive Capacity", capacity.Title);
        Assert.Equal(AreaLevel.Neutral, capacity.Level);
        Assert.Equal(new[] { "C:\\", "D:\\" }, capacity.Rows.Select(r => r.Values[0])); // drive letter order
        // The totals as numbers, for the page's agent fields.
        Assert.Equal(1500 * GB, capacity.TotalBytes);
        Assert.Equal(800 * GB, capacity.FreeBytes);
        Assert.Equal(700 * GB, capacity.UsedBytes);

        var drive = rep.Cards[1];
        Assert.Equal("drive0", drive.Id);
        Assert.Equal("Healthy", drive.Headline);
        Assert.Contains($"{Size(800)} free", drive.Meta);
        Assert.Contains(drive.Rows, r => r.Values[0] == "Volume C:" && r.Values[1].StartsWith($"{Size(200)} free of {Size(500)}") && r.Level == AreaLevel.Neutral);
        Assert.Contains(drive.Rows, r => r.Values[0] == "Volume D:");
    }

    [Fact]
    public void A_nearly_full_volume_makes_its_own_drive_need_attention_and_is_counted_once()
    {
        var rep = DriveHealthModule.Build([Drive("Samsung 980", "C"), Drive("WD Blue", "D")], capacities: [Volume("C", 500, 200), Volume("D", 100, 5)]);

        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        // One drive, not two: the capacity card is not a drive.
        Assert.Equal($"1 of 2 drives needs attention · {Size(205)} free across 2 volumes", rep.Summary);
        Assert.Equal(AreaLevel.Warning, rep.Cards[0].Level);
        Assert.Contains("Nearly full: D:", rep.Cards[0].Meta);
        Assert.Equal(AreaLevel.Warning, rep.Cards[0].Rows.Single(r => r.Values[0] == "D:\\").Level);

        var samsung = rep.Cards.Single(c => c.Title == "Samsung 980");
        Assert.Equal(AreaLevel.Ok, samsung.Level);
        Assert.DoesNotContain(samsung.Rows, r => r.Values[0] == "Volume D:");

        var wd = rep.Cards.Single(c => c.Title == "WD Blue");
        Assert.Equal(AreaLevel.Warning, wd.Level);
        Assert.Equal("Needs attention", wd.Headline);
        Assert.Equal($"Needs attention: D: is nearly full ({Size(5)} free of {Size(100)})", wd.Rows.Single(r => r.Values[0] == "Overall").Values[1]);
        Assert.Equal(AreaLevel.Warning, wd.Rows.Single(r => r.Values[0] == "Volume D:").Level);
    }

    [Fact]
    public void A_failing_drive_stays_failing_when_it_is_also_nearly_full()
    {
        var rep = DriveHealthModule.Build([Drive("Old HDD", "C", health: "Unhealthy")], capacities: [Volume("C", 100, 5)]);

        Assert.Equal(DiagnosticStatus.Error, rep.Status);
        Assert.StartsWith("1 of 1 drive needs attention", rep.Summary);
        var card = rep.Cards.Single(c => c.Id == "drive0");
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Contains("back up", card.Headline);
        var overall = card.Rows.Single(r => r.Values[0] == "Overall").Values[1];
        Assert.Contains("Windows reports this drive as failing", overall);
        Assert.Contains("C: is nearly full", overall);
    }

    [Fact]
    public void A_large_drive_that_is_92_percent_used_is_not_a_warning()
    {
        var rep = DriveHealthModule.Build([Drive("Big", "C")], capacities: [Volume("C", 4000, 320)]);
        Assert.Equal(DiagnosticStatus.Ok, rep.Status);
        Assert.All(rep.Cards, c => Assert.NotEqual(AreaLevel.Warning, c.Level));
        Assert.Equal($"1 drive · healthy · {Size(320)} free on C:", rep.Summary);
    }

    [Fact]
    public void No_drives_is_still_a_warning_when_volumes_were_read()
    {
        var rep = DriveHealthModule.Build([], capacities: [Volume("C", 500, 200)]);
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        Assert.Equal("No drives were found to check.", rep.Summary);
        Assert.Empty(rep.Cards);
    }

    [Fact]
    public void A_volume_with_no_drive_letter_reported_belongs_to_the_only_drive()
    {
        // The osquery fallback knows no letters.
        var rep = DriveHealthModule.Build([Drive("Only", "")], capacities: [Volume("C", 100, 5), Volume("E", 32, 1, removable: true)]);
        var card = rep.Cards.Single(c => c.Id == "drive0");
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Contains(card.Rows, r => r.Values[0] == "Volume C:");
        Assert.DoesNotContain(card.Rows, r => r.Values[0] == "Volume E:"); // a removable volume is never guessed onto a drive
        Assert.StartsWith("1 of 1 drive needs attention", rep.Summary);
    }

    [Fact]
    public void With_several_drives_and_no_letters_the_capacity_card_alone_warns()
    {
        var rep = DriveHealthModule.Build([Drive("A", ""), Drive("B", "")], capacities: [Volume("C", 500, 200), Volume("D", 100, 5)]);
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        Assert.Equal($"2 drives · all healthy · {Size(205)} free across 2 volumes · D: nearly full", rep.Summary);
        Assert.Equal(AreaLevel.Warning, rep.Cards[0].Level);
        Assert.All(rep.Cards.Skip(1), c => Assert.Equal(AreaLevel.Ok, c.Level));
    }

    private const string TwoHealthyDrives = """
    [{"Name":"Samsung SSD 980 1TB","Serial":"S1","MediaType":"SSD","BusType":"NVMe","Health":"Healthy","Operational":"OK","Size":"1000204886016","Letters":"C"},
     {"Name":"WD Blue","Serial":"W2","MediaType":"HDD","BusType":"SATA","Health":"Healthy","Operational":"OK","Size":"2000398934016","Letters":"D"}]
    """;

    [Fact]
    public async Task A_nearly_full_volume_shows_in_its_drives_own_result_and_in_the_check_status()
    {
        var reads = 0;
        var (m, _, _) = Make((f, a) => ScriptedLauncher.Ok(TwoHealthyDrives), () => { Interlocked.Increment(ref reads); return [Volume("C", 500, 200), Volume("D", 100, 5)]; });
        var store = new ResultStore();
        var r = await new DiagnosticsService(store, [m]).RunAsync(DriveHealthModule.ModuleName);

        var perDrive = store.InstancesOf(DriveHealthModule.ModuleName);
        var samsung = perDrive.Single(x => x.InstanceLabel!.StartsWith("Samsung"));
        Assert.Equal(DiagnosticStatus.Ok, samsung.Status);
        Assert.Equal($"Healthy · {Size(200)} free on C:", samsung.Message);
        var wd = perDrive.Single(x => x.InstanceLabel!.StartsWith("WD"));
        Assert.Equal(DiagnosticStatus.Warning, wd.Status);
        Assert.Equal($"Needs attention · D: is nearly full ({Size(5)} free of {Size(100)})", wd.Message);
        // A drive's own report is that drive alone: no table of every volume.
        Assert.Equal("drive0", Assert.Single(Assert.IsType<AreaReport>(wd.Payload).Cards).Id);

        // The check's status, its message and the report agree.
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.StartsWith("1 of 2 need attention: WD Blue", r.Message);
        Assert.Contains("D: is nearly full", r.Message);
        var report = Assert.IsType<AreaReport>(r.Report());
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.Equal($"1 of 2 drives needs attention · {Size(205)} free across 2 volumes", report.Summary);
        Assert.Equal(new[] { DriveHealthModule.CapacityCardId, "drive0", "drive1" }, report.Cards.Select(c => c.Id));
        Assert.True(reads <= 2, $"read the volumes {reads} times"); // with the drives: detection, then one shared read
    }

    [Fact]
    public async Task When_every_drive_passes_the_check_message_carries_the_free_space()
    {
        var (m, _, _) = Make((f, a) => ScriptedLauncher.Ok(TwoHealthyDrives), () => [Volume("C", 500, 200), Volume("D", 1000, 600)]);
        var r = await new DiagnosticsService(new ResultStore(), [m]).RunAsync(DriveHealthModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal($"2 drives · all healthy · {Size(800)} free across 2 volumes", r.Message);
    }

    [Fact]
    public async Task A_single_drives_message_carries_its_free_space()
    {
        var (m, _, _) = Make((f, a) => ScriptedLauncher.Ok(Healthy), () => [Volume("C", 500, 200)]);
        var store = new ResultStore();
        var r = await new DiagnosticsService(store, [m]).RunAsync(DriveHealthModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal($"Healthy · {Size(200)} free on C:", r.Message);
        Assert.Equal($"1 drive · healthy · {Size(200)} free on C:", Assert.IsType<AreaReport>(r.Report()).Summary);
    }

    [Fact]
    public async Task Free_space_that_cannot_be_read_does_not_fail_the_drive_check()
    {
        var (m, _, log) = Make((f, a) => ScriptedLauncher.Ok(Healthy), () => throw new IOException("device not ready"));
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("1 drive · healthy", r.Message);
        Assert.Single(Assert.IsType<AreaReport>(r.Payload).Cards);
        Assert.Contains(log, s => s.Contains("free space not read") && s.Contains("device not ready"));
    }
}
