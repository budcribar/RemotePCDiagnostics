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

    private static (DriveHealthModule M, ScriptedLauncher L, List<string> Log) Make(Func<string, IReadOnlyList<string>, ProcessResult> run)
    {
        var log = new List<string>();
        var l = new ScriptedLauncher(run);
        return (new DriveHealthModule(new SystemCommandRunner(l, new LineLogger(s => log.Add(s))), ScriptedLauncher.Osquery(l, log)), l, log);
    }

    [Fact]
    public async Task Healthy_Drive_IsOk_WithFriendlySummary()
    {
        var (m, l, log) = Make((f, a) => ScriptedLauncher.Ok(Healthy));
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.StartsWith("1 drive · healthy", r.Message);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        var card = Assert.Single(rep.Cards, c => c.Title == "Samsung SSD 980 1TB");
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
        Assert.Equal("VirtualDisk", Assert.Single(rep.Cards, c => c.Title == "VirtualDisk").Title);
        Assert.Equal("Health not reported", rep.Cards.First(c => c.Title == "VirtualDisk").Headline);
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
        Assert.Contains(report.Cards, c => c.Title.StartsWith("Samsung"));
        Assert.Contains(report.Cards, c => c.Title.StartsWith("WD"));
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
        var m = new DriveHealthModule(new SystemCommandRunner(launcher), new OsqueryRunner(Path.GetTempPath(), launcher: launcher, fileExists: _ => true));
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

    [Fact]
    public void Build_with_capacities_inserts_capacity_card_and_includes_free_space_in_summary()
    {
        var drive = new DriveHealth("Samsung 980", "SN1", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 35, 10, ReadErrors: 0, WriteErrors: 0, PowerOnHours: 1000);
        var capacities = new List<DriveCapacityInfo>
        {
            new("C:\\", "OS", "NTFS", 500_000_000_000, 200_000_000_000),
            new("D:\\", "Data", "NTFS", 1_000_000_000_000, 600_000_000_000)
        };

        var rep = DriveHealthModule.Build([drive], capacities: capacities);

        Assert.Equal(2, rep.Cards.Count);
        var capCard = rep.Cards[0];
        Assert.Equal("capacity", capCard.Id);
        Assert.Equal("Drive Capacity", capCard.Title);
        Assert.Equal(AreaLevel.Neutral, capCard.Level);
        Assert.Equal(2, capCard.Rows.Count);
        Assert.Equal("C:\\", capCard.Rows[0].Values[0]);
        Assert.Equal("D:\\", capCard.Rows[1].Values[0]);

        // Summary includes total free space
        Assert.Contains("free", rep.Summary);
    }

    [Fact]
    public void Build_with_single_capacity_formats_single_drive_summary_and_warns_on_low_free_space()
    {
        var drive = new DriveHealth("Samsung 980", "SN1", "SSD", "NVMe", "Healthy", "OK", 500_000_000_000, 35, 10, ReadErrors: 0, WriteErrors: 0, PowerOnHours: 1000);
        var capacities = new List<DriveCapacityInfo>
        {
            new("C:\\", "OS", "NTFS", 100_000_000_000, 5_000_000_000) // 95% used
        };

        var rep = DriveHealthModule.Build([drive], capacities: capacities);

        Assert.Equal(2, rep.Cards.Count);
        var capCard = rep.Cards[0];
        Assert.Equal("capacity", capCard.Id);
        Assert.Equal(AreaLevel.Warning, capCard.Level);
        Assert.Equal(AreaLevel.Warning, capCard.Rows[0].Level);
        Assert.Contains("C", rep.Summary);
        Assert.Contains("free on C", rep.Summary);
    }
}
