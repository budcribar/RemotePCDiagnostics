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
        return (new DriveHealthModule(new SystemCommandRunner(l, s => log.Add(s)), ScriptedLauncher.Osquery(l, log)), l, log);
    }

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
        Assert.Equal("Drive health", svc.Modules.Single().DisplayName);
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
}
