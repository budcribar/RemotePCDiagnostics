using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;

namespace RemotePCDiagnostics.Tests;

public class GraphicsDriverCrashesTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private static string At(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");

    private static string Tdr(DateTimeOffset t, string driver = "nvlddmkm") => EventLogTests.Ev("Display", 4101, 3, At(t),
        $"Display driver {driver} stopped responding and has successfully recovered.", "System", $"<Data>{driver}</Data><Data></Data>");

    private static string NvError(DateTimeOffset t) => EventLogTests.Ev("nvlddmkm", 153, 2, At(t),
        @"The description for Event ID 153 from source nvlddmkm cannot be found. \Device\Video3 Error occurred on GPUID: 100", "System");

    private static string Wer(DateTimeOffset t, string eventName, string p1) => EventLogTests.Ev("Windows Error Reporting", 1001, 4, At(t),
        $"Fault bucket LKD_0x{p1}_Tdr:6_IMAGE_nvlddmkm.sys, type 0\nEvent Name: {eventName}\nResponse: Not available\nCab Id: 0\n\nProblem signature:\nP1: {p1}\nP2: ffffc30e5a3b2010",
        "Application",
        $"<Data>LKD_0x{p1}</Data><Data>0</Data><Data>{eventName}</Data><Data>Not available</Data><Data>0</Data><Data>{p1}</Data><Data>ffffc30e5a3b2010</Data>");

    private static string BugCheck(DateTimeOffset t, string code) => EventLogTests.Ev("Microsoft-Windows-WER-SystemErrorReporting", 1001, 2, At(t),
        $"The computer has rebooted from a bugcheck. The bugcheck was: {code} (0xffff9b0e1c5a3010, 0xfffff8063c2a1b3c, 0xffffffffc000009a, 0x0000000000000004).", "System");

    private static string Install(DateTimeOffset t, string version, string provider = "NVIDIA", string setupClass = "{4D36E968-E325-11CE-BFC1-08002BE10318}",
        string status = "0x0") => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-UserPnp' Guid='{"{96F4A050-7E31-453C-88BE-9634F4E02139}"}'/><EventID>20001</EventID><Level>4</Level>
        <TimeCreated SystemTime='{At(t)}'/><Channel>System</Channel><Computer>PC</Computer></System>
        <UserData><InstallDeviceID xmlns='http://manifests.microsoft.com/win/2004/08/windows/userpnp'><DriverName>oem42.inf</DriverName><DriverVersion>{version}</DriverVersion><DriverProvider>{provider}</DriverProvider><DeviceInstanceID>PCI\VEN_10DE&amp;DEV_2504</DeviceInstanceID><SetupClass>{setupClass}</SetupClass><RebootOption>false</RebootOption><UpgradeDevice>true</UpgradeDevice><IsDriverOEM>true</IsDriverOEM><InstallStatus>{status}</InstallStatus><DriverDescription>{provider} GeForce RTX 3060</DriverDescription></InstallDeviceID></UserData>
        <RenderingInfo Culture='en-US'><Message>Driver Management concluded the process to install driver oem42.inf for Device Instance ID PCI\VEN_10DE with the following status: {status}.</Message></RenderingInfo></Event>
        """;

    private static IReadOnlyList<WinEvent> Events(params string[] xml) => WindowsEventLog.Parse(string.Concat(xml), "System");
    private static IReadOnlyList<GpuDriverInstall> Installs(params string[] xml) => Events(xml).Select(GraphicsDriverCrashes.ToInstall).OfType<GpuDriverInstall>().ToList();
    private static readonly GpuDriver Nvidia = new("NVIDIA GeForce RTX 3060", "NVIDIA", "32.0.15.6094", new DateOnly(2026, 9, 12));

    [Fact]
    public void Driver_installs_are_read_from_UserData_and_only_display_class_successes_count()
    {
        var install = Assert.Single(Installs(Install(Now.AddDays(-3), "32.0.15.6094"),
            Install(Now.AddDays(-2), "1.0", setupClass: "{4d36e972-e325-11ce-bfc1-08002be10318}"),
            Install(Now.AddDays(-1), "2.0", status: "0xE0000203")));
        Assert.Equal("32.0.15.6094", install.Version);
        Assert.Equal("NVIDIA", install.Provider);
        Assert.Equal("NVIDIA GeForce RTX 3060", install.Device);
    }

    [Fact]
    public void Live_kernel_reports_are_read_from_WER_data_or_the_message()
    {
        var events = WindowsEventLog.Parse(Wer(Now, "LiveKernelEvent", "141") + Wer(Now, "LiveKernelEvent", "15e") + Wer(Now, "APPCRASH", "141"), "Application");
        Assert.Equal([0x141u], events.Select(GraphicsDriverCrashes.LiveKernelCode).OfType<uint>());

        var messageOnly = WindowsEventLog.Parse(EventLogTests.Ev("Windows Error Reporting", 1001, 4, At(Now),
            "Fault bucket , type 0\nEvent Name: LiveKernelEvent\n\nProblem signature:\nP1: 117\nP2: 0", "Application"), "Application").Single();
        Assert.Equal(0x117u, GraphicsDriverCrashes.LiveKernelCode(messageOnly));
    }

    [Fact]
    public void Graphics_blue_screens_are_told_apart_from_other_stop_codes()
    {
        var events = Events(BugCheck(Now, "0x00000116"), BugCheck(Now.AddHours(-1), "0x0000007e"));
        Assert.Equal([0x116u], events.Select(GraphicsDriverCrashes.GraphicsBugCheck).OfType<uint>());
    }

    [Fact]
    public void One_reset_logs_several_events_and_a_dump_and_counts_once_with_the_driver_of_the_time()
    {
        var t = Now.AddDays(-2);
        var events = Events(Tdr(t), NvError(t.AddSeconds(-1))).Concat(WindowsEventLog.Parse(Wer(t.AddMinutes(1), "LiveKernelEvent", "141"), "Application")).ToList();
        var dump = new MinidumpFile("WATCHDOG-20261117-1530.dmp", t.AddSeconds(5), 4_000_000, @"C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-20261117-1530.dmp");
        var installs = Installs(Install(Now.AddDays(-20), "31.0.15.5222"));

        var card = GraphicsDriverCrashes.Build(events, [dump], installs, [Nvidia], Now);

        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Equal("1 driver reset", card.Headline);
        var row = Assert.Single(card.Rows);
        Assert.Equal("Display driver stopped responding and recovered (TDR)", row.Values[1]);
        Assert.Equal("31.0.15.5222", row.Values[2]);
        Assert.Equal(dump.FullPath, row.DumpPath);
        Assert.Equal(3, row.ReviewKeys!.Count);
        Assert.Contains("Live kernel report", row.Detail);
        Assert.Contains("Current graphics driver: NVIDIA GeForce RTX 3060 32.0.15.6094", card.Note);
    }

    [Fact]
    public void No_events_is_ok_and_old_resets_are_neutral()
    {
        Assert.Equal(AreaLevel.Ok, GraphicsDriverCrashes.Build([], [], [], null, Now).Level);
        var old = GraphicsDriverCrashes.Build(Events(Tdr(Now.AddDays(-20))), [], [], [Nvidia], Now);
        Assert.Equal(AreaLevel.Neutral, old.Level);
        Assert.Equal("32.0.15.6094 (12 Sep 2026)", old.Rows.Single().Values[2]);
    }

    [Fact]
    public void Repeated_resets_or_a_graphics_blue_screen_are_an_error()
    {
        var five = Events(Enumerable.Range(1, 5).Select(d => Tdr(Now.AddDays(-d * 3))).ToArray());
        var card = GraphicsDriverCrashes.Build(five, [], [], [Nvidia], Now);
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Equal("5 driver resets", card.Headline);
        Assert.Contains("clean reinstall", card.Note);

        var bsod = GraphicsDriverCrashes.Build(Events(BugCheck(Now.AddDays(-10), "0x00000116")), [], [], [Nvidia], Now);
        Assert.Equal(AreaLevel.Error, bsod.Level);
        Assert.Equal("1 graphics blue screen", bsod.Headline);
        Assert.Equal("Graphics driver couldn't recover (0x116)", bsod.Rows.Single().Values[1]);
        Assert.Contains("GPU stress test", bsod.Note);
    }

    [Fact]
    public void Resets_that_started_after_a_driver_update_point_to_the_update()
    {
        var installs = Installs(Install(Now.AddDays(-6), "32.0.15.6094"));
        var card = GraphicsDriverCrashes.Build(Events(Tdr(Now.AddDays(-5)), Tdr(Now.AddDays(-1))), [], installs, [Nvidia], Now);
        Assert.StartsWith("The resets started after the graphics driver update on", card.Note);
        Assert.Contains("version 32.0.15.6094", card.Note);
        Assert.Contains("Roll the driver back", card.Note);
    }

    [Fact]
    public void Resets_across_driver_versions_point_to_the_graphics_card()
    {
        // Resets before and after the update: the update didn't start them, and they continued with the new driver.
        var installs = Installs(Install(Now.AddDays(-25), "31.0.15.5222"), Install(Now.AddDays(-10), "32.0.15.6094"));
        var events = Events(Tdr(Now.AddDays(-28)), Tdr(Now.AddDays(-20)), Tdr(Now.AddDays(-15)), Tdr(Now.AddDays(-5)), Tdr(Now.AddDays(-2)));
        var card = GraphicsDriverCrashes.Build(events, [], installs, [Nvidia], Now);
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Equal(["32.0.15.6094", "32.0.15.6094", "31.0.15.5222", "31.0.15.5222", "Unknown"], card.Rows.Select(r => r.Values[2]));
        Assert.Contains("points to the graphics card", card.Note);
    }

    [Fact]
    public void The_driver_is_matched_to_the_GPU_maker_on_a_PC_with_two_GPUs()
    {
        var intel = new GpuDriver("Intel(R) UHD Graphics 630", "Intel Corporation", "31.0.101.2125", new DateOnly(2026, 5, 1));
        var card = GraphicsDriverCrashes.Build(Events(Tdr(Now.AddDays(-1), "igfxn")), [], [], [Nvidia, intel], Now);
        Assert.Equal("31.0.101.2125 (1 May 2026)", card.Rows.Single().Values[2]);
    }

    [Fact]
    public void The_card_offers_the_GPU_stress_test_unless_a_driver_update_started_the_resets()
    {
        Assert.Null(GraphicsDriverCrashes.Build([], [], [], [Nvidia], Now).RunCheck);

        var bsod = GraphicsDriverCrashes.Build(Events(BugCheck(Now.AddDays(-10), "0x00000116")), [], [], [Nvidia], Now);
        Assert.Equal(new AreaCheckLink(ModuleSlugs.GpuStress, "Run GPU stress test"), bsod.RunCheck);
        var exported = AreaReportExport.ToJson(new AreaReport([bsod], "x", DiagnosticStatus.Error));
        Assert.Contains("\"runCheck\":{\"checkId\":\"GpuStress\",\"buttonText\":\"Run GPU stress test\"}", exported);

        var afterUpdate = GraphicsDriverCrashes.Build(Events(Tdr(Now.AddDays(-5))), [], Installs(Install(Now.AddDays(-6), "32.0.15.6094")), [Nvidia], Now);
        Assert.Null(afterUpdate.RunCheck);
    }

    [Fact]
    public void The_queries_fit_the_host_query_limits() =>
        Assert.All([GraphicsDriverCrashes.SystemQuery, GraphicsDriverCrashes.InstallQuery, GraphicsDriverCrashes.ReportQuery],
            q => Assert.InRange(q.Length, 1, HostCapabilities.MaxXPathLength));

    [Fact]
    public async Task Crashes_shows_the_graphics_card_in_user_mode_and_its_status_counts()
    {
        var host = new GraphicsHost
        {
            Resets = Events(Tdr(Now.AddDays(-1)), NvError(Now.AddDays(-1).AddSeconds(-2))),
            Installs = Events(Install(Now.AddDays(-20), "31.0.15.5222")),
            System = Events(BugCheck(Now.AddDays(-3), "0x00000116")),
            Reports = WindowsEventLog.Parse(Wer(Now.AddDays(-1).AddSeconds(30), "LiveKernelEvent", "141"), "Application"),
            Dumps = [new("WATCHDOG-1.dmp", Now.AddDays(-1), 1024, @"C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-1.dmp")],
        };
        var drivers = new FixedDrivers([new("NVIDIA GeForce RTX 3060", "DISPLAY", "NVIDIA", "32.0.15.6094", new DateOnly(2026, 9, 12), true),
            new("Realtek Audio", "MEDIA", "Realtek", "6.0.9600.1", null, true)]);
        var dumps = new FixedCrashDumps(liveKernelReports: host.Dumps);
        var result = await new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, dumps, drivers, host).RefreshAsync(null);
        var report = Assert.IsType<AreaReport>(result.Payload);
        var card = report.Cards.Single(c => c.Id == GraphicsDriverCrashes.CardId);
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Equal("1 driver reset, 1 graphics blue screen", card.Headline);
        Assert.Equal(DiagnosticStatus.Error, result.Status);
        Assert.Contains("1 driver reset, 1 graphics blue screen", report.Summary);
        Assert.Equal(1, drivers.Reads);
        Assert.Contains("Current graphics driver: NVIDIA GeForce RTX 3060 32.0.15.6094", card.Note);
        Assert.Equal(["bsods", "power", "whea", "minidumps", "graphics", "crashes", "hangs", "apps"], report.Cards.Select(c => c.Id));

        // The System log can't be read: the card says so instead of showing Ok.
        host.Resets = null;
        var failed = Assert.IsType<AreaReport>((await new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, dumps, drivers, host).RefreshAsync(null)).Payload);
        Assert.NotNull(failed.Cards.Single(c => c.Id == GraphicsDriverCrashes.CardId).ErrorText);
    }

    private sealed class GraphicsHost : IHostQueries
    {
        public IReadOnlyList<WinEvent>? Resets { get; set; } = [];
        public IReadOnlyList<WinEvent> Installs { get; init; } = [];
        public IReadOnlyList<WinEvent> System { get; init; } = [];
        public IReadOnlyList<WinEvent> Reports { get; init; } = [];
        public IReadOnlyList<MinidumpFile> Dumps { get; init; } = [];

        public Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<RemotePCDiagnostics.Core.Osquery.OsqueryQueryResult> SelectAsync(string sql, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<RemotePCDiagnostics.Core.Areas.DriveList?> ReadDrivesAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyDictionary<char, RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default) =>
            Task.FromResult(xpath == GraphicsDriverCrashes.SystemQuery ? Resets
                : xpath == GraphicsDriverCrashes.InstallQuery ? Installs
                : xpath == GraphicsDriverCrashes.ReportQuery ? Reports
                : log == "System" ? System : (IReadOnlyList<WinEvent>?)[]);
        public Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<MinidumpFile>>([]);
        public Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyCollection<string>>([]);
    }
}
