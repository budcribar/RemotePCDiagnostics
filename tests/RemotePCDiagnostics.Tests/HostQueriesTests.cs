using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Host queries: a module that ships with the app runs in user mode (the module host, restricted token) and asks the app for the reads
/// that need administrator rights. The app answers only modules that ship with it, only the capabilities their module.json lists, and only
/// with its own statements and logs.
/// </summary>
public sealed class HostQueriesTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-hq-" + Guid.NewGuid().ToString("N"));
    public HostQueriesTests() => Directory.CreateDirectory(_root);
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    private static string Dll(string name) => Path.Combine(AppContext.BaseDirectory, name);
    private static ModuleManifest ManifestOf(string file) => ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Dll(file))).Manifest;
    private static UserModeModule Bundled(string file)
    {
        var m = ManifestOf(file);
        return new UserModeModule(Dll(file), m, BuiltInModules.Descriptors.Single(d => d.Id == m.Id)) { Bundled = true };
    }

    private static UserModeModule With(params string[] capabilities) =>
        new("x.dll", new ModuleManifest { Id = ModuleIds.Services, Slug = "Services", Capabilities = [.. capabilities] },
            BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.Services)) { Bundled = true };

    private static ModuleHostMessage Query(string capability, object? args = null) => new()
    {
        Type = "query", Id = 7, Capability = capability, Args = args is null ? null : JsonSerializer.SerializeToElement(args, HostCapabilities.Json),
    };

    private static readonly SensorSnapshot Snapshot = new(
        [new SensorReading("Intel Core i7", HardwareKind.Cpu, "CPU Package", SensorKind.Temperature, 61.5, 40, 80, "°C"),
         new SensorReading("Board", HardwareKind.Motherboard, "Fan #1", SensorKind.Fan, double.NaN, null, null, "RPM")], IsElevated: true);

    private sealed class FakeSensors : ISensorProvider
    {
        public ModuleAvailability CheckAvailability() => ModuleAvailability.Available;
        public SensorSnapshot Read() => Snapshot;
    }

    /// <summary>osquery as if installed, answering every statement with these rows.</summary>
    private sealed class FakeOsquery(string json) : IProcessLauncher
    {
        public List<IReadOnlyList<string>> Calls { get; } = [];
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Calls.Add(arguments);
            return Task.FromResult(new ProcessResult(0, json, ""));
        }
    }

    private const string ServiceRows = """
        [{"name":"Spooler","display_name":"Print Spooler","status":"RUNNING","start_type":"AUTO_START","user_account":"LocalSystem","description":"Prints"},
         {"name":"wuauserv","display_name":"Windows Update","status":"STOPPED","start_type":"AUTO_START","user_account":"LocalSystem","description":""}]
        """;

    private HostQueryBackend Backend(IProcessLauncher? osquery = null) => new()
    {
        Sensors = new FakeSensors(),
        Osquery = new OsqueryRunner(baseDirectory: _root, launcher: osquery ?? new FakeOsquery(ServiceRows), fileExists: _ => true),
        Commands = new SystemCommandRunner(),
        Retrims = new FixedRetrims(),
        Minidumps = () => [new MinidumpFile("110726-01.dmp", new DateTimeOffset(2026, 11, 7, 9, 0, 0, TimeSpan.Zero), 1024)],
        EventReviews = () => ["Application|1000|x"],
    };

    private sealed class FixedRetrims : IRetrimHistory
    {
        public Task<IReadOnlyDictionary<char, RetrimRecord>> LatestAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyDictionary<char, RetrimRecord>>(new Dictionary<char, RetrimRecord> { ['C'] = new(new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero), RetrimSource.Windows) });
    }

    [Fact]
    public async Task An_unsigned_module_gets_no_answers()
    {
        var unsigned = With(HostCapabilities.SensorsRead) with { Bundled = false };
        var a = await new HostQueryServer(Backend()).AnswerAsync(unsigned, Query(HostCapabilities.SensorsRead));
        Assert.False(a.Ok);
        Assert.Equal("notAllowed", a.Error);
        Assert.Equal(7, a.Id);
    }

    [Fact]
    public async Task Only_capabilities_the_module_json_lists_are_answered()
    {
        var server = new HostQueryServer(Backend());
        var a = await server.AnswerAsync(With(HostCapabilities.OsquerySelect), Query(HostCapabilities.SensorsRead));
        Assert.Equal("notDeclared", a.Error);
        Assert.Equal("badRequest", (await server.AnswerAsync(With("files.read"), Query("files.read"))).Error);
    }

    [Theory]
    [InlineData("SELECT * FROM users;")]
    [InlineData("SELECT name FROM services;")]
    [InlineData("")]
    public async Task Osquery_runs_only_the_apps_own_statements(string sql)
    {
        var osquery = new FakeOsquery("[]");
        var a = await new HostQueryServer(Backend(osquery)).AnswerAsync(With(HostCapabilities.OsquerySelect), Query(HostCapabilities.OsquerySelect, new { sql }));
        Assert.Equal("notAllowed", a.Error);
        Assert.Empty(osquery.Calls); // refused before anything ran
    }

    [Theory]
    [InlineData("Security", "*", "10", "notAllowed")]
    [InlineData("Microsoft-Windows-PowerShell/Operational", "*", "10", "notAllowed")]
    [InlineData("System", "", "10", "badRequest")]
    [InlineData("System", "*", "0", "badRequest")]
    [InlineData("System", "*", "5000", "badRequest")]
    public async Task Event_log_queries_are_checked(string log, string xpath, string max, string error)
    {
        var a = await new HostQueryServer(Backend()).AnswerAsync(With(HostCapabilities.EventLogQuery), Query(HostCapabilities.EventLogQuery, new { log, xpath, max }));
        Assert.False(a.Ok);
        Assert.Equal(error, a.Error);
    }

    /// <summary>The module host's client and the app's server, joined in memory: what a module asks for comes back typed.</summary>
    private HostQueriesClient Joined(UserModeModule module, HostQueryBackend backend)
    {
        var server = new HostQueryServer(backend);
        HostQueriesClient? client = null;
        client = new HostQueriesClient(q => _ = Task.Run(async () =>
            client!.Complete(ModuleHostMessage.Parse((await server.AnswerAsync(module, ModuleHostMessage.Parse(q.ToLine())!)).ToLine())!)));
        return client;
    }

    [Fact]
    public async Task Answers_come_back_typed_over_the_protocol()
    {
        var all = With([.. HostCapabilities.All]);
        var client = Joined(all, Backend());

        var snap = await client.ReadSensorsAsync();
        Assert.Equal(2, snap.Readings.Count);
        Assert.Equal(61.5, snap.Readings[0].Value);
        Assert.True(double.IsNaN(snap.Readings[1].Value!.Value)); // a sensor that reports nothing survives the trip
        Assert.True((await client.SensorsAvailabilityAsync()).IsAvailable);

        var rows = await client.SelectAsync(ServicesModule.Sql);
        Assert.True(rows.Success);
        Assert.Equal("Spooler", rows.Rows![0]["name"]);

        var retrims = await client.ReadRetrimsAsync();
        Assert.Equal(RetrimSource.Windows, retrims['C'].Source);
        Assert.Equal("110726-01.dmp", Assert.Single(await client.ReadMinidumpsAsync()).FileName);
        Assert.Equal(["Application|1000|x"], await client.ReadEventReviewsAsync());

        var refused = await Assert.ThrowsAsync<HostQueryException>(() => client.SelectAsync("SELECT * FROM users;"));
        Assert.Equal("notAllowed", refused.Error);
    }

    [Fact]
    public async Task Services_in_user_mode_lists_what_the_app_read()
    {
        var module = new ServicesModule(new OsqueryRunner(baseDirectory: _root), Joined(With(HostCapabilities.OsquerySelect), Backend()));
        Assert.True((await module.CheckAvailabilityAsync()).IsAvailable); // no osquery of its own needed
        var r = await module.RefreshAsync(null);
        var report = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal(2, report.Cards.Single(c => c.Id == "all").Rows!.Count);
        Assert.Contains("1 running", report.Summary);
    }

    [Fact]
    public async Task A_refused_query_is_a_failed_check_not_a_crash()
    {
        var module = new ServicesModule(new OsqueryRunner(baseDirectory: _root), Joined(With(/* nothing declared */), Backend()));
        var r = await module.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
    }

    [Fact]
    public async Task Crashes_in_user_mode_read_the_logs_through_the_app()
    {
        var asked = new List<(string Log, int Max)>();
        var queries = new RecordingQueries(asked);
        var module = new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, host: queries);
        var r = await module.RefreshAsync(null);
        Assert.IsType<AreaReport>(r.Payload);
        Assert.Contains(("Application", CrashesModule.Max), asked);
        Assert.Contains(asked, a => a.Log == "System");
        Assert.True(queries.DumpsRead);
    }

    private sealed class RecordingQueries(List<(string Log, int Max)> asked) : IHostQueries
    {
        public bool DumpsRead { get; private set; }
        public Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<OsqueryQueryResult> SelectAsync(string sql, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ProcessResult?> ReadDrivesAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyDictionary<char, RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default)
        {
            lock (asked) asked.Add((log, max));
            return Task.FromResult<IReadOnlyList<WinEvent>?>([]);
        }
        public Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct = default) { DumpsRead = true; return Task.FromResult<IReadOnlyList<MinidumpFile>>([]); }
        public Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyCollection<string>>([]);
    }

    [Theory]
    [InlineData("RemotePCDiagnostics.Modules.Sensors.dll", new[] { HostCapabilities.SensorsRead })]
    [InlineData("RemotePCDiagnostics.Modules.DriveHealth.dll", new[] { HostCapabilities.StorageDrives, HostCapabilities.StorageRetrims, HostCapabilities.OsquerySelect })]
    [InlineData("RemotePCDiagnostics.Modules.Services.dll", new[] { HostCapabilities.OsquerySelect })]
    [InlineData("RemotePCDiagnostics.Modules.Crashes.dll", new[] { HostCapabilities.EventLogQuery, HostCapabilities.Minidumps, HostCapabilities.EventReviews })]
    public void The_four_modules_run_in_user_mode_and_list_what_they_ask_for(string file, string[] capabilities)
    {
        var m = ManifestOf(file);
        Assert.False(m.NeedsAdmin);
        Assert.Null(m.InProcessOnly);
        Assert.Equal(capabilities.Order(), m.Capabilities.Order());
        // Out of process they get a restricted token, not the app's.
        Assert.False(ModuleHosting.For(m, ModuleProcessMode.OutOfProcess).Elevated);
    }

    [Fact]
    public void An_unknown_capability_disables_the_module()
    {
        var m = new ModuleManifest { Id = Guid.NewGuid(), Slug = "acme.x", EntryType = "X", Capabilities = ["registry.write"] };
        Assert.Equal("unknown capability 'registry.write'", m.Problem(new Version(9, 0)));
    }

    [Fact]
    public async Task Sensors_answer_from_the_real_module_host_with_its_own_report()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.Sensors.dll");
        using var proxy = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(Backend()));
        Assert.True((await proxy.CheckAvailabilityAsync()).IsAvailable);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var r = await proxy.RefreshAsync(null, cts.Token);
        // The page reads a SensorReport: it arrives typed, so the page is the same as in process.
        var report = Assert.IsType<SensorReport>(r.Payload);
        Assert.Equal(61.5, report.Groups.Single(g => g.Id == "cpu").Hottest);
        Assert.StartsWith("CPU 62°C", r.Message);
    }

    [Fact]
    public async Task Services_answer_from_the_real_module_host()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.Services.dll");
        using var proxy = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(Backend()));
        Assert.True((await proxy.CheckAvailabilityAsync()).IsAvailable);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var r = await proxy.RefreshAsync(null, cts.Token);
        var report = Assert.IsType<AreaReport>(r.Payload);
        Assert.Contains("1 running", report.Summary);
    }

    [Fact]
    public void The_sensors_page_renders_in_the_app_when_the_check_runs_out_of_process()
    {
        var hosting = ModuleHosting.For(ManifestOf("RemotePCDiagnostics.Modules.Sensors.dll"), ModuleProcessMode.OutOfProcess);
        Assert.True(hosting.OutOfProcess);
        var layout = ModulePageLayout.For(hosting, outOfProcess: true, bundled: true, hasDetails: true, frameHost: false);
        Assert.Equal(ModuleOwnUi.InApp, layout.OwnUi);
        Assert.False(layout.ShowReport);
        Assert.Null(layout.Notice);
    }

    [Fact]
    public void Other_payloads_cross_only_when_listed()
    {
        Assert.Null(ModuleHostPayloads.Write(new { secret = 1 }));
        var report = LibreHardwareMonitorModule.BuildReport(Snapshot);
        var (payload, type) = ModuleHostPayloads.Write(report)!.Value;
        Assert.IsType<SensorReport>(ModuleHostPayloads.Read("Sensors", DiagnosticStatus.Ok, "", payload, type)!.Payload);
        Assert.Null(ModuleHostPayloads.Read("Sensors", DiagnosticStatus.Ok, "", payload, "System.IO.FileInfo"));
    }

    private const string DriveRows = """
        [{"Name":"SAMSUNG MZVL2512","Serial":"S1","UniqueId":"U1","MediaType":"SSD","BusType":"NVMe","Health":"Healthy","Operational":"OK","SizeBytes":"512110190592","TemperatureC":"38","Wear":"3","ReadErrors":"0","WriteErrors":"0","PowerOnHours":"1200","Letters":"C"}]
        """;

    [Fact]
    public async Task Drive_health_answers_from_the_real_module_host()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.DriveHealth.dll");
        var backend = Backend() with { Commands = new SystemCommandRunner(new FakeOsquery(DriveRows)) };
        using var proxy = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(backend));
        Assert.True((await proxy.CheckAvailabilityAsync()).IsAvailable);
        var steps = new List<string>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var r = await proxy.RefreshAsync(new Progress<string>(steps.Add), cts.Token);
        var report = Assert.IsType<AreaReport>(r.Payload);
        Assert.Contains(report.Cards, c => c.Title.Contains("SAMSUNG"));
    }

    private const string TwoDrives = """
        [{"Name":"SAMSUNG MZVL2512","Serial":"S1","UniqueId":"U1","MediaType":"SSD","BusType":"NVMe","Health":"Healthy","Operational":"OK","SizeBytes":"512110190592","TemperatureC":"38","Wear":"3","ReadErrors":"0","WriteErrors":"0","PowerOnHours":"1200","Letters":"C"},
         {"Name":"WDC WD20EZRZ","Serial":"S2","UniqueId":"U2","MediaType":"HDD","BusType":"SATA","Health":"Healthy","Operational":"OK","SizeBytes":"2000398934016","TemperatureC":"33","Wear":"","ReadErrors":"0","WriteErrors":"0","PowerOnHours":"30000","Letters":"D"}]
        """;

    [Fact]
    public async Task Drive_health_out_of_process_keeps_one_run_and_one_card_per_drive()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.DriveHealth.dll");
        Assert.True(module.Manifest.PerDevice);
        var backend = Backend() with { Commands = new SystemCommandRunner(new FakeOsquery(TwoDrives)) };
        var inner = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(backend));
        using var proxy = Assert.IsType<PerDeviceModuleProxy>(PerDeviceModuleProxy.For(inner));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var detection = await proxy.DetectAsync(cts.Token);
        Assert.True(detection.Applies);
        Assert.Equal(2, detection.Instances.Count);
        var results = new List<DiagnosticResult>();
        foreach (var drive in detection.Instances)
        {
            var r = await proxy.RefreshAsync(drive, null, cts.Token);
            var one = Assert.IsType<AreaReport>(r.Payload);
            Assert.Contains(one.Cards, c => c.Title.Contains(drive.Label.Split(' ')[0]));
            results.Add(r with { InstanceKey = drive.Key, InstanceLabel = drive.Label });
        }
        // One report with a card per drive, as the module builds it in process.
        var combined = Assert.IsType<AreaReport>(proxy.Combine(results));
        Assert.Contains(combined.Cards, c => c.Title.Contains("SAMSUNG"));
        Assert.Contains(combined.Cards, c => c.Title.Contains("WDC"));
        // Its storage clean-up panel, as in process.
        Assert.Equal(AreaPanels.StorageCleanup, ((IDiagnosticModule)proxy).Feature<IHasAreaPanels>()?.Panels);
    }

    [Fact]
    public void Only_a_bundled_per_device_module_gets_the_per_device_stand_in()
    {
        var drive = Bundled("RemotePCDiagnostics.Modules.DriveHealth.dll");
        using var bundled = new UserModeModuleProxy(drive, new ProcessModuleHostLauncher(AppContext.BaseDirectory));
        Assert.IsType<PerDeviceModuleProxy>(PerDeviceModuleProxy.For(bundled));
        using var unsigned = new UserModeModuleProxy(drive with { Bundled = false }, new ProcessModuleHostLauncher(AppContext.BaseDirectory));
        Assert.Same(unsigned, PerDeviceModuleProxy.For(unsigned));
        using var services = new UserModeModuleProxy(Bundled("RemotePCDiagnostics.Modules.Services.dll"), new ProcessModuleHostLauncher(AppContext.BaseDirectory));
        Assert.Same(services, PerDeviceModuleProxy.For(services));
    }

    [Fact]
    public async Task A_query_the_app_never_answers_fails_instead_of_hanging()
    {
        var client = new HostQueriesClient(_ => { }) { AnswerTimeout = TimeSpan.FromMilliseconds(200) };
        var ex = await Assert.ThrowsAsync<HostQueryException>(() => client.ReadDrivesAsync());
        Assert.Equal("timedOut", ex.Error);
    }

    [Fact]
    public async Task Two_overlapping_runs_both_finish()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.DriveHealth.dll");
        var backend = Backend() with { Commands = new SystemCommandRunner(new FakeOsquery(DriveRows)) };
        using var proxy = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(backend));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var a = proxy.RefreshAsync(null, cts.Token);
        var avail = proxy.CheckAvailabilityAsync(cts.Token);
        var b = proxy.RefreshAsync(null, cts.Token);
        var results = await Task.WhenAll(a, b);
        await avail;
        Assert.All(results, r => Assert.IsType<AreaReport>(r.Payload));
        var c = await proxy.RefreshAsync(null, cts.Token);
        Assert.IsType<AreaReport>(c.Payload);
    }

    [Fact]
    public async Task A_module_host_exits_after_its_run_and_starts_again_for_the_next()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.DriveHealth.dll");
        Assert.False(module.Manifest.KeepAlive);
        var backend = Backend() with { Commands = new SystemCommandRunner(new FakeOsquery(DriveRows)) };
        using var proxy = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(backend))
            { IdleExit = TimeSpan.FromMilliseconds(200) };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        Assert.True((await proxy.CheckAvailabilityAsync(cts.Token)).IsAvailable);
        Assert.IsType<AreaReport>((await proxy.RefreshAsync(null, cts.Token)).Payload);
        await WaitUntil(() => !proxy.IsHostRunning);
        Assert.IsType<AreaReport>((await proxy.RefreshAsync(null, cts.Token)).Payload);
        await WaitUntil(() => !proxy.IsHostRunning);
    }

    [Fact]
    public async Task The_sensors_module_host_stays_running_between_reads()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.Sensors.dll");
        Assert.True(module.Manifest.KeepAlive);
        using var proxy = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(Backend()))
            { IdleExit = TimeSpan.FromMilliseconds(100) };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await proxy.RefreshAsync(null, cts.Token);
        await Task.Delay(1000);
        Assert.True(proxy.IsHostRunning);
    }

    [Fact]
    public async Task Services_rows_keep_their_Start_and_Stop_buttons_out_of_process()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.Services.dll");
        using var proxy = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(Backend()));
        Assert.Null(proxy.Feature<IServiceRows>()); // nothing to act on before a run
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await proxy.RefreshAsync(null, cts.Token);
        // The page asks the stand-in as it asks the module in process.
        var rows = ((IDiagnosticModule)proxy).Feature<IServiceRows>()!;
        Assert.True(rows.Latest["spooler"].IsRunning);
        Assert.True(rows.Latest["wuauserv"].IsStopped);
        Assert.Same(rows.Latest, proxy.Feature<IServiceRows>()!.Latest); // the same until the next run, so the page keeps its live overrides
        Assert.Null(proxy.Feature<IHangEvidenceSource>());
    }

    [Fact]
    public async Task Crashes_find_related_evidence_in_the_real_module_host()
    {
        var module = Bundled("RemotePCDiagnostics.Modules.Crashes.dll");
        using var proxy = new UserModeModuleProxy(module, new ProcessModuleHostLauncher(AppContext.BaseDirectory), hostQueries: new HostQueryServer(Backend()));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        await proxy.RefreshAsync(null, cts.Token);
        var hangs = proxy.Feature<IHangEvidenceSource>()!;
        Assert.Equal(CrashesModule.HangsCardId, hangs.HangCardId);
        // The call starts a fresh host when the last one has exited, and the module's event log reads go through the app meanwhile.
        await WaitUntil(() => !proxy.IsHostRunning);
        var text = await hangs.FindHangEvidenceAsync([new HangOccurrence(DateTimeOffset.Now.AddDays(-1), "app.exe", @"C:\app.exe", "", "Hang", Guid.NewGuid().ToString())], cts.Token);
        Assert.StartsWith("Historical timeline.", text);
    }

    [Fact]
    public void Security_audit_page_renders_in_the_app_when_the_audit_runs_out_of_process()
    {
        var manifest = ManifestOf("RemotePCDiagnostics.Modules.SecurityAudit.dll");
        var hosting = ModuleHosting.For(manifest, ModuleProcessMode.OutOfProcess);
        Assert.True(hosting is { OutOfProcess: true, Elevated: true });
        Assert.Equal(new ModulePageLayout(ModuleOwnUi.InApp, false), ModulePageLayout.For(hosting, outOfProcess: true, bundled: true, hasDetails: true, frameHost: false));
        // Its report crosses typed, so the page reads it as in process.
        var report = new RemotePCDiagnostics.Core.Security.SecurityAuditReport(
            [new("1100", "Account Policies", "Account lockout threshold", "Medium", "0", "10", RemotePCDiagnostics.Core.Security.AuditOutcome.Failed)],
            Profile: new(false, false, false, "Professional"));
        var (payload, type) = ModuleHostPayloads.Write(report)!.Value;
        var back = Assert.IsType<RemotePCDiagnostics.Core.Security.SecurityAuditReport>(ModuleHostPayloads.Read("SecurityAudit", DiagnosticStatus.Error, "", payload, type)!.Payload);
        Assert.Equal(report.Findings, back.Findings);
        Assert.Equal(report.Shown.Count, back.Shown.Count);
    }

    [Fact]
    public async Task Bundled_modules_share_one_module_host_and_unsigned_ones_stay_separate()
    {
        var raw = new ProcessModuleHostLauncher(AppContext.BaseDirectory);
        var started = new List<string>();
        var shared = new SharedBundledHost(m => { lock (started) started.Add(m.Path); return raw.StartRaw(m); });
        var launcher = new DelegatingLauncher(shared.Start);
        var server = new HostQueryServer(Backend());

        using var services = new UserModeModuleProxy(Bundled("RemotePCDiagnostics.Modules.Services.dll"), launcher, hostQueries: server)
            { IdleExit = TimeSpan.FromMilliseconds(200) };
        using var sensors = new UserModeModuleProxy(Bundled("RemotePCDiagnostics.Modules.Sensors.dll"), launcher, hostQueries: server)
            { IdleExit = TimeSpan.FromMilliseconds(200) };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));

        // Running two bundled user-mode modules in parallel starts a single shared module host (--shared).
        var runs = await Task.WhenAll(services.RefreshAsync(null, cts.Token), sensors.RefreshAsync(null, cts.Token));
        Assert.IsType<AreaReport>(runs[0].Payload);
        Assert.IsType<SensorReport>(runs[1].Payload);
        Assert.Equal(["--shared"], started);

        // An unsigned module never shares the bundled host: it gets its own process.
        var sampleDll = Path.Combine(AppContext.BaseDirectory, "sample-module", "SampleModule.dll");
        var (sampleManifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(sampleDll));
        var unsigned = new UserModeModule(sampleDll, sampleManifest, sampleManifest.ToDescriptor(sampleManifest.Slug));
        using var unsignedProxy = new UserModeModuleProxy(unsigned, launcher) { IdleExit = TimeSpan.FromMilliseconds(200) };
        var unsignedResult = await unsignedProxy.RefreshAsync(null, cts.Token);
        Assert.Equal(DiagnosticStatus.Ok, unsignedResult.Status);
        Assert.Equal(["--shared", sampleDll], started);
    }

    private sealed class DelegatingLauncher(Func<UserModeModule, IModuleHostConnection> start) : IModuleHostLauncher
    {
        public IModuleHostConnection Start(UserModeModule module) => start(module);
    }

    private static async Task WaitUntil(Func<bool> done)
    {
        var until = DateTime.UtcNow.AddSeconds(15);
        while (!done()) { Assert.True(DateTime.UtcNow < until, "timed out"); await Task.Delay(50); }
    }
}

/// <summary>The app answers a module's host queries in the background: a slow one holds up neither the others nor a stop.</summary>
public sealed class HostQueryDispatchTests
{
    private static UserModeModule Services() =>
        new("x.dll", new ModuleManifest { Id = ModuleIds.Services, Slug = "Services", Capabilities = [HostCapabilities.OsquerySelect, HostCapabilities.Minidumps] },
            BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.Services)) { Bundled = true };

    /// <summary>osquery that never finishes until its run is cancelled.</summary>
    private sealed class HangingOsquery : IProcessLauncher
    {
        public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    private static HostQueryServer Server() => new(new HostQueryBackend
    {
        Osquery = new OsqueryRunner(baseDirectory: Path.GetTempPath(), launcher: new HangingOsquery(), fileExists: _ => true),
        Minidumps = () => [],
    });

    private static ModuleHostMessage Query(int id, string capability, object? args = null) => new()
    {
        Type = "query", Id = id, Capability = capability, Args = args is null ? null : JsonSerializer.SerializeToElement(args, HostCapabilities.Json),
    };

    private static readonly ModuleHostMessage SlowQuery = Query(1, HostCapabilities.OsquerySelect, new { sql = ServicesModule.Sql });
    private static readonly ModuleHostMessage FastQuery = Query(2, HostCapabilities.Minidumps);

    /// <summary>A module host played by the test: <paramref name="onLine"/> sees each line the app writes and returns the lines to send back.</summary>
    private sealed class ScriptedHost(Func<ModuleHostMessage, IEnumerable<ModuleHostMessage>> onLine) : IModuleHostLauncher, IModuleHostConnection
    {
        private readonly System.Threading.Channels.Channel<string> _out = System.Threading.Channels.Channel.CreateUnbounded<string>();
        public System.Collections.Concurrent.ConcurrentQueue<ModuleHostMessage> Written { get; } = new();
        public IModuleHostConnection Start(UserModeModule module) => this;
        public Task WriteLineAsync(string line, CancellationToken ct)
        {
            var m = ModuleHostMessage.Parse(line)!;
            Written.Enqueue(m);
            foreach (var reply in onLine(m)) _out.Writer.TryWrite(reply.ToLine());
            return Task.CompletedTask;
        }
        public async Task<string?> ReadLineAsync(CancellationToken ct) => await _out.Reader.ReadAsync(ct);
        public bool HasExited => false;
        public void Kill() { }
        public void Dispose() { }
        public ModuleHostMessage? AnswerTo(int id) => Written.FirstOrDefault(w => w.Type == "answer" && w.Id == id);
    }

    private static ModuleHostMessage Result(bool cancelled = false) => new() { Type = "result", Status = DiagnosticStatus.Ok, Message = "done", Cancelled = cancelled };

    [Fact]
    public async Task A_slow_query_does_not_hold_up_the_next_one()
    {
        var host = new ScriptedHost(m => m switch
        {
            { Type: "refresh" } => [SlowQuery, FastQuery],
            { Type: "answer", Id: 2 } => [Result()], // the module finishes once the fast query is answered
            _ => [],
        });
        using var proxy = new UserModeModuleProxy(Services(), host, hostQueries: Server()) { IdleExit = Timeout.InfiniteTimeSpan };
        var run = proxy.RefreshAsync(null);
        Assert.Same(run, await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(20))));
        Assert.Equal(DiagnosticStatus.Ok, (await run).Status);
        Assert.True(host.AnswerTo(2)!.Ok);
        // The run is over, so the query still running is answered "cancelled".
        var until = DateTime.UtcNow.AddSeconds(10);
        while (host.AnswerTo(1) is null && DateTime.UtcNow < until) await Task.Delay(20);
        Assert.Equal("cancelled", host.AnswerTo(1)?.Error);
    }

    private static UserModeModule Crashes(bool bundled = true) =>
        new("x.dll", new ModuleManifest { Id = ModuleIds.Crashes, Slug = "Crashes", Capabilities = [HostCapabilities.Minidumps] },
            BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.Crashes)) { Bundled = bundled };

    private static readonly Dictionary<string, JsonElement> HangPage = new()
    {
        [ModulePageCalls.HangEvidence] = JsonSerializer.SerializeToElement(new { cardId = "hangs" }, ModuleHostMessage.Json),
    };

    [Fact]
    public async Task A_call_from_the_page_answers_the_modules_queries_and_returns_its_value()
    {
        var host = new ScriptedHost(m => m switch
        {
            { Type: "refresh" } => [new() { Type = "result", Status = DiagnosticStatus.Ok, Message = "done", PageData = HangPage }],
            { Type: "call", Name: ModulePageCalls.HangEvidence } => [FastQuery], // the module reads the app's data first
            { Type: "answer", Id: 2 } => [new() { Type = "return", Id = 1, Ok = true, Value = JsonSerializer.SerializeToElement("timeline") }],
            _ => [],
        });
        using var proxy = new UserModeModuleProxy(Crashes(), host, hostQueries: Server()) { IdleExit = Timeout.InfiniteTimeSpan };
        await proxy.RefreshAsync(null);
        var hangs = proxy.Feature<IHangEvidenceSource>()!;
        Assert.Equal("hangs", hangs.HangCardId);
        Assert.Equal("timeline", await hangs.FindHangEvidenceAsync([new HangOccurrence(DateTimeOffset.Now, "a.exe", "", "", "Hang", "")], CancellationToken.None));
        var call = Assert.Single(host.Written, w => w.Type == "call");
        Assert.Equal("a.exe", call.Args!.Value[0].GetProperty("app").GetString());
        Assert.True(host.AnswerTo(2)!.Ok);
    }

    [Fact]
    public async Task A_call_the_module_cannot_answer_shows_why_on_the_page()
    {
        var host = new ScriptedHost(m => m switch
        {
            { Type: "refresh" } => [new() { Type = "result", Status = DiagnosticStatus.Ok, Message = "done", PageData = HangPage }],
            { Type: "call" } => [new() { Type = "return", Id = m.Id, Ok = false, Error = "failed", Reason = "the logs are busy" }],
            _ => [],
        });
        using var proxy = new UserModeModuleProxy(Crashes(), host, hostQueries: Server()) { IdleExit = Timeout.InfiniteTimeSpan };
        await proxy.RefreshAsync(null);
        Assert.Equal("Couldn't look up the related events: the logs are busy", await proxy.Feature<IHangEvidenceSource>()!.FindHangEvidenceAsync([], CancellationToken.None));
    }

    [Fact]
    public async Task An_unsigned_module_gets_no_page_features_or_calls()
    {
        var host = new ScriptedHost(m => m switch
        {
            { Type: "refresh" } => [new() { Type = "result", Status = DiagnosticStatus.Ok, Message = "done", PageData = HangPage }],
            _ => [],
        });
        using var proxy = new UserModeModuleProxy(Crashes(bundled: false), host) { IdleExit = Timeout.InfiniteTimeSpan };
        await proxy.RefreshAsync(null);
        Assert.Null(proxy.Feature<IHangEvidenceSource>());
        await Assert.ThrowsAsync<ModuleCallException>(() => proxy.CallAsync(ModulePageCalls.HangEvidence, null));
        Assert.DoesNotContain(host.Written, w => w.Type == "call");
    }

    [Fact]
    public async Task Stop_asks_the_module_host_to_stop_the_run_in_progress()
    {
        var host = new ScriptedHost(m => m switch
        {
            { Type: "stop" } => [Result(cancelled: true)],
            _ => [],
        });
        using var proxy = new UserModeModuleProxy(Services(), host, hostQueries: Server()) { IdleExit = Timeout.InfiniteTimeSpan };
        proxy.Stop(); // nothing running: nothing sent
        Assert.DoesNotContain(host.Written, w => w.Type == "stop");
        var run = proxy.RefreshAsync(null);
        var until = DateTime.UtcNow.AddSeconds(10);
        while (!host.Written.Any(w => w.Type == "refresh") && DateTime.UtcNow < until) await Task.Delay(20);
        proxy.Stop();
        Assert.Same(run, await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(10))));
        Assert.True((await run).Cancelled);
    }

    [Fact]
    public async Task Stopping_a_run_answers_its_slow_query_right_away()
    {
        var host = new ScriptedHost(m => m switch
        {
            { Type: "refresh" } => [SlowQuery],
            { Type: "answer", Id: 1 } => [Result(cancelled: true)], // the module gives up once its query fails
            _ => [],
        });
        using var proxy = new UserModeModuleProxy(Services(), host, hostQueries: Server()) { IdleExit = Timeout.InfiniteTimeSpan };
        using var cts = new CancellationTokenSource();
        var run = proxy.RefreshAsync(null, cts.Token);
        await Task.Delay(300);
        Assert.False(run.IsCompleted);
        cts.Cancel();
        Assert.Same(run, await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(10))));
        Assert.True((await run).Cancelled);
        Assert.Equal("cancelled", host.AnswerTo(1)?.Error);
        Assert.Contains(host.Written, w => w.Type == "stop");
    }
}
