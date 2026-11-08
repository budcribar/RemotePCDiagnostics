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

    [Fact]
    public async Task A_query_the_app_never_answers_fails_instead_of_hanging()
    {
        var client = new HostQueriesClient(_ => { }) { AnswerTimeout = TimeSpan.FromMilliseconds(200) };
        var ex = await Assert.ThrowsAsync<HostQueryException>(() => client.ReadDrivesAsync());
        Assert.Equal("timedOut", ex.Error);
    }
}
