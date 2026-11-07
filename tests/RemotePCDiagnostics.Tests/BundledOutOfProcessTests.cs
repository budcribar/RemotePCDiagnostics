using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Modules.BatteryPower;
using RemotePCDiagnostics.Modules.Programs;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Test branch for measuring the cost of out-of-process modules: Programs, Battery &amp; power and Device drivers are flipped back in
/// process (no module.json "outOfProcess"), so they load into the app and their own UI renders on the module page. The bundled
/// out-of-process path itself is still covered with a hand-built manifest.
/// </summary>
public sealed class BundledOutOfProcessTests : IDisposable
{
    public static readonly string[] FormerlyOutOfProcessDlls =
        ["RemotePCDiagnostics.Modules.BatteryPower.dll", "RemotePCDiagnostics.Modules.DeviceDrivers.dll", "RemotePCDiagnostics.Modules.Programs.dll"];

    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-oop-" + Guid.NewGuid().ToString("N"));
    private string Bundled => Path.Combine(_root, ModuleLoaderOptions.BundledFolderName);

    public BundledOutOfProcessTests() => Directory.CreateDirectory(Bundled);
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    private static string Dll(string name) => Path.Combine(AppContext.BaseDirectory, name);

    private (PluginRegistrar Registrar, ServiceCollection Services, List<UserModeModule> Started) Load()
    {
        foreach (var f in FormerlyOutOfProcessDlls.Append("RemotePCDiagnostics.Modules.EventLog.dll")) File.Copy(Dll(f), Path.Combine(Bundled, f));
        var registrar = new PluginRegistrar(new SessionContext(SessionMode.Local), new Version(1, 2, 0));
        var made = new List<UserModeModule>();
        var loader = new ModuleLoader(new ModuleLoaderOptions
        {
            ModulesFolder = Path.Combine(_root, "modules"), CatalogFolder = Path.Combine(_root, "catalog"), BundledFolder = Bundled, HostVersion = new Version(1, 2, 0),
            AllowUnsigned = false,
        }, registrar, userMode: um => { made.Add(um); return new UserModeModuleProxy(um, new ProcessModuleHostLauncher(AppContext.BaseDirectory)); });
        var services = new ServiceCollection();
        services.AddSingleton(new RemotePCDiagnostics.Core.Osquery.OsqueryRunner(baseDirectory: _root));
        services.AddSingleton(new SystemCommandRunner());
        loader.LoadBundled(services);
        return (registrar, services, made);
    }

    [Theory]
    [MemberData(nameof(Dlls))]
    public void The_manifest_no_longer_asks_for_out_of_process(string file)
    {
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Dll(file)));
        Assert.False(manifest.OutOfProcess);
        Assert.Equal(file != "RemotePCDiagnostics.Modules.DeviceDrivers.dll", manifest.HasUi);
    }

    public static IEnumerable<object[]> Dlls() => FormerlyOutOfProcessDlls.Select(f => new object[] { f });

    [Fact]
    public void Without_the_flag_the_modules_load_in_process_with_their_own_UI()
    {
        var (registrar, services, made) = Load();
        Assert.Equal(4, registrar.Records.Count);
        Assert.All(registrar.Records, r => Assert.Equal(PluginState.Loaded, r.State));
        Assert.Empty(made);

        using var sp = services.BuildServiceProvider();
        var modules = sp.GetServices<IDiagnosticModule>().ToDictionary(m => m.Id);
        foreach (var id in new[] { ModuleIds.Programs, ModuleIds.BatteryPower, ModuleIds.DeviceDrivers, ModuleIds.EventLog })
            Assert.IsNotType<UserModeModuleProxy>(modules[id]);

        var catalog = new ModuleCatalog();
        foreach (var m in modules.Values) catalog.Add(m);
        registrar.ApplyTo(catalog);
        Assert.Equal(ModuleSource.BuiltIn, catalog.Get(ModuleIds.Programs)!.Source);
        // In process the app renders the module's own UI on its page.
        Assert.Equal(typeof(ProgramsDetails).FullName, catalog.Get(ModuleIds.Programs)!.DetailsComponent?.FullName);
        Assert.Equal(typeof(BatteryDetails).FullName, catalog.Get(ModuleIds.BatteryPower)!.DetailsComponent?.FullName);
    }

    [Fact]
    public async Task A_bundled_module_keeps_its_one_click_fixes_an_unsigned_one_loses_them()
    {
        var report = new AreaReport([new AreaCard("plan", "Windows power plan", AreaLevel.Warning, "Power saver", "", ["Detail", "Value"], [],
            Actions: [new(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced plan")])], "Power saver plan", DiagnosticStatus.Warning);
        var launcher = new ScriptedLauncher(new ModuleHostMessage { Type = "result", Status = DiagnosticStatus.Warning, Message = "Power saver plan", Report = report });
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Dll("RemotePCDiagnostics.Modules.BatteryPower.dll")));
        var descriptor = BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.BatteryPower);

        var bundled = await new UserModeModuleProxy(new UserModeModule("x.dll", manifest, descriptor) { Bundled = true }, launcher).RefreshAsync(null);
        Assert.NotNull(Assert.IsType<AreaReport>(bundled.Payload).Cards[0].Actions);
        var unsigned = await new UserModeModuleProxy(new UserModeModule("x.dll", manifest, descriptor), launcher).RefreshAsync(null);
        Assert.Null(Assert.IsType<AreaReport>(unsigned.Payload).Cards[0].Actions);
    }

    [Fact]
    public void Programs_search_matches_any_column_newest_first()
    {
        var report = ProgramsModule.Build(null, true,
            [new InstalledUpdate("KB5030219", "Security Update", new DateOnly(2026, 10, 1))],
            [new InstalledProgram("7-Zip", "23.01", "Igor Pavlov", new DateOnly(2024, 1, 2)), new InstalledProgram("Zoom", "6.0", "Zoom Video", new DateOnly(2026, 10, 20))],
            new DateOnly(2026, 11, 1));
        Assert.Equal(["Zoom", "KB5030219", "7-Zip"], ProgramsDetails.Find(report, "", null).Select(m => m.Name));
        Assert.Equal(["7-Zip"], ProgramsDetails.Find(report, "pavlov", null).Select(m => m.Name));
        var kb = Assert.Single(ProgramsDetails.Find(report, "kb503", null));
        Assert.True(kb.IsUpdate);
        Assert.Equal(["Zoom", "KB5030219"], ProgramsDetails.Find(report, null, new DateOnly(2026, 9, 1)).Select(m => m.Name));
    }

    [Fact]
    public void Battery_gauges_read_the_battery_card()
    {
        var worn = BatteryPowerModule.Build([new BatteryStatus("L20M3PF0", "SMP", "LiP", "Discharging", 64, 45000, 27000, 410)], "Balanced");
        Assert.Equal(new BatteryDetails.Battery(60, 64, "Discharging"), BatteryDetails.Read(worn));
        Assert.Null(BatteryDetails.Read(BatteryPowerModule.Build([], "Balanced")));
        Assert.Equal(87, BatteryDetails.LeadingPercent("87% of original capacity (13% wear)"));
        Assert.Null(BatteryDetails.LeadingPercent("Not reported"));
    }

    /// <summary>A module host that answers every request with the same lines.</summary>
    private sealed class ScriptedLauncher(params ModuleHostMessage[] answers) : IModuleHostLauncher
    {
        public IModuleHostConnection Start(UserModeModule module) => new Connection(answers);

        private sealed class Connection(ModuleHostMessage[] answers) : IModuleHostConnection
        {
            private readonly Queue<string> _lines = new();
            public Task WriteLineAsync(string line, CancellationToken ct)
            {
                if (ModuleHostMessage.Parse(line)?.Type == "refresh") foreach (var a in answers) _lines.Enqueue(a.ToLine());
                return Task.CompletedTask;
            }
            public Task<string?> ReadLineAsync(CancellationToken ct) => Task.FromResult(_lines.TryDequeue(out var l) ? l : null);
            public bool HasExited => false;
            public void Kill() { }
            public void Dispose() { }
        }
    }
}
