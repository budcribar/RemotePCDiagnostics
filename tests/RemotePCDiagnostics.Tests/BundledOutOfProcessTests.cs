using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Modules.BatteryPower;
using RemotePCDiagnostics.Modules.Programs;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Modules that ship with the app but run out of process (module.json "outOfProcess": Programs, Battery &amp; power, Device drivers): the
/// app holds a stand-in, the check runs in RemotePCDiagnostics.ModuleHost and the details UI in the module UI host, like an unsigned
/// module's, but they keep the app's descriptor and their one-click fixes.
/// </summary>
public sealed class BundledOutOfProcessTests : IDisposable
{
    public static readonly string[] OutOfProcessDlls =
        ["RemotePCDiagnostics.Modules.BatteryPower.dll", "RemotePCDiagnostics.Modules.DeviceDrivers.dll", "RemotePCDiagnostics.Modules.Programs.dll"];

    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-oop-" + Guid.NewGuid().ToString("N"));
    private string Bundled => Path.Combine(_root, ModuleLoaderOptions.BundledFolderName);

    public BundledOutOfProcessTests() => Directory.CreateDirectory(Bundled);
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    private static string Dll(string name) => Path.Combine(AppContext.BaseDirectory, name);

    private (PluginRegistrar Registrar, ServiceCollection Services, List<UserModeModule> Started) Load(IModuleHostLauncher? launcher = null)
    {
        foreach (var f in OutOfProcessDlls.Append("RemotePCDiagnostics.Modules.EventLog.dll")) File.Copy(Dll(f), Path.Combine(Bundled, f));
        var registrar = new PluginRegistrar(new SessionContext(SessionMode.Local), new Version(1, 2, 0));
        var made = new List<UserModeModule>();
        var loader = new ModuleLoader(new ModuleLoaderOptions
        {
            ModulesFolder = Path.Combine(_root, "modules"), CatalogFolder = Path.Combine(_root, "catalog"), BundledFolder = Bundled, HostVersion = new Version(1, 2, 0),
            AllowUnsigned = false, // the app's own modules don't need the unsigned-modules switch
        }, registrar, userMode: um => { made.Add(um); return new UserModeModuleProxy(um, launcher ?? new ProcessModuleHostLauncher(AppContext.BaseDirectory)); });
        var services = new ServiceCollection();
        services.AddSingleton(new RemotePCDiagnostics.Core.Osquery.OsqueryRunner(baseDirectory: _root));
        services.AddSingleton(new SystemCommandRunner());
        loader.LoadBundled(services);
        return (registrar, services, made);
    }

    [Theory]
    [MemberData(nameof(Dlls))]
    public void The_manifest_asks_for_out_of_process(string file)
    {
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Dll(file)));
        Assert.True(manifest.OutOfProcess);
        Assert.Equal(file != "RemotePCDiagnostics.Modules.DeviceDrivers.dll", manifest.HasUi);
    }

    public static IEnumerable<object[]> Dlls() => OutOfProcessDlls.Select(f => new object[] { f });

    [Fact]
    public void Out_of_process_modules_register_a_stand_in_and_keep_the_app_descriptor()
    {
        var (registrar, services, made) = Load();
        Assert.Equal(4, registrar.Records.Count);
        Assert.All(registrar.Records, r => Assert.Equal(PluginState.Loaded, r.State));
        Assert.Equal(3, registrar.Records.Count(r => r.UserMode));
        Assert.All(made, um => Assert.True(um.Bundled));

        using var sp = services.BuildServiceProvider();
        var modules = sp.GetServices<IDiagnosticModule>().ToDictionary(m => m.Id);
        foreach (var id in new[] { ModuleIds.Programs, ModuleIds.BatteryPower, ModuleIds.DeviceDrivers })
        {
            var proxy = Assert.IsType<UserModeModuleProxy>(modules[id]);
            var builtIn = BuiltInModules.Descriptors.Single(d => d.Id == id);
            Assert.Equal(builtIn.Slug, proxy.Name);
            Assert.Same(builtIn, proxy.Source.Descriptor);
            Assert.True(proxy.IncludeInRunAll);
        }
        // A module without the flag still loads in the app process.
        Assert.IsNotType<UserModeModuleProxy>(modules[ModuleIds.EventLog]);

        var catalog = new ModuleCatalog();
        foreach (var m in modules.Values) catalog.Add(m);
        registrar.ApplyTo(catalog);
        Assert.Equal(ModuleSource.BuiltIn, catalog.Get(ModuleIds.Programs)!.Source);
        // Its own UI isn't the app's to render: the module page frames it from the module UI host.
        Assert.Null(catalog.Get(ModuleIds.Programs)!.DetailsComponent);
    }

    [Fact]
    public async Task A_bundled_module_runs_in_the_real_module_host()
    {
        var (_, services, _) = Load();
        using var sp = services.BuildServiceProvider();
        var programs = (UserModeModuleProxy)sp.GetServices<IDiagnosticModule>().Single(m => m.Id == ModuleIds.Programs);
        try
        {
            // No osquery next to the test host's module host here, so the module itself (loaded in the host with the app's helpers) says so.
            var a = await programs.CheckAvailabilityAsync();
            Assert.False(a.IsAvailable);
            Assert.Equal(OsqueryAreaModuleBase.ToolMissingMessage, a.Reason);
            var r = await programs.RefreshAsync(null);
            Assert.False(r is { Status: DiagnosticStatus.Error } && r.Message.StartsWith("The module host", StringComparison.Ordinal), r.Message);
            Assert.IsType<AreaReport>(r.Payload);
        }
        finally { programs.Dispose(); }
    }

    [Fact]
    public async Task A_bundled_module_keeps_its_one_click_fixes_an_unsigned_one_loses_them()
    {
        var report = new AreaReport([new AreaCard("plan", "Windows power plan", AreaLevel.Warning, "Power saver", "", ["Detail", "Value"], [],
            Actions: [new(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced plan")])], "Power saver plan", DiagnosticStatus.Warning);
        var launcher = new ScriptedLauncher(new ModuleHostMessage { Type = "result", Status = DiagnosticStatus.Warning, Message = "Power saver plan", Report = report });
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Dll("RemotePCDiagnostics.Modules.BatteryPower.dll")));
        var descriptor = BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.BatteryPower);

        using var bundledProxy = new UserModeModuleProxy(new UserModeModule("x.dll", manifest, descriptor) { Bundled = true }, launcher);
        var bundled = await bundledProxy.RefreshAsync(null);
        Assert.NotNull(Assert.IsType<AreaReport>(bundled.Payload).Cards[0].Actions);
        using var unsignedProxy = new UserModeModuleProxy(new UserModeModule("x.dll", manifest, descriptor), launcher);
        var unsigned = await unsignedProxy.RefreshAsync(null);
        Assert.Null(Assert.IsType<AreaReport>(unsigned.Payload).Cards[0].Actions);
    }

    [Theory]
    [InlineData("RemotePCDiagnostics.Modules.Programs.dll", typeof(ProgramsDetails))]
    [InlineData("RemotePCDiagnostics.Modules.BatteryPower.dll", typeof(BatteryDetails))]
    public void The_user_mode_loader_gets_the_module_its_helpers_and_its_UI(string file, Type ui)
    {
        // What the module host and the module UI host do: no vendor slug needed, osquery from the app folder they are given.
        var loaded = UserModePlugin.Load(Dll(file), appDirectory: _root);
        Assert.Equal(file.Contains("Programs") ? ModuleIds.Programs : ModuleIds.BatteryPower, loaded.Module.Id);
        Assert.Equal(ui.FullName, loaded.DetailsComponent?.FullName);
    }

    [Fact]
    public void Without_the_app_folder_the_helpers_are_missing()
    {
        var ex = Assert.ThrowsAny<Exception>(() => UserModePlugin.Load(Dll("RemotePCDiagnostics.Modules.Programs.dll")));
        Assert.Contains("OsqueryRunner", ex.ToString());
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
