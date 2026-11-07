using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// The process-mode switch: every module that ships with the app runs in or out of process as the About page says, with no code or page
/// changes. Each bundled DLL is loaded both ways; the ones that can run out of process are also run in the real
/// RemotePCDiagnostics.ModuleHost; the module page layout is the same either way.
/// </summary>
public sealed class ProcessModeSwitchTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-mode-" + Guid.NewGuid().ToString("N"));
    private string Bundled => Path.Combine(_root, ModuleLoaderOptions.BundledFolderName);

    public ProcessModeSwitchTests() => Directory.CreateDirectory(Bundled);
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    public static IEnumerable<object[]> ModuleDlls() => BundledModulesTests.ModuleDlls();

    private static string Dll(string name) => Path.Combine(AppContext.BaseDirectory, name);
    private static ModuleManifest ManifestOf(string file) => ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Dll(file))).Manifest;

    /// <summary>The modules that can run out of process (no <see cref="ModuleManifest.InProcessOnly"/>).</summary>
    public static IEnumerable<object[]> SwitchableDlls() => ModuleDlls().Where(f => ManifestOf((string)f[0]).InProcessOnly is null);

    private (PluginRegistrar Registrar, IReadOnlyDictionary<Guid, IDiagnosticModule> Modules, ModuleCatalog Catalog, List<UserModeModule> Made)
        Load(string file, ModuleProcessModeSetting modes)
    {
        File.Copy(Dll(file), Path.Combine(Bundled, file), overwrite: true);
        var registrar = new PluginRegistrar(new SessionContext(SessionMode.Local), new Version(1, 2, 0));
        var made = new List<UserModeModule>();
        var loader = new ModuleLoader(new ModuleLoaderOptions
        {
            ModulesFolder = Path.Combine(_root, "modules"), CatalogFolder = Path.Combine(_root, "catalog"), BundledFolder = Bundled,
            HostVersion = new Version(1, 2, 0), ProcessModes = modes,
        }, registrar, userMode: um => { made.Add(um); return new UserModeModuleProxy(um, new ProcessModuleHostLauncher(AppContext.BaseDirectory)); });
        var services = new ServiceCollection();
        AddAppServices(services, _root);
        loader.LoadBundled(services);
        var sp = services.BuildServiceProvider();
        var modules = sp.GetServices<IDiagnosticModule>().ToDictionary(m => m.Id);
        var catalog = new ModuleCatalog();
        foreach (var m in modules.Values) catalog.Add(m);
        registrar.ApplyTo(catalog);
        return (registrar, modules, catalog, made);
    }

    /// <summary>What the app's container gives modules (the Windows adapters as do-nothing stubs: only constructors run).</summary>
    private static void AddAppServices(IServiceCollection services, string root)
    {
        services.AddSingleton(new RemotePCDiagnostics.Core.Osquery.OsqueryRunner(baseDirectory: root));
        services.AddSingleton(new SystemCommandRunner());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Sensors.ISensorProvider>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Sensors.IEcFanSource>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Stress.IGpuDeviceFactory>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Audio.IAudioIo>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Webcam.IWebcamIo>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Npu.INpuIo>());
        services.AddSingleton(Stub<IRetrimHistory>());
    }

    private static T Stub<T>() where T : class => System.Reflection.DispatchProxy.Create<T, BundledModulesTests.NullProxy>();

    private static ModuleProcessModeSetting All(ModuleProcessMode mode) => new() { All = mode };

    [Theory]
    [MemberData(nameof(ModuleDlls))]
    public void In_process_every_module_loads_in_the_app(string file)
    {
        var manifest = ManifestOf(file);
        var (registrar, modules, catalog, made) = Load(file, All(ModuleProcessMode.InProcess));
        Assert.Empty(made);
        var m = modules[manifest.Id];
        Assert.IsNotType<UserModeModuleProxy>(m);
        var hosting = catalog.Hosting(manifest.Id)!;
        Assert.False(hosting.OutOfProcess);
        Assert.Equal(ModuleProcessMode.InProcess, hosting.Requested);
        Assert.False(Assert.Single(registrar.Records).UserMode);
        // Its own UI (if any) is the app's to render here.
        Assert.Equal(manifest.HasUi, catalog.Get(manifest.Id)!.DetailsComponent is not null);
    }

    [Theory]
    [MemberData(nameof(ModuleDlls))]
    public void Out_of_process_every_module_that_can_runs_in_the_module_host(string file)
    {
        var manifest = ManifestOf(file);
        var (registrar, modules, catalog, made) = Load(file, All(ModuleProcessMode.OutOfProcess));
        var hosting = catalog.Hosting(manifest.Id)!;
        var record = Assert.Single(registrar.Records);
        Assert.Equal(PluginState.Loaded, record.State);
        if (manifest.InProcessOnly is { } why)
        {
            // It stays in the app and says why (shown next to the switch).
            Assert.Empty(made);
            Assert.IsNotType<UserModeModuleProxy>(modules[manifest.Id]);
            Assert.False(hosting.OutOfProcess);
            Assert.Equal(why, hosting.InProcessOnly);
            return;
        }
        var um = Assert.Single(made);
        Assert.True(um.Bundled);
        Assert.Equal(manifest.NeedsAdmin, um.Elevated); // an admin module gets the app's own token, the others a restricted one
        var proxy = Assert.IsType<UserModeModuleProxy>(modules[manifest.Id]);
        Assert.Same(BuiltInModules.Descriptors.Single(d => d.Id == manifest.Id), proxy.Source.Descriptor);
        Assert.True(hosting.OutOfProcess);
        Assert.Equal(manifest.NeedsAdmin, hosting.Elevated);
        Assert.True(record.UserMode);
        // Its code never loaded into the app: no details component in the app's catalog.
        Assert.Null(catalog.Get(manifest.Id)!.DetailsComponent);
    }

    [Theory]
    [MemberData(nameof(ModuleDlls))]
    public void The_module_page_looks_the_same_either_way(string file)
    {
        var manifest = ManifestOf(file);
        var inProc = Load(file, All(ModuleProcessMode.InProcess)).Catalog.Hosting(manifest.Id);
        Directory.Delete(Bundled, true); Directory.CreateDirectory(Bundled);
        var outProc = Load(file, All(ModuleProcessMode.OutOfProcess)).Catalog.Hosting(manifest.Id)!;

        var inLayout = ModulePageLayout.For(inProc, outOfProcess: false, bundled: true, hasDetails: manifest.HasUi, frameHost: true);
        var outLayout = ModulePageLayout.For(outProc, outOfProcess: outProc.OutOfProcess, bundled: true, hasDetails: manifest.HasUi, frameHost: true);
        if (!outProc.OutOfProcess || manifest.PortableUi || !manifest.HasUi)
        {
            // Same parts in the same order; only where the module's own UI renders differs.
            Assert.Equal(inLayout.ShowReport, outLayout.ShowReport);
            Assert.Equal(inLayout.OwnUi != ModuleOwnUi.None, outLayout.OwnUi != ModuleOwnUi.None);
            Assert.Null(outLayout.Notice);
        }
        else
        {
            // A UI that needs the app process: out of process the page says so and shows the report, never an empty page.
            Assert.Equal(ModulePageLayout.NeedsAppProcess, outLayout.Notice);
            Assert.True(outLayout.ShowReport);
        }
    }

    [Theory]
    [MemberData(nameof(SwitchableDlls))]
    public async Task Switched_out_of_process_the_module_answers_from_the_real_module_host(string file)
    {
        var manifest = ManifestOf(file);
        var (_, modules, _, _) = Load(file, All(ModuleProcessMode.OutOfProcess));
        var proxy = Assert.IsType<UserModeModuleProxy>(modules[manifest.Id]);
        try
        {
            // On this machine most modules say they can't run (no osquery, not Windows); that answer still comes from the module, loaded in
            // the module host with the app's helpers, so the whole path works.
            var a = await proxy.CheckAvailabilityAsync();
            Assert.False(a.Reason is { } r && (r.StartsWith("The module host", StringComparison.Ordinal) || r.StartsWith("Couldn't load the module", StringComparison.Ordinal)), a.Reason);
            if (!a.IsAvailable) return;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var result = await proxy.RefreshAsync(null, cts.Token);
            Assert.False(result.Message.StartsWith("The module host", StringComparison.Ordinal), result.Message);
        }
        finally { proxy.Dispose(); }
    }

    [Theory]
    [MemberData(nameof(ModuleDlls))]
    public void The_in_process_only_flag_is_accurate(string file)
    {
        // The module host's loader (the app's helpers only): a module that loads there can run out of process, and one that can't must say why.
        var manifest = ManifestOf(file);
        Exception? failed = null;
        try { UserModePlugin.Load(Dll(file), appDirectory: _root); }
        catch (Exception ex) { failed = ex; }
        if (manifest.InProcessOnly is null) Assert.True(failed is null, $"{file} can't load in the module host: {failed}");
        else Assert.True(failed is not null, $"{file} loads in the module host: drop its inProcessOnly");
    }

    /// <summary>The rule for a module UI that renders out of process (portableUi): nothing but Components, Abstractions and Core, and the
    /// app's last result as its only input, so it renders the same in the app and in the module UI host.</summary>
    [Theory]
    [MemberData(nameof(ModuleDlls))]
    public void A_portable_ui_uses_only_what_the_module_ui_host_has(string file)
    {
        var manifest = ManifestOf(file);
        if (!manifest.HasUi) { Assert.False(manifest.PortableUi); return; }
        var references = AssemblyReferences(Dll(file));
        var appOnly = references.Where(r => r is "RemotePCDiagnostics.UI" or "RemotePCDiagnostics.Host" || r.StartsWith("PeakSWC.", StringComparison.Ordinal)).ToList();
        if (manifest.PortableUi)
        {
            Assert.True(appOnly.Count == 0, $"{file} says portableUi but references {string.Join(", ", appOnly)}");
            var loaded = UserModePlugin.Load(Dll(file), appDirectory: _root);
            Assert.NotNull(loaded.DetailsComponent);
            // Its inputs: the DiagnosticModule parameter and the ModuleDetails.LastResult cascading value. No injected app services.
            Assert.DoesNotContain(loaded.DetailsComponent!.GetProperties(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic),
                p => p.GetCustomAttributes(typeof(Microsoft.AspNetCore.Components.InjectAttribute), true).Length > 0);
        }
        else Assert.True(manifest.DetailsReplaceReport || appOnly.Count == 0, $"{file}: a UI that needs the app should say whether it replaces the report");
    }

    private static List<string> AssemblyReferences(string path)
    {
        using var pe = new PEReader(File.OpenRead(path));
        var md = pe.GetMetadataReader();
        return md.AssemblyReferences.Select(h => md.GetString(md.GetAssemblyReference(h).Name)).ToList();
    }

    [Fact]
    public void A_per_module_entry_wins_over_all()
    {
        var file = "RemotePCDiagnostics.Modules.Programs.dll";
        var (_, modules, _, _) = Load(file, new ModuleProcessModeSetting { All = ModuleProcessMode.OutOfProcess }.With("programs", ModuleProcessMode.InProcess));
        Assert.IsNotType<UserModeModuleProxy>(modules[ModuleIds.Programs]);
        var (_, back, _, _) = Load(file, new ModuleProcessModeSetting().With("Programs", ModuleProcessMode.Default));
        Assert.IsType<UserModeModuleProxy>(back[ModuleIds.Programs]); // Default: its module.json says out of process
        ((IDisposable)back[ModuleIds.Programs]).Dispose();
    }

    [Fact]
    public void The_setting_round_trips_and_default_removes_the_file()
    {
        var folder = Path.Combine(_root, "modules");
        Assert.Equal(ModuleProcessMode.Default, ModuleProcessModeSetting.Read(folder).For("Crashes"));
        new ModuleProcessModeSetting { All = ModuleProcessMode.InProcess }.With("Crashes", ModuleProcessMode.OutOfProcess).Save(folder);
        var read = ModuleProcessModeSetting.Read(folder);
        Assert.Equal(ModuleProcessMode.OutOfProcess, read.For("crashes"));
        Assert.Equal(ModuleProcessMode.InProcess, read.For("Programs"));
        (read with { All = ModuleProcessMode.Default }).With("Crashes", ModuleProcessMode.Default).Save(folder);
        Assert.False(File.Exists(ModuleProcessModeSetting.PathIn(folder)));
        File.WriteAllText(ModuleProcessModeSetting.PathIn(folder), "not json");
        Assert.Equal(ModuleProcessMode.Default, ModuleProcessModeSetting.Read(folder).All); // unreadable: as each module.json says
    }

    [Fact]
    public void Admin_modules_ship_in_process()
    {
        foreach (var id in BundledModulesTests.AdminModules)
        {
            var file = ModuleDlls().Select(f => (string)f[0]).Single(f => ManifestOf(f).Id == id);
            Directory.Delete(Bundled, true); Directory.CreateDirectory(Bundled);
            var (_, modules, catalog, _) = Load(file, new ModuleProcessModeSetting());
            Assert.IsNotType<UserModeModuleProxy>(modules[id]);
            Assert.False(catalog.Hosting(id)!.OutOfProcess);
        }
    }

    [Theory]
    [InlineData(false, false, ModuleOwnUi.InApp, true)]   // its UI above the report, in the app
    [InlineData(false, true, ModuleOwnUi.InApp, false)]   // its UI instead of the report
    [InlineData(true, false, ModuleOwnUi.Frame, true)]    // the same, framed from the module UI host
    [InlineData(true, true, ModuleOwnUi.Frame, false)]
    public void Layout_follows_the_manifest_not_the_process(bool outOfProcess, bool replaces, ModuleOwnUi ui, bool report)
    {
        var hosting = new ModuleHosting { OutOfProcess = outOfProcess, HasUi = true, PortableUi = true, DetailsReplaceReport = replaces };
        Assert.Equal(new ModulePageLayout(ui, report), ModulePageLayout.For(hosting, outOfProcess, bundled: true, hasDetails: true, frameHost: true));
    }

    [Fact]
    public void Without_a_frame_host_the_page_says_so_and_shows_the_report()
    {
        var hosting = new ModuleHosting { OutOfProcess = true, HasUi = true, PortableUi = true, DetailsReplaceReport = true };
        Assert.Equal(new ModulePageLayout(ModuleOwnUi.None, true, ModulePageLayout.NoFrameHost),
            ModulePageLayout.For(hosting, outOfProcess: true, bundled: true, hasDetails: true, frameHost: false));
        // A module compiled into the app keeps its page as the whole view.
        Assert.Equal(new ModulePageLayout(ModuleOwnUi.InApp, false), ModulePageLayout.For(null, false, true, true, true));
    }
}
