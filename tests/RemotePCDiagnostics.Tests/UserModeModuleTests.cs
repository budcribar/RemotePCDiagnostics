using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

/// <summary>Runs the unsigned sample module in the real RemotePCDiagnostics.ModuleHost process through the in-app proxy.</summary>
public sealed class UserModeModuleTests : IDisposable
{
    private static readonly Guid SampleId = new("e38471d6-d5da-4ef8-9063-155f4bd2ec1a");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-usermode-" + Guid.NewGuid().ToString("N"));
    private string Modules => Path.Combine(_root, "modules");

    public UserModeModuleTests()
    {
        Directory.CreateDirectory(Modules);
        File.Copy(Path.Combine(AppContext.BaseDirectory, "sample-module", "SampleModule.dll"), Path.Combine(Modules, "SampleModule.dll"));
    }

    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    private (ModuleLoader Loader, PluginRegistrar Registrar, ServiceCollection Services) Load(bool allowUnsigned)
    {
        var registrar = new PluginRegistrar(new SessionContext(SessionMode.Local), new Version(1, 2, 0));
        var launcher = new ProcessModuleHostLauncher(AppContext.BaseDirectory);
        var loader = new ModuleLoader(new ModuleLoaderOptions
        {
            ModulesFolder = Modules, CatalogFolder = Path.Combine(_root, "catalog"), PublicKeyPem = "", HostVersion = new Version(1, 2, 0), AllowUnsigned = allowUnsigned,
        }, registrar, userMode: um => new UserModeModuleProxy(um, launcher));
        var services = new ServiceCollection();
        loader.LoadAll(services);
        return (loader, registrar, services);
    }

    [Fact]
    public async Task An_unsigned_module_runs_in_the_module_host_and_reports_back()
    {
        var (_, registrar, services) = Load(allowUnsigned: true);
        var record = Assert.Single(registrar.Records);
        Assert.Equal(PluginState.Loaded, record.State);
        Assert.True(record.UserMode);

        using var sp = services.BuildServiceProvider();
        var module = Assert.Single(sp.GetServices<IDiagnosticModule>());
        var proxy = Assert.IsType<UserModeModuleProxy>(module);
        Assert.Equal(SampleId, module.Id);
        Assert.Equal("sample.uptime", module.Name);
        Assert.Equal("Uptime (sample plugin)", module.DisplayName);

        var diag = new DiagnosticsService(new ResultStore(), [module]);
        registrar.ApplyTo(diag.Catalog);
        var r = await diag.RunAsync("sample.uptime");
        Assert.NotEqual(DiagnosticStatus.Error, r.Status);
        Assert.StartsWith("Up ", r.Message);
        var report = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal("Uptime", Assert.Single(report.Cards).Title);
        Assert.Equal(ModuleSource.Plugin, diag.Catalog.Get(SampleId)!.Source);

        // A second run reuses the running host.
        Assert.StartsWith("Up ", (await diag.RunAsync("sample.uptime")).Message);
        proxy.Dispose();
    }

    [Fact]
    public void Without_the_toggle_an_unsigned_module_is_listed_but_not_registered()
    {
        var (loader, registrar, services) = Load(allowUnsigned: false);
        Assert.Equal(PluginState.Disabled, Assert.Single(registrar.Records).State);
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IDiagnosticModule));
        Assert.Empty(loader.UserMode);
    }

    [Fact]
    public async Task A_missing_module_host_is_a_couldnt_run_result_not_a_crash()
    {
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Path.Combine(Modules, "SampleModule.dll")));
        var proxy = new UserModeModuleProxy(new UserModeModule(Path.Combine(Modules, "SampleModule.dll"), manifest, manifest.ToDescriptor(manifest.Slug)),
            new ProcessModuleHostLauncher(Path.Combine(_root, "nowhere")));
        Assert.False((await proxy.CheckAvailabilityAsync()).IsAvailable);
        var r = await proxy.RefreshAsync(null);
        Assert.IsType<CouldNotRun>(r.Payload);
    }

    [Fact]
    public void One_click_actions_are_removed_from_an_unsigned_report()
    {
        var action = new AreaAction(RemediationKind.CleanTempFiles, "Clean");
        var report = new AreaReport([new AreaCard("c", "C", AreaLevel.Warning, "h", "m", ["A"], [new AreaRow(AreaLevel.Warning, ["x"], Actions: [action])], Actions: [action])],
            "s", DiagnosticStatus.Warning);
        var clean = UserModeModuleProxy.WithoutActions(report);
        Assert.Null(clean.Cards[0].Actions);
        Assert.Null(clean.Cards[0].Rows[0].Actions);
    }

    [Fact]
    public void The_unsigned_modules_switch_is_a_file_in_the_modules_folder()
    {
        Assert.False(UnsignedModulesSetting.IsOn(Modules));
        UnsignedModulesSetting.Set(true, Modules);
        Assert.True(UnsignedModulesSetting.IsOn(Modules));
        UnsignedModulesSetting.Set(false, Modules);
        Assert.False(UnsignedModulesSetting.IsOn(Modules));
    }

    [Fact]
    public void Protocol_messages_round_trip()
    {
        var m = new ModuleHostMessage { Type = "result", Status = DiagnosticStatus.Warning, Message = "m", Report = new AreaReport([], "s", DiagnosticStatus.Warning) };
        var back = ModuleHostMessage.Parse(m.ToLine())!;
        Assert.Equal("result", back.Type);
        Assert.Equal(DiagnosticStatus.Warning, back.Status);
        Assert.Equal("s", back.Report!.Summary);
        Assert.Null(ModuleHostMessage.Parse("not json"));
    }
}
