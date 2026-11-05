using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class PluginContractTests
{
    [Fact]
    public void The_contract_assembly_references_nothing_of_the_app()
    {
        var asm = typeof(IDiagnosticModule).Assembly;
        Assert.Equal("RemotePCDiagnostics.Abstractions", asm.GetName().Name);
        var refs = asm.GetReferencedAssemblies().Select(a => a.Name!).ToList();
        Assert.DoesNotContain(refs, r => r.StartsWith("RemotePCDiagnostics", StringComparison.Ordinal));
        Assert.All(refs, r => Assert.True(r.StartsWith("System", StringComparison.Ordinal) || r == "netstandard"
            || r.StartsWith("Microsoft.Extensions.DependencyInjection.Abstractions", StringComparison.Ordinal), $"unexpected reference {r}"));
        // The types a plugin needs live there, not in Core.
        foreach (var t in new[] { typeof(IModulePlugin), typeof(IPluginContext), typeof(ModuleDescriptor), typeof(DiagnosticResult), typeof(IStressSuiteModule),
                     typeof(IHardwareGatedModule), typeof(Core.Areas.AreaReport), typeof(Core.Areas.AreaModuleBase), typeof(ISessionContext) })
            Assert.Same(asm, t.Assembly);
    }

    [Theory]
    [InlineData("1.0.0", "1.0.0", true)]
    [InlineData("1.0.0", "1.3.0", true)]
    [InlineData("1.4.0", "1.3.0", false)]
    [InlineData("2.0.0", "1.3.0", false)]
    [InlineData("0.9.0", "1.3.0", false)]
    public void Contract_compatibility(string builtFor, string host, bool ok) =>
        Assert.Equal(ok, ContractVersion.IsCompatible(Version.Parse(builtFor), Version.Parse(host)));

    private static PluginRegistrar Registrar(List<string>? log = null) =>
        new(new SessionContext(SessionMode.Local), new Version(1, 2, 0), new LineLogger(l => log?.Add(l)));

    [Fact]
    public void A_plugin_that_throws_leaves_nothing_registered_and_is_disabled()
    {
        var services = new ServiceCollection();
        var reg = Registrar();
        Assert.False(reg.Register(services, new Plugin(s => { s.AddSingleton<IDiagnosticModule>(new Mod("contoso.a", Guid.NewGuid())); throw new InvalidOperationException("boom"); }), "contoso.a"));
        Assert.Empty(services);
        var rec = Assert.Single(reg.Records);
        Assert.Equal(PluginState.Disabled, rec.State);
        Assert.Contains("boom", rec.Reason);
    }

    [Fact]
    public void A_plugin_module_is_tracked_into_the_catalog_with_its_details_UI()
    {
        var id = Guid.NewGuid();
        var services = new ServiceCollection();
        var reg = Registrar();
        Assert.True(reg.Register(services, new Plugin((s, ctx) =>
        {
            s.AddSingleton<IDiagnosticModule>(new Mod("contoso.battery-wear", id));
            ctx.SetDetailsComponent(id, typeof(string));
            Assert.Equal("contoso", ctx.PluginId);
            Assert.Equal(ContractVersion.Current, ctx.ContractVersion);
        }), "contoso", expectedModuleId: id));
        using var sp = services.BuildServiceProvider();
        var diag = new DiagnosticsService(new ResultStore(), sp.GetServices<IDiagnosticModule>());
        reg.ApplyTo(diag.Catalog);
        var d = diag.Catalog.Get(id)!;
        Assert.Equal(ModuleSource.Plugin, d.Source);
        Assert.Equal("contoso", d.PluginId);
        Assert.Equal(typeof(string), d.DetailsComponent);
        Assert.Equal(ModuleState.Available, diag.Catalog.StateOf(id));
    }

    [Fact]
    public void A_module_whose_id_does_not_match_the_manifest_fails_to_resolve()
    {
        var services = new ServiceCollection();
        var reg = Registrar();
        reg.Register(services, new Plugin(s => s.AddSingleton<IDiagnosticModule, WrongId>()), "contoso", expectedModuleId: Guid.NewGuid());
        using var sp = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(() => { _ = sp.GetServices<IDiagnosticModule>().ToList(); });
    }

    [Fact]
    public void A_plugin_may_register_only_one_module()
    {
        var services = new ServiceCollection();
        var reg = Registrar();
        Assert.False(reg.Register(services, new Plugin(s =>
        {
            s.AddSingleton<IDiagnosticModule>(new Mod("a.one", Guid.NewGuid()));
            s.AddSingleton<IDiagnosticModule>(new Mod("a.two", Guid.NewGuid()));
        }), "a", expectedModuleId: Guid.NewGuid()));
        Assert.Empty(services);
    }

    [Fact]
    public void A_disabled_plugin_stays_in_the_catalog_for_History()
    {
        var reg = Registrar();
        var id = Guid.NewGuid();
        reg.RecordDisabled(new PluginRecord("contoso", ModuleSource.Plugin, PluginState.Disabled, "signature mismatch"),
            new ModuleDescriptor(id, "contoso.battery-wear", "Battery wear", ModuleKind.Check) { Source = ModuleSource.Plugin, PluginId = "contoso" });
        var catalog = new ModuleCatalog();
        reg.ApplyTo(catalog);
        Assert.Equal(ModuleState.Disabled, catalog.StateOf(id));
        Assert.Equal("Battery wear", catalog.DisplayName(id));
    }

    private sealed class Plugin(Action<IServiceCollection, IPluginContext> register) : IModulePlugin
    {
        public Plugin(Action<IServiceCollection> register) : this((s, _) => register(s)) { }
        public void Register(IServiceCollection services, IPluginContext context) => register(services, context);
    }

    private class Mod(string name, Guid id) : IDiagnosticModule
    {
        public Guid Id => id;
        public string Name => name;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) => Task.FromResult(FakeModule.Ok(name));
    }

    private sealed class WrongId() : Mod("contoso.wrong", Guid.NewGuid());
}
