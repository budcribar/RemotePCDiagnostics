using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.History;

namespace RemotePCDiagnostics.Tests;

public class ModuleCatalogTests
{
    [Fact]
    public void Every_built_in_id_has_a_descriptor_and_the_slugs_match()
    {
        Assert.Equal(ModuleIds.BuiltIn.Count, BuiltInModules.Descriptors.Count);
        foreach (var d in BuiltInModules.Descriptors)
        {
            Assert.Equal(ModuleIds.BuiltIn[d.Id], d.Slug);
            Assert.False(string.IsNullOrWhiteSpace(d.DisplayName));
            Assert.Equal(ModuleSource.BuiltIn, d.Source);
        }
        Assert.Equal(BuiltInModules.Descriptors.Count, BuiltInModules.Descriptors.Select(d => d.Slug.ToLowerInvariant()).Distinct().Count());
    }

    [Fact]
    public void Built_in_order_within_a_group_is_unique()
    {
        foreach (var g in BuiltInModules.Descriptors.GroupBy(d => d.Group))
            Assert.Equal(g.Count(), g.Select(d => d.Order).Distinct().Count());
    }

    [Fact]
    public void Unregistered_built_ins_are_retired_and_registered_ones_available()
    {
        var svc = new DiagnosticsService(new ResultStore());
        svc.Register(new FakeModule(ModuleSlugs.DriveHealth, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.DriveHealth))));
        Assert.Equal(ModuleState.Available, svc.Catalog.StateOf(ModuleIds.DriveHealth));
        Assert.Equal(ModuleState.Retired, svc.Catalog.StateOf(ModuleIds.Webcam));
        Assert.Equal(ModuleState.Retired, svc.Catalog.StateOf(Guid.NewGuid()));
        Assert.Equal("Webcam test", svc.Catalog.DisplayName(ModuleSlugs.Webcam));
        Assert.Contains(svc.Catalog.Available, d => d.Id == ModuleIds.DriveHealth);
        Assert.DoesNotContain(svc.Catalog.Available, d => d.Id == ModuleIds.Webcam);
    }

    [Fact]
    public async Task A_gated_module_without_its_hardware_stays_in_the_catalog_as_not_present()
    {
        var gated = new GatedModule(present: false);
        var svc = new DiagnosticsService(new ResultStore(), [gated]);
        await gated.Detected.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(50);
        Assert.DoesNotContain(svc.Modules, m => m.Id == gated.Id);
        Assert.Equal(ModuleState.NotPresent, svc.Catalog.StateOf(gated.Id));
        Assert.Equal("NPU (AI accelerator) test", svc.Catalog.DisplayName(gated.Id));
        Assert.Same(gated, svc.Catalog.ModuleFor(gated.Id));
    }

    [Fact]
    public async Task A_gated_module_with_its_hardware_is_available()
    {
        var gated = new GatedModule(present: true);
        var svc = new DiagnosticsService(new ResultStore(), [gated]);
        await gated.Detected.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(ModuleState.Available, svc.Catalog.StateOf(gated.Id));
    }

    [Fact]
    public void A_registered_module_keeps_the_built_in_group_and_order_and_takes_its_live_name()
    {
        var c = new ModuleCatalog();
        var d = c.Add(new FakeModule(ModuleSlugs.Crashes, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.Crashes))));
        Assert.Equal(ModuleGroups.Windows, d.Group);
        Assert.Equal(300, d.Order);
        Assert.Equal(ModuleSlugs.Crashes, d.DisplayName); // FakeModule's DisplayName defaults to its Name
        Assert.Equal(ModuleKind.Check, d.Kind);
    }

    [Fact]
    public void A_new_module_whose_slug_belongs_to_another_id_is_rejected()
    {
        var c = new ModuleCatalog();
        Assert.Throws<InvalidOperationException>(() => c.Add(new IdOnly(ModuleSlugs.DriveHealth, Guid.NewGuid())));
        Assert.Throws<InvalidOperationException>(() => c.Add(new IdOnly("SomethingElse", ModuleIds.DriveHealth)));
    }

    [Fact]
    public void Plugin_modules_are_marked_and_can_be_disabled()
    {
        var c = new ModuleCatalog();
        var id = Guid.NewGuid();
        var d = c.Add(new IdOnly("contoso.battery-wear", id), ModuleSource.Plugin, "contoso");
        Assert.Equal(ModuleSource.Plugin, d.Source);
        Assert.Equal("contoso", d.PluginId);
        Assert.Equal(ModuleGroups.Other, d.Group);
        c.Disable(id);
        Assert.Equal(ModuleState.Disabled, c.StateOf(id));
    }

    [Fact]
    public void Merged_modules_map_to_their_current_slug()
    {
        var c = new ModuleCatalog();
        Assert.Equal(ModuleSlugs.Crashes, c.CurrentSlug(ModuleSlugs.BsodHistory));
        Assert.Equal(ModuleSlugs.Network, c.CurrentSlug("wificonfig"));
        Assert.Equal(ModuleSlugs.DriveHealth, c.CurrentSlug(ModuleSlugs.DriveHealth));
        Assert.Equal("Mystery", c.CurrentSlug("Mystery"));
        Assert.Equal(ModuleSlugs.Crashes, HistoryNames.ModuleAliases[ModuleSlugs.BsodHistory]);
    }

    [Fact]
    public void History_names_a_module_that_is_not_registered_from_the_catalog()
    {
        var entry = new HistoryEntry(DateTimeOffset.UtcNow, ModuleSlugs.NpuTest, ModuleSlugs.NpuTest, "OK", "fine", null, null, [], "PC", "1.0");
        var n = HistoryNames.Normalize([entry], new ModuleCatalog());
        Assert.Equal("NPU (AI accelerator) test", n[0].Test);
    }

    [Fact]
    public void Unknown_ids_show_as_unknown()
    {
        var id = Guid.NewGuid();
        Assert.Equal($"{id} (unknown module)", new ModuleCatalog().DisplayName(id));
        Assert.Equal("Mystery", new ModuleCatalog().DisplayName("Mystery"));
    }

    private sealed class IdOnly(string name, Guid id) : IDiagnosticModule
    {
        public Guid Id => id;
        public string Name => name;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) => Task.FromResult(FakeModule.Ok(name));
    }

    private sealed class GatedModule(bool present) : IHardwareGatedModule
    {
        public TaskCompletionSource Detected { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Guid Id => ModuleIds.NpuTest;
        public string Name => ModuleSlugs.NpuTest;
        public string DisplayName => "NPU (AI accelerator) test";
        public bool IsPresent { get; private set; }
        public bool IncludeInRunAll => false;
        public Task<bool> DetectPresenceAsync(CancellationToken ct = default)
        {
            IsPresent = present;
            Detected.TrySetResult();
            return Task.FromResult(present);
        }
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) => Task.FromResult(FakeModule.Ok(Name));
    }
}
