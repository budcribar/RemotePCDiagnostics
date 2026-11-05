using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

/// <summary>Loads the real samples/SampleModule DLL (copied to sample-module/ by the test project) through the module loader.</summary>
public sealed class ModuleLoaderTests : IDisposable
{
    private static readonly Guid SampleId = new("e38471d6-d5da-4ef8-9063-155f4bd2ec1a");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-modules-" + Guid.NewGuid().ToString("N"));
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private string Modules => Path.Combine(_root, "modules");
    private string Catalog => Path.Combine(_root, "catalog");

    public ModuleLoaderTests() => Directory.CreateDirectory(Modules);
    public void Dispose() { _key.Dispose(); try { Directory.Delete(_root, true); } catch { } }

    private static byte[] SampleBytes() => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "sample-module", "SampleModule.dll"));

    /// <summary>Replaces text inside the embedded module.json with text of the same length (the resource is stored as is).</summary>
    private static byte[] Patch(byte[] dll, string from, string to)
    {
        Assert.Equal(from.Length, to.Length);
        var a = Encoding.UTF8.GetBytes(from);
        var at = dll.AsSpan().IndexOf(a);
        Assert.True(at >= 0, $"'{from}' not found in the sample DLL");
        var copy = dll.ToArray();
        Encoding.UTF8.GetBytes(to).CopyTo(copy, at);
        return copy;
    }

    private void Install(byte[] dll, bool sign = true, string name = "SampleModule.dll")
    {
        var path = Path.Combine(Modules, name);
        File.WriteAllBytes(path, dll);
        if (sign) File.WriteAllText(path + ModuleSignature.Extension, ModuleSignature.Sign(dll, _key));
    }

    private (ModuleLoader Loader, PluginRegistrar Registrar, ServiceCollection Services) Load(bool allowUnsigned = false, string? pem = null)
    {
        var registrar = new PluginRegistrar(new SessionContext(SessionMode.Local), new Version(1, 2, 0));
        var loader = new ModuleLoader(new ModuleLoaderOptions
        {
            ModulesFolder = Modules, CatalogFolder = Catalog, PublicKeyPem = pem ?? _key.ExportSubjectPublicKeyInfoPem(),
            HostVersion = new Version(1, 2, 0), AllowUnsigned = allowUnsigned,
        }, registrar);
        var services = new ServiceCollection();
        loader.LoadAll(services);
        return (loader, registrar, services);
    }

    private static int ModuleCount(IServiceCollection s) => s.Count(d => d.ServiceType == typeof(IDiagnosticModule));

    [Fact]
    public async Task A_signed_module_loads_in_its_own_context_and_shares_the_contract_types()
    {
        Install(SampleBytes());
        var (_, registrar, services) = Load();

        var record = Assert.Single(registrar.Records);
        Assert.Equal(PluginState.Loaded, record.State);
        Assert.Equal("sample.uptime", record.PluginId);
        Assert.Equal(SampleId, record.ModuleId);
        Assert.Equal("1.0.0", record.Version);
        Assert.Equal("Signed (project key)", record.Signature);

        using var sp = services.BuildServiceProvider();
        var module = Assert.Single(sp.GetServices<IDiagnosticModule>()); // the cast works: one IDiagnosticModule type across the boundary
        Assert.Equal(SampleId, module.Id);
        Assert.NotEqual(System.Runtime.Loader.AssemblyLoadContext.Default, System.Runtime.Loader.AssemblyLoadContext.GetLoadContext(module.GetType().Assembly));
        var result = await module.RefreshAsync(null);
        Assert.Equal("sample.uptime", result.ModuleName);
        Assert.StartsWith("Up ", result.Message);

        var catalog = new ModuleCatalog();
        foreach (var m in sp.GetServices<IDiagnosticModule>()) catalog.Add(m);
        registrar.ApplyTo(catalog);
        Assert.Equal(ModuleSource.Plugin, catalog.Get(SampleId)!.Source);
        Assert.Equal("sample.uptime", catalog.Get(SampleId)!.PluginId);

        // The manifest and strings are kept in the catalog folder.
        Assert.True(File.Exists(Path.Combine(Catalog, SampleId.ToString("D"), "module.json")));
        Assert.True(File.Exists(Path.Combine(Catalog, SampleId.ToString("D"), "strings", "de.json")));
    }

    [Fact]
    public void An_unsigned_module_never_loads_and_is_listed_with_the_reason()
    {
        Install(SampleBytes(), sign: false);
        var (loader, registrar, services) = Load();
        var record = Assert.Single(registrar.Records);
        Assert.Equal(PluginState.Disabled, record.State);
        Assert.Equal("Unsigned", record.Signature);
        Assert.Contains("unsigned modules are turned off", record.Reason);
        Assert.Equal(0, ModuleCount(services));
        Assert.Empty(loader.UserMode);
    }

    [Fact]
    public void An_unsigned_module_goes_to_user_mode_when_the_person_at_the_PC_allowed_it()
    {
        Install(SampleBytes(), sign: false);
        var (loader, registrar, services) = Load(allowUnsigned: true);
        var record = Assert.Single(registrar.Records);
        Assert.True(record.UserMode);
        Assert.Equal(0, ModuleCount(services));
        var um = Assert.Single(loader.UserMode);
        Assert.Equal(SampleId, um.Manifest.Id);
    }

    [Fact]
    public void An_unsigned_module_that_needs_administrator_is_disabled_even_when_unsigned_modules_are_on()
    {
        Install(Patch(SampleBytes(), "\"needsAdmin\": false", "\"needsAdmin\": true "), sign: false);
        var (loader, registrar, _) = Load(allowUnsigned: true);
        Assert.Contains("needs administrator", Assert.Single(registrar.Records).Reason);
        Assert.Empty(loader.UserMode);
    }

    [Fact]
    public void A_signature_from_another_key_or_over_other_bytes_does_not_count()
    {
        var dll = SampleBytes();
        Install(dll);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (_, registrar, services) = Load(pem: other.ExportSubjectPublicKeyInfoPem());
        Assert.Equal("Signature does not match", Assert.Single(registrar.Records).Signature);
        Assert.Equal(0, ModuleCount(services));

        // Signed, then changed after signing.
        var path = Path.Combine(Modules, "SampleModule.dll");
        File.WriteAllBytes(path, Patch(dll, "Uptime (sample plugin)", "Uptime (sampel plugin)"));
        (_, registrar, services) = Load();
        Assert.Equal("Signature does not match", Assert.Single(registrar.Records).Signature);
        Assert.Equal(0, ModuleCount(services));
    }

    [Fact]
    public void No_public_key_means_nothing_is_signed()
    {
        Install(SampleBytes());
        var (_, registrar, services) = Load(pem: " ");
        Assert.Equal(PluginState.Disabled, Assert.Single(registrar.Records).State);
        Assert.Equal(0, ModuleCount(services));
    }

    [Fact]
    public void A_module_built_for_another_contract_is_disabled()
    {
        Install(Patch(SampleBytes(), "\"contract\": \"1.0\"", "\"contract\": \"9.0\""));
        var (_, registrar, services) = Load();
        Assert.Contains("built for contract 9.0", Assert.Single(registrar.Records).Reason);
        Assert.Equal(0, ModuleCount(services));
    }

    [Fact]
    public void A_module_that_reuses_a_built_in_id_is_disabled()
    {
        Install(Patch(SampleBytes(), SampleId.ToString("D"), ModuleIds.Osquery.ToString("D")));
        var (_, registrar, services) = Load();
        Assert.Contains("already used by", Assert.Single(registrar.Records).Reason);
        Assert.Equal(0, ModuleCount(services));
    }

    [Fact]
    public void Two_DLLs_with_the_same_module_id_load_once()
    {
        var dll = SampleBytes();
        Install(dll, name: "A.dll");
        Install(dll, name: "B.dll");
        var (_, registrar, services) = Load();
        Assert.Equal(2, registrar.Records.Count);
        Assert.Single(registrar.Records, r => r.State == PluginState.Loaded);
        Assert.Single(registrar.Records, r => r.Reason?.Contains("already used") == true);
        Assert.Equal(1, ModuleCount(services));
    }

    [Fact]
    public void A_file_that_is_not_a_module_is_disabled_and_startup_carries_on()
    {
        File.WriteAllText(Path.Combine(Modules, "notes.dll"), "not a DLL");
        Install(SampleBytes());
        var (_, registrar, services) = Load();
        Assert.Equal(2, registrar.Records.Count);
        Assert.Single(registrar.Records, r => r.State == PluginState.Disabled && r.PluginId == "notes");
        Assert.Equal(1, ModuleCount(services));
    }

    [Fact]
    public void A_removed_module_stays_known_as_retired_from_the_catalog_folder()
    {
        Install(SampleBytes());
        Load();
        File.Delete(Path.Combine(Modules, "SampleModule.dll"));

        var (_, registrar, _) = Load();
        Assert.Empty(registrar.Records);
        var catalog = new ModuleCatalog();
        registrar.ApplyTo(catalog);
        Assert.Equal(ModuleState.Retired, catalog.StateOf(SampleId));
        Assert.Equal("Uptime (sample plugin)", catalog.DisplayName(SampleId));
        Assert.Equal(SampleId, catalog.Find("sample.uptime")!.Id);
    }

    [Fact]
    public void The_manifest_is_read_without_loading_the_assembly()
    {
        var (manifest, strings) = ModuleManifest.ReadFromAssembly(SampleBytes());
        Assert.Equal(SampleId, manifest.Id);
        Assert.Equal("SampleModule.SampleModulePlugin", manifest.EntryType);
        Assert.Equal(ModuleKind.Check, manifest.Kind);
        Assert.Equal(ModuleGroups.Other, manifest.Group);
        Assert.Contains("de.json", strings.Keys);
        Assert.Null(manifest.Problem(new Version(1, 2, 0)));
        Assert.Contains("vendor.name", (manifest with { Slug = "uptime" }).Problem(new Version(1, 2, 0)));
        Assert.Contains("needs app version", (manifest with { MinHost = "9.0" }).Problem(new Version(1, 2, 0)));
    }
}
