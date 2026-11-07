using System.Runtime.Loader;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// The modules that ship with the app as their own DLLs (src/Modules/*): each carries the id and slug the app always gave it, and
/// <see cref="ModuleLoader.LoadBundled"/> loads it into its own load context, in process and unsigned, sharing Core's types.
/// </summary>
public sealed class BundledModulesTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-bundled-" + Guid.NewGuid().ToString("N"));
    private string Bundled => Path.Combine(_root, ModuleLoaderOptions.BundledFolderName);
    private string Plugins => Path.Combine(_root, "modules");

    public BundledModulesTests() { Directory.CreateDirectory(Bundled); Directory.CreateDirectory(Plugins); }
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    /// <summary>The module DLLs built next to the tests (the test project references every src/Modules project).</summary>
    public static IEnumerable<object[]> ModuleDlls() =>
        Directory.EnumerateFiles(AppContext.BaseDirectory, "RemotePCDiagnostics.Modules.*.dll").Order(StringComparer.Ordinal).Select(p => new object[] { Path.GetFileName(p) });

    private static string Dll(string name) => Path.Combine(AppContext.BaseDirectory, name);

    private (ModuleLoader Loader, PluginRegistrar Registrar, ServiceCollection Services) Load(string? bundled = null)
    {
        var registrar = new PluginRegistrar(new SessionContext(SessionMode.Local), new Version(1, 2, 0));
        var loader = new ModuleLoader(new ModuleLoaderOptions
        {
            ModulesFolder = Plugins, CatalogFolder = Path.Combine(_root, "catalog"), BundledFolder = bundled ?? Bundled, HostVersion = new Version(1, 2, 0),
        }, registrar);
        var services = new ServiceCollection();
        services.AddSingleton(new OsqueryRunner(baseDirectory: _root));
        services.AddSingleton(new SystemCommandRunner());
        // The app's Windows adapters the test modules take (only their constructors run here).
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Sensors.ISensorProvider>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Sensors.IEcFanSource>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Stress.IGpuDeviceFactory>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Audio.IAudioIo>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Webcam.IWebcamIo>());
        services.AddSingleton(Stub<RemotePCDiagnostics.Core.Npu.INpuIo>());
        loader.LoadBundled(services);
        return (loader, registrar, services);
    }

    private static T Stub<T>() where T : class => System.Reflection.DispatchProxy.Create<T, NullProxy>();

    /// <summary>Answers every call with the default value.</summary>
    public class NullProxy : System.Reflection.DispatchProxy
    {
        protected override object? Invoke(System.Reflection.MethodInfo? method, object?[]? args) =>
            method?.ReturnType is { IsValueType: true } t && t != typeof(void) ? Activator.CreateInstance(t) : null;
    }

    [Fact]
    public void Every_module_project_is_built() =>
        Assert.True(ModuleDlls().Count() >= 24, "expected the module DLLs from src/Modules next to the tests");

    /// <summary>The modules that need administrator. They ship as their own DLLs too, and run in the app process by default.</summary>
    public static readonly Guid[] AdminModules = [ModuleIds.DismScanHealth, ModuleIds.SfcVerifyOnly, ModuleIds.SecurityAudit];

    /// <summary>Modules whose class is the app's Core type (other parts of the app use it too), so only their plugin is the DLL's. The
    /// last four used to need administrator; in user mode they ask the app for those reads (host queries).</summary>
    public static readonly Guid[] CoreTypeModules = [.. AdminModules, ModuleIds.Sensors, ModuleIds.DriveHealth, ModuleIds.Services, ModuleIds.Crashes];

    [Fact]
    public void Every_built_in_module_ships_as_its_own_dll()
    {
        var shipped = ModuleDlls().Select(f => ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Dll((string)f[0]))).Manifest.Id).ToHashSet();
        var missing = BuiltInModules.Descriptors.Where(d => d.MergedInto is null && !shipped.Contains(d.Id)).Select(d => d.Slug).ToList();
        Assert.True(missing.Count == 0, "no DLL for: " + string.Join(", ", missing));
    }

    [Theory]
    [MemberData(nameof(ModuleDlls))]
    public void Each_module_dll_keeps_its_built_in_id_and_slug(string file)
    {
        var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(Dll(file)));
        var known = Assert.Single(BuiltInModules.Descriptors, d => d.Id == manifest.Id);
        Assert.Equal(known.Slug, manifest.Slug);
        Assert.Equal(ModuleIds.BuiltIn[manifest.Id], manifest.Slug);
        Assert.Null(manifest.Problem(new Version(1, 2, 0), vendorSlug: false));
        Assert.Equal(AdminModules.Contains(manifest.Id), manifest.NeedsAdmin);
        // Admin modules ship in process; the process-mode switch can run them out of process (elevated) to test them.
        if (manifest.NeedsAdmin) Assert.False(manifest.OutOfProcess, $"{file}: a module that needs administrator ships in process");
        Assert.False(manifest.ChangesSystem);
        Assert.Equal($"{Path.GetFileNameWithoutExtension(file)}.{Path.GetFileNameWithoutExtension(file)["RemotePCDiagnostics.Modules.".Length..]}Plugin", manifest.EntryType);
    }

    [Theory]
    [MemberData(nameof(ModuleDlls))]
    public void Each_module_dll_loads_in_its_own_context_and_registers_its_one_module(string file)
    {
        File.Copy(Dll(file), Path.Combine(Bundled, file));
        var (_, registrar, services) = Load();

        var record = Assert.Single(registrar.Records);
        Assert.True(record.State == PluginState.Loaded, record.Reason);
        Assert.Equal(ModuleSource.BuiltIn, record.Source);
        Assert.Equal(ModuleLoader.BundledSignature, record.Signature);
        using var sp = services.BuildServiceProvider();
        var module = Assert.Single(sp.GetServices<IDiagnosticModule>());
        Assert.Equal(record.ModuleId, module.Id);
        Assert.Equal(ModuleIds.BuiltIn[module.Id], module.Name);
        // The module's own code is in its context. An admin module's class may be the app's Core type (other parts of the app use it too);
        // then only its plugin is the DLL's.
        var alc = AssemblyLoadContext.GetLoadContext(module.GetType().Assembly);
        if (module.GetType().Assembly != typeof(ModuleCatalog).Assembly)
        {
            Assert.NotEqual(AssemblyLoadContext.Default, alc);
            Assert.StartsWith("module:", alc!.Name);
        }
        else Assert.Contains(CoreTypeModules, id => id == module.Id);
    }

    [Fact]
    public void The_app_descriptor_and_details_UI_stay_with_the_module()
    {
        File.Copy(Dll("RemotePCDiagnostics.Modules.Osquery.dll"), Path.Combine(Bundled, "RemotePCDiagnostics.Modules.Osquery.dll"));
        var (_, registrar, services) = Load();
        using var sp = services.BuildServiceProvider();
        var catalog = new ModuleCatalog();
        foreach (var m in sp.GetServices<IDiagnosticModule>()) catalog.Add(m);
        registrar.ApplyTo(catalog);
        var d = catalog.Get(ModuleIds.Osquery)!;
        var builtIn = BuiltInModules.Descriptors.Single(x => x.Id == ModuleIds.Osquery);
        Assert.Equal((builtIn.Group, builtIn.Order), (d.Group, d.Order));
        Assert.Equal(ModuleSource.BuiltIn, d.Source);
        Assert.Equal("RemotePCDiagnostics.Modules.Osquery", d.PluginId);
        Assert.NotNull(d.DetailsComponent);
        Assert.Equal("OsqueryPage", d.DetailsComponent!.Name);
        Assert.NotEqual(AssemblyLoadContext.Default, AssemblyLoadContext.GetLoadContext(d.DetailsComponent.Assembly));
    }

    [Fact]
    public void Core_types_are_shared_with_the_app()
    {
        File.Copy(Dll("RemotePCDiagnostics.Modules.Programs.dll"), Path.Combine(Bundled, "RemotePCDiagnostics.Modules.Programs.dll"));
        var (_, _, services) = Load();
        using var sp = services.BuildServiceProvider();
        var module = Assert.Single(sp.GetServices<IDiagnosticModule>());
        // The module's base type is the app's own Core type, not a second copy loaded into the module's context.
        Assert.True(module is OsqueryAreaModuleBase);
    }

    [Fact]
    public void A_dll_with_an_id_the_app_does_not_ship_is_not_loaded()
    {
        File.Copy(Path.Combine(AppContext.BaseDirectory, "sample-module", "SampleModule.dll"), Path.Combine(Bundled, "SampleModule.dll"));
        var (_, registrar, services) = Load();
        var record = Assert.Single(registrar.Records);
        Assert.Equal(PluginState.Disabled, record.State);
        Assert.Contains("not a module that ships with this app", record.Reason);
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IDiagnosticModule));
    }

    [Fact]
    public void A_module_found_twice_loads_once()
    {
        File.Copy(Dll("RemotePCDiagnostics.Modules.Programs.dll"), Path.Combine(Bundled, "A.dll"));
        File.Copy(Dll("RemotePCDiagnostics.Modules.Programs.dll"), Path.Combine(Bundled, "B.dll"));
        var (_, registrar, services) = Load();
        Assert.Single(services, d => d.ServiceType == typeof(IDiagnosticModule));
        Assert.Equal([PluginState.Loaded, PluginState.Disabled], registrar.Records.Select(r => r.State));
        Assert.Contains("already loaded", registrar.Records[1].Reason);
    }

    [Fact]
    public void The_plugin_folder_is_never_trusted_as_the_built_in_folder()
    {
        File.Copy(Dll("RemotePCDiagnostics.Modules.Programs.dll"), Path.Combine(Plugins, "RemotePCDiagnostics.Modules.Programs.dll"));
        var (_, registrar, services) = Load(bundled: Plugins);
        Assert.Empty(registrar.Records);
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IDiagnosticModule));
    }

    [Fact]
    public void A_missing_folder_loads_nothing()
    {
        var (_, registrar, _) = Load(bundled: Path.Combine(_root, "nope"));
        Assert.Empty(registrar.Records);
    }

    [Fact]
    public void A_plugin_cannot_take_the_id_of_a_module_that_moved_to_its_own_dll()
    {
        // The built-in descriptors keep every moved module, so the plugin loader still treats its id as taken.
        Assert.Contains(BuiltInModules.Descriptors, d => d.Id == ModuleIds.Programs);
        Assert.NotNull(new ModuleCatalog().Get(ModuleIds.Programs));
    }
}
