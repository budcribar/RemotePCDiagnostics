using System.IO;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;
using RemotePCDiagnostics.Host.Sensors;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// The registration path for modules compiled into the app, kept so a module can be compiled in again without changing how plugins load.
/// Since every built-in module ships as its own DLL in builtin-modules\ (src/Modules, <see cref="ModuleLoader.LoadBundled"/>), including
/// the ones that need administrator, it registers none. The shared services modules use (command runner, osquery, sensors, audio, NPU
/// and the rest) are registered by <see cref="HostServices"/>.
/// </summary>
public sealed class BuiltInModulesPlugin : IModulePlugin
{
    public const string Id = "builtin";

    /// <summary>The modules compiled into the app: none. Every built-in module ships as its own DLL.</summary>
    public static IReadOnlyList<Guid> CompiledIn { get; } = [];

    /// <summary>The slugs of built-in modules that are neither compiled in nor found as a DLL in <paramref name="folder"/> (the package check).</summary>
    public static IReadOnlyList<string> MissingModuleDlls(string folder)
    {
        var found = new HashSet<Guid>();
        if (Directory.Exists(folder))
            foreach (var dll in Directory.EnumerateFiles(folder, "*.dll"))
                try { found.Add(ModuleManifest.ReadFromAssembly(File.ReadAllBytes(dll)).Manifest.Id); } catch { }
        return BuiltInModules.Descriptors.Where(d => d.MergedInto is null && !CompiledIn.Contains(d.Id) && !found.Contains(d.Id)).Select(d => d.Slug).ToList();
    }

    public void Register(IServiceCollection services, IPluginContext context)
    {
        foreach (var (id, type) in RemotePCDiagnostics.UI.BuiltInModuleUi.Components) context.SetDetailsComponent(id, type);
    }
}
