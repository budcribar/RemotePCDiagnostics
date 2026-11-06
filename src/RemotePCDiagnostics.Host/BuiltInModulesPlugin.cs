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
/// The modules compiled into the app: the ones that need administrator (sensors and fans, drive health, crashes, services, DISM, SFC and
/// the security audit), registered through <see cref="IModulePlugin"/> exactly as a loaded plugin would be. Every other module ships as
/// its own DLL in builtin-modules\ (src/Modules, <see cref="ModuleLoader.LoadBundled"/>). The shared services all of them use (command
/// runner, osquery, sensors, audio, NPU and the rest) are registered by <see cref="HostServices"/>.
/// </summary>
public sealed class BuiltInModulesPlugin(Microsoft.Extensions.Logging.ILoggerFactory loggers) : IModulePlugin
{
    public const string Id = "builtin";

    /// <summary>The modules compiled into the app because they need administrator. Every other built-in module ships as its own DLL.</summary>
    public static IReadOnlyList<Guid> CompiledIn { get; } =
        [ModuleIds.Sensors, ModuleIds.DriveHealth, ModuleIds.Services, ModuleIds.Crashes, ModuleIds.DismScanHealth, ModuleIds.SfcVerifyOnly, ModuleIds.SecurityAudit];

    /// <summary>The slugs of built-in modules that are neither compiled in nor found as a DLL in <paramref name="folder"/> (the package check).</summary>
    public static IReadOnlyList<string> MissingModuleDlls(string folder)
    {
        var found = new HashSet<Guid>();
        if (Directory.Exists(folder))
            foreach (var dll in Directory.EnumerateFiles(folder, "*.dll"))
                try { found.Add(ModuleManifest.ReadFromAssembly(File.ReadAllBytes(dll)).Manifest.Id); } catch { }
        return BuiltInModules.Descriptors.Where(d => d.MergedInto is null && !CompiledIn.Contains(d.Id) && !found.Contains(d.Id)).Select(d => d.Slug).ToList();
    }

    private ILogger L<T>() => HostServices.For<T>(loggers); // each module and adapter logs under its own category

    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule, LibreHardwareMonitorModule>();
        services.AddSingleton<IDiagnosticModule>(sp => new DriveHealthModule(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<IRetrimHistory>()));
        services.AddSingleton<IDiagnosticModule>(sp => sp.GetRequiredService<ServicesModule>());
        services.AddSingleton<IDiagnosticModule>(sp => new CrashesModule(sp.GetRequiredService<SystemCommandRunner>(), includeSystemCrashes: true));
        services.AddSingleton<IDiagnosticModule>(sp => new DismScanHealthModule(sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new SfcVerifyOnlyModule(sp.GetRequiredService<SystemCommandRunner>()));
        // On-demand only (Start button on its page): not in AutoRun below and excluded from Run All (IncludeInRunAll=false).
        services.AddSingleton<IDiagnosticModule>(new SecurityAuditModule(new SecurityAuditOptions { Log = L<SecurityAuditModule>() }));
        foreach (var (id, type) in RemotePCDiagnostics.UI.BuiltInModuleUi.Components) context.SetDetailsComponent(id, type);
    }
}
