using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// Loads one unsigned module inside a user-mode process (the module host, or the module's UI host): its own load context, its plugin's
/// registrations, exactly one module whose id matches its manifest. Never call it in the app process, which runs elevated.
/// </summary>
public static class UserModePlugin
{
    public sealed record Loaded(ModuleManifest Manifest, IDiagnosticModule Module, Type? DetailsComponent);

    /// <param name="log">Where the plugin's <see cref="IPluginContext.Log"/> lines go.</param>
    /// <param name="appDirectory">The app's folder (where tools\osquery is). When set, the plugin's services get the same helpers the
    /// app gives a module that ships with it (<see cref="AddHelpers"/>); they run in this user-mode process, with its token.</param>
    /// <param name="hostQueries">The module host's line to the app (<see cref="IHostQueries"/>), registered for the plugin when the module
    /// lists capabilities: a module that ships with the app then asks the app for what needs administrator rights.</param>
    public static Loaded Load(string path, ILogger? log = null, string? appDirectory = null, IHostQueries? hostQueries = null)
    {
        var dll = File.ReadAllBytes(path);
        var (manifest, _) = ModuleManifest.ReadFromAssembly(dll);
        // A module that ships with the app keeps the slug it always had (no vendor. prefix), whatever its module.json says about where it
        // runs (the About page's switch decides); the app checked it before starting this process, and never lets a plugin take a built-in id.
        var builtIn = BuiltInModules.Descriptors.Any(d => d.Id == manifest.Id && string.Equals(d.Slug, manifest.Slug, StringComparison.Ordinal));
        if (manifest.Problem(new Version(int.MaxValue, 0), vendorSlug: !builtIn) is { } problem && !problem.StartsWith("needs app version", StringComparison.Ordinal))
            throw new InvalidDataException(problem);
        var alc = new ModuleLoadContext(manifest.Slug, dll);
        var asm = alc.LoadFromStream(new MemoryStream(dll, writable: false));
        var entry = asm.GetType(manifest.EntryType, throwOnError: false) ?? throw new InvalidDataException($"entryType {manifest.EntryType} not found");
        if (Activator.CreateInstance(entry) is not IModulePlugin plugin) throw new InvalidDataException($"{manifest.EntryType} does not implement IModulePlugin");
        var context = new Context(manifest.Slug, log);
        var services = new ServiceCollection();
        if (appDirectory is not null) AddHelpers(services, appDirectory, log);
        if (hostQueries is not null && manifest.Capabilities.Count > 0) services.AddSingleton(hostQueries);
        plugin.Register(services, context);
        var sp = services.BuildServiceProvider();
        var modules = sp.GetServices<IDiagnosticModule>().ToList();
        if (modules.Count != 1) throw new InvalidDataException($"registered {modules.Count} modules; a plugin registers exactly one");
        if (modules[0].Id != manifest.Id) throw new InvalidDataException($"registered module {modules[0].Id}, but its manifest says {manifest.Id}");
        return new Loaded(manifest, modules[0], context.Details.GetValueOrDefault(manifest.Id));
    }

    /// <summary>The app's helpers that a module which ships with the app takes from its services: osquery (from the app's tools folder)
    /// and Windows commands. Both only read; here they run with the user-mode process's token.</summary>
    public static void AddHelpers(IServiceCollection services, string appDirectory, ILogger? log = null)
    {
        services.AddSingleton(new Osquery.OsqueryRunner(baseDirectory: appDirectory, options: new Osquery.OsqueryOptions { Log = log }));
        services.AddSingleton(new Areas.SystemCommandRunner(log: log));
    }

    private sealed class Context(string pluginId, ILogger? log) : IPluginContext
    {
        public Dictionary<Guid, Type> Details { get; } = [];
        public string PluginId => pluginId;
        // Remote rules still apply in the app (actor attribution, notices); a user-mode process never acts for a remote user.
        public ISessionContext Session { get; } = new SessionContext(SessionMode.Local);
        public Version HostVersion => typeof(Context).Assembly.GetName().Version ?? new Version(0, 0);
        public Version ContractVersion => Plugins.ContractVersion.Current;
        public ILogger Log { get; } = new PrefixedLogger(log, pluginId); // "[pluginId] " on each line, at the level the plugin chose
        public void SetDetailsComponent(Guid moduleId, Type component) => Details[moduleId] = component;
    }
}
