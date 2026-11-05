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
    public static Loaded Load(string path, Action<string>? log = null)
    {
        var dll = File.ReadAllBytes(path);
        var (manifest, _) = ModuleManifest.ReadFromAssembly(dll);
        if (manifest.Problem(new Version(int.MaxValue, 0)) is { } problem && !problem.StartsWith("needs app version", StringComparison.Ordinal))
            throw new InvalidDataException(problem);
        var alc = new ModuleLoadContext(manifest.Slug, dll);
        var asm = alc.LoadFromStream(new MemoryStream(dll, writable: false));
        var entry = asm.GetType(manifest.EntryType, throwOnError: false) ?? throw new InvalidDataException($"entryType {manifest.EntryType} not found");
        if (Activator.CreateInstance(entry) is not IModulePlugin plugin) throw new InvalidDataException($"{manifest.EntryType} does not implement IModulePlugin");
        var context = new Context(manifest.Slug, log);
        var services = new ServiceCollection();
        plugin.Register(services, context);
        var sp = services.BuildServiceProvider();
        var modules = sp.GetServices<IDiagnosticModule>().ToList();
        if (modules.Count != 1) throw new InvalidDataException($"registered {modules.Count} modules; a plugin registers exactly one");
        if (modules[0].Id != manifest.Id) throw new InvalidDataException($"registered module {modules[0].Id}, but its manifest says {manifest.Id}");
        return new Loaded(manifest, modules[0], context.Details.GetValueOrDefault(manifest.Id));
    }

    private sealed class Context(string pluginId, Action<string>? log) : IPluginContext
    {
        public Dictionary<Guid, Type> Details { get; } = [];
        public string PluginId => pluginId;
        // Remote rules still apply in the app (actor attribution, notices); a user-mode process never acts for a technician.
        public ISessionContext Session { get; } = new SessionContext(SessionMode.Local);
        public Version HostVersion => typeof(Context).Assembly.GetName().Version ?? new Version(0, 0);
        public Version ContractVersion => Plugins.ContractVersion.Current;
        public void Log(string message) { try { log?.Invoke($"[{pluginId}] {message}"); } catch { } }
        public void SetDetailsComponent(Guid moduleId, Type component) => Details[moduleId] = component;
    }
}
