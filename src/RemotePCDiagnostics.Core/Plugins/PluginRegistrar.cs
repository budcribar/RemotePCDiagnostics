using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Plugins;

public enum PluginState { Loaded, Disabled }

/// <summary>One plugin's registration, for the About page and the log.</summary>
public sealed record PluginRecord(string PluginId, ModuleSource Source, PluginState State, string? Reason = null)
{
    public string? Version { get; init; }
    public string? Signature { get; init; }
    public string? Path { get; init; }
    public Guid? ModuleId { get; init; }
    public string? DisplayName { get; init; }
    /// <summary>Unsigned plugin that runs out of process in user mode.</summary>
    public bool UserMode { get; init; }
}

/// <summary>
/// Runs each <see cref="IModulePlugin.Register"/> (built-in or loaded) before the container is built. A plugin's registrations go into a
/// scratch collection first, so one that throws leaves nothing behind: it is marked Disabled and the app carries on. Modules a plugin
/// registers are tracked so the catalog knows where each came from.
/// </summary>
public sealed class PluginRegistrar(ISessionContext session, Version hostVersion, ILogger? log = null)
{
    private readonly List<PluginRecord> _records = [];
    private readonly ConcurrentDictionary<Guid, (ModuleSource Source, string PluginId)> _origins = new();
    private readonly ConcurrentDictionary<Guid, Type> _details = new();
    private readonly ConcurrentDictionary<Guid, ModuleDescriptor> _known = new();
    private readonly ConcurrentDictionary<Guid, ModuleDescriptor> _retired = new();
    private readonly ConcurrentDictionary<Guid, ModuleDescriptor> _manifests = new();
    private readonly object _gate = new();

    public IReadOnlyList<PluginRecord> Records { get { lock (_gate) return _records.ToList(); } }

    /// <summary>Calls the plugin's Register. Returns false (and records it Disabled) when it throws or the module id isn't the expected one.</summary>
    /// <param name="expectedModuleId">From the plugin's manifest: the one module it may register.</param>
    public bool Register(IServiceCollection services, IModulePlugin plugin, string pluginId, ModuleSource source = ModuleSource.Plugin,
        Guid? expectedModuleId = null, PluginRecord? record = null, ModuleDescriptor? manifest = null)
    {
        var scratch = new ServiceCollection();
        var ctx = new Context(this, pluginId, session, hostVersion, log);
        try { plugin.Register(scratch, ctx); }
        catch (Exception ex)
        {
            Add((record ?? new PluginRecord(pluginId, source, PluginState.Loaded)) with { State = PluginState.Disabled, Reason = $"Register failed: {ex.Message}" });
            LogError($"plugin {pluginId}: Register failed, disabled: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
        if (expectedModuleId is { } expectedId)
        {
            var modules = scratch.Count(d => d.ServiceType == typeof(IDiagnosticModule));
            if (modules != 1)
            {
                Add((record ?? new PluginRecord(pluginId, source, PluginState.Loaded)) with { State = PluginState.Disabled, Reason = $"registered {modules} modules; a plugin registers exactly one" });
                return false;
            }
        }
        foreach (var d in scratch)
            services.Add(d.ServiceType == typeof(IDiagnosticModule) ? Tracked(d, pluginId, source, expectedModuleId) : d);
        Add(record ?? new PluginRecord(pluginId, source, PluginState.Loaded));
        if (manifest is not null) _manifests[manifest.Id] = manifest;
        if (source == ModuleSource.Plugin) Log($"plugin {pluginId}: registered");
        return true;
    }

    /// <summary>Records a plugin that was found but not loaded (bad signature, wrong contract version, duplicate id).</summary>
    public void RecordDisabled(PluginRecord record, ModuleDescriptor? known = null)
    {
        Add(record with { State = PluginState.Disabled });
        if (known is not null) _known[known.Id] = known;
        Log($"plugin {record.PluginId}: disabled: {record.Reason}");
    }

    /// <summary>A plugin whose DLL is gone but whose catalog copy is kept: History and the export can still name its results.</summary>
    public void AddRetired(ModuleDescriptor descriptor) => _retired[descriptor.Id] = descriptor;

    /// <summary>Copies where each module came from, the details components and the disabled plugins' descriptors into the catalog.</summary>
    public void ApplyTo(ModuleCatalog catalog)
    {
        foreach (var (id, type) in _details) catalog.SetDetailsComponent(id, type);
        foreach (var (id, origin) in _origins) catalog.SetOrigin(id, origin.Source, origin.PluginId);
        foreach (var d in _manifests.Values) catalog.Describe(d);
        foreach (var d in _known.Values) catalog.AddKnown(d, ModuleState.Disabled);
        foreach (var d in _retired.Values) catalog.AddKnown(d, ModuleState.Retired);
    }

    private ServiceDescriptor Tracked(ServiceDescriptor d, string pluginId, ModuleSource source, Guid? expectedModuleId)
    {
        Func<IServiceProvider, object> create = d.ImplementationInstance is { } instance ? _ => instance
            : d.ImplementationFactory ?? (sp => ActivatorUtilities.CreateInstance(sp, d.ImplementationType!));
        return ServiceDescriptor.Singleton(typeof(IDiagnosticModule), sp =>
        {
            var m = (IDiagnosticModule)create(sp);
            if (expectedModuleId is { } want && m.Id != want)
                throw new InvalidOperationException($"Plugin {pluginId} registered module {m.Id}, but its manifest says {want}.");
            _origins[m.Id] = (source, pluginId);
            return m;
        });
    }

    private void Add(PluginRecord r) { lock (_gate) _records.Add(r); }
    private void Log(string m) => log.Info(m);
    private void LogError(string m) => log.Error(m);

    private sealed class Context(PluginRegistrar owner, string pluginId, ISessionContext session, Version hostVersion, ILogger? log) : IPluginContext
    {
        public string PluginId => pluginId;
        public ISessionContext Session => session;
        public Version HostVersion => hostVersion;
        public Version ContractVersion => Plugins.ContractVersion.Current;
        public void Log(string message) => log.Line($"[{pluginId}] {message}"); // a plugin's own wording: level read from the text
        public void SetDetailsComponent(Guid moduleId, Type component) => owner._details[moduleId] = component;
    }
}
