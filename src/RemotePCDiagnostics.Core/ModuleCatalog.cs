using System.Collections.Concurrent;

namespace RemotePCDiagnostics.Core;

/// <summary>The descriptor of every built-in module that ever shipped, including retired ones. Never shrinks.</summary>
public static class BuiltInModules
{
    public static IReadOnlyList<ModuleDescriptor> Descriptors { get; } =
    [
        new(ModuleIds.Osquery, ModuleSlugs.Osquery, "Hardware inventory", ModuleKind.Check, ModuleGroups.Hardware, 100),
        new(ModuleIds.Sensors, ModuleSlugs.Sensors, "Temperatures & fans", ModuleKind.Check, ModuleGroups.Hardware, 200),
        new(ModuleIds.DeviceDrivers, ModuleSlugs.DeviceDrivers, "Device Manager & drivers", ModuleKind.Check, ModuleGroups.Hardware, 300),
        new(ModuleIds.DriveHealth, ModuleSlugs.DriveHealth, "Drive health", ModuleKind.Check, ModuleGroups.Storage, 100),
        new(ModuleIds.ResourceHogs, ModuleSlugs.ResourceHogs, "Resource hogs & uptime", ModuleKind.Check, ModuleGroups.Cpu, 100),
        new(ModuleIds.BatteryPower, ModuleSlugs.BatteryPower, "Battery & power plan", ModuleKind.Check, ModuleGroups.Power, 100),
        new(ModuleIds.Network, ModuleSlugs.Network, "Network & Wi-Fi", ModuleKind.Check, ModuleGroups.Network, 100),
        new(ModuleIds.Services, ModuleSlugs.Services, "Services", ModuleKind.Check, ModuleGroups.Windows, 100),
        new(ModuleIds.EventLog, ModuleSlugs.EventLog, "Windows error log", ModuleKind.Check, ModuleGroups.Windows, 200),
        new(ModuleIds.Crashes, ModuleSlugs.Crashes, "Crashes & unexpected restarts", ModuleKind.Check, ModuleGroups.Windows, 300),
        new(ModuleIds.Programs, ModuleSlugs.Programs, "Programs & updates", ModuleKind.Check, ModuleGroups.Apps, 100),
        new(ModuleIds.DismScanHealth, ModuleSlugs.DismScanHealth, "Windows component store (DISM)", ModuleKind.OnDemand, ModuleGroups.Windows, 400),
        new(ModuleIds.SfcVerifyOnly, ModuleSlugs.SfcVerifyOnly, "Protected system files (SFC)", ModuleKind.OnDemand, ModuleGroups.Windows, 500),
        new(ModuleIds.CpuStress, ModuleSlugs.CpuStress, "CPU stress test", ModuleKind.StressTest, ModuleGroups.Cpu, 200),
        new(ModuleIds.MemoryTest, ModuleSlugs.MemoryTest, "Memory test", ModuleKind.StressTest, ModuleGroups.Memory, 100),
        new(ModuleIds.DiskSpeed, ModuleSlugs.DiskSpeed, "Disk speed test", ModuleKind.StressTest, ModuleGroups.Storage, 200),
        new(ModuleIds.GpuStress, ModuleSlugs.GpuStress, "Graphics (GPU) stress test", ModuleKind.StressTest, ModuleGroups.Graphics, 100),
        new(ModuleIds.NetworkTest, ModuleSlugs.NetworkTest, "Network stability test", ModuleKind.StressTest, ModuleGroups.Network, 200),
        new(ModuleIds.SpeakerToMic, ModuleSlugs.SpeakerToMic, "Speaker to microphone test", ModuleKind.OnDemand, ModuleGroups.Audio, 100),
        new(ModuleIds.MicToSpeaker, ModuleSlugs.MicToSpeaker, "Microphone to speaker test", ModuleKind.OnDemand, ModuleGroups.Audio, 200),
        new(ModuleIds.Webcam, ModuleSlugs.Webcam, "Webcam test", ModuleKind.OnDemand, ModuleGroups.Camera, 100),
        new(ModuleIds.NpuTest, ModuleSlugs.NpuTest, "NPU (AI accelerator) test", ModuleKind.OnDemand, ModuleGroups.Ai, 100),
        new(ModuleIds.SecurityAudit, ModuleSlugs.SecurityAudit, "Security audit", ModuleKind.OnDemand, ModuleGroups.Security, 100) { Page = "security-audit" },
        // Merged into other modules; kept so History can still name their old results.
        new(ModuleIds.BsodHistory, ModuleSlugs.BsodHistory, "Blue screens & unexpected restarts", ModuleKind.Check, ModuleGroups.Windows, 310) { MergedInto = ModuleIds.Crashes },
        new(ModuleIds.WifiConfig, ModuleSlugs.WifiConfig, "Wi-Fi & network config", ModuleKind.Check, ModuleGroups.Network, 110) { MergedInto = ModuleIds.Network },
    ];
}

/// <summary>
/// Every module the app knows: the built-in descriptors (including retired ones) plus whatever was registered. A module that can't run
/// on this PC stays here, so History, the export and fix lookups can always name it. <see cref="DiagnosticsService.Modules"/> keeps
/// returning only the runnable modules.
/// </summary>
public sealed class ModuleCatalog
{
    private readonly ConcurrentDictionary<Guid, ModuleDescriptor> _byId = new();
    private readonly ConcurrentDictionary<Guid, IDiagnosticModule> _registered = new();
    private readonly ConcurrentDictionary<Guid, ModuleState> _disabled = new();
    private readonly ConcurrentDictionary<Guid, Type> _details = new();

    public ModuleCatalog(IEnumerable<ModuleDescriptor>? known = null)
    {
        foreach (var d in known ?? BuiltInModules.Descriptors) _byId[d.Id] = d;
    }

    /// <summary>A catalog of the built-ins plus <paramref name="modules"/>, for code that only has a module list.</summary>
    public static ModuleCatalog For(IEnumerable<IDiagnosticModule> modules)
    {
        var c = new ModuleCatalog();
        foreach (var m in modules) c.Add(m);
        return c;
    }

    /// <summary>Raised when a module is added or its state changes.</summary>
    public event EventHandler? Changed;

    /// <summary>Every known descriptor, in group then order.</summary>
    public IReadOnlyList<ModuleDescriptor> All =>
        _byId.Values.OrderBy(d => d.Group, StringComparer.Ordinal).ThenBy(d => d.Order).ThenBy(d => d.Slug, StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Adds a registered module. Its descriptor comes from the module, keeping the built-in Group, Order and links when known.</summary>
    public ModuleDescriptor Add(IDiagnosticModule module, ModuleSource source = ModuleSource.BuiltIn, string? pluginId = null)
    {
        var existing = _byId.GetValueOrDefault(module.Id);
        if (existing is not null && !string.Equals(existing.Slug, module.Name, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Module '{module.Name}' uses the id of '{existing.Slug}' ({module.Id}).");
        if (existing is null && Find(module.Name) is { } slugClash)
            throw new InvalidOperationException($"Module '{module.Name}' uses the slug of module {slugClash.Id}.");
        var d = DescriptorFor(module, existing) with
        {
            Source = existing?.Source == ModuleSource.Plugin ? ModuleSource.Plugin : source, PluginId = pluginId ?? existing?.PluginId,
            DetailsComponent = _details.GetValueOrDefault(module.Id) ?? existing?.DetailsComponent,
        };
        _byId[d.Id] = d;
        _registered[d.Id] = module;
        RaiseChanged();
        return d;
    }

    /// <summary>Adds a descriptor for a module that is known but not loaded (for example a plugin that failed to load).</summary>
    public void AddKnown(ModuleDescriptor descriptor, ModuleState state = ModuleState.Retired)
    {
        _byId.TryAdd(descriptor.Id, descriptor);
        if (state == ModuleState.Disabled) _disabled[descriptor.Id] = state;
        RaiseChanged();
    }

    /// <summary>Sets the module's own details UI (a Razor component type). The component gets the module as its
    /// <c>DiagnosticModule</c> parameter; a module without one is shown in the generic report view.</summary>
    public void SetDetailsComponent(Guid id, Type component)
    {
        _details[id] = component;
        if (_byId.TryGetValue(id, out var d)) _byId[id] = d with { DetailsComponent = component };
        RaiseChanged();
    }

    /// <summary>Records where a registered module came from (set by the plugin registrar, never by the module).</summary>
    public void SetOrigin(Guid id, ModuleSource source, string? pluginId)
    {
        if (_byId.TryGetValue(id, out var d)) _byId[id] = d with { Source = source, PluginId = pluginId };
        RaiseChanged();
    }

    /// <summary>Marks a module disabled (a plugin turned off or failed verification).</summary>
    public void Disable(Guid id) { _disabled[id] = ModuleState.Disabled; RaiseChanged(); }

    internal void RaiseChanged() { try { Changed?.Invoke(this, EventArgs.Empty); } catch { } }

    private static ModuleDescriptor DescriptorFor(IDiagnosticModule m, ModuleDescriptor? known)
    {
        var kind = m is IStressSuiteModule ? ModuleKind.StressTest : m.IncludeInRunAll ? ModuleKind.Check : ModuleKind.OnDemand;
        var display = string.IsNullOrWhiteSpace(m.DisplayName) ? m.Name : m.DisplayName;
        return known is null
            ? new ModuleDescriptor(m.Id, m.Name, display, kind)
            : known with { Slug = m.Name, DisplayName = display, Kind = kind };
    }

    public ModuleDescriptor? Get(Guid id) => _byId.GetValueOrDefault(id);

    /// <summary>The descriptor for a slug (case-insensitive), or null.</summary>
    public ModuleDescriptor? Find(string? slug) =>
        string.IsNullOrEmpty(slug) ? null : _byId.Values.FirstOrDefault(d => string.Equals(d.Slug, slug, StringComparison.OrdinalIgnoreCase));

    /// <summary>The registered module for an id, whether or not it can run here.</summary>
    public IDiagnosticModule? ModuleFor(Guid id) => _registered.GetValueOrDefault(id);

    /// <summary>Whether a known module can run on this PC now. Unknown ids are <see cref="ModuleState.Retired"/>.</summary>
    public ModuleState StateOf(Guid id)
    {
        if (_disabled.TryGetValue(id, out var s)) return s;
        if (!_registered.TryGetValue(id, out var m)) return ModuleState.Retired;
        return m is IHardwareGatedModule g && !g.IsPresent ? ModuleState.NotPresent : ModuleState.Available;
    }

    /// <summary>The module's name for people. An unknown slug is shown as itself with "(unknown module)".</summary>
    public string DisplayName(Guid id) => Get(id)?.DisplayName ?? $"{id} (unknown module)";

    /// <summary>The module's name for people, by slug; the slug itself when the catalog doesn't know it.</summary>
    public string DisplayName(string slug) => Find(slug)?.DisplayName ?? slug;

    /// <summary>The module a merged (retired) module's results now belong to; the slug itself otherwise.</summary>
    public string CurrentSlug(string slug) =>
        Find(slug) is { MergedInto: { } into } && Get(into) is { } target ? target.Slug : slug;

    /// <summary>Known descriptors that can run here now.</summary>
    public IReadOnlyList<ModuleDescriptor> Available => All.Where(d => StateOf(d.Id) == ModuleState.Available).ToList();
}
