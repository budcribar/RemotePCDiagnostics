using System.Collections.Concurrent;

namespace RemotePCDiagnostics.Core;

/// <summary>What kind of test a module is. Drives Run All and the stress suite.</summary>
public enum ModuleKind
{
    /// <summary>A quick check: part of Run All.</summary>
    Check,
    /// <summary>A stress test: runs in the stress suite or from its Start button, never in Run All.</summary>
    StressTest,
    /// <summary>Runs only when someone starts it (audio, webcam, NPU, security audit, SFC/DISM).</summary>
    OnDemand,
}

/// <summary>Where a module came from. Set by the registration path, never by the module.</summary>
public enum ModuleSource { BuiltIn, Plugin }

/// <summary>Whether a known module can run on this PC right now. Separate from the descriptor because it changes at run time.</summary>
public enum ModuleState
{
    /// <summary>Loaded and usable on this PC: shown in lists, Run All and History.</summary>
    Available,
    /// <summary>The hardware it tests is missing (no NPU, no webcam): History only.</summary>
    NotPresent,
    /// <summary>A plugin that is turned off or failed verification: History only.</summary>
    Disabled,
    /// <summary>No longer shipped (or not part of this build): History only.</summary>
    Retired,
}

/// <summary>
/// The description of a module: everything needed to name and place it, even when it can't run. The catalog keeps one for every module
/// that ever shipped, so History and the CSV export can always name a result.
/// </summary>
/// <param name="Id">Permanent identity (see <see cref="ModuleIds"/>).</param>
/// <param name="Slug">Readable handle (today's module Name). Built-ins keep their names; plugins use vendor.name.</param>
/// <param name="DisplayName">English label. Localized names are looked up by <see cref="Id"/> at display time.</param>
/// <param name="Kind">Check, stress test or on-demand test.</param>
/// <param name="Group">Stable group key such as "storage" (never display text). Unknown keys show under "Other".</param>
/// <param name="Order">Display position within the group, spaced by 100. Never affects run order.</param>
public sealed record ModuleDescriptor(Guid Id, string Slug, string DisplayName, ModuleKind Kind, string Group = ModuleGroups.Other, int Order = 10_000)
{
    public ModuleSource Source { get; init; } = ModuleSource.BuiltIn;
    /// <summary>The plugin that supplied the module, when <see cref="Source"/> is <see cref="ModuleSource.Plugin"/>.</summary>
    public string? PluginId { get; init; }
    /// <summary>The module's own details UI (a Razor component type), or null for the generic report view.</summary>
    public Type? DetailsComponent { get; init; }
    /// <summary>Modules that must run first in the same Run All and pass.</summary>
    public IReadOnlyList<Guid> DependsOn { get; init; } = [];
    /// <summary>Modules that should run first when both are selected (order only, no pass requirement).</summary>
    public IReadOnlyList<Guid> RunAfter { get; init; } = [];
    /// <summary>A retired module whose results now count as this module's (it was merged into it).</summary>
    public Guid? MergedInto { get; init; }
}

/// <summary>Stable group keys for built-in modules. A plugin may add its own key.</summary>
public static class ModuleGroups
{
    public const string Hardware = "hardware", Cpu = "cpu", Memory = "memory", Storage = "storage", Graphics = "graphics", Network = "network",
        Windows = "windows", Apps = "apps", Security = "security", Audio = "audio", Camera = "camera", Ai = "ai", Power = "power", Other = "other";

    /// <summary>English name for a group key; unknown keys are "Other".</summary>
    public static string DisplayName(string? key) => key switch
    {
        Hardware => "Hardware", Cpu => "Processor", Memory => "Memory", Storage => "Storage", Graphics => "Graphics", Network => "Network",
        Windows => "Windows", Apps => "Programs", Security => "Security", Audio => "Audio", Camera => "Camera", Ai => "AI accelerator",
        Power => "Power", _ => "Other",
    };
}

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
        new(ModuleIds.SecurityAudit, ModuleSlugs.SecurityAudit, "Security audit", ModuleKind.OnDemand, ModuleGroups.Security, 100),
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
        var d = DescriptorFor(module, existing) with { Source = existing?.Source == ModuleSource.Plugin ? ModuleSource.Plugin : source, PluginId = pluginId ?? existing?.PluginId };
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
