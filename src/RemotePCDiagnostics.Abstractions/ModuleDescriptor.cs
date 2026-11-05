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
    /// <summary>The route of the module's own top-level page (the security audit), when it isn't listed on Checks or Stress tests.</summary>
    public string? Page { get; init; }

    /// <summary>Listed on the Stress tests page: stress tests and on-demand tests without a page of their own.</summary>
    public bool OnStressPage => Kind != ModuleKind.Check && Page is null;
}

/// <summary>Stable group keys for built-in modules. A plugin may add its own key.</summary>
public static class ModuleGroups
{
    public const string Hardware = "hardware", Cpu = "cpu", Memory = "memory", Storage = "storage", Graphics = "graphics", Network = "network",
        Windows = "windows", Apps = "apps", Security = "security", Audio = "audio", Camera = "camera", Ai = "ai", Power = "power", Other = "other";

    private static readonly string[] Ranked = [Hardware, Cpu, Memory, Storage, Graphics, Network, Power, Windows, Apps, Audio, Camera, Ai, Security];

    /// <summary>Where a group sorts in lists (unknown keys last, as "Other").</summary>
    public static int Rank(string? key) => Array.IndexOf(Ranked, key) is var i and >= 0 ? i : Ranked.Length;

    /// <summary>English name for a group key; unknown keys are "Other".</summary>
    public static string DisplayName(string? key) => key switch
    {
        Hardware => "Hardware", Cpu => "Processor", Memory => "Memory", Storage => "Storage", Graphics => "Graphics", Network => "Network",
        Windows => "Windows", Apps => "Programs", Security => "Security", Audio => "Audio", Camera => "Camera", Ai => "AI accelerator",
        Power => "Power", _ => "Other",
    };
}
