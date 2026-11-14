using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>Where a module that ships with the app runs, as chosen on the About page.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ModuleProcessMode
{
    /// <summary>What the module's module.json says ("outOfProcess").</summary>
    Default,
    /// <summary>In the app process.</summary>
    InProcess,
    /// <summary>In RemotePCDiagnostics.ModuleHost: with a restricted, Medium-integrity token, or with the app's own token for a module that
    /// needs administrator (crash and memory isolation only).</summary>
    OutOfProcess,
}

/// <summary>
/// How one module is hosted, decided once at startup from its manifest and the process-mode setting. The module page lays itself out from
/// this, the same way in either process, so switching modes needs no code or page changes.
/// </summary>
public sealed record ModuleHosting
{
    /// <summary>The module's check runs in the module host, not the app.</summary>
    public bool OutOfProcess { get; init; }
    /// <summary>Out of process with the app's own token (the module needs administrator).</summary>
    public bool Elevated { get; init; }
    /// <summary>What the setting asked for.</summary>
    public ModuleProcessMode Requested { get; init; }
    /// <summary>Null when the module can run either way; otherwise why it stays in the app.</summary>
    public string? InProcessOnly { get; init; }
    /// <summary>The module sets its own details UI.</summary>
    public bool HasUi { get; init; }
    /// <summary>Its details UI can render in the module UI host (<see cref="ModuleManifest.PortableUi"/>).</summary>
    public bool PortableUi { get; init; }
    /// <summary>Its details UI isn't portable but renders in the app from the module's results alone (<see cref="ModuleManifest.ResultOnlyUi"/>).</summary>
    public bool ResultOnlyUi { get; init; }
    /// <summary>Its details UI replaces the generic report instead of sitting above it (<see cref="ModuleManifest.DetailsReplaceReport"/>).</summary>
    public bool DetailsReplaceReport { get; init; }

    public bool CanRunOutOfProcess => InProcessOnly is null;

    /// <summary>Shown on the About page.</summary>
    public string Describe() => OutOfProcess ? (Elevated ? "Out of process (administrator)" : "Out of process (user mode)") : "In process";

    /// <summary>Where a module that ships with the app runs for <paramref name="requested"/>.</summary>
    public static ModuleHosting For(ModuleManifest manifest, ModuleProcessMode requested)
    {
        var wantOut = requested switch
        {
            ModuleProcessMode.InProcess => false,
            ModuleProcessMode.OutOfProcess => true,
            _ => manifest.OutOfProcess,
        };
        var inProcessOnly = string.IsNullOrWhiteSpace(manifest.InProcessOnly) ? null : manifest.InProcessOnly;
        var outOfProcess = wantOut && inProcessOnly is null;
        return new ModuleHosting
        {
            OutOfProcess = outOfProcess, Elevated = outOfProcess && manifest.NeedsAdmin, Requested = requested, InProcessOnly = inProcessOnly,
            HasUi = manifest.HasUi, PortableUi = manifest.PortableUi, DetailsReplaceReport = manifest.DetailsReplaceReport, ResultOnlyUi = manifest.ResultOnlyUi,
        };
    }

    /// <summary>An unsigned plugin: always out of process in user mode, its UI always in the module UI host.</summary>
    public static ModuleHosting Unsigned(ModuleManifest manifest) => new()
    {
        OutOfProcess = true, HasUi = manifest.HasUi, PortableUi = true, DetailsReplaceReport = manifest.DetailsReplaceReport,
        InProcessOnly = null, Requested = ModuleProcessMode.OutOfProcess,
    };

    /// <summary>A signed plugin: in the app.</summary>
    public static ModuleHosting Signed(ModuleManifest manifest) => new()
    {
        HasUi = manifest.HasUi, PortableUi = manifest.PortableUi, DetailsReplaceReport = manifest.DetailsReplaceReport,
        InProcessOnly = "signed plugins run in the app", Requested = ModuleProcessMode.InProcess,
    };
}

/// <summary>
/// The process-mode switch: process-mode.json in the admin-only modules folder (next to the unsigned-modules marker), so only an elevated
/// app at the PC can change it. One mode for all modules that ship with the app, plus per-module overrides by slug. Takes effect at the next
/// start.
/// </summary>
public sealed record ModuleProcessModeSetting
{
    public const string FileName = "process-mode.json";

    /// <summary>The mode for every module without its own entry.</summary>
    public ModuleProcessMode All { get; init; } = ModuleProcessMode.Default;
    /// <summary>Per-module modes by slug (case-insensitive).</summary>
    public Dictionary<string, ModuleProcessMode> Modules { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public ModuleProcessMode For(string slug) =>
        Modules.TryGetValue(slug, out var m) && m != ModuleProcessMode.Default ? m : All;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true, WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true, Converters = { new JsonStringEnumConverter() },
    };

    public static string PathIn(string? modulesFolder = null) => Path.Combine(modulesFolder ?? ModuleLoaderOptions.DefaultModulesFolder(), FileName);

    public static void PurgeLegacySetting(string? modulesFolder = null)
    {
        try
        {
            var path = PathIn(modulesFolder);
            if (File.Exists(path)) File.Delete(path);
        }
        catch { }
    }

    /// <summary>The saved setting; the default (every module as its module.json says) when there is none or it can't be read.</summary>
    public static ModuleProcessModeSetting Read(string? modulesFolder = null)
    {
        try
        {
            var path = PathIn(modulesFolder);
            if (!File.Exists(path)) return new();
            var s = JsonSerializer.Deserialize<ModuleProcessModeSetting>(File.ReadAllBytes(path), Json) ?? new();
            return s with { Modules = new Dictionary<string, ModuleProcessMode>(s.Modules ?? [], StringComparer.OrdinalIgnoreCase) };
        }
        catch { return new(); }
    }

    /// <summary>Saves the setting (takes effect at the next start). Throws when the folder isn't writable (not elevated).</summary>
    public void Save(string? modulesFolder = null)
    {
        var path = PathIn(modulesFolder);
        var pruned = this with { Modules = Modules.Where(kv => kv.Value != ModuleProcessMode.Default).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase) };
        if (pruned.All == ModuleProcessMode.Default && pruned.Modules.Count == 0) { if (File.Exists(path)) File.Delete(path); return; }
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(pruned, Json));
    }

    /// <summary>This setting with <paramref name="slug"/> set to <paramref name="mode"/> (Default removes its entry).</summary>
    public ModuleProcessModeSetting With(string slug, ModuleProcessMode mode)
    {
        var modules = new Dictionary<string, ModuleProcessMode>(Modules, StringComparer.OrdinalIgnoreCase);
        if (mode == ModuleProcessMode.Default) modules.Remove(slug); else modules[slug] = mode;
        return this with { Modules = modules };
    }
}

/// <summary>Where a module's own details UI shows on its page.</summary>
public enum ModuleOwnUi { None, InApp, Frame }

/// <summary>
/// The module page's layout (ModuleDetailsView): the module's own UI, in the app or framed from the module UI host, above the generic report
/// or instead of it. Decided from the manifest, so a module looks the same in and out of process; the only difference is where its UI
/// renders, and a note when it can't render out of process.
/// </summary>
public sealed record ModulePageLayout(ModuleOwnUi OwnUi, bool ShowReport, string? Notice = null)
{
    public const string NeedsAppProcess =
        "it needs the app process, and this module now runs out of process. Switch it back to in process on the About page to see it.";
    public const string NoFrameHost = "module pages that run out of process can't be shown in this session yet.";

    /// <param name="hosting">The module's hosting; null for a module compiled into the app (its page is the whole view).</param>
    /// <param name="outOfProcess">The app holds an out-of-process stand-in for the module.</param>
    /// <param name="bundled">Ships with the app (only then can a UI need the app process; an unsigned plugin's UI always runs in the UI host).</param>
    /// <param name="hasDetails">In process: the module set a details component. Out of process: its manifest says hasUi.</param>
    /// <param name="frameHost">This session can frame a module UI host.</param>
    public static ModulePageLayout For(ModuleHosting? hosting, bool outOfProcess, bool bundled, bool hasDetails, bool frameHost)
    {
        var replaces = hosting is null || hosting.DetailsReplaceReport;
        if (!hasDetails) return new(ModuleOwnUi.None, true);
        if (!outOfProcess) return new(ModuleOwnUi.InApp, !replaces);
        // The app's own code, reading only the stand-in's results: rendered in the app, as in process.
        if (bundled && hosting is { PortableUi: false, ResultOnlyUi: true }) return new(ModuleOwnUi.InApp, !replaces);
        if (bundled && hosting is { PortableUi: false }) return new(ModuleOwnUi.None, true, NeedsAppProcess);
        if (!frameHost) return new(ModuleOwnUi.None, true, NoFrameHost);
        return new(ModuleOwnUi.Frame, !replaces);
    }
}
