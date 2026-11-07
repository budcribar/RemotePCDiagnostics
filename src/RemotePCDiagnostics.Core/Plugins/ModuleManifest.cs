using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// The module.json embedded in a module DLL: everything the host needs before any of the module's code runs. One DLL is one module, so
/// the manifest describes exactly one id.
/// </summary>
public sealed record ModuleManifest
{
    public const string ResourceName = "module.json";

    public Guid Id { get; init; }
    public string Slug { get; init; } = "";
    public string DisplayName { get; init; } = "";
    /// <summary>The plugin's own version (shown on the About page).</summary>
    public string Version { get; init; } = "1.0.0";
    /// <summary>The contract version the plugin was built against ("1.0").</summary>
    public string Contract { get; init; } = "2.0";
    /// <summary>The lowest app version the plugin needs, for behaviour the contract version doesn't capture.</summary>
    public string? MinHost { get; init; }
    /// <summary>Full name of the <see cref="IModulePlugin"/> type.</summary>
    public string EntryType { get; init; } = "";
    public ModuleKind Kind { get; init; } = ModuleKind.Check;
    public string Group { get; init; } = ModuleGroups.Other;
    public int Order { get; init; } = 10_000;
    public List<Guid> DependsOn { get; init; } = [];
    public List<Guid> RunAfter { get; init; } = [];
    /// <summary>The module changes the PC (through the host's change journal). Shown in the UI; an unsigned module with this set is disabled.</summary>
    public bool ChangesSystem { get; init; }
    /// <summary>The module needs administrator (SFC, DISM, SMART, sensors): it must be signed to run.</summary>
    public bool NeedsAdmin { get; init; }
    /// <summary>The module sets its own details UI (<see cref="IPluginContext.SetDetailsComponent"/>). An unsigned module's UI then runs in
    /// its own user-mode process and is shown on the module page in a sandboxed frame.</summary>
    public bool HasUi { get; init; }
    /// <summary>Only for a module that ships with the app (builtin-modules\): its check runs in its own user-mode process
    /// (RemotePCDiagnostics.ModuleHost, restricted token) instead of the app process, and its details UI, if it has one, in the module UI
    /// host, framed on the module page like an unsigned module's. Unlike an unsigned module it keeps its one-click fixes, which the app runs.
    /// A plugin's value is ignored: signed plugins run in the app, unsigned ones always out of process.</summary>
    public bool OutOfProcess { get; init; }
    /// <summary>Only for a module that ships with the app: why it can't run out of process (it uses services only the app process has,
    /// such as the hardware monitor driver or the app's audio and GPU adapters). Set: the process-mode switch keeps it in the app and
    /// shows this reason. Null: it can run either way.</summary>
    public string? InProcessOnly { get; init; }
    /// <summary>A module that ships with the app whose own UI isn't portable but reads only the module's results (no app services): out
    /// of process the app still renders it, from the stand-in's results, so the page is the same in either process.</summary>
    public bool ResultOnlyUi { get; init; }
    /// <summary>The host queries (<see cref="HostCapabilities"/>) the module asks the app for when it runs in user mode. The app answers
    /// nothing that isn't listed here, and only for a module that ships with the app.</summary>
    public List<string> Capabilities { get; init; } = [];
    /// <summary>The module's details UI already shows its results, so the module page shows it instead of the generic report. False (the
    /// default): the details UI is shown above the generic report. The same in and out of process, so switching modes never changes the
    /// page.</summary>
    public bool DetailsReplaceReport { get; init; }
    /// <summary>The module's details UI uses only Components, Abstractions and Core types and styles itself (no app UI assembly, no app
    /// services), so it can render in the module UI host when the module runs out of process. Out of process without it, the module page
    /// shows the generic report and says why. An unsigned plugin's UI always runs in the UI host.</summary>
    public bool PortableUi { get; init; }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static ModuleManifest Parse(ReadOnlySpan<byte> json) => JsonSerializer.Deserialize<ModuleManifest>(json, Json)
        ?? throw new InvalidDataException("module.json is empty");

    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions(Json) { WriteIndented = true });

    /// <summary>The problem with this manifest for this host, or null when it can load.</summary>
    /// <param name="vendorSlug">The slug must be vendor.name (every plugin). A module that ships with the app keeps the slug it always had.</param>
    public string? Problem(Version hostVersion, bool vendorSlug = true)
    {
        if (Id == Guid.Empty) return "module.json has no id";
        if (string.IsNullOrWhiteSpace(Slug)) return "module.json has no slug";
        if (vendorSlug && !Slug.Contains('.')) return $"slug '{Slug}' must be vendor.name";
        if (string.IsNullOrWhiteSpace(EntryType)) return "module.json has no entryType";
        if (!System.Version.TryParse(Contract.Count(c => c == '.') == 0 ? Contract + ".0" : Contract, out var contract)) return $"contract '{Contract}' is not a version";
        if (!ContractVersion.IsCompatible(contract))
            return $"built for contract {Contract}, this app implements {ContractVersion.Current.ToString(2)}";
        if (MinHost is { Length: > 0 } min && System.Version.TryParse(min, out var minHost) && minHost > hostVersion)
            return $"needs app version {MinHost} or later";
        if ((Capabilities ?? []).FirstOrDefault(c => !HostCapabilities.All.Contains(c)) is { } unknown) return $"unknown capability '{unknown}'";
        return null;
    }

    /// <summary>The catalog descriptor for this module.</summary>
    public ModuleDescriptor ToDescriptor(string pluginId) =>
        new(Id, Slug, string.IsNullOrWhiteSpace(DisplayName) ? Slug : DisplayName, Kind, Group, Order)
        {
            Source = ModuleSource.Plugin, PluginId = pluginId, DependsOn = DependsOn, RunAfter = RunAfter,
        };

    /// <summary>Reads module.json (and strings/*.json) from the DLL's embedded resources without loading or running it.</summary>
    public static (ModuleManifest Manifest, IReadOnlyDictionary<string, byte[]> Strings) ReadFromAssembly(byte[] dll)
    {
        using var pe = new PEReader(new MemoryStream(dll, writable: false));
        if (!pe.HasMetadata) throw new InvalidDataException("not a .NET assembly");
        var md = pe.GetMetadataReader();
        byte[]? manifest = null;
        var strings = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in md.ManifestResources)
        {
            var res = md.GetManifestResource(h);
            if (!res.Implementation.IsNil) continue; // linked or in another assembly
            var name = md.GetString(res.Name);
            if (name.Equals(ResourceName, StringComparison.OrdinalIgnoreCase) || name.EndsWith("." + ResourceName, StringComparison.OrdinalIgnoreCase))
                manifest = ReadResource(pe, res.Offset);
            else if (name.StartsWith("strings/", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                strings[name["strings/".Length..]] = ReadResource(pe, res.Offset);
        }
        if (manifest is null) throw new InvalidDataException("no embedded module.json");
        return (Parse(manifest), strings);
    }

    private static byte[] ReadResource(PEReader pe, long offset)
    {
        if (pe.PEHeaders.CorHeader is not { } cor || !pe.PEHeaders.TryGetDirectoryOffset(cor.ResourcesDirectory, out var start))
            throw new InvalidDataException("no resources directory");
        var image = pe.GetEntireImage().GetContent();
        if (offset < 0 || start < 0 || offset > image.Length - start - 4) throw new InvalidDataException("invalid resource offset");
        var at = start + (int)offset;
        var length = BitConverter.ToInt32(image.AsSpan(at, 4));
        if (length < 0 || length > image.Length - (at + 4)) throw new InvalidDataException("invalid resource length");
        return image.AsSpan(at + 4, length).ToArray();
    }
}
