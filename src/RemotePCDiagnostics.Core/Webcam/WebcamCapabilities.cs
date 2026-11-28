using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Webcam;

/// <summary>
/// What the camera offers, against what its name says it is. A camera sold as 1080p that only offers 640×480 is almost always running the
/// wrong (generic) driver or is plugged into a port that can't carry more.
/// </summary>
/// <param name="ExpectedWidth">The width its name implies (1280 for "HD"/720p, 1920 for "FHD"/1080p/2MP/5MP, 3840 for 4K/UHD), or null.</param>
/// <param name="ClassName">The words in the name that set <paramref name="ExpectedWidth"/>, for the message ("1080p").</param>
public sealed record WebcamCapabilityCheck(int MaxWidth, int MaxHeight, double MaxFps, int FormatCount, int? ExpectedWidth, string? ClassName)
{
    /// <summary>Offers clearly less than its class: its widest format is under 90% of the expected width.</summary>
    public bool BelowClass => ExpectedWidth is { } e && FormatCount > 0 && MaxWidth < e * 0.9;
}

public static class WebcamCapabilities
{
    /// <summary>The best format (largest, then fastest) and the class from the camera's name. IR cameras have no class.</summary>
    public static WebcamCapabilityCheck Assess(string deviceName, WebcamKind kind, IReadOnlyList<WebcamFormat> formats)
    {
        var best = formats.OrderByDescending(f => (long)f.Width * f.Height).ThenByDescending(f => f.Fps).FirstOrDefault();
        var (expected, name) = kind == WebcamKind.Infrared ? (null, null) : ClassOf(deviceName);
        return new WebcamCapabilityCheck(best?.Width ?? 0, best?.Height ?? 0, formats.Count == 0 ? 0 : Math.Round(formats.Max(f => f.Fps), 1),
            formats.Count, expected, name);
    }

    /// <summary>
    /// The resolution class a camera's name claims, from whole words in it ("HP 5MP Camera", "Integrated Webcam FHD", "Logitech BRIO 4K").
    /// "HD" alone is 720p. No match = null (most names say nothing).
    /// </summary>
    public static (int? Width, string? Name) ClassOf(string? deviceName)
    {
        var words = (deviceName ?? "").Split([' ', '-', '_', '(', ')', ',', '/', '.'], StringSplitOptions.RemoveEmptyEntries)
            .Select(w => w.ToUpperInvariant()).ToHashSet();
        if (words.Contains("4K") || words.Contains("UHD") || words.Contains("2160P")) return (3840, "4K");
        if (words.Contains("FHD") || words.Contains("1080P") || words.Contains("5MP") || words.Contains("2MP") || words.Contains("8MP")
            || (words.Contains("FULL") && words.Contains("HD")))
            return (1920, "1080p");
        if (words.Contains("720P") || words.Contains("HD")) return (1280, "720p");
        return (null, null);
    }

    /// <summary>Distinct formats, largest first, at most <paramref name="max"/> (a camera can list hundreds of combinations).</summary>
    public static IReadOnlyList<WebcamFormat> Distinct(IEnumerable<WebcamFormat> formats, int max = 64) =>
        formats.Where(f => f.Width > 0 && f.Height > 0)
            .Select(f => f with { Fps = Math.Round(f.Fps, 1), Subtype = f.Subtype?.ToUpperInvariant() })
            .Distinct()
            .OrderByDescending(f => (long)f.Width * f.Height).ThenByDescending(f => f.Fps).ThenBy(f => f.Subtype, StringComparer.Ordinal)
            .Take(max)
            .ToList();
}

public static class WebcamControls
{
    /// <summary>The controls read, in display order (names as Windows' VideoDeviceController has them).</summary>
    public static readonly IReadOnlyList<string> Names = ["Pan", "Tilt", "Zoom", "Focus", "Exposure", "Brightness", "Contrast", "WhiteBalance"];

    public static string Display(string name) => name == "WhiteBalance" ? "White balance" : name;

    /// <summary>The controls the driver says it has but couldn't read.</summary>
    public static IReadOnlyList<WebcamControl> Unreadable(IReadOnlyList<WebcamControl> controls) => controls.Where(c => c.Supported && c.ReadFailed).ToList();
}

/// <summary>An app Windows lists as using the camera right now (the camera privacy "recent activity" store).</summary>
/// <param name="App">What to show: the program file name, or the package name for a Store app.</param>
/// <param name="ProcessName">The process to close (no ".exe"), or null when it can't be told (a Store app).</param>
public sealed record WebcamHolder(string App, string? ProcessName, bool Packaged);

/// <summary>
/// Who holds the camera, from HKCU\...\CapabilityAccessManager\ConsentStore\webcam: a Store app has a subkey named after its package, a
/// desktop app one under NonPackaged named after its path ("C:#Program Files#…#Zoom.exe"). An app using the camera now has
/// LastUsedTimeStart set and LastUsedTimeStop 0 (or older than the start). The store is per Windows account and says "a camera", not which
/// one. Read through <see cref="IRegistrySource"/>, so it is recorded and replayed with the other registry reads.
/// </summary>
public static class WebcamHolders
{
    public const string ConsentPath = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam";
    private static readonly string[] Values = ["LastUsedTimeStart", "LastUsedTimeStop"];

    public static async Task<IReadOnlyList<WebcamHolder>> ReadAsync(IRegistrySource registry, string? ownProcessName, CancellationToken ct = default)
    {
        var packaged = await registry.ReadAsync(new RegistryRead(RegistryRoot.CurrentUser, ConsentPath, Values, SubKeys: true), ct).ConfigureAwait(false);
        var desktop = await registry.ReadAsync(new RegistryRead(RegistryRoot.CurrentUser, ConsentPath + @"\NonPackaged", Values, SubKeys: true), ct).ConfigureAwait(false);
        return From(packaged.Rows ?? [], desktop.Rows ?? [], ownProcessName);
    }

    /// <summary>The apps using the camera now, this app left out, most recent first.</summary>
    public static IReadOnlyList<WebcamHolder> From(IReadOnlyList<WmiRow> packaged, IReadOnlyList<WmiRow> desktop, string? ownProcessName)
    {
        var list = new List<(WebcamHolder Holder, long Start)>();
        foreach (var r in packaged)
        {
            var key = r.Str(RegistryRead.KeyColumn);
            if (key.Length == 0 || key.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase) || !InUse(r, out var start)) continue;
            // "Microsoft.WindowsCamera_8wekyb3d8bbwe": the part before the publisher hash.
            var cut = key.LastIndexOf('_');
            list.Add((new WebcamHolder(cut > 0 ? key[..cut] : key, null, true), start));
        }
        foreach (var r in desktop)
        {
            var key = r.Str(RegistryRead.KeyColumn);
            if (key.Length == 0 || !InUse(r, out var start)) continue;
            var file = key[(key.LastIndexOf('#') + 1)..];
            var process = Path.GetFileNameWithoutExtension(file);
            if (ownProcessName is { Length: > 0 } own && string.Equals(process, own, StringComparison.OrdinalIgnoreCase)) continue;
            list.Add((new WebcamHolder(file, Session.AgentScripts.IsProcessName(process) ? process : null, false), start));
        }
        return list.OrderByDescending(x => x.Start).Select(x => x.Holder).DistinctBy(h => h.App, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool InUse(WmiRow r, out long start)
    {
        start = r.Long("LastUsedTimeStart") ?? 0;
        var stop = r.Long("LastUsedTimeStop") ?? 0;
        return start > 0 && (stop == 0 || stop < start);
    }

    /// <summary>The holder this app can offer to close: a desktop app that isn't a protected Windows process.</summary>
    public static bool CanClose(WebcamHolder h) => h.ProcessName is { } p && !ProcessProtection.IsProtected(p);
}
