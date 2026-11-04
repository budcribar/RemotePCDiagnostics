namespace RemotePCDiagnostics.Agent.Core;

/// <summary>A folder under <c>%ProgramData%\RemotePCDiagnostics\app\</c> as seen on disk.</summary>
public sealed record CachedFolder(string Name, bool EntryExists, string? ZipRecord, string? EntryRecord);

/// <summary>
/// The verified-app cache: <c>app\&lt;version&gt;\</c> holds the extracted zip plus two records in <c>sha256sum</c> format,
/// <c>&lt;file&gt;.sha256</c> (the manifest's SHA-256 of the zip it came from) and <c>&lt;entry&gt;.sha256</c> (the program's own hash, checked again
/// before every launch). Only one version is kept.
/// </summary>
public static class AppCache
{
    public const string StagingSuffix = ".partial";
    public const string DownloadFileName = "download.tmp";

    public static string RecordFileName(string fileName) => fileName + ".sha256";

    /// <summary><c>"&lt;hash&gt; *&lt;name&gt;"</c>, the binary-mode sha256sum line.</summary>
    public static string FormatRecord(string sha256Hex, string fileName) => sha256Hex.ToLowerInvariant() + " *" + fileName + "\n";

    /// <summary>The hash in a record written by <see cref="FormatRecord"/> (or plain sha256sum output) for <paramref name="fileName"/>; null when it doesn't parse.</summary>
    public static string? ParseRecord(string? text, string fileName)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var line = text.Trim();
        var space = line.IndexOf(' ');
        if (space != 64) return null;
        var hash = line[..64];
        var name = line[65..].TrimStart('*', ' ');
        if (!ReleaseManifest.IsSha256Hex(hash) || !string.Equals(name, fileName, StringComparison.OrdinalIgnoreCase)) return null;
        return hash.ToLowerInvariant();
    }

    /// <summary>True when <paramref name="folder"/> holds exactly the manifest's verified release (same version and zip SHA-256, program present
    /// with a recorded hash). The program's hash itself is checked before launch.</summary>
    public static bool IsUsable(ReleaseManifest manifest, CachedFolder? folder) =>
        folder is not null
        && string.Equals(folder.Name, manifest.Version, StringComparison.OrdinalIgnoreCase)
        && folder.EntryExists
        && ParseRecord(folder.ZipRecord, manifest.File) == manifest.Sha256.ToLowerInvariant()
        && ParseRecord(folder.EntryRecord, manifest.Entry) is not null;

    /// <summary>Folders to delete once <paramref name="keepVersion"/> is in place (older versions, staging folders); "keep one".</summary>
    public static IReadOnlyList<string> FoldersToDelete(IEnumerable<string> folderNames, string keepVersion) =>
        folderNames.Where(n => !string.Equals(n, keepVersion, StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>The cached version to report in AgentHello/Heartbeat: the highest valid-looking version folder with both records; "" when none.</summary>
    public static string PickCachedVersion(IEnumerable<CachedFolder> folders) =>
        folders.Where(f => ReleaseManifest.IsSafeVersion(f.Name) && f.EntryExists && f.ZipRecord is not null && f.EntryRecord is not null)
               .Select(f => f.Name)
               .OrderByDescending(n => n, Comparer<string>.Create(CompareVersions))
               .FirstOrDefault() ?? "";

    /// <summary>Compares the numeric parts, then the suffix ("1.10.0" &gt; "1.9.0"; "1.2.0" &gt; "1.2.0-beta").</summary>
    public static int CompareVersions(string a, string b)
    {
        static (long[] Nums, string Suffix) Split(string v)
        {
            var cut = v.IndexOfAny(['-', '+']);
            var core = cut < 0 ? v : v[..cut];
            var nums = core.Split('.').Select(p => long.TryParse(p, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : 0).ToArray();
            return (nums, cut < 0 ? "" : v[cut..]);
        }
        var (an, asfx) = Split(a);
        var (bn, bsfx) = Split(b);
        for (var i = 0; i < Math.Max(an.Length, bn.Length); i++)
        {
            var c = (i < an.Length ? an[i] : 0).CompareTo(i < bn.Length ? bn[i] : 0);
            if (c != 0) return c;
        }
        if (asfx.Length == 0 && bsfx.Length > 0) return 1;
        if (bsfx.Length == 0 && asfx.Length > 0) return -1;
        return string.CompareOrdinal(asfx, bsfx);
    }

    /// <summary>"45 of 129 MB" style progress text and percent.</summary>
    public static (string Text, int Percent) Progress(long done, long total)
    {
        const double Mb = 1024 * 1024;
        var pct = total <= 0 ? 0 : (int)Math.Clamp(done * 100 / total, 0, 100);
        return ($"Downloading {done / Mb:0} of {total / Mb:0} MB", pct);
    }
}
