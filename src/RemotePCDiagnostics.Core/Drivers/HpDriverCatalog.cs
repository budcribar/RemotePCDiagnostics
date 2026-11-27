using System.Globalization;
using System.Net;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Core.Drivers;

/// <summary>
/// HP's per-model reference catalog (the one HP Image Assistant reads, at
/// <c>hpia.hpcloud.hp.com/ref/{id}/{id}_64_11.0.{release}.cab</c>). Its entries carry no hardware IDs, so each driver or firmware
/// SoftPaq is matched by the files it installs: the catalog names each file with its folder and version for every Windows release,
/// and a file on this PC with a lower version means HP has a newer package. A SoftPaq none of whose files is on the PC doesn't apply.
/// BIOS (the BIOS check covers it), docks, software and driver packs are left out.
/// </summary>
public sealed class HpDriverCatalog(HttpClient? http = null, SystemCommandRunner? commands = null, string? catalogUrlTemplate = null) : IVendorDriverCatalog
{
    public const string DefaultCatalogUrlTemplate = "https://hpia.hpcloud.hp.com/ref/{id}/{id}_{arch}_{os}.cab";
    private const long MaxCatalogBytes = 64L * 1024 * 1024;

    private readonly HttpClient _http = http ?? BiosProviderHttp.SharedClient;
    private readonly string _template = string.IsNullOrWhiteSpace(catalogUrlTemplate) ? DefaultCatalogUrlTemplate : catalogUrlTemplate;

    public string Vendor => "HP";

    public bool CanHandle(BiosSystemIdentity system) => BiosVendorIdentity.IsHp(system) && HpBiosUpdateProvider.TryExtractSystemId(system, out _);

    public async Task<VendorDriverScan> ScanAsync(BiosSystemIdentity system, IDriverInventory pc, CancellationToken ct)
    {
        if (!HpBiosUpdateProvider.TryExtractSystemId(system, out var systemId))
            return VendorDriverScan.Failed(Vendor, "This HP PC doesn't report its 4-character system ID.");
        var release = (await pc.ReadDisplayVersionAsync(ct).ConfigureAwait(false)).Trim().ToUpperInvariant();
        var arm64 = system.Architecture.Contains("arm64", StringComparison.OrdinalIgnoreCase);
        var win11 = BiosVendorIdentity.IsWindows11(system.OsVersion);

        string? xml = null;
        var usedRelease = "";
        try
        {
            foreach (var (url, rel) in CatalogCandidates(_template, systemId, release, arm64, win11))
            {
                using var response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(_http, url, HpBiosUpdateProvider.AllowedHostSuffixes,
                    HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden) continue;
                if (!response.IsSuccessStatusCode) return VendorDriverScan.Failed(Vendor, $"HP's catalog answered {(int)response.StatusCode}.");
                var payload = await BiosProviderHttp.ReadBoundedBytesAsync(response.Content, MaxCatalogBytes, "HP driver catalog", ct).ConfigureAwait(false);
                xml = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(payload, $"hp-drivers-{systemId}", commands, ct, MaxCatalogBytes).ConfigureAwait(false);
                usedRelease = rel;
                break;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return VendorDriverScan.Failed(Vendor, "Couldn't reach HP's driver catalog."); }

        if (usedRelease.Length == 0) return VendorDriverScan.Failed(Vendor, $"HP has no driver catalog for this model (system ID {systemId}).");
        if (string.IsNullOrWhiteSpace(xml)) return VendorDriverScan.Failed(Vendor, "HP's driver catalog couldn't be read.");

        var doc = BiosArchiveAndXml.ParseXmlSafe(xml);
        var (updates, compared) = Evaluate(doc, OsTags(release, usedRelease, arm64, win11), pc.ReadFileVersion);
        return new(Vendor, updates, compared);
    }

    /// <summary>
    /// The catalogs to try, this PC's Windows release first, then newer, then older ones (HP's folders are lower case, and a model that
    /// shipped later has no catalogs for older releases).
    /// </summary>
    public static IReadOnlyList<(string Url, string Release)> CatalogCandidates(string template, string systemId, string release, bool arm64, bool win11)
    {
        string[] known = win11 ? ["26H2", "25H2", "24H2", "23H2", "22H2", "21H2"] : ["22H2", "21H2"];
        var order = new List<string>();
        var at = Array.IndexOf(known, release);
        if (at >= 0)
        {
            order.Add(known[at]);
            for (var i = at - 1; i >= 0; i--) order.Add(known[i]); // newer
            for (var i = at + 1; i < known.Length; i++) order.Add(known[i]); // older
        }
        else order.AddRange(known);

        var os = win11 ? "11.0" : "10.0";
        var id = systemId.ToLowerInvariant();
        return order.Select(r => (template.Replace("{id}", id, StringComparison.Ordinal).Replace("{arch}", arm64 ? "arm64" : "64", StringComparison.Ordinal)
            .Replace("{os}", $"{os}.{r.ToLowerInvariant()}", StringComparison.Ordinal), r)).ToList();
    }

    /// <summary>The OS names of the catalog's file lists to use, best first: this PC's release, then the catalog's ("W11_23H2", "W11A_24H2").</summary>
    public static IReadOnlyList<string> OsTags(string release, string catalogRelease, bool arm64, bool win11)
    {
        var prefix = win11 ? arm64 ? "W11A_" : "W11_" : "WT64_";
        return new[] { release, catalogRelease }.Where(r => r.Length > 0).Select(r => prefix + r.ToUpperInvariant()).Distinct().ToList();
    }

    /// <summary>Compares each current driver or firmware SoftPaq with the PC's files: the newer ones, and how many applied to this PC.</summary>
    public static (IReadOnlyList<VendorDriverUpdate> Updates, int Compared) Evaluate(XDocument doc, IReadOnlyList<string> osTags, Func<string, Version?> fileVersion)
    {
        var root = doc.Root;
        var solutions = root?.Elements().FirstOrDefault(e => e.Name.LocalName == "Solutions");
        if (root is null || solutions is null) return ([], 0);

        // A current entry can be a reference to an entry written elsewhere in the catalog.
        var byId = root.Descendants().Where(e => e.Name.LocalName == "UpdateInfo" && Child(e, "Id") is { Length: > 0 })
            .GroupBy(e => Child(e, "Id")!, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var updates = new List<VendorDriverUpdate>();
        var compared = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in solutions.Elements().Where(e => e.Name.LocalName == "UpdateInfo"))
        {
            var entry = raw.Attribute("IdRef")?.Value is { Length: > 0 } idRef && byId.TryGetValue(idRef, out var target) ? target : raw;
            var id = Child(entry, "Id") ?? "";
            if (id.Length == 0 || !seen.Add(id)) continue;
            var category = Child(entry, "Category") ?? "";
            if (!IsDriverCategory(category)) continue;

            var files = FilesFor(entry, osTags);
            if (files.Count == 0) continue;
            // The first of its files found on the PC decides: a SoftPaq's files are the same driver, and a file it doesn't update isn't listed.
            Version? oldest = null;
            Version? newVersion = null;
            foreach (var (path, version) in files)
            {
                if (fileVersion(path) is not { } found) continue;
                compared++;
                var installed = DriverVersion.Normalize(found);
                if (installed < version) (oldest, newVersion) = (installed, version);
                break;
            }
            if (oldest is null || newVersion is null) continue;

            var url = HttpsUrl(Child(entry, "Url"));
            if (url is null) continue;
            updates.Add(new(
                Title: Child(entry, "Name") ?? id,
                Category: category,
                InstalledVersion: DriverVersion.Format(oldest),
                // Both file versions, so they compare like for like (the SoftPaq's own version can count differently).
                AvailableVersion: DriverVersion.Format(newVersion),
                Released: DateOnly.TryParse(Child(entry, "DateReleased"), CultureInfo.InvariantCulture, out var d) ? d : null,
                DownloadUrl: url,
                DetailsUrl: HttpsUrl(Child(entry, "ReleaseNotesUrl")),
                SizeBytes: long.TryParse(Child(entry, "Size"), NumberStyles.None, CultureInfo.InvariantCulture, out var size) ? size : 0,
                PackageId: id));
        }
        return (updates, compared);
    }

    /// <summary>Drivers and firmware; BIOS has its own check, docks report their own firmware, and driver packs repeat the drivers.</summary>
    public static bool IsDriverCategory(string category) =>
        category.StartsWith("Driver", StringComparison.OrdinalIgnoreCase) || category.Equals("Firmware", StringComparison.OrdinalIgnoreCase);

    /// <summary>The SoftPaq's files for the first of <paramref name="osTags"/> it lists, as Windows paths with their catalog versions.</summary>
    private static List<(string Path, Version Version)> FilesFor(XElement entry, IReadOnlyList<string> osTags)
    {
        var details = entry.Elements().FirstOrDefault(e => e.Name.LocalName == "DetailFileInformation")?.Elements()
            .Where(e => e.Name.LocalName == "FileDetail").ToList() ?? [];
        foreach (var tag in osTags)
        {
            var files = new List<(string, Version)>();
            foreach (var f in details.Where(f => string.Equals(Child(f, "OS"), tag, StringComparison.OrdinalIgnoreCase)))
            {
                var name = Child(f, "FileName");
                var version = DriverVersion.Parse(Child(f, "Version"));
                var dir = WindowsDirectory(Child(f, "Directory"));
                if (name is null || version is null || dir is null || name.IndexOfAny(['\\', '/', '*']) >= 0) continue;
                files.Add((dir.TrimEnd('\\') + "\\" + name, version));
            }
            if (files.Count > 0) return files;
        }
        return [];
    }

    private static readonly (string Token, string Folder)[] Tokens =
    [
        ("<DRIVERS>", @"%SystemRoot%\System32\drivers"),
        ("<WINSYSDIR>", @"%SystemRoot%\System32"),
        ("<WINDIR>", "%SystemRoot%"),
        ("<PROGRAMFILESDIRX86>", "%ProgramFiles(x86)%"),
        ("<PROGRAMFILESDIR>", "%ProgramFiles%"),
        ("<PROGRAMFILES>", "%ProgramFiles%"),
        ("<WINSYSDISK>", "%SystemDrive%"),
    ];

    /// <summary>
    /// The catalog's folder ("&lt;WINSYSDIR&gt;\DriverStore\FileRepository\ish.inf_amd64_e0c5…") as a Windows path, with the driver store's
    /// per-build hash as a wildcard (it differs on every PC). Null for a folder token this doesn't know.
    /// </summary>
    public static string? WindowsDirectory(string? catalogDir)
    {
        if (string.IsNullOrWhiteSpace(catalogDir)) return null;
        var dir = catalogDir.Trim().Replace('/', '\\');
        if (!dir.StartsWith('<')) return null;
        var close = dir.IndexOf('>');
        if (close < 0) return null;
        var token = dir[..(close + 1)];
        var folder = Tokens.FirstOrDefault(t => t.Token.Equals(token, StringComparison.OrdinalIgnoreCase)).Folder;
        if (folder is null) return null;
        var segments = dir[(close + 1)..].Split('\\', StringSplitOptions.RemoveEmptyEntries).ToList();
        if (segments.Any(s => s is "." or ".." || s.Contains('%') || s.Contains('*'))) return null;
        var repo = segments.FindIndex(s => s.Equals("FileRepository", StringComparison.OrdinalIgnoreCase));
        if (repo >= 0 && repo + 1 < segments.Count)
        {
            // "ish.inf_amd64_e0c5ebcbfde15d36" → "ish.inf_amd64_*"
            var s = segments[repo + 1];
            var cut = s.LastIndexOf('_');
            if (cut > 0) segments[repo + 1] = s[..(cut + 1)] + "*";
        }
        return segments.Count == 0 ? folder : folder + "\\" + string.Join('\\', segments);
    }

    /// <summary>HP writes "ftp.hp.com/pub/softpaq/…": an https URL on hp.com, or null.</summary>
    public static string? HttpsUrl(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim();
        if (!s.Contains("://", StringComparison.Ordinal)) s = "https://" + s;
        if (s.Contains('\\') || BiosProviderHttp.HasUnsafePathSegments(s, rejectAtSign: true)) return null;
        return BiosProviderHttp.TryValidateHttpsUrl(s, HpBiosUpdateProvider.AllowedHostSuffixes, out var uri, out _) ? uri.AbsoluteUri : null;
    }

    private static string? Child(XElement e, string name) =>
        e.Elements().FirstOrDefault(c => c.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value.Trim() is { Length: > 0 } v ? v : null;
}
