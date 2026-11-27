using System.Globalization;
using System.Net;
using System.Text;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Core.Drivers;

/// <summary>
/// Lenovo's per-model catalog (the one Lenovo System Update and Vantage read, at <c>download.lenovo.com/catalog/{MTM}_Win11.xml</c>).
/// It lists one descriptor per package, and a driver's descriptor says how to tell it's installed: a hardware ID and the lowest driver
/// version that counts (<c>&lt;_Driver&gt;&lt;HardwareID&gt;PCI\VEN_10EC&amp;DEV_8168&lt;/HardwareID&gt;&lt;Version&gt;10.50^&lt;/Version&gt;</c>).
/// A device with that hardware ID and a lower driver version means Lenovo has a newer package. BIOS is left to the BIOS check.
/// </summary>
public sealed class LenovoDriverCatalog(HttpClient? http = null, string? catalogBaseUrl = null) : IVendorDriverCatalog
{
    public const string DefaultCatalogBaseUrl = "https://download.lenovo.com/catalog";
    private const long MaxXmlBytes = 16L * 1024 * 1024;
    private const int MaxDescriptors = 120;
    private const int ParallelFetches = 4;

    private readonly HttpClient _http = http ?? BiosProviderHttp.SharedClient;
    private readonly string _base = (string.IsNullOrWhiteSpace(catalogBaseUrl) ? DefaultCatalogBaseUrl : catalogBaseUrl).TrimEnd('/');

    public string Vendor => "Lenovo";

    public bool CanHandle(BiosSystemIdentity system) => BiosVendorIdentity.IsLenovo(system) && BiosVendorIdentity.TryExtractLenovoMtm(system, out _);

    public async Task<VendorDriverScan> ScanAsync(BiosSystemIdentity system, IDriverInventory pc, CancellationToken ct)
    {
        if (!BiosVendorIdentity.TryExtractLenovoMtm(system, out var mtm))
            return VendorDriverScan.Failed(Vendor, "This Lenovo PC doesn't report its machine type.");
        var drivers = await pc.ReadDriversAsync(ct).ConfigureAwait(false);
        if (drivers is null) return VendorDriverScan.Failed(Vendor, "Couldn't read this PC's drivers to compare with Lenovo's catalog.");

        var os = BiosVendorIdentity.IsWindows11(system.OsVersion) ? "Win11" : "Win10";
        IReadOnlyList<(string Url, string Category)> packages;
        try
        {
            var index = await GetXmlAsync($"{_base}/{mtm}_{os}.xml", ct).ConfigureAwait(false);
            if (index is null) return VendorDriverScan.Failed(Vendor, $"Lenovo has no driver catalog for this model (machine type {mtm}).");
            packages = ParseIndex(index);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return VendorDriverScan.Failed(Vendor, "Couldn't reach Lenovo's driver catalog."); }

        using var gate = new SemaphoreSlim(ParallelFetches);
        var unread = 0;
        var results = await Task.WhenAll(packages.Take(MaxDescriptors).Select(async p =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var descriptor = await GetXmlAsync(p.Url, ct).ConfigureAwait(false);
                return descriptor is null ? null : Evaluate(descriptor, new Uri(p.Url), p.Category, drivers);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception)
            {
                Interlocked.Increment(ref unread);
                return null;
            }
            finally { gate.Release(); }
        })).ConfigureAwait(false);

        var compared = results.Count(r => r is not null && r.Value.Compared);
        var updates = results.Where(r => r?.Update is not null).Select(r => r!.Value.Update!).ToList();
        return new(Vendor, updates, compared, unread > 0 && compared == 0 ? "Couldn't read Lenovo's package descriptions." : null);
    }

    private async Task<XDocument?> GetXmlAsync(string url, CancellationToken ct)
    {
        using var response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(_http, url, LenovoBiosUpdateProvider.AllowedHostSuffixes,
            HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        var bytes = await BiosProviderHttp.ReadBoundedBytesAsync(response.Content, MaxXmlBytes, "Lenovo driver catalog", ct).ConfigureAwait(false);
        return BiosArchiveAndXml.ParseXmlSafe(Encoding.UTF8.GetString(bytes));
    }

    /// <summary>The descriptor URLs and categories in the model's index, without BIOS (the BIOS check covers it).</summary>
    public static IReadOnlyList<(string Url, string Category)> ParseIndex(XDocument index)
    {
        var list = new List<(string, string)>();
        foreach (var p in index.Descendants().Where(e => e.Name.LocalName.Equals("package", StringComparison.OrdinalIgnoreCase)))
        {
            var category = Child(p, "category") ?? "";
            if (category.Contains("BIOS", StringComparison.OrdinalIgnoreCase) || category.Contains("UEFI", StringComparison.OrdinalIgnoreCase)) continue;
            if (SafeUrl(Child(p, "location")) is { } url) list.Add((url, category));
        }
        return list;
    }

    /// <summary>
    /// One descriptor against the PC's drivers: <c>Compared</c> when one of its devices is on the PC, and the update when that device's
    /// driver is older than the version the descriptor counts as installed. Null when the descriptor has no driver rule.
    /// </summary>
    public static (bool Compared, VendorDriverUpdate? Update)? Evaluate(XDocument descriptor, Uri descriptorUri, string category, IReadOnlyList<InstalledDriver> drivers)
    {
        var root = descriptor.Root;
        if (root is null) return null;
        var detect = root.Elements().FirstOrDefault(e => e.Name.LocalName == "DetectInstall");
        if (detect is null) return null;

        var rules = detect.Descendants().Where(e => e.Name.LocalName == "_Driver" && !e.Ancestors().Any(a => a.Name.LocalName == "Not")).ToList();
        if (rules.Count == 0) return null;

        var compared = false;
        (InstalledDriver Driver, Version Installed, Version Wanted)? older = null;
        foreach (var rule in rules)
        {
            var versionText = Child(rule, "Version") ?? "";
            // "10.50^" is "10.50 or newer"; a rule with only an upper bound ("^10.50") or an exact version says nothing about newer.
            if (!versionText.EndsWith('^') || versionText.StartsWith('^')) continue;
            if (DriverVersion.Parse(versionText.TrimEnd('^')) is not { } wanted) continue;
            var ids = rule.Elements().Where(e => e.Name.LocalName == "HardwareID")
                .SelectMany(e => e.Value.Split([' ', '\r', '\n', '\t', ','], StringSplitOptions.RemoveEmptyEntries)).ToList();
            foreach (var d in drivers.Where(d => ids.Any(id => Matches(d, id))))
            {
                if (DriverVersion.Parse(d.Version) is not { } installed) continue;
                compared = true;
                if (installed < wanted && (older is null || installed < older.Value.Installed)) older = (d, installed, wanted);
            }
        }
        if (older is not { } o) return (compared, null);

        var installer = FileName(root, "Installer");
        if (installer is null || !LenovoBiosUpdateProvider.TryResolveDescriptorRelativeUrl(descriptorUri, installer.Value.Name,
                LenovoBiosUpdateProvider.AllowedHostSuffixes, out var download))
            return (compared, null);
        string? readme = null;
        if (FileName(root, "Readme") is { } r
            && LenovoBiosUpdateProvider.TryResolveDescriptorRelativeUrl(descriptorUri, r.Name, LenovoBiosUpdateProvider.AllowedHostSuffixes, out var readmeUrl))
            readme = readmeUrl;

        var title = root.Elements().FirstOrDefault(e => e.Name.LocalName == "Title")?.Elements().FirstOrDefault()?.Value.Trim();
        return (compared, new VendorDriverUpdate(
            Title: string.IsNullOrEmpty(title) ? root.Attribute("name")?.Value ?? "Lenovo driver" : title,
            Category: category.Length > 0 ? category : o.Driver.DeviceName,
            InstalledVersion: DriverVersion.Format(o.Installed),
            AvailableVersion: DriverVersion.Format(o.Wanted),
            Released: DateOnly.TryParse(Child(root, "ReleaseDate"), CultureInfo.InvariantCulture, out var date) ? date : null,
            DownloadUrl: download,
            DetailsUrl: readme,
            SizeBytes: installer.Value.Size,
            PackageId: root.Attribute("id")?.Value ?? root.Attribute("name")?.Value ?? ""));
    }

    /// <summary>
    /// A Lenovo hardware ID ("PCI\VEN_10EC&amp;DEV_8168") matches a device whose hardware or instance ID starts with it, up to a whole
    /// part ("…&amp;DEV_8168&amp;SUBSYS_…" yes, "…&amp;DEV_81681" no).
    /// </summary>
    public static bool Matches(InstalledDriver d, string lenovoId) => StartsWithPart(d.HardwareId, lenovoId) || StartsWithPart(d.DeviceId, lenovoId);

    private static bool StartsWithPart(string id, string prefix) =>
        prefix.Length > 0 && id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && (id.Length == prefix.Length || id[prefix.Length] is '&' or '\\');

    private static (string Name, long Size)? FileName(XElement root, string section)
    {
        var file = root.Elements().FirstOrDefault(e => e.Name.LocalName == "Files")?.Elements().FirstOrDefault(e => e.Name.LocalName == section)?
            .Elements().FirstOrDefault(e => e.Name.LocalName == "File");
        var name = file is null ? null : Child(file, "Name");
        if (name is null) return null;
        return (name, long.TryParse(Child(file!, "Size"), NumberStyles.None, CultureInfo.InvariantCulture, out var size) ? size : 0);
    }

    private static string? SafeUrl(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim();
        if (s.Contains('\\') || BiosProviderHttp.HasUnsafePathSegments(s, rejectAtSign: true)) return null;
        return BiosProviderHttp.TryValidateHttpsUrl(s, LenovoBiosUpdateProvider.AllowedHostSuffixes, out var uri, out _) ? uri.AbsoluteUri : null;
    }

    private static string? Child(XElement e, string name) =>
        e.Elements().FirstOrDefault(c => c.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value.Trim() is { Length: > 0 } v ? v : null;
}
