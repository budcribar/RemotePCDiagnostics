using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Core.Drivers;

/// <summary>
/// Dell's catalog of every model (<c>downloads.dell.com/catalog/CatalogPC.cab</c>, the one Dell Command | Update reads). Each driver or
/// firmware package names the models it's for (<c>&lt;Model systemID="0A2E"&gt;</c>), the devices it drives by PCI vendor and device ID, and
/// its driver version (<c>vendorVersion</c>). A device with a lower driver version means Dell has a newer package. Not yet tried on a
/// Dell PC: written from Dell's published catalog format.
/// </summary>
public sealed class DellDriverCatalog(HttpClient? http = null, SystemCommandRunner? commands = null, string? catalogUrl = null) : IVendorDriverCatalog
{
    private const long MaxCatalogBytes = 128L * 1024 * 1024;

    private readonly HttpClient _http = http ?? BiosProviderHttp.SharedClient;
    private readonly string _url = string.IsNullOrWhiteSpace(catalogUrl) ? DellBiosUpdateProvider.DefaultCatalogUrl : catalogUrl;

    public string Vendor => "Dell";

    public bool CanHandle(BiosSystemIdentity system) => BiosVendorIdentity.IsDell(system) && BiosVendorIdentity.TryExtractFourHex(system.SystemSku, out _);

    public async Task<VendorDriverScan> ScanAsync(BiosSystemIdentity system, IDriverInventory pc, CancellationToken ct)
    {
        if (!BiosVendorIdentity.TryExtractFourHex(system.SystemSku, out var sku))
            return VendorDriverScan.Failed(Vendor, "This Dell PC doesn't report its system ID.");
        var drivers = await pc.ReadDriversAsync(ct).ConfigureAwait(false);
        if (drivers is null) return VendorDriverScan.Failed(Vendor, "Couldn't read this PC's drivers to compare with Dell's catalog.");

        string? xml;
        try
        {
            using var response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(_http, _url, DellBiosUpdateProvider.AllowedHostSuffixes,
                HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return VendorDriverScan.Failed(Vendor, $"Dell's catalog answered {(int)response.StatusCode}.");
            var payload = await BiosProviderHttp.ReadBoundedBytesAsync(response.Content, MaxCatalogBytes, "Dell driver catalog", ct).ConfigureAwait(false);
            xml = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(payload, "dell-drivers", commands, ct, MaxCatalogBytes).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return VendorDriverScan.Failed(Vendor, "Couldn't reach Dell's driver catalog."); }
        if (string.IsNullOrWhiteSpace(xml)) return VendorDriverScan.Failed(Vendor, "Dell's driver catalog couldn't be read.");

        var arm64 = system.Architecture.Contains("arm64", StringComparison.OrdinalIgnoreCase);
        var win11 = BiosVendorIdentity.IsWindows11(system.OsVersion);
        using var reader = new StringReader(xml);
        var (updates, compared) = Evaluate(reader, sku, drivers, win11, arm64);
        return new(Vendor, updates, compared);
    }

    /// <summary>
    /// Reads the catalog one package at a time (it's tens of megabytes) and compares the packages for <paramref name="sku"/> with the PC's
    /// drivers: the newer ones, and how many matched a device on this PC.
    /// </summary>
    public static (IReadOnlyList<VendorDriverUpdate> Updates, int Compared) Evaluate(TextReader catalog, string sku, IReadOnlyList<InstalledDriver> drivers, bool win11, bool arm64)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreComments = true, IgnoreWhitespace = true };
        using var reader = XmlReader.Create(catalog, settings);
        var baseLocation = "downloads.dell.com";
        var best = new Dictionary<string, VendorDriverUpdate>(StringComparer.OrdinalIgnoreCase);
        var comparedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        reader.MoveToContent();
        if (reader.GetAttribute("baseLocation") is { Length: > 0 } b) baseLocation = b;
        while (!reader.EOF)
        {
            if (reader.NodeType != XmlNodeType.Element || reader.LocalName != "SoftwareComponent")
            {
                reader.Read();
                continue;
            }
            if (XNode.ReadFrom(reader) is not XElement comp) continue;
            if (Evaluate(comp, baseLocation, sku, drivers, win11, arm64) is not { } result) continue;
            comparedNames.Add(result.Name);
            if (result.Update is { } u && (!best.TryGetValue(result.Name, out var had)
                    || DriverVersion.Parse(u.AvailableVersion) > DriverVersion.Parse(had.AvailableVersion)))
                best[result.Name] = u;
        }
        // A newer package for the same driver supersedes an older one that's also still listed.
        return ([.. best.Values.OrderBy(u => u.Title, StringComparer.CurrentCultureIgnoreCase)], comparedNames.Count);
    }

    /// <summary>One package: null when it isn't a Windows driver or firmware for this model or none of its devices is on the PC.</summary>
    private static (string Name, VendorDriverUpdate? Update)? Evaluate(XElement comp, string baseLocation, string sku, IReadOnlyList<InstalledDriver> drivers, bool win11, bool arm64)
    {
        var type = comp.Elements().FirstOrDefault(e => e.Name.LocalName == "ComponentType")?.Attribute("value")?.Value;
        if (type is not ("DRVR" or "FRMW")) return null;
        if (!ForModel(comp, sku) || !ForWindows(comp, win11, arm64)) return null;
        if (DriverVersion.Parse(comp.Attribute("vendorVersion")?.Value) is not { } available) return null;

        var devices = comp.Elements().FirstOrDefault(e => e.Name.LocalName == "SupportedDevices")?.Elements().Where(e => e.Name.LocalName == "Device").ToList() ?? [];
        Version? oldest = null;
        var found = false;
        foreach (var pci in devices.SelectMany(d => d.Elements().Where(e => e.Name.LocalName == "PCIInfo")))
        {
            var ven = pci.Attribute("vendorID")?.Value;
            var dev = pci.Attribute("deviceID")?.Value;
            if (string.IsNullOrWhiteSpace(ven) || string.IsNullOrWhiteSpace(dev)) continue;
            var key = $"VEN_{ven.Trim()}&DEV_{dev.Trim()}";
            foreach (var d in drivers.Where(d => d.DeviceId.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase)
                         && d.DeviceId.Contains(key, StringComparison.OrdinalIgnoreCase)))
            {
                if (DriverVersion.Parse(d.Version) is not { } installed) continue;
                found = true;
                if (oldest is null || installed < oldest) oldest = installed;
            }
        }
        if (!found) return null;

        var name = Display(comp, "Name") ?? comp.Attribute("packageID")?.Value ?? "Dell driver";
        if (oldest is null || oldest >= available) return (name, null);
        if (!DellBiosUpdateProvider.TryBuildDellPackageUrl(baseLocation, comp.Attribute("path")?.Value, out var url)
            || !new Uri(url).AbsolutePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return (name, null);

        var notes = comp.Elements().FirstOrDefault(e => e.Name.LocalName == "ImportantInfo")?.Attribute("URL")?.Value;
        string? details = notes is not null && BiosProviderHttp.TryValidateHttpsUrl(notes, DellBiosUpdateProvider.AllowedHostSuffixes, out var n, out _) ? n.AbsoluteUri : null;
        var released = DateTimeOffset.TryParse(comp.Attribute("dateTime")?.Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dt)
            ? DateOnly.FromDateTime(dt.UtcDateTime) : (DateOnly?)null;
        return (name, new VendorDriverUpdate(
            Title: name,
            Category: Display(comp, "Category") ?? (type == "FRMW" ? "Firmware" : "Driver"),
            InstalledVersion: DriverVersion.Format(oldest),
            AvailableVersion: DriverVersion.Format(available),
            Released: released,
            DownloadUrl: url,
            DetailsUrl: details,
            SizeBytes: long.TryParse(comp.Attribute("size")?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var size) ? size : 0,
            PackageId: comp.Attribute("releaseID")?.Value ?? comp.Attribute("packageID")?.Value ?? ""));
    }

    private static bool ForModel(XElement comp, string sku) =>
        comp.Elements().FirstOrDefault(e => e.Name.LocalName == "SupportedSystems")?.Descendants().Any(m => m.Name.LocalName == "Model"
            && BiosVendorIdentity.TryExtractFourHex(m.Attribute("systemID")?.Value, out var id) && id.Equals(sku, StringComparison.OrdinalIgnoreCase)) == true;

    /// <summary>Windows 11 packages are "W11…" (Windows 10 "W10…"/"WT64…"); a package that lists no Windows version isn't trusted either way.</summary>
    private static bool ForWindows(XElement comp, bool win11, bool arm64)
    {
        var oses = comp.Elements().FirstOrDefault(e => e.Name.LocalName == "SupportedOperatingSystems")?.Elements()
            .Where(e => e.Name.LocalName == "OperatingSystem").ToList() ?? [];
        return oses.Any(o =>
        {
            var code = o.Attribute("osCode")?.Value ?? "";
            var arch = o.Attribute("osArch")?.Value ?? "";
            var codeOk = win11 ? code.StartsWith("W11", StringComparison.OrdinalIgnoreCase)
                : code.StartsWith("W10", StringComparison.OrdinalIgnoreCase) || code.StartsWith("WT64", StringComparison.OrdinalIgnoreCase);
            var archOk = arm64 ? arch.Contains("arm", StringComparison.OrdinalIgnoreCase) : arch.Equals("x64", StringComparison.OrdinalIgnoreCase);
            return codeOk && archOk;
        });
    }

    private static string? Display(XElement comp, string child)
    {
        var holder = comp.Elements().FirstOrDefault(e => e.Name.LocalName == child);
        var displays = holder?.Elements().Where(e => e.Name.LocalName == "Display").ToList() ?? [];
        var text = (displays.FirstOrDefault(d => d.Attribute("lang")?.Value == "en") ?? displays.FirstOrDefault())?.Value.Trim();
        return string.IsNullOrEmpty(text) ? null : text;
    }
}
