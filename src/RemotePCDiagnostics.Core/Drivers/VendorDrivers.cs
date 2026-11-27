using System.Globalization;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Core.Drivers;

/// <summary>
/// One driver or firmware package the PC maker lists for this model that is newer than what this PC has. Read only: the technician
/// downloads it from <see cref="DownloadUrl"/> (on the maker's site) and runs it.
/// </summary>
public sealed record VendorDriverUpdate(
    string Title, string Category, string InstalledVersion, string AvailableVersion, DateOnly? Released,
    string DownloadUrl, string? DetailsUrl = null, long SizeBytes = 0, string PackageId = "");

/// <summary>What one PC maker's catalog says about this PC: the newer packages, how many it could compare, or why it couldn't be read.</summary>
public sealed record VendorDriverScan(string Vendor, IReadOnlyList<VendorDriverUpdate> Updates, int Compared, string? Problem = null)
{
    public static VendorDriverScan Failed(string vendor, string problem) => new(vendor, [], 0, problem);
}

/// <summary>One installed device driver: the device's instance ID, the hardware ID its driver matched, and the driver's version.</summary>
public sealed record InstalledDriver(string DeviceId, string HardwareId, string DeviceName, string Version);

/// <summary>What the catalogs read from this PC. Each method never throws except on cancellation.</summary>
public interface IDriverInventory
{
    /// <summary>The Windows feature release ("23H2", "24H2"), or "" when unknown.</summary>
    Task<string> ReadDisplayVersionAsync(CancellationToken ct);

    /// <summary>
    /// The file version of <paramref name="path"/> (environment variables like <c>%SystemRoot%</c> are expanded; a directory segment may
    /// hold one <c>*</c> wildcard, and then the newest match counts), or null when there's no such file or it has no version.
    /// </summary>
    Version? ReadFileVersion(string path);

    /// <summary>Installed device drivers, or null when they couldn't be read.</summary>
    Task<IReadOnlyList<InstalledDriver>?> ReadDriversAsync(CancellationToken ct);
}

/// <summary>One PC maker's driver catalog (HP, Lenovo, Dell). It compares the catalog for this model with what's installed.</summary>
public interface IVendorDriverCatalog
{
    /// <summary>The maker's name as shown on the card ("HP").</summary>
    string Vendor { get; }

    /// <summary>Whether this catalog covers <paramref name="system"/>. Offline; never throws.</summary>
    bool CanHandle(BiosSystemIdentity system);

    /// <summary>Reads the catalog and returns the newer packages. Never throws except on cancellation.</summary>
    Task<VendorDriverScan> ScanAsync(BiosSystemIdentity system, IDriverInventory pc, CancellationToken ct);
}

/// <summary>Finds the catalog for this PC's maker and asks it for newer drivers ("Newer from HP" rows on the Drivers card).</summary>
public sealed class VendorDriverUpdates(IBiosSystemProbe probe, IEnumerable<IVendorDriverCatalog> catalogs, IDriverInventory pc, ILogger? log = null)
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(90);
    private readonly IReadOnlyList<IVendorDriverCatalog> _catalogs = [.. catalogs];

    /// <summary>The scan, or null when no catalog covers this PC's maker. Never throws except on cancellation.</summary>
    public async Task<VendorDriverScan?> ScanAsync(CancellationToken ct)
    {
        BiosSystemIdentity system;
        try { system = await probe.ProbeAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log?.Warn($"Vendor drivers: couldn't identify this PC: {ex.Message}");
            return null;
        }

        var catalog = _catalogs.FirstOrDefault(c => SafeCanHandle(c, system));
        if (catalog is null) return null;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        try
        {
            var scan = await catalog.ScanAsync(system, pc, cts.Token).ConfigureAwait(false);
            log?.Info($"Vendor drivers: {catalog.Vendor} compared {scan.Compared}, {scan.Updates.Count} newer{(scan.Problem is null ? "" : $", problem: {scan.Problem}")}");
            return scan;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return VendorDriverScan.Failed(catalog.Vendor, $"{catalog.Vendor}'s catalog took too long to answer."); }
        catch (Exception ex)
        {
            log?.Warn($"Vendor drivers: {catalog.Vendor} scan failed: {ex.Message}");
            return VendorDriverScan.Failed(catalog.Vendor, $"Couldn't read {catalog.Vendor}'s driver catalog.");
        }
    }

    private static bool SafeCanHandle(IVendorDriverCatalog catalog, BiosSystemIdentity system)
    {
        try { return catalog.CanHandle(system); }
        catch { return false; }
    }
}

/// <summary>Driver and file versions as the catalogs write them ("31.0.101.5594", "10.50.511.2021^", "A05" isn't one).</summary>
public static class DriverVersion
{
    /// <summary>The leading dotted number of <paramref name="text"/> with missing parts as 0, or null when it doesn't start with one.</summary>
    public static Version? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var s = text.Trim();
        var end = 0;
        while (end < s.Length && (char.IsAsciiDigit(s[end]) || s[end] == '.')) end++;
        var parts = s[..end].Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length is 0 or > 4) return null;
        var n = new int[4];
        for (var i = 0; i < parts.Length; i++)
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out n[i])) return null;
        return new Version(n[0], n[1], n[2], n[3]);
    }

    /// <summary>The version as four parts, so "1.2" and "1.2.0.0" compare equal.</summary>
    public static Version Normalize(Version v) => new(v.Major, v.Minor, Math.Max(0, v.Build), Math.Max(0, v.Revision));

    /// <summary>Shown on the card: "31.0.101.5594", or "1.2" for 1.2.0.0.</summary>
    public static string Format(Version v)
    {
        var n = Normalize(v);
        return n.Revision != 0 ? n.ToString(4) : n.Build != 0 ? n.ToString(3) : n.ToString(2);
    }
}
