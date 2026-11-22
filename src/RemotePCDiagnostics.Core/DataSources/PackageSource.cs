namespace RemotePCDiagnostics.Core.DataSources;

/// <summary>
/// The Store (MSIX) packages installed for the signed-in user, as Windows' package API lists them, for the Programs check. The answer reuses
/// <see cref="WmiQueryResult"/> so it is recorded and replayed like WMI: one row per package with the <see cref="PackageList"/> columns.
/// Every package is listed; the check decides which are apps a person installed.
/// </summary>
public interface IPackageSource
{
    /// <summary>Never throws except on cancellation.</summary>
    Task<WmiQueryResult> ReadPackagesAsync(CancellationToken ct = default);
}

/// <summary>The names a package list uses, and which packages are apps a person would recognize.</summary>
public static class PackageList
{
    public const string Location = "packages";
    public const string Query = "packages for the current user";

    public const string FullName = "FullName";
    public const string DisplayName = "DisplayName";
    public const string Publisher = "PublisherDisplayName";
    public const string Version = "Version";
    /// <summary>yyyyMMdd, local time.</summary>
    public const string InstalledDate = "InstalledDate";
    public const string IsFramework = "IsFramework";
    public const string IsResourcePackage = "IsResourcePackage";
    /// <summary>Store, Developer, Enterprise, None or System (part of Windows).</summary>
    public const string SignatureKind = "SignatureKind";

    public static WmiQueryResult Failed(string error) => WmiQueryResult.Failed(Location, Query, error);

    /// <summary>
    /// The apps among the packages: not frameworks or language resources, not part of Windows (signature kind System), and with a real name
    /// (an unresolved "ms-resource:" name is a package nobody sees). Each name and version once.
    /// </summary>
    public static IEnumerable<WmiRow> Apps(WmiQueryResult packages) =>
        (packages.Rows ?? []).Where(IsApp).DistinctBy(p => (p.Str(DisplayName).ToUpperInvariant(), p.Str(Version)));

    public static bool IsApp(WmiRow p) =>
        p.Bool(IsFramework) != true && p.Bool(IsResourcePackage) != true
        && !p.Str(SignatureKind).Equals("System", StringComparison.OrdinalIgnoreCase)
        && p.Str(DisplayName) is { Length: > 0 } name && !name.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Where the package API isn't available (off Windows, in tests): no packages, as a failed answer.</summary>
public sealed class NoPackageSource : IPackageSource
{
    public Task<WmiQueryResult> ReadPackagesAsync(CancellationToken ct = default) =>
        Task.FromResult(PackageList.Failed("Store apps can't be listed here."));
}

/// <summary>A module in user mode (the module host) asks the app for the list (<c>packages.list</c>).</summary>
public sealed class HostPackageSource(Plugins.IHostQueries host, ILogger? log = null) : IPackageSource
{
    public async Task<WmiQueryResult> ReadPackagesAsync(CancellationToken ct = default)
    {
        try { return await host.ListPackagesAsync(ct).ConfigureAwait(false); }
        catch (Plugins.HostQueryException ex)
        {
            log.Warn($"packages.list refused ({ex.Error}): {ex.Message}");
            return PackageList.Failed(ex.Message);
        }
    }
}
