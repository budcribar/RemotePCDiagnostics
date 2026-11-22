using System.Globalization;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Logging;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using RemotePCDiagnostics.Core.DataSources;
using Windows.Management.Deployment;

namespace RemotePCDiagnostics.Host.Platform;

/// <summary>
/// The signed-in user's Store packages from Windows' package API (PackageManager.FindPackagesForUser with the current user), which needs no
/// administrator rights and no PowerShell. A package whose details can't be read is skipped.
/// </summary>
public sealed class SystemPackageSource(ILogger? log = null) : IPackageSource
{
    public Task<WmiQueryResult> ReadPackagesAsync(CancellationToken ct = default) => Task.Run(() =>
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        WmiQueryResult result;
        try
        {
            var rows = new List<WmiRow>();
            foreach (var p in new PackageManager().FindPackagesForUser(string.Empty))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var v = p.Id.Version;
                    rows.Add(WmiRow.From(new Dictionary<string, object?>
                    {
                        [PackageList.FullName] = p.Id.FullName,
                        [PackageList.DisplayName] = Safe(() => p.DisplayName),
                        [PackageList.Publisher] = Safe(() => p.PublisherDisplayName),
                        [PackageList.Version] = $"{v.Major}.{v.Minor}.{v.Build}.{v.Revision}",
                        [PackageList.InstalledDate] = Safe(() => p.InstalledDate.ToLocalTime().ToString("yyyyMMdd", CultureInfo.InvariantCulture)),
                        [PackageList.IsFramework] = p.IsFramework,
                        [PackageList.IsResourcePackage] = p.IsResourcePackage,
                        [PackageList.SignatureKind] = Safe(() => p.SignatureKind.ToString()),
                    }));
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { log.Warn($"package skipped: {ex.Message}"); }
            }
            result = new(PackageList.Location, PackageList.Query, rows);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { result = PackageList.Failed(ex.Message); }
        log.Line($"packages {(result.Success ? "ok" : "FAILED")} rows={result.Rows?.Count ?? 0} ms={sw.ElapsedMilliseconds}" +
                 (result.Error is null ? "" : $" error=\"{result.Error}\""));
        return result;
    }, ct);

    /// <summary>A package's text property, or "" when Windows can't give it (some system packages throw).</summary>
    private static string Safe(Func<string> read)
    {
        try { return read() ?? ""; } catch { return ""; }
    }
}
