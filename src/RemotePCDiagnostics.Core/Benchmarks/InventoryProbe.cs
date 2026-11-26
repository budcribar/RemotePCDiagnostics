using System.Globalization;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Platform;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>Independent probes: a failed or incomplete query is unknown, never a zero count.</summary>
public static partial class InventoryProbe
{
    private const string BloatwarePattern =
        @"Clipchamp|PowerAutomateDesktop|MicrosoftJournal|SolitaireCollection|WindowsMaps|windowscommunicationsapps|MixedReality\.Portal|Windows\.DevHome|Microsoft\.People|DropboxOEM|BingNews|BingWeather|NarratorExtension|NarratorScript";

    [GeneratedRegex(BloatwarePattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BloatwareRegex();

    public static async Task<SystemResourceSnapshot> ReadAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!commands.IsScripted && OperatingSystem.IsWindows())
            return await ReadWindowsAsync(ct).ConfigureAwait(false);

        async Task<int?> Count(string query)
        {
            ct.ThrowIfCancellationRequested();
            var script = "$ErrorActionPreference='Stop'; try { $items=@(" + query +
                "); [Console]::WriteLine($items.Count) } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";
            var result = await commands.RunPowerShellAsync(script, ct).ConfigureAwait(false);

            return result is { ExitCode: 0, TimedOut: false } && string.IsNullOrWhiteSpace(result.StdErr) &&
                int.TryParse(result.StdOut.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var count)
                ? count : null;
        }

        var services = await Count(@"Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notmatch 'C:\\Windows\\' }").ConfigureAwait(false);
        var tasks = await Count(@"Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' -and $_.State -ne 'Disabled' }").ConfigureAwait(false);
        var apps = await Count(@"Get-AppxPackage -ErrorAction Stop | Where-Object { $_.Name -match '" + BloatwarePattern + "' }").ConfigureAwait(false);
        return new(AutoVendorServices: services, ActiveScheduledTasks: tasks, InstalledBloatwareApps: apps);
    }

    [SupportedOSPlatform("windows")]
    private static Task<SystemResourceSnapshot> ReadWindowsAsync(CancellationToken ct) =>
        Task.Run(() => ReadWindows(ct), ct);

    [SupportedOSPlatform("windows")]
    internal static SystemResourceSnapshot ReadWindows(CancellationToken ct)
    {
        var services = TryCount(() => CountAutoVendorServices(ct), ct);
        var tasks = TryCount(() => WindowsTaskScheduler.CountActiveTasksExcluding(@"\Microsoft\Windows\", ct), ct);
        var apps = TryCount(() => CountInstalledBloatwareApps(ct), ct);
        return new(AutoVendorServices: services, ActiveScheduledTasks: tasks, InstalledBloatwareApps: apps);
    }

    private static int? TryCount(Func<int> probe, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try { return probe(); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    [SupportedOSPlatform("windows")]
    private static int CountAutoVendorServices(CancellationToken ct)
    {
        var count = 0;
        using var searcher = new ManagementObjectSearcher("SELECT PathName FROM Win32_Service WHERE StartMode = 'Auto'");
        using var results = searcher.Get();
        foreach (ManagementBaseObject o in results)
        {
            ct.ThrowIfCancellationRequested();
            using (o)
            {
                var path = o["PathName"]?.ToString() ?? "";
                if (!path.Contains(@"C:\Windows\", StringComparison.OrdinalIgnoreCase))
                    count++;
            }
        }
        return count;
    }

    [SupportedOSPlatform("windows")]
    private static int CountInstalledBloatwareApps(CancellationToken ct)
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages")
            ?? throw new InvalidOperationException("AppModel package repository key not found.");
        return CountMatchingPackageNames(key.GetSubKeyNames(), ct);
    }

    internal static int CountMatchingPackageNames(IEnumerable<string> packageFullNames, CancellationToken ct = default)
    {
        var count = 0;
        foreach (var fullName in packageFullNames)
        {
            ct.ThrowIfCancellationRequested();
            var underscore = fullName.IndexOf('_');
            var name = underscore > 0 ? fullName[..underscore] : fullName;
            if (BloatwareRegex().IsMatch(name))
                count++;
        }
        return count;
    }
}
