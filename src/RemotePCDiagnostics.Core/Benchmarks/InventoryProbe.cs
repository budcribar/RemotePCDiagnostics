using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>Independent probes: a failed or incomplete query is unknown, never a zero count.</summary>
public static class InventoryProbe
{
    public static async Task<SystemResourceSnapshot> ReadAsync(SystemCommandRunner commands, CancellationToken ct)
    {
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
        var apps = await Count(@"Get-AppxPackage -ErrorAction Stop | Where-Object { $_.Name -match 'Clipchamp|PowerAutomateDesktop|MicrosoftJournal|SolitaireCollection|WindowsMaps|windowscommunicationsapps|MixedReality\.Portal|Windows\.DevHome|Microsoft\.People|DropboxOEM|BingNews|BingWeather|NarratorExtension|NarratorScript' }").ConfigureAwait(false);
        return new(AutoVendorServices: services, ActiveScheduledTasks: tasks, InstalledBloatwareApps: apps);
    }
}
