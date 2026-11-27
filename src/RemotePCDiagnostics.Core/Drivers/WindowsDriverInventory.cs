using System.Diagnostics;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Drivers;

/// <summary>
/// This PC's Windows release (registry), file versions (read directly: driver folders and the driver store are readable by a standard
/// user) and installed drivers (WMI <c>Win32_PnPSignedDriver</c>, through the Agent like the Drivers check's other reads).
/// </summary>
public sealed class WindowsDriverInventory(IWmiSource? wmi, IRegistrySource? registry) : IDriverInventory
{
    public const string DriversSql = "SELECT DeviceID, HardWareID, DeviceName, DriverVersion FROM Win32_PnPSignedDriver";
    private static readonly RegistryRead CurrentVersion = new(RegistryRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", ["DisplayVersion", "CurrentBuild"]);

    public async Task<string> ReadDisplayVersionAsync(CancellationToken ct)
    {
        if (registry is null) return "";
        var r = await registry.ReadAsync(CurrentVersion, ct).ConfigureAwait(false);
        var row = r.Rows is { Count: > 0 } rows ? rows[0] : null;
        if (row is null) return "";
        var display = row.Str("DisplayVersion");
        return display.Length > 0 ? display : ReleaseForBuild(row.Str("CurrentBuild"));
    }

    /// <summary>Windows 11's release for a build number, when the registry has no DisplayVersion.</summary>
    public static string ReleaseForBuild(string build) => int.TryParse(build, out var b) ? b switch
    {
        >= 26200 => "25H2",
        >= 26100 => "24H2",
        >= 22631 => "23H2",
        >= 22621 => "22H2",
        >= 22000 => "21H2",
        >= 19045 => "22H2",
        _ => "",
    } : "";

    public Version? ReadFileVersion(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            Version? best = null;
            foreach (var file in Expand(Environment.ExpandEnvironmentVariables(path)))
            {
                var info = FileVersionInfo.GetVersionInfo(file);
                if (info.FileMajorPart == 0 && info.FileMinorPart == 0 && info.FileBuildPart == 0 && info.FilePrivatePart == 0) continue;
                var v = new Version(info.FileMajorPart, info.FileMinorPart, info.FileBuildPart, info.FilePrivatePart);
                if (best is null || v > best) best = v;
            }
            return best;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return null; }
    }

    /// <summary>The files a path names; a directory segment with a <c>*</c> matches every folder it fits.</summary>
    public static IEnumerable<string> Expand(string path)
    {
        var segments = path.Split('\\');
        var star = Array.FindIndex(segments, s => s.Contains('*'));
        if (star < 0)
        {
            if (File.Exists(path)) yield return path;
            yield break;
        }
        if (star == 0 || star == segments.Length - 1) yield break; // no wildcard drive or file name
        var parent = string.Join('\\', segments[..star]) + "\\";
        if (!Directory.Exists(parent)) yield break;
        var rest = string.Join('\\', segments[(star + 1)..]);
        foreach (var dir in Directory.EnumerateDirectories(parent, segments[star]))
            foreach (var f in Expand(Path.Combine(dir, rest)))
                yield return f;
    }

    public async Task<IReadOnlyList<InstalledDriver>?> ReadDriversAsync(CancellationToken ct)
    {
        if (wmi is null) return null;
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, DriversSql, ct).ConfigureAwait(false);
        return q.Success
            ? q.Rows!.Where(r => r.Str("DeviceID").Length > 0)
                .Select(r => new InstalledDriver(r.Str("DeviceID"), r.Str("HardWareID"), r.Str("DeviceName"), r.Str("DriverVersion"))).ToList()
            : null;
    }
}
