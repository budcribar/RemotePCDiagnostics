using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using RemotePCDiagnostics.Core.NetworkUsage;

namespace NetworkUsagePrototype;

// Names are presentation only: retain the original identity for grouping and exports.
internal static class ProgramNames
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string name, StringBuilder target, int length);

    public static IReadOnlyList<NetworkUsageEntry> Resolve(IReadOnlyList<NetworkUsageEntry> entries)
    {
        var drives = new List<(string Device, string Drive)>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            var buffer = new StringBuilder(4096);
            if (QueryDosDevice(drive.Name[..2], buffer, buffer.Capacity) != 0)
                drives.Add((buffer.ToString(), drive.Name[..2]));
        }
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        return entries.Select(e =>
        {
            if (!names.TryGetValue(e.AppId, out var name)) names[e.AppId] = name = ResolveName(e.AppId, e.App, drives);
            return e with { App = name };
        }).ToList();
    }

    private static string ResolveName(string identity, string supplied, List<(string Device, string Drive)> drives)
    {
        if (string.IsNullOrWhiteSpace(identity)) return "Unattributed traffic";
        var path = identity;
        foreach (var drive in drives.OrderByDescending(d => d.Device.Length))
            if (path.StartsWith(drive.Device + "\\", StringComparison.OrdinalIgnoreCase))
            { path = drive.Drive + path[drive.Device.Length..]; break; }
        // Never inspect remote paths just to obtain a friendly name.
        if (path.Length > 2 && char.IsLetter(path[0]) && path[1] == ':' && path[2] == '\\')
        {
            try
            {
                if (File.Exists(path))
                {
                    var version = FileVersionInfo.GetVersionInfo(path);
                    var product = version.ProductName?.Trim();
                    var description = version.FileDescription?.Trim();
                    if (!string.IsNullOrWhiteSpace(product))
                        return string.IsNullOrWhiteSpace(description) || description.Equals(product, StringComparison.OrdinalIgnoreCase)
                            ? product : $"{product} — {description}";
                    if (!string.IsNullOrWhiteSpace(description)) return description;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { }
        }
        var known = identity.Split('_')[0] switch
        {
            "Microsoft.YourPhone" => "Phone Link",
            "Microsoft.OutlookForWindows" => "Outlook for Windows",
            "Microsoft.BingNews" => "Microsoft News",
            "Microsoft.Todos" => "Microsoft To Do",
            "OpenAI.Codex" => "OpenAI Codex",
            "Claude" => "Claude",
            "E046963F.LenovoCompanion" => "Lenovo Vantage",
            "MicrosoftWindows.CrossDevice" => "Windows Cross Device",
            "Agilebits.1Password" => "1Password",
            _ => null
        };
        if (known is not null) return known;
        var lower = identity.ToLowerInvariant();
        if (lower.Contains("\\antigravity\\") && lower.EndsWith("\\language_server.exe"))
            return "Antigravity — language server (from installation path)";
        if (lower.Contains("\\openai\\codex\\") && lower.EndsWith("\\codex.exe"))
            return "OpenAI Codex — command-line helper (from installation path)";
        if (lower.Contains("\\microsoft visual studio\\installer\\") && lower.EndsWith("\\backgrounddownload.exe"))
            return "Visual Studio — background download (from installation path)";
        if (!string.IsNullOrWhiteSpace(supplied) && supplied != identity) return supplied;
        if (identity.Contains('\\'))
        {
            var file = Path.GetFileName(identity);
            var folder = Path.GetFileName(Path.GetDirectoryName(identity));
            return $"{file} (folder: {folder}; name unavailable)";
        }
        return identity;
    }
}
