namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// The devices allowed to wake the PC (<c>powercfg /devicequery wake_armed</c>), and the guard for the fix that stops one
/// (<see cref="RemediationKind.DisableDeviceWake"/>): the fix only ever names a device Windows itself listed as wake-armed.
/// </summary>
public static class DeviceWake
{
    public static string PowerCfg => SystemCommandRunner.SystemTool("powercfg.exe");

    public static readonly IReadOnlyList<string> QueryArgs = ["/devicequery", "wake_armed"];

    /// <summary>One device per line. "NONE" (any case) or an empty output means no device can wake the PC.</summary>
    public static IReadOnlyList<string> ParseArmed(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return [];
        var list = new List<string>();
        foreach (var raw in stdout.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.Equals("NONE", StringComparison.OrdinalIgnoreCase)) continue;
            if (!list.Contains(line, StringComparer.OrdinalIgnoreCase)) list.Add(line);
        }
        return list;
    }

    /// <summary>A name this app will pass to powercfg: printable, no quotes, no line breaks, not absurdly long.</summary>
    public static bool IsSafeName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= 256 && name == name.Trim() && !name.Any(c => char.IsControl(c) || c == '"');

    /// <summary>
    /// True for shared USB hubs, host controllers, routers, and composite devices where disabling wake
    /// (<c>powercfg /devicedisablewake</c>) can break selective-suspend/D3 recovery for downstream keyboards,
    /// mice, or docks (including Code 43 descriptor failures).
    /// </summary>
    public static bool IsProtectedBusOrHub(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        return name.Contains("USB Root Hub", StringComparison.OrdinalIgnoreCase)
            || name.Contains("USB Hub", StringComparison.OrdinalIgnoreCase)
            || name.Contains("USB Composite Device", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Host Controller", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Host Router", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Root Device Router", StringComparison.OrdinalIgnoreCase)
            || name.Contains("xHCI", StringComparison.OrdinalIgnoreCase)
            || name.Contains("eHCI", StringComparison.OrdinalIgnoreCase)
            || name.Contains("oHCI", StringComparison.OrdinalIgnoreCase)
            || name.Contains("uHCI", StringComparison.OrdinalIgnoreCase)
            || (name.Contains("USB", StringComparison.OrdinalIgnoreCase)
                && (name.Contains("Hub", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("Controller", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("Router", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("Composite", StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>True when this app may offer and run <c>powercfg /devicedisablewake</c> for <paramref name="name"/>.</summary>
    public static bool CanDisableWake(string? name) => IsSafeName(name) && !IsProtectedBusOrHub(name);

    /// <summary>Asks Windows for the wake-armed list now; null when powercfg couldn't run.</summary>
    public static async Task<IReadOnlyList<string>?> QueryArmedAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        var pr = await commands.RunAsync(PowerCfg, QueryArgs, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? ParseArmed(pr.StdOut) : null;
    }

    /// <summary>The device's name exactly as Windows lists it among the wake-armed devices, or null when it isn't one of them.</summary>
    public static string? FindArmed(IReadOnlyList<string> armed, string? target) =>
        IsSafeName(target) ? armed.FirstOrDefault(a => string.Equals(a, target, StringComparison.OrdinalIgnoreCase)) : null;

    /// <summary>
    /// Extracts a Task Scheduler full path (e.g. <c>\Hewlett-Packard\HP Diagnostics\SmartCheckTest</c>) from a
    /// <c>powercfg /waketimers</c> reason such as <c>Windows will execute 'NT TASK\Hewlett-Packard\HP Diagnostics\SmartCheckTest' scheduled task…</c>.
    /// </summary>
    public static bool TryExtractTaskPath(string? reason, out string taskPath)
    {
        taskPath = "";
        if (string.IsNullOrWhiteSpace(reason)) return false;
        const string marker = "'NT TASK\\";
        var start = reason.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return false;
        var pathStart = start + marker.Length - 1; // keep leading '\'
        var end = reason.IndexOf('\'', pathStart);
        if (end <= pathStart) return false;
        var candidate = reason[pathStart..end].Trim();
        if (!IsSafeTaskPath(candidate)) return false;
        taskPath = candidate;
        return true;
    }

    /// <summary>A Task Scheduler full path this app will modify: starts with <c>\</c>, no quotes/control chars/traversal, and has a non-empty task name.</summary>
    public static bool IsSafeTaskPath(string? path) => TrySplitTaskPath(path, out _, out _);

    /// <summary>Splits <c>\Folder\Sub\TaskName</c> into <c>\Folder\Sub</c> (or <c>\</c>) and <c>TaskName</c>.</summary>
    public static bool TrySplitTaskPath(string? path, out string folderPath, out string taskName)
    {
        folderPath = "";
        taskName = "";
        if (string.IsNullOrWhiteSpace(path) || path.Length > 260 || path != path.Trim() || !path.StartsWith('\\')) return false;
        if (path.Any(c => char.IsControl(c) || c == '"' || c == '\'')) return false;
        if (path.Contains("..", StringComparison.Ordinal)) return false;
        var lastSlash = path.LastIndexOf('\\');
        if (lastSlash < 0 || lastSlash == path.Length - 1) return false;
        folderPath = lastSlash == 0 ? "\\" : path[..lastSlash];
        taskName = path[(lastSlash + 1)..];
        return !string.IsNullOrWhiteSpace(taskName);
    }

    /// <summary>The trailing task name for display (e.g. <c>SmartCheckTest</c>).</summary>
    public static string ShortTaskName(string taskPath) =>
        TrySplitTaskPath(taskPath, out _, out var name) ? name : taskPath;
}
