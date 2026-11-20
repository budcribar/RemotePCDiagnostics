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

    /// <summary>Asks Windows for the wake-armed list now; null when powercfg couldn't run.</summary>
    public static async Task<IReadOnlyList<string>?> QueryArmedAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        var pr = await commands.RunAsync(PowerCfg, QueryArgs, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? ParseArmed(pr.StdOut) : null;
    }

    /// <summary>The device's name exactly as Windows lists it among the wake-armed devices, or null when it isn't one of them.</summary>
    public static string? FindArmed(IReadOnlyList<string> armed, string? target) =>
        IsSafeName(target) ? armed.FirstOrDefault(a => string.Equals(a, target, StringComparison.OrdinalIgnoreCase)) : null;
}
