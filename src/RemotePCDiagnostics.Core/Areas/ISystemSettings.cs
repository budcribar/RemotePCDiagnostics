namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Windows settings the fixes and undo read and write in process (registry and WMI), instead of starting PowerShell for a one-liner.
/// Core stays platform-neutral: the Host implements this (WindowsSystemSettings); tests use a fake. Writes throw when Windows refuses.
/// </summary>
public interface ISystemSettings
{
    /// <summary>HKLM ...\Session Manager\Power HiberbootEnabled (1 = Fast Startup on), or null when it isn't set.</summary>
    int? GetFastStartup();
    void SetFastStartup(int value);

    /// <summary>ProxyEnable in the signed-in user's Internet Settings (their own hive, not the elevated administrator's), or null when it
    /// isn't set or nobody is signed in at this desktop.</summary>
    int? GetUserProxyEnable();
    void SetUserProxyEnable(int value);

    /// <summary>Static IPv4 DNS servers on the adapter named <paramref name="alias"/>, comma separated ("" = automatic), or null when there is
    /// no such adapter.</summary>
    string? GetAdapterDns(string alias);
    /// <summary>Sets the adapter's IPv4 DNS servers; an empty list goes back to automatic (DHCP).</summary>
    void SetAdapterDns(string alias, IReadOnlyList<string> servers);
}

/// <summary>Checks shared by the fixes and undo before a value reaches <see cref="ISystemSettings"/>.</summary>
public static class SystemSettingsRules
{
    /// <summary>A network adapter name as Windows shows it: no wildcard characters, no control characters, at most 256 characters.</summary>
    public static bool IsAdapterName(string? alias) =>
        !string.IsNullOrWhiteSpace(alias) && alias.Length <= 256 && alias.IndexOfAny(['*', '?', '[', ']']) < 0 && !alias.Any(char.IsControl);

    /// <summary>The IPv4 addresses in a comma separated list (the journal's format); any other entry is dropped.</summary>
    public static IReadOnlyList<string> Ipv4Servers(string? list) =>
        (list ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => System.Net.IPAddress.TryParse(s, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && s.Count(c => c == '.') == 3)
            .ToList();
}
