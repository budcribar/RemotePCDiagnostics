using System.Management;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// <see cref="ISystemSettings"/> in process: the registry for Fast Startup and the proxy, WMI (Win32_NetworkAdapterConfiguration) for
/// adapter DNS. The proxy is the signed-in user's setting, so it is read and written in their hive (HKEY_USERS\&lt;SID&gt; of the shell's
/// account), not in the elevated administrator's HKCU, which differs when someone else typed the administrator password at the UAC prompt.
/// </summary>
public sealed class WindowsSystemSettings(ILogger? log = null) : ISystemSettings
{
    private const string PowerKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Power";
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string TcpipInterfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";

    public int? GetFastStartup()
    {
        using var lm = OpenLocalMachine();
        using var k = lm.OpenSubKey(PowerKey);
        return k?.GetValue("HiberbootEnabled") is int v ? v : null;
    }

    public void SetFastStartup(int value)
    {
        using var lm = OpenLocalMachine();
        using var k = lm.OpenSubKey(PowerKey, writable: true) ?? throw new InvalidOperationException("The power settings key is missing.");
        k.SetValue("HiberbootEnabled", value, RegistryValueKind.DWord);
    }

    public int? GetUserProxyEnable()
    {
        using var root = OpenSignedInUserHive(writable: false);
        using var k = root?.OpenSubKey(InternetSettingsKey);
        return k?.GetValue("ProxyEnable") is int v ? v : null;
    }

    public void SetUserProxyEnable(int value)
    {
        using var root = OpenSignedInUserHive(writable: true) ?? throw new InvalidOperationException("Nobody is signed in at this PC's desktop.");
        using var k = root.CreateSubKey(InternetSettingsKey, writable: true);
        k.SetValue("ProxyEnable", value, RegistryValueKind.DWord);
    }

    public string? GetAdapterDns(string alias)
    {
        if (!SystemSettingsRules.IsAdapterName(alias)) return null;
        using var config = FindAdapterConfiguration(alias);
        if (config?["SettingID"] is not string guid) return null;
        using var lm = OpenLocalMachine();
        using var k = lm.OpenSubKey(TcpipInterfacesKey + guid);
        var servers = k?.GetValue("NameServer") as string ?? "";
        return string.Join(",", servers.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    public void SetAdapterDns(string alias, IReadOnlyList<string> servers)
    {
        if (!SystemSettingsRules.IsAdapterName(alias)) throw new ArgumentException("Invalid network adapter name.", nameof(alias));
        using var config = FindAdapterConfiguration(alias) ?? throw new InvalidOperationException($"No network adapter named '{alias}'.");
        // An empty or null list makes the adapter take its DNS servers from DHCP again.
        var result = config.InvokeMethod("SetDNSServerSearchOrder", [servers.Count == 0 ? null : servers.ToArray()]);
        var code = Convert.ToUInt32(result ?? 0u);
        log.Info($"SetDNSServerSearchOrder '{alias}' [{string.Join(",", servers)}]: {code}");
        if (code is not (0 or 1)) throw new InvalidOperationException($"Windows refused the DNS change (WMI error {code}).");
    }

    /// <summary>The Win32_NetworkAdapterConfiguration of the adapter whose connection name (as in Settings) is <paramref name="alias"/>.</summary>
    private static ManagementObject? FindAdapterConfiguration(string alias)
    {
        var escaped = alias.Replace("\\", "\\\\").Replace("'", "\\'");
        using var adapters = new ManagementObjectSearcher($"SELECT Index FROM Win32_NetworkAdapter WHERE NetConnectionID = '{escaped}'");
        using var adapterResults = adapters.Get();
        foreach (ManagementObject adapter in adapterResults)
        {
            using (adapter)
            {
                if (adapter["Index"] is not uint index) continue;
                using var configs = new ManagementObjectSearcher($"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = {index}");
                using var configResults = configs.Get();
                ManagementObject? found = null;
                foreach (ManagementObject config in configResults)
                {
                    if (found is null) found = config;
                    else config.Dispose();
                }
                if (found is not null) return found;
            }
        }
        return null;
    }

    private static RegistryKey OpenLocalMachine() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

    /// <summary>The signed-in user's HKEY_USERS\&lt;SID&gt; (HKCU when that is this process's own account), or null when nobody is signed in.</summary>
    private RegistryKey? OpenSignedInUserHive(bool writable = false)
    {
        using var user = WindowsMemorySystem.SignedInUser.Open(log);
        if (user is null) return null;
        if (user.IsCurrentProcessUser) return RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
        if (!Core.Optimizations.StoreReinstall.IsValidSid(user.Sid)) { log.Warn($"Signed-in user: unexpected SID {user.Sid}"); return null; }
        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
        return users.OpenSubKey(user.Sid, writable);
    }
}
