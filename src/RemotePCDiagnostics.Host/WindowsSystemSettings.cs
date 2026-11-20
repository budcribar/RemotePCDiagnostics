using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// <see cref="ISystemSettings"/>: Fast Startup and adapter DNS are read here (registry, WMI) and changed by the Agent (<paramref name="admin"/>,
/// over the admin pipe), because they need administrator rights and the app never runs as administrator. The proxy is the signed-in user's
/// setting, so it is read and written here, in their hive (HKEY_USERS\&lt;SID&gt; of the shell's account when that isn't this process's).
/// </summary>
public sealed class WindowsSystemSettings(ILogger? log = null, IAdminSettingsBackend? admin = null) : ISystemSettings
{
    private readonly IAdminSettingsBackend _admin = admin ?? new AgentAdminSettings(null);

    private const string PowerKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Power";
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string TcpipInterfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";

    public int? GetFastStartup()
    {
        using var lm = OpenLocalMachine();
        using var k = lm.OpenSubKey(PowerKey);
        return k?.GetValue("HiberbootEnabled") is int v ? v : null;
    }

    public void SetFastStartup(int value) => _admin.SetFastStartup(value);

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
        using var config = WindowsAdminSettings.FindAdapterConfiguration(alias);
        if (config?["SettingID"] is not string guid) return null;
        using var lm = OpenLocalMachine();
        using var k = lm.OpenSubKey(TcpipInterfacesKey + guid);
        var servers = k?.GetValue("NameServer") as string ?? "";
        return string.Join(",", servers.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    public void SetAdapterDns(string alias, IReadOnlyList<string> servers)
    {
        if (!SystemSettingsRules.IsAdapterName(alias)) throw new ArgumentException("Invalid network adapter name.", nameof(alias));
        _admin.SetAdapterDns(alias, servers);
        log.Info($"DNS on '{alias}' set to [{string.Join(",", servers)}] by the Agent");
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
