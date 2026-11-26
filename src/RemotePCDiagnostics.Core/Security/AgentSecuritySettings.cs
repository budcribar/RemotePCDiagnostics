using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Security;

/// <summary><see cref="AgentScripts.SecurityRead"/>: prints the <see cref="SecurityFixes"/> setting's current value in journal form.</summary>
public sealed record SecurityReadAction(string Key) : AgentNativeAction;

/// <summary><see cref="AgentScripts.SecurityApply"/>: makes the change and reads it back (exit 3 when Windows didn't keep it).</summary>
public sealed record SecurityApplyAction(string Key) : AgentNativeAction;

/// <summary><see cref="AgentScripts.SecurityRestore"/>: puts the setting back to the journaled value (already checked by <see cref="SecurityFixes.ParsePrevious"/>).</summary>
public sealed record SecurityRestoreAction(string Key, SecurityFixes.Previous Previous) : AgentNativeAction;

/// <summary>Defender's settings the Security fixes read (<c>MSFT_MpPreference</c>).</summary>
public sealed record DefenderPreferences(int PuaProtection, int NetworkProtection, IReadOnlyList<string> AsrIds, IReadOnlyList<int> AsrActions, int CloudProtection = 2);

/// <summary>The calls behind the Security fixes (<see cref="WindowsSecuritySettingsStore"/> on Windows, a fake in tests).</summary>
public interface ISecuritySettingsStore
{
    DefenderPreferences ReadDefender();
    /// <summary><c>MSFT_MpPreference.Set</c> with one byte setting (PUAProtection, EnableNetworkProtection, MAPSReporting).</summary>
    void SetDefender(string name, int value);
    void AddAsrRules(IReadOnlyList<string> ids, IReadOnlyList<int> actions);
    void RemoveAsrRules(IReadOnlyList<string> ids);
    /// <summary>A value under HKLM; null when it doesn't exist.</summary>
    long? ReadDword(string key, string name);
    /// <summary>Writes a REG_DWORD under HKLM, creating the key.</summary>
    void WriteDword(string key, string name, long value);
    void DeleteValue(string key, string name);
}

/// <summary>
/// The Security fixes the Agent makes, in C# (they were PowerShell: Get/Set/Add/Remove-MpPreference and the registry cmdlets). Same
/// output and exit codes: the value on stdout for a read, exit 3 when a change didn't stick, exit 1 with Windows' reason on stderr.
/// </summary>
public static class AgentSecuritySettings
{
    public const int NotKeptExitCode = 3;
    private const int AsrEnabled = 1;

    private static ProcessResult Ok(string stdOut = "") => new(0, stdOut, "");

    public static ProcessResult Run(ISecuritySettingsStore store, AgentNativeAction action)
    {
        try
        {
            return action switch
            {
                SecurityReadAction r => Read(store, r.Key),
                SecurityApplyAction a => Apply(store, a.Key),
                SecurityRestoreAction r => Restore(store, r.Key, r.Previous),
                _ => throw new ArgumentException($"{action.GetType().Name} isn't a security setting change.", nameof(action)),
            };
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or IOException
            or System.Security.SecurityException or InvalidOperationException)
        {
            return new ProcessResult(1, "", ex.Message.Trim());
        }
    }

    /// <summary>The registry value behind a policy fix (key without the hive), or null for a Defender one.</summary>
    public static (string Key, string Name)? RegistryValue(string key) => SecurityFixes.Find(key)?.Key switch
    {
        SecurityFixes.Llmnr => (Hklm(SecurityFixes.LlmnrKey), SecurityFixes.LlmnrValue),
        SecurityFixes.AutoRun => (Hklm(SecurityFixes.AutoRunKey), SecurityFixes.AutoRunValue),
        SecurityFixes.GuestLogons => (Hklm(SecurityFixes.GuestKey), SecurityFixes.GuestValue),
        _ => null,
    };

    /// <summary>The value each policy fix writes.</summary>
    private static long AppliedValue(string key) => key == SecurityFixes.AutoRun ? SecurityFixes.AutoRunAllDrives : 0;

    /// <summary>The Defender preference behind a Defender fix (PUA, network protection, and cloud-delivered protection).</summary>
    private static string? DefenderSetting(string key) => key switch
    {
        SecurityFixes.Pua => "PUAProtection",
        SecurityFixes.NetworkProtection => "EnableNetworkProtection",
        SecurityFixes.CloudProtection => "MAPSReporting",
        _ => null,
    };

    /// <summary>The value each Defender fix writes (1 = block/enable, 2 = Advanced MAPS reporting).</summary>
    private static int DefenderAppliedValue(string key) => key == SecurityFixes.CloudProtection ? 2 : 1;

    private static string Hklm(string psPath)
    {
        const string prefix = @"HKLM:\";
        return psPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? psPath[prefix.Length..]
            : throw new InvalidOperationException($"{psPath} isn't under HKLM.");
    }

    private static string Fixed(string key) => SecurityFixes.Find(key)?.Key ?? throw new InvalidOperationException($"'{key}' isn't a security setting this app changes.");

    private static string Number(long n) => n.ToString(CultureInfo.InvariantCulture);

    public static ProcessResult Read(ISecuritySettingsStore store, string key)
    {
        key = Fixed(key);
        if (RegistryValue(key) is { } reg) return Ok(store.ReadDword(reg.Key, reg.Name) is { } v ? Number(v) : "");
        var p = store.ReadDefender();
        return key switch
        {
            SecurityFixes.Pua => Ok(Number(p.PuaProtection)),
            SecurityFixes.NetworkProtection => Ok(Number(p.NetworkProtection)),
            SecurityFixes.CloudProtection => Ok(Number(p.CloudProtection)),
            SecurityFixes.AsrRules => Ok(AsrJournal(p)),
            _ => throw new InvalidOperationException($"'{key}' can't be read here."),
        };
    }

    /// <summary>"guid=action;guid=" for <see cref="SecurityFixes.SafeAsrRules"/>, in their order (empty action = the rule isn't set).</summary>
    public static string AsrJournal(DefenderPreferences p)
    {
        var actions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < p.AsrIds.Count; i++)
            if (!string.IsNullOrEmpty(p.AsrIds[i]) && i < p.AsrActions.Count) actions[p.AsrIds[i]] = p.AsrActions[i];
        return string.Join(';', SecurityFixes.SafeAsrRules.Select(r => r.Id + "=" + (actions.TryGetValue(r.Id, out var a) ? Number(a) : "")));
    }

    public static ProcessResult Apply(ISecuritySettingsStore store, string key)
    {
        key = Fixed(key);
        if (RegistryValue(key) is { } reg)
        {
            store.WriteDword(reg.Key, reg.Name, AppliedValue(key));
            return Ok();
        }
        if (DefenderSetting(key) is { } setting)
        {
            var target = DefenderAppliedValue(key);
            store.SetDefender(setting, target);
            var after = store.ReadDefender();
            var actual = key switch
            {
                SecurityFixes.Pua => after.PuaProtection,
                SecurityFixes.NetworkProtection => after.NetworkProtection,
                SecurityFixes.CloudProtection => after.CloudProtection,
                _ => -1,
            };
            return actual == target ? Ok() : NotKept();
        }
        if (key != SecurityFixes.AsrRules) throw new InvalidOperationException($"'{key}' can't be changed here.");

        var ids = SecurityFixes.SafeAsrRules.Select(r => r.Id).ToList();
        store.AddAsrRules(ids, ids.Select(_ => AsrEnabled).ToList());
        var set = store.ReadDefender().AsrIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return ids.All(set.Contains) ? Ok() : NotKept();
    }

    /// <summary>Tamper Protection or an organization's policy can silently refuse a Defender change.</summary>
    private static ProcessResult NotKept() => new(NotKeptExitCode, "", "Windows didn't keep the change.");

    public static ProcessResult Restore(ISecuritySettingsStore store, string key, SecurityFixes.Previous previous)
    {
        key = Fixed(key);
        if (RegistryValue(key) is { } reg)
        {
            if (previous.Value is { } v) store.WriteDword(reg.Key, reg.Name, v);
            else store.DeleteValue(reg.Key, reg.Name);
            return Ok();
        }
        if (DefenderSetting(key) is { } setting)
        {
            store.SetDefender(setting, (int)(previous.Value ?? throw new InvalidOperationException("No previous value was recorded.")));
            return Ok();
        }
        if (key != SecurityFixes.AsrRules) throw new InvalidOperationException($"'{key}' can't be put back here.");
        foreach (var (id, action) in previous.Rules)
        {
            if (action is { } a) store.AddAsrRules([id], [a]);
            else store.RemoveAsrRules([id]);
        }
        return Ok();
    }
}

/// <summary>Defender through its WMI provider (what the Defender PowerShell module calls) and policy values in the 64-bit registry.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsSecuritySettingsStore : ISecuritySettingsStore
{
    private const string DefenderNamespace = @"root\Microsoft\Windows\Defender";
    private const string PreferenceClass = "MSFT_MpPreference";

    public DefenderPreferences ReadDefender()
    {
        using var searcher = new ManagementObjectSearcher(new ManagementScope(DefenderNamespace), new ObjectQuery("SELECT * FROM " + PreferenceClass));
        using var results = searcher.Get();
        using var o = results.OfType<ManagementObject>().FirstOrDefault();
        if (o is not null)
        {
            return new DefenderPreferences(
                Convert.ToInt32(o["PUAProtection"] ?? 0, CultureInfo.InvariantCulture),
                Convert.ToInt32(o["EnableNetworkProtection"] ?? 0, CultureInfo.InvariantCulture),
                o["AttackSurfaceReductionRules_Ids"] is string[] ids ? ids : [],
                o["AttackSurfaceReductionRules_Actions"] is Array actions
                    ? actions.Cast<object>().Select(a => Convert.ToInt32(a, CultureInfo.InvariantCulture)).ToList() : [],
                Convert.ToInt32(o["MAPSReporting"] ?? 0, CultureInfo.InvariantCulture));
        }
        throw new InvalidOperationException("Microsoft Defender's settings aren't available (Defender may be turned off or replaced by another antivirus).");
    }

    /// <summary>Calls a static <c>MSFT_MpPreference</c> method; its ReturnValue is an HRESULT (0 = done).</summary>
    private static void Invoke(string method, Action<ManagementBaseObject> fill)
    {
        using var cls = new ManagementClass(new ManagementScope(DefenderNamespace), new ManagementPath(PreferenceClass), null);
        using var input = cls.GetMethodParameters(method);
        fill(input);
        using var output = cls.InvokeMethod(method, input, null);
        var hr = output?["ReturnValue"] is { } rv ? Convert.ToUInt32(rv, CultureInfo.InvariantCulture) : 0u;
        if (hr != 0) throw new COMException($"Microsoft Defender refused the change (0x{hr:X8}).", unchecked((int)hr));
    }

    public void SetDefender(string name, int value) => Invoke("Set", p => p[name] = checked((byte)value));

    public void AddAsrRules(IReadOnlyList<string> ids, IReadOnlyList<int> actions) => Invoke("Add", p =>
    {
        p["AttackSurfaceReductionRules_Ids"] = ids.ToArray();
        p["AttackSurfaceReductionRules_Actions"] = actions.Select(a => checked((byte)a)).ToArray();
    });

    public void RemoveAsrRules(IReadOnlyList<string> ids) => Invoke("Remove", p => p["AttackSurfaceReductionRules_Ids"] = ids.ToArray());

    private static RegistryKey Hklm() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

    public long? ReadDword(string key, string name)
    {
        using var root = Hklm();
        using var k = root.OpenSubKey(key);
        return k?.GetValue(name) switch
        {
            null => null,
            int dword => unchecked((uint)dword),
            long qword => qword,
            string s when long.TryParse(s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) => n,
            var other => throw new InvalidOperationException($@"HKLM\{key}\{name} holds {other.GetType().Name}, not a number."),
        };
    }

    public void WriteDword(string key, string name, long value)
    {
        using var root = Hklm();
        using var k = root.CreateSubKey(key, writable: true) ?? throw new UnauthorizedAccessException($@"Can't open HKLM\{key}.");
        k.SetValue(name, unchecked((int)checked((uint)value)), RegistryValueKind.DWord);
    }

    public void DeleteValue(string key, string name)
    {
        using var root = Hklm();
        using var k = root.OpenSubKey(key, writable: true);
        k?.DeleteValue(name, throwOnMissingValue: false);
    }
}
