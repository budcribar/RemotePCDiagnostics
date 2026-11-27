using System.Management;
using System.Runtime.Versioning;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Battery;

/// <summary>One of HP's battery charging BIOS settings, as HP's WMI provider reports it: its value now and the values it can take.</summary>
public sealed record HpBatterySetting(string Name, string CurrentValue, IReadOnlyList<string> PossibleValues)
{
    /// <summary>The value that stops charging at about 80%, or null when this setting has none.</summary>
    public string? LimitValue => HpBatteryCharge.LimitValue(Name, PossibleValues);

    /// <summary>True when charging is already limited.</summary>
    public bool IsLimited => HpBatteryCharge.IsLimitValue(Name, CurrentValue);
}

/// <summary>
/// HP's battery charge limit, a BIOS setting in HP's WMI provider (<c>root\HP\InstrumentedBIOS</c>): "Battery Health Manager" on
/// business PCs (set to "Maximize my battery health" it stops charging at about 80%), "Battery Care Function" on others ("80%"). A PC
/// that stays plugged in at 100% wears its battery faster. The app reads it through the Agent's WMI; the Agent changes it
/// (<c>HP_BIOSSettingInterface.SetBIOSSetting</c>), only to a value the setting lists, and never when a BIOS setup password is set.
/// </summary>
public static class HpBatteryCharge
{
    public const string Namespace = @"root\HP\InstrumentedBIOS";
    public const string HealthManager = "Battery Health Manager";
    public const string CareFunction = "Battery Care Function";
    public const string ReadSql = "SELECT Name, CurrentValue, PossibleValues FROM HP_BIOSEnumeration WHERE Name = 'Battery Health Manager' OR Name = 'Battery Care Function'";
    public const int MaxValueLength = 80;
    /// <summary>HP's WMI password argument with no password (the encoding tag and nothing after it).</summary>
    public const string NoPassword = "<utf-16/>";

    public static bool IsSetting(string? name) => name is HealthManager or CareFunction;

    /// <summary>True when the SMBIOS manufacturer (in the registry, readable by any user) is HP, so other PCs never ask HP's provider.</summary>
    public static bool IsHpPc()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            var maker = (key?.GetValue("SystemManufacturer") as string ?? "").Trim();
            return maker.Equals("HP", StringComparison.OrdinalIgnoreCase) || maker.StartsWith("Hewlett", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return false; }
    }

    /// <summary>A value as the Agent accepts one from the app (it also checks the setting lists it).</summary>
    public static bool IsValue(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaxValueLength && !value.Any(char.IsControl);

    public static string? LimitValue(string name, IReadOnlyList<string> possible) => name switch
    {
        CareFunction => possible.FirstOrDefault(v => v.Trim() == "80%"),
        HealthManager => possible.FirstOrDefault(v => v.Contains("battery health", StringComparison.OrdinalIgnoreCase)),
        _ => null,
    };

    public static bool IsLimitValue(string name, string value) => name switch
    {
        CareFunction => value.Trim() is "80%" or "50%",
        HealthManager => value.Contains("battery health", StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    /// <summary>The HP charging settings this PC has: empty when none or unreadable (not an HP, or HP's provider isn't there).</summary>
    public static async Task<IReadOnlyList<HpBatterySetting>> ReadAsync(IWmiSource wmi, CancellationToken ct)
    {
        var q = await wmi.QueryAsync(Namespace, ReadSql, ct).ConfigureAwait(false);
        if (!q.Success) return [];
        return q.Rows!.Select(r => new HpBatterySetting(r.Str("Name"), r.Str("CurrentValue"), Strings(r, "PossibleValues")))
            .Where(s => IsSetting(s.Name) && s.PossibleValues.Count > 0).ToList();
    }

    private static List<string> Strings(WmiRow r, string name) =>
        r.Values.TryGetValue(name, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.Array
            ? v.EnumerateArray().Where(e => e.ValueKind == System.Text.Json.JsonValueKind.String).Select(e => e.GetString()!.Trim()).Where(s => s.Length > 0).ToList()
            : [];

    /// <summary>The fix's target: the setting and the value to set ("Battery Health Manager|Maximize my battery health").</summary>
    public static string Target(string name, string value) => name + "|" + value;

    public static bool TryParseTarget(string? target, out string name, out string value)
    {
        name = value = "";
        var bar = target?.IndexOf('|') ?? -1;
        if (bar <= 0) return false;
        name = target![..bar];
        value = target[(bar + 1)..];
        return IsSetting(name) && IsValue(value);
    }

    /// <summary>What HP's <c>SetBIOSSetting</c> return code means.</summary>
    public static string DescribeReturn(uint code) => code switch
    {
        1 => "this PC's BIOS doesn't support the setting",
        2 => "the BIOS reported an unspecified error",
        3 => "the BIOS timed out",
        4 => "the BIOS refused the change",
        5 => "the BIOS rejected the value",
        6 => "the BIOS denied access (a BIOS password may be set)",
        _ => $"the BIOS returned {code}",
    };
}

/// <summary><see cref="AgentScripts.HpBatteryRead"/>: prints the setting's current value (journaled before the change).</summary>
public sealed record HpBatteryReadAction(string Name) : AgentNativeAction;

/// <summary><see cref="AgentScripts.HpBatterySet"/>: sets the setting to <paramref name="Value"/>, one of the values it lists.</summary>
public sealed record HpBatterySetAction(string Name, string Value) : AgentNativeAction;

/// <summary>HP's BIOS settings provider, behind an interface so the Agent's checks can be tested.</summary>
public interface IHpBiosSettings
{
    /// <summary>The setting, or null when this PC doesn't have it.</summary>
    HpBatterySetting? Read(string name);
    /// <summary>True when a BIOS setup (administrator) password is set.</summary>
    bool SetupPasswordSet();
    /// <summary>Calls <c>SetBIOSSetting</c>; returns its return code (0 = done).</summary>
    uint Set(string name, string value);
}

/// <summary>What the Agent does for the two actions, answering like its other changes (exit 0, else exit 1 and why).</summary>
public static class AgentHpBatteryCharge
{
    public static ProcessResult Run(IHpBiosSettings bios, AgentNativeAction action)
    {
        try
        {
            switch (action)
            {
                case HpBatteryReadAction read:
                    return bios.Read(read.Name) is { } s ? new(0, s.CurrentValue, "") : new(1, "", $"This PC has no \"{read.Name}\" BIOS setting.");
                case HpBatterySetAction set:
                    if (bios.Read(set.Name) is not { } current) return new(1, "", $"This PC has no \"{set.Name}\" BIOS setting.");
                    if (!current.PossibleValues.Contains(set.Value, StringComparer.Ordinal))
                        return new(1, "", $"\"{set.Value}\" isn't a value \"{set.Name}\" can take.");
                    if (current.CurrentValue == set.Value) return new(0, "", "");
                    if (bios.SetupPasswordSet())
                        return new(1, "", "A BIOS setup password is set on this PC, so the setting can only be changed in BIOS setup (F10 at startup).");
                    var code = bios.Set(set.Name, set.Value);
                    return code == 0 ? new(0, "", "") : new(1, "", $"Couldn't change \"{set.Name}\": {HpBatteryCharge.DescribeReturn(code)}.");
                default:
                    throw new ArgumentException($"{action.GetType().Name} isn't an HP battery setting change.", nameof(action));
            }
        }
        catch (Exception ex) when (ex is ManagementException or System.Runtime.InteropServices.COMException or UnauthorizedAccessException)
        {
            return new(1, "", "HP's BIOS settings couldn't be read (HP's WMI provider didn't answer): " + ex.Message.Trim());
        }
    }
}

/// <summary>HP's WMI provider on the PC (in the Agent, which has the administrator rights it needs).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsHpBiosSettings : IHpBiosSettings
{
    private static ManagementScope Scope() => new(HpBatteryCharge.Namespace);

    private static string Quote(string s) => s.Replace("\\", "\\\\").Replace("'", "\\'");

    public HpBatterySetting? Read(string name)
    {
        using var searcher = new ManagementObjectSearcher(Scope(),
            new ObjectQuery($"SELECT Name, CurrentValue, PossibleValues FROM HP_BIOSEnumeration WHERE Name = '{Quote(name)}'"));
        using var results = searcher.Get();
        foreach (ManagementBaseObject o in results)
            using (o)
                return new(name, (o["CurrentValue"] as string ?? "").Trim(),
                    (o["PossibleValues"] as string[] ?? []).Select(v => v.Trim()).Where(v => v.Length > 0).ToList());
        return null;
    }

    public bool SetupPasswordSet()
    {
        using var searcher = new ManagementObjectSearcher(Scope(), new ObjectQuery("SELECT Name, IsSet FROM HP_BIOSPassword WHERE Name = 'Setup Password'"));
        using var results = searcher.Get();
        foreach (ManagementBaseObject o in results)
            using (o)
                return Convert.ToInt64(o["IsSet"] ?? 0L, System.Globalization.CultureInfo.InvariantCulture) != 0;
        return false;
    }

    public uint Set(string name, string value)
    {
        using var searcher = new ManagementObjectSearcher(Scope(), new ObjectQuery("SELECT * FROM HP_BIOSSettingInterface"));
        using var results = searcher.Get();
        foreach (ManagementObject o in results)
        {
            using (o)
            {
                using var args = o.GetMethodParameters("SetBIOSSetting");
                args["Name"] = name;
                args["Value"] = value;
                args["Password"] = HpBatteryCharge.NoPassword;
                using var outArgs = o.InvokeMethod("SetBIOSSetting", args, null);
                return Convert.ToUInt32(outArgs?["Return"] ?? 4u, System.Globalization.CultureInfo.InvariantCulture);
            }
        }
        throw new ManagementException("HP_BIOSSettingInterface isn't on this PC.");
    }
}
