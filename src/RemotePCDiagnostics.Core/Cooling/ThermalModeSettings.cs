using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RemotePCDiagnostics.Core.Cooling;

/// <summary>
/// Windows' power mode (Settings, System, Power: Best power efficiency, Balanced, Best performance): the power plan's overlay, read with
/// <c>PowerGetEffectiveOverlayScheme</c> and set with <c>PowerSetActiveOverlayScheme</c> for the power source in use. Windows offers it only
/// on the Balanced plan.
/// </summary>
public static class WindowsPowerMode
{
    public static readonly Guid BestEfficiency = new("961cc777-2547-4f9d-8174-7d86181b8a7a");
    public static readonly Guid Balanced = Guid.Empty;
    /// <summary>Windows 10's "Better performance" position; Windows 11 calls it Balanced. Read, never set.</summary>
    public static readonly Guid BetterPerformance = new("3af9b8d9-7c97-431d-ad78-34a8bfea439f");
    public static readonly Guid BestPerformance = new("ded574b5-45a0-4f42-8737-46345c09c238");
    public static readonly Guid BalancedPlan = new("381b4222-f694-41f0-9685-ff5bb260df2e");

    public static readonly IReadOnlyList<CoolingModeOption> Options =
    [
        new(BestEfficiency.ToString(), "Best power efficiency"),
        new(Balanced.ToString(), "Balanced"),
        new(BestPerformance.ToString(), "Best performance"),
    ];

    public static bool IsKnown(string? id) => Guid.TryParse(id, out var g) && Options.Any(o => Guid.Parse(o.Id) == g);

    public static string Name(Guid g) => g == BetterPerformance ? "Better performance" : Options.FirstOrDefault(o => Guid.Parse(o.Id) == g)?.Name ?? g.ToString();

    /// <summary>The setting as Windows has it: <paramref name="activePlan"/> and the effective overlay.</summary>
    public static CoolingModeGroup Describe(Guid? activePlan, Guid? overlay)
    {
        const string title = "Windows power mode";
        if (activePlan is { } plan && plan != BalancedPlan)
            return new(CoolingModes.WindowsKind, title, overlay?.ToString(), [], "Windows offers power modes only on the Balanced power plan, and this PC uses another plan.");
        if (overlay is null) return new(CoolingModes.WindowsKind, title, null, [], "Windows didn't report its power mode.");
        // Windows 10's middle position reads as Balanced here, so restore puts the same position back.
        var current = overlay == BetterPerformance ? Balanced : overlay.Value;
        return new(CoolingModes.WindowsKind, title, current.ToString(), Options);
    }
}

[SupportedOSPlatform("windows")]
public sealed partial class WindowsPowerModeSetting : IThermalModeSetting
{
    public string Kind => CoolingModes.WindowsKind;

    public CoolingModeGroup? Read()
    {
        Guid? plan = null, overlay = null;
        if (PowerGetActiveScheme(IntPtr.Zero, out var p) == 0 && p != IntPtr.Zero)
        {
            plan = Marshal.PtrToStructure<Guid>(p);
            LocalFree(p);
        }
        if (PowerGetEffectiveOverlayScheme(out var o) == 0) overlay = o;
        return WindowsPowerMode.Describe(plan, overlay);
    }

    public string? Set(string id)
    {
        if (!Guid.TryParse(id, out var g)) return "That isn't a Windows power mode.";
        var rc = PowerSetActiveOverlayScheme(g);
        return rc == 0 ? null : $"Windows refused the power mode (error {rc}).";
    }

    [LibraryImport("powrprof.dll")]
    private static partial uint PowerGetActiveScheme(IntPtr userRootPowerKey, out IntPtr activePolicyGuid);

    [LibraryImport("powrprof.dll")]
    private static partial uint PowerGetEffectiveOverlayScheme(out Guid effectiveOverlayGuid);

    [LibraryImport("powrprof.dll")]
    private static partial uint PowerSetActiveOverlayScheme(Guid overlaySchemeGuid);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr LocalFree(IntPtr mem);
}

/// <summary>The PC maker, from SMBIOS in the registry (readable by anyone): picks which maker setting to ask.</summary>
public static class PcMaker
{
    public const string Hp = "HP", Dell = "Dell", Lenovo = "Lenovo";

    public static string? Normalize(string? manufacturer)
    {
        var m = (manufacturer ?? "").Trim();
        if (m.Equals("HP", StringComparison.OrdinalIgnoreCase) || m.StartsWith("Hewlett", StringComparison.OrdinalIgnoreCase)) return Hp;
        if (m.StartsWith("Dell", StringComparison.OrdinalIgnoreCase)) return Dell;
        if (m.StartsWith("Lenovo", StringComparison.OrdinalIgnoreCase)) return Lenovo;
        return m.Length == 0 ? null : m;
    }

    public static string? Read()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            return Normalize(key?.GetValue("SystemManufacturer") as string);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    /// <summary>The maker's thermal setting for this PC, or one that says why there is none (so the report can name it).</summary>
    [SupportedOSPlatform("windows")]
    public static IThermalModeSetting For(string? maker) => maker switch
    {
        Hp => new HpThermalProfileSetting(new WindowsHpBiosCalls()),
        Dell => new DellThermalManagementSetting(),
        _ => new NoMakerSetting(maker),
    };
}

/// <summary>A maker without a thermal setting Windows can switch: listed with the reason, never switched.</summary>
public sealed class NoMakerSetting(string? maker) : IThermalModeSetting
{
    public string Kind => CoolingModes.MakerKind;

    public CoolingModeGroup? Read() => new(Kind, "Maker thermal mode", null, [],
        maker == PcMaker.Lenovo ? "Lenovo's thermal modes (Fn+Q, Lenovo Vantage) aren't open to other apps, so they can't be switched from here."
        : $"{(maker is { Length: > 0 } ? maker : "This PC's maker")} doesn't offer thermal modes that Windows apps can switch.");

    public string? Set(string id) => "This PC has no maker thermal mode to switch.";
}

/// <summary>
/// HP's thermal profile on consumer PCs (HP Command Center's Balanced, Performance, Cool and Quiet): HP's BIOS WMI interface in
/// <c>root\wmi</c>, query 0x4C, read (command 1) and write (command 2) of one byte. Business PCs and ARM PCs answer "not supported".
/// </summary>
public sealed class HpThermalProfileSetting(IHpBiosCalls bios) : IThermalModeSetting
{
    public const int Query = 0x4C, ReadCommand = 1, WriteCommand = 2;

    /// <summary>The byte values and their names, as HP Command Center shows them.</summary>
    public static readonly IReadOnlyList<CoolingModeOption> Profiles =
    [
        new("1", "Balanced"), new("0", "Performance"), new("2", "Cool"), new("3", "Quiet"),
    ];

    public string Kind => CoolingModes.MakerKind;

    public CoolingModeGroup? Read()
    {
        var (code, data) = bios.Call(ReadCommand, Query, [0, 0, 0, 0]);
        if (code != 0 || data is not { Length: > 0 })
            return new(Kind, "HP thermal profile", null, [], $"This HP doesn't offer thermal profiles to Windows apps ({Describe(code)}).");
        var current = data[0].ToString(System.Globalization.CultureInfo.InvariantCulture);
        return Profiles.Any(p => p.Id == current)
            ? new(Kind, "HP thermal profile", current, Profiles)
            : new(Kind, "HP thermal profile", current, [], $"This HP reported thermal profile {current}, which this app doesn't know, so it isn't switched.");
    }

    public string? Set(string id)
    {
        if (!byte.TryParse(id, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var b) || Profiles.All(p => p.Id != id))
            return "That isn't an HP thermal profile.";
        var (code, _) = bios.Call(WriteCommand, Query, [b, 0, 0, 0]);
        return code == 0 ? null : $"HP's BIOS refused the profile ({Describe(code)}).";
    }

    public static string Describe(int code) => code switch
    {
        0 => "done",
        1 => "wrong signature",
        2 => "unknown command",
        3 or 4 => "not supported",
        5 => "wrong data size",
        -1 => "HP's WMI interface isn't on this PC",
        _ => $"code {code}",
    };
}

/// <summary>HP's BIOS WMI call (<c>hpqBIntM.hpqBIOSInt128</c>), behind an interface so the profile logic can be tested.</summary>
public interface IHpBiosCalls
{
    /// <summary>Return code (0 is done, -1 when the interface is missing) and the data HP's BIOS gave back.</summary>
    (int Code, byte[]? Data) Call(int command, int query, byte[] input);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsHpBiosCalls : IHpBiosCalls
{
    private static readonly byte[] Signature = "SECU"u8.ToArray();

    public (int Code, byte[]? Data) Call(int command, int query, byte[] input)
    {
        try
        {
            var scope = new ManagementScope(@"root\wmi");
            using var inClass = new ManagementClass(scope, new ManagementPath("hpqBDataIn"), null);
            using var data = inClass.CreateInstance();
            data["Sign"] = Signature;
            data["Command"] = (uint)command;
            data["CommandType"] = (uint)query;
            data["Size"] = (uint)input.Length;
            data["hpqBData"] = input;
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM hpqBIntM"));
            using var results = searcher.Get();
            foreach (ManagementObject o in results)
            {
                using (o)
                {
                    using var args = o.GetMethodParameters("hpqBIOSInt128");
                    args["InData"] = data;
                    using var outArgs = o.InvokeMethod("hpqBIOSInt128", args, null);
                    if (outArgs?["OutData"] is not ManagementBaseObject outData) return (-1, null);
                    using (outData)
                        return (Convert.ToInt32(outData["rwReturnCode"] ?? -1, System.Globalization.CultureInfo.InvariantCulture), outData["Data"] as byte[]);
                }
            }
            return (-1, null);
        }
        catch (ManagementException) { return (-1, null); }
        catch (COMException) { return (-1, null); }
    }
}

/// <summary>
/// Dell's "Thermal Management" BIOS setting (Optimized, Cool, Quiet, Ultra Performance), through Dell's BIOS WMI
/// (<c>root\dcim\sysman\biosattributes</c>), which takes effect without a restart. Not switched when a BIOS admin password is set.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DellThermalManagementSetting : IThermalModeSetting
{
    public const string Namespace = @"root\dcim\sysman\biosattributes", Attribute = "ThermalManagement";
    public string Kind => CoolingModes.MakerKind;

    public static string Name(string value) => value switch
    {
        "Optimized" => "Optimized (balanced)",
        "UltraPerformance" => "Ultra performance",
        _ => value,
    };

    public CoolingModeGroup? Read()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(new ManagementScope(Namespace),
                new ObjectQuery($"SELECT AttributeName, CurrentValue, PossibleValue FROM EnumerationAttribute WHERE AttributeName = '{Attribute}'"));
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
            {
                using (o)
                {
                    var current = (o["CurrentValue"] as string[])?.FirstOrDefault() ?? o["CurrentValue"] as string;
                    var options = (o["PossibleValue"] as string[] ?? []).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => new CoolingModeOption(v.Trim(), Name(v.Trim()))).ToList();
                    if (PasswordSet()) return new(Kind, "Dell thermal management", current, [], "A BIOS admin password is set, so Dell's thermal mode can only be changed in BIOS setup.");
                    return new(Kind, "Dell thermal management", current, options);
                }
            }
        }
        catch (ManagementException) { }
        catch (COMException) { }
        return new(Kind, "Dell thermal management", null, [], "This Dell doesn't offer its thermal management setting to Windows apps.");
    }

    private static bool PasswordSet()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(new ManagementScope(@"root\dcim\sysman\wmisecurity"), new ObjectQuery("SELECT NameId, IsPasswordSet FROM PasswordObject WHERE NameId = 'Admin'"));
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
                using (o)
                    return Convert.ToInt64(o["IsPasswordSet"] ?? 0L, System.Globalization.CultureInfo.InvariantCulture) != 0;
        }
        catch (ManagementException) { }
        catch (COMException) { }
        return false;
    }

    public string? Set(string id)
    {
        using var searcher = new ManagementObjectSearcher(new ManagementScope(Namespace), new ObjectQuery("SELECT * FROM BIOSAttributeInterface"));
        using var results = searcher.Get();
        foreach (ManagementObject o in results)
        {
            using (o)
            {
                using var args = o.GetMethodParameters("SetAttribute");
                args["SecType"] = 0u;
                args["SecHndCount"] = 0u;
                args["SecHandle"] = Array.Empty<byte>();
                args["AttributeName"] = Attribute;
                args["AttributeValue"] = id;
                using var outArgs = o.InvokeMethod("SetAttribute", args, null);
                var status = Convert.ToUInt32(outArgs?["Status"] ?? 1u, System.Globalization.CultureInfo.InvariantCulture);
                return status == 0 ? null : $"Dell's BIOS refused the mode (status {status}).";
            }
        }
        return "Dell's BIOS settings interface isn't on this PC.";
    }
}

/// <summary>The Agent's one <see cref="AgentCoolingModes"/> on the PC: Windows' power mode and the maker's thermal setting.</summary>
[SupportedOSPlatform("windows")]
public static class AgentCoolingModesHost
{
    private static AgentCoolingModes? _instance;
    private static readonly object Gate = new();

    public static AgentCoolingModes Instance(ILogger? log = null)
    {
        lock (Gate)
            return _instance ??= new AgentCoolingModes([new WindowsPowerModeSetting(), PcMaker.For(PcMaker.Read())],
                ProtectedState.PathFor(CoolingModes.JournalFile), log);
    }

    public static Osquery.ProcessResult Run(CoolingModesAction action) => Instance().Run(action);

    /// <summary>At the Agent's start: thermal modes a cooling test left changed (a crash or restart mid-test) go back. Never throws.</summary>
    public static void RecoverAtStart(ILogger? log = null)
    {
        try
        {
            if (!File.Exists(ProtectedState.PathFor(CoolingModes.JournalFile))) return;
            Instance(log).RecoverAtStart();
        }
        catch (Exception ex) { log.Warn($"[cooling] Couldn't restore the thermal modes at start: {ex.Message}"); }
    }
}
