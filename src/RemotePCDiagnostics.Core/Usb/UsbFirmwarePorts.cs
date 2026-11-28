using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Usb;

/// <summary>One BIOS setting that turns USB or Thunderbolt ports on or off, as the PC maker's WMI provider reports it.</summary>
public sealed record UsbFirmwareSetting(string Name, string Value)
{
    public bool Disabled => UsbFirmwarePorts.IsOff(Value);
}

/// <summary>
/// What the BIOS says about the USB ports. <see cref="Maker"/> is HP, Lenovo or Dell; <see cref="Reason"/> says why nothing was read (another
/// maker, no Agent, the maker's provider missing). <see cref="NeedsAgent"/>: the read needs the Agent and it isn't connected.
/// </summary>
public sealed record UsbFirmwareReading(string? Maker, IReadOnlyList<UsbFirmwareSetting> Settings, string? Reason = null, bool NeedsAgent = false)
{
    public bool Read => Reason is null;
    public IReadOnlyList<UsbFirmwareSetting> Disabled => [.. Settings.Where(s => s.Disabled)];
}

/// <summary>
/// Reads the BIOS settings that turn USB ports off, from the PC maker's WMI provider (HP <c>HP_BIOSEnumeration</c>, Lenovo
/// <c>Lenovo_BiosSetting</c>, Dell <c>EnumerationAttribute</c>). Those classes answer only an administrator, so the read goes through the
/// Agent's WMI (<see cref="WmiQueryPolicy"/>). Read only: changing BIOS settings is out of scope.
/// </summary>
public static class UsbFirmwarePorts
{
    public const string HpNamespace = @"root\HP\InstrumentedBIOS";
    public const string HpSql = "SELECT Name, CurrentValue FROM HP_BIOSEnumeration";
    public const string LenovoNamespace = @"root\WMI";
    public const string LenovoSql = "SELECT CurrentSetting FROM Lenovo_BiosSetting";
    public const string DellNamespace = @"root\dcim\sysman\biosattributes";
    public const string DellSql = "SELECT AttributeName, DisplayName, CurrentValue FROM EnumerationAttribute";

    public static readonly RegistryRead MakerRead = new(RegistryRoot.LocalMachine, @"HARDWARE\DESCRIPTION\System\BIOS", ["SystemManufacturer"]);

    private static readonly string[] PortWords = ["usb", "thunderbolt", "type-c", "typec"];
    private static readonly string[] SettingWords = ["port", "access", "connector"];
    // Settings that mention USB ports but don't turn them off: wake, charging, boot, legacy keyboards, provisioning, debug.
    private static readonly string[] NotPortSwitches =
        ["wake", "legacy", "charg", "boot", "power", "provision", "emulation", "debug", "security", "pxe", "ucsi", "always", "restrict", "storage class"];

    /// <summary>A BIOS setting that turns USB or Thunderbolt ports on or off ("USB Port", "Rear USB Ports", "USBPortAccess", "UsbPortsFront").</summary>
    public static bool IsPortSetting(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        return PortWords.Any(w => name.Contains(w, StringComparison.OrdinalIgnoreCase))
            && SettingWords.Any(w => name.Contains(w, StringComparison.OrdinalIgnoreCase))
            && !NotPortSwitches.Any(w => name.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsOff(string? value) =>
        value?.Trim().ToLowerInvariant() is "disable" or "disabled" or "off" or "no" or "false";

    /// <summary>HP, Lenovo or Dell from the SMBIOS manufacturer; null for any other maker.</summary>
    public static string? Maker(string? manufacturer)
    {
        var m = (manufacturer ?? "").Trim();
        if (m.Equals("HP", StringComparison.OrdinalIgnoreCase) || m.StartsWith("Hewlett", StringComparison.OrdinalIgnoreCase)) return "HP";
        if (m.StartsWith("Lenovo", StringComparison.OrdinalIgnoreCase)) return "Lenovo";
        if (m.StartsWith("Dell", StringComparison.OrdinalIgnoreCase)) return "Dell";
        return null;
    }

    public static async Task<UsbFirmwareReading> ReadAsync(IWmiSource wmi, IRegistrySource registry, CancellationToken ct)
    {
        var reg = await registry.ReadAsync(MakerRead, ct).ConfigureAwait(false);
        var manufacturer = reg.Rows?.Select(r => r.Str("SystemManufacturer")).FirstOrDefault(s => s.Length > 0);
        var maker = Maker(manufacturer);
        if (maker is null)
            return new(null, [], manufacturer is null ? "The PC maker couldn't be read." : $"Reading BIOS settings isn't supported on {manufacturer.Trim()} PCs (only HP, Lenovo and Dell).");
        var (ns, sql) = maker switch { "HP" => (HpNamespace, HpSql), "Lenovo" => (LenovoNamespace, LenovoSql), _ => (DellNamespace, DellSql) };
        var q = await wmi.QueryAsync(ns, sql, ct).ConfigureAwait(false);
        if (!q.Success)
        {
            var needsAgent = q.Error?.Contains(AgentWmiSource.NotConnected, StringComparison.Ordinal) == true
                || q.Error?.Contains("Access denied", StringComparison.OrdinalIgnoreCase) == true;
            return new(maker, [], needsAgent ? "Needs the Agent: BIOS settings can only be read with administrator rights."
                : $"{maker}'s BIOS settings couldn't be read: {q.Error}", needsAgent);
        }
        var settings = maker switch
        {
            "HP" => q.Rows!.Select(r => new UsbFirmwareSetting(r.Str("Name").Trim(), r.Str("CurrentValue").Trim())),
            "Lenovo" => q.Rows!.Select(r => Lenovo(r.Str("CurrentSetting"))).OfType<UsbFirmwareSetting>(),
            _ => q.Rows!.Select(r => new UsbFirmwareSetting(
                r.Str("DisplayName").Trim() is { Length: > 0 } d ? d : r.Str("AttributeName").Trim(), First(r, "CurrentValue"))),
        };
        return new(maker, [.. settings.Where(s => IsPortSetting(s.Name)).DistinctBy(s => s.Name, StringComparer.OrdinalIgnoreCase)]);
    }

    /// <summary>Lenovo's "Name,Value" (sometimes "Name,Value;[Optional:...]"); null when it isn't that shape.</summary>
    public static UsbFirmwareSetting? Lenovo(string? currentSetting)
    {
        if (string.IsNullOrWhiteSpace(currentSetting)) return null;
        var comma = currentSetting.IndexOf(',');
        if (comma <= 0) return null;
        var value = currentSetting[(comma + 1)..];
        var semi = value.IndexOf(';');
        if (semi >= 0) value = value[..semi];
        return new(currentSetting[..comma].Trim(), value.Trim());
    }

    /// <summary>The first string of a WMI string array (Dell's CurrentValue), or the value itself.</summary>
    private static string First(WmiRow r, string name)
    {
        if (!r.Values.TryGetValue(name, out var v)) return "";
        if (v.ValueKind == System.Text.Json.JsonValueKind.Array)
            return v.EnumerateArray().Where(e => e.ValueKind == System.Text.Json.JsonValueKind.String).Select(e => e.GetString()!.Trim()).FirstOrDefault() ?? "";
        return v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString()!.Trim() : "";
    }
}
