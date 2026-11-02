using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Npu;

/// <summary>Turns raw PnP rows and DXCore adapters into a de-duplicated NPU list. Pure logic, unit-tested.</summary>
public static partial class NpuDetection
{
    /// <summary>Windows device setup class "ComputeAccelerator" (MCDM NPUs register here).</summary>
    public static readonly Guid ComputeAcceleratorClassGuid = new("f01a9d53-3ff6-48d2-9f97-c8a7004be10c");

    [GeneratedRegex(@"\bNPU\b|Neural Process|AI Boost|Hexagon|Ryzen AI|\bIPU\b", RegexOptions.IgnoreCase)]
    private static partial Regex NpuNameRegex();

    [GeneratedRegex(@"VEN_([0-9A-F]{4})|^ACPI\\([A-Z]{3,4})", RegexOptions.IgnoreCase)]
    private static partial Regex VendorRegex();

    /// <summary>True for a PnP device that looks like an NPU: in the ComputeAccelerator class, or named like one (any class, e.g. System).</summary>
    public static bool IsNpuCandidate(PnpRow r)
    {
        if (string.Equals(r.PnpClass, "ComputeAccelerator", StringComparison.OrdinalIgnoreCase)) return true;
        if (Guid.TryParse(r.ClassGuid, out var g) && g == ComputeAcceleratorClassGuid) return true;
        var name = r.Name ?? "";
        if (name.Length == 0) return false;
        // Avoid "Display" GPUs and audio co-processors that merely mention AI in marketing names.
        if (string.Equals(r.PnpClass, "Display", StringComparison.OrdinalIgnoreCase)) return false;
        return NpuNameRegex().IsMatch(name);
    }

    /// <summary>"Intel", "AMD", "Qualcomm", or the manufacturer string, from PCI vendor id or ACPI prefix.</summary>
    public static string VendorOf(string? deviceId, string? manufacturer, string? name)
    {
        var m = VendorRegex().Match(deviceId ?? "");
        var code = m.Success ? (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).ToUpperInvariant() : "";
        var v = code switch
        {
            "8086" or "INTC" => "Intel",
            "1022" or "1002" or "AMDI" => "AMD",
            "17CB" or "QCOM" or "QCOMM" => "Qualcomm",
            _ => null,
        };
        if (v is not null) return v;
        var s = (manufacturer ?? "") + " " + (name ?? "");
        if (s.Contains("Intel", StringComparison.OrdinalIgnoreCase)) return "Intel";
        if (s.Contains("AMD", StringComparison.OrdinalIgnoreCase) || s.Contains("Advanced Micro", StringComparison.OrdinalIgnoreCase)) return "AMD";
        if (s.Contains("Qualcomm", StringComparison.OrdinalIgnoreCase) || s.Contains("Hexagon", StringComparison.OrdinalIgnoreCase)) return "Qualcomm";
        return string.IsNullOrWhiteSpace(manufacturer) ? "Unknown" : manufacturer.Trim();
    }

    public static string VendorOf(uint pciVendorId) => pciVendorId switch
    {
        0x8086 => "Intel", 0x1022 or 0x1002 => "AMD", 0x17CB or 0x5143 => "Qualcomm", _ => $"0x{pciVendorId:X4}",
    };

    /// <summary>DXCore packs the driver version as four 16-bit parts (like DXGI's UMD version).</summary>
    public static string FormatDriverVersion(ulong v) => $"{v >> 48 & 0xFFFF}.{v >> 32 & 0xFFFF}.{v >> 16 & 0xFFFF}.{v & 0xFFFF}";

    /// <summary>DXCore adapters that are NPUs: the NPU hardware-type attribute, or (older Windows without it) an ML-capable hardware adapter without graphics.</summary>
    public static bool IsNpuAdapter(DxCoreAdapterRow a) => a.IsHardware && (a.IsNpuHardwareType || (!a.SupportsGraphics && a.SupportsGenericMl));

    public static NpuComputeLevel LevelOf(DxCoreAdapterRow a) =>
        a.SupportsCoreCompute ? NpuComputeLevel.CoreCompute : a.SupportsGenericMl ? NpuComputeLevel.GenericMl : NpuComputeLevel.None;

    /// <summary>PnP candidates merged with NPU DXCore adapters (matched by PCI vendor+device id, else by vendor when there is one of each).</summary>
    public static IReadOnlyList<NpuDevice> Merge(IEnumerable<PnpRow> pnp, IEnumerable<DxCoreAdapterRow> adapters)
    {
        var dx = adapters.Where(IsNpuAdapter).ToList();
        var used = new HashSet<long>();
        var list = new List<NpuDevice>();
        foreach (var r in pnp.Where(IsNpuCandidate))
        {
            var vendor = VendorOf(r.DeviceId, r.Manufacturer, r.Name);
            var ids = string.Join(" ", new[] { r.DeviceId ?? "" }.Concat(r.HardwareIds ?? []));
            var match = dx.FirstOrDefault(a => !used.Contains(a.Luid) && ids.Contains($"VEN_{a.VendorId:X4}&DEV_{a.DeviceId:X4}", StringComparison.OrdinalIgnoreCase))
                ?? (dx.Count(a => !used.Contains(a.Luid) && VendorOf(a.VendorId) == vendor) == 1 ? dx.First(a => !used.Contains(a.Luid) && VendorOf(a.VendorId) == vendor) : null);
            if (match is not null) used.Add(match.Luid);
            list.Add(new NpuDevice(r.DeviceId ?? r.Name ?? "?", (r.Name ?? match?.Description ?? "NPU").Trim(), vendor,
                r.DriverVersion ?? (match is null ? null : FormatDriverVersion(match.DriverVersion)), r.Status, r.ConfigManagerErrorCode,
                match is null ? NpuSource.PnP : NpuSource.Both, r.HardwareIds?.FirstOrDefault(), match?.Luid, match is null ? NpuComputeLevel.Unknown : LevelOf(match)));
        }
        foreach (var a in dx.Where(a => !used.Contains(a.Luid)))
        {
            list.Add(new NpuDevice($"dxcore:{a.Luid:X}", a.Description.Trim(), VendorOf(a.VendorId), FormatDriverVersion(a.DriverVersion), "OK", 0,
                NpuSource.DXCore, $"PCI\\VEN_{a.VendorId:X4}&DEV_{a.DeviceId:X4}", a.Luid, LevelOf(a)));
        }
        return list;
    }

    /// <summary>Plain-language text for common Device Manager problem codes.</summary>
    public static string ProblemText(int code) => code switch
    {
        0 => "Working properly",
        1 => "Not configured correctly (code 1)",
        3 => "Driver may be corrupted (code 3)",
        10 => "Device cannot start (code 10)",
        12 => "Not enough free resources (code 12)",
        18 => "Drivers need reinstalling (code 18)",
        19 => "Registry configuration damaged (code 19)",
        21 => "Windows is removing this device (code 21)",
        22 => "Device is disabled (code 22)",
        24 => "Device not present or not all drivers installed (code 24)",
        28 => "Drivers are not installed (code 28)",
        29 => "Disabled by firmware (code 29)",
        31 => "Windows cannot load the drivers (code 31)",
        32 => "Driver service disabled (code 32)",
        37 => "Driver failed to initialise (code 37)",
        39 => "Driver is corrupted or missing (code 39)",
        43 => "Windows stopped this device after it reported problems (code 43)",
        45 => "Device not connected (code 45)",
        48 => "Driver blocked from starting (code 48)",
        52 => "Driver signature can't be verified (code 52)",
        _ => $"Device problem (code {code})",
    };
}
