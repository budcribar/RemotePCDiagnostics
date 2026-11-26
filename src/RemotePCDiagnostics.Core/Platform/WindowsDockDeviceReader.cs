using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// In-process dock / peripheral device reader using WMI and <c>cfgmgr32.dll</c> (<c>DEVPKEY_Device_ContainerId</c>),
/// replacing <c>DockDevices.ps1</c>.
/// </summary>
public static partial class WindowsDockDeviceReader
{
    private const uint CrSuccess = 0;
    private const uint CmLocateDevNodeNormal = 0;
    private const uint DevPropTypeGuid = 0x0000000D;

    // DEVPKEY_Device_ContainerId: {8C7ED206-3F8A-4827-B3AB-AE9E1FAEFC6C}, pid 2
    private static readonly DevPropKey DevpkeyDeviceContainerId = new(
        new Guid("8C7ED206-3F8A-4827-B3AB-AE9E1FAEFC6C"), 2);

    [GeneratedRegex(@"_\d+$", RegexOptions.CultureInvariant)]
    private static partial Regex MonitorInstanceSuffixRegex();

    /// <summary>Maps <c>WmiMonitorConnectionParams.VideoOutputTechnology</c> to the display connection label.</summary>
    public static string? FormatVideoOutputTechnology(long technology) => technology switch
    {
        6 or 11 or 13 or 2147483648 => "Built-in display",
        0 => "VGA",
        4 => "DVI",
        5 => "HDMI",
        10 => "External DisplayPort",
        15 => "Miracast",
        16 => "Indirect wired display",
        _ => null,
    };

    /// <summary>Normalizes a <c>WmiMonitorConnectionParams.InstanceName</c> by stripping the trailing <c>_N</c> suffix.</summary>
    public static string NormalizeMonitorInstanceName(string instanceName) =>
        MonitorInstanceSuffixRegex().Replace(instanceName, "");

    /// <summary>Reads present Display, USB hub, physical Ethernet, and Audio endpoint devices on Windows.</summary>
    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<DockDevice> Read(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var usbHubs = ReadIdSet(@"root\cimv2", "SELECT PNPDeviceID FROM Win32_USBHub", "PNPDeviceID", ct);
        var ethernet = ReadPhysicalEthernetIds(ct);
        var monitors = ReadMonitorConnections(ct);

        var devices = new List<DockDevice>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT PNPDeviceID, PNPClass, Name, Status FROM Win32_PnPEntity " +
            "WHERE Present = TRUE AND (PNPClass = 'Monitor' OR PNPClass = 'USB' OR PNPClass = 'Net' OR PNPClass = 'AudioEndpoint')");
        using var results = searcher.Get();
        foreach (ManagementBaseObject o in results)
        {
            ct.ThrowIfCancellationRequested();
            using (o)
            {
                var id = o["PNPDeviceID"]?.ToString();
                var pnpClass = o["PNPClass"]?.ToString();
                if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(pnpClass))
                    continue;

                var kind = pnpClass switch
                {
                    "Monitor" when id.StartsWith(@"DISPLAY\", StringComparison.OrdinalIgnoreCase) => "Display",
                    "USB" when usbHubs.Contains(id) => "USB hub",
                    "Net" when ethernet.Contains(id) => "Ethernet",
                    "AudioEndpoint" => "Audio endpoint",
                    _ => null,
                };
                if (kind is null) continue;

                var name = o["Name"]?.ToString();
                if (string.IsNullOrWhiteSpace(name)) name = kind;
                var status = o["Status"]?.ToString() ?? "";
                var container = TryReadContainerId(id);

                bool? active = null;
                string? connection = null;
                if (kind == "Display" && monitors.TryGetValue(id, out var mon))
                {
                    active = mon.Active;
                    connection = mon.Connection;
                }

                devices.Add(new DockDevice(id, kind, name, status, container, active, connection));
            }
        }

        return devices;
    }

    [SupportedOSPlatform("windows")]
    private static HashSet<string> ReadIdSet(string ns, string query, string prop, CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(new ManagementScope(ns), new ObjectQuery(query));
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
            {
                ct.ThrowIfCancellationRequested();
                using (o)
                {
                    if (o[prop]?.ToString() is { Length: > 0 } id)
                        set.Add(id);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
        return set;
    }

    [SupportedOSPlatform("windows")]
    private static HashSet<string> ReadPhysicalEthernetIds(CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"root\StandardCimv2"),
                new ObjectQuery("SELECT PnPDeviceID, NdisPhysicalMedium, MediaType FROM MSFT_NetAdapter WHERE HardwareInterface = TRUE"));
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
            {
                ct.ThrowIfCancellationRequested();
                using (o)
                {
                    var medium = o["NdisPhysicalMedium"] is { } m ? Convert.ToInt32(m, CultureInfo.InvariantCulture) : -1;
                    var mediaType = o["MediaType"]?.ToString();
                    if (medium == 14 || string.Equals(mediaType, "802.3", StringComparison.OrdinalIgnoreCase))
                    {
                        if (o["PnPDeviceID"]?.ToString() is { Length: > 0 } id)
                            set.Add(id);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
        return set;
    }

    [SupportedOSPlatform("windows")]
    private static Dictionary<string, (bool? Active, string? Connection)> ReadMonitorConnections(CancellationToken ct)
    {
        var map = new Dictionary<string, (bool? Active, string? Connection)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"root\wmi"),
                new ObjectQuery("SELECT InstanceName, Active, VideoOutputTechnology FROM WmiMonitorConnectionParams"));
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
            {
                ct.ThrowIfCancellationRequested();
                using (o)
                {
                    var rawName = o["InstanceName"]?.ToString();
                    if (string.IsNullOrEmpty(rawName)) continue;
                    var key = NormalizeMonitorInstanceName(rawName);
                    if (map.ContainsKey(key)) continue;
                    bool? active = o["Active"] is bool b ? b : null;
                    string? conn = o["VideoOutputTechnology"] is { } tech
                        ? FormatVideoOutputTechnology(Convert.ToInt64(tech, CultureInfo.InvariantCulture))
                        : null;
                    map[key] = (active, conn);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
        return map;
    }

    [SupportedOSPlatform("windows")]
    private static string? TryReadContainerId(string deviceInstanceId)
    {
        try
        {
            if (CM_Locate_DevNodeW(out var devInst, deviceInstanceId, CmLocateDevNodeNormal) != CrSuccess)
                return null;
            var buffer = new byte[16];
            uint size = (uint)buffer.Length;
            var key = DevpkeyDeviceContainerId;
            if (CM_Get_DevNode_PropertyW(devInst, in key, out var propType, buffer, ref size, 0) != CrSuccess)
                return null;
            if (propType != DevPropTypeGuid || size != 16)
                return null;
            return new Guid(buffer).ToString("B");
        }
        catch
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DevPropKey(Guid fmtid, uint pid)
    {
        public Guid FmtId = fmtid;
        public uint Pid = pid;
    }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CM_Locate_DevNodeW(out uint pdnDevInst, string pDeviceID, uint ulFlags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CM_Get_DevNode_PropertyW(
        uint dnDevInst,
        in DevPropKey propertyKey,
        out uint propertyType,
        [Out] byte[] propertyBuffer,
        ref uint propertyBufferSize,
        uint ulFlags);
}
