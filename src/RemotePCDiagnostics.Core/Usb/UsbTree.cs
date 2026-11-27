using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Usb;

/// <summary>Where a node sits in the USB tree.</summary>
public enum UsbNodeKind { Controller, RootHub, Hub, Device, Function }

/// <summary>The speed a USB link runs at, as the hub reports it (<c>USB_DEVICE_SPEED</c>, plus SuperSpeed+ from the V2 flags).</summary>
public enum UsbSpeed { Unknown, Low, Full, High, Super, SuperPlus }

/// <summary>
/// One downstream port of a hub, as the hub driver reports it (<c>IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX</c>, <c>_EX_V2</c> and
/// <c>IOCTL_USB_GET_PORT_CONNECTOR_PROPERTIES</c>). <see cref="Status"/> is <c>USB_CONNECTION_STATUS</c> by name: NoDeviceConnected,
/// DeviceConnected, DeviceFailedEnumeration, DeviceGeneralFailure, DeviceCausedOvercurrent, DeviceNotEnoughPower, DeviceNotEnoughBandwidth,
/// DeviceHubNestedTooDeeply, DeviceInLegacyHub, DeviceEnumerating, DeviceReset.
/// </summary>
public sealed record UsbPortInfo(
    int Number,
    string Status,
    UsbSpeed Speed = UsbSpeed.Unknown,
    bool DeviceIsHub = false,
    bool? SuperSpeedCapable = null,
    bool? AtSuperSpeed = null,
    bool? SuperSpeedPlusCapable = null,
    bool? AtSuperSpeedPlus = null,
    bool? UserConnectable = null,
    bool? TypeC = null,
    int? BcdUsb = null,
    string? Vid = null,
    string? Pid = null,
    /// <summary>The port on the other hub that shares this connector (a USB 3 port's USB 2 companion), when the hub reports one.</summary>
    int? CompanionPort = null)
{
    public bool HasDevice => Status is not (UsbPortStatus.NoDevice or "");

    /// <summary>The device connected at a speed below what it can do (a USB 3 device on a USB 2 link).</summary>
    public bool SpeedDowngraded =>
        HasDevice && (SuperSpeedCapable == true && AtSuperSpeed == false || SuperSpeedPlusCapable == true && AtSuperSpeedPlus == false && AtSuperSpeed == true);
}

/// <summary><c>USB_CONNECTION_STATUS</c> names.</summary>
public static class UsbPortStatus
{
    public const string NoDevice = "NoDeviceConnected";
    public const string Connected = "DeviceConnected";
    public const string FailedEnumeration = "DeviceFailedEnumeration";
    public const string GeneralFailure = "DeviceGeneralFailure";
    public const string Overcurrent = "DeviceCausedOvercurrent";
    public const string NotEnoughPower = "DeviceNotEnoughPower";
    public const string NotEnoughBandwidth = "DeviceNotEnoughBandwidth";
    public const string NestedTooDeeply = "DeviceHubNestedTooDeeply";
    public const string InLegacyHub = "DeviceInLegacyHub";
    public const string Enumerating = "DeviceEnumerating";
    public const string Reset = "DeviceReset";

    private static readonly string[] Names =
        [NoDevice, Connected, FailedEnumeration, GeneralFailure, Overcurrent, NotEnoughPower, NotEnoughBandwidth, NestedTooDeeply, InLegacyHub, Enumerating, Reset];

    /// <summary>The name of a <c>USB_CONNECTION_STATUS</c> value; unknown values keep their number.</summary>
    public static string Name(int value) => value >= 0 && value < Names.Length ? Names[value] : "Status" + value;

    /// <summary>A status that means the port or the device on it failed.</summary>
    public static bool IsFailure(string status) =>
        status is FailedEnumeration or GeneralFailure or Overcurrent or NotEnoughPower or NotEnoughBandwidth or NestedTooDeeply;

    /// <summary>Plain words for a failing status.</summary>
    public static string Describe(string status) => status switch
    {
        FailedEnumeration => "Windows couldn't identify the device (failed enumeration)",
        GeneralFailure => "The port reported a general failure",
        Overcurrent => "The device drew too much power (over-current)",
        NotEnoughPower => "Not enough power on this port for the device",
        NotEnoughBandwidth => "Not enough USB bandwidth for the device",
        NestedTooDeeply => "Too many hubs chained together",
        InLegacyHub => "A fast device behind an older hub",
        Reset => "The port is resetting",
        Enumerating => "The device is still being set up",
        Connected => "Connected",
        NoDevice => "Empty",
        _ => status,
    };
}

/// <summary>
/// One node of the USB part of the Windows device tree (configuration manager): a host controller, a hub, a device, or a function a
/// device exposes (a keyboard, a network adapter, an audio device). <see cref="Port"/> is the device's port on its parent hub
/// (<c>DEVPKEY_Device_Address</c>); <see cref="Ports"/> is a hub's own ports.
/// </summary>
public sealed record UsbNode(
    // Named as device instance paths elsewhere, so the recording scrubber replaces a serial in them the same way wherever it appears.
    [property: JsonPropertyName("instanceId")] string Id,
    [property: JsonPropertyName("parentInstanceId")] string? ParentId,
    UsbNodeKind Kind,
    string Name,
    string? Class = null,
    string? Vid = null,
    string? Pid = null,
    int ProblemCode = 0,
    int? Port = null,
    string? ContainerId = null,
    IReadOnlyList<UsbPortInfo>? Ports = null,
    /// <summary>A hub's type (<c>USB_HUB_TYPE</c>): 1 a root hub, 2 a USB 2 hub, 3 a USB 3 hub.</summary>
    int? HubType = null)
{
    public bool IsHub => Kind is UsbNodeKind.RootHub or UsbNodeKind.Hub;
}

/// <summary>The USB tree as read once. <see cref="Error"/> says why it couldn't be read (then <see cref="Nodes"/> is empty).</summary>
public sealed record UsbSnapshot(IReadOnlyList<UsbNode> Nodes, string? Error = null)
{
    public static UsbSnapshot Unavailable(string reason) => new([], reason);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static UsbSnapshot FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unavailable("No USB answer.");
        try { return JsonSerializer.Deserialize<UsbSnapshot>(json, Json) is { } s ? s with { Nodes = s.Nodes ?? [] } : Unavailable("No USB answer."); }
        catch (JsonException ex) { return Unavailable("The USB answer couldn't be read: " + ex.Message); }
    }
}

/// <summary>Reads the USB tree (the app: configuration manager and the hub driver, no administrator rights needed).</summary>
public interface IUsbTreeSource
{
    Task<UsbSnapshot> ReadAsync(CancellationToken ct = default);
}

/// <summary>No USB tree here (CI, non-Windows).</summary>
public sealed class NullUsbTreeSource : IUsbTreeSource
{
    public Task<UsbSnapshot> ReadAsync(CancellationToken ct = default) => Task.FromResult(UsbSnapshot.Unavailable("USB devices can't be read here."));
}

/// <summary>This PC's USB tree, read in this process (<see cref="Platform.WindowsUsbTreeReader"/>).</summary>
public sealed class WindowsUsbTreeSource(ILogger? log = null) : IUsbTreeSource
{
    public Task<UsbSnapshot> ReadAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult(UsbSnapshot.Unavailable("USB devices can only be read on Windows."));
        return Task.Run(() =>
        {
            try { return Platform.WindowsUsbTreeReader.Read(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                log.Warn($"USB tree unreadable: {ex.GetType().Name}: {ex.Message}");
                return UsbSnapshot.Unavailable("The USB devices couldn't be read: " + ex.Message);
            }
        }, ct);
    }
}

/// <summary>
/// For a module in user mode (the module host): asks the app (<c>usb.tree</c>), which reads the tree in the signed-in user's session, so the
/// read is recorded with the app's other answers.
/// </summary>
public sealed class HostUsbTreeSource(Plugins.IHostQueries host, ILogger? log = null) : IUsbTreeSource
{
    public async Task<UsbSnapshot> ReadAsync(CancellationToken ct = default)
    {
        try { return await host.ReadUsbTreeAsync(ct).ConfigureAwait(false); }
        catch (Plugins.HostQueryException ex)
        {
            log.Warn($"usb.tree refused ({ex.Error}): {ex.Message}");
            return UsbSnapshot.Unavailable(ex.Message);
        }
    }
}
