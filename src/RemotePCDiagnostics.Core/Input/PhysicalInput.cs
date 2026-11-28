namespace RemotePCDiagnostics.Core.Input;

/// <summary>What kind of pointing device a <see cref="PointerDevice"/> is.</summary>
public enum PointerDeviceKind
{
    Mouse,
    Touchpad,
    Touchscreen,
    Pen,
}

/// <summary>
/// One physical pointing device on this PC: a mouse, a touchpad (precision or not), a touchscreen or a pen digitizer. A device with several
/// HID collections (a precision touchpad is both a mouse and a digitizer) is one entry; <see cref="Id"/> is its parent device's instance id.
/// </summary>
/// <param name="PrecisionTouchpad">A Windows precision touchpad: reports finger contacts, so tap, two-finger and three/four-finger checks work.</param>
/// <param name="MaxContacts">Contacts the digitizer says it can track at once, when it reports it.</param>
public sealed record PointerDevice(string Id, string Name, PointerDeviceKind Kind, bool PrecisionTouchpad = false, int? MaxContacts = null);

public enum PhysicalInputKind
{
    Key,
    Move,
    ButtonDown,
    Wheel,
    HWheel,
    /// <summary>A digitizer report (touchpad, touchscreen or pen) with <see cref="PhysicalInputEvent.Value"/> contacts down.</summary>
    Contacts,
}

public enum PointerButton
{
    Left,
    Right,
    Middle,
}

/// <summary>
/// One input report Windows delivered from a device (raw input). <see cref="Injected"/> is input no device produced (SendInput, remote control
/// tools). No key identity is kept: a key report says only that a key went down.
/// </summary>
/// <param name="DeviceId">The <see cref="PointerDevice.Id"/> it came from; null for injected input or a device not in the list.</param>
/// <param name="Value">Wheel ticks (signed: up/right positive) or the contact count.</param>
public sealed record PhysicalInputEvent(DateTimeOffset At, PhysicalInputKind Kind, string? DeviceId = null, PointerDeviceKind? DeviceKind = null,
    bool Injected = false, PointerButton? Button = null, int Value = 0);

/// <summary>
/// The operating system's own view of keyboard, mouse and touch input on this PC. The interactive tests use it to tell input made on this PC's
/// hardware from input that came another way: a remote technician's browser (which never reaches Windows at all), Remote Desktop, or software
/// that injects input. Listens only while a test holds a <see cref="Listen"/> lease.
/// </summary>
public interface IPhysicalInputMonitor
{
    /// <summary>Null when input can be verified; otherwise why not (not Windows, a Remote Desktop session, registration failed).</summary>
    string? UnavailableReason { get; }

    /// <summary>The pointing devices present now.</summary>
    IReadOnlyList<PointerDevice> PointerDevices();

    /// <summary>Raised on the monitor's own thread for every report while at least one lease is held.</summary>
    event Action<PhysicalInputEvent>? Input;

    /// <summary>Starts listening (if not already) until the returned lease is disposed.</summary>
    IDisposable Listen();
}

/// <summary>Used where the host has no monitor (tests, non-Windows): input can't be verified.</summary>
public sealed class UnavailablePhysicalInputMonitor(string reason) : IPhysicalInputMonitor
{
    public string? UnavailableReason { get; } = reason;
    public IReadOnlyList<PointerDevice> PointerDevices() => [];
    public event Action<PhysicalInputEvent>? Input { add { } remove { } }
    public IDisposable Listen() => new Lease();
    private sealed class Lease : IDisposable { public void Dispose() { } }
}
