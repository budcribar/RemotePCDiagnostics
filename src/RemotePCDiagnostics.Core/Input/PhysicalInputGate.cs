namespace RemotePCDiagnostics.Core.Input;

/// <summary>
/// Decides whether an input the page saw (a key press, click, scroll or touch in the browser) counts toward an interactive test: it counts
/// only when Windows saw matching input from this PC's own hardware just before. A remote technician's browser input never reaches Windows,
/// and injected input (Remote Desktop, remote control tools, SendInput) is marked as such, so neither can pass a test.
/// </summary>
/// <remarks>
/// When the monitor can't verify input (not Windows, a Remote Desktop session, registration failed) input counts only while no remote session
/// is active, and the result says it was not verified.
/// </remarks>
public sealed class PhysicalInputGate : IDisposable
{
    /// <summary>How far back a hardware report may be and still back up a page event.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan Keep = TimeSpan.FromSeconds(2);

    private readonly IPhysicalInputMonitor? _monitor;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _grace;
    private readonly object _gate = new();
    private readonly LinkedList<PhysicalInputEvent> _recent = new();
    private IDisposable? _lease;
    private int _ignored;
    private int _injected;
    private DateTimeOffset? _lastTouchpadPress;

    /// <param name="grace">How long to wait for the hardware report when the page event got here first.</param>
    public PhysicalInputGate(IPhysicalInputMonitor? monitor, TimeProvider? clock = null, TimeSpan? grace = null)
    {
        _monitor = monitor;
        _clock = clock ?? TimeProvider.System;
        _grace = grace ?? TimeSpan.FromMilliseconds(200);
    }

    /// <summary>Input is checked against Windows' hardware input.</summary>
    public bool Verified => _monitor is { UnavailableReason: null };

    public string? UnverifiedReason => _monitor is null ? "Input can't be checked on this computer." : _monitor.UnavailableReason;

    /// <summary>A remote session is connected. Without verification, input then never counts.</summary>
    public bool RemoteSessionActive { get; set; }

    /// <summary>Only this pointing device's input counts (null: any device). Keys are never filtered.</summary>
    public string? DeviceId { get; set; }

    /// <summary>Page events that did not count: no matching hardware input behind them.</summary>
    public int Ignored { get { lock (_gate) return _ignored; } }

    /// <summary>Injected (non-hardware) input reports Windows delivered while listening, moves left out.</summary>
    public int InjectedSeen { get { lock (_gate) return _injected; } }

    /// <summary>Hardware input reports (not injected, from the selected device) as they arrive, on the monitor's thread.</summary>
    public event Action<PhysicalInputEvent>? Physical;

    public void Start()
    {
        if (_monitor is null || _lease is not null) return;
        _monitor.Input += OnInput;
        _lease = _monitor.Listen();
    }

    public void Stop()
    {
        if (_lease is null) return;
        _monitor!.Input -= OnInput;
        _lease.Dispose();
        _lease = null;
        lock (_gate) { _recent.Clear(); _lastTouchpadPress = null; }
    }

    public void ResetCounts()
    {
        lock (_gate) { _ignored = 0; _injected = 0; }
    }

    public void Dispose() => Stop();

    /// <summary>Feeds one report in (the monitor does this; tests call it directly).</summary>
    public void OnInput(PhysicalInputEvent e)
    {
        var forward = false;
        lock (_gate)
        {
            if (e.Injected)
            {
                if (e.Kind != PhysicalInputKind.Move) _injected++;
                return;
            }
            if (e.Kind != PhysicalInputKind.Key && DeviceId is not null && e.DeviceId != DeviceId) return;
            if (e.Kind == PhysicalInputKind.ButtonDown && e.DeviceKind == PointerDeviceKind.Touchpad) _lastTouchpadPress = e.At;
            _recent.AddLast(e);
            while (_recent.First is { } first && e.At - first.Value.At > Keep) _recent.RemoveFirst();
            forward = e.Kind != PhysicalInputKind.Key;
        }
        if (forward)
        {
            try { Physical?.Invoke(e); } catch { }
        }
    }

    /// <summary>Whether a page event of this kind counts, waiting briefly for the hardware report when it has not arrived yet.</summary>
    /// <param name="minContacts">For <see cref="PhysicalInputKind.Contacts"/>: at least this many fingers.</param>
    public async Task<bool> AcceptAsync(PhysicalInputKind kind, PointerButton? button = null, int minContacts = 1)
    {
        if (!Verified) return AcceptUnverified();
        if (TryMatch(kind, button, minContacts, countMiss: false)) return true;
        if (_grace > TimeSpan.Zero) await Task.Delay(_grace, _clock).ConfigureAwait(false);
        return TryMatch(kind, button, minContacts, countMiss: true);
    }

    /// <summary>The same as <see cref="AcceptAsync"/> without the wait.</summary>
    public bool Accept(PhysicalInputKind kind, PointerButton? button = null, int minContacts = 1) =>
        Verified ? TryMatch(kind, button, minContacts, countMiss: true) : AcceptUnverified();

    /// <summary>Hardware reported a button press of a touchpad in the last <see cref="Window"/> (a press, not a tap).</summary>
    public bool RecentTouchpadPress()
    {
        lock (_gate)
            return _lastTouchpadPress is { } at && _clock.GetUtcNow() - at <= Window;
    }

    private bool AcceptUnverified()
    {
        if (!RemoteSessionActive) return true;
        lock (_gate) _ignored++;
        return false;
    }

    private bool TryMatch(PhysicalInputKind kind, PointerButton? button, int minContacts, bool countMiss)
    {
        lock (_gate)
        {
            var now = _clock.GetUtcNow();
            for (var node = _recent.Last; node is not null; node = node.Previous)
            {
                var e = node.Value;
                if (now - e.At > Window) break;
                if (!Matches(e, kind, button, minContacts)) continue;
                // One key press or click backs up one page event; contact and movement reports stream, so they are not used up.
                if (e.Kind is PhysicalInputKind.Key or PhysicalInputKind.ButtonDown) _recent.Remove(node);
                return true;
            }
            if (countMiss) _ignored++;
            return false;
        }
    }

    internal static bool Matches(PhysicalInputEvent e, PhysicalInputKind kind, PointerButton? button, int minContacts)
    {
        var digitizer = e.DeviceKind is PointerDeviceKind.Touchpad or PointerDeviceKind.Touchscreen or PointerDeviceKind.Pen;
        return kind switch
        {
            PhysicalInputKind.Key => e.Kind == PhysicalInputKind.Key,
            PhysicalInputKind.Move => e.Kind != PhysicalInputKind.Key,
            // A touchpad reports one physical button; Windows makes it a right click by where or with how many fingers it is pressed.
            PhysicalInputKind.ButtonDown => e.Kind == PhysicalInputKind.ButtonDown && (e.Button == button || e.DeviceKind == PointerDeviceKind.Touchpad)
                || e.Kind == PhysicalInputKind.Contacts && digitizer && e.Value >= (button == PointerButton.Right ? 2 : 1),
            PhysicalInputKind.Wheel or PhysicalInputKind.HWheel => e.Kind == kind || e.Kind == PhysicalInputKind.Contacts && e.Value >= 2,
            PhysicalInputKind.Contacts => e.Kind == PhysicalInputKind.Contacts && e.Value >= minContacts,
            _ => false,
        };
    }
}
