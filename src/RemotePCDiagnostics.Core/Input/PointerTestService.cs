namespace RemotePCDiagnostics.Core.Input;

/// <summary>
/// The Pointer and touch interactive test: walks the person through the steps for the device they picked, and counts only input that
/// Windows saw from that device (<see cref="PhysicalInputGate"/>), so a remote technician can't pass it from their own browser. Each step
/// has Skip, Doesn't work, and a <see cref="TimeoutSeconds"/> no-input timeout. The page reports what happened in the test area; this
/// class decides what counts.
/// </summary>
public sealed class PointerTestService : IDisposable
{
    public const int TimeoutSeconds = 30;
    public const int GridColumns = 6;
    public const int GridRows = 4;
    /// <summary>Scrolls needed each way.</summary>
    public const int ScrollsNeeded = 3;
    public static readonly TimeSpan DoubleClickTime = TimeSpan.FromMilliseconds(500);

    private readonly object _lock = new();
    private readonly IPhysicalInputMonitor? _monitor;
    private readonly TimeProvider _clock;
    private readonly PhysicalInputGate _gate;
    private PointerTestSnapshot _current;
    private readonly HashSet<int> _cells = [];
    private readonly Dictionary<PointerButton, DateTimeOffset> _lastDown = [];
    private PointerButton? _dragButton;
    private int _screenContacts;
    private DateTimeOffset _lastInput;
    private bool _stopGate;

    public PointerTestService(IPhysicalInputMonitor? monitor = null, TimeProvider? clock = null, TimeSpan? grace = null)
    {
        _monitor = monitor;
        _clock = clock ?? TimeProvider.System;
        _gate = new PhysicalInputGate(monitor, _clock, grace);
        _gate.Physical += OnPhysical;
        _current = Fresh();
    }

    public event Action? Changed;

    public PointerTestSnapshot Current { get { lock (_lock) return _current; } }

    /// <summary>The device list for the picker: what Windows reports, or one unnamed entry when it can't say.</summary>
    public IReadOnlyList<PointerDevice> Devices()
    {
        IReadOnlyList<PointerDevice> found = [];
        try { found = _monitor?.PointerDevices() ?? []; } catch { }
        return found.Count > 0 ? found : [new PointerDevice("", "Mouse or touchpad", PointerDeviceKind.Mouse)];
    }

    /// <summary>The page sets this from the session: with no input verification, input never counts while a remote session is active.</summary>
    public bool RemoteSessionActive
    {
        get => _gate.RemoteSessionActive;
        set => _gate.RemoteSessionActive = value;
    }

    public static IReadOnlyList<PointerStep> StepsFor(PointerDevice device) => device.Kind switch
    {
        PointerDeviceKind.Touchscreen => [PointerStep.TouchGrid],
        PointerDeviceKind.Pen => [PointerStep.Move, PointerStep.TouchGrid],
        PointerDeviceKind.Touchpad when device.PrecisionTouchpad =>
            [PointerStep.Move, PointerStep.Buttons, PointerStep.Scroll, PointerStep.Drag, PointerStep.TouchpadGestures],
        _ => [PointerStep.Move, PointerStep.Buttons, PointerStep.Scroll, PointerStep.Drag],
    };

    public static string Title(PointerStep step) => step switch
    {
        PointerStep.Move => "Move to the corners",
        PointerStep.Buttons => "Double-click each button",
        PointerStep.Scroll => "Scroll up and down",
        PointerStep.Drag => "Drag with each button",
        PointerStep.TouchpadGestures => "Touchpad taps and fingers",
        PointerStep.TouchGrid => "Touch every square",
        _ => step.ToString(),
    };

    public static string Instructions(PointerStep step) => step switch
    {
        PointerStep.Move => "Move the pointer onto each of the four corner targets.",
        PointerStep.Buttons => "Double-click the left, right and middle buttons inside the box. No middle button? Tick \"My device has no middle button\".",
        PointerStep.Scroll => $"Scroll up and down at least {ScrollsNeeded} times each, with the wheel or two fingers. Sideways scrolling is optional.",
        PointerStep.Drag => "Hold the left button and drag the Left box onto its target, then hold the right button and drag the Right box onto its target.",
        PointerStep.TouchpadGestures => "Tap the touchpad once without pressing it down, tap or click with two fingers for a right click, then rest three or four fingers on it.",
        PointerStep.TouchGrid => "Touch every square until all of them turn green; slide a finger to cover several. Then put as many fingers down at once as you can.",
        _ => "",
    };

    public void Start(PointerDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        _gate.Stop();
        lock (_lock)
        {
            _stopGate = false;
            _gate.DeviceId = string.IsNullOrEmpty(device.Id) ? null : device.Id;
            _gate.ResetCounts();
            _cells.Clear();
            _lastDown.Clear();
            _dragButton = null;
            _screenContacts = 0;
            var now = _clock.GetUtcNow();
            var steps = StepsFor(device).Select(s =>
                s == PointerStep.TouchpadGestures && !_gate.Verified
                    ? new PointerStepResult(s, PointerStepState.NotSupported, "Needs Windows to report the touchpad's fingers, which it can't here.")
                    : new PointerStepResult(s, PointerStepState.Pending)).ToList();
            _current = Fresh() with { Verdict = PointerTestVerdict.Running, Device = device, Steps = steps, StartedUtc = now, Notes = _current.Notes };
            AdvanceLocked(now);
        }
        _gate.Start();
        Raise();
    }

    public void Cancel()
    {
        lock (_lock)
        {
            if (_current.Verdict != PointerTestVerdict.Running) return;
            _current = Counted(_current) with { Verdict = PointerTestVerdict.Cancelled, Current = null, FinishedUtc = _clock.GetUtcNow(), SecondsLeft = 0 };
        }
        _gate.Stop();
        Raise();
    }

    public void Reset()
    {
        _gate.Stop();
        lock (_lock) _current = Fresh();
        Raise();
    }

    public void SetNotes(string? notes)
    {
        lock (_lock) _current = _current with { Notes = string.IsNullOrWhiteSpace(notes) ? null : notes.Trim() };
        Raise();
    }

    /// <summary>Skip the current step.</summary>
    public void Skip() => EndStep(PointerStepState.Skipped, "Skipped by the person.");

    /// <summary>The person says the current step doesn't work on their device.</summary>
    public void FailStep() => EndStep(PointerStepState.Failed, "The person said it doesn't work.");

    public void SetNoMiddleButton(bool none)
    {
        lock (_lock)
        {
            _current = _current with { NoMiddleButton = none };
            CheckStepLocked();
        }
        Raise();
    }

    /// <summary>Call once a second while the test runs: ends a step after <see cref="TimeoutSeconds"/> with no input.</summary>
    public void Tick()
    {
        var changed = false;
        lock (_lock)
        {
            if (_current.Current is null) return;
            var left = TimeoutSeconds - (int)Math.Floor((_clock.GetUtcNow() - _lastInput).TotalSeconds);
            if (left <= 0)
            {
                EndStepLocked(PointerStepState.Failed, $"No input for {TimeoutSeconds} seconds.");
                changed = true;
            }
            else if (left != _current.SecondsLeft)
            {
                _current = _current with { SecondsLeft = left };
                changed = true;
            }
            // The input counts shown while the test runs (which device Windows hears from) refresh once a second.
            changed |= _gate.DeviceEvents != _current.DeviceInputs || _gate.OtherDevice.Events != _current.OtherDeviceInputs
                || _gate.InjectedSeen != _current.InjectedInputs;
        }
        if (changed) Raise();
    }

    /// <summary>The pointer entered corner target <paramref name="corner"/> (0 top left, 1 top right, 2 bottom left, 3 bottom right).</summary>
    public async Task CornerAsync(int corner)
    {
        if (corner is < 0 or > 3 || !IsStep(PointerStep.Move)) return;
        if (!await _gate.AcceptAsync(PhysicalInputKind.Move).ConfigureAwait(false)) { Raise(); return; }
        Apply(PointerStep.Move, s => s with { Corners = s.Corners | (1 << corner) });
    }

    /// <summary>A button went down in the test area.</summary>
    public async Task ButtonDownAsync(PointerButton button)
    {
        var at = _clock.GetUtcNow();
        if (IsStep(PointerStep.Buttons))
        {
            if (!await _gate.AcceptAsync(PhysicalInputKind.ButtonDown, button).ConfigureAwait(false)) { Raise(); return; }
            Apply(PointerStep.Buttons, s =>
            {
                var dbl = _lastDown.TryGetValue(button, out var prev) && at - prev <= DoubleClickTime;
                _lastDown[button] = dbl ? DateTimeOffset.MinValue : at;
                if (!dbl) return s;
                return button switch
                {
                    PointerButton.Left => s with { LeftDoubleClick = true },
                    PointerButton.Right => s with { RightDoubleClick = true },
                    _ => s with { MiddleDoubleClick = true },
                };
            });
        }
        else if (IsStep(PointerStep.TouchpadGestures))
        {
            if (button == PointerButton.Left)
            {
                if (!await _gate.AcceptAsync(PhysicalInputKind.Contacts).ConfigureAwait(false)) { Raise(); return; }
                // A tap is finger contact with no press of the touchpad's button.
                if (!_gate.RecentTouchpadPress()) Apply(PointerStep.TouchpadGestures, s => s with { TapToClick = true });
                else Touched();
            }
            else if (button == PointerButton.Right)
            {
                if (!await _gate.AcceptAsync(PhysicalInputKind.Contacts, minContacts: 2).ConfigureAwait(false)) { Raise(); return; }
                Apply(PointerStep.TouchpadGestures, s => s with { TwoFingerClick = true });
            }
        }
        else if (IsStep(PointerStep.Drag))
        {
            if (!await _gate.AcceptAsync(PhysicalInputKind.ButtonDown, button).ConfigureAwait(false)) { Raise(); return; }
            lock (_lock) _dragButton = button;
            Touched();
        }
    }

    /// <summary>The <paramref name="box"/> box was dropped on its target with <paramref name="button"/> held.</summary>
    public async Task DropAsync(PointerButton box, PointerButton button)
    {
        if (!IsStep(PointerStep.Drag)) return;
        bool started;
        lock (_lock) { started = _dragButton == button; _dragButton = null; }
        if (!started || box != button) return;
        if (!await _gate.AcceptAsync(PhysicalInputKind.Move).ConfigureAwait(false)) { Raise(); return; }
        Apply(PointerStep.Drag, s => box == PointerButton.Left ? s with { LeftDragged = true } : s with { RightDragged = true });
    }

    /// <summary>The drag was released outside a drop target.</summary>
    public void CancelDrag()
    {
        lock (_lock) _dragButton = null;
    }

    /// <summary>A scroll in the test area, in the browser's deltas (negative <paramref name="deltaY"/> is up).</summary>
    public async Task ScrollAsync(double deltaX, double deltaY)
    {
        if (!IsStep(PointerStep.Scroll)) return;
        if (deltaY != 0)
        {
            if (!await _gate.AcceptAsync(PhysicalInputKind.Wheel).ConfigureAwait(false)) { Raise(); return; }
            Apply(PointerStep.Scroll, s => deltaY < 0 ? s with { ScrollUp = s.ScrollUp + 1 } : s with { ScrollDown = s.ScrollDown + 1 });
        }
        else if (deltaX != 0)
        {
            if (!await _gate.AcceptAsync(PhysicalInputKind.HWheel).ConfigureAwait(false)) { Raise(); return; }
            Apply(PointerStep.Scroll, s => deltaX < 0 ? s with { ScrollLeft = s.ScrollLeft + 1 } : s with { ScrollRight = s.ScrollRight + 1 });
        }
    }

    /// <summary>
    /// A touch or pen contact at (<paramref name="x"/>, <paramref name="y"/>) in a grid area <paramref name="width"/> by
    /// <paramref name="height"/>, with <paramref name="contacts"/> touches down on the page.
    /// </summary>
    public async Task TouchAsync(double x, double y, double width, double height, int contacts)
    {
        if (!IsStep(PointerStep.TouchGrid) || width <= 0 || height <= 0) return;
        if (!await _gate.AcceptAsync(PhysicalInputKind.Contacts).ConfigureAwait(false)) { Raise(); return; }
        var col = Math.Clamp((int)(x / (width / GridColumns)), 0, GridColumns - 1);
        var row = Math.Clamp((int)(y / (height / GridRows)), 0, GridRows - 1);
        Apply(PointerStep.TouchGrid, s =>
        {
            _cells.Add(row * GridColumns + col);
            // Windows' own contact count caps what the page reports, so extra page touches can't be added from elsewhere.
            var points = _gate.Verified ? Math.Min(contacts, Math.Max(_screenContacts, 1)) : contacts;
            return s with { CellsTouched = _cells.ToArray(), MaxTouchPoints = Math.Max(s.MaxTouchPoints, points) };
        });
    }

    public void Dispose() => _gate.Dispose();

    private void OnPhysical(PhysicalInputEvent e)
    {
        var changed = false;
        lock (_lock)
        {
            if (_current.Current is not { } step) return;
            _lastInput = _clock.GetUtcNow();
            if (step == PointerStep.Scroll && e.Kind is PhysicalInputKind.Wheel or PhysicalInputKind.HWheel)
            {
                _current = _current with { WheelTicks = _current.WheelTicks + Math.Max(1, Math.Abs(e.Value)) };
                changed = true;
            }
            else if (e.Kind == PhysicalInputKind.Contacts && e.DeviceKind == PointerDeviceKind.Touchpad && step == PointerStep.TouchpadGestures
                     && e.Value > _current.MaxTouchpadContacts)
            {
                _current = _current with { MaxTouchpadContacts = e.Value };
                CheckStepLocked();
                changed = true;
            }
            else if (e.Kind == PhysicalInputKind.Contacts && e.DeviceKind is PointerDeviceKind.Touchscreen or PointerDeviceKind.Pen)
            {
                _screenContacts = Math.Max(_screenContacts, e.Value);
            }
        }
        if (changed) Raise();
    }

    private bool IsStep(PointerStep step)
    {
        lock (_lock) return _current.Current == step;
    }

    private void Touched()
    {
        lock (_lock) _lastInput = _clock.GetUtcNow();
    }

    private void Apply(PointerStep step, Func<PointerTestSnapshot, PointerTestSnapshot> update)
    {
        lock (_lock)
        {
            if (_current.Current != step) return;
            _lastInput = _clock.GetUtcNow();
            _current = update(_current) with { SecondsLeft = TimeoutSeconds };
            CheckStepLocked();
        }
        Raise();
    }

    private void CheckStepLocked()
    {
        var s = _current;
        var done = s.Current switch
        {
            PointerStep.Move => s.Corners == 0b1111,
            PointerStep.Buttons => s.LeftDoubleClick && s.RightDoubleClick && (s.MiddleDoubleClick || s.NoMiddleButton),
            PointerStep.Scroll => s.ScrollUp >= ScrollsNeeded && s.ScrollDown >= ScrollsNeeded,
            PointerStep.Drag => s.LeftDragged && s.RightDragged,
            PointerStep.TouchpadGestures => s.TapToClick && s.TwoFingerClick && s.MaxTouchpadContacts >= 3,
            PointerStep.TouchGrid => _cells.Count >= GridColumns * GridRows
                && (s.Device?.Kind != PointerDeviceKind.Touchscreen || s.MaxTouchPoints >= 2),
            _ => false,
        };
        if (done) EndStepLocked(PointerStepState.Passed, null);
    }

    private void EndStep(PointerStepState state, string reason)
    {
        lock (_lock) EndStepLocked(state, reason);
        Raise();
    }

    private void EndStepLocked(PointerStepState state, string? reason)
    {
        if (_current.Current is not { } step) return;
        var steps = _current.Steps.Select(s => s.Step == step ? s with { State = state, Reason = reason } : s).ToList();
        _current = _current with { Steps = steps };
        AdvanceLocked(_clock.GetUtcNow());
    }

    private void AdvanceLocked(DateTimeOffset now)
    {
        var next = _current.Steps.FirstOrDefault(s => s.State == PointerStepState.Pending);
        if (next is not null)
        {
            _lastInput = now;
            _dragButton = null;
            _current = Counted(_current) with
            {
                Current = next.Step,
                SecondsLeft = TimeoutSeconds,
                Steps = _current.Steps.Select(s => s.Step == next.Step ? s with { State = PointerStepState.Active } : s).ToList(),
            };
            return;
        }
        var steps = _current.Steps;
        var verdict = steps.Any(s => s.State == PointerStepState.Failed) ? PointerTestVerdict.Failed
            : steps.Any(s => s.State == PointerStepState.Passed) ? PointerTestVerdict.Passed
            : PointerTestVerdict.Skipped;
        _current = Counted(_current) with { Verdict = verdict, Current = null, SecondsLeft = 0, FinishedUtc = now };
        // A finished test needs no more input; Raise stops the gate outside the lock.
        _stopGate = true;
    }

    private PointerTestSnapshot Counted(PointerTestSnapshot s) => s with
    {
        InputVerified = _gate.Verified,
        UnverifiedReason = _gate.Verified ? null : _gate.UnverifiedReason,
        IgnoredInputs = _gate.Ignored,
        InjectedInputs = _gate.InjectedSeen,
        DeviceInputs = _gate.DeviceEvents,
        OtherDevice = OtherDeviceLocked(),
        OtherDeviceInputs = _gate.OtherDevice.Events,
    };

    private IReadOnlyList<PointerDevice>? _knownDevices;

    private PointerDevice? OtherDeviceLocked()
    {
        if (_gate.OtherDevice.Id is not { } id) return null;
        _knownDevices ??= Devices();
        var known = _knownDevices.FirstOrDefault(d => d.Id == id);
        if (known is null)
        {
            // A device plugged in after the list was read.
            _knownDevices = Devices();
            known = _knownDevices.FirstOrDefault(d => d.Id == id);
        }
        return known;
    }

    private PointerTestSnapshot Fresh() => new() { InputVerified = _gate.Verified, UnverifiedReason = _gate.Verified ? null : _gate.UnverifiedReason };

    private void Raise()
    {
        bool stop;
        lock (_lock)
        {
            _current = Counted(_current);
            stop = _stopGate;
            _stopGate = false;
        }
        if (stop) _gate.Stop();
        try { Changed?.Invoke(); } catch { }
    }
}
