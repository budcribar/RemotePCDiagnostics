namespace RemotePCDiagnostics.Core.Workflow;

public enum PhysicalCheckOutcome
{
    NotRun,
    Passed,
    PassedWithNote,
    Failed,
}

/// <param name="IgnoredKeys">Key presses the page saw that no keyboard on this PC made (a remote viewer's keys, injected input): not counted.</param>
/// <param name="KeysVerified">Keys were checked against Windows' own keyboard input (see Input.PhysicalInputGate).</param>
public sealed record PhysicalBenchQaSnapshot(
    PhysicalCheckOutcome KeyboardOutcome = PhysicalCheckOutcome.NotRun,
    int UniqueKeysPressed = 0,
    int PeakKeyRollover = 0,
    string? KeyboardNotes = null,
    PhysicalCheckOutcome DisplayOutcome = PhysicalCheckOutcome.NotRun,
    int SolidColorsInspected = 0,
    int MaxTouchPoints = 0,
    string? DisplayNotes = null,
    DateTimeOffset? UpdatedUtc = null,
    int IgnoredKeys = 0,
    bool KeysVerified = false)
{
    public bool HasAny =>
        KeyboardOutcome != PhysicalCheckOutcome.NotRun
        || DisplayOutcome != PhysicalCheckOutcome.NotRun
        || UniqueKeysPressed > 0
        || SolidColorsInspected > 0;
}

/// <summary>
/// Thread-safe in-memory state for interactive bench technician checks (keyboard matrix/rollover and display dead-pixel/touch inspection)
/// that roll up onto <see cref="HardwareQaCertificate"/>.
/// </summary>
public sealed class PhysicalBenchQaService
{
    private readonly object _gate = new();
    private PhysicalBenchQaSnapshot _current = new();

    public event Action? Changed;

    public PhysicalBenchQaSnapshot Current
    {
        get { lock (_gate) return _current; }
    }

    public PhysicalBenchQaSnapshot Update(Func<PhysicalBenchQaSnapshot, PhysicalBenchQaSnapshot> update)
    {
        ArgumentNullException.ThrowIfNull(update);
        PhysicalBenchQaSnapshot next;
        lock (_gate)
        {
            next = update(_current) with { UpdatedUtc = DateTimeOffset.UtcNow };
            _current = next;
        }
        RaiseChanged();
        return next;
    }

    public void Reset()
    {
        lock (_gate)
        {
            _current = new PhysicalBenchQaSnapshot();
        }
        RaiseChanged();
    }

    private void RaiseChanged()
    {
        try { Changed?.Invoke(); } catch { }
    }
}
