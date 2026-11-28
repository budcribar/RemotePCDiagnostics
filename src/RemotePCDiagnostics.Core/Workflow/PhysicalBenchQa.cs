namespace RemotePCDiagnostics.Core.Workflow;

public enum PhysicalCheckOutcome
{
    NotRun,
    Passed,
    PassedWithNote,
    Failed,
}

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
    /// <summary>The display test on each screen it ran on (patterns and the color number check), in the order tested.</summary>
    IReadOnlyList<Display.DisplayScreenResult>? DisplayScreens = null,
    Display.BlankScreenOutcome BlankScreen = Display.BlankScreenOutcome.NotRun,
    /// <summary>Why the screen off and on check couldn't run (with <see cref="Display.BlankScreenOutcome.NotSupported"/>).</summary>
    string? BlankScreenReason = null)
{
    /// <summary>Replaces (or adds) one screen's display result, keeping the order screens were tested in.</summary>
    public PhysicalBenchQaSnapshot WithScreen(Display.DisplayScreenResult screen)
    {
        var list = new List<Display.DisplayScreenResult>(DisplayScreens ?? []);
        var at = list.FindIndex(s => string.Equals(s.ScreenId, screen.ScreenId, StringComparison.OrdinalIgnoreCase));
        if (at >= 0) list[at] = screen; else list.Add(screen);
        return this with { DisplayScreens = list };
    }

    public bool HasAny =>
        KeyboardOutcome != PhysicalCheckOutcome.NotRun
        || DisplayOutcome != PhysicalCheckOutcome.NotRun
        || UniqueKeysPressed > 0
        || SolidColorsInspected > 0
        || DisplayScreens is { Count: > 0 }
        || BlankScreen != Display.BlankScreenOutcome.NotRun;
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
