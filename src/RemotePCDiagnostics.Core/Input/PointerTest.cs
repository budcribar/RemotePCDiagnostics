namespace RemotePCDiagnostics.Core.Input;

public enum PointerStep
{
    /// <summary>The pointer visits the four corner targets.</summary>
    Move,
    /// <summary>Double-click left, right and middle.</summary>
    Buttons,
    /// <summary>Scroll up and down (wheel or two fingers); sideways is optional.</summary>
    Scroll,
    /// <summary>Drag the Left box with the left button and the Right box with the right button.</summary>
    Drag,
    /// <summary>Precision touchpad: tap to click, two-finger right click, three or four fingers.</summary>
    TouchpadGestures,
    /// <summary>Touchscreen or pen: touch every cell of a grid; multi-touch count.</summary>
    TouchGrid,
}

public enum PointerStepState
{
    Pending,
    Active,
    Passed,
    Failed,
    Skipped,
    NotSupported,
}

public enum PointerTestVerdict
{
    NotRun,
    Running,
    Passed,
    Failed,
    /// <summary>Every step was skipped or not supported.</summary>
    Skipped,
    /// <summary>Stopped before the end; the steps done so far are kept.</summary>
    Cancelled,
}

/// <param name="Reason">Why a step failed, was skipped or is not supported.</param>
public sealed record PointerStepResult(PointerStep Step, PointerStepState State, string? Reason = null);

/// <summary>Everything the Pointer and touch test measured, for the page and interactive-data.</summary>
public sealed record PointerTestSnapshot
{
    public PointerTestVerdict Verdict { get; init; }
    public PointerDevice? Device { get; init; }
    public IReadOnlyList<PointerStepResult> Steps { get; init; } = [];
    public PointerStep? Current { get; init; }
    /// <summary>Seconds left before the current step times out with no input.</summary>
    public int SecondsLeft { get; init; }

    /// <summary>Corner targets reached, as bits: 1 top left, 2 top right, 4 bottom left, 8 bottom right.</summary>
    public int Corners { get; init; }
    public bool LeftDoubleClick { get; init; }
    public bool RightDoubleClick { get; init; }
    public bool MiddleDoubleClick { get; init; }
    /// <summary>The person said the device has no middle button.</summary>
    public bool NoMiddleButton { get; init; }
    public int ScrollUp { get; init; }
    public int ScrollDown { get; init; }
    public int ScrollLeft { get; init; }
    public int ScrollRight { get; init; }
    /// <summary>Wheel notches Windows saw from the device during the Scroll step (0 for two-finger scrolling).</summary>
    public int WheelTicks { get; init; }
    public bool LeftDragged { get; init; }
    public bool RightDragged { get; init; }
    public bool TapToClick { get; init; }
    public bool TwoFingerClick { get; init; }
    /// <summary>Most fingers the touchpad reported at once during the touchpad step.</summary>
    public int MaxTouchpadContacts { get; init; }
    public int GridColumns { get; init; } = PointerTestService.GridColumns;
    public int GridRows { get; init; } = PointerTestService.GridRows;
    public IReadOnlyCollection<int> CellsTouched { get; init; } = [];
    public int MaxTouchPoints { get; init; }

    /// <summary>Input was checked against Windows' hardware input (see <see cref="PhysicalInputGate"/>).</summary>
    public bool InputVerified { get; init; }
    public string? UnverifiedReason { get; init; }
    /// <summary>Page input that did not count because no hardware input backed it (a remote viewer, injected input).</summary>
    public int IgnoredInputs { get; init; }
    public int InjectedInputs { get; init; }
    public DateTimeOffset? StartedUtc { get; init; }
    public DateTimeOffset? FinishedUtc { get; init; }
    public string? Notes { get; init; }

    public int CornerCount => System.Numerics.BitOperations.PopCount((uint)Corners);
    public int CellCount => GridColumns * GridRows;

    public PointerStepState StateOf(PointerStep step) => Steps.FirstOrDefault(s => s.Step == step)?.State ?? PointerStepState.Pending;
}
