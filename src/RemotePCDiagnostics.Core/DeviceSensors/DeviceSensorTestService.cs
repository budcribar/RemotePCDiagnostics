namespace RemotePCDiagnostics.Core.DeviceSensors;

/// <summary>A step of the interactive Sensor test.</summary>
public enum SensorTestStep { Tilt, Light, Presence }

public enum SensorStepState { Pending, Active, Passed, Failed, Skipped, NotSupported }

public enum SensorTestVerdict { NotRun, Running, Passed, Failed, Skipped, Cancelled }

public sealed record SensorStepResult(SensorTestStep Step, SensorStepState State, string? Reason = null, string? Sensor = null);

/// <summary>Min and max seen on one axis since the tilt step began.</summary>
public sealed record AxisRange(double Min, double Max)
{
    public double Span => Max - Min;
    public AxisRange With(double v) => new(Math.Min(Min, v), Math.Max(Max, v));
}

/// <summary>What the Sensor test has measured and where it is. Live values are the latest reading of each sensor.</summary>
public sealed record SensorTestSnapshot
{
    public SensorTestVerdict Verdict { get; init; } = SensorTestVerdict.NotRun;
    public IReadOnlyList<SensorStepResult> Steps { get; init; } = [];
    public SensorTestStep? Current { get; init; }
    public int SecondsLeft { get; init; }
    public DateTimeOffset? StartedUtc { get; init; }
    public DateTimeOffset? FinishedUtc { get; init; }

    // Tilt (accelerometer, g)
    public double? X { get; init; }
    public double? Y { get; init; }
    public double? Z { get; init; }
    public AxisRange? RangeX { get; init; }
    public AxisRange? RangeY { get; init; }
    public AxisRange? RangeZ { get; init; }

    // Light (lux)
    public double? Lux { get; init; }
    /// <summary>The brightest reading since the light step began: the level covering it must halve.</summary>
    public double? LuxHigh { get; init; }
    public double? LuxLow { get; init; }

    // Presence
    public bool? Present { get; init; }
    public double? DistanceMm { get; init; }
    /// <summary>The person's answer to "Does it follow you?", or null before they answer.</summary>
    public bool? PresenceConfirmed { get; init; }

    // Other live readings
    public double? HingeDegrees { get; init; }
    public int? Orientation { get; init; }
    public double? HeadingDegrees { get; init; }

    /// <summary>Why the sensors couldn't be read just now (shown while it lasts).</summary>
    public string? ReadError { get; init; }
    public string? Notes { get; init; }
}

/// <summary>
/// The interactive Sensor test (Interactive tests page): tilt the PC until the accelerometer has changed on all three axes, cover the light
/// sensor until the light level halves, and confirm the presence sensor follows the person. Readings come from <see cref="IDeviceSensorSource"/>
/// (the app, no administrator rights), polled while the test runs; nothing is changed on the PC. Each step has Skip and Doesn't work, and a
/// timeout: tilt <see cref="TiltSeconds"/> s (fails), light <see cref="LightSeconds"/> s (fails), presence <see cref="PresenceSeconds"/> s
/// without an answer (skipped). A step for a sensor the PC doesn't have is Not supported.
/// </summary>
public sealed class DeviceSensorTestService : IDisposable
{
    public const int TiltSeconds = 20;
    public const int LightSeconds = 30;
    public const int PresenceSeconds = 60;
    /// <summary>How far (in g) each axis must change for the tilt step to pass.</summary>
    public const double TiltAxisG = 0.3;
    /// <summary>The light level must drop to this share of the brightest reading.</summary>
    public const double LightDropRatio = 0.5;
    /// <summary>Below this many lux the room is too dark to tell a covered sensor from an uncovered one.</summary>
    public const double MinLightLux = 5;
    public static readonly TimeSpan DefaultPoll = TimeSpan.FromMilliseconds(150);

    private readonly object _lock = new();
    private readonly IDeviceSensorSource? _source;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _poll;
    private readonly bool _autoPoll;
    private SensorTestSnapshot _current = new();
    private DateTimeOffset _stepStarted;
    private CancellationTokenSource? _loop;

    public DeviceSensorTestService(IDeviceSensorSource? source = null, TimeProvider? clock = null, TimeSpan? poll = null, bool autoPoll = true)
    {
        _source = source;
        _clock = clock ?? TimeProvider.System;
        _poll = poll ?? DefaultPoll;
        _autoPoll = autoPoll;
    }

    public event Action? Changed;

    public SensorTestSnapshot Current { get { lock (_lock) return _current; } }

    public bool IsRunning => Current.Verdict == SensorTestVerdict.Running;

    public static string Title(SensorTestStep step) => step switch
    {
        SensorTestStep.Tilt => "Tilt (accelerometer)",
        SensorTestStep.Light => "Cover the light sensor",
        SensorTestStep.Presence => "Presence sensor",
        _ => step.ToString(),
    };

    public static string Instructions(SensorTestStep step) => step switch
    {
        SensorTestStep.Tilt => $"Tilt the PC forward and back, then side to side, then lay it flat or stand it up, until the ball has moved and all three axes show a tick. Within {TiltSeconds} s.",
        SensorTestStep.Light => "Cover the light sensor with your hand (it's usually next to the camera above the screen) until the level drops by half, then uncover it.",
        SensorTestStep.Presence => "Sit in front of the PC, then lean away or step back. Does Present / No one follow you? Answer Yes or No.",
        _ => "",
    };

    public static DeviceSensorKind[] KindsFor(SensorTestStep step) => step switch
    {
        SensorTestStep.Tilt => [DeviceSensorKind.Accelerometer],
        SensorTestStep.Light => [DeviceSensorKind.AmbientLight],
        _ => [DeviceSensorKind.HumanPresence, DeviceSensorKind.Proximity],
    };

    private static int TimeoutOf(SensorTestStep step) => step switch
    {
        SensorTestStep.Tilt => TiltSeconds,
        SensorTestStep.Light => LightSeconds,
        _ => PresenceSeconds,
    };

    private static DeviceSensor? SensorFor(DeviceSensorSnapshot s, SensorTestStep step) =>
        KindsFor(step).Select(s.First).FirstOrDefault(x => x is not null);

    /// <summary>Reads the sensors and starts with the first step the PC has a sensor for. Ends at once (Skipped) when it has none.</summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        StopLoop();
        DeviceSensorSnapshot first;
        try { first = _source is null ? DeviceSensorSnapshot.Unavailable("Sensors can't be read here.") : await _source.ReadAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { first = DeviceSensorSnapshot.Unavailable(ex.Message); }
        lock (_lock)
        {
            var now = _clock.GetUtcNow();
            var steps = Enum.GetValues<SensorTestStep>().Select(step =>
            {
                var sensor = first.Error is null ? SensorFor(first, step) : null;
                if (sensor is null)
                    return new SensorStepResult(step, SensorStepState.NotSupported, first.Error is { } e ? "The sensors couldn't be read: " + e
                        : step switch
                        {
                            SensorTestStep.Tilt => "This PC has no accelerometer.",
                            SensorTestStep.Light => "This PC has no light sensor.",
                            _ => "This PC has no presence or proximity sensor.",
                        });
                if (sensor.State is DeviceSensorStatus.Error or DeviceSensorStatus.AccessDenied or DeviceSensorStatus.NotAvailable)
                    return new SensorStepResult(step, SensorStepState.Failed, $"{DeviceSensorAnalysis.Name(sensor)} is {DeviceSensorTypes.StateText(sensor.State).ToLowerInvariant()}.",
                        DeviceSensorAnalysis.Name(sensor));
                return new SensorStepResult(step, SensorStepState.Pending, null, DeviceSensorAnalysis.Name(sensor));
            }).ToList();
            _current = new SensorTestSnapshot { Verdict = SensorTestVerdict.Running, Steps = steps, StartedUtc = now, Notes = _current.Notes };
            AdvanceLocked(now);
            ApplyReadingsLocked(first);
        }
        Raise();
        if (_autoPoll && IsRunning) StartLoop();
    }

    /// <summary>Applies one read of the sensors (the poll loop calls this; tests call it directly) and moves the test on.</summary>
    public void Observe(DeviceSensorSnapshot? reading)
    {
        lock (_lock)
        {
            if (_current.Verdict != SensorTestVerdict.Running) return;
            if (reading is not null) ApplyReadingsLocked(reading);
            var now = _clock.GetUtcNow();
            CheckStepLocked(now);
        }
        Raise();
    }

    public void Skip() => EndStep(SensorStepState.Skipped, "Skipped by the person.");

    public void DoesNotWork() => EndStep(SensorStepState.Failed, "The person said it doesn't work.");

    /// <summary>The person's answer to whether the presence reading followed them.</summary>
    public void ConfirmPresence(bool follows)
    {
        lock (_lock)
        {
            if (_current.Current != SensorTestStep.Presence) return;
            _current = _current with { PresenceConfirmed = follows };
        }
        EndStep(follows ? SensorStepState.Passed : SensorStepState.Failed,
            follows ? "The person saw it follow them." : "The person said it didn't follow them.");
    }

    public void Cancel()
    {
        StopLoop();
        lock (_lock)
        {
            if (_current.Verdict != SensorTestVerdict.Running) return;
            _current = _current with
            {
                Verdict = SensorTestVerdict.Cancelled, Current = null, SecondsLeft = 0, FinishedUtc = _clock.GetUtcNow(),
                Steps = [.. _current.Steps.Select(s => s.State is SensorStepState.Pending or SensorStepState.Active ? s with { State = SensorStepState.Skipped, Reason = "Stopped." } : s)],
            };
        }
        Raise();
    }

    public void Reset()
    {
        StopLoop();
        lock (_lock) _current = new SensorTestSnapshot();
        Raise();
    }

    public void SetNotes(string? notes)
    {
        lock (_lock) _current = _current with { Notes = string.IsNullOrWhiteSpace(notes) ? null : notes.Trim() };
        Raise();
    }

    private void EndStep(SensorStepState state, string reason)
    {
        lock (_lock)
        {
            if (_current.Verdict != SensorTestVerdict.Running || _current.Current is not { } step) return;
            SetStepLocked(step, state, reason);
            AdvanceLocked(_clock.GetUtcNow());
        }
        if (!IsRunning) StopLoop();
        Raise();
    }

    private void ApplyReadingsLocked(DeviceSensorSnapshot s)
    {
        if (s.Error is { } err) { _current = _current with { ReadError = err }; return; }
        var c = _current with { ReadError = null };
        if (s.First(DeviceSensorKind.Accelerometer)?.Reading is { X: { } x, Y: { } y, Z: { } z })
        {
            c = c with { X = x, Y = y, Z = z };
            if (c.Current == SensorTestStep.Tilt)
                c = c with
                {
                    RangeX = c.RangeX?.With(x) ?? new(x, x), RangeY = c.RangeY?.With(y) ?? new(y, y), RangeZ = c.RangeZ?.With(z) ?? new(z, z),
                };
        }
        if (s.First(DeviceSensorKind.AmbientLight)?.Reading?.Lux is { } lux)
        {
            c = c with { Lux = lux };
            if (c.Current == SensorTestStep.Light)
                c = c with { LuxHigh = Math.Max(c.LuxHigh ?? lux, lux), LuxLow = Math.Min(c.LuxLow ?? lux, lux) };
        }
        var presence = s.First(DeviceSensorKind.HumanPresence) is { Reading.IsEmpty: false } hp ? hp : s.First(DeviceSensorKind.Proximity);
        if (presence?.Reading is { } pr) c = c with { Present = pr.Detected ?? c.Present, DistanceMm = pr.DistanceMm ?? c.DistanceMm };
        if (s.First(DeviceSensorKind.HingeAngle)?.Reading?.AngleDegrees is { } hinge) c = c with { HingeDegrees = hinge };
        if (s.First(DeviceSensorKind.SimpleOrientation)?.Reading?.SimpleOrientation is { } o) c = c with { Orientation = o };
        if (s.First(DeviceSensorKind.Compass)?.Reading?.HeadingDegrees is { } h) c = c with { HeadingDegrees = h };
        _current = c;
    }

    /// <summary>Axes that haven't changed by <see cref="TiltAxisG"/> yet ("X", "Y", "Z").</summary>
    public static IReadOnlyList<string> StillAxes(SensorTestSnapshot s)
    {
        var still = new List<string>();
        if (s.RangeX is not { Span: >= TiltAxisG }) still.Add("X");
        if (s.RangeY is not { Span: >= TiltAxisG }) still.Add("Y");
        if (s.RangeZ is not { Span: >= TiltAxisG }) still.Add("Z");
        return still;
    }

    public static bool LightCovered(SensorTestSnapshot s) =>
        s.LuxHigh is >= MinLightLux && s.LuxLow is { } low && low <= s.LuxHigh.Value * LightDropRatio;

    private void CheckStepLocked(DateTimeOffset now)
    {
        if (_current.Current is not { } step) return;
        var left = TimeoutOf(step) - (int)Math.Floor((now - _stepStarted).TotalSeconds);
        _current = _current with { SecondsLeft = Math.Max(0, left) };
        switch (step)
        {
            case SensorTestStep.Tilt when StillAxes(_current).Count == 0:
                SetStepLocked(step, SensorStepState.Passed, null);
                AdvanceLocked(now);
                return;
            case SensorTestStep.Light when LightCovered(_current):
                SetStepLocked(step, SensorStepState.Passed, null);
                AdvanceLocked(now);
                return;
        }
        if (left > 0) return;
        var reason = step switch
        {
            SensorTestStep.Tilt => _current.RangeX is null
                ? "The accelerometer sent no readings."
                : $"No change on {string.Join(", ", StillAxes(_current))} in {TiltSeconds} s.",
            SensorTestStep.Light => _current.LuxHigh is null ? "The light sensor sent no readings."
                : _current.LuxHigh < MinLightLux ? $"Too dark to tell ({Lx(_current.LuxHigh)} at most): turn on a light and try again."
                : $"The light level never dropped by half ({Lx(_current.LuxHigh)} to {Lx(_current.LuxLow)} at the lowest).",
            _ => "No answer.",
        };
        SetStepLocked(step, step == SensorTestStep.Presence ? SensorStepState.Skipped : SensorStepState.Failed, reason);
        AdvanceLocked(now);
    }

    private static string Lx(double? v) => v is { } x ? Math.Round(x, x < 10 ? 1 : 0).ToString(System.Globalization.CultureInfo.InvariantCulture) + " lux" : "?";

    private void SetStepLocked(SensorTestStep step, SensorStepState state, string? reason) =>
        _current = _current with { Steps = [.. _current.Steps.Select(s => s.Step == step ? s with { State = state, Reason = reason ?? s.Reason } : s)] };

    /// <summary>Starts the next pending step, or ends the test with its verdict.</summary>
    private void AdvanceLocked(DateTimeOffset now)
    {
        var next = _current.Steps.FirstOrDefault(s => s.State is SensorStepState.Pending or SensorStepState.Active);
        if (next is not null)
        {
            _stepStarted = now;
            _current = _current with
            {
                Current = next.Step, SecondsLeft = TimeoutOf(next.Step),
                Steps = [.. _current.Steps.Select(s => s.Step == next.Step ? s with { State = SensorStepState.Active } : s)],
            };
            return;
        }
        var steps = _current.Steps;
        var verdict = steps.Any(s => s.State == SensorStepState.Failed) ? SensorTestVerdict.Failed
            : steps.Any(s => s.State == SensorStepState.Passed) ? SensorTestVerdict.Passed
            : SensorTestVerdict.Skipped;
        _current = _current with { Verdict = verdict, Current = null, SecondsLeft = 0, FinishedUtc = now };
    }

    /// <summary>One line on how the test went, for the row on the page and the export.</summary>
    public static string Summary(SensorTestSnapshot s)
    {
        if (s.Verdict == SensorTestVerdict.NotRun) return "Tilt, cover the light sensor and check presence";
        if (s.Verdict == SensorTestVerdict.Running && s.Current is { } now) return Title(now) + (s.SecondsLeft > 0 ? $" · {s.SecondsLeft} s left" : "");
        var passed = s.Steps.Count(x => x.State == SensorStepState.Passed);
        var failed = s.Steps.Where(x => x.State == SensorStepState.Failed).ToList();
        var tested = s.Steps.Count(x => x.State is SensorStepState.Passed or SensorStepState.Failed);
        if (s.Steps.All(x => x.State == SensorStepState.NotSupported)) return "This PC has no sensors the test can check";
        if (failed.Count > 0) return $"{Title(failed[0].Step)}: {failed[0].Reason}";
        if (s.Verdict == SensorTestVerdict.Cancelled) return "Stopped";
        return tested == 0 ? "Every step skipped" : $"{passed} of {tested} sensors passed";
    }

    private void StartLoop()
    {
        var cts = new CancellationTokenSource();
        var token = cts.Token;
        lock (_lock) _loop = cts;
        _ = Task.Run(async () =>
        {
            try
            {
                while (!token.IsCancellationRequested && IsRunning)
                {
                    await Task.Delay(_poll, _clock, token).ConfigureAwait(false);
                    DeviceSensorSnapshot? r = null;
                    try { r = _source is null ? null : await _source.ReadAsync(token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex) { r = DeviceSensorSnapshot.Unavailable(ex.Message); }
                    Observe(r);
                }
            }
            catch (OperationCanceledException) { }
        });
    }

    private void StopLoop()
    {
        CancellationTokenSource? loop;
        lock (_lock) { loop = _loop; _loop = null; }
        if (loop is null) return;
        loop.Cancel();
        loop.Dispose();
    }

    private void Raise()
    {
        try { Changed?.Invoke(); } catch { }
    }

    public void Dispose() => StopLoop();
}
