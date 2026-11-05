namespace RemotePCDiagnostics.Core;

public enum DiagnosticStatus { NotRun, Running, Ok, Warning, Error }

/// <summary>Snapshot of a module's latest result.</summary>
public record DiagnosticResult(
    string ModuleName,
    DiagnosticStatus Status,
    string Message,
    DateTimeOffset Timestamp,
    object? Payload = null)
{
    /// <summary>
    /// The run was cancelled or stopped by the user: not a problem. Set where the cancel happens, so nothing has to recognise it from the
    /// (possibly translated) message.
    /// </summary>
    public bool Cancelled { get; init; }

    /// <summary>The hardware instance this result is for (<see cref="ModuleInstance.Key"/>), or null for the module as a whole.</summary>
    public string? InstanceKey { get; init; }
    /// <summary>The instance's label at run time ("Samsung 990 Pro 2 TB, Disk 1").</summary>
    public string? InstanceLabel { get; init; }

    public static DiagnosticResult NotRun(string module) =>
        new(module, DiagnosticStatus.NotRun, "Not run yet", DateTimeOffset.Now);
}

/// <summary>Strongly typed result wrapper.</summary>
public sealed record DiagnosticResult<T>(
    string ModuleName, DiagnosticStatus Status, string Message, DateTimeOffset Timestamp, T? Data)
    : DiagnosticResult(ModuleName, Status, Message, Timestamp, Data);

public record ModuleAvailability(bool IsAvailable, string? Reason = null)
{
    public static ModuleAvailability Available { get; } = new(true);
    public static ModuleAvailability Unavailable(string reason) => new(false, reason);
}

/// <summary>The one place that decides "cancelled, not a problem": the flag set where the run was cancelled.</summary>
public static class Cancellation
{
    public static bool IsCancelled(DiagnosticResult r) => r.Cancelled;
}
