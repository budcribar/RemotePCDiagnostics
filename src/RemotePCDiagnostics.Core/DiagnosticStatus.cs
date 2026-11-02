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
    /// (possibly translated) message. Results saved before this flag existed are still recognised by <see cref="Cancellation.IsCancelled(DiagnosticResult)"/>.
    /// </summary>
    public bool Cancelled { get; init; }

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

/// <summary>The one place that decides "cancelled, not a problem".</summary>
public static class Cancellation
{
    /// <summary>The flag, or (results saved before the flag existed) the English messages the app used to write.</summary>
    public static bool IsCancelled(DiagnosticResult r) => r.Cancelled || IsLegacyCancelledText(r.Status, r.Message);

    public static bool IsLegacyCancelledText(DiagnosticStatus status, string? message) =>
        status == DiagnosticStatus.Warning && message is { } msg
        && (msg.Trim().Equals("Cancelled", StringComparison.OrdinalIgnoreCase)
            || msg.Trim().Equals("Stopped", StringComparison.OrdinalIgnoreCase)
            || msg.Trim().Equals("Stopped by you", StringComparison.OrdinalIgnoreCase)
            || msg == Security.SecurityAuditModule.CancelledMessage);
}
