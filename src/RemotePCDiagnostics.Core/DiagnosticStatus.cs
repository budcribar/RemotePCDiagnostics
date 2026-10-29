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
