namespace RemotePCDiagnostics.Core;

/// <summary>How long each test in the stress suite runs.</summary>
public enum StressSuiteMode { Short, Extended }

/// <summary>State of one test in the stress suite.</summary>
public enum StressSuiteStepState { Pending, Running, Passed, Problem, Skipped, NotRun }

public sealed record StressSuiteStep(string ModuleName, string DisplayName, StressSuiteStepState State, string? Message = null);

/// <summary>Progress of a stress suite run. <see cref="Index"/> is 1-based; 0 while the quick checks run.</summary>
public sealed record StressSuiteProgress(StressSuiteMode Mode, int Index, int Total, string? CurrentDisplayName,
    IReadOnlyList<StressSuiteStep> Steps, bool Finished, string? Message)
{
    /// <summary>User-facing line such as "Stress test 2 of 5: Memory".</summary>
    public string Headline => Finished ? Message ?? "Stress tests finished"
        : Index == 0 ? "Running quick checks…" : $"Stress test {Index} of {Total}: {CurrentDisplayName}";
}

public enum StressSuiteOutcome { Completed, StoppedOnProblem, Cancelled }

public sealed record StressSuiteResult(StressSuiteMode Mode, StressSuiteOutcome Outcome, IReadOnlyList<StressSuiteStep> Steps, string Message);

/// <summary>A stress-test module that the sequential stress suite can drive.</summary>
public interface IStressSuiteModule : IDiagnosticModule
{
    TimeSpan Duration { get; set; }
    /// <summary>Asks a running test to stop.</summary>
    void Stop();
    /// <summary>Short name shown in suite progress ("CPU", "Memory", …).</summary>
    string SuiteName => DisplayName;
    /// <summary>Captures settings the suite changes, so they can be restored afterwards.</summary>
    object SaveSuiteSettings() => Duration;
    void RestoreSuiteSettings(object saved) => Duration = (TimeSpan)saved;
    /// <summary>Applies the suite's per-test length (and mode) for a run.</summary>
    void ApplySuiteMode(StressSuiteMode mode) => Duration = StressSuite.PerTestDuration(mode);
    /// <summary>True when a finished result means "this PC doesn't have that hardware" (skip, not a failure).</summary>
    bool IsUnavailableResult(DiagnosticResult result) => false;
    /// <summary>True when a result means the test stopped because the PC got too hot.</summary>
    bool IsOverheatedResult(DiagnosticResult result) => false;
    /// <summary>True when the test couldn't run or finish for a reason that is not a hardware problem (too little free memory,
    /// helper couldn't start, the test itself crashed). The suite skips it with the reason and carries on.</summary>
    bool IsCouldNotRunResult(DiagnosticResult result) => result.Payload is Exception;
    /// <summary>True when a result means the user stopped the test before it finished.</summary>
    bool IsStoppedByUserResult(DiagnosticResult result) => result.Cancelled;
}

public static class StressSuite
{
    /// <summary>Strict run order (module names).</summary>
    public static readonly string[] Order = ["CpuStress", "MemoryTest", "DiskSpeed", "GpuStress", "NetworkTest"];

    public static TimeSpan PerTestDuration(StressSuiteMode mode) =>
        mode == StressSuiteMode.Extended ? TimeSpan.FromMinutes(5) : TimeSpan.FromMinutes(1);

    public static string RunLabel(StressSuiteMode mode) => mode == StressSuiteMode.Extended ? "extended run" : "short run";
}
