namespace RemotePCDiagnostics.Core;

/// <summary>Live sub-step progress for a running check or scan. <see cref="HasProgress"/> is true when <see cref="Total"/> &gt; 1.</summary>
public sealed record CheckProgress(int Step, int Total, string Message)
{
    public bool HasProgress => Total > 1;
    public double Fraction => Total > 0 ? Math.Clamp((double)Step / Total, 0.0, 1.0) : 0.0;
    public int Percent => (int)Math.Round(Fraction * 100);
}

public interface ICheckProgress : IProgress<string>
{
    void Report(int step, int total, string message);
}

public static class CheckProgressExtensions
{
    public static void ReportStep(this IProgress<string>? progress, int step, int total, string message)
    {
        if (progress is ICheckProgress cp) cp.Report(step, total, message);
        else progress?.Report(message);
    }

    public static ICheckProgress Create(Action<CheckProgress> onProgress, IProgress<string>? inner = null) =>
        new CallbackCheckProgress(onProgress, inner);

    private sealed class CallbackCheckProgress(Action<CheckProgress> onProgress, IProgress<string>? inner) : ICheckProgress
    {
        public void Report(string value) => Report(0, 0, value);

        public void Report(int step, int total, string message)
        {
            try { onProgress(new CheckProgress(step, total, message)); } catch { }
            try
            {
                if (inner is ICheckProgress cp) cp.Report(step, total, message);
                else inner?.Report(message);
            }
            catch { }
        }
    }
}

public interface IDiagnosticModule
{
    string Name { get; }
    /// <summary>User-visible label (nav, dashboard). Defaults to <see cref="Name"/>.</summary>
    string DisplayName => Name;
    /// <summary>False for on-demand modules (stress tests) that must only run when the user presses Start; excluded from Run All.</summary>
    bool IncludeInRunAll => true;
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default);
    Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default);
    /// <summary>Raised when the module pushes an unsolicited update (e.g. live sensors).</summary>
    event EventHandler<DiagnosticResult>? Updated;
}
