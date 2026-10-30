using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand network stability test. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class NetworkTestModule(IPinger pinger, IGatewayResolver gateway, ISpeedTester speed, IAdapterCounters counters, ISensorProvider sensors,
    NetworkTestSettings? settings = null, Action<string>? log = null, Func<IStressClock>? clockFactory = null) : IStressSuiteModule
{
    public const string ModuleName = "NetworkTest";
    public string Name => ModuleName;
    public string DisplayName => "Network stability test";
    public bool IncludeInRunAll => false;
    public event EventHandler<DiagnosticResult>? Updated;
    string IStressSuiteModule.SuiteName => "Network";
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => r.Payload is NetworkTestReport { Outcome: NetworkTestOutcome.Overheated };
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Payload is NetworkTestReport { Outcome: NetworkTestOutcome.StoppedByUser };
    public event EventHandler<NetworkTestProgress>? ProgressChanged;

    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(1);
    public NetworkTestOptions? Options { get; set; }
    public NetworkTestProgress? LastProgress { get; private set; }

    private CancellationTokenSource? _stop;
    private readonly object _gate = new();

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    public void Stop()
    {
        lock (_gate) { try { _stop?.Cancel(); } catch (ObjectDisposedException) { } }
    }

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_gate) _stop = stop;
        try
        {
            LastProgress = null;
            var opts = (Options ?? new NetworkTestOptions()) with { Duration = Duration };
            var test = new NetworkTest(pinger, gateway, speed, counters, sensors, settings, clockFactory?.Invoke(), log);
            var report = await test.RunAsync(opts, new P(x => { LastProgress = x; ProgressChanged?.Invoke(this, x); }), stop.Token).ConfigureAwait(false);
            return new DiagnosticResult<NetworkTestReport>(Name, ToStatus(report.Outcome), report.Headline, DateTimeOffset.Now, report);
        }
        finally { lock (_gate) _stop = null; }
    }

    public static DiagnosticStatus ToStatus(NetworkTestOutcome o) => o switch
    {
        NetworkTestOutcome.Stable => DiagnosticStatus.Ok,
        NetworkTestOutcome.SomeLoss or NetworkTestOutcome.StoppedByUser => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };

    private sealed class P(Action<NetworkTestProgress> a) : IProgress<NetworkTestProgress> { public void Report(NetworkTestProgress v) => a(v); }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
