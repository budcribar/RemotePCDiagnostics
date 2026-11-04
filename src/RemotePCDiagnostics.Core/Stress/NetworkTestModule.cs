using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand network stability test. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class NetworkTestModule(IPinger pinger, IGatewayResolver gateway, ISpeedTester speed, IAdapterCounters counters, ISensorProvider sensors,
    NetworkTestSettings? settings = null, Action<string>? log = null, Func<IStressClock>? clockFactory = null) : StressModuleBase<NetworkTestProgress, NetworkTestReport>(log), IStressSuiteModule
{
    public const string ModuleName = "NetworkTest";
    public override string Name => ModuleName;
    public override string DisplayName => "Network stability test";
    string IStressSuiteModule.SuiteName => "Network";
    bool IStressSuiteModule.IsCouldNotRunResult(DiagnosticResult r) => r.Payload is NetworkTestReport { Outcome: NetworkTestOutcome.Failed } or Exception;
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => r.Payload is NetworkTestReport { Outcome: NetworkTestOutcome.Overheated };
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Payload is NetworkTestReport { Outcome: NetworkTestOutcome.StoppedByUser };

    public NetworkTestOptions? Options { get; set; }

    protected override Task<NetworkTestReport> RunTestAsync(StressCleanup cleanup, IProgress<NetworkTestProgress> progress, CancellationToken cancellationToken)
    {
        var opts = (Options ?? new NetworkTestOptions()) with { Duration = Duration };
        var test = new NetworkTest(pinger, gateway, speed, counters, sensors, settings, clockFactory?.Invoke(), log, cleanup);
        return test.RunAsync(opts, progress, cancellationToken);
    }

    protected override (DiagnosticStatus Status, string Headline) Describe(NetworkTestReport report) => (ToStatus(report.Outcome), report.Headline);

    public static DiagnosticStatus ToStatus(NetworkTestOutcome o) => o switch
    {
        NetworkTestOutcome.Stable => DiagnosticStatus.Ok,
        NetworkTestOutcome.SomeLoss or NetworkTestOutcome.StoppedByUser => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };
}
