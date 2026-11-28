using Microsoft.AspNetCore.Components;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.UI.Shared;

/// <summary>
/// Base for a module's own details UI (<see cref="ModuleDescriptor.DetailsComponent"/>). The shell (the module page or the Checks and
/// Stress tests lists) passes the module in, so a details component never looks modules up by type.
/// </summary>
public abstract class ModuleDetailsBase : StoreAwareComponent
{
    /// <summary>The module this UI shows.</summary>
    [Parameter] public IDiagnosticModule? DiagnosticModule { get; set; }

    /// <summary>The app's services, for one a page may use when the app has it (<c>GetService</c>), such as the history store. A page
    /// that renders in the app from results only (resultOnlyUi) uses these instead of injecting its own.</summary>
    [Inject] protected IServiceProvider Services { get; set; } = default!;

    /// <summary>The module's latest result.</summary>
    protected DiagnosticResult? LatestResult => DiagnosticModule is { } m ? Store.Get(m.Name) : null;

    /// <summary>Runs the module through <see cref="DiagnosticsService"/> (no-op when no module was passed).</summary>
    protected Task RunModuleAsync() => DiagnosticModule is { } m ? Diagnostics.RunAsync(m.Name) : Task.CompletedTask;
}

/// <summary>What <see cref="StressTestShell{TReport}"/> reads from its page: the test's result and state, its run length, and Start/Stop.</summary>
public interface IStressTestPage
{
    /// <summary>The test's latest result (not run before its first run).</summary>
    DiagnosticResult Result { get; }
    /// <summary>Something else keeps this test from starting now (another stress test or the stress run): its choices and Start are locked.</summary>
    bool IsBlocked { get; }
    /// <summary>Stop shows in place of Start: this test runs, or a stress run that includes it does.</summary>
    bool ShowStop { get; }
    /// <summary>Start can be pressed once nothing else runs (false: the test has nothing to test, such as no drive).</summary>
    bool CanStart { get; }
    /// <summary>How long the next run takes.</summary>
    TimeSpan Duration { get; }
    /// <summary>The Progress card while the test runs (null before its first report).</summary>
    LiveProgress? Progress { get; }
    void SetDuration(TimeSpan duration);
    void Start();
    void Stop();
}

/// <summary>Shared lifecycle, progress subscription, run length, and Start/Stop for the 5 stress test pages. Their look is
/// <see cref="StressTestShell{TReport}"/>.</summary>
public abstract class StressPageBase<TModule, TProgress, TReport> : ModuleDetailsBase, IStressTestPage
    where TModule : StressModuleBase<TProgress, TReport>
    where TProgress : class
    where TReport : class
{
    protected TModule? Module => DiagnosticModule as TModule;
    protected TimeSpan _duration = TimeSpan.FromMinutes(1);

    /// <summary>The test's latest result.</summary>
    protected DiagnosticResult Result => Store.Get(DiagnosticModule?.Name ?? "");
    protected bool Running => Result.Status == DiagnosticStatus.Running;
    /// <summary>Another stress test or the stress run is going.</summary>
    protected bool OtherBusy => Diagnostics.IsAnyStressRunning && !Running;
    /// <summary>The page's choices can't change now: this test or another one runs.</summary>
    protected bool Locked => Running || OtherBusy;
    /// <summary>The last run's report (for a test that runs once per device, the one the result names).</summary>
    protected TReport? Report => Result.Report() as TReport;
    /// <summary>The current run's live readings (null when it isn't running or before its first report).</summary>
    protected TProgress? Progress => Running ? Module?.LastProgress : null;
    /// <summary>Whether Start can be pressed once nothing else runs.</summary>
    protected virtual bool CanStart => Module is not null;

    DiagnosticResult IStressTestPage.Result => Result;
    bool IStressTestPage.IsBlocked => OtherBusy;
    bool IStressTestPage.ShowStop => Running || Diagnostics.IsStressSuiteRunning;
    bool IStressTestPage.CanStart => CanStart;
    TimeSpan IStressTestPage.Duration => _duration;
    LiveProgress? IStressTestPage.Progress => Running ? Module?.LiveProgress : null;
    void IStressTestPage.SetDuration(TimeSpan duration) => _duration = duration;
    void IStressTestPage.Start() => Start();
    void IStressTestPage.Stop() => Stop();

    protected override void OnInitialized()
    {
        base.OnInitialized();
        if (Module is { } m)
        {
            SyncFromModule(m);
            m.ProgressChanged += OnProgress;
        }
        Diagnostics.StressSuiteProgressChanged += OnSuite;
    }

    protected virtual void SyncFromModule(TModule m) => _duration = m.Duration;
    protected virtual void ApplyToModule(TModule m) => m.Duration = _duration;

    private void OnProgress(object? s, TProgress p) => _ = InvokeAsync(StateHasChanged);

    private void OnSuite(object? s, StressSuiteProgress p)
    {
        if (p.Finished && Module is { } m) SyncFromModule(m);
        _ = InvokeAsync(StateHasChanged);
    }

    protected void Start()
    {
        if (Module is not { } m || Diagnostics.IsRunning(m.Name) || Diagnostics.IsAnyStressRunning || !CanStart) return;
        ApplyToModule(m);
        _ = Diagnostics.RunAsync(m.Name);
    }

    protected void Stop()
    {
        if (Diagnostics.IsStressSuiteRunning) Diagnostics.CancelStressSuite();
        Module?.Stop();
    }

    protected static string Clock(TimeSpan t) => LiveProgress.Clock(t);

    public override void Dispose()
    {
        if (Module is { } m) m.ProgressChanged -= OnProgress;
        Diagnostics.StressSuiteProgressChanged -= OnSuite;
        base.Dispose();
    }
}

/// <summary>Shared device list management, device dropdown renderer, and level formatting for the audio test pages.</summary>
public abstract class AudioPageBase<TModule> : ModuleDetailsBase
    where TModule : class, IAudioTestModule
{
    protected IReadOnlyList<AudioDevice> _outputs = [], _inputs = [];

    protected override void OnInitialized()
    {
        base.OnInitialized();
        if (DiagnosticModule is TModule m) LoadDevices(m);
    }

    protected void LoadDevices(TModule m)
    {
        _outputs = m.Devices(AudioFlow.Output);
        _inputs = m.Devices(AudioFlow.Input);
    }

    protected void Start(TModule m)
    {
        if (Diagnostics.IsStressSuiteRunning) return;
        _ = Diagnostics.RunAsync(m.Name);
    }

    protected static string? Id(ChangeEventArgs e) => e.Value?.ToString() is { Length: > 0 } v ? v : null;

    protected static RenderFragment DeviceOptions(IReadOnlyList<AudioDevice> devices, string? selected) => builder =>
    {
        if (devices.Count == 0)
        {
            builder.OpenElement(0, "option");
            builder.AddAttribute(1, "value", "");
            builder.AddContent(2, "None found");
            builder.CloseElement();
        }
        else
        {
            builder.OpenElement(3, "option");
            builder.AddAttribute(4, "value", "");
            builder.AddAttribute(5, "selected", selected is null);
            builder.AddContent(6, "Windows default");
            builder.CloseElement();
            foreach (var d in devices)
            {
                builder.OpenElement(7, "option");
                builder.AddAttribute(8, "value", d.Id);
                builder.AddAttribute(9, "selected", d.Id == selected);
                builder.AddContent(10, d.Label);
                builder.CloseElement();
            }
        }
    };

    protected static string Db(double v) => v <= AudioMath.SilenceDbfs ? "silent" : $"{v:0.0} dBFS";
}

