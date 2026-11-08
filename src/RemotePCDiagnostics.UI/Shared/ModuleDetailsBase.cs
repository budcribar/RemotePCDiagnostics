using System.Globalization;
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

/// <summary>Shared lifecycle, progress subscription, duration selector, and Start/Stop controls for the 5 stress test pages.</summary>
public abstract class StressPageBase<TModule, TProgress, TReport> : ModuleDetailsBase
    where TModule : StressModuleBase<TProgress, TReport>
    where TProgress : class
{
    protected TModule? Module => DiagnosticModule as TModule;
    protected TimeSpan _duration = TimeSpan.FromMinutes(1);

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

    protected void SetDuration(ChangeEventArgs e)
    {
        if (double.TryParse(e.Value?.ToString(), CultureInfo.InvariantCulture, out var min)) _duration = TimeSpan.FromMinutes(min);
    }

    protected void Start()
    {
        if (Module is not { } m || Diagnostics.IsRunning(m.Name) || Diagnostics.IsAnyStressRunning) return;
        ApplyToModule(m);
        _ = Diagnostics.RunAsync(m.Name);
    }

    protected void Stop()
    {
        if (Diagnostics.IsStressSuiteRunning) Diagnostics.CancelStressSuite();
        Module?.Stop();
    }

    protected static string Minutes(TimeSpan d) => d.TotalMinutes == 1 ? "1 minute" : $"{d.TotalMinutes:0} minutes";
    protected static string Clock(TimeSpan t) => $"{(int)t.TotalMinutes}:{t.Seconds:00}";

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

