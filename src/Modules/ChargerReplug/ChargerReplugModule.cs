using static RemotePCDiagnostics.Core.Areas.ChargerReplug;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// The interactive charger test (<see cref="ChargerReplug"/> has its rules): asks the person to unplug the charger, then to plug it back in,
/// and polls the power state (<see cref="IPowerLineSource"/>) for each change and for charging to start. Changes nothing on the PC.
/// </summary>
public sealed class ChargerReplugModule(IPowerLineSource power, ILogger? log = null, Func<TimeSpan, CancellationToken, Task>? delay = null) : OnDemandModuleBase(log)
{
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? Task.Delay;

    public override string Name => ModuleSlugs.ChargerReplug;
    public override Guid Id => ModuleIds.ChargerReplug;
    public override string DisplayName => "Charger replug test";

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var start = power.Read();
        if (start is { HasBattery: false }) return ToResult(new(ReplugOutcome.NotApplicable, null, null, null, null));
        if (start?.OnAc is null) return ToResult(new(ReplugOutcome.NotReported, null, null, null, start?.Percent));

        if (start.OnAc == false)
        {
            progress?.Report(PlugInPrompt);
            if (await WaitAsync(s => s.OnAc == true, PlugInFirstWindow, ct).ConfigureAwait(false) is null)
                return ToResult(new(ReplugOutcome.NeverPluggedIn, null, null, null, power.Read()?.Percent));
        }

        progress?.Report(UnplugPrompt);
        var unplug = await WaitAsync(s => s.OnAc == false, StepWindow, ct).ConfigureAwait(false);
        if (unplug is null) return ToResult(new(ReplugOutcome.UnplugNotSeen, null, null, null, power.Read()?.Percent));
        Log($"{Name}: on battery after {unplug.Value.TotalSeconds:0.0} s");

        progress?.Report(PlugBackPrompt);
        var plug = await WaitAsync(s => s.OnAc == true, StepWindow, ct).ConfigureAwait(false);
        if (plug is null) return ToResult(new(ReplugOutcome.PlugNotSeen, unplug, null, null, power.Read()?.Percent));
        Log($"{Name}: on wall power after {plug.Value.TotalSeconds:0.0} s");

        progress?.Report(ChargingPrompt);
        var charging = await WaitAsync(s => s.Charging == true, ChargingWindow, ct).ConfigureAwait(false) is not null;
        var end = power.Read();
        var full = end?.Percent is >= FullPercent;
        return ToResult(new(charging || full ? ReplugOutcome.Passed : ReplugOutcome.NotCharging, unplug, plug, charging, end?.Percent));
    }

    /// <summary>Polls until <paramref name="done"/> holds; returns how long that took, or null after <paramref name="window"/>.</summary>
    private async Task<TimeSpan?> WaitAsync(Func<PowerLineState, bool> done, TimeSpan window, CancellationToken ct)
    {
        for (var waited = TimeSpan.Zero; waited <= window; waited += Poll)
        {
            if (power.Read() is { } s && done(s)) return waited;
            await _delay(Poll, ct).ConfigureAwait(false);
        }
        return null;
    }
}
