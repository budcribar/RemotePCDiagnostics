using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests.Battery;

public sealed class ChargerReplugTests
{
    /// <summary>A power state that follows a script: each poll (one per <see cref="ChargerReplug.Poll"/>) moves the clock on.</summary>
    private sealed class ScriptedPower(Func<TimeSpan, PowerLineState?> at) : IPowerLineSource
    {
        public TimeSpan Now { get; set; }
        public PowerLineState? Read() => at(Now);
    }

    private static async Task<(DiagnosticResult Result, List<string> Prompts)> RunAsync(ScriptedPower power)
    {
        var prompts = new List<string>();
        var module = new ChargerReplugModule(power, delay: (d, _) => { power.Now += d; return Task.CompletedTask; });
        var r = await module.RefreshAsync(new SyncProgress(prompts.Add), TestContext.Current.CancellationToken);
        return (r, prompts);
    }

    private sealed class SyncProgress(Action<string> report) : IProgress<string>
    {
        public void Report(string value) => report(value);
    }

    private static readonly PowerLineState Ac = new(true, false, 60), Battery = new(false, false, 60), Charging = new(true, true, 60);

    [Fact]
    public async Task Unplug_and_replug_with_charging_passes()
    {
        // Unplugged 2 s in, plugged back 5 s in, charging from 6 s.
        var power = new ScriptedPower(t => t < TimeSpan.FromSeconds(2) ? Ac : t < TimeSpan.FromSeconds(5) ? Battery : t < TimeSpan.FromSeconds(6) ? Ac : Charging);
        var (r, prompts) = await RunAsync(power);
        var rep = Assert.IsType<ChargerReplugReport>(r.Payload);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(ReplugOutcome.Passed, rep.Outcome);
        Assert.Equal(TimeSpan.FromSeconds(2) + ChargerReplug.Poll, rep.UnplugSeenAfter);
        Assert.Equal(TimeSpan.FromSeconds(3), rep.PlugSeenAfter);
        Assert.True(rep.StartedCharging);
        Assert.Equal([ChargerReplug.UnplugPrompt, ChargerReplug.PlugBackPrompt, ChargerReplug.ChargingPrompt], prompts);
    }

    [Fact]
    public async Task Starting_on_battery_asks_to_plug_in_first()
    {
        var power = new ScriptedPower(t => t < TimeSpan.FromSeconds(3) ? Battery : t < TimeSpan.FromSeconds(6) ? Ac : t < TimeSpan.FromSeconds(8) ? Battery : Charging);
        var (r, prompts) = await RunAsync(power);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(ChargerReplug.PlugInPrompt, prompts[0]);
    }

    [Fact]
    public async Task An_unplug_windows_never_sees_fails_without_overshooting_the_window()
    {
        var power = new ScriptedPower(_ => Ac);
        var (r, _) = await RunAsync(power);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(ReplugOutcome.UnplugNotSeen, ((ChargerReplugReport)r.Payload!).Outcome);
        Assert.Equal(ChargerReplug.StepWindow, power.Now);
    }

    [Fact]
    public async Task A_single_transient_poll_glitch_does_not_count_as_an_unplug()
    {
        // A single 250 ms dip to battery at t = 1 s, then back on AC forever.
        var power = new ScriptedPower(t => t == TimeSpan.FromSeconds(1) ? Battery : Ac);
        var (r, _) = await RunAsync(power);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(ReplugOutcome.UnplugNotSeen, ((ChargerReplugReport)r.Payload!).Outcome);
    }

    [Fact]
    public async Task A_replug_windows_never_sees_fails()
    {
        var (r, _) = await RunAsync(new ScriptedPower(t => t < TimeSpan.FromSeconds(1) ? Ac : Battery));
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(ReplugOutcome.PlugNotSeen, ((ChargerReplugReport)r.Payload!).Outcome);
    }

    [Fact]
    public async Task Not_charging_after_replug_warns_unless_the_battery_is_full()
    {
        var notCharging = await RunAsync(new ScriptedPower(t => t < TimeSpan.FromSeconds(1) ? Ac : t < TimeSpan.FromSeconds(2) ? Battery : Ac));
        Assert.Equal(DiagnosticStatus.Warning, notCharging.Result.Status);
        Assert.Equal(ReplugOutcome.NotCharging, ((ChargerReplugReport)notCharging.Result.Payload!).Outcome);

        PowerLineState full = new(true, false, 100), fullOff = new(false, false, 100);
        var fullPower = new ScriptedPower(t => t < TimeSpan.FromSeconds(1) ? full : t < TimeSpan.FromSeconds(2) ? fullOff : full);
        var fullBattery = await RunAsync(fullPower);
        Assert.Equal(DiagnosticStatus.Ok, fullBattery.Result.Status);
        Assert.Contains("full", fullBattery.Result.Message);
        // Full battery (>=95% on AC) passes promptly without stalling for the 15 s charging window.
        Assert.True(fullPower.Now < TimeSpan.FromSeconds(4), $"Expected fast pass on full battery, took {fullPower.Now}");
    }

    [Fact]
    public async Task Unplugging_during_step_4_at_full_battery_does_not_false_pass()
    {
        // Replug confirmed at t = 2.25 s (while briefly at 94% on AC so Step 4 doesn't exit on poll 0),
        // then unplugged during Step 4 with battery at 95% (OnAc = false).
        PowerLineState ac94 = new(true, false, 94), batt95 = new(false, false, 95);
        var power = new ScriptedPower(t =>
            t < TimeSpan.FromSeconds(1) ? ac94
            : t < TimeSpan.FromSeconds(2) ? batt95
            : t <= TimeSpan.FromSeconds(2) + ChargerReplug.Poll ? ac94
            : batt95);
        var (r, _) = await RunAsync(power);
        var rep = Assert.IsType<ChargerReplugReport>(r.Payload);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal(ReplugOutcome.NotCharging, rep.Outcome);
        Assert.False(rep.StartedCharging);
    }

    [Fact]
    public async Task A_desktop_is_not_applicable()
    {
        var (r, prompts) = await RunAsync(new ScriptedPower(_ => new PowerLineState(true, null, null, HasBattery: false)));
        var rep = (ChargerReplugReport)r.Payload!;
        Assert.Equal(ReplugOutcome.NotApplicable, rep.Outcome);
        Assert.Equal(RunEnd.CouldNotRun, rep.RunEnd);
        Assert.Empty(prompts);
    }

    [Fact]
    public void GetSystemPowerStatus_flags_decode()
    {
        Assert.Equal(new PowerLineState(true, true, 55), WindowsPowerLineSource.FromStatus(1, 8 | 1, 55));
        Assert.Equal(new PowerLineState(false, false, 40), WindowsPowerLineSource.FromStatus(0, 2, 40));
        Assert.Equal(new PowerLineState(true, false, null, HasBattery: false), WindowsPowerLineSource.FromStatus(1, 128, 255));
        Assert.Equal(new PowerLineState(null, null, null), WindowsPowerLineSource.FromStatus(255, 255, 255));
    }
}
