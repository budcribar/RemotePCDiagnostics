using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Battery;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>The battery drain & runtime test (#295): the measurement, the run with fake batteries and Agent, and the Agent's power settings.</summary>
public sealed class BatteryDrainTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpcd-drain-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    internal sealed class FakeClock : IStressClock
    {
        public TimeSpan Elapsed { get; private set; }
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Elapsed += delay;
            return Task.CompletedTask;
        }
    }

    /// <summary>A battery that loses <see cref="MwhPer30s"/> every reading on battery and gains while on AC; the gauge shows
    /// <see cref="GaugeFull"/> as the full charge while it really holds <see cref="RealFull"/>.</summary>
    internal sealed class FakeBattery : IBatteryDrainReadings
    {
        public long RealFull { get; init; } = 50_000;
        public long GaugeFull { get; init; } = 50_000;
        public double Real { get; set; } = 50_000;
        public int DrainMw { get; init; } = 20_000;
        public bool None { get; init; }
        /// <summary>Readings (by number, from 0) taken with the charger connected.</summary>
        public HashSet<int> AcAt { get; init; } = [];
        public int Reads { get; private set; }
        public Action<int>? OnRead { get; set; }

        public Task<BatteryDrainReading?> ReadAsync(CancellationToken ct)
        {
            if (None) return Task.FromResult<BatteryDrainReading?>(null);
            var n = Reads++;
            OnRead?.Invoke(n);
            var ac = AcAt.Contains(n);
            if (n > 0 && !ac && !AcAt.Contains(n - 1)) Real = Math.Max(0, Real - DrainMw * 30.0 / 3600.0);
            // The gauge shows the real energy left as a share of what it thinks a full charge is.
            var pct = (int)Math.Round(Math.Clamp(Real / RealFull * 100, 0, 100));
            var remaining = (long)(GaugeFull * pct / 100.0);
            return Task.FromResult<BatteryDrainReading?>(new(ac, pct, remaining, GaugeFull, ac ? null : DrainMw, 11_500 - n));
        }
    }

    internal sealed class FakeAgent : IBatteryDrainAgent
    {
        public List<string> Verbs { get; } = [];
        public bool Missing { get; init; }
        public Task<BatteryDrainAgentAnswer> SendAsync(string verb, CancellationToken ct)
        {
            Verbs.Add(verb);
            if (Missing) return Task.FromResult(new BatteryDrainAgentAnswer(null, "No Agent.", NeedsAgent: true));
            return Task.FromResult(new BatteryDrainAgentAnswer(new BatteryDrainPowerAnswer(verb is "apply" or "renew", [],
                ShutdownInSeconds: verb == "shutdown" ? 60 : null)));
        }
    }

    internal sealed class FakeLoad : IBatteryDrainLoad
    {
        public List<string> Calls { get; } = [];
        public void Start(BatteryDrainMode mode) => Calls.Add("start " + BatteryDrainReport.ModeArg(mode));
        public void Stop() => Calls.Add("stop");
    }

    internal sealed class MemoryLogStore : IBatteryDrainLogStore
    {
        public BatteryDrainRunLog? Log { get; set; }
        public List<BatteryDrainRunLog?> Writes { get; } = [];
        public BatteryDrainRunLog? Read() => Log;
        public void Write(BatteryDrainRunLog? log) { Log = log; Writes.Add(log); }
    }

    internal static readonly DateTimeOffset Boot = new(2026, 11, 27, 8, 0, 0, TimeSpan.Zero);

    internal static (BatteryDrainModule Module, FakeAgent Agent, FakeLoad Load, MemoryLogStore Logs) Make(FakeBattery battery, FakeAgent? agent = null,
        MemoryLogStore? logs = null, DateTimeOffset? boot = null)
    {
        agent ??= new FakeAgent();
        var load = new FakeLoad();
        logs ??= new MemoryLogStore();
        var clock = new FakeClock();
        var m = new BatteryDrainModule(battery, agent, load, logs, clock: clock, now: () => Boot.AddHours(1) + clock.Elapsed, bootTime: () => boot ?? Boot, processId: () => 42);
        return (m, agent, load, logs);
    }

    private static AreaReport Report(DiagnosticResult r) => Assert.IsType<AreaReport>(r.Payload);
    private static string Row(AreaReport r, string key) => r.Cards[0].Rows.Single(x => x.Key == key).Values[1];

    [Fact]
    public async Task A_confirmed_full_drain_reaches_5_percent_shuts_down_and_passes_when_the_gauge_is_right()
    {
        var (m, agent, load, logs) = Make(new FakeBattery());
        m.ShutdownConfirmed = true;
        var r = await m.RefreshAsync(null);
        var report = Report(r);

        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("apply", agent.Verbs[0]);
        Assert.Equal("shutdown", agent.Verbs[^1]);
        Assert.DoesNotContain("restore", agent.Verbs);
        Assert.All(agent.Verbs.Skip(1).SkipLast(1), v => Assert.Equal("renew", v));
        Assert.Equal(["start max", "stop"], load.Calls);
        Assert.StartsWith("Reached 5 %", Row(report, "end"));
        // The log is finished before the shutdown, then cleared: nothing is left to look like a PC that turned off.
        Assert.Contains(logs.Writes, w => w?.End == nameof(BatteryDrainEnd.ReachedStop));
        Assert.Null(logs.Log);
        var measure = BatteryDrainMeasure.From(m.LastSamples!);
        Assert.InRange(measure.DeliveredRatio!.Value, 0.95, 1.05);
        Assert.InRange(measure.AverageWatts!.Value, 19.9, 20.1);
        Assert.Contains(report.KeyMetrics!, k => k.Id == "batterydrain.deliveredWh");
        Assert.Equal(BatteryDrainReport.SamplesCardId, report.Cards[1].Id);
    }

    [Fact]
    public async Task A_gauge_that_promises_more_than_the_battery_holds_warns_that_it_needs_calibrating()
    {
        // The gauge says 50 Wh, the battery holds 35: the charge falls faster than the energy measured would explain.
        var (m, _, _, _) = Make(new FakeBattery { RealFull = 35_000, GaugeFull = 50_000, Real = 35_000 });
        m.ShutdownConfirmed = true;
        var r = await m.RefreshAsync(null);
        var report = Report(r);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.EndsWith("the gauge needs calibrating", report.Cards[0].Headline);
        Assert.Equal(AreaLevel.Warning, report.Cards[0].Rows.Single(x => x.Key == "delivered-ratio").Level);
        Assert.StartsWith("30 %", Row(report, "gauge-off"));
    }

    [Fact]
    public async Task Without_the_confirmation_the_run_stops_at_15_percent_and_restores_without_shutting_down()
    {
        var (m, agent, _, _) = Make(new FakeBattery());
        var r = await m.RefreshAsync(null);
        var report = Report(r);
        Assert.Equal("restore", agent.Verbs[^1]);
        Assert.DoesNotContain("shutdown", agent.Verbs);
        Assert.Contains("wasn't confirmed", Row(report, "end"));
        Assert.InRange(BatteryDrainMeasure.From(m.LastSamples!).EndPercent!.Value, 14, 15);
        // 85 points drained: enough to judge.
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
    }

    [Fact]
    public async Task Confirming_during_the_run_lets_it_go_on_to_5_percent()
    {
        var battery = new FakeBattery();
        var (m, agent, _, _) = Make(battery);
        battery.OnRead = n => { if (n == 50) m.ShutdownConfirmed = true; };
        await m.RefreshAsync(null);
        Assert.Equal("shutdown", agent.Verbs[^1]);
    }

    [Fact]
    public async Task On_the_charger_it_refuses_to_start_and_changes_nothing()
    {
        var (m, agent, load, _) = Make(new FakeBattery { AcAt = [0] });
        var r = await m.RefreshAsync(null);
        var report = Report(r);
        Assert.Equal("Unplug the charger to start", report.Cards[0].Headline);
        Assert.NotNull(report.CouldNotRunReason);
        Assert.Empty(agent.Verbs);
        Assert.Empty(load.Calls);
    }

    [Fact]
    public async Task A_PC_without_a_battery_is_not_applicable()
    {
        var (m, agent, _, _) = Make(new FakeBattery { None = true });
        var report = Report(await m.RefreshAsync(null));
        Assert.True(report.NotOnThisPc);
        Assert.Empty(agent.Verbs);
    }

    [Fact]
    public async Task Without_the_Agent_it_is_skipped_as_needing_the_Agent()
    {
        var (m, _, load, _) = Make(new FakeBattery(), new FakeAgent { Missing = true });
        var report = Report(await m.RefreshAsync(null));
        Assert.True(report.NotOnThisPc);
        Assert.Equal(BatteryDrainReport.NeedsAgentSummary, report.Summary);
        Assert.Empty(load.Calls);
    }

    [Fact]
    public async Task The_charger_coming_back_pauses_the_run_and_unplugging_it_in_time_resumes_it()
    {
        // Plugged in for readings 10 to 12 (a minute and a half), then unplugged again.
        var (m, agent, load, _) = Make(new FakeBattery { AcAt = [10, 11, 12] });
        m.ShutdownConfirmed = true;
        var report = Report(await m.RefreshAsync(null));
        Assert.Equal(["start max", "stop", "start max", "stop"], load.Calls);
        Assert.Equal("shutdown", agent.Verbs[^1]);
        Assert.True(BatteryDrainMeasure.From(m.LastSamples!).PausedSeconds > 0);
        Assert.Contains(report.Cards[0].Rows, x => x.Key == "paused");
    }

    [Fact]
    public async Task The_charger_staying_connected_past_the_resume_window_ends_the_run_and_restores()
    {
        var (m, agent, _, _) = Make(new FakeBattery { AcAt = [.. Enumerable.Range(5, 100)] });
        var r = await m.RefreshAsync(null);
        var report = Report(r);
        Assert.Equal("restore", agent.Verbs[^1]);
        Assert.Contains("charger was connected", Row(report, "end"));
        Assert.True(report.Cancelled);
    }

    [Fact]
    public async Task Cancelling_stops_the_load_and_puts_the_settings_back()
    {
        var battery = new FakeBattery();
        var (m, agent, load, logs) = Make(battery);
        battery.OnRead = n => { if (n == 20) m.Cancel(); };
        var r = await m.RefreshAsync(null);
        Assert.Equal("restore", agent.Verbs[^1]);
        Assert.Equal("stop", load.Calls[^1]);
        Assert.Null(logs.Log);
        Assert.Contains("before the end", Row(Report(r), "end"));
    }

    [Fact]
    public async Task A_run_cut_short_by_the_PC_turning_off_above_10_percent_fails_at_the_next_run()
    {
        var samples = Enumerable.Range(0, 120).Select(i => new BatteryDrainSample(Boot.AddMinutes(i / 2.0), i * 30, false, 100 - i * 60 / 120,
            50_000 - i * 250L, 50_000, 30_000, 11_000)).ToList();
        var logs = new MemoryLogStore { Log = new BatteryDrainRunLog { Mode = "max", StartedUtc = Boot, BootUtc = Boot, ProcessId = 7, ShutdownConfirmed = true, Samples = samples } };
        var (m, agent, load, _) = Make(new FakeBattery(), logs: logs, boot: Boot.AddHours(2));
        Assert.Equal(BatteryDrainEnd.PcShutOff, m.Leftover()!.Value.End);

        var r = await m.RefreshAsync(null);
        var report = Report(r);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.StartsWith("The PC turned off at 41 %", report.Cards[0].Headline);
        Assert.Equal(["restore"], agent.Verbs);
        Assert.Empty(load.Calls);
        Assert.Null(logs.Log);
        Assert.Null(m.Leftover());
    }

    [Fact]
    public void The_same_boot_means_only_the_app_closed()
    {
        var logs = new MemoryLogStore { Log = new BatteryDrainRunLog { BootUtc = Boot.AddSeconds(30), Samples = [] } };
        var (m, _, _, _) = Make(new FakeBattery(), logs: logs);
        Assert.Equal(BatteryDrainEnd.AppClosed, m.Leftover()!.Value.End);
    }

    [Fact]
    public void Turning_off_between_5_and_10_percent_only_warns()
    {
        var samples = new List<BatteryDrainSample>
        {
            new(Boot, 0, false, 100, 50_000, 50_000, 20_000, 12_000),
            new(Boot.AddHours(2), 7200, false, 8, 4_000, 50_000, 20_000, 10_000),
        };
        var report = BatteryDrainReport.Build(samples, BatteryDrainMode.MaxLoad, BatteryDrainEnd.PcShutOff, true);
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
    }

    [Fact]
    public void The_measure_leaves_out_time_on_the_charger_and_falls_back_to_the_gauge_without_a_rate()
    {
        var s = new List<BatteryDrainSample>
        {
            new(Boot, 0, false, 80, 40_000, 50_000, null, null),
            new(Boot, 3600, false, 60, 30_000, 50_000, null, null),
            new(Boot, 7200, true, 70, 35_000, 50_000, null, null),
            new(Boot, 10800, false, 70, 35_000, 50_000, null, null),
            new(Boot, 14400, false, 50, 25_000, 50_000, null, null),
        };
        var m = BatteryDrainMeasure.From(s);
        Assert.Equal(7200, m.BatterySeconds);
        Assert.Equal(7200, m.PausedSeconds);
        Assert.Equal(40, m.PercentDrained);
        Assert.False(m.DeliveredFromRate);
        Assert.Equal(20_000, m.DeliveredMWh);
        Assert.Equal(1.0, m.DeliveredRatio!.Value, 3);
        Assert.Equal(18000, m.ProjectedRuntimeSeconds!.Value, 0);
    }

    [Fact]
    public void The_run_log_round_trips_and_rejects_another_schema()
    {
        var log = new BatteryDrainRunLog { Mode = "balanced", StartedUtc = Boot, BootUtc = Boot, ProcessId = 3, Samples = [new(Boot, 0, false, 90, 1, 2, 3, 4)] };
        var back = BatteryDrainRunLog.Parse(log.ToJson())!;
        Assert.Equal("balanced", back.Mode);
        Assert.Null(back.End);
        Assert.Equal(90, back.Samples[0].Percent);
        Assert.Null(BatteryDrainRunLog.Parse("""{"schema":2}"""));
        Assert.Null(BatteryDrainRunLog.Parse("not json"));

        var store = new FileBatteryDrainLogStore(Path.Combine(_dir, "run.json"));
        store.Write(log);
        Assert.Equal(3, store.Read()!.ProcessId);
        store.Write(null);
        Assert.Null(store.Read());
    }

    [Fact]
    public async Task The_WMI_readings_add_up_batteries_and_take_the_charge_Windows_shows()
    {
        var wmi = new ScriptedWmi
        {
            [WmiBatteryDrainReadings.StatusSql] = [Row(("PowerOnline", false), ("RemainingCapacity", 20_000), ("DischargeRate", 9_000), ("Voltage", 11_800)),
                                                  Row(("PowerOnline", false), ("RemainingCapacity", 10_000), ("DischargeRate", 3_000), ("Voltage", 11_700))],
            [BatteryReader.FullChargeSql] = [Row(("FullChargedCapacity", 40_000)), Row(("FullChargedCapacity", 20_000))],
            [WmiBatteryDrainReadings.PercentSql] = [Row(("EstimatedChargeRemaining", 50))],
        };
        var r = (await new WmiBatteryDrainReadings(wmi).ReadAsync(default))!;
        Assert.False(r.OnAc);
        Assert.Equal(30_000, r.RemainingMWh);
        Assert.Equal(60_000, r.FullChargeMWh);
        Assert.Equal(12_000, r.DischargeMw);
        Assert.Equal(11_800, r.VoltageMv);
        Assert.Equal(50, r.Percent);

        Assert.Null(await new WmiBatteryDrainReadings(new ScriptedWmi()).ReadAsync(default));
    }

    private static WmiRow Row(params (string Name, object? Value)[] values) =>
        WmiRow.From(values.Select(v => new KeyValuePair<string, object?>(v.Name, v.Value)));

    private sealed class ScriptedWmi : Dictionary<string, IReadOnlyList<WmiRow>>, IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) =>
            Task.FromResult(TryGetValue(wql, out var rows) ? new WmiQueryResult(wmiNamespace, wql, rows) : WmiQueryResult.Failed(wmiNamespace, wql, "Not supported"));
    }

    // --- The Agent's half ---

    private sealed class FakePlan : IPowerPlanValues
    {
        public Guid Scheme { get; } = Guid.NewGuid();
        public Dictionary<Guid, uint> Values { get; } = AgentBatteryDrainPower.Settings.ToDictionary(s => s.Setting, _ => 15u);
        public HashSet<Guid> Refuse { get; } = [];
        public int Activations { get; private set; }
        public Guid? ActiveScheme() => Scheme;
        public uint? ReadDc(Guid scheme, Guid subgroup, Guid setting) => Values.TryGetValue(setting, out var v) ? v : null;
        public bool WriteDc(Guid scheme, Guid subgroup, Guid setting, uint value)
        {
            if (Refuse.Contains(setting)) return false;
            Values[setting] = value;
            return true;
        }
        public void Activate(Guid scheme) => Activations++;
    }

    private (AgentBatteryDrainPower Power, FakePlan Plan, Func<DateTimeOffset, DateTimeOffset> SetNow, List<string> Shutdowns) Power(Func<DateTimeOffset>? boot = null)
    {
        var plan = new FakePlan();
        var now = Boot.AddHours(1);
        var shutdowns = new List<string>();
        var power = new AgentBatteryDrainPower(plan, Path.Combine(_dir, AgentBatteryDrainPower.JournalFile), () => now, boot ?? (() => Boot),
            (s, msg) => { shutdowns.Add($"{s} {msg}"); return null; });
        return (power, plan, t => now = t, shutdowns);
    }

    private static BatteryDrainPowerAnswer Answer(Core.Osquery.ProcessResult pr)
    {
        Assert.Equal(0, pr.ExitCode);
        return BatteryDrainPowerAnswer.Parse(pr.StdOut)!;
    }

    [Fact]
    public void Apply_saves_the_old_values_first_then_sets_the_drain_values_and_restore_puts_them_back()
    {
        var (power, plan, _, _) = Power();
        var applied = Answer(power.Run(new(BatteryDrainPowerAction.Apply)));
        Assert.True(applied.Applied);
        Assert.NotNull(power.ReadJournal());
        foreach (var s in AgentBatteryDrainPower.Settings) Assert.Equal(s.DrainValue, plan.Values[s.Setting]);
        Assert.All(applied.Settings, i => Assert.Equal(15u, i.Previous));

        // Applying again (a second run) keeps the original values in the journal.
        power.Run(new(BatteryDrainPowerAction.Apply));
        Assert.All(power.ReadJournal()!.Previous.Values, v => Assert.Equal(15u, v));

        var restored = Answer(power.Run(new(BatteryDrainPowerAction.Restore)));
        Assert.False(restored.Applied);
        Assert.All(plan.Values.Values, v => Assert.Equal(15u, v));
        Assert.Null(power.ReadJournal());
        Assert.True(plan.Activations >= 2);
    }

    [Fact]
    public void A_setting_Windows_refuses_to_put_back_keeps_the_journal_for_another_try()
    {
        var (power, plan, _, _) = Power();
        power.Run(new(BatteryDrainPowerAction.Apply));
        var sleep = AgentBatteryDrainPower.Settings[0].Setting;
        plan.Refuse.Add(sleep);
        Assert.Equal(1, power.Run(new(BatteryDrainPowerAction.Restore)).ExitCode);
        Assert.NotNull(power.ReadJournal());
        plan.Refuse.Clear();
        Assert.Equal(0, power.Run(new(BatteryDrainPowerAction.Restore)).ExitCode);
        Assert.Equal(15u, plan.Values[sleep]);
    }

    [Fact]
    public void Settings_left_behind_come_back_when_the_lease_runs_out_or_the_PC_restarted()
    {
        var boot = Boot;
        var (power, plan, setNow, _) = Power(() => boot);
        power.Run(new(BatteryDrainPowerAction.Apply));
        setNow(Boot.AddHours(1) + TimeSpan.FromMinutes(2));
        Assert.False(power.RestoreIfAbandoned());
        Assert.Equal(0, power.Run(new(BatteryDrainPowerAction.Renew)).ExitCode);
        setNow(Boot.AddHours(1) + TimeSpan.FromMinutes(4));
        Assert.False(power.RestoreIfAbandoned());

        // A restart: the lease is still valid by the clock, but it was renewed before this boot.
        boot = Boot.AddHours(1) + TimeSpan.FromMinutes(4);
        Assert.True(power.RestoreIfAbandoned());
        Assert.All(plan.Values.Values, v => Assert.Equal(15u, v));

        power.Run(new(BatteryDrainPowerAction.Apply));
        setNow(Boot.AddHours(3));
        Assert.True(power.RestoreIfAbandoned());
        Assert.Equal(1, power.Run(new(BatteryDrainPowerAction.Renew)).ExitCode);
    }

    [Fact]
    public void Shutdown_puts_the_settings_back_then_shuts_down_in_a_minute()
    {
        var (power, plan, _, shutdowns) = Power();
        power.Run(new(BatteryDrainPowerAction.Apply));
        var a = Answer(power.Run(new(BatteryDrainPowerAction.Shutdown)));
        Assert.Equal(60, a.ShutdownInSeconds);
        Assert.Equal($"60 {AgentBatteryDrainPower.ShutdownMessage}", Assert.Single(shutdowns));
        Assert.All(plan.Values.Values, v => Assert.Equal(15u, v));
    }

    [Theory]
    [InlineData("apply", true)]
    [InlineData("renew", true)]
    [InlineData("restore", true)]
    [InlineData("shutdown", true)]
    [InlineData("status", true)]
    [InlineData("reboot", false)]
    [InlineData("", false)]
    public void The_Agent_accepts_only_the_fixed_verbs(string verb, bool ok)
    {
        var plan = AgentScripts.Plan(AgentScripts.Of(AgentScripts.BatteryDrainPower, verb), null, out var refusal);
        Assert.Equal(ok, plan?.Native is BatteryDrainPowerAction);
        Assert.Equal(ok, refusal is null);
        Assert.Null(AgentScripts.Plan(AgentScripts.Of(AgentScripts.BatteryDrainPower, "apply", "extra"), null, out _));
    }

    [Fact]
    public void The_Agent_answer_reader_tells_a_missing_or_old_Agent_from_a_failure()
    {
        Assert.True(AgentBatteryDrainSource.Read(new(SystemCommandRunner.AgentFailedExitCode, "", "Unknown script 'battery_drain_power'.")).NeedsAgent);
        Assert.True(AgentBatteryDrainSource.Read(new(1, "", "Unknown script 'battery_drain_power'.")).NeedsAgent);
        var failed = AgentBatteryDrainSource.Read(new(1, "", "Windows said no."));
        Assert.False(failed.NeedsAgent);
        Assert.Equal("Windows said no.", failed.Error);
        Assert.True(AgentBatteryDrainSource.Read(new(0, new BatteryDrainPowerAnswer(true, []).ToJson(), "")).Ok);
        Assert.False(AgentBatteryDrainSource.Read(null).Ok);
    }

    // ---- Interactive tests page (the person unplugs the charger, so it is an interactive test)

    [Fact]
    public void It_is_an_interactive_test_not_a_stress_or_checks_page_test()
    {
        var d = BuiltInModules.Descriptors.Single(x => x.Slug == ModuleSlugs.BatteryDrain);
        Assert.Equal("interactive", d.Page);
        Assert.False(d.OnStressPage);
    }

    [Fact]
    public void Interactive_data_has_the_drain_test_running_with_its_choices_and_never_checked()
    {
        var at = DateTimeOffset.Now;
        InteractiveExport.ModuleState NotRun(string slug) => new(new DiagnosticResult(slug, DiagnosticStatus.NotRun, "", at), false);
        BatteryDrainSample S(double sec, int pct, long mwh) => new(at.AddSeconds(sec), sec, false, pct, mwh, 50_000, 20_000, 11_500);
        var live = new BatteryDrainLive(BatteryDrainMode.Balanced, "running", "Draining at 90 %.", false, [S(0, 100, 50_000), S(1800, 90, 45_000)]);
        var running = new DiagnosticResult(ModuleSlugs.BatteryDrain, DiagnosticStatus.Running, "Draining", at);
        var page = new InteractiveExport.PageState("batterydrain", ["keyboard"], false, false, false, false);

        using var doc = JsonDocument.Parse(InteractiveExport.ToJson(page, new Core.Workflow.PhysicalBenchQaSnapshot(), NotRun("Webcam"), NotRun("SpeakerToMic"),
            NotRun("MicToSpeaker"), batteryDrain: new(running, BatteryDrainMode.Balanced, true, live)));
        var t = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "batterydrain");
        Assert.True(t.GetProperty("open").GetBoolean());
        Assert.False(t.GetProperty("checked").GetBoolean());
        Assert.Equal("running", t.GetProperty("state").GetString());
        Assert.Equal("balanced", t.GetProperty("mode").GetString());
        Assert.True(t.GetProperty("shutdownConfirmed").GetBoolean());
        Assert.Equal("Draining at 90 %.", t.GetProperty("step").GetString());
        Assert.Equal(90, t.GetProperty("measured").GetProperty("percent").GetInt32());
        Assert.Equal(100, t.GetProperty("measured").GetProperty("startPercent").GetInt32());
        Assert.Contains("unplug the charger", t.GetProperty("instructions").GetString());
        Assert.False(string.IsNullOrEmpty(t.GetProperty("reportIf").GetString()));

        // Not run yet: waiting for the person, nothing measured.
        using var idle = JsonDocument.Parse(InteractiveExport.ToJson(page, new Core.Workflow.PhysicalBenchQaSnapshot(), NotRun("Webcam"), NotRun("SpeakerToMic"), NotRun("MicToSpeaker")));
        var i = idle.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "batterydrain");
        Assert.Equal("waiting-for-person", i.GetProperty("state").GetString());
        Assert.False(i.TryGetProperty("measured", out _));
    }

    [Fact]
    public void The_Interactive_tests_page_has_the_drain_row_and_pane_but_Run_selected_never_starts_it()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "RemotePCDiagnostics.sln"))) root = root.Parent;
        var page = File.ReadAllText(Path.Combine(root!.FullName, "src", "RemotePCDiagnostics.UI", "Pages", "InteractiveTestsPage.razor"));
        Assert.Contains("data-testid=\"interactive-row-batterydrain\"", page);
        Assert.Contains("<BatteryDrainPanel Module=\"drain\"", page);
        Assert.Contains("data-testid=\"batterydrain-start-btn\"", page);
        var allIds = page[page.IndexOf("AllTestIds = [", StringComparison.Ordinal)..];
        Assert.DoesNotContain("\"batterydrain\"", allIds[..allIds.IndexOf(']')]);
        var checks = File.ReadAllText(Path.Combine(root.FullName, "src", "RemotePCDiagnostics.UI", "Pages", "ChecksPage.razor"));
        Assert.DoesNotContain("BatteryDrainPanel", checks);
    }
}
