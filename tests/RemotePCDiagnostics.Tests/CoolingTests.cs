using Bunit;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Cooling;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>The cooling test (#284): heat at low load, fan response under load, and thermal modes, without hardware.</summary>
public sealed class CoolingTests
{
    /// <summary>Each delay moves time on at once.</summary>
    private sealed class InstantClock : IStressClock
    {
        public TimeSpan Elapsed { get; private set; }
        public Task DelayAsync(TimeSpan delay, CancellationToken ct) { ct.ThrowIfCancellationRequested(); Elapsed += delay; return Task.CompletedTask; }
    }

    private sealed class FakeLoad : ICoolingLoad
    {
        public int Started, Stopped;
        public bool Running => Started > Stopped;
        public IAsyncDisposable Start() { Started++; return new Stop(this); }
        private sealed class Stop(FakeLoad l) : IAsyncDisposable { public ValueTask DisposeAsync() { l.Stopped++; return ValueTask.CompletedTask; } }
    }

    /// <summary>A PC whose readings are a function of whether the load runs and how long it has run, and an Agent with fake modes.</summary>
    private sealed class FakePc(FakeLoad load, Func<int, bool, CoolingReading> reading) : ICoolingSource
    {
        private int _idle, _loaded;
        public bool NoAgent { get; init; }
        /// <summary>Kind -> (current, options). A set changes current unless the id is in <see cref="Sticky"/>.</summary>
        public Dictionary<string, (string? Current, List<CoolingModeOption> Options)> Modes { get; } = new()
        {
            [CoolingModes.WindowsKind] = (WindowsPowerMode.Balanced.ToString(), [.. WindowsPowerMode.Options]),
            [CoolingModes.MakerKind] = (null, []),
        };
        public HashSet<string> Sticky { get; } = [];
        public List<string> Requests { get; } = [];
        public Action<string>? OnRequest { get; init; }

        public Task<CoolingReading> SampleAsync(CancellationToken ct) =>
            Task.FromResult(load.Running ? reading(_loaded++, true) : reading(_idle++, false));

        public Task<CoolingModesReply> ModesAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            var request = string.Join(' ', args);
            Requests.Add(request);
            OnRequest?.Invoke(request);
            if (NoAgent) return Task.FromResult(CoolingModesReply.Failed("The Agent isn't connected.", noAgent: true));
            if (args[0] == CoolingModesAction.Set && !Sticky.Contains(args[2]))
                Modes[args[1]] = (args[2], Modes[args[1]].Options);
            if (args[0] == CoolingModesAction.Restore)
                Modes[CoolingModes.WindowsKind] = (WindowsPowerMode.Balanced.ToString(), Modes[CoolingModes.WindowsKind].Options);
            var groups = Modes.Select(m => new CoolingModeGroup(m.Key, m.Key == CoolingModes.WindowsKind ? "Windows power mode" : "Maker thermal mode",
                m.Value.Current, m.Value.Options, m.Value.Options.Count == 0 ? "No maker modes here." : null)).ToList();
            return Task.FromResult(new CoolingModesReply(new CoolingModesAnswer(groups, Restored: args[0] == CoolingModesAction.Restore ? true : null), null));
        }
    }

    private static readonly CoolingRules Fast = new() { IdleQuick = TimeSpan.FromSeconds(120), LoadFor = TimeSpan.FromSeconds(90), CoolFor = TimeSpan.FromSeconds(30) };

    /// <summary>Healthy: 45 °C at 5 % load, fan 2,000; under load it warms to 75 °C over 40 s then levels off, the fan goes to 4,000.</summary>
    private static CoolingReading Healthy(int i, bool loaded) => loaded
        ? new(Math.Min(75, 45 + i * 0.75), null, 99, 4000, 1)
        : new(45, null, 5, 2000, 1);

    private static (CoolingTestModule Module, FakePc Pc, FakeLoad Load) Make(Func<int, bool, CoolingReading> reading, bool noAgent = false, Action<string>? onRequest = null)
    {
        var load = new FakeLoad();
        var pc = new FakePc(load, reading) { NoAgent = noAgent, OnRequest = onRequest };
        return (new CoolingTestModule(pc, load, () => "TestMaker", rules: Fast, clock: new InstantClock()), pc, load);
    }

    private static async Task<AreaReport> Run(CoolingTestModule m)
    {
        var r = await m.RefreshAsync(null);
        return Assert.IsType<AreaReport>(r.Report());
    }

    private static AreaCard Card(AreaReport r, string id) => Assert.Single(r.Cards, c => c.Id == id);

    [Fact]
    public async Task A_healthy_pc_passes_every_part_and_the_modes_are_put_back()
    {
        var (m, pc, load) = Make(Healthy);
        var r = await Run(m);

        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.StartsWith("Passed: typically 45°C at low load", r.Summary);
        Assert.Equal(AreaLevel.Ok, Card(r, CoolingJudge.IdleCard).Level);
        var fans = Card(r, CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Ok, fans.Level);
        Assert.Contains("fans rose from 2,000 RPM to 4,000 RPM", fans.Headline);
        Assert.Contains("leveled off at 75°C", fans.Headline);
        Assert.Equal(AreaLevel.Neutral, Card(r, CoolingJudge.FanControlCard).Level);
        var modes = Card(r, CoolingJudge.ModesCard);
        Assert.Equal(AreaLevel.Ok, modes.Level);
        Assert.Equal("Passed: 3 modes set and read back, then put back", modes.Headline);
        Assert.Equal(CoolingModesAction.Restore, pc.Requests[^1]);
        Assert.Equal(1, load.Started);
        Assert.Equal(1, load.Stopped);
        Assert.Contains(r.KeyMetrics!, k => k.Id == "cooling.idle-cpu" && k.Value == 45);
        // The chart card: one row every 5 s, with every phase.
        var samples = Card(r, CoolingJudge.SamplesCard);
        Assert.Contains(samples.Rows, x => x.Key == CoolingRules.Idle);
        Assert.Contains(samples.Rows, x => x.Key == CoolingRules.Load);
        Assert.Contains(samples.Rows, x => x.Key == CoolingRules.Cool);
        Assert.InRange(samples.Rows.Count, 45, 55);
    }

    [Fact]
    public async Task A_cpu_near_tj_max_for_a_minute_at_low_load_fails_hot_at_low_load()
    {
        var (m, _, _) = Make((i, loaded) => loaded ? new(97, 100, 99, 5000, 1) : new(93, 100, 4, 2000, 1));
        var r = await Run(m);
        var idle = Card(r, CoolingJudge.IdleCard);
        Assert.Equal(AreaLevel.Error, idle.Level);
        Assert.StartsWith("Hot at low load: above 90°C", idle.Headline);
        Assert.Contains("Tj max 100°C reported by the CPU", idle.Meta);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(idle.Headline, r.Summary);
    }

    [Fact]
    public async Task Hot_only_while_busy_is_a_workload_not_a_cooling_fault()
    {
        // 93 °C, but the PC's own apps keep the CPU 80 % busy: the passive part can't judge, so it warns instead of failing.
        var (m, _, _) = Make((i, loaded) => loaded ? new(95, null, 99, 5000, 1) : new(93, null, 80, 3000, 1));
        var idle = Card(await Run(m), CoolingJudge.IdleCard);
        Assert.Equal(AreaLevel.Warning, idle.Level);
        Assert.Contains("stayed busy", idle.Headline);
    }

    [Fact]
    public void Hot_samples_must_persist_for_sixty_seconds_in_a_row()
    {
        var r = CoolingRules.Default;
        var broken = Enumerable.Range(0, 120).Select(i => new CoolingSample(i, CoolingRules.Idle, i % 50 == 49 ? 60 : 95, 5, 2000)).ToList();
        Assert.Equal(49, CoolingJudge.LongestHotAtLowLoad(broken, 90, r));
        Assert.Equal(AreaLevel.Warning, CoolingJudge.IdleVerdict(broken, null, false, r).Level);
        var steady = Enumerable.Range(0, 120).Select(i => new CoolingSample(i, CoolingRules.Idle, i >= 50 ? 95 : 60, 5, 2000)).ToList();
        Assert.Equal(70, CoolingJudge.LongestHotAtLowLoad(steady, 90, r));
        Assert.Equal(AreaLevel.Error, CoolingJudge.IdleVerdict(steady, null, false, r).Level);
    }

    [Fact]
    public async Task A_fan_that_stays_flat_while_the_cpu_heats_fails()
    {
        var (m, _, _) = Make((i, loaded) => loaded ? new(Math.Min(85, 45 + i), null, 99, 2050, 1) : new(45, null, 5, 2000, 1));
        var fans = Card(await Run(m), CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Error, fans.Level);
        Assert.StartsWith("Fan not responding: it stayed at about 2,050 RPM while the CPU heated from 45°C to 85°C", fans.Headline);
    }

    [Fact]
    public async Task A_fan_reading_zero_while_the_cpu_heats_fails()
    {
        var (m, _, _) = Make((i, loaded) => loaded ? new(Math.Min(85, 45 + i), null, 99, 0, 1) : new(45, null, 5, 0, 1));
        var fans = Card(await Run(m), CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Error, fans.Level);
        Assert.StartsWith("Fan not responding: it read 0 RPM the whole time", fans.Headline);
    }

    [Fact]
    public async Task A_fan_that_starts_from_a_stop_counts_as_rising()
    {
        var (m, _, _) = Make((i, loaded) => loaded ? new(Math.Min(70, 40 + i), null, 99, i > 10 ? 3200 : 0, 1) : new(40, null, 3, 0, 1));
        var fans = Card(await Run(m), CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Ok, fans.Level);
        Assert.Contains("fans started and reached 3,200 RPM", fans.Headline);
    }

    [Fact]
    public async Task No_fan_readings_is_a_warning()
    {
        var (m, _, _) = Make((i, loaded) => loaded ? new(Math.Min(70, 40 + i), null, 99, null) : new(40, null, 3, null));
        var r = await Run(m);
        var fans = Card(r, CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Warning, fans.Level);
        Assert.StartsWith("No fan readings", fans.Headline);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
    }

    [Fact]
    public async Task Still_heating_at_the_end_of_the_load_warns()
    {
        var (m, _, _) = Make((i, loaded) => loaded ? new(45 + i * 0.4, null, 99, 4500, 1) : new(45, null, 5, 2000, 1));
        var fans = Card(await Run(m), CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Warning, fans.Level);
        Assert.Contains("still heating at the end of the load", fans.Headline);
    }

    [Fact]
    public async Task The_load_stops_early_near_tj_max()
    {
        var (m, _, load) = Make((i, loaded) => loaded ? new(60 + i * 2, 100, 99, 5000, 1) : new(50, 100, 5, 2500, 1));
        var r = await Run(m);
        var fans = Card(r, CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Warning, fans.Level);
        Assert.Contains("the load was stopped early", fans.Headline);
        Assert.Equal(1, load.Stopped);
        // 60 + 2i >= 97 at the 19th loaded sample: far fewer than 90.
        Assert.True(m.LiveSamples.Count(s => s.Phase == CoolingRules.Load) < 25);
    }

    [Fact]
    public async Task A_mode_that_doesnt_read_back_fails_profile_wont_set_and_the_rest_are_still_put_back()
    {
        var (m, pc, _) = Make(Healthy);
        pc.Sticky.Add(WindowsPowerMode.BestPerformance.ToString());
        var r = await Run(m);
        var modes = Card(r, CoolingJudge.ModesCard);
        Assert.Equal(AreaLevel.Error, modes.Level);
        Assert.StartsWith("Profile won't set: Best performance (reads Balanced)", modes.Headline);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(CoolingModesAction.Restore, pc.Requests[^1]);
    }

    [Fact]
    public async Task Without_the_agent_the_modes_are_skipped_not_failed()
    {
        var (m, pc, _) = Make(Healthy, noAgent: true);
        var r = await Run(m);
        var modes = Card(r, CoolingJudge.ModesCard);
        Assert.Equal(AreaLevel.Neutral, modes.Level);
        Assert.StartsWith("Skipped: Needs the Agent", modes.Headline);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal([CoolingModesAction.List], pc.Requests);
    }

    [Fact]
    public async Task Modes_can_be_left_alone()
    {
        var (m, pc, _) = Make(Healthy);
        m.SwitchModes = false;
        var r = await Run(m);
        Assert.DoesNotContain(r.Cards, c => c.Id == CoolingJudge.ModesCard);
        Assert.Empty(pc.Requests);
    }

    [Fact]
    public async Task Cancelling_while_modes_switch_puts_them_back()
    {
        CoolingTestModule? module = null;
        var (m, pc, load) = Make(Healthy, onRequest: req => { if (req.StartsWith("set", StringComparison.Ordinal)) module!.Cancel(); });
        module = m;
        var r = await Run(m);
        Assert.True(r.Cancelled);
        Assert.Contains("thermal modes put back", r.Summary);
        Assert.Equal(CoolingModesAction.Restore, pc.Requests[^1]);
        Assert.Equal(load.Started, load.Stopped);
    }

    [Fact]
    public async Task A_pc_with_no_temperature_or_fan_is_not_loaded()
    {
        var (m, _, load) = Make((_, _) => new(null, null, 5, null));
        var r = await Run(m);
        Assert.True(r.NotOnThisPc);
        Assert.Equal(0, load.Started);
    }

    [Fact]
    public async Task Full_watches_low_load_for_five_minutes()
    {
        var load = new FakeLoad();
        var pc = new FakePc(load, Healthy);
        var m = new CoolingTestModule(pc, load, clock: new InstantClock()) { Mode = CoolingTestMode.Full, SwitchModes = false };
        var r = await Run(m);
        Assert.Equal(300, m.LiveSamples.Last(s => s.Phase == CoolingRules.Idle).At);
        Assert.Equal(TimeSpan.FromMinutes(7), m.Estimated);
        var samples = Card(r, CoolingJudge.SamplesCard);
        Assert.True(samples.Rows.Count <= AreaReportExport.MaxRowsPerCard);
        Assert.Contains(samples.Rows, x => x.Key == CoolingRules.Idle);
        Assert.Contains(samples.Rows, x => x.Key == CoolingRules.Load);
        Assert.Contains(samples.Rows, x => x.Key == CoolingRules.Cool);
    }

    [Fact]
    public async Task A_cool_zero_rpm_pc_warming_modestly_does_not_false_fail()
    {
        var (m, _, _) = Make((i, loaded) => loaded ? new(Math.Min(45, 38 + i * 0.5), null, 99, 0, 1) : new(38, null, 5, 0, 1));
        var fans = Card(await Run(m), CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Ok, fans.Level);
        Assert.DoesNotContain("Fan not responding", fans.Headline);
    }

    [Fact]
    public async Task Missing_idle_fan_baseline_does_not_false_fail_fan_not_responding()
    {
        var (m, _, _) = Make((i, loaded) => loaded ? new(Math.Min(75, 45 + i), null, 99, 3200, 1) : new(45, null, 5, null, 0));
        var fans = Card(await Run(m), CoolingJudge.FansCard);
        Assert.Equal(AreaLevel.Warning, fans.Level);
        Assert.DoesNotContain("Fan not responding", fans.Headline);
    }

    [Fact]
    public async Task A_non_cancellation_exception_while_modes_switch_still_puts_them_back()
    {
        var sets = 0;
        var (m, pc, _) = Make(Healthy, onRequest: req => { if (req.StartsWith("set", StringComparison.Ordinal) && ++sets == 2) throw new InvalidOperationException("boom"); });
        var r = await Run(m);
        Assert.False(r.Cancelled);
        Assert.Equal(CoolingModesAction.Restore, pc.Requests[^1]);
        Assert.Equal(WindowsPowerMode.Balanced.ToString(), pc.Modes[CoolingModes.WindowsKind].Current);
    }

    [Fact]
    public void The_reading_takes_tj_max_from_intel_distances_and_leaves_them_out_of_the_temperature()
    {
        SensorReading T(string name, double v) => new("Intel Core i7-1185G7", HardwareKind.Cpu, name, SensorKind.Temperature, v, null, null, "°C");
        var snap = new SensorSnapshot([
            T("CPU Core #1", 52), T("CPU Core #2", 55), T("CPU Core #1 Distance to TjMax", 48), T("CPU Core #2 Distance to TjMax", 45),
            new("Board", HardwareKind.Motherboard, "Fan #1", SensorKind.Fan, 2100, null, null, "RPM"),
        ], IsElevated: true);
        var r = CoolingReading.From(snap, 12);
        Assert.Equal(55, r.CpuC);
        Assert.Equal(100, r.TjMaxC);
        Assert.Equal(2100, r.FanRpm);
        Assert.Equal(12, r.LoadPercent);
        Assert.Null(CoolingReading.From(new SensorSnapshot([T("CPU Package", 60)], true), null).TjMaxC);
    }

    [Fact]
    public void Cpu_load_comes_from_the_idle_share_of_system_time()
    {
        Assert.Equal(25, WindowsCpuLoadSource.Busy(0, 0, 750, 1000));
        Assert.Null(WindowsCpuLoadSource.Busy(10, 100, 20, 100));
    }

    [Fact]
    public void The_agent_takes_only_the_requests_the_app_sends()
    {
        AgentNativeAction? Plan(params string[] args) => AgentScripts.Plan(AgentScripts.Of(AgentScripts.CoolingModes, args), null, out _)?.Native;
        Assert.Equal(new CoolingModesAction("list"), Plan("list"));
        Assert.Equal(new CoolingModesAction("restore"), Plan("restore"));
        Assert.Equal(new CoolingModesAction("set", "windows", WindowsPowerMode.BestPerformance.ToString()), Plan("set", "windows", WindowsPowerMode.BestPerformance.ToString()));
        Assert.Equal(new CoolingModesAction("set", "maker", "2"), Plan("set", "maker", "2"));
        Assert.Null(Plan("set", "windows", Guid.NewGuid().ToString()));
        Assert.Null(Plan("set", "fan", "100"));
        Assert.Null(Plan("set", "maker", "x\ny"));
        Assert.Null(Plan("list", "extra"));
        Assert.Null(Plan());
    }

    private sealed class FakeSetting(string kind, string current, params string[] options) : IThermalModeSetting
    {
        public string Current = current;
        public bool Refuse;
        public string Kind => kind;
        public CoolingModeGroup? Read() => new(kind, kind, Current, options.Select(o => new CoolingModeOption(o, o)).ToList());
        public string? Set(string id) { if (Refuse) return "refused"; Current = id; return null; }
    }

    [Fact]
    public void The_agent_journals_before_the_first_switch_and_restores_from_it()
    {
        var dir = Directory.CreateTempSubdirectory("cooling-");
        try
        {
            var journal = Path.Combine(dir.FullName, CoolingModes.JournalFile);
            var windows = new FakeSetting(CoolingModes.WindowsKind, "a", "a", "b", "c");
            var maker = new FakeSetting(CoolingModes.MakerKind, "1", "0", "1", "2");
            var agent = new AgentCoolingModes([windows, maker], journal);

            var refused = agent.Run(new CoolingModesAction("set", CoolingModes.MakerKind, "9"));
            Assert.Equal(1, refused.ExitCode);
            Assert.False(File.Exists(journal));

            var set = agent.Run(new CoolingModesAction("set", CoolingModes.WindowsKind, "c"));
            Assert.Equal(0, set.ExitCode);
            Assert.Equal("c", CoolingModesAnswer.Parse(set.StdOut)!.Group(CoolingModes.WindowsKind)!.Current);
            Assert.True(File.Exists(journal));
            agent.Run(new CoolingModesAction("set", CoolingModes.MakerKind, "2"));

            // A crash here: the next start puts both back from the journal written before the first switch.
            new AgentCoolingModes([windows, maker], journal).RecoverAtStart();
            Assert.Equal("a", windows.Current);
            Assert.Equal("1", maker.Current);
            Assert.False(File.Exists(journal));

            // A restore that fails keeps the journal so it is tried again.
            agent.Run(new CoolingModesAction("set", CoolingModes.MakerKind, "0"));
            maker.Refuse = true;
            var restore = agent.Run(new CoolingModesAction("restore"));
            Assert.False(CoolingModesAnswer.Parse(restore.StdOut)!.Restored);
            Assert.True(File.Exists(journal));
            maker.Refuse = false;
            Assert.True(CoolingModesAnswer.Parse(agent.Run(new CoolingModesAction("restore")).StdOut)!.Restored);
            Assert.Equal("1", maker.Current);
        }
        finally { dir.Delete(true); }
    }

    [Fact]
    public void Windows_power_mode_is_offered_only_on_the_balanced_plan()
    {
        Assert.Equal(3, WindowsPowerMode.Describe(WindowsPowerMode.BalancedPlan, WindowsPowerMode.BestPerformance).Options.Count);
        var other = WindowsPowerMode.Describe(Guid.NewGuid(), Guid.Empty);
        Assert.Empty(other.Options);
        Assert.Contains("Balanced power plan", other.Note);
        Assert.Equal(Guid.Empty.ToString(), WindowsPowerMode.Describe(WindowsPowerMode.BalancedPlan, WindowsPowerMode.BetterPerformance).Current);
    }

    private sealed class FakeHpBios(int readCode, byte current) : IHpBiosCalls
    {
        public byte Current = current;
        public (int, byte[]?) Call(int command, int query, byte[] input)
        {
            Assert.Equal(HpThermalProfileSetting.Query, query);
            if (readCode != 0) return (readCode, null);
            if (command == HpThermalProfileSetting.WriteCommand) Current = input[0];
            return (0, [Current, 0, 0, 0]);
        }
    }

    [Fact]
    public void Hp_thermal_profiles_read_and_set_one_byte_and_unsupported_pcs_list_none()
    {
        var bios = new FakeHpBios(0, 1);
        var hp = new HpThermalProfileSetting(bios);
        var g = hp.Read()!;
        Assert.Equal("1", g.Current);
        Assert.Equal(["Balanced", "Performance", "Cool", "Quiet"], g.Options.Select(o => o.Name));
        Assert.Null(hp.Set("3"));
        Assert.Equal("3", hp.Read()!.Current);
        Assert.NotNull(hp.Set("7"));

        var business = new HpThermalProfileSetting(new FakeHpBios(4, 0)).Read()!;
        Assert.Empty(business.Options);
        Assert.Contains("not supported", business.Note);
    }

    [Fact]
    public async Task A_recorded_run_replays_to_the_same_verdict()
    {
        var calls = new CallRecorder();
        var load = new FakeLoad();
        var recording = new RecordingCoolingSource(new FakePc(load, Healthy), calls);
        var recorded = await Run(new CoolingTestModule(recording, load, rules: Fast, clock: new InstantClock()));

        var replay = new RecordingReplay(calls.Snapshot());
        var replayed = await Run(new CoolingTestModule(replay.Cooling, new FakeLoad(), rules: Fast, clock: new InstantClock()));

        Assert.Equal(recorded.Status, replayed.Status);
        Assert.Equal(recorded.Summary, replayed.Summary);
        Assert.Equal(recorded.Cards.Select(c => (c.Id, c.Level, c.Headline)), replayed.Cards.Select(c => (c.Id, c.Level, c.Headline)));
        Assert.Contains(calls.Snapshot(), c => c.Kind == RecordedCall.CoolingKind && c.Query == "list");
    }

    [Fact]
    public void The_cooling_test_is_on_demand_in_hardware()
    {
        var d = Assert.Single(BuiltInModules.Descriptors, x => x.Id == ModuleIds.Cooling);
        Assert.Equal(ModuleKind.OnDemand, d.Kind);
        Assert.Equal(ModuleGroups.Hardware, d.Group);
        Assert.False(new CoolingTestModule(new FakePc(new FakeLoad(), Healthy), new FakeLoad()).IncludeInRunAll);
    }

    [Fact]
    public void The_cooling_test_lives_on_the_stress_tests_page()
    {
        var store = new ResultStore();
        var cooling = new CoolingTestModule(new FakePc(new FakeLoad(), Healthy), new FakeLoad());
        var diag = new DiagnosticsService(store, [cooling]);
        var screen = new ChecksScreenState(diag, store);
        // Through the interface, as Run all and the catalog see it (a plain property on the class would not reimplement it).
        Assert.False(((IDiagnosticModule)cooling).IncludeInRunAll);
        Assert.Equal(ModuleKind.OnDemand, diag.Catalog.Get(cooling.Id)?.Kind);
        Assert.Equal(ChecksScreenState.StressRoute, screen.PageFor(cooling.Name));
        Assert.Equal(CheckGroup.Stress, screen.GroupOf(cooling.Name));
        Assert.Contains(screen.StressModules, m => m.Name == cooling.Name);
        Assert.Empty(screen.ChecksModules);
    }
}

/// <summary>The cooling test's page part: the next run's choices, and the chart from the last run's samples card.</summary>
public sealed class CoolingDetailsTests : BunitContext
{
    private sealed class Idle : ICoolingSource
    {
        public Task<CoolingReading> SampleAsync(CancellationToken ct) => Task.FromResult(new CoolingReading(null, null, null, null));
        public Task<CoolingModesReply> ModesAsync(IReadOnlyList<string> args, CancellationToken ct) => Task.FromResult(CoolingModesReply.Failed("none"));
    }

    private sealed class NoLoad : ICoolingLoad
    {
        public IAsyncDisposable Start() => throw new InvalidOperationException();
    }

    [Fact]
    public void Draws_the_chart_from_the_samples_card_and_sets_the_next_runs_choices()
    {
        var samples = Enumerable.Range(0, 240).Select(i => new CoolingSample(i, i < 120 ? CoolingRules.Idle : i < 210 ? CoolingRules.Load : CoolingRules.Cool,
            i < 120 ? 45 : i < 210 ? Math.Min(78, 45 + (i - 120) * 0.8) : 78 - (i - 210), i is >= 120 and < 210 ? 99 : 4, i is >= 120 and < 210 ? 4200 : 2100)).ToList();
        var card = CoolingJudge.Samples(samples, CoolingRules.Default);
        var report = new AreaReport([card], "Passed", DiagnosticStatus.Ok);
        var result = new DiagnosticResult<AreaReport>(CoolingTestModule.ModuleName, DiagnosticStatus.Ok, "Passed", DateTimeOffset.Now, report);
        var module = new CoolingTestModule(new Idle(), new NoLoad());

        var cut = Render<RemotePCDiagnostics.Modules.Cooling.CoolingDetails>(p => p.Add(x => x.DiagnosticModule, module).AddCascadingValue(RemotePCDiagnostics.Core.Plugins.ModuleDetails.LastResult, result));

        var chart = cut.Find("[data-testid='cooling-chart']");
        Assert.Equal(card.Rows.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), chart.GetAttribute("data-points"));
        Assert.Equal(3, chart.QuerySelectorAll("polyline").Length);
        Assert.Contains("hottest 78°C", chart.GetAttribute("aria-label"));
        cut.Find("[data-testid='cooling-mode']").Change("full");
        Assert.Equal(CoolingTestMode.Full, module.Mode);
        cut.Find("[data-testid='cooling-switch-modes']").Change(false);
        Assert.False(module.SwitchModes);
        Assert.Equal("false", cut.Find("[data-testid='cooling-options']").GetAttribute("data-switch-modes"));
    }
}
