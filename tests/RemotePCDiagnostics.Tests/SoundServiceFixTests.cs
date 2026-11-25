using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.Modules.Sound;

namespace RemotePCDiagnostics.Tests;

/// <summary>Batch 3 of the audio plan: starting, restarting and re-enabling the Windows Audio services through the Agent.</summary>
public class SoundServiceFixTests
{
    private const string Spk = "{0.0.0.00000000}.{11111111-1111-1111-1111-111111111111}";
    private const string Mic = "{0.0.1.00000000}.{44444444-4444-4444-4444-444444444444}";
    private static readonly string[] AllRoles = [AudioEndpointInfo.Console, AudioEndpointInfo.Multimedia, AudioEndpointInfo.Communications];

    // ---------------------------------------------------------------- the Agent's steps

    private sealed class FakeHost : AudioServices.IHost
    {
        public readonly Dictionary<string, ServiceState> States = new(StringComparer.OrdinalIgnoreCase)
        {
            [AudioServices.AudioSrv] = ServiceState.Running, [AudioServices.EndpointBuilder] = ServiceState.Running,
        };
        public readonly HashSet<string> Disabled = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Services that never reach the state they're asked for.</summary>
        public readonly HashSet<string> Hangs = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Calls = [];

        public ServiceState State(string name) => States.TryGetValue(name, out var s) ? s : ServiceState.NotFound;
        public bool IsDisabled(string name) => Disabled.Contains(name);
        public void Start(string name) { Calls.Add("start " + name); if (!Hangs.Contains(name)) States[name] = ServiceState.Running; }
        public void Stop(string name)
        {
            Calls.Add("stop " + name);
            if (Hangs.Contains(name)) { States[name] = ServiceState.StopPending; return; }
            States[name] = ServiceState.Stopped;
            if (name == AudioServices.EndpointBuilder) States[AudioServices.AudioSrv] = ServiceState.Stopped; // its dependent
        }
        public bool WaitFor(string name, ServiceState state, TimeSpan timeout) => State(name) == state;
    }

    [Fact]
    public void Start_starts_the_endpoint_builder_before_windows_audio()
    {
        var host = new FakeHost();
        host.States[AudioServices.AudioSrv] = ServiceState.Stopped;
        host.States[AudioServices.EndpointBuilder] = ServiceState.Stopped;

        Assert.Null(AudioServices.Run(AudioServices.Start, host));
        Assert.Equal(["start AudioEndpointBuilder", "start Audiosrv"], host.Calls);
    }

    [Fact]
    public void Start_leaves_running_services_alone()
    {
        var host = new FakeHost();
        Assert.Null(AudioServices.Run(AudioServices.Start, host));
        Assert.Empty(host.Calls);
    }

    [Fact]
    public void Start_reports_a_disabled_service_and_a_timeout()
    {
        var host = new FakeHost();
        host.States[AudioServices.AudioSrv] = ServiceState.Stopped;
        host.Disabled.Add(AudioServices.AudioSrv);
        Assert.Equal("Windows Audio is disabled. Set it to Automatic first.", AudioServices.Run(AudioServices.Start, host));

        host.Disabled.Clear();
        host.Hangs.Add(AudioServices.AudioSrv);
        Assert.Equal("Windows Audio didn't start within 15 seconds.", AudioServices.Run(AudioServices.Start, host));
    }

    [Fact]
    public void Restart_stops_only_windows_audio_and_restart_all_takes_the_endpoint_builder_too()
    {
        var host = new FakeHost();
        Assert.Null(AudioServices.Run(AudioServices.Restart, host));
        Assert.Equal(["stop Audiosrv", "start Audiosrv"], host.Calls);

        host.Calls.Clear();
        Assert.Null(AudioServices.Run(AudioServices.RestartAll, host));
        Assert.Equal(["stop AudioEndpointBuilder", "start AudioEndpointBuilder", "start Audiosrv"], host.Calls);
    }

    [Fact]
    public void A_service_stuck_stopping_fails_the_restart()
    {
        var host = new FakeHost();
        host.Hangs.Add(AudioServices.AudioSrv);
        Assert.Equal("Windows Audio didn't stop within 15 seconds. Restart the PC.", AudioServices.Run(AudioServices.Restart, host));
    }

    [Theory]
    [InlineData("start", true)]
    [InlineData("restart", true)]
    [InlineData("restart_all", true)]
    [InlineData("stop", false)]
    [InlineData("Start", false)]
    [InlineData("", false)]
    public void Agent_takes_only_the_three_verbs(string verb, bool allowed)
    {
        var plan = AgentScripts.Plan(AgentScripts.Of(AgentScripts.AudioServices, verb), null, out var refusal);
        Assert.Equal(allowed, plan is not null);
        if (allowed) Assert.Equal(new AudioServicesAction(verb), plan!.Native);
        else Assert.NotNull(refusal);
        Assert.Null(AgentScripts.Plan(AgentScripts.Of(AgentScripts.AudioServices, "start", "Spooler"), null, out _));
    }

    [Theory]
    [InlineData("AudioEndpointBuilder", true)]
    [InlineData("Audiosrv", true)]
    [InlineData("RpcSs", false)]
    [InlineData("RemotePCDiagnosticsAgent", false)]
    public void Only_the_audio_services_start_type_may_change_among_protected_ones(string service, bool allowed)
    {
        Assert.Equal(!allowed, ServiceProtection.ProtectsStartType(service));
        Assert.Equal(allowed, AdminSettingsRules.Refusal(new AdminPipeSetting(AdminPipeSetting.ServiceStartType, Target: service, Text: "Automatic")) is null);
    }

    [Fact]
    public void The_endpoint_builder_still_cant_be_stopped_from_the_services_page()
    {
        Assert.NotNull(AdminSettingsRules.Refusal(new AdminPipeSetting(AdminPipeSetting.ServiceStop, Target: AudioServices.EndpointBuilder)));
        var options = ServiceProtection.For(new ServiceInfo(AudioServices.EndpointBuilder, "Windows Audio Endpoint Builder", "RUNNING", "AUTO_START", "LocalSystem", ""));
        Assert.False(options.CanStop);
        Assert.False(options.CanRestart);
    }

    // ---------------------------------------------------------------- the app's fixes

    private sealed class FakeSettings : IAudioServiceSettings
    {
        public readonly Dictionary<string, string> Types = new(StringComparer.OrdinalIgnoreCase) { [AudioServices.AudioSrv] = "Automatic", [AudioServices.EndpointBuilder] = "Automatic" };
        public bool Sticks = true;
        public string? StartType(string service) => Types.GetValueOrDefault(service);
        public void SetStartType(string service, string startType) { if (Sticks) Types[service] = startType; }
    }

    private static AudioState State(AudioProbeOutcome probe) => new([new AudioEndpointInfo(Spk, "Speakers", AudioFlow.Output, AudioEndpointState.Active, AudioBus.Internal,
        "Speakers", "", AllRoles, false, 0.5, null, null, false, probe)], []);

    private static (RemediationService Fixes, MemoryChangeJournal Journal, List<string> Verbs) Setup(FakeSettings? settings = null,
        Queue<AudioProbeOutcome>? probes = null, Func<string, ProcessResult>? agent = null)
    {
        var verbs = new List<string>();
        var journal = new MemoryChangeJournal();
        var audio = new AudioFixService(null, null, (s, _) =>
            {
                Assert.Equal(AgentScripts.AudioServices, s.Name);
                verbs.Add(s.Args![0]);
                return Task.FromResult<ProcessResult?>(agent?.Invoke(s.Args[0]) ?? new ProcessResult(0, "", ""));
            }, services: settings ?? new FakeSettings(),
            readState: probes is null ? null : _ => Task.FromResult(State(probes.Count > 0 ? probes.Dequeue() : AudioProbeOutcome.Ok)));
        return (new RemediationService(new SystemCommandRunner(), journal: journal, audio: audio), journal, verbs);
    }

    private static AreaAction A(RemediationKind k) => new(k, k.ToString(), "", "Windows Audio");

    [Fact]
    public async Task Start_runs_the_agent_script()
    {
        var (fixes, journal, verbs) = Setup();
        var r = await fixes.ExecuteAsync(A(RemediationKind.StartAudioServices));
        Assert.True(r.Success, r.Message);
        Assert.Equal(["start"], verbs);
        Assert.Empty(journal.All);
    }

    [Fact]
    public async Task The_agents_reason_is_shown_when_it_fails()
    {
        var (fixes, _, _) = Setup(agent: _ => new ProcessResult(1, "", "Windows Audio is disabled. Set it to Automatic first."));
        var r = await fixes.ExecuteAsync(A(RemediationKind.StartAudioServices));
        Assert.False(r.Success);
        Assert.Contains("Set it to Automatic first", r.Message);
    }

    [Fact]
    public async Task Restart_stops_at_windows_audio_when_the_devices_answer_again()
    {
        var (fixes, _, verbs) = Setup(probes: new([AudioProbeOutcome.Ok]));
        var r = await fixes.ExecuteAsync(A(RemediationKind.RestartAudioServices));
        Assert.True(r.Success, r.Message);
        Assert.Equal(["restart"], verbs);
        Assert.StartsWith("Restarted Windows Audio.", r.Message);
    }

    [Fact]
    public async Task Restart_goes_on_to_the_endpoint_builder_only_while_the_devices_still_dont_answer()
    {
        var (fixes, _, verbs) = Setup(probes: new([AudioProbeOutcome.TimedOut, AudioProbeOutcome.Ok]));
        var r = await fixes.ExecuteAsync(A(RemediationKind.RestartAudioServices));
        Assert.True(r.Success, r.Message);
        Assert.Equal(["restart", "restart_all"], verbs);
        Assert.Contains("Endpoint Builder", r.Message);

        var (stuck, _, _) = Setup(probes: new([AudioProbeOutcome.TimedOut, AudioProbeOutcome.TimedOut]));
        var still = await stuck.ExecuteAsync(A(RemediationKind.RestartAudioServices));
        Assert.False(still.Success);
        Assert.Contains("Restart the PC", still.Message);
    }

    [Fact]
    public async Task Turning_windows_audio_back_on_journals_the_start_type_then_starts_it()
    {
        var settings = new FakeSettings();
        settings.Types[AudioServices.EndpointBuilder] = "Disabled";
        var (fixes, journal, verbs) = Setup(settings);

        var r = await fixes.ExecuteAsync(A(RemediationKind.SetAudioServicesAutomatic));

        Assert.True(r.Success, r.Message);
        Assert.Equal("Automatic", settings.Types[AudioServices.EndpointBuilder]);
        Assert.Equal(["start"], verbs);
        var c = Assert.Single(journal.All);
        Assert.Equal(ChangeKind.ServiceStartType, c.Kind);
        Assert.Equal(AudioServices.EndpointBuilder, c.Target);
        Assert.Equal("Disabled", c.Previous);
        Assert.Equal(UndoSupport.Full, Undoability.Of(c));
    }

    [Fact]
    public async Task A_start_type_windows_puts_back_is_a_failure_and_nothing_is_started()
    {
        var settings = new FakeSettings { Sticks = false };
        settings.Types[AudioServices.AudioSrv] = "Disabled";
        var (fixes, journal, verbs) = Setup(settings);

        var r = await fixes.ExecuteAsync(A(RemediationKind.SetAudioServicesAutomatic));

        Assert.False(r.Success);
        Assert.Contains("policy", r.Message);
        Assert.Empty(verbs);
        Assert.Empty(journal.All);
    }

    [Fact]
    public async Task Without_the_agent_nothing_runs()
    {
        var fixes = new RemediationService(new SystemCommandRunner(), audio: new AudioFixService(null, null));
        var r = await fixes.ExecuteAsync(A(RemediationKind.StartAudioServices));
        Assert.False(r.Success);
        Assert.Contains("Agent", r.Message);
    }

    [Fact]
    public void Undo_traits_match_the_plan()
    {
        Assert.Equal(UndoSupport.NothingToUndo, Undoability.Of(RemediationKind.StartAudioServices));
        Assert.Equal(UndoSupport.NothingToUndo, Undoability.Of(RemediationKind.RestartAudioServices));
        Assert.Equal(UndoSupport.Full, Undoability.Of(RemediationKind.SetAudioServicesAutomatic));
        Assert.Equal(RemotePCDiagnostics.Core.Optimizations.SuggestionRisk.Medium, FixCatalog.RiskOf(RemediationKind.RestartAudioServices));
    }

    // ---------------------------------------------------------------- what the services card offers

    private static ServiceInfo Svc(string name, string status = "RUNNING", string start = "AUTO_START") => new(name, name, status, start, "LocalSystem", "");

    private static AudioEndpointInfo Ep(string id, AudioFlow flow, AudioProbeOutcome probe = AudioProbeOutcome.Ok) =>
        new(id, flow == AudioFlow.Output ? "Speakers" : "Mic", flow, AudioEndpointState.Active, AudioBus.Internal, flow == AudioFlow.Output ? "Speakers" : "Microphone",
            "", AllRoles, false, flow == AudioFlow.Output ? 0.5 : 0.8, null, null, false, probe);

    private static AreaCard ServicesCard(IReadOnlyList<ServiceInfo> services, AudioProbeOutcome probe = AudioProbeOutcome.Ok) =>
        SoundModule.Build(new AudioState([Ep(Spk, AudioFlow.Output, probe), Ep(Mic, AudioFlow.Input)], []),
            new SoundFacts(services, null, [], [], true, new CapturePrivacy.Switches(false, false, false, true), false)).Cards.Single(c => c.Id == "audio-services");

    private static IReadOnlyList<RemediationKind> KindsOn(AreaCard card, string row) =>
        card.Rows.Single(r => r.Key == row).Actions?.Select(a => a.Kind).ToList() ?? [];

    [Fact]
    public void A_stopped_service_offers_start()
    {
        var card = ServicesCard([Svc(AudioServices.AudioSrv, "STOPPED"), Svc(AudioServices.EndpointBuilder)]);
        Assert.Equal([RemediationKind.StartAudioServices], KindsOn(card, AudioServices.AudioSrv));
        Assert.Empty(KindsOn(card, AudioServices.EndpointBuilder));
    }

    [Fact]
    public void While_one_is_disabled_only_turning_it_back_on_is_offered()
    {
        var card = ServicesCard([Svc(AudioServices.AudioSrv, "STOPPED"), Svc(AudioServices.EndpointBuilder, "STOPPED", "DISABLED")]);
        Assert.Equal([RemediationKind.SetAudioServicesAutomatic], KindsOn(card, AudioServices.EndpointBuilder));
        Assert.Empty(KindsOn(card, AudioServices.AudioSrv));
    }

    [Fact]
    public void Windows_audio_not_answering_offers_one_restart()
    {
        var card = ServicesCard([Svc(AudioServices.AudioSrv), Svc(AudioServices.EndpointBuilder)], AudioProbeOutcome.TimedOut);
        Assert.Equal([RemediationKind.RestartAudioServices], KindsOn(card, AudioServices.AudioSrv));
        Assert.Empty(KindsOn(card, AudioServices.EndpointBuilder));
    }

    [Fact]
    public void Healthy_services_offer_nothing()
    {
        var card = ServicesCard([Svc(AudioServices.AudioSrv), Svc(AudioServices.EndpointBuilder)]);
        Assert.All(card.Rows, r => Assert.Null(r.Actions));
    }

    [Fact]
    public void The_workflow_lists_turning_windows_audio_back_on_but_not_start_or_restart()
    {
        AreaReport Report(IReadOnlyList<ServiceInfo> s, AudioProbeOutcome probe = AudioProbeOutcome.Ok) =>
            SoundModule.Build(new AudioState([Ep(Spk, AudioFlow.Output, probe), Ep(Mic, AudioFlow.Input)], []),
                new SoundFacts(s, null, [], [], true, new CapturePrivacy.Switches(false, false, false, true), false));
        List<RemediationKind> Kinds(AreaReport r) =>
            FixCatalog.Build([new DiagnosticResult(SoundModule.ModuleName, DiagnosticStatus.Warning, r.Summary, DateTimeOffset.Now, r)], []).Select(f => f.Remediation!.Kind).ToList();

        Assert.Contains(RemediationKind.SetAudioServicesAutomatic, Kinds(Report([Svc(AudioServices.AudioSrv, "STOPPED", "DISABLED"), Svc(AudioServices.EndpointBuilder)])));
        Assert.DoesNotContain(RemediationKind.StartAudioServices, Kinds(Report([Svc(AudioServices.AudioSrv, "STOPPED"), Svc(AudioServices.EndpointBuilder)])));
        Assert.DoesNotContain(RemediationKind.RestartAudioServices, Kinds(Report([Svc(AudioServices.AudioSrv), Svc(AudioServices.EndpointBuilder)], AudioProbeOutcome.TimedOut)));
    }
}
