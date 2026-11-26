using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Modules.Sound;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

/// <summary>The Sound check pane on the Interactive tests page: the answers, Can't hear sound and the one-side list.</summary>
public class SoundCheckPageTests : BunitContext
{
    private const string SpkId = "{0.0.0.00000000}.{11111111-1111-1111-1111-111111111111}";
    private const string MicId = "{0.0.1.00000000}.{44444444-4444-4444-4444-444444444444}";
    private static readonly string[] AllRoles = [AudioEndpointInfo.Console, AudioEndpointInfo.Multimedia, AudioEndpointInfo.Communications];

    private static AreaReport SoundReport(bool muted = false, double volume = 0.5, double[]? channels = null) => SoundModule.Build(
        new AudioState(
        [
            new(SpkId, "Speakers (Realtek(R) Audio)", AudioFlow.Output, AudioEndpointState.Active, AudioBus.Internal, "Speakers", "", AllRoles, muted, volume,
                Probe: AudioProbeOutcome.Ok, ChannelLevels: channels),
            new(MicId, "Microphone Array", AudioFlow.Input, AudioEndpointState.Active, AudioBus.Internal, "Microphone", "", AllRoles, false, 0.8, Probe: AudioProbeOutcome.Ok),
        ], []),
        new SoundFacts([new(SoundModule.AudioSrv, SoundModule.AudioSrv, "RUNNING", "AUTO_START", "LocalSystem", ""),
                        new(SoundModule.EndpointBuilder, SoundModule.EndpointBuilder, "RUNNING", "AUTO_START", "LocalSystem", "")],
            null, [], [], true, new CapturePrivacy.Switches(false, false, false, true), false));

    private (ResultStore Store, IRenderedComponent<InteractiveTestsPage> Page) Render(AreaReport sound, string query = "?test=soundcheck")
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var store = new ResultStore();
        var soundModule = new FakeModule(ModuleSlugs.Sound, _ => Task.FromResult<DiagnosticResult>(new DiagnosticResult<AreaReport>(ModuleSlugs.Sound, DiagnosticStatus.Warning, "", DateTimeOffset.Now, sound)));
        var diagnostics = new DiagnosticsService(store, [soundModule, new SoundCheckModule(new PlayIo())]);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new ChecksScreenState(diagnostics, store));
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(Remediation: new RemediationService(new SystemCommandRunner())));
        Services.GetRequiredService<NavigationManager>().NavigateTo("interactive" + query);
        return (store, Render<InteractiveTestsPage>());
    }

    [Fact]
    public void Play_then_answer_nothing_lists_the_fixes_in_order()
    {
        var (store, page) = Render(SoundReport(muted: true, volume: 0.04));
        Assert.NotNull(page.Find("[data-testid='interactive-soundcheck-pane']"));

        page.Find("[data-testid='soundcheck-play-btn']").Click();
        page.WaitForAssertion(() => Assert.Equal("Waiting for answer", page.Find("[data-testid='interactive-status-soundcheck']").TextContent.Trim()));

        page.Find("[data-testid='soundcheck-answer-nothing']").Click();
        page.WaitForAssertion(() => Assert.Equal(2, page.FindAll("[data-testid='soundcheck-step']").Count));
        Assert.Equal("cant-hear", page.Find("[data-testid='soundcheck-help']").GetAttribute("data-mode"));
        Assert.Equal(DiagnosticStatus.Error, store.Get(ModuleSlugs.SoundCheck).Status);
        var steps = page.FindAll("[data-testid='soundcheck-step']");
        Assert.Equal(["Muted", "Low volume"], steps.Select(s => s.QuerySelector("b")!.TextContent));
        Assert.NotNull(page.Find("[data-testid='soundcheck-step-services-ok']"));
        Assert.Equal("UnmuteAudioEndpoint", steps[0].QuerySelector("[data-action='remediate']")!.GetAttribute("data-action-kind"));
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "soundcheck-cant-hear.html"), page.Markup);
    }

    [Fact]
    public void Only_left_lists_the_balance_with_its_fix_and_the_hardware_hint()
    {
        var (_, page) = Render(SoundReport(channels: [1.0, 0.12]));
        page.Find("[data-testid='soundcheck-play-btn']").Click();
        page.WaitForAssertion(() => page.Find("[data-testid='soundcheck-answer-only-left']"));
        page.Find("[data-testid='soundcheck-answer-only-left']").Click();

        page.WaitForAssertion(() => Assert.Single(page.FindAll("[data-testid='soundcheck-step']")));
        Assert.Equal("one-side", page.Find("[data-testid='soundcheck-help']").GetAttribute("data-mode"));
        Assert.Equal("EvenAudioBalance", page.Find("[data-testid='soundcheck-fix-EvenAudioBalance']").GetAttribute("data-action-kind"));
        Assert.NotNull(page.Find("[data-testid='soundcheck-step-hardware']"));
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "soundcheck-one-side.html"), page.Markup);
    }

    [Fact]
    public void Cant_hear_link_opens_the_list_on_a_healthy_pc_and_points_at_the_app()
    {
        var (_, page) = Render(SoundReport(), "?test=soundcheck&help=cant-hear");
        page.WaitForAssertion(() => Assert.NotNull(page.Find("[data-testid='soundcheck-step-app']")));
        Assert.Empty(page.FindAll("[data-testid='soundcheck-step']"));
    }

    private sealed class PlayIo : IAudioIo
    {
        public IReadOnlyList<AudioDevice> ListDevices() => [new(SpkId, "Speakers (Realtek(R) Audio)", AudioFlow.Output, AudioBus.Internal, true)];
        public bool IsMicrophoneBlockedByPrivacy() => false;
        public Task<PlayCaptureResult> PlayAndCaptureAsync(PlayCaptureRequest r, CancellationToken ct) => throw new NotSupportedException();
        public Task<MonitorResult> MonitorAsync(MonitorRequest r, CancellationToken ct) => throw new NotSupportedException();
        public Task<int> PlayOnChannelAsync(PlayChannelRequest r, CancellationToken ct) => Task.FromResult(2);
    }
}
