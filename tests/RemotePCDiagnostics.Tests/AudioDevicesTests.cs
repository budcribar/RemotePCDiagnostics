using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

/// <summary>Every speaker and microphone: device rows, judging a recording, the module's steps, the page and interactive-data.</summary>
public class AudioDevicesTests : BunitContext
{
    private const string SpkId = "{0.0.0.00000000}.{11111111-1111-1111-1111-111111111111}";
    private const string HdmiId = "{0.0.0.00000000}.{22222222-2222-2222-2222-222222222222}";
    private const string HeadphonesId = "{0.0.0.00000000}.{33333333-3333-3333-3333-333333333333}";
    private const string GoneId = "{0.0.0.00000000}.{55555555-5555-5555-5555-555555555555}";
    private const string MicId = "{0.0.1.00000000}.{44444444-4444-4444-4444-444444444444}";
    private const string HeadsetMicId = "{0.0.1.00000000}.{66666666-6666-6666-6666-666666666666}";
    private static readonly string[] AllRoles = [AudioEndpointInfo.Console, AudioEndpointInfo.Multimedia, AudioEndpointInfo.Communications];

    private static AudioState State(bool spkMuted = false, double micLevel = 0.8, bool micBusy = false) => new(
    [
        new(SpkId, "Speakers (Realtek(R) Audio)", AudioFlow.Output, AudioEndpointState.Active, AudioBus.Internal, "Speakers", "", AllRoles, spkMuted, 0.5, Probe: AudioProbeOutcome.Ok),
        new(HdmiId, "LG TV (HDMI)", AudioFlow.Output, AudioEndpointState.Unplugged, AudioBus.Internal, "DigitalAudioDisplayDevice", "", []),
        new(HeadphonesId, "Headphones", AudioFlow.Output, AudioEndpointState.Disabled, AudioBus.Internal, "Headphones", "", []),
        new(GoneId, "Old USB speaker", AudioFlow.Output, AudioEndpointState.NotPresent, AudioBus.Usb, "Speakers", "", []),
        new(MicId, "Microphone Array", AudioFlow.Input, AudioEndpointState.Active, AudioBus.Internal, "Microphone", "", AllRoles, false, micLevel,
            Probe: micBusy ? AudioProbeOutcome.DeviceInUse : AudioProbeOutcome.Ok),
        new(HeadsetMicId, "Headset Microphone", AudioFlow.Input, AudioEndpointState.Active, AudioBus.Usb, "Headset", "", [], true, 0.1),
    ], []);

    private static float[] Speech(double dbfs, int rate = 48000, double seconds = 3)
    {
        var amp = AudioMath.FromDbfs(dbfs) * Math.Sqrt(2);
        var n = (int)(rate * seconds);
        var s = new float[n];
        for (var i = n / 3; i < 2 * n / 3; i++) s[i] = (float)(amp * Math.Sin(2 * Math.PI * 300 * i / rate));
        return s;
    }

    [Fact]
    public void Rows_list_every_device_with_its_state_and_fixes()
    {
        var r = AudioDevicesTest.Build(State(spkMuted: true));

        Assert.Equal([SpkId, HeadphonesId, HdmiId, MicId, HeadsetMicId], r.Devices.Select(d => d.Id));
        var spk = r.Devices[0];
        Assert.Equal(AudioDeviceOutcome.NotTested, spk.Outcome);
        Assert.True(spk.IsDefault);
        Assert.Equal(RemediationKind.UnmuteAudioEndpoint, Assert.Single(spk.Actions!).Kind);

        var off = r.Devices.Single(d => d.Id == HeadphonesId);
        Assert.Equal(AudioDeviceOutcome.Skipped, off.Outcome);
        Assert.Equal("Disabled", off.Result);
        Assert.Equal(RemediationKind.EnableAudioEndpoint, Assert.Single(off.Actions!).Kind);

        var hdmi = r.Devices.Single(d => d.Id == HdmiId);
        Assert.Equal("HDMI or DisplayPort", hdmi.Kind);
        Assert.Equal(AudioDeviceOutcome.Skipped, hdmi.Outcome);
        Assert.Contains("monitor or TV with speakers", hdmi.Hint);

        var headset = r.Devices.Single(d => d.Id == HeadsetMicId);
        Assert.Equal("Headset · USB", headset.Kind);
        Assert.Equal([RemediationKind.UnmuteAudioEndpoint, RemediationKind.RaiseAudioVolume], headset.Actions!.Select(a => a.Kind));
        Assert.Equal(3, r.Untested);
    }

    [Fact]
    public void Fixes_are_hidden_when_windows_wont_let_the_app_change_devices()
    {
        var r = AudioDevicesTest.Build(State() with { CanChangeSettings = false });
        Assert.Null(r.Devices.Single(d => d.Id == HeadphonesId).Actions);
    }

    [Theory]
    [InlineData(-90, AudioDeviceOutcome.Failed, AudioDevicesTest.NoSignal)]
    [InlineData(-50, AudioDeviceOutcome.Warning, "Very low level")]
    [InlineData(-25, AudioDeviceOutcome.Passed, "Picked up sound")]
    public void A_recording_is_judged_by_its_loudest_moment(double dbfs, AudioDeviceOutcome outcome, string result)
    {
        var row = AudioDevicesTest.Build(State()).Devices.Single(d => d.Id == MicId);
        var level = AudioDevicesTest.Measure(Speech(dbfs), 48000);
        Assert.InRange(level.LevelDbfs, dbfs - 1, dbfs + 1);

        var judged = AudioDevicesTest.Judge(row, level, privacyBlocked: false);
        Assert.Equal(outcome, judged.Outcome);
        Assert.Equal(result, judged.Result);
    }

    [Fact]
    public void Silence_on_a_muted_mic_says_unmute_and_privacy_says_privacy()
    {
        var reportRows = AudioDevicesTest.Build(State()).Devices;
        var silent = AudioDevicesTest.Measure(new float[48000], 48000);
        Assert.True(silent.DigitalSilence);

        var muted = AudioDevicesTest.Judge(reportRows.Single(d => d.Id == HeadsetMicId), silent, false);
        Assert.Equal(AudioDeviceOutcome.Failed, muted.Outcome);
        Assert.Contains("muted", muted.Hint);

        var blocked = AudioDevicesTest.Judge(reportRows.Single(d => d.Id == MicId), silent, true);
        Assert.Equal("Blocked by privacy settings", blocked.Result);
        Assert.Equal(AudioVerdicts.PrivacyMessage, blocked.Hint);
    }

    [Fact]
    public void Clipping_is_a_warning()
    {
        var s = Speech(-1);
        s[100] = 1f;
        var judged = AudioDevicesTest.Judge(AudioDevicesTest.Build(State()).Devices.Single(d => d.Id == MicId), AudioDevicesTest.Measure(s, 48000), false);
        Assert.Equal(AudioDeviceOutcome.Warning, judged.Outcome);
        Assert.Contains("clipping", judged.Result);
    }

    [Fact]
    public async Task Play_answer_and_record_each_device_then_the_test_passes()
    {
        var io = new DeviceIo(Speech(-25));
        var m = new AudioDevicesModule(io, state: new FakeAudio(State()));
        var listed = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, listed.Status);
        Assert.Contains("3 devices to test", listed.Message);

        await m.PlayAsync(SpkId);
        Assert.Equal([AudioChannel.Left, AudioChannel.Right], io.Played.Select(p => p.Channel));
        Assert.All(io.Played, p => Assert.Equal(SpkId, p.OutputId));
        Assert.True(m.Report.Devices[0].WaitingForAnswer);
        Assert.NotNull(m.Answer(SpkId, SoundCheckAnswer.Both));
        Assert.Equal(AudioDeviceOutcome.Passed, m.Report.Devices[0].Outcome);

        await m.RecordAsync(MicId);
        Assert.Equal(MicId, io.Recorded.Single().InputId);
        Assert.True(m.HasRecording(MicId));
        Assert.Equal(AudioDeviceOutcome.Passed, m.Report.Devices.Single(d => d.Id == MicId).Outcome);

        await m.PlayBackAsync(MicId);
        Assert.Single(io.PlayedBack);

        var last = await m.RecordAsync(HeadsetMicId);
        Assert.Equal(DiagnosticStatus.Ok, last.Status);
        Assert.StartsWith("Passed: all 3", last.Message);
    }

    [Fact]
    public async Task One_side_heard_fails_the_device_and_a_refresh_keeps_results()
    {
        var m = new AudioDevicesModule(new DeviceIo(Speech(-25)), state: new FakeAudio(State()));
        await m.RefreshAsync(null);
        await m.PlayAsync(SpkId);
        var r = m.Answer(SpkId, SoundCheckAnswer.OnlyLeft)!;
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Contains("Speakers (Realtek(R) Audio)", r.Message);

        await m.RefreshAsync(null);
        Assert.Equal("Only the left side was heard", m.Report.Devices[0].Result);
        Assert.Equal(AudioDeviceOutcome.NotTested, m.Reset().Payload is AudioDevicesReport rep ? rep.Devices[0].Outcome : AudioDeviceOutcome.Failed);
    }

    [Fact]
    public async Task A_busy_microphone_is_not_recorded_and_says_why()
    {
        var io = new DeviceIo(Speech(-25));
        var m = new AudioDevicesModule(io, state: new FakeAudio(State(micBusy: true)));
        await m.RefreshAsync(null);
        await m.RecordAsync(MicId);
        Assert.Empty(io.Recorded);
        var row = m.Report.Devices.Single(d => d.Id == MicId);
        Assert.Equal(AudioDeviceOutcome.Failed, row.Outcome);
        Assert.Contains("exclusive mode", row.Hint);
    }

    [Fact]
    public async Task Disabled_and_unplugged_devices_are_never_played()
    {
        var io = new DeviceIo(Speech(-25));
        var m = new AudioDevicesModule(io, state: new FakeAudio(State()));
        await m.RefreshAsync(null);
        await m.PlayAsync(HeadphonesId);
        await m.PlayAsync(HdmiId);
        Assert.Empty(io.Played);
        Assert.Null(m.Answer(HeadphonesId, SoundCheckAnswer.Both));
    }

    [Fact]
    public async Task Without_core_audio_it_lists_the_connected_devices()
    {
        var m = new AudioDevicesModule(new DeviceIo(Speech(-25)), state: new FakeAudio(AudioState.Unavailable("no")));
        var r = await m.RefreshAsync(null);
        Assert.Equal(2, m.Report.Devices.Count);
        Assert.NotNull(m.Report.Notice);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
    }

    [Fact]
    public async Task Interactive_data_lists_each_device_with_result_and_fixes()
    {
        var m = new AudioDevicesModule(new DeviceIo(Speech(-50)), state: new FakeAudio(State(spkMuted: true)));
        await m.RefreshAsync(null);
        await m.PlayAsync(SpkId);
        await m.RecordAsync(MicId);
        var result = AudioDevicesTest.ToResult(m.Report);

        var json = InteractiveExport.ToJson(new InteractiveExport.PageState("audiodevices", ["audiodevices"], false, false, false, false),
            new PhysicalBenchQaSnapshot(), New(ModuleSlugs.Webcam), New(ModuleSlugs.SpeakerToMic), New(ModuleSlugs.MicToSpeaker),
            audioDevices: new InteractiveExport.ModuleState(result, false));
        using var doc = JsonDocument.Parse(json);
        var test = doc.RootElement.GetProperty("tests").EnumerateArray().Single(t => t.GetProperty("id").GetString() == "audiodevices");
        Assert.Equal("waiting-for-person-verdict", test.GetProperty("state").GetString());
        var devices = test.GetProperty("devices").EnumerateArray().ToList();
        Assert.Equal(5, devices.Count);
        var spk = devices[0];
        Assert.True(spk.GetProperty("waitingForAnswer").GetBoolean());
        Assert.Equal(2, spk.GetProperty("measured").GetProperty("channels").GetInt32());
        Assert.Equal("UnmuteAudioEndpoint", spk.GetProperty("fixes")[0].GetProperty("kind").GetString());
        var mic = devices.Single(d => d.GetProperty("id").GetString() == MicId);
        Assert.Equal("warning", mic.GetProperty("result").GetString());
        Assert.InRange(mic.GetProperty("measured").GetProperty("levelDbfs").GetDouble(), -51, -49);
        Assert.Equal("skipped", devices.Single(d => d.GetProperty("id").GetString() == HeadphonesId).GetProperty("result").GetString());
    }

    private static InteractiveExport.ModuleState New(string slug) => new(DiagnosticResult.NotRun(slug), false);

    private (ResultStore Store, IRenderedComponent<InteractiveTestsPage> Page, DeviceIo Io) Render(AudioState state)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var store = new ResultStore();
        var io = new DeviceIo(Speech(-25));
        var diagnostics = new DiagnosticsService(store, [new AudioDevicesModule(io, state: new FakeAudio(state))]);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new ChecksScreenState(diagnostics, store));
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(Remediation: new RemediationService(new SystemCommandRunner())));
        Services.GetRequiredService<NavigationManager>().NavigateTo("interactive?test=audiodevices");
        return (store, Render<InteractiveTestsPage>(), io);
    }

    [Fact]
    public void Page_lists_devices_and_runs_each_one()
    {
        var (store, page, io) = Render(State(spkMuted: true));
        page.WaitForAssertion(() => Assert.Equal(5, page.FindAll("[data-testid='audiodevices-device']").Count));
        Assert.NotNull(page.Find("[data-testid='interactive-row-audiodevices']"));

        var spk = page.Find($"[data-device-id='{SpkId}']");
        Assert.Equal("UnmuteAudioEndpoint", spk.QuerySelector("[data-action='remediate']")!.GetAttribute("data-action-kind"));
        Assert.Contains("Muted", spk.TextContent);
        Assert.Null(page.Find($"[data-device-id='{HeadphonesId}']").QuerySelector("[data-testid='audiodevices-play']"));
        Assert.NotNull(page.Find($"[data-device-id='{HeadphonesId}']").QuerySelector("[data-testid='audiodevices-fix-EnableAudioEndpoint']"));

        page.Find($"[data-device-id='{SpkId}'] [data-testid='audiodevices-play']").Click();
        page.WaitForAssertion(() => page.Find($"[data-device-id='{SpkId}'] [data-testid='audiodevices-answer-both']"));
        Assert.Equal("Waiting for answer", page.Find("[data-testid='interactive-status-audiodevices']").TextContent.Trim());
        page.Find($"[data-device-id='{SpkId}'] [data-testid='audiodevices-answer-both']").Click();
        page.WaitForAssertion(() => Assert.Equal("passed", page.Find($"[data-device-id='{SpkId}']").GetAttribute("data-result")));

        page.Find($"[data-device-id='{MicId}'] [data-testid='audiodevices-record']").Click();
        page.WaitForAssertion(() => Assert.Equal("passed", page.Find($"[data-device-id='{MicId}']").GetAttribute("data-result")));
        Assert.NotNull(page.Find($"[data-device-id='{MicId}'] [data-testid='audiodevices-playback']"));
        Assert.Contains("Level", page.Find($"[data-device-id='{MicId}'] [data-testid='audiodevices-level']").TextContent);

        var data = page.Find("[data-testid='interactive-data']").GetAttribute("data-report") ?? "";
        Assert.Contains("\"id\":\"audiodevices\"", data);
        Assert.Equal(DiagnosticStatus.Warning, store.Get(ModuleSlugs.AudioDevices).Status);
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "audiodevices-pane.html"), page.Markup);
    }

    private sealed class DeviceIo(float[] recording) : IAudioIo
    {
        public List<PlayChannelRequest> Played { get; } = [];
        public List<RecordRequest> Recorded { get; } = [];
        public List<PlaySamplesRequest> PlayedBack { get; } = [];
        public IReadOnlyList<AudioDevice> ListDevices() =>
            [new(SpkId, "Speakers", AudioFlow.Output, AudioBus.Internal, true), new(MicId, "Microphone Array", AudioFlow.Input, AudioBus.Internal, true)];
        public bool IsMicrophoneBlockedByPrivacy() => false;
        public Task<PlayCaptureResult> PlayAndCaptureAsync(PlayCaptureRequest r, CancellationToken ct) => throw new NotSupportedException();
        public Task<MonitorResult> MonitorAsync(MonitorRequest r, CancellationToken ct) => throw new NotSupportedException();
        public Task<int> PlayOnChannelAsync(PlayChannelRequest r, CancellationToken ct) { Played.Add(r); return Task.FromResult(2); }
        public Task<RecordResult> RecordAsync(RecordRequest r, CancellationToken ct)
        {
            Recorded.Add(r);
            r.OnLevel?.Invoke(-30);
            return Task.FromResult(new RecordResult(recording, 48000));
        }
        public Task PlaySamplesAsync(PlaySamplesRequest r, CancellationToken ct) { PlayedBack.Add(r); return Task.CompletedTask; }
    }

    private sealed class FakeAudio(AudioState state) : IAudioStateSource
    {
        public Task<AudioState> ReadAsync(CancellationToken ct = default) => Task.FromResult(state);
    }
}
