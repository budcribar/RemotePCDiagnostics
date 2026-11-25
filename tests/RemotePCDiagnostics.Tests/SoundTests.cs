using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Modules.Sound;

namespace RemotePCDiagnostics.Tests;

public class SoundTests
{
    private const string SpkId = "{0.0.0.00000000}.{11111111-1111-1111-1111-111111111111}";
    private const string HdmiId = "{0.0.0.00000000}.{22222222-2222-2222-2222-222222222222}";
    private const string BtId = "{0.0.0.00000000}.{33333333-3333-3333-3333-333333333333}";
    private const string MicId = "{0.0.1.00000000}.{44444444-4444-4444-4444-444444444444}";
    private static readonly string[] AllRoles = [AudioEndpointInfo.Console, AudioEndpointInfo.Multimedia, AudioEndpointInfo.Communications];

    private static AudioEndpointInfo Speaker(double volume = 0.5, bool muted = false, string[]? roles = null, AudioProbeOutcome probe = AudioProbeOutcome.Ok,
        string format = "48000 Hz, 24-bit, 2 channels", string? oem = "48000 Hz, 24-bit, 2 channels", bool? fxOff = false) =>
        new(SpkId, "Speakers (Realtek(R) Audio)", AudioFlow.Output, AudioEndpointState.Active, AudioBus.Internal, "Speakers", @"SWD\MMDEVAPI\" + SpkId,
            roles ?? AllRoles, muted, volume, format, oem, fxOff, probe);

    private static AudioEndpointInfo Mic(double volume = 0.8, bool muted = false, string[]? roles = null) =>
        new(MicId, "Microphone Array (Realtek(R) Audio)", AudioFlow.Input, AudioEndpointState.Active, AudioBus.Internal, "Microphone", @"SWD\MMDEVAPI\" + MicId,
            roles ?? AllRoles, muted, volume, "48000 Hz, 16-bit, 2 channels", "48000 Hz, 16-bit, 2 channels", false, AudioProbeOutcome.Ok);

    private static ServiceInfo Svc(string name, string status = "RUNNING", string start = "AUTO_START") => new(name, name, status, start, "LocalSystem", "");

    private static readonly ServiceInfo[] HealthyServices = [Svc(SoundModule.AudioSrv), Svc(SoundModule.EndpointBuilder)];

    private static SoundFacts Facts(IReadOnlyList<ServiceInfo>? services = null, IReadOnlyList<ProblemDevice>? problems = null, IReadOnlyList<AudioDriver>? drivers = null,
        bool? battery = true, CapturePrivacy.Switches? mic = null, bool? mono = false, IReadOnlyList<ServiceInfo>? again = null) =>
        new(services ?? HealthyServices, again, problems ?? [], drivers ?? [], battery, mic ?? new CapturePrivacy.Switches(false, false, false, true), mono);

    private static AreaReport Build(IReadOnlyList<AudioEndpointInfo> endpoints, SoundFacts? facts = null, IReadOnlyList<AudioSessionInfo>? sessions = null) =>
        SoundModule.Build(new AudioState(endpoints, sessions ?? []), facts ?? Facts());

    private static AreaCard Card(AreaReport r, string id) => r.Cards.Single(c => c.Id == id);
    private static AreaRow RowOf(AreaCard c, string check) => c.Rows.First(r => r.Values[0] == check);

    [Fact]
    public void Healthy_pc_has_no_problems()
    {
        var r = Build([Speaker(), Mic()]);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("No sound problems found", r.Summary);
        Assert.Equal(["audio-output", "audio-input", "audio-services"], r.Cards.Select(c => c.Id));
        Assert.Equal("Speakers (Realtek(R) Audio)", RowOf(Card(r, "audio-output"), "Default device").Values[1]);
        Assert.All(r.Cards, c => Assert.Equal(AreaLevel.Ok, c.Level));
    }

    [Theory]
    [InlineData(0.09, AreaLevel.Warning)]
    [InlineData(0.10, AreaLevel.Ok)]
    [InlineData(0.0, AreaLevel.Warning)]
    public void Output_volume_threshold(double volume, AreaLevel expected) =>
        Assert.Equal(expected, RowOf(Card(Build([Speaker(volume), Mic()]), "audio-output"), "Low volume").Level);

    [Theory]
    [InlineData(0.24, AreaLevel.Warning)]
    [InlineData(0.25, AreaLevel.Ok)]
    public void Microphone_level_threshold(double volume, AreaLevel expected) =>
        Assert.Equal(expected, RowOf(Card(Build([Speaker(), Mic(volume)]), "audio-input"), "Low microphone level").Level);

    [Fact]
    public void Muted_default_output_is_a_warning_and_the_check_warns()
    {
        var r = Build([Speaker(muted: true), Mic()]);
        Assert.Equal(AreaLevel.Warning, RowOf(Card(r, "audio-output"), "Muted").Level);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.StartsWith("1 sound problem: muted", r.Summary);
    }

    [Fact]
    public void Active_outputs_without_a_default_warn()
    {
        var r = Build([Speaker(roles: []), Mic()]);
        var row = RowOf(Card(r, "audio-output"), "Default device");
        Assert.Equal(AreaLevel.Warning, row.Level);
        Assert.Equal("No default device", row.Values[1]);
    }

    [Theory]
    [InlineData(true, AreaLevel.Warning)]
    [InlineData(false, AreaLevel.Neutral)]
    public void No_outputs_warns_only_on_a_laptop(bool battery, AreaLevel expected) =>
        Assert.Equal(expected, RowOf(Card(Build([Mic()], Facts(battery: battery)), "audio-output"), "Default device").Level);

    [Fact]
    public void Only_a_disabled_speaker_is_a_warning_but_an_extra_unplugged_jack_is_info()
    {
        var disabled = Speaker() with { State = AudioEndpointState.Disabled, DefaultFor = [] };
        Assert.Equal(AreaLevel.Warning, RowOf(Card(Build([disabled, Mic()]), "audio-output"), "Disabled or unplugged").Level);

        var jack = new AudioEndpointInfo(HdmiId, "Headphones", AudioFlow.Output, AudioEndpointState.Unplugged, AudioBus.Internal, "Headphones", "", []);
        Assert.Equal(AreaLevel.Neutral, RowOf(Card(Build([Speaker(), jack, Mic()]), "audio-output"), "Disabled or unplugged").Level);
    }

    [Fact]
    public void Changed_format_is_info_unless_the_device_failed_to_open()
    {
        var changed = Speaker(format: "44100 Hz, 16-bit, 2 channels");
        Assert.Equal(AreaLevel.Neutral, RowOf(Card(Build([changed, Mic()]), "audio-output"), "Sound format").Level);
        var failed = changed with { Probe = AudioProbeOutcome.Failed };
        Assert.Equal(AreaLevel.Warning, RowOf(Card(Build([failed, Mic()]), "audio-output"), "Sound format").Level);
        Assert.Equal(AreaLevel.Ok, RowOf(Card(Build([Speaker(oem: null), Mic()]), "audio-output"), "Sound format").Level);
    }

    [Theory]
    [InlineData(AudioProbeOutcome.Ok, AreaLevel.Ok, "No issues found")]
    [InlineData(AudioProbeOutcome.DeviceInUse, AreaLevel.Warning, "Another app has exclusive control of this device")]
    [InlineData(AudioProbeOutcome.TimedOut, AreaLevel.Warning, "Windows Audio isn't answering")]
    [InlineData(AudioProbeOutcome.ServiceNotRunning, AreaLevel.Warning, "Windows Audio isn't answering")]
    [InlineData(AudioProbeOutcome.EndpointCreateFailed, AreaLevel.Warning, "Windows couldn't open this device")]
    public void Probe_outcomes(AudioProbeOutcome probe, AreaLevel level, string text)
    {
        var row = RowOf(Card(Build([Speaker(probe: probe), Mic()]), "audio-output"), "Device responds");
        Assert.Equal(level, row.Level);
        Assert.Equal(text, row.Values[1]);
    }

    [Fact]
    public void Timed_out_probe_marks_the_running_audio_service_not_responding()
    {
        var services = Card(Build([Speaker(probe: AudioProbeOutcome.TimedOut), Mic()]), "audio-services");
        Assert.Equal("Not responding", services.Rows.First(r => r.Key == SoundModule.AudioSrv).Values[1]);
        Assert.Equal(AreaLevel.Warning, services.Level);
    }

    [Fact]
    public void Stopped_disabled_and_stuck_services()
    {
        Assert.Equal("Not running", ServiceRow([Svc(SoundModule.AudioSrv, "STOPPED"), Svc(SoundModule.EndpointBuilder)]).Values[1]);
        Assert.Equal("Disabled", ServiceRow([Svc(SoundModule.AudioSrv, "STOPPED", "DISABLED"), Svc(SoundModule.EndpointBuilder)]).Values[1]);
        ServiceInfo[] pending = [Svc(SoundModule.AudioSrv, "START_PENDING"), Svc(SoundModule.EndpointBuilder)];
        Assert.Equal("Not responding", ServiceRow(pending, again: pending).Values[1]);
        // Starting at the first read, running at the second: fine.
        Assert.Equal(AreaLevel.Ok, ServiceRow(pending, again: HealthyServices).Level);
    }

    private static AreaRow ServiceRow(IReadOnlyList<ServiceInfo> services, IReadOnlyList<ServiceInfo>? again = null) =>
        Card(Build([Speaker(), Mic()], Facts(services, again: again)), "audio-services").Rows.First(r => r.Key == SoundModule.AudioSrv);

    [Fact]
    public void Oem_audio_services_and_drivers_are_listed_as_info()
    {
        var drivers = new[] { new AudioDriver("Realtek(R) Audio", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257\4&1", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257", "oem12.inf", "Realtek", "6.0.9549.1") };
        var card = Card(Build([Speaker(), Mic()], Facts([.. HealthyServices, Svc("RtkAudioUniversalService", "STOPPED", "DEMAND_START")], drivers: drivers)), "audio-services");
        Assert.Contains(card.Rows, r => r.Key == "RtkAudioUniversalService" && r.Level == AreaLevel.Neutral);
        Assert.Contains(card.Rows, r => r.Values[0] == "Driver: Realtek(R) Audio" && r.Values[1] == "6.0.9549.1");
        Assert.Equal(AreaLevel.Ok, card.Level);
    }

    [Fact]
    public void Bluetooth_hands_free_monitor_mono_and_muted_app_are_info()
    {
        var bt = new AudioEndpointInfo(BtId, "Headset (WH-1000XM4 Hands-Free AG Audio)", AudioFlow.Output, AudioEndpointState.Active, AudioBus.Bluetooth, "Headset", "",
            AllRoles, false, 0.5, null, null, null, AudioProbeOutcome.Ok);
        var card = Card(Build([bt, Speaker(roles: []), Mic()], Facts(mono: true), [new AudioSessionInfo("Teams", 42, true, 1, true)]), "audio-output");
        Assert.Equal(AreaLevel.Neutral, RowOf(card, "Bluetooth call mode").Level);
        Assert.Equal(AreaLevel.Neutral, RowOf(card, "Mono audio").Level);
        Assert.Equal("Teams", RowOf(card, "App muted in Volume mixer").Values[1]);
        Assert.Equal(AreaLevel.Ok, card.Level);

        var hdmi = new AudioEndpointInfo(HdmiId, "DELL U2720Q (Intel(R) Display Audio)", AudioFlow.Output, AudioEndpointState.Active, AudioBus.Internal,
            "DigitalAudioDisplayDevice", "", AllRoles, false, 1, null, null, null, AudioProbeOutcome.Ok);
        Assert.Equal(AreaLevel.Neutral, RowOf(Card(Build([hdmi, Speaker(roles: []), Mic()]), "audio-output"), "Sound goes to a monitor").Level);
        // A monitor that is the only output isn't called out.
        Assert.DoesNotContain(Card(Build([hdmi, Mic()]), "audio-output").Rows, r => r.Values[0] == "Sound goes to a monitor");
    }

    [Fact]
    public void Microphone_privacy_names_the_switch_and_opens_settings()
    {
        var row = RowOf(Card(Build([Speaker(), Mic()], Facts(mic: new CapturePrivacy.Switches(false, false, true, true))), "audio-input"), "Microphone privacy");
        Assert.Equal(AreaLevel.Warning, row.Level);
        Assert.Contains("Let desktop apps access your microphone", row.Values[2]);
        Assert.Equal(RemediationKind.AllowCapturePrivacy, row.Actions![0].Kind);
        Assert.Equal(RemediationKind.OpenSettings, row.Actions[1].Kind);
        Assert.Equal("ms-settings:privacy-microphone", row.Actions[1].Target);
    }

    [Fact]
    public void Sound_device_problems_offer_the_existing_device_fixes()
    {
        ProblemDevice[] problems =
        [
            new("Realtek(R) Audio", "MEDIA", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257\4&1", 22, "Error"),
            new("Speakers", "AudioEndpoint", @"SWD\MMDEVAPI\" + SpkId, 10, "Error"),
            new("Wi-Fi", "NET", @"PCI\VEN_8086", 10, "Error"),
        ];
        var r = Build([Speaker(), Mic()], Facts(problems: problems));
        var outRows = Card(r, "audio-output").Rows.Where(x => x.Values[0] == "Sound hardware").ToList();
        Assert.Equal(2, outRows.Count);
        Assert.Equal(RemediationKind.EnableDevice, outRows[0].Actions![0].Kind);
        Assert.Equal(RemediationKind.RestartDevice, outRows[1].Actions![0].Kind);
        // The speaker endpoint's problem isn't shown on the Microphones card; the shared MEDIA device is.
        Assert.Single(Card(r, "audio-input").Rows, x => x.Values[0] == "Sound hardware");
    }

    [Fact]
    public void Generic_driver_on_an_oem_codec_warns_and_links_to_device_manager()
    {
        var generic = new AudioDriver("High Definition Audio Device", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257&SUBSYS_17AA3801\4&1", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257&SUBSYS_17AA3801",
            "hdaudio.inf", "Microsoft", "10.0.22621.1");
        var card = Card(Build([Speaker(), Mic()], Facts(drivers: [generic])), "audio-output");
        var row = RowOf(card, "Generic audio driver");
        Assert.Equal(AreaLevel.Warning, row.Level);
        Assert.Contains("Realtek", row.Values[2]);
        Assert.Equal(RemediationKind.CheckAndInstallDriverUpdates, row.Actions![0].Kind);
        Assert.Equal(ModuleSlugs.DeviceDrivers, card.RunCheck?.CheckId);
    }

    [Theory]
    [InlineData(@"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257", "hdaudio.inf", true)]   // Realtek on the generic driver
    [InlineData(@"HDAUDIO\FUNC_01&VEN_14F1&DEV_1F86", "HDAUDIO.INF", true)]   // Conexant
    [InlineData(@"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257", "oem12.inf", false)]    // Realtek's own driver
    [InlineData(@"HDAUDIO\FUNC_01&VEN_8086&DEV_2812", "hdaudio.inf", false)]  // Intel display audio
    [InlineData(@"HDAUDIO\FUNC_02&VEN_14F1&DEV_2C06", "hdaudio.inf", false)]  // a modem function
    [InlineData(@"USB\VID_046D&PID_0A44&MI_00", "usbaudio2.inf", false)]      // USB headset on the class driver: normal
    [InlineData(@"ACPI\QCOM0D2B", "qcasd8380.inf", false)]                    // Qualcomm ACX (the HP OmniBook)
    [InlineData(@"BTHHFENUM\{0000111e-0000-1000-8000-00805f9b34fb}", "bthhfenum.inf", false)]
    public void Generic_driver_detection(string hardwareId, string inf, bool flagged) =>
        Assert.Equal(flagged, SoundModule.GenericDrivers([new AudioDriver("x", hardwareId + @"\1", hardwareId, inf, "p", "1")]).Count == 1);

    [Theory]
    [InlineData(@"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257&SUBSYS_17AA3801", "10EC")]
    [InlineData(@"HDAUDIO\FUNC_01&ven_14f1&DEV_1F86", "14F1")]
    [InlineData(@"HDAUDIO\FUNC_01&DEV_0257", null)]
    [InlineData(@"HDAUDIO\FUNC_01&VEN_1", null)]
    public void Codec_vendor_is_split_by_hand(string hw, string? vendor) => Assert.Equal(vendor, SoundModule.CodecVendor(hw));

    [Fact]
    public void Unreadable_audio_keeps_the_services_card()
    {
        var r = SoundModule.Build(AudioState.Unavailable("COM failed"), Facts());
        Assert.Equal(AreaLevel.Error, Card(r, "audio-output").Level);
        Assert.Equal(AreaLevel.Error, Card(r, "audio-input").Level);
        Assert.Equal(AreaLevel.Ok, Card(r, "audio-services").Level);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);

        var none = SoundModule.Build(AudioState.Unavailable("COM failed"), Facts() with { Services = null });
        Assert.Equal(DiagnosticStatus.Error, none.Status);
        Assert.Empty(none.Cards);
    }

    [Fact]
    public void Unread_facts_leave_their_rows_out()
    {
        var card = Card(SoundModule.Build(new AudioState([Speaker(), Mic()], []), new SoundFacts(HealthyServices)), "audio-input");
        Assert.DoesNotContain(card.Rows, r => r.Values[0] is "Sound hardware" or "Generic audio driver" or "Microphone privacy");
    }

    [Fact]
    public void Devices_are_listed_after_the_checks_default_first()
    {
        var other = Speaker(roles: []) with { Id = HdmiId, Name = "Another output" };
        var rows = Card(Build([other, Speaker(), Mic()]), "audio-output").Rows.Where(r => r.Values[0] == "Device").ToList();
        Assert.Equal(["Speakers (Realtek(R) Audio)", "Another output"], rows.Select(r => r.Values[1]));
        Assert.Contains("default for console, multimedia, communications", rows[0].Values[2]);
        Assert.Contains("built-in", rows[0].Values[2]);
    }

    [Theory]
    [InlineData("FEFF0200 80BB0000 00DC0500 08002000 1600 1800 03000000 0100000000001000800000AA00389B71", "48000 Hz, 24-bit, 2 channels")]
    [InlineData("01000100 44AC0000 88580100 02001000 0000", "44100 Hz, 16-bit, 1 channel")]
    public void Wave_format_in_words(string hex, string expected) =>
        Assert.Equal(expected, AudioFormatText.FromWaveFormatEx(Convert.FromHexString(hex.Replace(" ", ""))));

    [Fact]
    public void Wave_format_missing_or_short_is_null()
    {
        Assert.Null(AudioFormatText.FromWaveFormatEx(null));
        Assert.Null(AudioFormatText.FromWaveFormatEx(new byte[8]));
    }

    [Fact]
    public void Pre_check_stops_the_interactive_test_with_the_reason()
    {
        Assert.Null(AudioModuleBase.PreCheckMessage(new AudioState([Speaker(), Mic()], []), SpkId, MicId));
        Assert.Contains("isn't answering", AudioModuleBase.PreCheckMessage(new AudioState([Speaker(probe: AudioProbeOutcome.TimedOut), Mic()], []), SpkId, MicId));
        Assert.Contains("exclusive mode", AudioModuleBase.PreCheckMessage(new AudioState([Speaker(probe: AudioProbeOutcome.DeviceInUse), Mic()], []), SpkId, MicId));
        var off = Mic() with { State = AudioEndpointState.Disabled };
        Assert.Contains("is disabled", AudioModuleBase.PreCheckMessage(new AudioState([Speaker(), off], []), SpkId, MicId));
    }

    [Fact]
    public void Audio_state_round_trips_as_json_with_enum_names()
    {
        var s = new AudioState([Speaker(), Mic()], [new AudioSessionInfo("Teams", 42, true, 0.5, true)]);
        var json = s.ToJson();
        Assert.Contains("\"state\":\"Active\"", json);
        Assert.Contains("\"bus\":\"Internal\"", json);
        var back = AudioState.FromJson(json);
        Assert.Equal(s.Endpoints[0], back.Endpoints[0] with { DefaultFor = s.Endpoints[0].DefaultFor });
        Assert.Equal(AllRoles, back.Endpoints[0].DefaultFor);
        Assert.Equal("Teams", back.Sessions[0].ProcessName);
        Assert.False(AudioState.FromJson("not json").Available);
    }

    [Fact]
    public async Task Recorded_audio_replays()
    {
        var recorder = new CallRecorder();
        var live = new FakeAudio(new AudioState([Speaker(), Mic()], []));
        await new RecordingAudioStateSource(live, recorder).ReadAsync();
        var replay = new RecordingReplay(recorder.Snapshot());
        var again = await replay.Audio.ReadAsync();
        Assert.Equal(2, again.Endpoints.Count);
        Assert.Equal(SpkId, again.Endpoints[0].Id);
        Assert.False((await new RecordingReplay([]).Audio.ReadAsync()).Available);
    }

    [Fact]
    public void Scrubber_hides_bluetooth_names_and_device_paths()
    {
        var bt = new AudioEndpointInfo(BtId, "Bud's AirPods Pro", AudioFlow.Output, AudioEndpointState.Active, AudioBus.Bluetooth, "Headphones",
            @"BTHENUM\{0000110b-0000-1000-8000-00805f9b34fb}_LOCALMFG&004c\7&2A2B&0&A0B1C2D3E4F5_C00000000", []);
        var call = RecordedCall.FromAudio(new AudioState([bt, Speaker()], []));
        var scrubbed = new RecordingScrubber("TESTPC", ["someone"]).Scrub(call);
        Assert.DoesNotContain("AirPods", scrubbed.StdOut);
        Assert.DoesNotContain("A0B1C2D3E4F5", scrubbed.StdOut);
        Assert.Contains("<bluetooth:", scrubbed.StdOut);
        Assert.Contains("Speakers (Realtek(R) Audio)", scrubbed.StdOut);
        Assert.Equal(2, AudioState.FromJson(scrubbed.StdOut).Endpoints.Count);

        var wmi = RecordedCall.FromWmi(new WmiQueryResult(@"root\cimv2", "q", [new WmiRow(new Dictionary<string, JsonElement>
        {
            ["DeviceID"] = JsonSerializer.SerializeToElement(@"USB\VID_046D&PID_0A44\SERIAL123"),
        })]));
        Assert.DoesNotContain("SERIAL123", new RecordingScrubber("TESTPC", []).Scrub(wmi).Rows![0]["DeviceID"].GetString());
    }

    [Fact]
    public async Task Check_reads_every_source_and_rechecks_a_pending_service()
    {
        var reads = 0;
        var services = new FakeServices(() => ++reads == 1
            ? [Svc(SoundModule.AudioSrv, "START_PENDING"), Svc(SoundModule.EndpointBuilder)]
            : HealthyServices);
        var wmi = new FakeWmi((ns, q) => q == SoundModule.DriversSql
            ? new WmiQueryResult(ns, q, [Row(("DeviceName", "Realtek(R) Audio"), ("DeviceID", "d"), ("HardWareID", "h"), ("InfName", "oem1.inf"), ("DriverProviderName", "Realtek"), ("DriverVersion", "6.0"))])
            : q == BatteryReader.StaticSql ? new WmiQueryResult(ns, q, [Row(("InstanceName", "b"))]) : WmiQueryResult.Failed(ns, q, "no"));
        var registry = new FakeRegistry(read => read.Path.EndsWith("NonPackaged") ? "Deny" : null);
        var module = new SoundModule(new FakeAudio(new AudioState([Speaker(), Mic()], [])), services, new FakeDevices(), wmi, registry,
            pendingRecheck: TimeSpan.Zero);
        var result = await module.RefreshAsync(null);
        var report = Assert.IsType<AreaReport>(result.Payload);
        Assert.Equal(2, reads);
        Assert.Equal(AreaLevel.Ok, Card(report, "audio-services").Rows.First(r => r.Key == SoundModule.AudioSrv).Level);
        Assert.Contains(Card(report, "audio-services").Rows, r => r.Values[0] == "Driver: Realtek(R) Audio");
        Assert.Equal(AreaLevel.Warning, RowOf(Card(report, "audio-input"), "Microphone privacy").Level);
        Assert.Equal(DiagnosticStatus.Warning, result.Status);
    }

    [Fact]
    public void Sound_is_a_check_in_the_audio_group()
    {
        var d = BuiltInModules.Descriptors.Single(x => x.Id == ModuleIds.Sound);
        Assert.Equal(ModuleKind.Check, d.Kind);
        Assert.Equal(ModuleGroups.Audio, d.Group);
        Assert.Equal(ModuleIds.Sound, ModuleIds.FromSlug("sound"));
    }

    [Fact]
    public async Task Host_query_answers_audio_state()
    {
        var state = new AudioState([Speaker()], []);
        var json = JsonSerializer.SerializeToElement(state, Core.Plugins.HostCapabilities.Json);
        var back = json.Deserialize<AudioState>(Core.Plugins.HostCapabilities.Json)!;
        Assert.Equal(SpkId, back.Endpoints[0].Id);
        Assert.Equal(AudioEndpointState.Active, back.Endpoints[0].State);
        // A host that can't read audio says so instead of throwing.
        var fallback = await new HostAudioStateSource(new NoAudioHost()).ReadAsync();
        Assert.False(fallback.Available);
    }

    private static WmiRow Row(params (string Key, string Value)[] values) =>
        new(values.ToDictionary(v => v.Key, v => JsonSerializer.SerializeToElement(v.Value)));

    private sealed class FakeAudio(AudioState state) : IAudioStateSource
    {
        public Task<AudioState> ReadAsync(CancellationToken ct = default) => Task.FromResult(state);
    }

    private sealed class FakeServices(Func<IReadOnlyList<ServiceInfo>> read) : IServiceSource
    {
        public Task<IReadOnlyList<ServiceInfo>?> ReadServicesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<ServiceInfo>?>(read());
    }

    private sealed class FakeDevices : IDeviceDriverSource
    {
        public Task<IReadOnlyList<ProblemDevice>?> ReadProblemDevicesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<ProblemDevice>?>([]);
        public Task<IReadOnlyList<DriverEntry>?> ReadDriversAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<DriverEntry>?>([]);
    }

    private sealed class FakeWmi(Func<string, string, WmiQueryResult> answer) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) => Task.FromResult(answer(wmiNamespace, wql));
    }

    private sealed class FakeRegistry(Func<RegistryRead, string?> value) : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) =>
            Task.FromResult(new WmiQueryResult(read.Location, read.Describe(), value(read) is { } v ? [Row(("Value", v))] : []));
    }

    private sealed class NoAudioHost : Core.Plugins.IHostQueries
    {
        public Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<Core.Sensors.SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<DriveList?> ReadDrivesAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyDictionary<char, RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default) => throw new NotSupportedException();
    }
}
