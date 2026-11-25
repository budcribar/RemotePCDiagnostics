using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.Modules.Sound;
using RegistryRoot = RemotePCDiagnostics.Core.DataSources.RegistryRoot;

namespace RemotePCDiagnostics.Tests;

/// <summary>Batch 2 of the audio plan: the Sound fixes, their undo, the choice dialogs and what the Sound check offers.</summary>
public class SoundFixTests
{
    private const string Spk = "{0.0.0.00000000}.{11111111-1111-1111-1111-111111111111}";
    private const string Hdmi = "{0.0.0.00000000}.{22222222-2222-2222-2222-222222222222}";
    private const string BtStereo = "{0.0.0.00000000}.{33333333-3333-3333-3333-333333333333}";
    private const string BtCalls = "{0.0.0.00000000}.{55555555-5555-5555-5555-555555555555}";
    private const string Off = "{0.0.0.00000000}.{66666666-6666-6666-6666-666666666666}";
    private const string Mic = "{0.0.1.00000000}.{44444444-4444-4444-4444-444444444444}";
    private static readonly string[] AllRoles = [AudioEndpointInfo.Console, AudioEndpointInfo.Multimedia, AudioEndpointInfo.Communications];

    // ---------------------------------------------------------------- fakes

    private sealed class FakeControl : IAudioEndpointControl
    {
        public sealed class Ep
        {
            public string Name = "";
            public AudioEndpointState State = AudioEndpointState.Active;
            public bool Mute;
            public double Volume = 0.5;
            public byte[]? Format, Oem;
            public bool FxOff;
        }

        public bool CanChangeSettings { get; set; } = true;
        public readonly Dictionary<string, Ep> Endpoints = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<(AudioFlow, string), string> Defaults = [];
        public readonly List<AudioSessionInfo> SessionList = [];
        /// <summary>An OEM panel that puts its own value back.</summary>
        public bool MuteSticks = true, VolumeSticks = true;
        public bool RejectFormats;

        public Ep Add(string id, string name, AudioEndpointState state = AudioEndpointState.Active)
        {
            var e = new Ep { Name = name, State = state };
            Endpoints[id] = e;
            return e;
        }

        private Ep? Get(string id) => Endpoints.TryGetValue(id, out var e) ? e : null;
        private Ep Must(string id) => Get(id) ?? throw new InvalidOperationException("Element not found.");
        public string? Name(string id) => Get(id)?.Name;
        public AudioEndpointState? State(string id) => Get(id)?.State;
        public bool? GetMute(string id) => Get(id)?.Mute;
        public void SetMute(string id, bool mute) { if (MuteSticks) Must(id).Mute = mute; }
        public double? GetVolume(string id) => Get(id)?.Volume;
        public void SetVolume(string id, double level) { if (VolumeSticks) Must(id).Volume = level; }
        public string? GetDefault(AudioFlow flow, string role) => Defaults.TryGetValue((flow, role), out var id) ? id : null;
        public void SetDefault(string id, string role) { Must(id); Defaults[(AudioTargets.FlowOf(id), role)] = id; }
        public void SetEnabled(string id, bool enabled) => Must(id).State = enabled ? AudioEndpointState.Active : AudioEndpointState.Disabled;
        public byte[]? GetFormat(string id) => Get(id)?.Format;
        public byte[]? GetOemFormat(string id) => Get(id)?.Oem;
        public void SetFormat(string id, byte[] f) { if (RejectFormats) throw new InvalidOperationException("format not supported"); Must(id).Format = f; }
        public bool? GetEnhancementsDisabled(string id) => Get(id)?.FxOff;
        public void SetEnhancementsDisabled(string id, bool disabled) => Must(id).FxOff = disabled;
        public IReadOnlyList<AudioSessionInfo> Sessions(string id) => SessionList.Where(s => s.EndpointId == id).ToList();
        public int SetSessionMute(string id, string process, bool mute)
        {
            var n = 0;
            for (var i = 0; i < SessionList.Count; i++)
                if (SessionList[i].EndpointId == id && string.Equals(SessionList[i].ProcessName, process, StringComparison.OrdinalIgnoreCase))
                {
                    SessionList[i] = SessionList[i] with { Muted = mute };
                    n++;
                }
            return n;
        }
    }

    private sealed class FakePrivacy : ICapturePrivacyStore
    {
        public readonly Dictionary<string, string?> Values = [];
        private static string K(RegistryRoot root, string cap, bool np) => CapturePrivacy.JournalTarget(root, cap, np);
        public string? Read(RegistryRoot root, string capability, bool nonPackaged) => Values.GetValueOrDefault(K(root, capability, nonPackaged));
        public void Write(RegistryRoot root, string capability, bool nonPackaged, string? value)
        {
            if (root == RegistryRoot.LocalMachine) throw new UnauthorizedAccessException("Access is denied.");
            if (value is null) Values.Remove(K(root, capability, nonPackaged)); else Values[K(root, capability, nonPackaged)] = value;
        }
    }

    private static byte[] Wave(uint rate, ushort bits, ushort channels = 2)
    {
        var b = new byte[18];
        BitConverter.GetBytes((ushort)1).CopyTo(b, 0);
        BitConverter.GetBytes(channels).CopyTo(b, 2);
        BitConverter.GetBytes(rate).CopyTo(b, 4);
        BitConverter.GetBytes(bits).CopyTo(b, 14);
        return b;
    }

    private static (FakeControl Control, MemoryChangeJournal Journal, RemediationService Fixes, UndoService Undo, List<AdminPipeScript> Agent, FakePrivacy Privacy) Setup(
        Func<AdminPipeScript, ProcessResult>? agent = null)
    {
        var control = new FakeControl();
        control.Add(Spk, "Speakers");
        control.Add(Mic, "Microphone Array");
        var journal = new MemoryChangeJournal();
        var calls = new List<AdminPipeScript>();
        var privacy = new FakePrivacy();
        var fixes = new AudioFixService(control, privacy, (s, _) =>
        {
            calls.Add(s);
            return Task.FromResult<ProcessResult?>(agent?.Invoke(s) ?? new ProcessResult(0, "", ""));
        });
        return (control, journal, new RemediationService(new SystemCommandRunner(), journal: journal, audio: fixes), new UndoService(journal, new SystemCommandRunner(), audio: fixes), calls, privacy);
    }

    private static AreaAction A(RemediationKind k, string target, string label = "") => new(k, k.ToString(), target, label);

    // ---------------------------------------------------------------- targets

    [Theory]
    [InlineData(Spk, true)]
    [InlineData(Mic, true)]
    [InlineData("{0.0.2.00000000}.{11111111-1111-1111-1111-111111111111}", false)]
    [InlineData("{0.0.0.00000000}.11111111-1111-1111-1111-111111111111", false)]
    [InlineData("{0.0.0.00000000}.{11111111-1111-1111-1111-11111111111}", false)]
    [InlineData("{0.0.0.00000000}.{11111111-1111-1111-1111-111111111111}; calc", false)]
    [InlineData("output", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Endpoint_ids_are_checked_by_shape(string? id, bool valid) => Assert.Equal(valid, AudioTargets.IsEndpointId(id));

    [Fact]
    public async Task A_malformed_endpoint_id_changes_nothing()
    {
        var (control, journal, fixes, _, _, _) = Setup();
        control.Endpoints[Spk].Mute = true;
        var r = await fixes.ExecuteAsync(A(RemediationKind.UnmuteAudioEndpoint, Spk + "|x"));
        Assert.False(r.Success);
        Assert.True(control.Endpoints[Spk].Mute);
        Assert.Empty(journal.All);
    }

    // ---------------------------------------------------------------- endpoint fixes and undo

    [Fact]
    public async Task Unmute_is_journaled_and_undone()
    {
        var (control, journal, fixes, undo, _, _) = Setup();
        control.Endpoints[Spk].Mute = true;

        var r = await fixes.ExecuteAsync(A(RemediationKind.UnmuteAudioEndpoint, Spk, "Speakers"));

        Assert.True(r.Success, r.Message);
        Assert.False(control.Endpoints[Spk].Mute);
        var rec = Assert.Single(journal.All);
        Assert.Equal(ChangeKind.AudioEndpoint, rec.Kind);
        Assert.Equal($"{Spk}|mute", rec.Target);
        Assert.Equal("true", rec.Previous);

        var u = await undo.UndoAllAsync("tech");
        Assert.Equal(1, u.Succeeded);
        Assert.True(control.Endpoints[Spk].Mute);
        Assert.Empty(journal.All);
    }

    [Fact]
    public async Task Unmute_that_did_not_stick_fails()
    {
        var (control, journal, fixes, _, _, _) = Setup();
        control.Endpoints[Spk].Mute = true;
        control.MuteSticks = false;
        var r = await fixes.ExecuteAsync(A(RemediationKind.UnmuteAudioEndpoint, Spk, "Speakers"));
        Assert.False(r.Success);
        Assert.Contains("still muted", r.Message);
        Assert.Empty(journal.All);
    }

    [Fact]
    public async Task Already_unmuted_succeeds_without_a_journal_entry()
    {
        var (_, journal, fixes, _, _, _) = Setup();
        var r = await fixes.ExecuteAsync(A(RemediationKind.UnmuteAudioEndpoint, Spk, "Speakers"));
        Assert.True(r.Success);
        Assert.Empty(journal.All);
    }

    [Theory]
    [InlineData(Spk, 0.5)]
    [InlineData(Mic, 0.8)]
    public async Task Raise_volume_goes_to_the_test_levels_and_undo_puts_the_old_level_back(string id, double expected)
    {
        var (control, journal, fixes, undo, _, _) = Setup();
        control.Endpoints[id].Volume = 0.05;

        var r = await fixes.ExecuteAsync(A(RemediationKind.RaiseAudioVolume, id));

        Assert.True(r.Success, r.Message);
        Assert.Equal(expected, control.Endpoints[id].Volume);
        Assert.Equal("0.050", Assert.Single(journal.All).Previous);
        await undo.UndoAllAsync("tech");
        Assert.Equal(0.05, control.Endpoints[id].Volume, 3);
    }

    [Fact]
    public async Task Volume_an_oem_panel_puts_back_is_reported_as_failed()
    {
        var (control, journal, fixes, _, _, _) = Setup();
        control.Endpoints[Spk].Volume = 0.02;
        control.VolumeSticks = false;
        var r = await fixes.ExecuteAsync(A(RemediationKind.RaiseAudioVolume, Spk));
        Assert.False(r.Success);
        Assert.Contains("didn't stay", r.Message);
        Assert.Empty(journal.All);
    }

    [Fact]
    public async Task Default_device_without_a_choice_does_nothing()
    {
        var (control, journal, fixes, _, _, _) = Setup();
        var r = await fixes.ExecuteAsync(A(RemediationKind.SetDefaultAudioEndpoint, AudioTargets.Output));
        Assert.False(r.Success);
        Assert.Contains("Pick a device", r.Message);
        Assert.Empty(control.Defaults);
        Assert.Empty(journal.All);
    }

    [Fact]
    public async Task Default_device_sets_console_and_multimedia_and_calls_only_when_ticked()
    {
        var (control, journal, fixes, undo, _, _) = Setup();
        control.Add(Hdmi, "Monitor");
        foreach (var role in AllRoles) control.Defaults[(AudioFlow.Output, role)] = Spk;

        var r = await fixes.ExecuteAsync(A(RemediationKind.SetDefaultAudioEndpoint, Hdmi, "Monitor"));

        Assert.True(r.Success, r.Message);
        Assert.Equal(Hdmi, control.Defaults[(AudioFlow.Output, AudioEndpointInfo.Console)]);
        Assert.Equal(Hdmi, control.Defaults[(AudioFlow.Output, AudioEndpointInfo.Multimedia)]);
        Assert.Equal(Spk, control.Defaults[(AudioFlow.Output, AudioEndpointInfo.Communications)]);
        Assert.Equal([$"{Hdmi}|default:Console", $"{Hdmi}|default:Multimedia"], journal.All.Select(c => c.Target));
        Assert.All(journal.All, c => Assert.Equal(Spk, c.Previous));

        await undo.UndoAllAsync("tech");
        Assert.All(AllRoles, role => Assert.Equal(Spk, control.Defaults[(AudioFlow.Output, role)]));

        var withCalls = await fixes.ExecuteAsync(A(RemediationKind.SetDefaultAudioEndpoint, Hdmi + AudioTargets.CallsSuffix, "Monitor"));
        Assert.True(withCalls.Success);
        Assert.All(AllRoles, role => Assert.Equal(Hdmi, control.Defaults[(AudioFlow.Output, role)]));
        Assert.Equal(3, journal.All.Count);
    }

    [Fact]
    public async Task Default_device_refuses_a_device_that_is_unplugged()
    {
        var (control, journal, fixes, _, _, _) = Setup();
        control.Add(Off, "USB headset", AudioEndpointState.Unplugged);
        var r = await fixes.ExecuteAsync(A(RemediationKind.SetDefaultAudioEndpoint, Off, "USB headset"));
        Assert.False(r.Success);
        Assert.Empty(journal.All);
    }

    [Fact]
    public async Task Undo_of_a_default_whose_previous_device_was_unplugged_is_skipped_not_failed()
    {
        var (control, journal, fixes, undo, _, _) = Setup();
        control.Add(Hdmi, "Monitor");
        control.Defaults[(AudioFlow.Output, AudioEndpointInfo.Console)] = Spk;
        control.Defaults[(AudioFlow.Output, AudioEndpointInfo.Multimedia)] = Spk;
        await fixes.ExecuteAsync(A(RemediationKind.SetDefaultAudioEndpoint, Hdmi, "Monitor"));
        control.Endpoints[Spk].State = AudioEndpointState.Unplugged;

        var u = await undo.UndoAllAsync("tech");

        Assert.Equal(0, u.Failed);
        Assert.Equal(2, u.Skipped);
        Assert.Equal(Hdmi, control.Defaults[(AudioFlow.Output, AudioEndpointInfo.Console)]);
        Assert.Empty(journal.All);
    }

    [Fact]
    public async Task Undo_after_the_device_itself_is_gone_is_skipped()
    {
        var (control, _, fixes, undo, _, _) = Setup();
        control.Endpoints[Spk].Mute = true;
        await fixes.ExecuteAsync(A(RemediationKind.UnmuteAudioEndpoint, Spk));
        control.Endpoints.Remove(Spk);
        var u = await undo.UndoAllAsync("tech");
        Assert.Equal(1, u.Skipped);
        Assert.Equal(0, u.Failed);
    }

    [Fact]
    public async Task Enable_endpoint_and_undo()
    {
        var (control, journal, fixes, undo, _, _) = Setup();
        control.Add(Off, "Headphones", AudioEndpointState.Disabled);
        var r = await fixes.ExecuteAsync(A(RemediationKind.EnableAudioEndpoint, Off, "Headphones"));
        Assert.True(r.Success, r.Message);
        Assert.Equal(AudioEndpointState.Active, control.Endpoints[Off].State);
        Assert.Equal($"{Off}|state", Assert.Single(journal.All).Target);
        await undo.UndoAllAsync("tech");
        Assert.Equal(AudioEndpointState.Disabled, control.Endpoints[Off].State);
    }

    [Fact]
    public async Task Reset_format_and_undo_and_a_format_the_device_no_longer_takes()
    {
        var (control, journal, fixes, undo, _, _) = Setup();
        var custom = Wave(192000, 24);
        control.Endpoints[Spk].Format = custom;
        control.Endpoints[Spk].Oem = Wave(48000, 16);

        var r = await fixes.ExecuteAsync(A(RemediationKind.ResetAudioFormat, Spk, "Speakers"));

        Assert.True(r.Success, r.Message);
        Assert.Contains("48000 Hz, 16-bit, 2 channels", r.Message);
        Assert.Equal(control.Endpoints[Spk].Oem, control.Endpoints[Spk].Format);
        Assert.Equal(Convert.ToBase64String(custom), Assert.Single(journal.All).Previous);

        control.RejectFormats = true;
        var failed = await undo.UndoAllAsync("tech");
        Assert.Equal(1, failed.Failed);
        Assert.Contains("doesn't accept its old format", failed.Items[0].Message);
        Assert.Single(journal.All); // kept for a later try

        control.RejectFormats = false;
        await undo.UndoAllAsync("tech");
        Assert.Equal(custom, control.Endpoints[Spk].Format);
    }

    [Fact]
    public async Task Enhancements_off_and_undo()
    {
        var (control, journal, fixes, undo, _, _) = Setup();
        var r = await fixes.ExecuteAsync(A(RemediationKind.ToggleAudioEnhancements, $"{Spk}|off", "Speakers"));
        Assert.True(r.Success, r.Message);
        Assert.True(control.Endpoints[Spk].FxOff);
        Assert.Equal(("" + Spk + "|sysfx", "false"), (journal.All[0].Target, journal.All[0].Previous));
        await undo.UndoAllAsync("tech");
        Assert.False(control.Endpoints[Spk].FxOff);
    }

    [Fact]
    public async Task App_unmute_and_undo_skipped_once_the_app_closed()
    {
        var (control, journal, fixes, undo, _, _) = Setup();
        control.SessionList.Add(new AudioSessionInfo("spotify", 42, true, 1, true, Spk));

        var r = await fixes.ExecuteAsync(A(RemediationKind.UnmuteAudioSession, $"{Spk}|spotify"));

        Assert.True(r.Success, r.Message);
        Assert.False(control.SessionList[0].Muted);
        Assert.Equal(ChangeKind.AudioSession, Assert.Single(journal.All).Kind);
        control.SessionList.Clear();
        var u = await undo.UndoAllAsync("tech");
        Assert.Equal(1, u.Skipped);
    }

    [Fact]
    public async Task Without_ipolicyconfig_the_policy_fixes_are_not_allowed_but_mute_still_is()
    {
        var (control, _, fixes, _, _, _) = Setup();
        control.CanChangeSettings = false;
        control.Add(Off, "Headphones", AudioEndpointState.Disabled);
        Assert.False(fixes.Plan(A(RemediationKind.EnableAudioEndpoint, Off)).Allowed);
        Assert.False(fixes.Plan(A(RemediationKind.SetDefaultAudioEndpoint, AudioTargets.Output)).Allowed);
        Assert.True(fixes.Plan(A(RemediationKind.UnmuteAudioEndpoint, Spk)).Allowed);
        var r = await fixes.ExecuteAsync(A(RemediationKind.EnableAudioEndpoint, Off));
        Assert.False(r.Success);
        Assert.Equal(AudioEndpointState.Disabled, control.Endpoints[Off].State);
    }

    [Fact]
    public void Without_the_audio_service_the_fixes_are_not_offered_as_allowed()
    {
        var plans = new RemediationService(new SystemCommandRunner());
        Assert.False(plans.Plan(A(RemediationKind.UnmuteAudioEndpoint, Spk)).Allowed);
    }

    // ---------------------------------------------------------------- privacy

    [Fact]
    public async Task Privacy_per_account_switches_change_in_the_app_and_undo_restores_or_deletes()
    {
        var (_, journal, fixes, undo, agent, privacy) = Setup();
        privacy.Values["HKCU|microphone"] = "Deny";
        privacy.Values["HKCU|microphone|NonPackaged"] = "Deny";
        privacy.Values["HKLM|microphone"] = "Allow";

        var r = await fixes.ExecuteAsync(A(RemediationKind.AllowCapturePrivacy, CapturePrivacy.Microphone));

        Assert.True(r.Success, r.Message);
        Assert.Empty(agent);
        Assert.Equal("Allow", privacy.Values["HKCU|microphone"]);
        Assert.Equal("Allow", privacy.Values["HKCU|microphone|NonPackaged"]);
        Assert.Equal(["HKCU|microphone", "HKCU|microphone|NonPackaged"], journal.All.Select(c => c.Target));
        Assert.All(journal.All, c => Assert.Equal(ChangeKind.CapturePrivacy, c.Kind));

        await undo.UndoAllAsync("tech");
        Assert.Equal("Deny", privacy.Values["HKCU|microphone"]);
        Assert.Equal("Deny", privacy.Values["HKCU|microphone|NonPackaged"]);
    }

    [Fact]
    public async Task Privacy_device_wide_switch_goes_to_the_agent_only_when_it_is_off()
    {
        FakePrivacy? store = null;
        var (_, journal, fixes, undo, agent, privacy) = Setup(s =>
        {
            store!.Values["HKLM|microphone"] = s.Args![1] is { Length: > 0 } v ? v : null;
            return new ProcessResult(0, "", "");
        });
        store = privacy;
        privacy.Values["HKLM|microphone"] = "Deny";

        var r = await fixes.ExecuteAsync(A(RemediationKind.AllowCapturePrivacy, CapturePrivacy.Microphone));

        Assert.True(r.Success, r.Message);
        var call = Assert.Single(agent);
        Assert.Equal(AgentScripts.CapturePrivacySet, call.Name);
        Assert.Equal(["microphone", "Allow"], call.Args);
        Assert.Equal("HKLM|microphone", Assert.Single(journal.All).Target);

        await undo.UndoAllAsync("tech");
        Assert.Equal(["microphone", "Deny"], agent[1].Args);
        Assert.Equal("Deny", privacy.Values["HKLM|microphone"]);
    }

    [Fact]
    public async Task Privacy_absent_value_is_deleted_again_on_undo()
    {
        var (_, journal, _, undo, _, privacy) = Setup();
        journal.Add(ChangeRecord.New(ChangeKind.CapturePrivacy, "HKCU|webcam", null, "Let apps access your camera turned on", "tech"));
        privacy.Values["HKCU|webcam"] = "Allow";
        await undo.UndoAllAsync("tech");
        Assert.False(privacy.Values.ContainsKey("HKCU|webcam"));
    }

    [Theory]
    [InlineData("HKCU|microphone", true)]
    [InlineData("HKCU|webcam|NonPackaged", true)]
    [InlineData("HKLM|microphone", true)]
    [InlineData("HKLM|microphone|NonPackaged", false)]
    [InlineData("HKCU|location", false)]
    [InlineData("HKCU|microphone|Other", false)]
    [InlineData("HKU|microphone", false)]
    public void Privacy_journal_targets_come_from_a_fixed_list(string target, bool valid) =>
        Assert.Equal(valid, CapturePrivacy.TryParseJournalTarget(target, out _, out _, out _));

    [Theory]
    [InlineData("microphone", "Allow", true)]
    [InlineData("webcam", "Deny", true)]
    [InlineData("microphone", "", true)]
    [InlineData("location", "Allow", false)]
    [InlineData("microphone", "Prompt", false)]
    public void Agent_takes_only_the_capture_privacy_switches(string capability, string value, bool allowed)
    {
        var plan = AgentScripts.Plan(AgentScripts.Of(AgentScripts.CapturePrivacySet, capability, value), null, out var refusal);
        Assert.Equal(allowed, plan is not null);
        if (allowed) Assert.Equal(new SetCapturePrivacyAction(capability, value.Length > 0 ? value : null), plan!.Native);
        else Assert.NotNull(refusal);
    }

    // ---------------------------------------------------------------- device busy

    [Fact]
    public async Task Close_holder_refuses_a_protected_process_and_one_no_longer_on_the_device()
    {
        var (control, _, fixes, _, _, _) = Setup();
        control.SessionList.Add(new AudioSessionInfo("obs64", 7, false, 1, true, Spk));

        Assert.False(fixes.Plan(A(RemediationKind.CloseAudioHolder, $"{Spk}|audiodg")).Allowed);
        Assert.True(fixes.Plan(A(RemediationKind.CloseAudioHolder, Spk, "Speakers")).Allowed); // the dialog, before a choice
        var gone = await fixes.ExecuteAsync(A(RemediationKind.CloseAudioHolder, $"{Spk}|zoom"));
        Assert.False(gone.Success);
        Assert.Contains("isn't using the sound device", gone.Message);
        var none = await fixes.ExecuteAsync(A(RemediationKind.CloseAudioHolder, Spk));
        Assert.False(none.Success);
        Assert.Equal(UndoSupport.None, Undoability.Of(RemediationKind.CloseAudioHolder));
    }

    // ---------------------------------------------------------------- what the Sound check offers

    private static AudioEndpointInfo Ep(string id, string name, AudioBus bus = AudioBus.Internal, string form = "Speakers", string[]? roles = null,
        AudioEndpointState state = AudioEndpointState.Active, bool muted = false, double volume = 0.5, AudioProbeOutcome probe = AudioProbeOutcome.Ok, bool? fxOff = false) =>
        new(id, name, AudioTargets.FlowOf(id), state, bus, form, "", roles ?? [], muted, volume, "48000 Hz, 24-bit, 2 channels", "48000 Hz, 24-bit, 2 channels", fxOff, probe);

    private static AreaReport Build(IReadOnlyList<AudioEndpointInfo> eps, IReadOnlyList<AudioSessionInfo>? sessions = null, bool? policy = true,
        CapturePrivacy.Switches? mic = null) =>
        SoundModule.Build(new AudioState(eps, sessions ?? [], CanChangeSettings: policy),
            new SoundFacts([], null, [], [], true, mic ?? new CapturePrivacy.Switches(false, false, false, true), false));

    private static AreaRow Row(AreaReport r, string card, string check) => r.Cards.Single(c => c.Id == card).Rows.First(x => x.Values[0] == check);

    [Fact]
    public void Picker_lists_connected_devices_first_bluetooth_stereo_above_hands_free_and_greys_out_the_rest()
    {
        var r = Build([
            Ep(Spk, "Speakers", roles: AllRoles),
            Ep(BtCalls, "Headset Hands-Free", AudioBus.Bluetooth, "Headset"),
            Ep(BtStereo, "Headphones (WH-1000XM4)", AudioBus.Bluetooth, "Headphones"),
            Ep(Hdmi, "LG Monitor", form: "DigitalAudioDisplayDevice"),
            Ep(Off, "Headphones (jack)", form: "Headphones", state: AudioEndpointState.Unplugged),
            Ep(Mic, "Microphone Array", form: "Microphone", roles: AllRoles)]);

        var picker = Assert.Single(r.Cards.Single(c => c.Id == "audio-output").Actions!);
        Assert.Equal(RemediationKind.SetDefaultAudioEndpoint, picker.Kind);
        Assert.Equal(AudioTargets.Output, picker.Target);
        var ids = picker.Choices!.Select(c => c.Id).ToList();
        Assert.True(ids.IndexOf(BtStereo) < ids.IndexOf(BtCalls));
        Assert.Equal(Off, ids[^1]);
        Assert.NotNull(picker.Choices!.Single(c => c.Id == Off).DisabledReason);
        Assert.Contains("Stereo (music and video)", picker.Choices!.Single(c => c.Id == BtStereo).Detail);
        Assert.Contains("Hands-free (calls)", picker.Choices!.Single(c => c.Id == BtCalls).Detail);
        Assert.Contains("Only plays sound if the monitor has speakers", picker.Choices!.Single(c => c.Id == Hdmi).Detail);
        Assert.DoesNotContain(picker.Choices!, c => c.Selected);
        Assert.Equal(AudioTargets.CallsSuffix, picker.Option!.Suffix);
        Assert.True(picker.Option.DefaultOn);
        Assert.DoesNotContain(picker.Choices!, c => c.Id == Mic);
    }

    [Fact]
    public void Muted_quiet_and_disabled_rows_carry_their_fixes()
    {
        var r = Build([Ep(Spk, "Speakers", roles: AllRoles, muted: true, volume: 0.03), Ep(Off, "Headphones", state: AudioEndpointState.Disabled),
            Ep(Mic, "Mic", form: "Microphone", roles: AllRoles, volume: 0.1)]);

        Assert.Equal((RemediationKind.UnmuteAudioEndpoint, Spk), Act(Row(r, "audio-output", "Muted")));
        Assert.Equal((RemediationKind.RaiseAudioVolume, Spk), Act(Row(r, "audio-output", "Low volume")));
        Assert.Equal((RemediationKind.EnableAudioEndpoint, Off), Act(Row(r, "audio-output", "Disabled or unplugged")));
        Assert.Equal((RemediationKind.RaiseAudioVolume, Mic), Act(Row(r, "audio-input", "Low microphone level")));
        static (RemediationKind, string) Act(AreaRow row) => (row.Actions![0].Kind, row.Actions[0].Target);
    }

    [Fact]
    public void Without_ipolicyconfig_only_mute_and_volume_fixes_are_offered()
    {
        var r = Build([Ep(Spk, "Speakers", roles: AllRoles, muted: true), Ep(Hdmi, "Monitor", form: "DigitalAudioDisplayDevice"),
            Ep(Off, "Headphones", state: AudioEndpointState.Disabled), Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)], policy: false);
        var kinds = r.Cards.SelectMany(c => (c.Actions ?? []).Concat(c.Rows.SelectMany(x => x.Actions ?? []))).Select(a => a.Kind).ToList();
        Assert.Contains(RemediationKind.UnmuteAudioEndpoint, kinds);
        Assert.DoesNotContain(RemediationKind.SetDefaultAudioEndpoint, kinds);
        Assert.DoesNotContain(RemediationKind.EnableAudioEndpoint, kinds);
    }

    [Fact]
    public void Busy_device_lists_its_apps_without_protected_ones_or_offers_the_volume_mixer()
    {
        var busy = Ep(Spk, "Speakers", roles: AllRoles, probe: AudioProbeOutcome.DeviceInUse);
        var r = Build([busy, Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)], [
            new AudioSessionInfo("obs64", 1, false, 1, true, Spk, "OBS 30.1"),
            new AudioSessionInfo("audiodg", 2, false, 1, true, Spk),
            new AudioSessionInfo("spotify", 3, false, 1, false, Spk),
            new AudioSessionInfo("teams", 4, false, 1, true, Mic)]);
        var close = Row(r, "audio-output", "Device responds").Actions!.Single();
        Assert.Equal(RemediationKind.CloseAudioHolder, close.Kind);
        Assert.Equal(Spk, close.Target);
        Assert.Equal([$"{Spk}|obs64", $"{Spk}|spotify"], close.Choices!.Select(c => c.Id));
        Assert.Equal("obs64 (OBS 30.1)", close.Choices![0].Label);

        var empty = Build([busy, Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)]);
        var mixer = Row(empty, "audio-output", "Device responds").Actions!.Single();
        Assert.Equal((RemediationKind.OpenSettings, "ms-settings:apps-volume"), (mixer.Kind, mixer.Target));
    }

    [Fact]
    public void Muted_app_gets_an_unmute_for_its_own_device()
    {
        var r = Build([Ep(Spk, "Speakers", roles: AllRoles), Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)],
            [new AudioSessionInfo("spotify", 3, true, 1, true, Spk), new AudioSessionInfo("teams", 4, true, 1, true, Mic)]);
        var row = Row(r, "audio-output", "App muted in Volume mixer");
        Assert.Equal("spotify", row.Values[1]);
        Assert.Equal($"{Spk}|spotify", Assert.Single(row.Actions!).Target);
    }

    [Fact]
    public void Privacy_row_asks_for_consent_and_keeps_the_settings_link()
    {
        var r = Build([Ep(Spk, "Speakers", roles: AllRoles), Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)],
            mic: new CapturePrivacy.Switches(false, true, false, true));
        var actions = Row(r, "audio-input", "Microphone privacy").Actions!;
        Assert.Equal(RemediationKind.AllowCapturePrivacy, actions[0].Kind);
        Assert.Equal(CapturePrivacy.Microphone, actions[0].Target);
        Assert.NotNull(actions[0].Consent);
        Assert.Equal(RemediationKind.OpenSettings, actions[1].Kind);
    }

    [Fact]
    public void Enhancements_off_is_offered_only_when_the_device_fails_to_open()
    {
        var ok = Build([Ep(Spk, "Speakers", roles: AllRoles), Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)]);
        Assert.Null(Row(ok, "audio-output", "Audio enhancements").Actions);
        var failed = Build([Ep(Spk, "Speakers", roles: AllRoles, probe: AudioProbeOutcome.Failed), Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)]);
        var row = Row(failed, "audio-output", "Audio enhancements");
        Assert.Equal(AreaLevel.Warning, row.Level);
        Assert.Equal($"{Spk}|off", row.Actions![0].Target);
    }

    // ---------------------------------------------------------------- dialogs and the workflow

    [Fact]
    public void Dialog_export_needs_a_choice_and_consent_before_go()
    {
        var picker = SoundModule.Picker(new AudioState([Ep(Spk, "Speakers", roles: AllRoles), Ep(Hdmi, "Monitor"), Ep(Off, "Jack", state: AudioEndpointState.Unplugged)], []), AudioFlow.Output);
        var plan = new RemediationPlan(picker, "Choose where sound plays", "", "", null, true);

        var none = AgentExports.BuildFixDialog(plan, null, true, false)!;
        Assert.False(none.CanConfirm);
        Assert.Null(none.ChosenTarget);
        Assert.Equal(3, none.Choices.Count);
        Assert.False(AgentExports.BuildFixDialog(plan, Off, true, false)!.CanConfirm); // greyed out
        var hdmi = AgentExports.BuildFixDialog(plan, Hdmi, true, false)!;
        Assert.True(hdmi.CanConfirm);
        Assert.Equal(Hdmi + AudioTargets.CallsSuffix, hdmi.ChosenTarget);
        Assert.Equal(Hdmi, AgentExports.BuildFixDialog(plan, Hdmi, false, false)!.ChosenTarget);

        var consent = new RemediationPlan(SoundModule.PrivacyAction(CapturePrivacy.Microphone, new(false, true, false, true)), "Turn on", "", "", null, true);
        Assert.False(AgentExports.BuildFixDialog(consent, null, false, false)!.CanConfirm);
        Assert.True(AgentExports.BuildFixDialog(consent, null, false, true)!.CanConfirm);
        Assert.Null(AgentExports.BuildFixDialog(new RemediationPlan(A(RemediationKind.UnmuteAudioEndpoint, Spk), "", "", "", null, true), null, false, false));
        Assert.Contains("\"dialog\"", AgentExports.FixState(null, null, none));
    }

    [Fact]
    public void Workflow_leaves_out_the_dialog_fixes_and_lists_enhancements_unticked()
    {
        var r = Build([Ep(Spk, "Speakers", roles: AllRoles, muted: true, probe: AudioProbeOutcome.DeviceInUse), Ep(Hdmi, "Monitor"),
            Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)], [new AudioSessionInfo("obs64", 1, false, 1, true, Spk)],
            mic: new CapturePrivacy.Switches(false, true, false, true));
        var result = new DiagnosticResult(SoundModule.ModuleName, DiagnosticStatus.Warning, r.Summary, DateTimeOffset.Now, r);
        var fixes = FixCatalog.Build([result], []);
        Assert.Contains(fixes, f => f.Remediation!.Kind == RemediationKind.UnmuteAudioEndpoint && f.Area == "Sound");
        Assert.DoesNotContain(fixes, f => f.Remediation!.Kind is RemediationKind.SetDefaultAudioEndpoint or RemediationKind.AllowCapturePrivacy or RemediationKind.CloseAudioHolder);

        var fx = Build([Ep(Spk, "Speakers", roles: AllRoles, probe: AudioProbeOutcome.Failed), Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)]);
        var toggle = FixCatalog.Build([new DiagnosticResult(SoundModule.ModuleName, DiagnosticStatus.Warning, fx.Summary, DateTimeOffset.Now, fx)], []).Single(f => f.Remediation!.Kind == RemediationKind.ToggleAudioEnhancements);
        Assert.False(toggle.DefaultOn);
    }

    [Fact]
    public void Choice_target_adds_the_option_suffix_only_when_ticked()
    {
        var a = SoundModule.Picker(new AudioState([Ep(Spk, "Speakers")], []), AudioFlow.Output);
        Assert.Equal(Spk + "|calls", a.TargetFor(a.Choices![0], true));
        Assert.Equal(Spk, a.TargetFor(a.Choices![0], false));
    }

    [Fact]
    public void The_report_copy_carries_the_dialog_for_Admin()
    {
        var r = Build([Ep(Spk, "Speakers", roles: AllRoles), Ep(Hdmi, "Monitor"), Ep(Mic, "Mic", form: "Microphone", roles: AllRoles)],
            mic: new CapturePrivacy.Switches(false, true, false, true));
        var json = AreaReportExport.ToJson(r);
        // Admin reads the copy with a depth limit of 10: a row action's choice sits at depth 9.
        using var doc = System.Text.Json.JsonDocument.Parse(json, new System.Text.Json.JsonDocumentOptions { MaxDepth = 10 });
        var actions = doc.RootElement.GetProperty("cards").EnumerateArray()
            .SelectMany(c => (c.TryGetProperty("actions", out var a) ? a.EnumerateArray() : default(System.Text.Json.JsonElement.ArrayEnumerator))
                .Concat(c.GetProperty("rows").EnumerateArray().SelectMany(row => row.TryGetProperty("actions", out var ra) ? ra.EnumerateArray() : default(System.Text.Json.JsonElement.ArrayEnumerator))))
            .ToList();
        var picker = actions.First(a => a.GetProperty("kind").GetString() == nameof(RemediationKind.SetDefaultAudioEndpoint));
        Assert.Contains(picker.GetProperty("choices").EnumerateArray(), c => c.GetProperty("id").GetString() == Hdmi);
        Assert.Equal("|calls", picker.GetProperty("option").GetProperty("suffix").GetString());
        var privacy = actions.First(a => a.GetProperty("kind").GetString() == nameof(RemediationKind.AllowCapturePrivacy));
        Assert.False(string.IsNullOrEmpty(privacy.GetProperty("consent").GetString()));
        Assert.False(privacy.TryGetProperty("choices", out _));
    }
}
