using System.Globalization;
using System.Runtime.Versioning;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RegistryRoot = RemotePCDiagnostics.Core.DataSources.RegistryRoot;

namespace RemotePCDiagnostics.Core.Audio;

/// <summary>Audio endpoint ids and the fix and journal targets built on them, checked with string operations (never passed to a shell).</summary>
public static class AudioTargets
{
    public const string OutputPrefix = "{0.0.0.00000000}.", InputPrefix = "{0.0.1.00000000}.";
    /// <summary>The picker's Target before a device is chosen.</summary>
    public const string Output = "output", Input = "input";
    /// <summary>Added to the picker's Target when "Also use for calls" is ticked.</summary>
    public const string CallsSuffix = "|calls";
    public const string Off = "off", On = "on";

    /// <summary>Journal target suffixes for <see cref="ChangeKind.AudioEndpoint"/>.</summary>
    public const string Mute = "mute", Volume = "volume", State = "state", Format = "format", SysFx = "sysfx", DefaultPrefix = "default:";

    /// <summary><c>{0.0.0.00000000}.{guid}</c> (an output) or <c>{0.0.1.00000000}.{guid}</c> (an input).</summary>
    public static bool IsEndpointId(string? id)
    {
        if (id is null || id.Length != OutputPrefix.Length + 38) return false;
        if (!id.StartsWith(OutputPrefix, StringComparison.OrdinalIgnoreCase) && !id.StartsWith(InputPrefix, StringComparison.OrdinalIgnoreCase)) return false;
        var g = id[OutputPrefix.Length..];
        return g[0] == '{' && g[^1] == '}' && Guid.TryParseExact(g, "B", out _);
    }

    public static AudioFlow FlowOf(string id) => id.StartsWith(InputPrefix, StringComparison.OrdinalIgnoreCase) ? AudioFlow.Input : AudioFlow.Output;

    /// <summary>Splits "{endpointId}|rest"; false when the endpoint id isn't one.</summary>
    public static bool TrySplit(string? target, out string id, out string rest)
    {
        id = rest = "";
        if (string.IsNullOrEmpty(target)) return false;
        var bar = target.IndexOf('|');
        id = bar < 0 ? target : target[..bar];
        rest = bar < 0 ? "" : target[(bar + 1)..];
        return IsEndpointId(id);
    }

    public static readonly IReadOnlyList<string> Roles = [AudioEndpointInfo.Console, AudioEndpointInfo.Multimedia, AudioEndpointInfo.Communications];
}

/// <summary>
/// Changes to audio endpoints, in the signed-in user's session (the app, never elevated). Reads return null when the value can't be
/// read; writes throw with the reason. <see cref="CanChangeSettings"/> is false when Windows' <c>IPolicyConfig</c> isn't there: the
/// default device, the endpoint switch, the format and the enhancements switch can't be changed then (mute and volume still can).
/// </summary>
public interface IAudioEndpointControl
{
    bool CanChangeSettings { get; }
    string? Name(string id);
    AudioEndpointState? State(string id);
    bool? GetMute(string id);
    void SetMute(string id, bool mute);
    double? GetVolume(string id);
    void SetVolume(string id, double level);
    /// <summary>The default endpoint's id for a flow and role (Console, Multimedia, Communications); null when there is none.</summary>
    string? GetDefault(AudioFlow flow, string role);
    void SetDefault(string id, string role);
    void SetEnabled(string id, bool enabled);
    byte[]? GetFormat(string id);
    byte[]? GetOemFormat(string id);
    void SetFormat(string id, byte[] waveFormat);
    /// <summary>The "Audio enhancements" switch is off (<c>PKEY_AudioEndpoint_Disable_SysFx</c> = 1); null when unknown.</summary>
    bool? GetEnhancementsDisabled(string id);
    void SetEnhancementsDisabled(string id, bool disabled);
    /// <summary>The apps with an audio session on the endpoint.</summary>
    IReadOnlyList<AudioSessionInfo> Sessions(string id);
    /// <summary>Mutes or unmutes every session of <paramref name="process"/> on the endpoint; returns how many it changed.</summary>
    int SetSessionMute(string id, string process, bool mute);
}

/// <summary>The ConsentStore <c>Value</c> of one privacy switch (<see cref="CapturePrivacy"/>): "Allow", "Deny", or null when absent.</summary>
public interface ICapturePrivacyStore
{
    string? Read(RegistryRoot root, string capability, bool nonPackaged);
    /// <summary>Writes the value; null deletes it. HKLM needs administrator rights (the Agent).</summary>
    void Write(RegistryRoot root, string capability, bool nonPackaged, string? value);
}

/// <summary>The ConsentStore switches in the registry.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsCapturePrivacyStore : ICapturePrivacyStore
{
    private static Microsoft.Win32.RegistryKey Base(RegistryRoot root) => Microsoft.Win32.RegistryKey.OpenBaseKey(
        root == RegistryRoot.LocalMachine ? Microsoft.Win32.RegistryHive.LocalMachine : Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64);

    public string? Read(RegistryRoot root, string capability, bool nonPackaged)
    {
        if (!CapturePrivacy.IsCapability(capability)) throw new ArgumentException("Not a privacy switch this app changes.", nameof(capability));
        using var b = Base(root);
        using var k = b.OpenSubKey(CapturePrivacy.KeyFor(capability, nonPackaged));
        return k?.GetValue("Value") as string;
    }

    public void Write(RegistryRoot root, string capability, bool nonPackaged, string? value)
    {
        if (!CapturePrivacy.IsCapability(capability) || !CapturePrivacy.IsValue(value) || root == RegistryRoot.LocalMachine && nonPackaged)
            throw new ArgumentException("Not a privacy switch this app changes.");
        using var b = Base(root);
        using var k = b.CreateSubKey(CapturePrivacy.KeyFor(capability, nonPackaged), writable: true);
        if (value is null) k.DeleteValue("Value", throwOnMissingValue: false);
        else k.SetValue("Value", value, Microsoft.Win32.RegistryValueKind.String);
    }
}

/// <summary>
/// Runs and undoes the Sound fixes. Every write is read back, and a value that didn't stick (an OEM control panel putting its own volume
/// back) is a failure. The device-wide privacy switch goes through the Agent; everything else runs here, in the user's session.
/// </summary>
public sealed class AudioFixService(IAudioEndpointControl? control, ICapturePrivacyStore? privacy,
    Func<AdminPipeScript, CancellationToken, Task<ProcessResult?>>? agent = null, ILogger? log = null)
{
    /// <summary>The levels the fix raises a quiet device to (the interactive tests' levels).</summary>
    public const double OutputLevel = 0.5, InputLevel = 0.8;

    public sealed record Outcome(bool Success, string Message, IReadOnlyList<ChangeRecord> Changes)
    {
        public static Outcome Fail(string m) => new(false, m, []);
    }

    public bool Available => control is not null;
    public bool CanChangeSettings => control?.CanChangeSettings == true;

    /// <summary>The apps with a session on the endpoint now; null when that can't be read.</summary>
    public IReadOnlyList<AudioSessionInfo>? SessionsOn(string id)
    {
        if (control is null) return null;
        try { return control.Sessions(id); } catch (Exception ex) { log.Warn($"[audio-fix] sessions: {ex.Message}"); return null; }
    }

    public static bool NeedsPolicyConfig(RemediationKind k) => k is RemediationKind.SetDefaultAudioEndpoint or RemediationKind.EnableAudioEndpoint
        or RemediationKind.ResetAudioFormat or RemediationKind.ToggleAudioEnhancements;

    private string NameOf(AreaAction a, string id) => a.TargetLabel is { Length: > 0 } l ? l : control?.Name(id) ?? "the sound device";

    public Task<Outcome> RunAsync(AreaAction a, string actor, CancellationToken ct) => a.Kind == RemediationKind.AllowCapturePrivacy
        ? AllowPrivacyAsync(a.Target, actor, ct)
        : Task.Run(() => Run(a, actor), ct);

    private Outcome Run(AreaAction a, string actor)
    {
        if (control is null) return Outcome.Fail("Sound devices can't be changed in this session.");
        if (NeedsPolicyConfig(a.Kind) && !control.CanChangeSettings) return Outcome.Fail("Windows doesn't let this app change that sound setting on this PC. Use Sound settings instead.");
        ChangeRecord Rec(ChangeKind k, string target, string? prev, string label) => ChangeRecord.New(k, target, prev, label, actor);
        try
        {
            switch (a.Kind)
            {
                case RemediationKind.UnmuteAudioEndpoint:
                {
                    if (!AudioTargets.IsEndpointId(a.Target)) return Outcome.Fail("That isn't a sound device.");
                    var name = NameOf(a, a.Target);
                    var was = control.GetMute(a.Target);
                    if (was is null) return Outcome.Fail($"Couldn't read whether {name} is muted (it may have been unplugged).");
                    if (was == false) return new(true, $"{name} isn't muted.", []);
                    control.SetMute(a.Target, false);
                    if (control.GetMute(a.Target) != false) return Outcome.Fail($"{name} is still muted: something on the PC muted it again.");
                    return new(true, $"Unmuted {name}.", [Rec(ChangeKind.AudioEndpoint, $"{a.Target}|{AudioTargets.Mute}", "true", $"{name} unmuted")]);
                }
                case RemediationKind.RaiseAudioVolume:
                {
                    if (!AudioTargets.IsEndpointId(a.Target)) return Outcome.Fail("That isn't a sound device.");
                    var name = NameOf(a, a.Target);
                    var to = AudioTargets.FlowOf(a.Target) == AudioFlow.Input ? InputLevel : OutputLevel;
                    var was = control.GetVolume(a.Target);
                    if (was is null) return Outcome.Fail($"Couldn't read the volume of {name} (it may have been unplugged).");
                    if (was >= to) return new(true, $"{name} is already at {Pct(was.Value)}.", []);
                    control.SetVolume(a.Target, to);
                    if (control.GetVolume(a.Target) is not { } now || Math.Abs(now - to) > 0.02)
                        return Outcome.Fail($"The volume of {name} didn't stay at {Pct(to)}: the sound driver's own app may be setting it.");
                    return new(true, $"Raised {name} from {Pct(was.Value)} to {Pct(to)}.",
                        [Rec(ChangeKind.AudioEndpoint, $"{a.Target}|{AudioTargets.Volume}", was.Value.ToString("0.000", CultureInfo.InvariantCulture), $"{name} volume raised to {Pct(to)} (was {Pct(was.Value)})")]);
                }
                case RemediationKind.SetDefaultAudioEndpoint:
                {
                    if (a.Target is AudioTargets.Output or AudioTargets.Input) return Outcome.Fail("Pick a device first.");
                    var calls = a.Target.EndsWith(AudioTargets.CallsSuffix, StringComparison.Ordinal);
                    var id = calls ? a.Target[..^AudioTargets.CallsSuffix.Length] : a.Target;
                    if (!AudioTargets.IsEndpointId(id)) return Outcome.Fail("That isn't a sound device.");
                    var name = NameOf(a, id);
                    if (control.State(id) != AudioEndpointState.Active) return Outcome.Fail($"{name} isn't connected and turned on, so it can't be the default.");
                    var flow = AudioTargets.FlowOf(id);
                    var records = new List<ChangeRecord>();
                    foreach (var role in calls ? AudioTargets.Roles : AudioTargets.Roles.Take(2))
                    {
                        var prev = control.GetDefault(flow, role);
                        if (string.Equals(prev, id, StringComparison.OrdinalIgnoreCase)) continue;
                        control.SetDefault(id, role);
                        if (!string.Equals(control.GetDefault(flow, role), id, StringComparison.OrdinalIgnoreCase))
                            return new(false, $"Windows didn't make {name} the default.", records);
                        records.Add(Rec(ChangeKind.AudioEndpoint, $"{id}|{AudioTargets.DefaultPrefix}{role}", prev,
                            $"{name} is the default {(flow == AudioFlow.Input ? "microphone" : "output")}{(role == AudioEndpointInfo.Communications ? " for calls" : "")}"));
                    }
                    var what = flow == AudioFlow.Input ? "microphone" : "output";
                    return new(true, records.Count == 0 ? $"{name} was already the default {what}." : $"{name} is now the default {what}{(calls ? ", for calls too" : "")}.", records);
                }
                case RemediationKind.EnableAudioEndpoint:
                {
                    if (!AudioTargets.IsEndpointId(a.Target)) return Outcome.Fail("That isn't a sound device.");
                    var name = NameOf(a, a.Target);
                    var state = control.State(a.Target);
                    if (state is null) return Outcome.Fail($"{name} isn't on this PC anymore.");
                    if (state != AudioEndpointState.Disabled) return new(true, $"{name} is already turned on.", []);
                    control.SetEnabled(a.Target, true);
                    if (control.State(a.Target) == AudioEndpointState.Disabled) return Outcome.Fail($"Windows didn't turn {name} on.");
                    return new(true, $"Turned {name} on.", [Rec(ChangeKind.AudioEndpoint, $"{a.Target}|{AudioTargets.State}", nameof(AudioEndpointState.Disabled), $"{name} turned on")]);
                }
                case RemediationKind.ResetAudioFormat:
                {
                    if (!AudioTargets.IsEndpointId(a.Target)) return Outcome.Fail("That isn't a sound device.");
                    var name = NameOf(a, a.Target);
                    var was = control.GetFormat(a.Target);
                    var oem = control.GetOemFormat(a.Target);
                    if (oem is null) return Outcome.Fail($"The driver of {name} doesn't say what its default format is.");
                    if (was is not null && was.AsSpan().SequenceEqual(oem)) return new(true, $"{name} already uses the driver's default format.", []);
                    control.SetFormat(a.Target, oem);
                    if (control.GetFormat(a.Target) is not { } now || !now.AsSpan().SequenceEqual(oem)) return Outcome.Fail($"Windows didn't keep the default format on {name}.");
                    var text = AudioFormatText.FromWaveFormatEx(oem);
                    return new(true, $"{name} uses the driver's default format again{(text is null ? "" : $" ({text})")}.",
                        was is null ? [] : [Rec(ChangeKind.AudioEndpoint, $"{a.Target}|{AudioTargets.Format}", Convert.ToBase64String(was),
                            $"{name} format reset to the default (was {AudioFormatText.FromWaveFormatEx(was) ?? "another format"})")]);
                }
                case RemediationKind.ToggleAudioEnhancements:
                {
                    if (!AudioTargets.TrySplit(a.Target, out var id, out var rest) || rest is not (AudioTargets.Off or AudioTargets.On)) return Outcome.Fail("That isn't a sound device.");
                    var name = NameOf(a, id);
                    var disable = rest == AudioTargets.Off;
                    var was = control.GetEnhancementsDisabled(id) ?? false;
                    if (was == disable) return new(true, $"Audio enhancements are already {(disable ? "off" : "on")} for {name}.", []);
                    control.SetEnhancementsDisabled(id, disable);
                    if (control.GetEnhancementsDisabled(id) != disable) return Outcome.Fail($"Windows didn't keep audio enhancements {(disable ? "off" : "on")} for {name}.");
                    return new(true, $"Turned audio enhancements {(disable ? "off" : "on")} for {name}.",
                        [Rec(ChangeKind.AudioEndpoint, $"{id}|{AudioTargets.SysFx}", was ? "true" : "false", $"Audio enhancements turned {(disable ? "off" : "on")} for {name}")]);
                }
                case RemediationKind.UnmuteAudioSession:
                {
                    if (!AudioTargets.TrySplit(a.Target, out var id, out var process) || !AgentScripts.IsProcessName(process)) return Outcome.Fail("That isn't an app on a sound device.");
                    var changed = control.SetSessionMute(id, process, false);
                    if (changed == 0) return Outcome.Fail($"{process} isn't playing sound anymore.");
                    return new(true, $"Unmuted {process} in the Volume mixer.", [Rec(ChangeKind.AudioSession, $"{id}|{process}", "true", $"{process} unmuted in the Volume mixer")]);
                }
            }
        }
        catch (Exception ex)
        {
            log.Warn($"[audio-fix] {a.Kind} '{a.Target}': {ex}");
            return Outcome.Fail($"Windows refused the change: {ex.Message}");
        }
        return Outcome.Fail("Unsupported action.");
    }

    private static string Pct(double v) => $"{Math.Round(v * 100):0}%";

    /// <summary>The switches that are off, in the order Settings shows them: (root, nonPackaged, its name).</summary>
    private static IEnumerable<(RegistryRoot Root, bool NonPackaged)> Switches => [(RegistryRoot.LocalMachine, false), (RegistryRoot.CurrentUser, false), (RegistryRoot.CurrentUser, true)];

    private async Task<Outcome> AllowPrivacyAsync(string capability, string actor, CancellationToken ct)
    {
        if (!CapturePrivacy.IsCapability(capability)) return Outcome.Fail("That isn't a privacy switch this app changes.");
        if (privacy is null) return Outcome.Fail("Privacy settings can't be changed in this session.");
        var thing = CapturePrivacy.Thing(capability);
        var records = new List<ChangeRecord>();
        try
        {
            foreach (var (root, np) in Switches)
            {
                var was = privacy.Read(root, capability, np);
                if (!string.Equals(was, CapturePrivacy.Deny, StringComparison.OrdinalIgnoreCase)) continue;
                if (root == RegistryRoot.LocalMachine)
                {
                    if (agent is null) return new(false, $"{thing} access for this device needs the Agent, which isn't connected.", records);
                    var r = await agent(AgentScripts.Of(AgentScripts.CapturePrivacySet, capability, CapturePrivacy.Allow), ct).ConfigureAwait(false);
                    if (r is not { ExitCode: 0 }) return new(false, SystemCommandRunner.AgentFailure(r) ?? $"Couldn't turn on {thing.ToLowerInvariant()} access for this device (the Agent isn't connected).", records);
                }
                else privacy.Write(root, capability, np, CapturePrivacy.Allow);
                if (!string.Equals(privacy.Read(root, capability, np), CapturePrivacy.Allow, StringComparison.OrdinalIgnoreCase))
                    return new(false, $"Windows didn't keep {CapturePrivacy.SwitchName(root, np, thing)} on (an organization policy may set it).", records);
                records.Add(ChangeRecord.New(ChangeKind.CapturePrivacy, CapturePrivacy.JournalTarget(root, capability, np), was,
                    $"{CapturePrivacy.SwitchName(root, np, thing)} turned on", actor));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Warn($"[audio-fix] privacy {capability}: {ex}");
            return new(false, $"Windows refused the change: {ex.Message}", records);
        }
        return new(true, records.Count == 0 ? $"{thing} access is already on." : $"{thing} access is on. Apps that were already open may need to be restarted to use the {thing.ToLowerInvariant()}.", records);
    }

    /// <summary>Puts one journaled Sound change back. Skipped when the device or app is gone (nothing to put back), failed when Windows refused.</summary>
    public async Task<UndoItemResult> UndoAsync(ChangeRecord c, CancellationToken ct)
    {
        UndoItemResult Ok(string m) => new(c, true, m);
        UndoItemResult Fail(string m) => new(c, false, m);
        UndoItemResult Gone(string m) => new(c, false, m, Skipped: true);
        if (c.Kind == ChangeKind.CapturePrivacy)
        {
            if (!CapturePrivacy.TryParseJournalTarget(c.Target, out var root, out var cap, out var np) || !CapturePrivacy.IsValue(c.Previous))
                return Fail("That privacy switch wasn't recorded, so it was left as is.");
            var name = CapturePrivacy.SwitchName(root, np, CapturePrivacy.Thing(cap));
            if (root == RegistryRoot.LocalMachine)
            {
                if (agent is null) return Fail("The Agent isn't connected.");
                var r = await agent(AgentScripts.Of(AgentScripts.CapturePrivacySet, cap, c.Previous ?? ""), ct).ConfigureAwait(false);
                return r is { ExitCode: 0 } ? Ok($"{name} put back.") : Fail(SystemCommandRunner.AgentFailure(r) ?? "Windows didn't allow putting it back.");
            }
            if (privacy is null) return Fail("Not available.");
            privacy.Write(root, cap, np, c.Previous);
            return Ok($"{name} put back.");
        }
        if (control is null) return Fail("Sound devices can't be changed in this session.");
        if (!AudioTargets.TrySplit(c.Target, out var id, out var what)) return Fail("The sound device wasn't recorded, so it was left as is.");
        return await Task.Run(() =>
        {
            var state = control.State(id);
            if (c.Kind == ChangeKind.AudioSession)
            {
                if (!AgentScripts.IsProcessName(what)) return Fail("The app wasn't recorded, so it was left as is.");
                return state is null ? Gone("The sound device isn't on this PC anymore.")
                    : control.SetSessionMute(id, what, true) > 0 ? Ok($"{what} muted again.") : Gone($"{what} isn't running anymore; nothing to mute.");
            }
            if (c.Kind != ChangeKind.AudioEndpoint) return Fail("Unknown change.");
            var name = control.Name(id) ?? "The sound device";
            if (state is null or AudioEndpointState.NotPresent) return Gone($"{name} isn't connected anymore, so it was left as is.");
            switch (what)
            {
                case AudioTargets.Mute:
                    control.SetMute(id, c.Previous == "true");
                    return Ok(c.Previous == "true" ? $"{name} muted again." : $"{name} unmuted.");
                case AudioTargets.Volume:
                    if (!double.TryParse(c.Previous, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) || v is < 0 or > 1) return Fail("The old volume wasn't recorded.");
                    control.SetVolume(id, v);
                    return Ok($"{name} back at {Pct(v)}.");
                case AudioTargets.State:
                    if (!control.CanChangeSettings) return Fail("Windows doesn't let this app change that sound setting on this PC.");
                    control.SetEnabled(id, false);
                    return Ok($"{name} turned off again.");
                case AudioTargets.Format:
                    if (!control.CanChangeSettings) return Fail("Windows doesn't let this app change that sound setting on this PC.");
                    byte[] fmt;
                    try { fmt = Convert.FromBase64String(c.Previous ?? ""); } catch (FormatException) { return Fail("The old format wasn't recorded."); }
                    if (AudioFormatText.FromWaveFormatEx(fmt) is null) return Fail("The old format wasn't recorded.");
                    try { control.SetFormat(id, fmt); }
                    catch (Exception ex) { return Fail($"{name} doesn't accept its old format anymore ({ex.Message}); the driver's default was kept."); }
                    return Ok($"{name} back to {AudioFormatText.FromWaveFormatEx(fmt)}.");
                case AudioTargets.SysFx:
                    if (!control.CanChangeSettings) return Fail("Windows doesn't let this app change that sound setting on this PC.");
                    control.SetEnhancementsDisabled(id, c.Previous == "true");
                    return Ok($"Audio enhancements {(c.Previous == "true" ? "off" : "on")} again for {name}.");
            }
            if (what.StartsWith(AudioTargets.DefaultPrefix, StringComparison.Ordinal) && what[AudioTargets.DefaultPrefix.Length..] is var role && AudioTargets.Roles.Contains(role))
            {
                if (!control.CanChangeSettings) return Fail("Windows doesn't let this app change that sound setting on this PC.");
                if (!AudioTargets.IsEndpointId(c.Previous)) return Gone("There was no default device before, so the new one was kept.");
                var prevName = control.Name(c.Previous!) ?? "The previous device";
                if (control.State(c.Previous!) != AudioEndpointState.Active) return Gone($"{prevName} isn't connected anymore, so {name} stays the default.");
                control.SetDefault(c.Previous!, role);
                return Ok($"{prevName} is the default again{(role == AudioEndpointInfo.Communications ? " for calls" : "")}.");
            }
            return Fail("That sound setting wasn't recorded, so it was left as is.");
        }, ct).ConfigureAwait(false);
    }
}
