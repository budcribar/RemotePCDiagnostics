using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Audio;

/// <summary>One device's result in the per-device test.</summary>
public enum AudioDeviceOutcome { NotTested, Passed, Warning, Failed, Skipped }

/// <summary>
/// One speaker or microphone in the "Every speaker and microphone" test: what Windows says about it (state, mute, level) and what the
/// test found. Outputs are judged by the person (they heard the chime on the left and the right); microphones by the recorded level.
/// </summary>
/// <param name="Kind">Plain words for the device: "Speakers", "Headphones", "HDMI or DisplayPort", "Microphone", "Line in"…, with "Bluetooth" or "USB".</param>
/// <param name="Result">One line for the row ("Heard on both sides", "No signal", "Disabled", "Not tested").</param>
/// <param name="Heard">Outputs: what the person heard; null until they answer.</param>
/// <param name="Channels">Outputs: the channel count the chime played on (1 = it can't play left and right apart); null until played.</param>
/// <param name="LevelDbfs">Microphones: the loudest 100 ms of the recording (RMS, dBFS); null until recorded.</param>
/// <param name="PeakDbfs">Microphones: the recording's peak (dBFS); null until recorded.</param>
/// <param name="Hint">What to do next, for the person ("Speak closer", "Connect a monitor with speakers"); null when nothing.</param>
/// <param name="Actions">The Sound fixes for this device (turn on, unmute, raise the level), as on the Sound check.</param>
public sealed record AudioDeviceRow(
    string Id, string Name, AudioFlow Flow, string Kind, AudioEndpointState State, bool IsDefault, bool? Muted, double? Volume,
    AudioDeviceOutcome Outcome, string Result, SoundCheckAnswer? Heard = null, int? Channels = null, double? LevelDbfs = null,
    double? PeakDbfs = null, string? Hint = null, IReadOnlyList<AreaAction>? Actions = null)
{
    public bool IsActive => State == AudioEndpointState.Active;
    /// <summary>The device can be tested now (active). Disabled and unplugged devices are Skipped with the reason.</summary>
    public bool Testable => IsActive;
    /// <summary>An output that was played and is waiting for the person's answer.</summary>
    public bool WaitingForAnswer => Flow == AudioFlow.Output && Channels is not null && Heard is null && Outcome == AudioDeviceOutcome.NotTested;
}

/// <param name="Devices">Every output, then every input, the Windows default first in each.</param>
/// <param name="Notice">Why the device list is incomplete (Core Audio couldn't be read); null when it's complete.</param>
public sealed record AudioDevicesReport(IReadOnlyList<AudioDeviceRow> Devices, string? Notice = null)
{
    public IEnumerable<AudioDeviceRow> Outputs => Devices.Where(d => d.Flow == AudioFlow.Output);
    public IEnumerable<AudioDeviceRow> Inputs => Devices.Where(d => d.Flow == AudioFlow.Input);
    public int Tested => Devices.Count(d => d.Outcome is AudioDeviceOutcome.Passed or AudioDeviceOutcome.Warning or AudioDeviceOutcome.Failed);
    public int Untested => Devices.Count(d => d.Testable && d.Outcome == AudioDeviceOutcome.NotTested);
}

/// <summary>What a microphone recording sounded like.</summary>
public sealed record MicLevel(double LevelDbfs, double PeakDbfs, bool DigitalSilence, bool Clipped);

/// <summary>The per-device test's rules: device rows from the Sound check's reader, judging a recording, and the overall verdict.</summary>
public static class AudioDevicesTest
{
    public const string DisplayName = "Every speaker and microphone";
    public static readonly TimeSpan RecordLength = TimeSpan.FromSeconds(3);

    /// <summary>The loudest 100 ms below this: the microphone gave no signal (Failed).</summary>
    public const double NoSignalDbfs = -60;
    /// <summary>…below this: very quiet, "speak closer" (Warning). Normal speech at arm's length is about -35 to -20 dBFS.</summary>
    public const double LowLevelDbfs = -45;
    /// <summary>The same low-volume thresholds as the Sound check: outputs under 10%, microphones under 25%.</summary>
    public const double LowOutputVolume = 0.10, LowInputVolume = 0.25;

    public const string NoSignal = "No signal";
    public const string NotTested = "Not tested";

    /// <summary>Plain words for a Core Audio form factor and bus.</summary>
    public static string KindOf(AudioEndpointInfo e)
    {
        var kind = e.FormFactor switch
        {
            "Speakers" => "Speakers",
            "Headphones" => "Headphones",
            "Headset" => "Headset",
            "Handset" => "Handset",
            "LineLevel" => e.Flow == AudioFlow.Output ? "Line out" : "Line in",
            "DigitalAudioDisplayDevice" => "HDMI or DisplayPort",
            "Spdif" => "S/PDIF (digital)",
            "Microphone" => "Microphone",
            _ => e.Flow == AudioFlow.Output ? "Speaker" : "Microphone",
        };
        return e.Bus switch { AudioBus.Bluetooth => kind + " · Bluetooth", AudioBus.Usb => kind + " · USB", _ => kind };
    }

    /// <summary>Every endpoint the Sound check's reader lists, as rows: active ones Not tested, the rest Skipped with the reason.</summary>
    /// <param name="previous">The last report: a device still present and active keeps its result (a fix in between doesn't wipe it).</param>
    public static AudioDevicesReport Build(AudioState state, AudioDevicesReport? previous = null)
    {
        if (!state.Available) return new([], state.Error);
        var policy = state.CanChangeSettings != false;
        var rows = new List<AudioDeviceRow>();
        foreach (var flow in new[] { AudioFlow.Output, AudioFlow.Input })
        {
            // NotPresent endpoints are leftovers of devices removed long ago (Windows keeps them): not worth a row.
            foreach (var e in state.Endpoints.Where(e => e.Flow == flow && e.State != AudioEndpointState.NotPresent)
                         .OrderByDescending(e => e.IsActive).ThenByDescending(e => e.IsDefault).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
            {
                var row = Row(e, policy);
                if (row.IsActive && previous?.Devices.FirstOrDefault(p => p.Id == e.Id && p.IsActive) is { } old)
                    row = row with { Outcome = old.Outcome, Result = old.Result, Heard = old.Heard, Channels = old.Channels, LevelDbfs = old.LevelDbfs,
                        PeakDbfs = old.PeakDbfs, Hint = KeepHint(old, row) };
                rows.Add(row);
            }
        }
        return new(rows);
    }

    private static string? KeepHint(AudioDeviceRow old, AudioDeviceRow updated)
    {
        if (old.Hint is null) return updated.Hint;
        if (updated.Muted != true && old.Hint.Contains("muted", StringComparison.OrdinalIgnoreCase))
            return updated.Hint;
        var low = updated.Flow == AudioFlow.Output ? LowOutputVolume : LowInputVolume;
        if ((updated.Volume is not { } nv || nv >= low) && old.Hint.Contains("very low", StringComparison.OrdinalIgnoreCase))
            return updated.Hint;
        return old.Hint;
    }

    /// <summary>Rows from the plain device list, when Core Audio's full reader isn't there (only active devices, no mute or level).</summary>
    public static AudioDevicesReport FromDevices(IReadOnlyList<AudioDevice> devices, string? notice) =>
        new(devices.OrderBy(d => d.Flow).ThenByDescending(d => d.IsDefault).Select(d => new AudioDeviceRow(d.Id, d.Name, d.Flow,
            d.Flow == AudioFlow.Output ? "Speaker" : "Microphone", AudioEndpointState.Active, d.IsDefault, null, null, AudioDeviceOutcome.NotTested, NotTested)).ToList(),
            notice);

    private static AudioDeviceRow Row(AudioEndpointInfo e, bool policy)
    {
        var output = e.Flow == AudioFlow.Output;
        var kind = KindOf(e);
        if (!e.IsActive)
        {
            var hint = e.IsDisplayAudio && e.State != AudioEndpointState.Disabled
                ? "Connect a monitor or TV with speakers to this port, then check again."
                : e.Reconnect;
            IReadOnlyList<AreaAction>? on = policy && e.State == AudioEndpointState.Disabled
                ? [new AreaAction(RemediationKind.EnableAudioEndpoint, $"Turn on {e.Name}", e.Id, e.Name)]
                : null;
            return new(e.Id, e.Name, e.Flow, kind, e.State, e.IsDefault, null, null, AudioDeviceOutcome.Skipped, e.FriendlyState, Hint: hint, Actions: on);
        }
        var actions = new List<AreaAction>();
        if (e.Muted == true) actions.Add(new AreaAction(RemediationKind.UnmuteAudioEndpoint, "Unmute", e.Id, e.Name));
        if (e.Volume is { } v && v < (output ? LowOutputVolume : LowInputVolume))
            actions.Add(new AreaAction(RemediationKind.RaiseAudioVolume, output ? "Raise volume to 50%" : "Raise level to 80%", e.Id, e.Name));
        var hintActive = e.IsDisplayAudio ? "Sound goes to the monitor or TV: it needs speakers, and its own volume up." : null;
        return new(e.Id, e.Name, e.Flow, kind, e.State, e.IsDefault, e.Muted, e.Volume, AudioDeviceOutcome.NotTested, NotTested, Hint: hintActive,
            Actions: actions.Count > 0 ? actions : null);
    }

    /// <summary>The loudest 100 ms (RMS) and the peak of a recording.</summary>
    public static MicLevel Measure(ReadOnlySpan<float> s, int sampleRate)
    {
        if (s.IsEmpty || sampleRate <= 0) return new(AudioMath.SilenceDbfs, AudioMath.SilenceDbfs, true, false);
        var block = Math.Max(16, sampleRate / 10);
        double loudest = 0;
        for (var o = 0; o < s.Length; o += block)
            loudest = Math.Max(loudest, AudioMath.Rms(s.Slice(o, Math.Min(block, s.Length - o))));
        var peak = AudioMath.Peak(s);
        var levelDb = AudioMath.ToDbfs(loudest);
        var peakDb = AudioMath.ToDbfs(peak);
        return new(Math.Round(levelDb, 1), Math.Round(peakDb, 1), peak == 0, peakDb >= ToneAnalyzer.ClipDbfs);
    }

    /// <summary>A microphone's result from its recording: no signal (Failed), very low (Warning, speak closer), clipping (Warning) or OK.</summary>
    public static AudioDeviceRow Judge(AudioDeviceRow row, MicLevel level, bool privacyBlocked)
    {
        row = row with { LevelDbfs = level.LevelDbfs, PeakDbfs = level.PeakDbfs };
        if (privacyBlocked && level.DigitalSilence)
            return row with { Outcome = AudioDeviceOutcome.Failed, Result = "Blocked by privacy settings", Hint = AudioVerdicts.PrivacyMessage };
        if (level.LevelDbfs < NoSignalDbfs)
            return row with
            {
                Outcome = AudioDeviceOutcome.Failed, Result = NoSignal,
                Hint = row.Muted == true ? "It's muted. Unmute it and record again."
                    : row.Volume is { } v && v < LowInputVolume ? "Its level is very low. Raise it and record again."
                    : "Nothing was picked up. Check the cable or switch on the headset, and that no other app holds the microphone.",
            };
        if (level.LevelDbfs < LowLevelDbfs)
            return row with { Outcome = AudioDeviceOutcome.Warning, Result = "Very low level", Hint = "Speak closer to the microphone, or raise its level." };
        if (level.Clipped)
            return row with { Outcome = AudioDeviceOutcome.Warning, Result = "Too loud (clipping)", Hint = "Speak a little further away, or lower its level." };
        return row with { Outcome = AudioDeviceOutcome.Passed, Result = "Picked up sound", Hint = null };
    }

    /// <summary>An output's result from what the person heard.</summary>
    public static AudioDeviceRow Answer(AudioDeviceRow row, SoundCheckAnswer heard)
    {
        var mono = row.Channels == 1;
        return heard switch
        {
            SoundCheckAnswer.Both => row with { Heard = heard, Outcome = AudioDeviceOutcome.Passed, Result = mono ? "Heard (one channel)" : "Heard on both sides", Hint = null },
            SoundCheckAnswer.OnlyLeft => row with { Heard = heard, Outcome = AudioDeviceOutcome.Failed, Result = "Only the left side was heard",
                Hint = "The right speaker, earbud or cable may be faulty, or the balance may be set. The Sound check pane lists the balance fix." },
            SoundCheckAnswer.OnlyRight => row with { Heard = heard, Outcome = AudioDeviceOutcome.Failed, Result = "Only the right side was heard",
                Hint = "The left speaker, earbud or cable may be faulty, or the balance may be set. The Sound check pane lists the balance fix." },
            _ => row with { Heard = heard, Outcome = AudioDeviceOutcome.Failed, Result = "Not heard",
                Hint = row.Muted == true ? "It's muted. Unmute it and play again."
                    : row.Volume is { } v && v < LowOutputVolume ? "Its volume is very low. Raise it and play again."
                    : row.Kind.StartsWith("HDMI", StringComparison.Ordinal) ? "Check the monitor or TV has speakers and its own volume is up."
                    : "Use Can't hear sound on the Sound check pane to find the cause." },
        };
    }

    /// <summary>The test's verdict: any device Failed is Failed, any Warning is Warning, devices left to test is Warning (waiting), else Passed.</summary>
    public static (DiagnosticStatus Status, string Message) Outcome(AudioDevicesReport r)
    {
        var testable = r.Devices.Count(d => d.Testable);
        if (r.Devices.Count == 0) return (DiagnosticStatus.Error, r.Notice ?? "No speakers or microphones were found.");
        if (testable == 0) return (DiagnosticStatus.Error, "No speaker or microphone is turned on and connected. Turn one on or plug one in.");
        var failed = r.Devices.Where(d => d.Outcome == AudioDeviceOutcome.Failed).ToList();
        var warned = r.Devices.Where(d => d.Outcome == AudioDeviceOutcome.Warning).ToList();
        var left = r.Untested;
        string Names(IEnumerable<AudioDeviceRow> rows) => string.Join(", ", rows.Select(d => d.Name));
        if (failed.Count > 0) return (DiagnosticStatus.Error, $"{AreaModuleBase.Plural(failed.Count, "device")} failed: {Names(failed)}.");
        if (warned.Count > 0) return (DiagnosticStatus.Warning, $"{AreaModuleBase.Plural(warned.Count, "device")} need a look: {Names(warned)}.");
        if (left > 0)
            return (DiagnosticStatus.Warning, r.Tested == 0
                ? $"{AreaModuleBase.Plural(testable, "device")} to test. Play each speaker and record each microphone."
                : $"{r.Tested} of {testable} devices tested. {AreaModuleBase.Plural(left, "device")} left.");
        return (DiagnosticStatus.Ok, $"Passed: all {AreaModuleBase.Plural(r.Tested, "speaker and microphone", "speakers and microphones")} worked.");
    }

    public static DiagnosticResult ToResult(AudioDevicesReport r)
    {
        var (status, msg) = Outcome(r);
        return new DiagnosticResult<AudioDevicesReport>(ModuleSlugs.AudioDevices, status, msg, DateTimeOffset.Now, r);
    }

    public static AudioDevicesReport Replace(AudioDevicesReport r, AudioDeviceRow row) =>
        r with { Devices = r.Devices.Select(d => d.Id == row.Id ? row : d).ToList() };
}

/// <summary>The per-device sound test as the Interactive tests page drives it (the module lives in its own DLL).</summary>
public interface IAudioDevicesTestModule : IAudioTestModule
{
    /// <summary>The device being played or recorded now; null when idle.</summary>
    string? BusyId { get; }
    /// <summary>The live microphone level while recording (dBFS), for the meter.</summary>
    double LiveLevelDbfs { get; }
    /// <summary>Raised on each meter update while recording (on the capture thread).</summary>
    event Action? LevelChanged;
    AudioDevicesReport Report { get; }
    bool HasRecording(string inputId);
    Task<DiagnosticResult> PlayAsync(string outputId, CancellationToken cancellationToken = default);
    DiagnosticResult? Answer(string outputId, SoundCheckAnswer heard);
    Task<DiagnosticResult> RecordAsync(string inputId, CancellationToken cancellationToken = default);
    Task<DiagnosticResult> PlayBackAsync(string inputId, string? outputId = null, CancellationToken cancellationToken = default);
    DiagnosticResult Reset();
}
