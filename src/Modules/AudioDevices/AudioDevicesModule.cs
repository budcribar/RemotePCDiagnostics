namespace RemotePCDiagnostics.Core.Audio;

/// <summary>
/// The per-device sound test (Interactive tests page): lists every speaker and microphone with its state, plays the left/right chime on any
/// output (the person answers), records 3 s from any microphone and judges the level, and plays a recording back. Mute and levels are left
/// as they are, so a muted device stays the finding and its fix button shows on the row. Nothing runs unless the person presses a button.
/// </summary>
public sealed class AudioDevicesModule(IAudioIo io, ILogger? log = null, IAudioStateSource? state = null) : AudioModuleBase(io, log, state), IAudioDevicesTestModule
{
    public const int SampleRate = 48000;
    private readonly Dictionary<string, RecordResult> _recordings = new(StringComparer.Ordinal);
    private AudioDevicesReport _report = new([]);
    private string? _busyId;

    public override string Name => ModuleSlugs.AudioDevices;
    public override Guid Id => ModuleIds.AudioDevices;
    public override string DisplayName => AudioDevicesTest.DisplayName;

    /// <summary>The device being played or recorded now; null when idle.</summary>
    public string? BusyId => Volatile.Read(ref _busyId);
    /// <summary>The live microphone level while recording (dBFS), for the meter.</summary>
    public double LiveLevelDbfs { get; private set; } = AudioMath.SilenceDbfs;
    /// <summary>Raised on each meter update while recording (on the capture thread).</summary>
    public event Action? LevelChanged;

    public AudioDevicesReport Report => _report;
    public bool HasRecording(string inputId) { lock (_recordings) return _recordings.ContainsKey(inputId); }

    /// <summary>Reads the device list (keeping results of devices still present). Plays and records nothing.</summary>
    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Reading the sound devices…");
        AudioDevicesReport report;
        var s = StateSource is null ? null : await SafeReadAsync(ct).ConfigureAwait(false);
        if (s is { Available: true }) report = AudioDevicesTest.Build(s, _report);
        else
        {
            var plain = Io.ListDevices();
            report = AudioDevicesTest.FromDevices(plain, plain.Count == 0 ? s?.Error : "Only the connected devices are listed: their state couldn't be read.");
        }
        _report = report;
        Log($"{Name}: {report.Outputs.Count()} outputs, {report.Inputs.Count()} inputs, {report.Untested} to test");
        return AudioDevicesTest.ToResult(report);
    }

    private async Task<AudioState?> SafeReadAsync(CancellationToken ct)
    {
        try { return await StateSource!.ReadAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"{Name}: device read failed: {ex.Message}"); return null; }
    }

    private AudioDeviceRow? Find(string id) => _report.Devices.FirstOrDefault(d => d.Id == id);

    private DiagnosticResult Publish(AudioDeviceRow row)
    {
        _report = AudioDevicesTest.Replace(_report, row);
        var r = AudioDevicesTest.ToResult(_report);
        Raise(r);
        return r;
    }

    private DiagnosticResult Running(string message)
    {
        var r = new DiagnosticResult<AudioDevicesReport>(Name, DiagnosticStatus.Running, message, DateTimeOffset.Now, _report);
        Raise(r);
        return r;
    }

    /// <summary>Plays the chime on the left, then the right, of one output. The row then waits for the person's answer.</summary>
    public async Task<DiagnosticResult> PlayAsync(string outputId, CancellationToken cancellationToken = default)
    {
        if (Find(outputId) is not { Flow: AudioFlow.Output, Testable: true } row) return AudioDevicesTest.ToResult(_report);
        if (Interlocked.CompareExchange(ref _busyId, outputId, null) is not null) return AudioDevicesTest.ToResult(_report);
        try
        {
            return await RunGuardedAsync(async ct =>
            {
                if (await PreCheckAsync(new AudioDevice(row.Id, row.Name, AudioFlow.Output, AudioBus.Unknown, row.IsDefault), null, ct).ConfigureAwait(false) is { } blocked)
                    return Publish(row with { Outcome = AudioDeviceOutcome.Failed, Result = "Couldn't play", Hint = blocked, Heard = null, Channels = null });
                try
                {
                    var chime = SoundCheck.Chime(SampleRate);
                    var channels = 0;
                    foreach (var side in new[] { AudioChannel.Left, AudioChannel.Right })
                    {
                        Running(side == AudioChannel.Left ? $"Playing on the left of {row.Name}…" : $"Playing on the right of {row.Name}…");
                        channels = await Io.PlayOnChannelAsync(new PlayChannelRequest(outputId, chime, SampleRate, side), ct).ConfigureAwait(false);
                        if (side == AudioChannel.Left) await Task.Delay(SoundCheck.Gap, ct).ConfigureAwait(false);
                    }
                    Log($"{Name}: played left and right on '{row.Name}' ({channels} channels)");
                    return Publish(row with { Channels = channels, Heard = null, Outcome = AudioDeviceOutcome.NotTested, Result = "Waiting for answer",
                        Hint = channels == 1 ? "This device has one channel, so the sound played the same both times." : null });
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    LogWarn($"{Name}: playing on '{row.Name}' failed: {ex.Message}");
                    return Publish(row with { Outcome = AudioDeviceOutcome.Failed, Result = "Couldn't play", Hint = ex is AudioDeviceException ? $"Couldn't use it: {ex.Message}." : "Couldn't play the test sound on it." });
                }
            }, cancellationToken).ConfigureAwait(false);
        }
        finally { Volatile.Write(ref _busyId, null); }
    }

    /// <summary>Records what the person heard on one output; null when it wasn't played.</summary>
    public DiagnosticResult? Answer(string outputId, SoundCheckAnswer heard)
    {
        if (Find(outputId) is not { Flow: AudioFlow.Output, Channels: not null } row) return null;
        Log($"{Name}: '{row.Name}' answer {heard}");
        return Publish(AudioDevicesTest.Answer(row, heard));
    }

    /// <summary>Records 3 s from one microphone and judges the level (no signal, very low, clipping, OK).</summary>
    public async Task<DiagnosticResult> RecordAsync(string inputId, CancellationToken cancellationToken = default)
    {
        if (Find(inputId) is not { Flow: AudioFlow.Input, Testable: true } row) return AudioDevicesTest.ToResult(_report);
        if (Interlocked.CompareExchange(ref _busyId, inputId, null) is not null) return AudioDevicesTest.ToResult(_report);
        LiveLevelDbfs = AudioMath.SilenceDbfs;
        try
        {
            return await RunGuardedAsync(async ct =>
            {
                if (await PreCheckAsync(null, new AudioDevice(row.Id, row.Name, AudioFlow.Input, AudioBus.Unknown, row.IsDefault), ct).ConfigureAwait(false) is { } blocked)
                {
                    lock (_recordings) _recordings.Remove(inputId);
                    return Publish(row with { Outcome = AudioDeviceOutcome.Failed, Result = "Couldn't record", Hint = blocked, LevelDbfs = null, PeakDbfs = null });
                }
                var privacy = false;
                try { privacy = Io.IsMicrophoneBlockedByPrivacy(); } catch { }
                try
                {
                    Running($"Recording from {row.Name}: say a few words…");
                    var rec = await Io.RecordAsync(new RecordRequest(inputId, AudioDevicesTest.RecordLength, db => { LiveLevelDbfs = db; LevelChanged?.Invoke(); }), ct).ConfigureAwait(false);
                    lock (_recordings) _recordings[inputId] = rec;
                    var level = AudioDevicesTest.Measure(rec.Samples, rec.SampleRate);
                    var judged = AudioDevicesTest.Judge(row, level, privacy);
                    Log($"{Name}: '{row.Name}' level={level.LevelDbfs:0.0} peak={level.PeakDbfs:0.0} silent={level.DigitalSilence} -> {judged.Outcome}");
                    return Publish(judged);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    LogWarn($"{Name}: recording from '{row.Name}' failed: {ex.Message}");
                    lock (_recordings) _recordings.Remove(inputId);
                    var denied = IsAccessDenied(ex) || privacy;
                    return Publish(row with { Outcome = AudioDeviceOutcome.Failed, Result = denied ? "Blocked by privacy settings" : "Couldn't record",
                        Hint = denied ? AudioVerdicts.PrivacyMessage : ex is AudioDeviceException ? $"Couldn't use it: {ex.Message}." : "Couldn't record from it.",
                        LevelDbfs = null, PeakDbfs = null });
                }
            }, cancellationToken).ConfigureAwait(false);
        }
        finally { Volatile.Write(ref _busyId, null); LiveLevelDbfs = AudioMath.SilenceDbfs; LevelChanged?.Invoke(); }
    }

    /// <summary>Plays a microphone's last recording on <paramref name="outputId"/> (null = the Windows default). Doesn't change the result.</summary>
    public async Task<DiagnosticResult> PlayBackAsync(string inputId, string? outputId = null, CancellationToken cancellationToken = default)
    {
        RecordResult? rec;
        lock (_recordings) _recordings.TryGetValue(inputId, out rec);
        if (rec is null || Find(inputId) is not { } row) return AudioDevicesTest.ToResult(_report);
        if (Interlocked.CompareExchange(ref _busyId, inputId, null) is not null) return AudioDevicesTest.ToResult(_report);
        try
        {
            return await RunGuardedAsync(async ct =>
            {
                try
                {
                    Running($"Playing back the recording from {row.Name}…");
                    await Io.PlaySamplesAsync(new PlaySamplesRequest(outputId, rec.Samples, rec.SampleRate), ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"{Name}: play back failed: {ex.Message}"); }
                var r = AudioDevicesTest.ToResult(_report);
                Raise(r);
                return r;
            }, cancellationToken).ConfigureAwait(false);
        }
        finally { Volatile.Write(ref _busyId, null); }
    }

    /// <summary>Clears every device's result (the list stays).</summary>
    public DiagnosticResult Reset()
    {
        lock (_recordings) _recordings.Clear();
        _report = _report with
        {
            Devices = _report.Devices.Select(d => d.Testable
                ? d with { Outcome = AudioDeviceOutcome.NotTested, Result = AudioDevicesTest.NotTested, Heard = null, Channels = null, LevelDbfs = null, PeakDbfs = null }
                : d).ToList(),
        };
        var r = AudioDevicesTest.ToResult(_report);
        Raise(r);
        return r;
    }
}
