namespace RemotePCDiagnostics.Core.Audio;

/// <summary>
/// Plays a short chime on the left channel of the speaker, then the right. Nothing is measured: the person says what they heard
/// (<see cref="SoundCheck.Answer"/>), like the webcam's Pass/Fail. Mute and volume are left as they are, so a muted speaker stays the
/// finding (the "Can't hear sound" list shows it with its fix).
/// </summary>
public sealed class SoundCheckModule(IAudioIo io, ILogger? log = null, IAudioStateSource? state = null) : AudioModuleBase(io, log, state)
{
    public const int SampleRate = 48000;

    public override string Name => ModuleSlugs.SoundCheck;
    public override Guid Id => ModuleIds.SoundCheck;
    public override string DisplayName => "Sound check (left and right)";

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var output = Pick(AudioFlow.Output, Settings.OutputId);
        if (output is null)
            return new DiagnosticResult(Name, DiagnosticStatus.Error, "No speaker or headphones were found. Use Can't hear sound to find out why.", DateTimeOffset.Now);
        if (await PreCheckAsync(output, null, ct).ConfigureAwait(false) is { } blocked)
        {
            Log($"{Name}: pre-check stopped the test: {blocked}");
            return new DiagnosticResult(Name, DiagnosticStatus.Error, blocked, DateTimeOffset.Now, new SoundCheckReport(output.Name, 0, null, blocked));
        }
        var chime = SoundCheck.Chime(SampleRate);
        var channels = 0;
        try
        {
            foreach (var side in new[] { AudioChannel.Left, AudioChannel.Right })
            {
                progress?.Report(side == AudioChannel.Left ? "Playing on the left…" : "Playing on the right…");
                channels = await Io.PlayOnChannelAsync(new PlayChannelRequest(output.Id, chime, SampleRate, side), ct).ConfigureAwait(false);
                if (side == AudioChannel.Left) await Task.Delay(SoundCheck.Gap, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return Fail(ex, null); }
        Log($"{Name}: played left and right on '{output.Name}' ({channels} channels)");
        var notice = channels == 1 ? "This speaker has one channel, so the sound played the same both times." : null;
        return SoundCheck.ToResult(new SoundCheckReport(output.Name, channels, null, notice));
    }
}
