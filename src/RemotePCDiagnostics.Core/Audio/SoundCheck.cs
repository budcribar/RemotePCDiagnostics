using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Audio;

/// <summary>What the person heard when the test sound played on the left, then the right.</summary>
public enum SoundCheckAnswer { Both, OnlyLeft, OnlyRight, Nothing }

/// <param name="Output">The speaker the sound played on.</param>
/// <param name="Channels">The speaker's channel count; 1 = it can't play left and right separately.</param>
/// <param name="Answer">What the person heard; null until they answer.</param>
public sealed record SoundCheckReport(string Output, int Channels, SoundCheckAnswer? Answer, string? Notice = null)
{
    public bool OneSide => Answer is SoundCheckAnswer.OnlyLeft or SoundCheckAnswer.OnlyRight;
}

/// <summary>One thing to try in the "Can't hear sound" list: a Sound check row (with its fix buttons) and the card it came from.</summary>
public sealed record SoundCheckStep(string CardId, AreaRow Row)
{
    public string Title => Row.Values.Count > 0 ? Row.Values[0] : "";
    public string Text => string.Join(" · ", Row.Values.Skip(1).Where(v => !string.IsNullOrWhiteSpace(v) && v != "No issues found"));
}

/// <summary>
/// The interactive Sound check (Interactive tests page): its result for each answer, and the "Can't hear sound" list built from the Sound
/// check's own cards, so the same rows and the same fix buttons show in both places.
/// </summary>
public static class SoundCheck
{
    public const string OutputCard = "audio-output", ServicesCard = "audio-services";
    public const string WaitingMessage = "Did you hear the sound on the left, then the right? Choose what you heard.";

    /// <summary>The test sound: a short 880 Hz chime per side, at the capped test level.</summary>
    public const double ChimeHz = 880;
    public static readonly TimeSpan ChimeLength = TimeSpan.FromMilliseconds(700);
    public static readonly TimeSpan Gap = TimeSpan.FromMilliseconds(400);

    public static (DiagnosticStatus Status, string Message) Outcome(SoundCheckReport r) => r.Answer switch
    {
        SoundCheckAnswer.Both => (DiagnosticStatus.Ok, "Passed: the sound was heard on the left and the right."),
        SoundCheckAnswer.OnlyLeft => (DiagnosticStatus.Error, "Only the left side was heard. The right speaker, earbud or cable may be faulty, or the balance or mono audio may be set."),
        SoundCheckAnswer.OnlyRight => (DiagnosticStatus.Error, "Only the right side was heard. The left speaker, earbud or cable may be faulty, or the balance or mono audio may be set."),
        SoundCheckAnswer.Nothing => (DiagnosticStatus.Error, "No sound was heard. Use Can't hear sound to find the cause."),
        _ => (DiagnosticStatus.Warning, WaitingMessage),
    };

    public static DiagnosticResult ToResult(SoundCheckReport r)
    {
        var (status, msg) = Outcome(r);
        return new DiagnosticResult<SoundCheckReport>(ModuleSlugs.SoundCheck, status, msg, DateTimeOffset.Now, r);
    }

    /// <summary>The latest result with the person's answer; null when there's no played sound to answer for.</summary>
    public static DiagnosticResult? Answer(DiagnosticResult latest, SoundCheckAnswer answer) =>
        latest.Payload is SoundCheckReport r ? ToResult(r with { Answer = answer }) : null;

    /// <summary>
    /// The Sound check rows worth trying when nothing plays, in the order to try them: the Windows Audio services first, then the
    /// Speakers &amp; headphones card in its own order (default device, turned off, muted, volume, balance, busy, format, ...). A row is listed
    /// when it's a problem, or when it's information that comes with a fix (sound going to a monitor or a headset's call mode, mono audio).
    /// </summary>
    public static IReadOnlyList<SoundCheckStep> CantHearSteps(AreaReport sound)
    {
        var steps = new List<SoundCheckStep>();
        foreach (var id in new[] { ServicesCard, OutputCard })
        {
            if (sound.Cards.FirstOrDefault(c => c.Id == id) is not { } card) continue;
            foreach (var row in card.Rows)
                if (row.Level is AreaLevel.Warning or AreaLevel.Error || row.Level == AreaLevel.Neutral && row.Actions is { Count: > 0 })
                    steps.Add(new SoundCheckStep(id, row));
        }
        return steps;
    }

    /// <summary>The Windows Audio services card is fine (shown ticked at the top of the list).</summary>
    public static bool ServicesOk(AreaReport sound) => sound.Cards.FirstOrDefault(c => c.Id == ServicesCard) is { Level: AreaLevel.Ok or AreaLevel.Neutral };

    /// <summary>When only one side was heard: the default speaker's Balance and Mono audio rows, when the Sound check has them.</summary>
    public static IReadOnlyList<SoundCheckStep> OneSideSteps(AreaReport sound) =>
        sound.Cards.FirstOrDefault(c => c.Id == OutputCard) is { } card
            ? card.Rows.Where(r => r.Values.Count > 0 && r.Values[0] is "Balance" or "Mono audio").Select(r => new SoundCheckStep(OutputCard, r)).ToList()
            : [];

    /// <summary>Speaker to mic verdicts that point at "Can't hear sound".</summary>
    public static bool SuggestFor(AudioVerdict v) => v is AudioVerdict.NoOutput or AudioVerdict.MicDidNotHear or AudioVerdict.NotHeardUnknownOutput;

    /// <summary>The chime for one side: mono samples at <paramref name="sampleRate"/>.</summary>
    public static float[] Chime(int sampleRate) => AudioMath.GenerateTone(ChimeHz, sampleRate, ChimeLength, fade: TimeSpan.FromMilliseconds(60));
}
