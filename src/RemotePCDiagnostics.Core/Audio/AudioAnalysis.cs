namespace RemotePCDiagnostics.Core.Audio;

/// <summary>Pure audio maths for the speaker/microphone tests (no hardware, unit-testable).</summary>
public static class AudioMath
{
    /// <summary>Hard cap for any generated tone: about -12 dBFS.</summary>
    public const double MaxToneDbfs = -12;
    /// <summary>Hard cap for the mic-to-speaker monitor gain (linear; 0.5 = -6 dB).</summary>
    public const float MaxMonitorGain = 0.5f;
    public const double SilenceDbfs = -120;

    public static double MaxToneAmplitude => FromDbfs(MaxToneDbfs);
    public static double FromDbfs(double db) => Math.Pow(10, db / 20);
    public static double ToDbfs(double linear) => linear <= 1e-6 ? SilenceDbfs : Math.Max(SilenceDbfs, 20 * Math.Log10(linear));

    public static float ClampMonitorGain(float gain) => float.IsNaN(gain) ? 0 : Math.Clamp(gain, 0f, MaxMonitorGain);

    public static double Rms(ReadOnlySpan<float> s)
    {
        if (s.IsEmpty) return 0;
        double sum = 0;
        foreach (var v in s) sum += (double)v * v;
        return Math.Sqrt(sum / s.Length);
    }

    public static double Peak(ReadOnlySpan<float> s)
    {
        double p = 0;
        foreach (var v in s) { var a = Math.Abs(v); if (a > p) p = a; }
        return p;
    }

    /// <summary>Amplitude (0..1 peak) of the <paramref name="frequency"/> component, via the Goertzel algorithm.</summary>
    public static double GoertzelAmplitude(ReadOnlySpan<float> s, int sampleRate, double frequency)
    {
        if (s.IsEmpty || sampleRate <= 0) return 0;
        var w = 2 * Math.PI * frequency / sampleRate;
        var coeff = 2 * Math.Cos(w);
        double q1 = 0, q2 = 0;
        foreach (var x in s) { var q0 = coeff * q1 - q2 + x; q2 = q1; q1 = q0; }
        var re = q1 - q2 * Math.Cos(w);
        var im = q2 * Math.Sin(w);
        return 2 * Math.Sqrt(re * re + im * im) / s.Length;
    }

    /// <summary>Gain (0..1) of the raised-cosine fade at sample <paramref name="i"/> of <paramref name="total"/>.</summary>
    public static double FadeGain(int i, int total, int fadeSamples)
    {
        if (fadeSamples <= 0 || total <= 0) return 1;
        fadeSamples = Math.Min(fadeSamples, total / 2);
        if (fadeSamples <= 0) return 1;
        double g = 1;
        if (i < fadeSamples) g = 0.5 - 0.5 * Math.Cos(Math.PI * i / fadeSamples);
        var fromEnd = total - 1 - i;
        if (fromEnd < fadeSamples) g = Math.Min(g, 0.5 - 0.5 * Math.Cos(Math.PI * fromEnd / fadeSamples));
        return g;
    }

    /// <summary>Mono sine tone with fade-in/out. The level is capped at <see cref="MaxToneDbfs"/> whatever is asked for.</summary>
    public static float[] GenerateTone(double frequency, int sampleRate, TimeSpan duration, double levelDbfs = MaxToneDbfs, TimeSpan? fade = null)
    {
        var n = Math.Max(0, (int)(duration.TotalSeconds * sampleRate));
        var amp = Math.Min(FromDbfs(levelDbfs), MaxToneAmplitude);
        var fadeN = (int)((fade ?? TimeSpan.FromMilliseconds(200)).TotalSeconds * sampleRate);
        var buf = new float[n];
        for (var i = 0; i < n; i++)
            buf[i] = (float)(amp * FadeGain(i, n, fadeN) * Math.Sin(2 * Math.PI * frequency * i / sampleRate));
        return buf;
    }

    /// <summary>Fade-in only (for monitor playback that starts abruptly).</summary>
    public static void ApplyFadeIn(Span<float> s, int fadeSamples)
    {
        for (var i = 0; i < Math.Min(fadeSamples, s.Length); i++) s[i] *= (float)(0.5 - 0.5 * Math.Cos(Math.PI * i / fadeSamples));
    }
}

/// <summary>Level and tone measurement of one recording.</summary>
public sealed record ToneMeasurement(double PeakDbfs, double RmsDbfs, double ToneDbfs, double NoiseDbfs, double SnrDb, bool ToneDetected, bool Clipped, bool DigitalSilence)
{
    public static ToneMeasurement Empty { get; } = new(AudioMath.SilenceDbfs, AudioMath.SilenceDbfs, AudioMath.SilenceDbfs, AudioMath.SilenceDbfs, 0, false, false, true);
}

public static class ToneAnalyzer
{
    /// <summary>Tone must be at least this far above the noise in its blocks.</summary>
    public const double MinSnrDb = 10;
    /// <summary>…and at least this loud (RMS of the tone component).</summary>
    public const double MinToneDbfs = -75;
    public const double ClipDbfs = -0.1;

    /// <summary>
    /// Splits the recording into 50 ms blocks, measures the tone (Goertzel) and the rest (noise) in each, and uses the loudest half
    /// of the blocks for the tone/noise levels, so lead-in silence and the fades do not dilute the result.
    /// </summary>
    public static ToneMeasurement Analyze(ReadOnlySpan<float> s, int sampleRate, double frequency)
    {
        if (s.IsEmpty || sampleRate <= 0) return ToneMeasurement.Empty;
        var peak = AudioMath.Peak(s);
        var rms = AudioMath.Rms(s);
        var block = Math.Max(16, sampleRate / 20);
        var blocks = new List<(double Tone, double Noise)>();
        for (var o = 0; o + block <= s.Length; o += block)
        {
            var b = s.Slice(o, block);
            var amp = AudioMath.GoertzelAmplitude(b, sampleRate, frequency);
            var toneRms = amp / Math.Sqrt(2);
            var total = AudioMath.Rms(b);
            var noise = Math.Sqrt(Math.Max(total * total - toneRms * toneRms, 1e-14));
            blocks.Add((toneRms, noise));
        }
        if (blocks.Count == 0) blocks.Add((AudioMath.GoertzelAmplitude(s, sampleRate, frequency) / Math.Sqrt(2), rms));
        var top = blocks.OrderByDescending(b => b.Tone).Take(Math.Max(1, blocks.Count / 2)).ToList();
        var tone = top.Average(b => b.Tone);
        var noiseRms = Math.Max(top.Average(b => b.Noise), 1e-7);
        var toneDb = AudioMath.ToDbfs(tone);
        var snr = 20 * Math.Log10(Math.Max(tone, 1e-9) / noiseRms);
        var silent = peak == 0;
        return new ToneMeasurement(AudioMath.ToDbfs(peak), AudioMath.ToDbfs(rms), toneDb, AudioMath.ToDbfs(noiseRms), Math.Round(snr, 1),
            !silent && snr >= MinSnrDb && toneDb >= MinToneDbfs, AudioMath.ToDbfs(peak) >= ClipDbfs, silent);
    }
}

public enum AudioVerdict
{
    /// <summary>Tone in the speaker output and heard by the microphone.</summary>
    Pass,
    /// <summary>Heard, but the microphone overloaded (clipping).</summary>
    PassClipped,
    /// <summary>Tone in the speaker output but not heard by the microphone.</summary>
    MicDidNotHear,
    /// <summary>Tone in neither recording: software, volume, mute or device problem.</summary>
    NoOutput,
    /// <summary>Microphone heard it, but the output capture did not (loopback problem only).</summary>
    PassLoopbackMissing,
    /// <summary>Output capture unavailable and the microphone did not hear it.</summary>
    NotHeardUnknownOutput,
    MicAccessDenied,
    NoDevice,
    Feedback,
}

public static class AudioVerdicts
{
    public const string PrivacyMessage = "Microphone access is blocked by Windows privacy settings (Settings > Privacy & security > Microphone).";

    /// <summary>The speaker-to-mic decision table. <paramref name="loopbackTone"/> null = output capture was not available.</summary>
    public static AudioVerdict Decide(bool? loopbackTone, bool micTone, bool micClipped = false, bool micAccessDenied = false)
    {
        if (micAccessDenied) return AudioVerdict.MicAccessDenied;
        return (loopbackTone, micTone) switch
        {
            (true, true) => micClipped ? AudioVerdict.PassClipped : AudioVerdict.Pass,
            (true, false) => AudioVerdict.MicDidNotHear,
            (false, true) => AudioVerdict.PassLoopbackMissing,
            (false, false) => AudioVerdict.NoOutput,
            (null, true) => micClipped ? AudioVerdict.PassClipped : AudioVerdict.Pass,
            (null, false) => AudioVerdict.NotHeardUnknownOutput,
        };
    }

    public static DiagnosticStatus StatusOf(AudioVerdict v) => v switch
    {
        AudioVerdict.Pass or AudioVerdict.PassLoopbackMissing => DiagnosticStatus.Ok,
        AudioVerdict.PassClipped or AudioVerdict.NoDevice or AudioVerdict.Feedback => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };

    public static string MessageOf(AudioVerdict v) => v switch
    {
        AudioVerdict.Pass => "Passed: the speaker played the test tone and the microphone heard it.",
        AudioVerdict.PassClipped => "The microphone heard the test tone, but it was too loud for it (clipping). Lower the speaker volume or the microphone level and run again.",
        AudioVerdict.PassLoopbackMissing => "Passed: the microphone heard the test tone (the app couldn't confirm the speaker output directly).",
        AudioVerdict.MicDidNotHear => "Windows played the tone, but the microphone didn't pick it up. The speaker may be dead or muted, the volume too low, or the microphone muted or its level too low.",
        AudioVerdict.NoOutput => "The tone didn't reach the speaker output. Check the volume and mute, the selected output device and the audio driver.",
        AudioVerdict.NotHeardUnknownOutput => "The microphone didn't hear the test tone. Check the volume and mute, the selected devices and the microphone level.",
        AudioVerdict.MicAccessDenied => PrivacyMessage,
        AudioVerdict.NoDevice => "Skipped: no speaker or microphone was found on this PC.",
        AudioVerdict.Feedback => "Feedback detected (howling): the test was stopped. Try again with Half-duplex turned on, or lower the volume.",
        _ => v.ToString(),
    };
}

public enum HowlAction { None, Duck, Stop }

/// <summary>
/// Feedback ("howling") brake for live monitoring. Fed 10–50 ms blocks of the microphone signal:
/// stops when the peak stays above -3 dBFS for <see cref="SustainedLoud"/>, or when a strong narrowband (tone-like, low crest factor)
/// signal keeps growing; asks to duck the gain as soon as a loud tone-like signal appears.
/// </summary>
public sealed class HowlDetector
{
    public const double LoudPeakDbfs = -3;
    public static readonly TimeSpan SustainedLoud = TimeSpan.FromMilliseconds(250);
    /// <summary>A pure sine has a crest factor of 3 dB; speech and noise are well above 8 dB.</summary>
    public const double TonalCrestDb = 4.0;
    public const double TonalMinRmsDbfs = -30;
    public const double GrowthDb = 6;
    private const int GrowthBlocks = 5;

    private readonly int _sampleRate;
    private double _loudSeconds;
    private readonly Queue<double> _tonalRms = new();
    public bool FeedbackDetected { get; private set; }

    public HowlDetector(int sampleRate) => _sampleRate = Math.Max(1, sampleRate);

    public HowlAction Feed(ReadOnlySpan<float> block)
    {
        if (FeedbackDetected) return HowlAction.Stop;
        if (block.IsEmpty) return HowlAction.None;
        var peakDb = AudioMath.ToDbfs(AudioMath.Peak(block));
        var rmsDb = AudioMath.ToDbfs(AudioMath.Rms(block));
        var secs = (double)block.Length / _sampleRate;
        _loudSeconds = peakDb > LoudPeakDbfs ? _loudSeconds + secs : 0;
        if (_loudSeconds >= SustainedLoud.TotalSeconds) { FeedbackDetected = true; return HowlAction.Stop; }

        var tonal = rmsDb > TonalMinRmsDbfs && peakDb - rmsDb < TonalCrestDb;
        if (!tonal) { _tonalRms.Clear(); return HowlAction.None; }
        _tonalRms.Enqueue(rmsDb);
        while (_tonalRms.Count > GrowthBlocks) _tonalRms.Dequeue();
        if (_tonalRms.Count == GrowthBlocks)
        {
            var arr = _tonalRms.ToArray();
            var rising = true;
            for (var i = 1; i < arr.Length; i++) if (arr[i] < arr[i - 1]) { rising = false; break; }
            if (rising && arr[^1] - arr[0] >= GrowthDb) { FeedbackDetected = true; return HowlAction.Stop; }
        }
        return HowlAction.Duck;
    }
}

/// <summary>Per-block processing for live monitoring: meters the mic, runs the howl brake and returns the gain to play the block at.</summary>
public sealed class MonitorController
{
    private readonly HowlDetector _howl;
    private float _gain;
    private double _peak, _sumSq;
    private long _count;
    public MonitorController(int sampleRate, float gain) { _howl = new HowlDetector(sampleRate); _gain = AudioMath.ClampMonitorGain(gain); }

    public float CurrentGain => _gain;
    public bool FeedbackDetected => _howl.FeedbackDetected;
    public bool Ducked { get; private set; }
    public double PeakDbfs => AudioMath.ToDbfs(_peak);
    public double RmsDbfs => _count == 0 ? AudioMath.SilenceDbfs : AudioMath.ToDbfs(Math.Sqrt(_sumSq / _count));

    /// <summary>Returns the gain for this block (0 = stop playback now).</summary>
    public float Process(ReadOnlySpan<float> mic)
    {
        foreach (var v in mic) { var a = Math.Abs(v); if (a > _peak) _peak = a; _sumSq += (double)v * v; }
        _count += mic.Length;
        switch (_howl.Feed(mic))
        {
            case HowlAction.Stop: _gain = 0; break;
            case HowlAction.Duck: _gain = Math.Max(0.05f, _gain * 0.5f); Ducked = true; break;
        }
        return _gain;
    }
}
