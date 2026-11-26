using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Webcam;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Machine-readable state of the Interactive tests page (interactive-data), so an agent can coach the person at the PC through each
/// test. For every test it separates what RPCD measured (keys seen, patterns shown, frames, tone levels) from the verdict a person
/// entered, and says whether the test is waiting for the person. Interactive tests run only on the PC itself: an agent reads this and
/// talks the person through the steps; it never supplies the input.
/// </summary>
public static class InteractiveExport
{
    public const int SchemaVersion = 1;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>The page's own view: what this viewer can do and which test pane is open.</summary>
    public sealed record PageState(string SelectedTestId, IReadOnlyCollection<string> CheckedTestIds, bool BatchRunning,
        bool ThisViewerIsRemote, bool RemoteSessionActive, bool TechnicianHasControl);

    /// <summary>A module result and whether its current verdict was entered by a person (Pass/Fail buttons).</summary>
    public sealed record ModuleState(DiagnosticResult Result, bool PersonEntered);

    private static string? V(string? v) => AreaReportExport.Text(v, AreaReportExport.MaxValueLength);
    private static string? T(string? v) => AreaReportExport.Text(v, AreaReportExport.MaxTextLength);

    public static string ToJson(PageState page, PhysicalBenchQaSnapshot bench, ModuleState webcam, ModuleState speakerToMic, ModuleState micToSpeaker,
        ModuleState? soundCheck = null, SoundCheckHelp? help = null) =>
        JsonSerializer.Serialize(Build(page, bench, webcam, speakerToMic, micToSpeaker, soundCheck, help), Json);

    /// <summary>The Sound check pane's helper lists: what it shows and why (Can't hear sound, or only one side heard).</summary>
    /// <param name="Mode">"cant-hear", "one-side" or null when no list shows.</param>
    /// <param name="Steps">The Sound check rows listed, in order (title, text, level, and their fix kinds).</param>
    public sealed record SoundCheckHelp(string? Mode, bool Reading, IReadOnlyList<SoundCheckStep> Steps, bool ServicesOk);

    public static object Build(PageState page, PhysicalBenchQaSnapshot bench, ModuleState webcam, ModuleState speakerToMic, ModuleState micToSpeaker,
        ModuleState? soundCheck = null, SoundCheckHelp? help = null) => new
    {
        schema = SchemaVersion,
        selectedTestId = page.SelectedTestId,
        batchRunning = page.BatchRunning,
        thisViewerIsRemote = page.ThisViewerIsRemote,
        remoteSessionActive = page.RemoteSessionActive,
        technicianHasControl = page.TechnicianHasControl,
        // Only the person at the PC can run these tests; a remote viewer in control must hand control back first.
        personCanRunTests = !page.TechnicianHasControl || !page.RemoteSessionActive,
        tests = new object[]
        {
            KeyboardTest(page, bench),
            DisplayTest(page, bench),
            WebcamTest(page, webcam),
            SpeakerToMicTest(page, speakerToMic),
            MicToSpeakerTest(page, micToSpeaker),
            SoundCheckTest(page, soundCheck ?? new ModuleState(DiagnosticResult.NotRun(ModuleSlugs.SoundCheck), false), help),
        },
    };

    private static string Physical(PhysicalCheckOutcome o) => o switch
    {
        PhysicalCheckOutcome.Passed => "passed",
        PhysicalCheckOutcome.PassedWithNote => "passed-with-note",
        PhysicalCheckOutcome.Failed => "failed",
        _ => "notrun",
    };

    private static string Person(DiagnosticStatus s) => s switch
    {
        DiagnosticStatus.Ok => "passed",
        DiagnosticStatus.Warning => "passed-with-note",
        DiagnosticStatus.Error => "failed",
        _ => "notrun",
    };

    private static object KeyboardTest(PageState page, PhysicalBenchQaSnapshot b) => new
    {
        id = "keyboard",
        name = "Keyboard",
        @checked = page.CheckedTestIds.Contains("keyboard"),
        open = page.SelectedTestId == "keyboard",
        state = b.KeyboardOutcome != PhysicalCheckOutcome.NotRun ? "done" : b.UniqueKeysPressed > 0 ? "in-progress" : "waiting-for-person",
        measured = new { uniqueKeysPressed = b.UniqueKeysPressed, peakKeyRollover = b.PeakKeyRollover },
        personOutcome = b.KeyboardOutcome == PhysicalCheckOutcome.NotRun ? null : Physical(b.KeyboardOutcome),
        notes = T(b.KeyboardNotes),
        instructions = "Open the keyboard test, choose the matching layout, click Capture keys, then press every key once and a few keys "
            + "together to check rollover. Keys light up as they register. Then choose Pass keyboard, Pass with note or Fail keyboard.",
        reportIf = ReportIf.Keyboard,
    };

    private static object DisplayTest(PageState page, PhysicalBenchQaSnapshot b) => new
    {
        id = "display",
        name = "Display and touch",
        @checked = page.CheckedTestIds.Contains("display"),
        open = page.SelectedTestId == "display",
        state = b.DisplayOutcome != PhysicalCheckOutcome.NotRun ? "done" : b.SolidColorsInspected > 0 ? "in-progress" : "waiting-for-person",
        measured = new { solidColorsInspected = b.SolidColorsInspected, maxTouchPoints = b.MaxTouchPoints },
        personOutcome = b.DisplayOutcome == PhysicalCheckOutcome.NotRun ? null : Physical(b.DisplayOutcome),
        notes = T(b.DisplayNotes),
        instructions = "Launch the full-screen test, step through each solid colour looking for dead or stuck pixels, bleed and blemishes, "
            + "and touch the screen with several fingers if it is a touch screen. Then Pass & exit, or choose Note blemish or Fail display.",
        reportIf = ReportIf.Display,
    };

    private static object WebcamTest(PageState page, ModuleState m)
    {
        var r = m.Result;
        var rep = r.Payload as WebcamReport;
        return new
        {
            id = "webcam",
            name = "Webcam",
            @checked = page.CheckedTestIds.Contains("webcam"),
            open = page.SelectedTestId == "webcam",
            state = r.Status == DiagnosticStatus.Running ? "running" : m.PersonEntered ? "done"
                : rep is not null ? "waiting-for-person-verdict" : "waiting-for-person",
            runId = r.RunId,
            device = V(rep?.Device),
            measured = rep is null ? null : new
            {
                verdict = rep.Verdict.ToString(),
                width = rep.Width,
                height = rep.Height,
                fps = Math.Round(rep.Stats.Fps, 1),
                frames = rep.Stats.Frames,
                meanBrightness = Math.Round(rep.Stats.MeanBrightness, 1),
                blackFraction = Math.Round(rep.Stats.BlackFraction, 3),
                frozenFraction = Math.Round(rep.Stats.FrozenFraction, 3),
                stalls = rep.Stats.Stalls,
                notice = T(rep.Notice),
            },
            personOutcome = m.PersonEntered ? Person(r.Status) : null,
            message = T(r.Message),
            instructions = "Choose the camera and length, then Start camera test. Look at the live preview on the PC: is the picture clear, "
                + "correctly exposed and smooth? RPCD measures frames and brightness; the person decides. Then Pass camera, Pass with note or Fail camera.",
            reportIf = ReportIf.Webcam,
        };
    }

    private static object SpeakerToMicTest(PageState page, ModuleState m)
    {
        var r = m.Result;
        var rep = r.Payload as SpeakerToMicReport;
        return new
        {
            id = "speakertomic",
            name = "Speaker to microphone",
            @checked = page.CheckedTestIds.Contains("speakertomic"),
            open = page.SelectedTestId == "speakertomic",
            state = r.Status == DiagnosticStatus.Running ? "running" : m.PersonEntered ? "done"
                : rep is not null ? "waiting-for-person-verdict" : "waiting-for-person",
            runId = r.RunId,
            output = V(rep?.Output),
            input = V(rep?.Input),
            measured = rep is null ? null : new
            {
                verdict = rep.Verdict.ToString(),
                frequencyHz = rep.FrequencyHz,
                toneDetected = rep.Mic.ToneDetected,
                micToneDbfs = Math.Round(rep.Mic.ToneDbfs, 1),
                snrDb = Math.Round(rep.Mic.SnrDb, 1),
                clipped = rep.Mic.Clipped,
                halfDuplex = rep.HalfDuplex,
                notice = T(rep.Notice),
            },
            personOutcome = m.PersonEntered ? Person(r.Status) : null,
            message = T(r.Message),
            instructions = "Turn the volume up and keep the room quiet. Choose the speaker and microphone, then start the test: RPCD plays a "
                + "tone and listens for it. The person confirms they heard the tone, then Pass audio, Pass with note or Fail audio.",
            reportIf = ReportIf.SpeakerToMic,
        };
    }

    private static object MicToSpeakerTest(PageState page, ModuleState m)
    {
        var r = m.Result;
        var rep = r.Payload as MicToSpeakerReport;
        return new
        {
            id = "mictospeaker",
            name = "Microphone to speaker",
            @checked = page.CheckedTestIds.Contains("mictospeaker"),
            open = page.SelectedTestId == "mictospeaker",
            state = r.Status == DiagnosticStatus.Running ? "running"
                : m.PersonEntered || rep?.HeardByListener is not null ? "done"
                : rep is not null ? "waiting-for-person-verdict" : "waiting-for-person",
            runId = r.RunId,
            output = V(rep?.Output),
            input = V(rep?.Input),
            measured = rep is null ? null : new
            {
                micPeakDbfs = Math.Round(rep.MicPeakDbfs, 1),
                micRmsDbfs = Math.Round(rep.MicRmsDbfs, 1),
                micHeardSomething = rep.MicHeardSomething,
                feedbackDetected = rep.FeedbackDetected,
                gainReduced = rep.GainReduced,
                notice = T(rep.Notice),
            },
            heardByListener = rep?.HeardByListener,
            personOutcome = m.PersonEntered || rep?.HeardByListener is not null ? Person(r.Status) : null,
            message = T(r.Message),
            instructions = "Choose the microphone and speaker, then start the test and talk or tap near the microphone: the sound plays back "
                + "through the speaker. RPCD measures the microphone level; the person says whether they heard it (Heard it / Didn't hear it).",
            reportIf = ReportIf.MicToSpeaker,
        };
    }

    private static object SoundCheckTest(PageState page, ModuleState m, SoundCheckHelp? help)
    {
        var r = m.Result;
        var rep = r.Payload as SoundCheckReport;
        return new
        {
            id = "soundcheck",
            name = "Sound check (left and right)",
            @checked = page.CheckedTestIds.Contains("soundcheck"),
            open = page.SelectedTestId == "soundcheck",
            state = r.Status == DiagnosticStatus.Running ? "running" : rep?.Answer is not null || m.PersonEntered ? "done"
                : rep is not null ? "waiting-for-person-verdict" : "waiting-for-person",
            runId = r.RunId,
            output = V(rep?.Output),
            measured = rep is null ? null : new { channels = rep.Channels, notice = T(rep.Notice) },
            heard = rep?.Answer switch
            {
                SoundCheckAnswer.Both => "both", SoundCheckAnswer.OnlyLeft => "only-left", SoundCheckAnswer.OnlyRight => "only-right",
                SoundCheckAnswer.Nothing => "nothing", _ => null,
            },
            personOutcome = rep?.Answer is not null || m.PersonEntered ? Person(r.Status) : null,
            message = T(r.Message),
            help = help is null || help.Mode is null ? null : new
            {
                mode = help.Mode,
                reading = help.Reading,
                servicesOk = help.ServicesOk,
                steps = help.Steps.Select(s => new
                {
                    card = s.CardId,
                    key = s.Row.Key,
                    title = V(s.Title),
                    text = V(s.Text),
                    level = s.Row.Level.ToString().ToLowerInvariant(),
                    fixes = s.Row.Actions?.Select(a => new { kind = a.Kind.ToString(), button = V(a.ButtonText), target = a.Target }).ToList(),
                }).ToList(),
            },
            instructions = "Choose the speaker, then Play test sound: a chime plays on the left, then the right. The person says what they "
                + "heard (Heard both, Only left, Only right, Nothing). Only one side lists the balance and mono audio; Nothing, or Can't hear "
                + "sound, lists the Sound check problems in the order to fix them, with their fix buttons.",
            reportIf = ReportIf.SoundCheck,
        };
    }

    /// <summary>
    /// When an agent coaching a test should report a learning (Admin's report_learning tool): the test's instructions or screen did not
    /// match what the person has. One line each, written for the agent, not the person.
    /// </summary>
    public static class ReportIf
    {
        public const string Keyboard = "The person's keyboard does not match any layout offered (for example AZERTY, Japanese, a compact "
            + "laptop or a keyboard with extra keys), keys they press do not light up, or they cannot find a key the test asks for.";
        public const string Display = "The full-screen test does not open on the screen the person is using, does not cover it, cannot be "
            + "exited, or touch does not register on a touch screen.";
        public const string Webcam = "The camera the person uses is not listed, the preview never appears, or the measured result disagrees "
            + "with what the person sees.";
        public const string SpeakerToMic = "The person's speaker or microphone is not listed, they hear the tone but it is not detected, or "
            + "the test cannot start.";
        public const string SoundCheck = "The person hears the chime on the wrong side, hears nothing although the Can't hear sound list is "
            + "empty, or the list shows a problem the person doesn't have.";
        public const string MicToSpeaker = "The person's microphone or speaker is not listed, there is no playback, or feedback makes the test "
            + "unusable.";
    }
}
