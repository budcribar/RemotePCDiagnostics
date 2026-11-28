using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Input;
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
    /// <summary>Formats listed per camera in the export (the best ones; the count is in capability.formatCount).</summary>
    public const int MaxWebcamFormats = 16;

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
        ModuleState? soundCheck = null, SoundCheckHelp? help = null, DiagnosticResult? wifi = null, WifiPane? wifiPane = null,
        DiagnosticResult? ethernet = null, EthernetPane? ethernetPane = null, DiagnosticResult? charger = null, UsbPortCheckState? usbPortCheck = null,
        ModuleState? audioDevices = null, string? audioDevicesBusyId = null, PointerTestSnapshot? pointer = null, DisplayOutputCheckState? displayOutputs = null) =>
        JsonSerializer.Serialize(Build(page, bench, webcam, speakerToMic, micToSpeaker, soundCheck, help, wifi, wifiPane, ethernet, ethernetPane, charger, usbPortCheck, audioDevices, audioDevicesBusyId, pointer, displayOutputs), Json);

    /// <summary>The display output check's result and what it has seen so far in the watch that is running (the result is Running meanwhile).</summary>
    public sealed record DisplayOutputCheckState(ModuleState Module, Display.DisplayOutputCheckReport Live);

    /// <summary>The USB port check's result and what it has seen so far in the watch that is running (the result is Running meanwhile).</summary>
    public sealed record UsbPortCheckState(ModuleState Module, Usb.UsbPortCheckReport Live);

    /// <summary>The Wi-Fi connect pane: the networks its picker lists, the one picked, and whether starting drops a remote session.</summary>
    /// <param name="PasswordTyped">Whether a password is typed (never the password itself).</param>
    public sealed record WifiPane(IReadOnlyList<WifiNetworkSeen> Networks, string? PickedSsid, bool PasswordTyped, bool DropsRemoteSession, bool Scanning);

    /// <summary>The Ethernet port pane: the wired ports its picker lists, the one picked, the mode, whether starting drops a remote session, and whether ports are still loading.</summary>
    public sealed record EthernetPane(IReadOnlyList<EthernetPortChoice> Ports, string? PickedPort, EthernetPortMode Mode, bool DropsRemoteSession, bool Loading = false);

    /// <summary>The Sound check pane's helper lists: what it shows and why (Can't hear sound, or only one side heard).</summary>
    /// <param name="Mode">"cant-hear", "one-side" or null when no list shows.</param>
    /// <param name="Steps">The Sound check rows listed, in order (title, text, level, and their fix kinds).</param>
    public sealed record SoundCheckHelp(string? Mode, bool Reading, IReadOnlyList<SoundCheckStep> Steps, bool ServicesOk);

    public static object Build(PageState page, PhysicalBenchQaSnapshot bench, ModuleState webcam, ModuleState speakerToMic, ModuleState micToSpeaker,
        ModuleState? soundCheck = null, SoundCheckHelp? help = null, DiagnosticResult? wifi = null, WifiPane? wifiPane = null,
        DiagnosticResult? ethernet = null, EthernetPane? ethernetPane = null, DiagnosticResult? charger = null, UsbPortCheckState? usbPortCheck = null,
        ModuleState? audioDevices = null, string? audioDevicesBusyId = null, PointerTestSnapshot? pointer = null, DisplayOutputCheckState? displayOutputs = null) => new
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
            PointerTest(page, pointer ?? new PointerTestSnapshot()),
            WebcamTest(page, webcam),
            SpeakerToMicTest(page, speakerToMic),
            MicToSpeakerTest(page, micToSpeaker),
            SoundCheckTest(page, soundCheck ?? new ModuleState(DiagnosticResult.NotRun(ModuleSlugs.SoundCheck), false), help),
            WifiTest(page, wifi ?? DiagnosticResult.NotRun(ModuleSlugs.WifiConnect), wifiPane),
            EthernetTest(page, ethernet ?? DiagnosticResult.NotRun(ModuleSlugs.EthernetPort), ethernetPane),
            ChargerTest(page, charger ?? DiagnosticResult.NotRun(ModuleSlugs.ChargerReplug)),
            UsbPortCheckTest(page, usbPortCheck ?? new(new ModuleState(DiagnosticResult.NotRun(ModuleSlugs.UsbPortCheck), false), Usb.UsbPortCheckReport.Empty)),
            AudioDevicesExport(page, audioDevices ?? new ModuleState(DiagnosticResult.NotRun(ModuleSlugs.AudioDevices), false), audioDevicesBusyId),
            DisplayOutputCheckTest(page, displayOutputs ?? new(new ModuleState(DiagnosticResult.NotRun(ModuleSlugs.DisplayOutputCheck), false),
                Display.DisplayOutputCheckReport.Empty)),
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
        // Keys count only when this PC's keyboard pressed them; ignoredKeys came from elsewhere (a remote viewer, injected input).
        measured = new { uniqueKeysPressed = b.UniqueKeysPressed, peakKeyRollover = b.PeakKeyRollover, ignoredKeys = b.IgnoredKeys, keysVerified = b.KeysVerified },
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
        state = b.DisplayOutcome != PhysicalCheckOutcome.NotRun ? "done"
            : b.DisplayScreens?.Any(s => s.ColorCheck == Display.ColorCheckState.WaitingForAnswers) == true ? "waiting-for-person"
            : b.SolidColorsInspected > 0 || b.DisplayScreens is { Count: > 0 } ? "in-progress" : "waiting-for-person",
        measured = new
        {
            solidColorsInspected = b.SolidColorsInspected,
            maxTouchPoints = b.MaxTouchPoints,
            screens = b.DisplayScreens?.Select(Screen).ToArray() ?? [],
            colorChannels = ColorChannelsVerdict(b.DisplayScreens),
            blankScreen = Blank(b.BlankScreen),
            blankScreenReason = T(b.BlankScreenReason),
        },
        personOutcome = b.DisplayOutcome == PhysicalCheckOutcome.NotRun ? null : Physical(b.DisplayOutcome),
        notes = T(b.DisplayNotes),
        instructions = "Launch the full-screen test. On each screen, step through the solid colours looking for dead or stuck pixels, bleed "
            + "and blemishes, then type the three numbers drawn in red, green and blue on black (a number that can't be seen is left empty: "
            + "that colour channel fails). Touch the screen with several fingers if it is a touch screen. Optionally run Screen off and on "
            + "and say whether every screen came back. A failed colour channel or a screen that didn't come back fails the test; otherwise "
            + "Pass, Note blemish or Fail display.",
        reportIf = ReportIf.Display,
    };

    private static string StepId(PointerStep s) => s switch
    {
        PointerStep.Move => "move",
        PointerStep.Buttons => "buttons",
        PointerStep.Scroll => "scroll",
        PointerStep.Drag => "drag",
        PointerStep.TouchpadGestures => "touchpad",
        PointerStep.TouchGrid => "touch-grid",
        _ => s.ToString().ToLowerInvariant(),
    };

    private static string StepState(PointerStepState s) => s switch
    {
        PointerStepState.NotSupported => "not-supported",
        _ => s.ToString().ToLowerInvariant(),
    };

    private static object PointerTest(PageState page, PointerTestSnapshot p) => new
    {
        id = "pointer",
        name = "Mouse, touchpad and touchscreen",
        @checked = page.CheckedTestIds.Contains("pointer"),
        open = page.SelectedTestId == "pointer",
        state = p.Verdict switch
        {
            PointerTestVerdict.Running => "running",
            PointerTestVerdict.NotRun => "waiting-for-person",
            _ => "done",
        },
        device = p.Device is null ? null : new
        {
            name = V(p.Device.Name),
            kind = p.Device.Kind.ToString().ToLowerInvariant(),
            precisionTouchpad = p.Device.PrecisionTouchpad,
        },
        // Measured by RPCD from this PC's own input; the person never enters this verdict.
        verdict = p.Verdict switch
        {
            PointerTestVerdict.Passed => "passed",
            PointerTestVerdict.Failed => "failed",
            PointerTestVerdict.Skipped => "skipped",
            PointerTestVerdict.Cancelled => "stopped",
            PointerTestVerdict.Running => "running",
            _ => "notrun",
        },
        currentStep = p.Current is { } c ? StepId(c) : null,
        secondsLeft = p.Current is null ? (int?)null : p.SecondsLeft,
        steps = p.Steps.Select(s => new { id = StepId(s.Step), title = PointerTestService.Title(s.Step), state = StepState(s.State), reason = V(s.Reason) }).ToList(),
        measured = new
        {
            corners = p.CornerCount,
            leftDoubleClick = p.LeftDoubleClick,
            rightDoubleClick = p.RightDoubleClick,
            middleDoubleClick = p.MiddleDoubleClick,
            noMiddleButton = p.NoMiddleButton,
            scrollUp = p.ScrollUp,
            scrollDown = p.ScrollDown,
            scrollSideways = p.ScrollLeft + p.ScrollRight,
            wheelTicks = p.WheelTicks,
            leftDragged = p.LeftDragged,
            rightDragged = p.RightDragged,
            tapToClick = p.TapToClick,
            twoFingerClick = p.TwoFingerClick,
            maxTouchpadContacts = p.MaxTouchpadContacts,
            cellsTouched = p.CellsTouched.Count,
            cells = p.CellCount,
            untouchedCells = p.Steps.Any(s => s.Step == PointerStep.TouchGrid)
                ? Enumerable.Range(0, p.CellCount).Where(i => !p.CellsTouched.Contains(i)).ToList() : null,
            gridColumns = p.GridColumns,
            maxTouchPoints = p.MaxTouchPoints,
        },
        inputVerified = p.InputVerified,
        unverifiedReason = V(p.UnverifiedReason),
        ignoredInputs = p.IgnoredInputs,
        injectedInputs = p.InjectedInputs,
        notes = T(p.Notes),
        instructions = p.Current is { } now ? PointerTestService.Instructions(now)
            : "Choose the device (mouse, touchpad, touchscreen or pen) and press Start test. A full-screen test walks through moving to the corners, "
            + "double-clicking each button, scrolling, dragging with each button, touchpad taps and fingers, and touching every square of a "
            + "touchscreen. Each step has Skip and Doesn't work, and fails after 30 s with no input. Only this PC's own input counts.",
        reportIf = ReportIf.Pointer,
    };

    /// <summary>
    /// One screen's display result. The numbers shown are left out until the person has answered, so a reader can't pass them on.
    /// </summary>
    private static object Screen(Display.DisplayScreenResult s) => new
    {
        id = V(s.ScreenId),
        name = V(s.Name),
        primary = s.Primary,
        width = s.Width,
        height = s.Height,
        patternsInspected = s.PatternsInspected,
        colorCheck = s.ColorCheck switch
        {
            Display.ColorCheckState.Passed => "passed",
            Display.ColorCheckState.Failed => "failed",
            Display.ColorCheckState.WaitingForAnswers => "waiting-for-answers",
            _ => "notrun",
        },
        failedChannels = s.FailedChannels.Select(Display.DisplayColorCheck.Name).ToArray(),
        answers = s.Answers?.Select(a => new { channel = Display.DisplayColorCheck.Name(a.Channel), shown = a.Shown, entered = a.Entered, passed = a.Passed })
            .ToArray(),
        checkedUtc = s.CheckedUtc,
    };

    /// <summary>"passed" when every screen checked passed, "failed" when any failed, else "notrun".</summary>
    private static string ColorChannelsVerdict(IReadOnlyList<Display.DisplayScreenResult>? screens)
    {
        var done = screens?.Where(s => s.ColorCheck is Display.ColorCheckState.Passed or Display.ColorCheckState.Failed).ToList() ?? [];
        if (done.Count == 0) return "notrun";
        return done.Any(s => s.ColorCheck == Display.ColorCheckState.Failed) ? "failed" : "passed";
    }

    private static string Blank(Display.BlankScreenOutcome o) => o switch
    {
        Display.BlankScreenOutcome.Returned => "returned",
        Display.BlankScreenOutcome.DidNotReturn => "did-not-return",
        Display.BlankScreenOutcome.NotSupported => "not-supported",
        _ => "notrun",
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
                kind = rep.Kind == WebcamKind.Infrared ? "infrared" : "color",
                // What the camera offers: the best format against the class its name claims (belowClass = wrong driver likely).
                capability = rep.Capability is not { } c ? null : new
                {
                    formatCount = c.FormatCount,
                    maxWidth = c.MaxWidth,
                    maxHeight = c.MaxHeight,
                    maxFps = c.MaxFps,
                    nameClass = c.ClassName,
                    expectedWidth = c.ExpectedWidth,
                    belowClass = c.BelowClass,
                },
                formats = rep.Formats.Take(MaxWebcamFormats).Select(f => new { width = f.Width, height = f.Height, fps = f.Fps, subtype = V(f.Subtype) }).ToList(),
                controls = rep.Controls.Select(x => new
                {
                    name = x.Name,
                    supported = x.Supported,
                    readFailed = x.ReadFailed,
                    min = x.Supported ? x.Min : (double?)null,
                    max = x.Supported ? x.Max : (double?)null,
                    step = x.Supported ? x.Step : (double?)null,
                    value = x.Value,
                    auto = x.Auto,
                }).ToList(),
                // Apps Windows lists as using a camera now (when it was busy or only shared). canClose = the pane's Close button closes it.
                holders = rep.Holders.Select(h => new { app = V(h.App), process = V(h.ProcessName), packaged = h.Packaged, canClose = WebcamHolders.CanClose(h) }).ToList(),
            },
            // The person's "Do you see yourself in the preview?" answer, kept beside the measured verdict (null = not answered).
            personSawPicture = rep?.PersonSawPicture,
            personOutcome = m.PersonEntered ? Person(r.Status) : null,
            message = T(r.Message),
            instructions = "Choose the camera and length, then Start test. Look at the live preview on the PC: is the picture clear, "
                + "correctly exposed and smooth? RPCD measures frames and brightness and lists the formats and controls the camera offers; the person "
                + "answers Do you see yourself in the preview? (Yes / No) and decides: Pass camera, Pass with note or Fail camera. A camera listed with "
                + "(IR) is the Windows Hello sensor: it is tested on its own and has no preview question. When another app holds the camera, the pane "
                + "names it and offers Close.",
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

    /// <summary>The charger replug test: measured only (Windows saw each change or not), with no verdict a person enters.</summary>
    private static object ChargerTest(PageState page, DiagnosticResult r)
    {
        var rep = r.Payload as ChargerReplugReport;
        static double? Secs(TimeSpan? t) => t is { } v ? Math.Round(v.TotalSeconds, 1) : null;
        return new
        {
            id = "charger",
            name = "Charger replug",
            @checked = page.CheckedTestIds.Contains("charger"),
            open = page.SelectedTestId == "charger",
            state = r.Status == DiagnosticStatus.Running ? "running"
                : r.Cancelled ? "cancelled"
                : rep is not null ? "done"
                : "waiting-for-person",
            runId = r.RunId,
            // While running, the message is the step the person is asked to do now ("Unplug the charger now.").
            step = r.Status == DiagnosticStatus.Running ? T(r.Message) : null,
            measured = rep is null ? null : new
            {
                outcome = rep.Outcome.ToString(),
                unplugSeenAfterSeconds = Secs(rep.UnplugSeenAfter),
                plugSeenAfterSeconds = Secs(rep.PlugSeenAfter),
                startedCharging = rep.StartedCharging,
                batteryPercent = rep.Percent,
            },
            result = r.Status == DiagnosticStatus.Running ? null
                : r.Cancelled ? "cancelled"
                : rep is null ? null
                : rep.RunEnd == RunEnd.CouldNotRun ? "not-applicable"
                : r.Status switch { DiagnosticStatus.Ok => "passed", DiagnosticStatus.Error => "failed", _ => "warning" },
            message = T(r.Message),
            instructions = $"Press Start replug test with the charger plugged in. When asked, unplug the charger, then plug it back in: Windows "
                + $"must see each change within {ChargerReplug.StepWindow.TotalSeconds:0} seconds, and the battery must start charging "
                + "(a full battery passes). RPCD decides the result; the person only follows the prompts.",
            reportIf = ReportIf.Charger,
        };
    }

    /// <summary>The Ethernet port test: measured only (link, speed, duplex, pings or loopback frames), with no verdict a person enters.</summary>
    private static object EthernetTest(PageState page, DiagnosticResult r, EthernetPane? pane)
    {
        var rep = r.Payload as EthernetPortReport;
        return new
        {
            id = "ethernet",
            name = "Ethernet port",
            @checked = page.CheckedTestIds.Contains("ethernet"),
            open = page.SelectedTestId == "ethernet",
            // While running it waits for the person to plug the cable or the loopback plug in (step says which, and the seconds left).
            state = r.Status == DiagnosticStatus.Running ? "running" : rep is not null || r.Status == DiagnosticStatus.Error ? "done" : "waiting-for-person",
            runId = r.RunId,
            step = r.Status == DiagnosticStatus.Running ? T(r.Message) : null,
            loading = pane?.Loading,
            ports = pane?.Ports.Select(p => new { name = V(p.Name), adapter = V(p.Description), cablePluggedIn = p.Connected }).ToList(),
            pickedPort = V(pane?.PickedPort),
            mode = pane is null ? null : pane.Mode == EthernetPortMode.Loopback ? "loopback" : "network",
            // Unplugging this port drops the remote session (it is the PC's only way out) until the cable is back in.
            dropsRemoteSession = pane?.DropsRemoteSession,
            measured = rep is null ? null : new
            {
                outcome = rep.Outcome.ToString(),
                mode = rep.Mode == EthernetPortMode.Loopback ? "loopback" : "network",
                port = V(rep.Adapter),
                adapter = V(rep.Description),
                linkWaitSeconds = rep.LinkWaitSeconds,
                speedMbps = rep.SpeedBps is { } b ? b / 1_000_000 : (long?)null,
                fullDuplex = rep.FullDuplex,
                gigabitCapable = rep.GigabitCapable,
                gotDhcpAddress = rep.GotDhcpAddress,
                pings = rep.Pings.Select(p => new { target = p.Target, sent = p.Sent, replies = p.Replies }).ToList(),
                framesSent = rep.FramesSent,
                framesCountedOut = rep.FramesCountedOut,
                framesCountedIn = rep.FramesCountedIn,
            },
            result = r.Status == DiagnosticStatus.Running ? null
                : rep is null ? (r.Status == DiagnosticStatus.Error ? "failed" : null)
                : rep.RunEnd == RunEnd.CouldNotRun ? "not-applicable"
                : r.Status switch { DiagnosticStatus.Ok => "passed", DiagnosticStatus.Error => "failed", _ => "warning" },
            message = T(r.Message),
            instructions = "The person picks the port and what is plugged in: Cable to network, or Loopback plug (a plug that wires the port's "
                + "send pins to its receive pins). After Start, RPCD waits up to " + $"{EthernetPort.LinkWindow.TotalMinutes:0}" + " minutes for the "
                + "cable or plug to be plugged in, then pings the PC's own address and the DHCP server and reads speed and duplex (cable), or "
                + $"sends {EthernetPort.LoopbackFrames} test frames and checks they come back (loopback). When dropsRemoteSession is true, unplugging "
                + "the cable drops the remote session until it is back in. RPCD decides the result.",
            reportIf = ReportIf.Ethernet,
        };
    }

    private static object UsbPortCheckTest(PageState page, UsbPortCheckState s)
    {
        var r = s.Module.Result;
        var running = r.Status == DiagnosticStatus.Running;
        var rep = running ? s.Live : r.Payload as Usb.UsbPortCheckReport;
        return new
        {
            id = "usbports",
            name = "USB port check",
            @checked = page.CheckedTestIds.Contains("usbports"),
            open = page.SelectedTestId == "usbports",
            state = running ? "in-progress" : rep?.EveryDeviceWorked is not null || s.Module.PersonEntered ? "done"
                : rep is not null ? "waiting-for-person-verdict" : "waiting-for-person",
            runId = r.RunId,
            measured = rep is null ? null : new
            {
                portsTested = rep.PortsTested.Count,
                ports = rep.PortsTested.Select(a => new
                {
                    device = V(a.Name),
                    port = V(a.Where),
                    speed = a.Speed.ToString(),
                    speedText = V(Usb.UsbAnalysis.SpeedText(a.Speed, a.Usb4)),
                    belowItsSpeed = a.Downgraded,
                    works = a.Works,
                    problem = a.ProblemCode != 0 ? V(new ProblemDevice(a.Name, "USB", a.DeviceId, a.ProblemCode, "").FriendlyError)
                        : a.PortStatus is { } ps && Usb.UsbPortStatus.IsFailure(ps) ? V(Usb.UsbPortStatus.Describe(ps)) : null,
                }).ToList(),
                drops = rep.Drops.Select(d => new { hub = V(d.HubName), devices = d.Devices.Select(V).ToList() }).ToList(),
                notice = T(rep.Notice),
            },
            everyDeviceWorked = rep?.EveryDeviceWorked,
            personOutcome = rep?.EveryDeviceWorked is not null || s.Module.PersonEntered ? Person(r.Status) : null,
            message = T(running ? Usb.UsbPortCheck.Outcome(s.Live).Message : r.Message),
            instructions = "Start watching, then the person plugs a USB stick or mouse into each USB port in turn (USB-A and USB-C, and the "
                + "dock's ports). Each device shows with the port it was found on and its speed; a USB 3 device at USB 2 speed is flagged. "
                + "When every port is done the person presses Finish and answers Did every device work? (Yes or No).",
            reportIf = ReportIf.UsbPortCheck,
        };
    }

    private static string Outcome(AudioDeviceOutcome o) => o switch
    {
        AudioDeviceOutcome.Passed => "passed",
        AudioDeviceOutcome.Warning => "warning",
        AudioDeviceOutcome.Failed => "failed",
        AudioDeviceOutcome.Skipped => "skipped",
        _ => "notrun",
    };

    private static string? Heard(SoundCheckAnswer? a) => a switch
    {
        SoundCheckAnswer.Both => "both", SoundCheckAnswer.OnlyLeft => "only-left", SoundCheckAnswer.OnlyRight => "only-right",
        SoundCheckAnswer.Nothing => "nothing", _ => null,
    };

    /// <summary>
    /// The per-device test: one entry per speaker and microphone, with its state, what RPCD measured (the recorded level for a microphone)
    /// or what the person heard (for a speaker), its result and the Sound fixes on its row.
    /// </summary>
    private static object AudioDevicesExport(PageState page, ModuleState m, string? busyId)
    {
        var r = m.Result;
        var rep = r.Payload as AudioDevicesReport;
        var waiting = rep?.Devices.Any(d => d.WaitingForAnswer) == true;
        return new
        {
            id = "audiodevices",
            name = AudioDevicesTest.DisplayName,
            @checked = page.CheckedTestIds.Contains("audiodevices"),
            open = page.SelectedTestId == "audiodevices",
            state = r.Status == DiagnosticStatus.Running ? "running" : m.PersonEntered ? "done"
                : waiting ? "waiting-for-person-verdict"
                : rep is { Untested: 0, Tested: > 0 } ? "done"
                : rep is { Tested: > 0 } ? "in-progress" : "waiting-for-person",
            runId = r.RunId,
            busyDevice = busyId,
            tested = rep?.Tested,
            untested = rep?.Untested,
            notice = T(rep?.Notice),
            devices = rep?.Devices.Select(d => new
            {
                id = d.Id,
                name = V(d.Name),
                flow = d.Flow == AudioFlow.Output ? "output" : "input",
                kind = V(d.Kind),
                state = d.State.ToString().ToLowerInvariant(),
                isDefault = d.IsDefault,
                muted = d.Muted,
                volume = d.Volume is { } v ? Math.Round(v * 100) : (double?)null,
                result = Outcome(d.Outcome),
                summary = V(d.Result),
                waitingForAnswer = d.WaitingForAnswer,
                measured = d.Flow == AudioFlow.Output
                    ? d.Channels is null ? null : (object)new { channels = d.Channels }
                    : d.LevelDbfs is null ? null : new { levelDbfs = d.LevelDbfs, peakDbfs = d.PeakDbfs },
                heard = Heard(d.Heard),
                hint = T(d.Hint),
                fixes = d.Actions?.Select(a => new { kind = a.Kind.ToString(), button = V(a.ButtonText), target = a.Target }).ToList(),
            }).ToList(),
            personOutcome = m.PersonEntered ? Person(r.Status) : null,
            message = T(r.Message),
            instructions = "Every speaker and microphone is listed with its state. For a speaker, press Play: a chime plays on the left, then "
                + "the right, and the person answers Heard both, Only left, Only right or Nothing. For a microphone, press Record and talk for "
                + "3 seconds: RPCD judges the level (no signal = failed, very low = speak closer) and Play back lets the person hear it. "
                + "Disabled, muted or very quiet devices show their fix button. For HDMI or DisplayPort sound, connect a monitor or TV with speakers.",
            reportIf = ReportIf.AudioDevices,
        };
    }

    /// <summary>
    /// When an agent coaching a test should report a learning (Admin's report_learning tool): the test's instructions or screen did not
    /// match what the person has. One line each, written for the agent, not the person.
    /// </summary>
    /// <summary>The Wi-Fi connect test: measured only (connected or not, pings, signal), with no verdict a person enters.</summary>
    private static object WifiTest(PageState page, DiagnosticResult r, WifiPane? pane)
    {
        var rep = r.Payload as WifiConnectReport;
        static object? Pings(PingStats? p) => p is null ? null : new { sent = p.Sent, received = p.Received, lossPercent = p.LossPercent, averageMs = p.AverageMs, maxMs = p.MaxMs };
        return new
        {
            id = "wifi",
            name = "Wi-Fi connect",
            @checked = page.CheckedTestIds.Contains("wifi"),
            open = page.SelectedTestId == "wifi",
            state = r.Status == DiagnosticStatus.Running ? "running" : rep is not null ? "done" : "waiting-for-person",
            runId = r.RunId,
            step = r.Status == DiagnosticStatus.Running ? T(r.Message) : null,
            networks = pane?.Networks.Take(WifiRadio.MaxNetworksShown).Select(n => new
            {
                ssid = V(n.Ssid), security = n.Security, band = n.Band, rssiDbm = n.Rssi, saved = n.HasProfile, connected = n.Connected,
                needsPassword = !n.HasProfile && n.CanTypePassword && n.Security is not (WifiRadio.Open or WifiRadio.Owe),
                canTest = n.HasProfile || n.CanTypePassword,
            }).ToList(),
            pickedSsid = V(pane?.PickedSsid),
            passwordTyped = pane?.PasswordTyped,
            scanning = pane?.Scanning,
            // Starting the test disconnects this PC's only network route, so a remote session drops until the test ends (about a minute).
            dropsRemoteSession = pane?.DropsRemoteSession,
            measured = rep is null ? null : new
            {
                outcome = rep.Outcome.ToString(),
                ssid = V(rep.Ssid),
                mode = rep.Mode,
                adapter = V(rep.Adapter),
                connectSeconds = rep.ConnectSeconds,
                gateway = rep.Gateway is null ? null : "router",
                routerPings = Pings(rep.GatewayPings),
                internetPings = Pings(rep.InternetPings),
                rssiMinDbm = rep.RssiMin,
                rssiMaxDbm = rep.RssiMax,
                rssiAverageDbm = rep.RssiAverage,
                restore = rep.Restore.ToString(),
                originalSsid = V(rep.OriginalSsid),
                wlanError = rep.ErrorCode,
            },
            result = r.Status == DiagnosticStatus.Running || rep is null ? null
                : rep.RunEnd == RunEnd.CouldNotRun ? "not-applicable"
                : r.Status switch { DiagnosticStatus.Ok => "passed", DiagnosticStatus.Error => "failed", _ => "warning" },
            message = T(r.Message),
            instructions = "The person picks a network (a saved one, or types its password; the password is never saved or shown) and presses "
                + $"Start Wi-Fi test. RPCD disconnects, connects, pings the router and the internet for {WifiConnect.PingTime.TotalSeconds:0} seconds, "
                + "then goes back to the original network. When dropsRemoteSession is true the remote session drops for about a minute and "
                + "reconnects by itself: read this again after it reconnects. RPCD decides the result.",
            reportIf = ReportIf.Wifi,
        };
    }

    private static object DisplayOutputCheckTest(PageState page, DisplayOutputCheckState s)
    {
        var r = s.Module.Result;
        var running = r.Status == DiagnosticStatus.Running;
        var rep = running ? s.Live : r.Payload as Display.DisplayOutputCheckReport;
        var answered = rep is not null && !rep.Watching && rep.Unanswered == 0 && (rep.Arrivals.Count > 0 || rep.NoSignal.Count > 0);
        var done = answered || (s.Module.PersonEntered && (rep is null || rep.Unanswered == 0));
        return new
        {
            id = "displayoutputs",
            name = "Video output check",
            @checked = page.CheckedTestIds.Contains("displayoutputs"),
            open = page.SelectedTestId == "displayoutputs",
            state = running ? "in-progress" : done ? "done"
                : rep is not null ? "waiting-for-person-verdict" : "waiting-for-person",
            runId = r.RunId,
            measured = rep is null ? null : new
            {
                portsTested = rep.Arrivals.Count,
                ports = rep.Arrivals.Select(a => new
                {
                    key = a.Key,
                    monitor = V(a.Monitor),
                    connector = V(a.Connector),
                    graphics = V(a.Adapter),
                    active = a.Active,
                    mode = V(a.Mode),
                    refreshHz = a.RefreshHz,
                    edidProblem = V(a.EdidProblem),
                    belowNative = a.BelowNative,
                    unplugged = a.Unplugged,
                    pictureAppeared = a.PictureAppeared,
                }).ToList(),
                noSignal = rep.NoSignal.Select(n => V(n.Port)).ToList(),
                unanswered = rep.Unanswered,
                notice = T(rep.Notice),
            },
            personOutcome = !running && done ? Person(r.Status) : null,
            message = T(running ? Display.DisplayOutputCheck.Outcome(s.Live).Message : r.Message),
            instructions = "Start watching, then the person plugs a monitor into each video port in turn (HDMI, DisplayPort, USB-C, VGA, the "
                + "dock's). Each monitor shows with its connector, mode and whether its EDID is valid, and the person answers Did the picture "
                + "appear? (Yes or No) for each. When nothing shows up at all on a port, they press Nothing appeared and name the port. Finish "
                + "stops watching. Windows normally extends the desktop onto a new monitor by itself; one shown as not active is connected but "
                + "gets no picture from Windows.",
            reportIf = ReportIf.DisplayOutputCheck,
        };
    }

    public static class ReportIf
    {
        public const string Wifi = "The person's network is not listed, the test says it couldn't connect although the password is right and "
            + "other devices connect, or the PC didn't go back to its original network.";
        public const string Ethernet = "The person's wired port is not listed, the link never comes up although the cable works on another "
            + "PC, or the loopback test fails with a plug that passes on another PC.";
        public const string Keyboard = "The person's keyboard does not match any layout offered (for example AZERTY, Japanese, a compact "
            + "laptop or a keyboard with extra keys), keys they press do not light up, or they cannot find a key the test asks for.";
        public const string Display = "The full-screen test does not open on the screen the person is using, does not cover it, cannot be "
            + "exited, or touch does not register on a touch screen; a screen the person has is not listed or the test never moves to it; "
            + "the person can't read a colour number on a screen that otherwise looks right; or Screen off and on leaves a screen dark.";
        public const string Pointer = "The person's mouse, touchpad, touchscreen or pen is not listed, input they make on the PC is not counted "
            + "(ignoredInputs rises while they use it), or a step asks for something their device does not have.";
        public const string Webcam = "The camera the person uses is not listed, the preview never appears, or the measured result disagrees "
            + "with what the person sees.";
        public const string SpeakerToMic = "The person's speaker or microphone is not listed, they hear the tone but it is not detected, or "
            + "the test cannot start.";
        public const string DisplayOutputCheck = "A monitor the person plugs in doesn't show, shows on the wrong connector, or the "
            + "picture appears although the check says the monitor isn't active.";
        public const string SoundCheck = "The person hears the chime on the wrong side, hears nothing although the Can't hear sound list is "
            + "empty, or the list shows a problem the person doesn't have.";
        public const string Charger = "The person unplugged or plugged in the charger but the test didn't see it, the battery charged but "
            + "the test said it didn't, or the PC charges only from a dock the test doesn't account for.";
        public const string UsbPortCheck = "A device the person plugs in doesn't show, shows on the wrong port, or shows a speed that "
            + "disagrees with the device or the port (for example a USB 3 stick in a blue port shown at USB 2 speed when it works fast).";
        public const string AudioDevices = "A speaker or microphone the person has is not listed, the chime plays on a different device than "
            + "the one pressed, a microphone the person hears in Play back is judged no signal, or a fix button doesn't change the device.";
        public const string MicToSpeaker = "The person's microphone or speaker is not listed, there is no playback, or feedback makes the test "
            + "unusable.";
    }
}
