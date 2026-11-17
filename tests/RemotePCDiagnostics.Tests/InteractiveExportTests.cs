using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class InteractiveExportTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 16, 20, 0, 0, TimeSpan.Zero);
    private static InteractiveExport.ModuleState NotRun(string slug) => new(new DiagnosticResult(slug, DiagnosticStatus.NotRun, "", At), false);

    private static JsonElement Test(JsonElement root, string id) =>
        root.GetProperty("tests").EnumerateArray().Single(t => t.GetProperty("id").GetString() == id);

    [Fact]
    public void Keyboard_and_display_separate_measured_counts_from_the_persons_verdict()
    {
        var bench = new PhysicalBenchQaSnapshot(KeyboardOutcome: PhysicalCheckOutcome.NotRun, UniqueKeysPressed: 40, PeakKeyRollover: 6,
            DisplayOutcome: PhysicalCheckOutcome.PassedWithNote, SolidColorsInspected: 8, DisplayNotes: "Faint bleed bottom left");
        var page = new InteractiveExport.PageState("keyboard", ["keyboard", "display"], false, ThisViewerIsRemote: true, RemoteSessionActive: true, TechnicianHasControl: true);

        using var doc = JsonDocument.Parse(InteractiveExport.ToJson(page, bench, NotRun("Webcam"), NotRun("SpeakerToMic"), NotRun("MicToSpeaker")));
        var root = doc.RootElement;

        Assert.False(root.GetProperty("personCanRunTests").GetBoolean());
        var kb = Test(root, "keyboard");
        Assert.Equal("in-progress", kb.GetProperty("state").GetString());
        Assert.Equal(40, kb.GetProperty("measured").GetProperty("uniqueKeysPressed").GetInt32());
        Assert.False(kb.TryGetProperty("personOutcome", out _));
        Assert.True(kb.GetProperty("open").GetBoolean());
        var display = Test(root, "display");
        Assert.Equal("done", display.GetProperty("state").GetString());
        Assert.Equal("passed-with-note", display.GetProperty("personOutcome").GetString());
        Assert.Equal("Faint bleed bottom left", display.GetProperty("notes").GetString());
        Assert.False(Test(root, "webcam").GetProperty("checked").GetBoolean());
    }

    [Fact]
    public void A_finished_webcam_run_waits_for_the_persons_verdict_until_they_give_it()
    {
        var page = new InteractiveExport.PageState("webcam", [], false, false, false, false);
        var bench = new PhysicalBenchQaSnapshot();
        var measured = new DiagnosticResult("Webcam", DiagnosticStatus.Ok, "Camera delivered frames", At) { RunId = Guid.NewGuid() };

        using var waiting = JsonDocument.Parse(InteractiveExport.ToJson(page, bench, new(measured, false), NotRun("SpeakerToMic"), NotRun("MicToSpeaker")));
        Assert.True(waiting.RootElement.GetProperty("personCanRunTests").GetBoolean());
        Assert.Equal("waiting-for-person", Test(waiting.RootElement, "webcam").GetProperty("state").GetString());

        var entered = measured with { Status = DiagnosticStatus.Error, Message = "Webcam failed inspection" };
        using var done = JsonDocument.Parse(InteractiveExport.ToJson(page, bench, new(entered, true), NotRun("SpeakerToMic"), NotRun("MicToSpeaker")));
        var cam = Test(done.RootElement, "webcam");
        Assert.Equal("done", cam.GetProperty("state").GetString());
        Assert.Equal("failed", cam.GetProperty("personOutcome").GetString());
    }

    [Fact]
    public void Running_tests_report_running()
    {
        var page = new InteractiveExport.PageState("speakertomic", ["speakertomic"], true, false, false, false);
        var running = new InteractiveExport.ModuleState(new DiagnosticResult("SpeakerToMic", DiagnosticStatus.Running, "Playing tone", At), false);

        using var doc = JsonDocument.Parse(InteractiveExport.ToJson(page, new PhysicalBenchQaSnapshot(), NotRun("Webcam"), running, NotRun("MicToSpeaker")));

        Assert.True(doc.RootElement.GetProperty("batchRunning").GetBoolean());
        Assert.Equal("running", Test(doc.RootElement, "speakertomic").GetProperty("state").GetString());
        Assert.False(string.IsNullOrEmpty(Test(doc.RootElement, "speakertomic").GetProperty("instructions").GetString()));
    }

    [Fact]
    public void Every_test_says_when_to_report_a_learning()
    {
        var page = new InteractiveExport.PageState("keyboard", [], false, false, false, false);

        using var doc = JsonDocument.Parse(InteractiveExport.ToJson(page, new PhysicalBenchQaSnapshot(), NotRun("Webcam"), NotRun("SpeakerToMic"), NotRun("MicToSpeaker")));

        foreach (var id in new[] { "keyboard", "display", "webcam", "speakertomic", "mictospeaker" })
            Assert.False(string.IsNullOrWhiteSpace(Test(doc.RootElement, id).GetProperty("reportIf").GetString()), id);
        Assert.Contains("AZERTY", Test(doc.RootElement, "keyboard").GetProperty("reportIf").GetString());
    }
}
