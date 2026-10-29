using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class EventLogTests
{
    private static string Ev(string provider, int id, int level, string time, string message, string channel = "System", string data = "") => $"""
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{provider}'/><EventID Qualifiers='0'>{id}</EventID><Level>{level}</Level>
    <TimeCreated SystemTime='{time}'/><Channel>{channel}</Channel><Computer>PC</Computer></System><EventData>{data}</EventData>
    <RenderingInfo Culture='en-US'><Message>{message}</Message><Level>x</Level><Provider>{provider}</Provider></RenderingInfo></Event>
    """;

    private static readonly string SystemXml =
        Ev("Microsoft-Windows-Kernel-Power", 41, 1, "2026-10-28T10:00:00.0000000Z", "The system has rebooted without cleanly shutting down first.&#xD;\nMore text") +
        Ev("Service Control Manager", 7000, 2, "2026-10-28T11:00:00.0000000Z", "The Foo service failed to start.") +
        Ev("Service Control Manager", 7000, 2, "2026-10-29T11:00:00.0000000Z", "The Foo service failed to start.");

    [Fact]
    public void Parse_ReadsSystemFieldsAndMessage()
    {
        var events = WindowsEventLog.Parse(SystemXml, "System");
        Assert.Equal(3, events.Count);
        Assert.Equal(7000, events[0].EventId); // newest first
        var kp = events.Single(e => e.EventId == 41);
        Assert.Equal("Kernel-Power", kp.Source);
        Assert.Equal(1, kp.Level);
        Assert.Equal("The system has rebooted without cleanly shutting down first.", kp.ShortMessage);
        Assert.Equal(new DateTimeOffset(2026, 10, 28, 10, 0, 0, TimeSpan.Zero), kp.Time);
    }

    [Fact]
    public void Parse_EmptyOutput_IsNoEvents() => Assert.Empty(WindowsEventLog.Parse("  \r\n"));

    [Fact]
    public void LevelQuery_And_Arguments()
    {
        Assert.Equal("*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 604800000]]]", WindowsEventLog.LevelQuery(7, 1, 2));
        Assert.Equal(["qe", "System", "/q:X", "/c:5", "/rd:true", "/f:RenderedXml"], WindowsEventLog.Arguments("System", "X", 5));
    }

    [Fact]
    public async Task Module_CriticalWarns_FriendlySummary()
    {
        var log = new List<string>();
        var l = new ScriptedLauncher((f, a) => ScriptedLauncher.Ok(a[1] == "System" ? SystemXml : ""));
        var r = await new EventLogModule(new SystemCommandRunner(l, log.Add)).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal("Last 7 days: 1 critical problem, 2 Windows errors, 0 app errors", r.Message);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal(AreaLevel.Error, rep.Cards.Single(c => c.Id == "critical").Level);
        var src = rep.Cards.Single(c => c.Id == "sources");
        Assert.Equal("Service Control Manager", src.Headline);
        Assert.Equal("2", src.Rows[0].Values[2]);
        Assert.Equal("No errors", rep.Cards.Single(c => c.Id == "apps").Headline);
        Assert.StartsWith("wevtutil", Path.GetFileName(l.Calls[0].File));
        Assert.Contains(log, s => s.Contains("source=wevtutil"));
    }

    [Fact]
    public async Task Module_OneLogFails_CardErrorOthersShown()
    {
        var l = new ScriptedLauncher((f, a) => a[1] == "System" ? ScriptedLauncher.Ok(SystemXml) : ScriptedLauncher.Fail("Access is denied."));
        var r = await new EventLogModule(new SystemCommandRunner(l)).RefreshAsync(null);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        Assert.NotNull(rep.Cards.Single(c => c.Id == "apps").ErrorText);
        Assert.DoesNotContain("denied", r.Message);
    }

    [Fact]
    public async Task Module_AllFail_FriendlyError()
    {
        var r = await new EventLogModule(new SystemCommandRunner(new ScriptedLauncher((f, a) => ScriptedLauncher.Fail()))).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("Couldn't read the Windows error log on this PC.", r.Message);
    }

    [Fact]
    public void Quiet_IsOk() => Assert.Equal("No errors in the last 7 days", EventLogModule.Build([], []).Summary);

    // --- Crashes ---
    private static readonly string CrashXml =
        Ev("Application Error", 1000, 2, "2026-10-27T09:00:00Z", "Faulting application name: chrome.exe", "Application",
           "<Data Name='AppName'>chrome.exe</Data><Data Name='AppVersion'>130.0.1</Data><Data Name='AppTimeStamp'>0</Data><Data Name='ModuleName'>ntdll.dll</Data>") +
        Ev("Application Error", 1000, 2, "2026-10-28T09:00:00Z", "Faulting application name: chrome.exe", "Application",
           "<Data>chrome.exe</Data><Data>130.0.1</Data><Data>0</Data><Data>chrome.dll</Data>") +
        Ev("Application Hang", 1002, 2, "2026-10-26T09:00:00Z", "The program EXCEL.EXE stopped interacting with Windows", "Application",
           "<Data>EXCEL.EXE</Data><Data>16.0</Data>");

    [Fact]
    public async Task Crashes_GroupsByApp()
    {
        var l = new ScriptedLauncher((f, a) => ScriptedLauncher.Ok(CrashXml));
        var r = await new CrashesModule(new SystemCommandRunner(l)).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal("2 crashes, 1 freeze in the last 30 days · most: chrome.exe", r.Message);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        var crashes = rep.Cards.Single(c => c.Id == "crashes");
        Assert.Equal("Closed unexpectedly (problem in chrome.dll)", crashes.Rows[0].Values[3]);
        Assert.Equal("Closed unexpectedly (problem in ntdll.dll)", crashes.Rows[1].Values[3]);
        Assert.Equal("Stopped responding", rep.Cards.Single(c => c.Id == "hangs").Rows.Single().Values[3]);
        Assert.Equal(["chrome.exe", "2", "0"], rep.Cards.Single(c => c.Id == "apps").Rows[0].Values.Take(3));
        Assert.Contains("Application Error", l.Calls[0].Args[2]);
    }

    [Fact]
    public async Task Crashes_None_IsOk()
    {
        var r = await new CrashesModule(new SystemCommandRunner(new ScriptedLauncher((f, a) => ScriptedLauncher.Ok("")))).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("No app crashes in the last 30 days", r.Message);
    }

    [Fact]
    public async Task Crashes_ReadFails_Friendly()
    {
        var r = await new CrashesModule(new SystemCommandRunner(new ScriptedLauncher((f, a) => ScriptedLauncher.Fail()))).RefreshAsync(null);
        Assert.Equal("Couldn't read app crash reports on this PC.", r.Message);
    }
}
