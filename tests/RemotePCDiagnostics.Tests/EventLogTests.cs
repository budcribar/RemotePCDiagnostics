using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class EventLogTests
{
    internal static string Ev(string provider, int id, int level, string time, string message, string channel = "System", string data = "") => $"""
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

    private static List<WinEvent> Errs(string source, int n, int level = 2) =>
        WindowsEventLog.Parse(string.Concat(Enumerable.Range(0, n).Select(k => Ev(source, 7000 + k, level, $"2026-10-2{k % 8 + 1}T09:00:00Z", "Something failed"))), "System").ToList();

    [Fact]
    public void IsolatedErrors_StayGreen_ButListed()
    {
        var rep = EventLogModule.Build([.. Errs("A", 4), .. Errs("B", 2)], []);
        Assert.Equal(DiagnosticStatus.Ok, rep.Status);
        Assert.Equal(AreaLevel.Ok, rep.Cards.Single(c => c.Id == "system").Level);
        // Identical errors are grouped: one row per source/message, with the count in "Times".
        var sys = rep.Cards.Single(c => c.Id == "system");
        Assert.Equal(2, sys.Rows.Count);
        Assert.Equal(["4", "2"], sys.Rows.Select(r => r.Values[3]).OrderByDescending(x => x));
        Assert.Equal("6 errors", sys.Headline);
    }

    [Fact]
    public void FiveFromSameSource_Warns()
    {
        var rep = EventLogModule.Build(Errs("Disk", 5), []);
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        Assert.Equal(AreaLevel.Warning, rep.Cards.Single(c => c.Id == "system").Level);
    }

    [Fact]
    public void Critical_Warns() => Assert.Equal(DiagnosticStatus.Warning, EventLogModule.Build(Errs("Kernel-Power", 1, level: 1), []).Status);
}
