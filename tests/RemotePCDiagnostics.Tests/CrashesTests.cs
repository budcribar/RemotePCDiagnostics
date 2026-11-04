using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class CrashesTests
{
    // Relative to now so the test doesn't age out of the module's recent-crash window.
    private static string Ago(int days) => DateTime.UtcNow.AddDays(-days).ToString("yyyy-MM-ddTHH:mm:ssZ");

    private static readonly string CrashXml =
        EventLogTests.Ev("Application Error", 1000, 2, Ago(2), "Faulting application name: chrome.exe", "Application",
           "<Data Name='AppName'>chrome.exe</Data><Data Name='AppVersion'>130.0.1</Data><Data Name='AppTimeStamp'>0</Data><Data Name='ModuleName'>ntdll.dll</Data>") +
        EventLogTests.Ev("Application Error", 1000, 2, Ago(1), "Faulting application name: chrome.exe", "Application",
           "<Data>chrome.exe</Data><Data>130.0.1</Data><Data>0</Data><Data>chrome.dll</Data>") +
        EventLogTests.Ev("Application Hang", 1002, 2, Ago(3), "The program EXCEL.EXE stopped interacting with Windows", "Application",
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
        Assert.Equal("Closed unexpectedly (problem in chrome.dll)", crashes.Rows[0].Values[4]);
        Assert.Equal("Closed unexpectedly (problem in ntdll.dll)", crashes.Rows[1].Values[4]);
        Assert.Equal("Stopped responding", rep.Cards.Single(c => c.Id == "hangs").Rows.Single().Values[4]);
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

    private static readonly DateTimeOffset Now = new(2026, 10, 29, 12, 0, 0, TimeSpan.Zero);
    private static string Crash(string app, string time) => EventLogTests.Ev("Application Error", 1000, 2, time, "Faulting application name: " + app, "Application", $"<Data>{app}</Data><Data>1.0</Data><Data>0</Data><Data>x.dll</Data>");
    private static AreaReport B(params string[] xml) => CrashesModule.Build(WindowsEventLog.Parse(string.Concat(xml), "Application"), Now);

    [Fact]
    public void OnlyOldCrashes_GreenAndNeutral()
    {
        var rep = B(Crash("a.exe", "2026-10-10T09:00:00Z"), Crash("b.exe", "2026-10-05T09:00:00Z"));
        Assert.Equal(DiagnosticStatus.Ok, rep.Status);
        Assert.Equal("No crashes in the last 7 days (2 older)", rep.Summary);
        Assert.Equal(AreaLevel.Neutral, rep.Cards.Single(c => c.Id == "crashes").Level);
        Assert.All(rep.Cards.Single(c => c.Id == "crashes").Rows, r => Assert.Equal(AreaLevel.Neutral, r.Level));
    }

    [Fact]
    public void RecentCrash_Yellow() => Assert.Equal(DiagnosticStatus.Warning, B(Crash("a.exe", Ago(2)), Crash("a.exe", "2026-10-01T09:00:00Z")).Status);

    [Fact]
    public void SameAppThreeTimesInWeek_Red()
    {
        var rep = B(Crash("a.exe", Ago(2)), Crash("A.EXE", Ago(3)), Crash("a.exe", "2026-10-25T09:00:00Z"));
        Assert.Equal(DiagnosticStatus.Error, rep.Status);
        Assert.Equal(AreaLevel.Error, rep.Cards.Single(c => c.Id == "crashes").Level);
        Assert.Contains("crashed 3 times in the last 7 days", rep.Summary);
    }

    [Fact]
    public void AllCrashLists_AreSortable_ByEveryColumn()
    {
        var rep = B(Crash("a.exe", Ago(2)), Crash("b.exe", "2026-10-20T09:00:00Z"), Crash("b.exe", "2026-10-21T09:00:00Z"),
            Crash("b.exe", "2026-10-02T09:00:00Z"));
        var apps = rep.Cards.Single(c => c.Id == "apps");
        Assert.Equal(["App", "Crashes", "Freezes", "Last time"], apps.Columns);
        Assert.Equal(["a.exe", "b.exe"], AreaSort.Sort(apps.Rows, 1, false).Select(r => r.Values[0]));          // by crash count
        Assert.Equal(["a.exe", "b.exe"], AreaSort.Sort(apps.Rows, 3, true).Select(r => r.Values[0]));           // last seen, newest first
        var crashes = rep.Cards.Single(c => c.Id == "crashes");
        Assert.Equal((0, true), AreaSort.Default(crashes.Columns));
        Assert.Equal("a.exe", AreaSort.Sort(crashes.Rows, 0, true)[0].Values[1]);
        Assert.Equal("b.exe", AreaSort.Sort(crashes.Rows, 0, false)[0].Values[1]);
    }
}
