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
    private static string NowAgo(int days) => Now.AddDays(-days).ToString("yyyy-MM-ddTHH:mm:ssZ");
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
    public void RecentCrash_Yellow() => Assert.Equal(DiagnosticStatus.Warning, B(Crash("a.exe", NowAgo(2)), Crash("a.exe", "2026-10-01T09:00:00Z")).Status);

    [Fact]
    public void SameAppThreeTimesInWeek_Red()
    {
        var rep = B(Crash("a.exe", NowAgo(2)), Crash("A.EXE", NowAgo(3)), Crash("a.exe", "2026-10-25T09:00:00Z"));
        Assert.Equal(DiagnosticStatus.Error, rep.Status);
        Assert.Equal(AreaLevel.Error, rep.Cards.Single(c => c.Id == "crashes").Level);
        Assert.Contains("crashed 3 times in the last 7 days", rep.Summary);
    }

    [Fact]
    public void AllCrashLists_AreSortable_ByEveryColumn()
    {
        var rep = B(Crash("a.exe", NowAgo(2)), Crash("b.exe", "2026-10-20T09:00:00Z"), Crash("b.exe", "2026-10-21T09:00:00Z"),
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

    [Fact]
    public async Task SystemCrashes_HostReviewsFilterBsodEvents_AndPartialFailuresKeepHealthySections()
    {
        var bsodXml = EventLogTests.Ev("Microsoft-Windows-WER-SystemErrorReporting", 1001, 2, Ago(1),
            "The computer has rebooted from a bugcheck. The bugcheck was: 0x0000007e.", "System");
        var bsodEvents = WindowsEventLog.Parse(bsodXml, "System");
        var reviewedKey = EventReviews.Key(bsodEvents.Single());
        var dump = new MinidumpFile("102926-01.dmp", DateTimeOffset.UtcNow.AddDays(-1), 262_144, @"C:\Windows\Minidump\102926-01.dmp");

        var hostReviewed = new StubCrashHost(appEvents: [], sysEvents: bsodEvents, dumps: [dump], reviewed: [reviewedKey]);
        var reviewedRes = await new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, host: hostReviewed).RefreshAsync(null);
        var reviewedRep = Assert.IsType<AreaReport>(reviewedRes.Payload);
        Assert.Empty(reviewedRep.Cards.Single(c => c.Id == "bsods").Rows);
        Assert.Single(reviewedRep.ReviewedCards!.Single(c => c.Id == "bsods").Rows);

        // System log failure still surfaces failed BSOD/power cards, minidumps on disk, and healthy app cards.
        var sysFailHost = new StubCrashHost(appEvents: [], sysEvents: null, dumps: [dump], reviewed: []);
        var sysFailRes = await new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, host: sysFailHost).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, sysFailRes.Status);
        var sysFailRep = Assert.IsType<AreaReport>(sysFailRes.Payload);
        Assert.NotNull(sysFailRep.Cards.Single(c => c.Id == "bsods").ErrorText);
        Assert.Single(sysFailRep.Cards.Single(c => c.Id == "minidumps").Rows);
        Assert.Null(sysFailRep.Cards.Single(c => c.Id == "crashes").ErrorText);

        // Application log failure still collects System log BSODs and minidumps instead of aborting early.
        var appFailHost = new StubCrashHost(appEvents: null, sysEvents: bsodEvents, dumps: [dump], reviewed: []);
        var appFailRes = await new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, host: appFailHost).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, appFailRes.Status);
        var appFailRep = Assert.IsType<AreaReport>(appFailRes.Payload);
        Assert.Single(appFailRep.Cards.Single(c => c.Id == "bsods").Rows);
        Assert.NotNull(appFailRep.Cards.Single(c => c.Id == "crashes").ErrorText);
    }

    private sealed class StubCrashHost(IReadOnlyList<WinEvent>? appEvents, IReadOnlyList<WinEvent>? sysEvents,
        IReadOnlyList<MinidumpFile> dumps, IReadOnlyCollection<string> reviewed) : RemotePCDiagnostics.Core.Plugins.IHostQueries
    {
        public Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<RemotePCDiagnostics.Core.Osquery.OsqueryQueryResult> SelectAsync(string sql, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ProcessResult?> ReadDrivesAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyDictionary<char, RemotePCDiagnostics.Core.Storage.RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default) =>
            Task.FromResult(log == "System" ? sysEvents : appEvents);
        public Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct = default) => Task.FromResult(dumps);
        public Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default) => Task.FromResult(reviewed);
    }
}
