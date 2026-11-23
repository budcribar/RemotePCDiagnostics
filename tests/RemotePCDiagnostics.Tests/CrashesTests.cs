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
        var counts = rep.Cards.Single(c => c.Id == "crashes");
        Assert.Equal(2, counts.EventCount);
        Assert.Equal(30, counts.WindowDays);
        Assert.Equal(0, counts.RecentEventCount);
        Assert.Equal(7, counts.RecentWindowDays);
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

        var dumps = new FixedCrashDumps([dump]);
        var hostReviewed = new StubCrashHost(appEvents: [], sysEvents: bsodEvents, reviewed: [reviewedKey]);
        var reviewedRes = await new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, dumps, host: hostReviewed).RefreshAsync(null);
        var reviewedRep = Assert.IsType<AreaReport>(reviewedRes.Payload);
        Assert.Empty(reviewedRep.Cards.Single(c => c.Id == "bsods").Rows);
        Assert.Single(reviewedRep.ReviewedCards!.Single(c => c.Id == "bsods").Rows);

        // System log failure still surfaces failed BSOD/power cards, minidumps on disk, and healthy app cards.
        var sysFailHost = new StubCrashHost(appEvents: [], sysEvents: null, reviewed: []);
        var sysFailRes = await new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, dumps, host: sysFailHost).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, sysFailRes.Status);
        var sysFailRep = Assert.IsType<AreaReport>(sysFailRes.Payload);
        Assert.NotNull(sysFailRep.Cards.Single(c => c.Id == "bsods").ErrorText);
        Assert.Single(sysFailRep.Cards.Single(c => c.Id == "minidumps").Rows);
        Assert.Null(sysFailRep.Cards.Single(c => c.Id == "crashes").ErrorText);

        // Application log failure still collects System log BSODs and minidumps instead of aborting early.
        var appFailHost = new StubCrashHost(appEvents: null, sysEvents: bsodEvents, reviewed: []);
        var appFailRes = await new CrashesModule(new SystemCommandRunner(), includeSystemCrashes: true, dumps, host: appFailHost).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, appFailRes.Status);
        var appFailRep = Assert.IsType<AreaReport>(appFailRes.Payload);
        Assert.Single(appFailRep.Cards.Single(c => c.Id == "bsods").Rows);
        Assert.NotNull(appFailRep.Cards.Single(c => c.Id == "crashes").ErrorText);
    }

    [Fact]
    public void WerOnlyCrash_Surfaces_WhileDuplicateAndTelemetryEventsAreIgnored()
    {
        var t1 = NowAgo(1);
        var t2 = NowAgo(2);
        var reportMatchId = "683aadb0-46dc-42dc-99d1-df440e6f0b4d";
        var werOnlyId = "11111111-2222-3333-4444-555555555555";

        // Primary Event 1000 with ReportId
        var primary1000 = EventLogTests.Ev("Application Error", 1000, 2, t1, "Faulting application name: app.exe", "Application",
            $"<Data Name='AppName'>app.exe</Data><Data Name='AppVersion'>1.0.0.0</Data><Data Name='AppTimeStamp'>0</Data><Data Name='ModuleName'>core.dll</Data><Data Name='ModuleVersion'>1.0</Data><Data Name='ModuleTimeStamp'>0</Data><Data Name='ExceptionCode'>c0000005</Data><Data Name='FaultingOffset'>0</Data><Data Name='ProcessId'>1</Data><Data Name='ProcessCreationTime'>0</Data><Data Name='AppPath'>C:\\app.exe</Data><Data Name='ModulePath'>C:\\core.dll</Data><Data Name='IntegratorReportId'>{reportMatchId}</Data>");

        // Duplicate WER 1001 matching the primary 1000 by ReportId (must not double-count)
        var dupWer = EventLogTests.Ev("Windows Error Reporting", 1001, 4, t1, "Fault bucket", "Application",
            $"<Data Name='Bucket'>123</Data><Data Name='BucketType'>5</Data><Data Name='EventName'>APPCRASH</Data><Data Name='Response'>Not available</Data><Data Name='CabId'>0</Data><Data Name='P1'>app.exe</Data><Data Name='P2'>1.0.0.0</Data><Data Name='P3'>0</Data><Data Name='P4'>core.dll</Data><Data Name='P5'>1.0</Data><Data Name='P6'>0</Data><Data Name='P7'>c0000005</Data><Data Name='P8'>0</Data><Data Name='P9'></Data><Data Name='P10'></Data><Data Name='AttachedFiles'></Data><Data Name='StorePath'></Data><Data Name='AnalysisSymbol'></Data><Data Name='Rechecking'>0</Data><Data Name='ReportId'>{reportMatchId}</Data>");

        // WER-only APPCRASH (no Event 1000) — logged twice with same ReportId (queued + sent)
        var werOnly = EventLogTests.Ev("Windows Error Reporting", 1001, 4, t2, "Fault bucket", "Application",
            $"<Data Name='Bucket'>999</Data><Data Name='BucketType'>5</Data><Data Name='EventName'>APPCRASH</Data><Data Name='Response'>Not available</Data><Data Name='CabId'>0</Data><Data Name='P1'>AppXSVC</Data><Data Name='P2'>10.0.26100.1</Data><Data Name='P3'>0</Data><Data Name='P4'>appxdeploymentserver.dll</Data><Data Name='P5'>10.0</Data><Data Name='P6'>0</Data><Data Name='P7'>c0000005</Data><Data Name='P8'>0</Data><Data Name='P9'></Data><Data Name='P10'></Data><Data Name='AttachedFiles'></Data><Data Name='StorePath'></Data><Data Name='AnalysisSymbol'></Data><Data Name='Rechecking'>0</Data><Data Name='ReportId'>{werOnlyId}</Data>");

        // Telemetry / non-app WER events (must be ignored)
        var telemetry = EventLogTests.Ev("Windows Error Reporting", 1001, 4, t2, "Fault bucket", "Application",
            "<Data Name='Bucket'>1</Data><Data Name='BucketType'>0</Data><Data Name='EventName'>RADAR_PRE_LEAK_64</Data><Data Name='Response'>Not available</Data><Data Name='CabId'>0</Data><Data Name='P1'>chrome.exe</Data>");
        var bsodWer = EventLogTests.Ev("Windows Error Reporting", 1001, 4, t2, "Fault bucket", "Application",
            "<Data Name='Bucket'></Data><Data Name='BucketType'>0</Data><Data Name='EventName'>BlueScreen</Data><Data Name='Response'>Not available</Data><Data Name='CabId'>0</Data><Data Name='P1'>9f</Data>");

        var rep = B(primary1000, dupWer, werOnly, werOnly, telemetry, bsodWer);
        var crashes = rep.Cards.Single(c => c.Id == "crashes");
        Assert.Equal(2, crashes.Rows.Count);
        Assert.Equal(["app.exe", "AppXSVC"], crashes.Rows.Select(r => r.Values[1]));
        Assert.Equal("Access violation (in appxdeploymentserver.dll)", crashes.Rows[1].Values[4]);
        Assert.Contains("WER event: APPCRASH", crashes.Rows[1].Detail);
    }

    [Fact]
    public void QuiesceHang_LabelsAsBackgroundSuspend()
    {
        var quiesce = EventLogTests.Ev("Application Hang", 1002, 2, NowAgo(1), "The program olk.exe stopped interacting with Windows", "Application",
            "<Data Name='AppName'>olk.exe</Data><Data Name='AppVersion'>1.2024.1124.100</Data><Data Name='ProcessId'>0x1</Data><Data Name='StartTime'>0</Data><Data Name='TerminationTime'>0</Data><Data Name='ExeFileName'>C:\\olk.exe</Data><Data Name='ReportId'>683aadb0-46dc-42dc-99d1-df440e6f0b4d</Data><Data Name='PackageFullName'>Microsoft.OutlookForWindows_1.2024.1126.101_arm64__8wekyb3d8bbwe</Data><Data Name='PackageRelativeAppId'>Microsoft.OutlookforWindows</Data><Data Name='HangType'>Quiesce</Data>");

        var rep = B(quiesce);
        var row = Assert.Single(rep.Cards.Single(c => c.Id == CrashesModule.HangsCardId).Rows);
        Assert.Equal("Stopped responding (background suspend)", row.Values[4]);
    }

    private sealed class StubCrashHost(IReadOnlyList<WinEvent>? appEvents, IReadOnlyList<WinEvent>? sysEvents,
        IReadOnlyCollection<string> reviewed) : RemotePCDiagnostics.Core.Plugins.IHostQueries
    {
        public Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<RemotePCDiagnostics.Core.Areas.DriveList?> ReadDrivesAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyDictionary<char, RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default) =>
            Task.FromResult(log == "System" ? sysEvents : appEvents);
        public Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default) => Task.FromResult(reviewed);
    }
}
