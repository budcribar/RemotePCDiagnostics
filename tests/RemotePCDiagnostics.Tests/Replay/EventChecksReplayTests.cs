using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// The checks built on the event logs, replayed from recorded PCs: Crashes &amp; unexpected restarts (its dump files and graphics drivers moved
/// from listing the folders and osquery to WMI through the Agent), the Windows error log, and Sleep, wake &amp; standby drain. Their event logs
/// come from wevtutil and their sleep answers from powercfg, recorded as the programs' output; the battery report is recorded by name. Each
/// report is built at the time the PC was recorded, in UTC. A recording made before the recorder knew a check skips its tests.
/// </summary>
public sealed class EventChecksReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasWevtutil(ReplayedPc pc, string xpath) =>
        pc.Has(c => c.Kind == RecordedCall.ProcessKind && c.File == "wevtutil.exe" && c.Args?.Contains("/q:" + xpath) == true);
    private static bool HasCrashes(ReplayedPc pc) => HasWevtutil(pc, CrashesModule.Query) && pc.Has(c => c.Kind == RecordedCall.WmiKind
        && c.Query == WmiCrashDumpSource.FilesSql(@"C:\Windows\Minidump", "dmp"));
    private static bool HasCrashesOld(ReplayedPc pc) => pc.HasFile(CrashDumpFiles.Minidumps) && pc.HasOsquery(OsqueryDeviceDriverSource.DriversSql);
    private static bool HasEventLog(ReplayedPc pc) => HasWevtutil(pc, WindowsEventLog.LevelQuery(EventLogModule.Days, 1, 2));
    private static bool HasSleepWake(ReplayedPc pc) => HasWevtutil(pc, SleepWakeModule.EventQuery(SleepWakeModule.EventDays));

    private static AreaReport Report(DiagnosticResult r) => Assert.IsType<AreaReport>(r.Payload);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Crashes_MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasCrashes(pc), "This recording has no Crashes answers.");
        var result = await pc.Crashes().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Crashes", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task EventLog_MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasEventLog(pc), "This recording has no error log answers.");
        var result = await pc.EventLog().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "EventLog", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SleepWake_MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasSleepWake(pc), "This recording has no sleep and wake answers.");
        var result = await pc.SleepWake().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "SleepWake", result);
    }

    /// <summary>
    /// The two paths list the same dump files (WMI gives the names in lower case, so names are compared ignoring case) and the same graphics
    /// drivers, so the reports match card for card, apart from the dump files' names and paths.
    /// </summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Crashes_WmiAndLegacyAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasCrashes(pc) && HasCrashesOld(pc), "This recording doesn't hold both the WMI and the legacy Crashes answers.");
        var ct = TestContext.Current.CancellationToken;
        var diffs = new List<string>();

        var newDumps = new WmiCrashDumpSource(pc.Wmi, @"C:\Windows");
        var oldPc = new ReplayedPc(rec);
        void Same(string what, IReadOnlyList<MinidumpFile> old, IReadOnlyList<MinidumpFile> now)
        {
            static string Key(MinidumpFile f) => $"{f.FileName.ToLowerInvariant()} {f.SizeBytes} {f.Created.ToUniversalTime():yyyy-MM-dd HH:mm:ss}";
            var o = old.Select(Key).Order().ToList();
            var n = now.Select(Key).Order().ToList();
            if (!o.SequenceEqual(n)) diffs.Add($"{what}: old [{string.Join(", ", o)}]; new [{string.Join(", ", n)}]");
        }
        Same("blue screen dumps", CrashDumpFiles.Parse(oldPc.Replay.FileText(CrashDumpFiles.Minidumps)), await newDumps.ReadMinidumpsAsync(ct));
        // The legacy reader keeps only the last 30 days; the check does the same with WMI's list.
        var cutoff = rec.CapturedAt.AddDays(-GraphicsDriverCrashes.Days);
        Same("live kernel reports", CrashDumpFiles.Parse(oldPc.Replay.FileText(CrashDumpFiles.LiveKernelReports)),
            [.. (await newDumps.ReadLiveKernelReportsAsync(ct)).Where(d => d.Created >= cutoff)]);

        var gpus = (await new WmiDeviceDriverSource(pc.Wmi).ReadDriversAsync(ct))?.Where(GraphicsDriverCrashes.IsDisplayDriver).Select(GpuDriver.From).ToList();
        var oldGpus = (await new OsqueryDeviceDriverSource(oldPc.Osquery, oldPc.Commands).ReadDriversAsync(ct))?.Where(GraphicsDriverCrashes.IsDisplayDriver)
            .Select(GpuDriver.From).ToList();
        Assert.NotNull(gpus);
        Assert.NotNull(oldGpus);
        if (gpus.Count == 0) diffs.Add("no graphics driver on the new path");
        if (!gpus.Select(g => g.Label).Order().SequenceEqual(oldGpus.Select(g => g.Label).Order()))
            diffs.Add($"graphics drivers: old [{string.Join(", ", oldGpus.Select(g => g.Label))}]; new [{string.Join(", ", gpus.Select(g => g.Label))}]");

        var now = Report(await new ReplayedPc(rec).Crashes().RefreshAsync(null, ct));
        var old = Report(await new ReplayedPc(rec).CrashesOld().RefreshAsync(null, ct));
        diffs.AddRange(ReportDiff.Between(WithoutDumpNames(old), WithoutDumpNames(now)));
        Assert.True(diffs.Count == 0, string.Join("\n", diffs));
    }

    /// <summary>The cards with each dump file's name and path left out (their case differs between the paths).</summary>
    private static AreaReport WithoutDumpNames(AreaReport r) => r with
    {
        Cards = [.. r.Cards.Select(c => c.Id == "minidumps"
            ? c with { Headline = c.Headline.Split(" (")[0], Rows = [.. c.Rows.Select(x => x with { Values = [x.Values[0], "", .. x.Values.Skip(2)] })] }
            : c.Id == GraphicsDriverCrashes.CardId ? c with { Rows = [.. c.Rows.Select(x => x with { Detail = null })] } : c)],
    };

    // Damaged answers: each check survives every one of its answers failing or coming back damaged, on each path.

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Crashes_DamagedAnswersNeverBreakTheReport(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasCrashes(new ReplayedPc(rec)), "This recording has no Crashes answers.");
        // The drivers list is long and Device Manager & drivers already damages it row by row: one row is enough here.
        (string, Func<ReplayedPc, IDiagnosticModule>)[] paths = HasCrashesOld(new ReplayedPc(rec))
            ? [("WMI", pc => pc.Crashes()), ("legacy", pc => pc.CrashesOld())]
            : [("WMI", pc => pc.Crashes())];
        await DamagedRuns.AssertSurvivesAsync(rec, Problems, maxRows: 1, paths);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task EventLog_DamagedAnswersNeverBreakTheReport(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasEventLog(new ReplayedPc(rec)), "This recording has no error log answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, Problems, maxRows: 1, ("wevtutil", pc => pc.EventLog()));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SleepWake_DamagedAnswersNeverBreakTheReport(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasSleepWake(new ReplayedPc(rec)), "This recording has no sleep and wake answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, Problems, maxRows: 1, ("powercfg", pc => pc.SleepWake()));
    }

    private static IEnumerable<string> Problems(DiagnosticResult r) => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"];
}
