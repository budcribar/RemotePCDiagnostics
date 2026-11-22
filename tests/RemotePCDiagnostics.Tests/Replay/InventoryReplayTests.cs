using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

// The four checks that moved from osquery (and one PowerShell script) to WMI and the registry, replayed from recorded PCs: each matches its
// approved snapshot, shows what the old path showed on the same PC at the same moment, and survives damaged answers. A recording made before
// the recorder knew a check skips that check's tests.

/// <summary>Hardware inventory (the Osquery check).</summary>
public sealed class HardwareInventoryReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiHardwareInventorySource.ComputerSql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(HardwareInventory.SystemSql);

    internal static AreaReport Report(DiagnosticResult r) => HardwareInventoryReport.Build((HardwareInventory)r.Payload!, r.Status, r.Message);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI hardware answers.");
        var result = await pc.Inventory().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Osquery", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery hardware answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = Report(await pc.Inventory().RefreshAsync(null, ct));
        var old = Report(await new ReplayedPc(rec).InventoryOld().RefreshAsync(null, ct));
        var diffs = ReportDiff.Between(old, now, Live);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    /// <summary>The processor's load and current clock change from moment to moment; the two paths read them seconds apart.</summary>
    private static bool Live(AreaCard card, AreaRow row) =>
        row.Values.Count > 0 && (row.Values[0].Contains("load", StringComparison.OrdinalIgnoreCase) || row.Values[0].Contains("current", StringComparison.OrdinalIgnoreCase));

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI hardware answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => DamagedRuns.CommonProblems(Report(r)), maxRows: 3,
            ("WMI", pc => pc.Inventory()), ("osquery", pc => pc.InventoryOld()));
    }
}

/// <summary>Services.</summary>
public sealed class ServicesReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiServiceSource.Sql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(OsqueryServiceSource.Sql);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI services answer.");
        var result = await pc.Services().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Services", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery services answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = (AreaReport)(await pc.Services().RefreshAsync(null, ct)).Payload!;
        var old = (AreaReport)(await new ReplayedPc(rec).ServicesOld().RefreshAsync(null, ct)).Payload!;
        var diffs = ReportDiff.Between(old, now);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI services answer.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI", pc => pc.Services()), ("osquery", pc => pc.ServicesOld()));
    }
}

/// <summary>Device Manager and drivers.</summary>
public sealed class DeviceDriversReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiDeviceDriverSource.DriversSql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(OsqueryDeviceDriverSource.DriversSql);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI driver answers.");
        var result = await pc.DeviceDrivers().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "DeviceDrivers", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery driver answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = (AreaReport)(await pc.DeviceDrivers().RefreshAsync(null, ct)).Payload!;
        var old = (AreaReport)(await new ReplayedPc(rec).DeviceDriversOld().RefreshAsync(null, ct)).Payload!;
        var diffs = ReportDiff.Between(old, now);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI driver answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI", pc => pc.DeviceDrivers()), ("PowerShell + osquery", pc => pc.DeviceDriversOld()));
    }
}

/// <summary>Programs and updates.</summary>
public sealed class ProgramsReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiProgramsSource.OsSql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(OsqueryProgramsSource.ProgramsSql);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI programs answers.");
        var result = await pc.Programs().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Programs", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery programs answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = (AreaReport)(await pc.Programs().RefreshAsync(null, ct)).Payload!;
        var old = (AreaReport)(await new ReplayedPc(rec).ProgramsOld().RefreshAsync(null, ct)).Payload!;
        var diffs = ReportDiff.Between(old, now);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI programs answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI + registry", pc => pc.Programs()), ("osquery", pc => pc.ProgramsOld()));
    }
}
