using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>DriveHealth replayed from recorded PCs: snapshots, the WMI and PowerShell paths agreeing, damaged answers, and known failures.</summary>
public sealed class DriveHealthReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasDrives(ReplayedPc pc) => pc.Has(c => c.Query == DriveReader.DiskSql);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasDrives(pc), "This recording has no drive answers.");
        var result = await pc.DriveHealth().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "DriveHealth", result);
    }

    /// <summary>WMI reads the same drives, health and counters as the Get-PhysicalDisk script it replaces.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndPowerShellAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasDrives(pc) && pc.Has(c => c.Args?.LastOrDefault() == PowerShellDriveSource.Script),
            "This recording doesn't hold both the WMI and the PowerShell drive answers.");
        var ct = TestContext.Current.CancellationToken;
        var wmi = await DriveReader.ReadWmiAsync(pc.Wmi, ct);
        var ps = await pc.Commands.RunPowerShellAsync(PowerShellDriveSource.Script, ct);
        Assert.NotNull(wmi);
        Assert.Equal(0, ps?.ExitCode);
        var old = Core.Osquery.OsqueryJson.ParseRows(ps!.StdOut).Select(DriveHealth.FromRow).ToList();
        Assert.Equal(old.Select(Describe), wmi.Select(Describe));

        var newReport = Normalized(await pc.DriveHealth().RefreshAsync(null, ct));
        var oldReport = Normalized(await new ReplayedPc(rec).DriveHealthOld().RefreshAsync(null, ct));
        Assert.Equal(oldReport, newReport);

        static string Describe(DriveHealth d) => string.Join(" | ", d.Name, d.Serial, d.MediaType, d.BusType, d.Health, d.Operational, d.SizeBytes,
            d.TemperatureC, d.Wear, d.ReadErrors, d.WriteErrors, d.PowerOnHours, d.Letters, d.UniqueId);
        static string Normalized(DiagnosticResult r) => Snapshot.Normalize(r);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var ct = TestContext.Current.CancellationToken;
        var source = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasDrives(new ReplayedPc(source)), "This recording has no drive answers.");
        var failures = new List<string>();
        var variants = 0;
        foreach (var (fault, rec) in FaultInjector.Variants(source))
        {
            foreach (var (path, module) in new[] { ("WMI", new ReplayedPc(rec).DriveHealth()), ("PowerShell", new ReplayedPc(rec).DriveHealthOld()) })
            {
                variants++;
                try
                {
                    var r = await module.RefreshAsync(null, ct);
                    failures.AddRange(Problems(r).Select(p => $"{path}, {fault}: {p}"));
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failures.Add($"{path}, {fault}: threw {ex.GetType().Name}: {ex.Message}");
                }
            }
        }
        Assert.True(variants > 50, $"only {variants} damaged variants");
        Assert.True(failures.Count == 0, $"{failures.Count} of {variants} damaged runs went wrong:\n" + string.Join("\n", failures.Take(40)));
    }

    private static IEnumerable<string> Problems(DiagnosticResult r)
    {
        if (r.Payload is not AreaReport report) { yield return "no report"; yield break; }
        foreach (var card in report.Cards)
        {
            if (string.IsNullOrWhiteSpace(card.Headline) && card.ErrorText is null) yield return $"card {card.Id} has no headline";
            foreach (var row in card.Rows)
            {
                // Text Windows reports (serial, connection, its health word) is shown as it came; numbers must be sane.
                var asReported = row.Values[0] is "Serial number" or "Connection" or "Status reported by Windows";
                foreach (var v in row.Values.Skip(1))
                    if (v.Contains("NaN") || v.Contains("Infinity") || v.Contains('\0') || (!asReported && v.StartsWith('-')))
                        yield return $"{card.Id}: {row.Values[0]} \"{v}\"";
            }
        }
        foreach (var m in report.KeyMetrics ?? [])
            if (!double.IsFinite(m.Value) || m.Value < 0) yield return $"metric {m.Id} = {m.Value}";
    }

    // Known failures, made from the sample recording.

    private static MachineRecording Sample => RecordingLibrary.Load("sample/sample-laptop");

    private static async Task<DiagnosticResult> Run(MachineRecording rec) =>
        await new ReplayedPc(rec).DriveHealth().RefreshAsync(null, TestContext.Current.CancellationToken);

    [Fact]
    public async Task FailingDrive_IsAnError()
    {
        var r = await Run(Sample.SetWmi("FROM MSFT_PhysicalDisk", "HealthStatus", 2));
        Assert.Equal(DiagnosticStatus.Error, r.Status);
    }

    [Theory]
    [InlineData("Wear", 95)]
    [InlineData("Temperature", 72)]
    [InlineData("ReadErrorsUncorrected", 4)]
    public async Task WornHotOrErroringDrive_IsAWarning(string counter, int value)
    {
        var r = await Run(Sample.SetWmi("StorageReliabilityCounter", counter, value));
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
    }

    [Fact]
    public async Task CountersRefused_StillListsTheDriveWithItsHealth()
    {
        var r = await Run(Sample.FailWmi("StorageReliabilityCounter", "Access denied"));
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Contains("SAMPLE NVMe SSD", Snapshot.Normalize(r));
    }

    [Fact]
    public async Task NoStorageWmi_FallsBackToTheDriveList()
    {
        var r = await new ReplayedPc(Sample.FailWmi("FROM MSFT_PhysicalDisk", "Not supported")).DriveHealth().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.NotNull(r.Payload);
    }
}
