using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// Resource hogs & uptime, moved from osquery and PowerShell to WMI (through the Agent) and the registry, replayed from recorded PCs: it matches
/// its approved snapshot, reads what the old path read on the same PC seconds apart, survives damaged answers, and flags known bad states.
/// A recording made before the recorder knew this check skips its tests.
/// </summary>
public sealed class ResourceHogsReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiResourceHogsSource.ProcessesSql);
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(OsqueryResourceHogsSource.ProcessesSql);

    private static AreaReport Report(DiagnosticResult r) => Assert.IsType<AreaReport>(r.Payload);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI process answers.");
        var result = await pc.ResourceHogs().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "ResourceHogs", result);
    }

    /// <summary>
    /// The two paths read seconds apart, and processes come and go and use memory and CPU all the time, so the reports can't match row for row.
    /// What must agree: the cards shown, the uptime (to within ten minutes), the memory sizes and the Fast Startup setting, and, for each process
    /// both saw, its name, parent and start, and its memory and CPU time in the same units.
    /// </summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery process answers.");
        var ct = TestContext.Current.CancellationToken;
        var diffs = new List<string>();

        var now = Report(await pc.ResourceHogs().RefreshAsync(null, ct));
        var old = Report(await new ReplayedPc(rec).ResourceHogsOld().RefreshAsync(null, ct));
        var nowCards = now.Cards.Select(c => c.Id).ToList();
        var oldCards = old.Cards.Select(c => c.Id).ToList();
        if (!nowCards.SequenceEqual(oldCards)) diffs.Add($"cards: old {string.Join(", ", oldCards)}; new {string.Join(", ", nowCards)}");

        var newSource = new WmiResourceHogsSource(new ReplayedPc(rec).Wmi, new ReplayedPc(rec).Registry);
        var oldPc = new ReplayedPc(rec);
        var oldSource = new OsqueryResourceHogsSource(oldPc.Osquery, oldPc.Commands);

        var (up, oldUp) = (await newSource.ReadUptimeAsync(ct), await oldSource.ReadUptimeAsync(ct));
        if (up is null || oldUp is null) diffs.Add($"uptime: old {oldUp?.TotalSeconds}, new {up?.TotalSeconds}");
        else if (Math.Abs(up.TotalSeconds - oldUp.TotalSeconds) > 600) diffs.Add($"uptime: old {oldUp.TotalSeconds} s, new {up.TotalSeconds} s");

        var (mem, oldMem) = (await newSource.ReadMemoryAsync(ct), await oldSource.ReadMemoryAsync(ct));
        if (mem.FastStartup != oldMem.FastStartup) diffs.Add($"Fast Startup: old {oldMem.FastStartup}, new {mem.FastStartup}");
        if (mem.Memory is not { } m || oldMem.Memory is not { } o) diffs.Add($"memory: old {oldMem.Memory is not null}, new {mem.Memory is not null}");
        else
        {
            void Same(string what, long? a, long? b) { if (a != b) diffs.Add($"{what}: old {a}, new {b}"); }
            Same("usable memory", o.TotalBytes, m.TotalBytes);
            Same("installed memory", o.InstalledBytes, m.InstalledBytes);
            Same("page file size", o.PagefileSizeBytes, m.PagefileSizeBytes);
            Same("commit limit", o.CommitLimitBytes / (64L << 20), m.CommitLimitBytes / (64L << 20)); // grows with the page file
            if (Math.Abs(o.UsedPercent - m.UsedPercent) > 10) diffs.Add($"memory in use: old {o.UsedPercent}%, new {m.UsedPercent}%");
        }

        var procs = await newSource.ReadProcessesAsync(ct);
        var oldProcs = await oldSource.ReadProcessesAsync(ct);
        Assert.NotNull(procs);
        Assert.NotNull(oldProcs);
        var byPid = procs.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
        var both = 0;
        foreach (var op in oldProcs)
        {
            // A process that ended and one that took its id later aren't the same process.
            if (!byPid.TryGetValue(op.Pid, out var np) || op.StartTime > 0 && np.StartTime > 0 && Math.Abs(op.StartTime - np.StartTime) > 2) continue;
            both++;
            var who = $"{op.Name} ({op.Pid})";
            if (!string.Equals(op.Name, np.Name, StringComparison.OrdinalIgnoreCase)) diffs.Add($"{who}: new name {np.Name}");
            if (op.ParentPid != np.ParentPid) diffs.Add($"{who}: parent old {op.ParentPid}, new {np.ParentPid}");
            // osquery as a standard user reads 0 for processes it may not open; the Agent reads them all.
            if (op.ResidentBytes > 0 && !Near(op.ResidentBytes, np.ResidentBytes, 4, 64L << 20)) diffs.Add($"{who}: memory old {op.ResidentBytes}, new {np.ResidentBytes}");
            if (op.PrivateBytes > 0 && !Near(op.PrivateBytes, np.PrivateBytes, 4, 64L << 20)) diffs.Add($"{who}: private memory old {op.PrivateBytes}, new {np.PrivateBytes}");
            if (op.CpuTimeMs > 0 && !Near(op.CpuTimeMs, np.CpuTimeMs, 2, 120_000)) diffs.Add($"{who}: CPU time old {op.CpuTimeMs} ms, new {np.CpuTimeMs} ms");
        }
        if (both < oldProcs.Count * 8 / 10) diffs.Add($"only {both} of osquery's {oldProcs.Count} processes are in WMI's list");
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs.Take(60)));
    }

    /// <summary>Within a factor of <paramref name="factor"/>, or <paramref name="slack"/> apart: a units mix-up is 1,000 or 10,000 times off.</summary>
    private static bool Near(long a, long b, double factor, long slack) =>
        Math.Abs(a - b) <= slack || b >= a / factor && b <= a * factor;

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI process answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI", pc => pc.ResourceHogs()), ("osquery", pc => pc.ResourceHogsOld()));
    }

    // Known bad states, made by editing a recording.

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task AlmostFullMemoryIsAWarning(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI process answers.");
        var total = new ReplayedPc(rec).Recording.Calls.First(c => c.Query == WmiResourceHogsSource.MemorySql).ToWmiResult().Rows![0].Long("TotalVisibleMemorySize")!.Value;
        var full = rec.SetWmi(WmiResourceHogsSource.MemorySql, "FreePhysicalMemory", total / 20);
        var report = Report(await new ReplayedPc(full).ResourceHogs().RefreshAsync(null, TestContext.Current.CancellationToken));
        var ram = report.Cards.Single(c => c.Id == "ram");
        Assert.Equal(AreaLevel.Warning, ram.Level);
        Assert.Equal("95% in use", ram.Headline);
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task NearTheCommitLimitIsAWarning(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI process answers.");
        var limit = rec.Calls.First(c => c.Query == WmiResourceHogsSource.MemorySql).ToWmiResult().Rows![0].Long("TotalVirtualMemorySize")!.Value;
        var near = rec.SetWmi(WmiResourceHogsSource.MemorySql, "FreeVirtualMemory", limit / 50);
        var commit = Report(await new ReplayedPc(near).ResourceHogs().RefreshAsync(null, TestContext.Current.CancellationToken)).Cards.Single(c => c.Id == "commit");
        Assert.Equal(AreaLevel.Warning, commit.Level);
        Assert.StartsWith("98%", commit.Meta);
    }

    /// <summary>Up three weeks with Fast Startup on: the uptime card warns and offers to turn Fast Startup off.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task LongUptimeWithFastStartupOffersToTurnItOff(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI process answers.");
        var now = CimDateTime.Parse(rec.Calls.First(c => c.Query == WmiResourceHogsSource.UptimeSql).ToWmiResult().Rows![0].Str("LocalDateTime"))!.Value;
        var bootText = Cim(now - TimeSpan.FromDays(21) - TimeSpan.FromHours(5));
        var longUp = WithFastStartup(rec.SetWmi(WmiResourceHogsSource.UptimeSql, "LastBootUpTime", bootText), 1);
        var uptime = Report(await new ReplayedPc(longUp).ResourceHogs().RefreshAsync(null, TestContext.Current.CancellationToken)).Cards.Single(c => c.Id == "uptime");
        Assert.Equal(AreaLevel.Warning, uptime.Level);
        Assert.Equal("Up 21d 5h", uptime.Headline);
        Assert.Contains(uptime.Actions!, a => a.Kind == RemediationKind.DisableFastStartup);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task FastStartupOffIsShown(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI process answers.");
        var uptime = Report(await new ReplayedPc(WithFastStartup(rec, 0)).ResourceHogs().RefreshAsync(null, TestContext.Current.CancellationToken)).Cards.Single(c => c.Id == "uptime");
        Assert.Equal("Fast Startup is off (clean shutdowns)", uptime.Meta);
    }

    /// <summary>The Agent isn't there (every WMI read fails): the check fails and says why, rather than showing an empty report as good.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task NoWmiFailsTheCheck(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI process answers.");
        var r = await new ReplayedPc(rec.FailWmi("FROM Win32_", "The Agent isn't connected.")).ResourceHogs().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("Couldn't read running processes and uptime on this PC.", r.Message);
    }

    private static string Cim(DateTimeOffset t) =>
        t.ToString("yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture) + ".000000"
        + (t.Offset < TimeSpan.Zero ? "-" : "+") + ((int)Math.Abs(t.Offset.TotalMinutes)).ToString("000", System.Globalization.CultureInfo.InvariantCulture);

    private static MachineRecording WithFastStartup(MachineRecording rec, int value) => new()
    {
        Schema = rec.Schema, Machine = rec.Machine, CapturedAt = rec.CapturedAt,
        Calls = rec.Calls.Select(c => c.Kind == RecordedCall.RegistryKind && c.Query == WmiResourceHogsSource.FastStartupRead.Describe()
            ? c with { Error = null, Rows = [new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase) { ["HiberbootEnabled"] = JsonSerializer.SerializeToElement(value) }] }
            : c).ToList(),
    };
}

/// <summary>The WMI reader's conversions, without a recording.</summary>
public sealed class WmiResourceHogsSourceTests
{
    [Fact]
    public void Reads_WMI_datetimes_with_their_offset()
    {
        Assert.Equal(new DateTimeOffset(2026, 11, 19, 6, 30, 0, TimeSpan.FromHours(-7)).AddTicks(5_000_000), CimDateTime.Parse("20261119063000.500000-420"));
        Assert.Equal(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.FromMinutes(330)), CimDateTime.Parse("20260102030405.000000+330"));
        Assert.Null(CimDateTime.Parse(""));
        Assert.Null(CimDateTime.Parse("2026****063000.500000-420"));
        Assert.Null(CimDateTime.Parse("20261119063000.500000*420"));
        Assert.Null(CimDateTime.Parse("@@ not a value ##"));
    }

    [Fact]
    public void Splits_uptime_as_osquery_does()
    {
        var up = WmiResourceHogsSource.FromSeconds(3 * 86400 + 2 * 3600 + 30 * 60 + 12);
        Assert.Equal((3, 2, 30), (up.Days, up.Hours, up.Minutes));
        Assert.Null(up.FastStartupEnabled);
    }

    [Fact]
    public async Task Converts_process_times_to_milliseconds_and_the_start_to_Unix_seconds()
    {
        var wmi = new OneAnswerWmi(WmiRow.From(new Dictionary<string, object?>
        {
            ["ProcessId"] = 7010L, ["ParentProcessId"] = 7000L, ["Name"] = "chrome.exe", ["CreationDate"] = "20261119063000.000000-420",
            ["WorkingSetSize"] = 650_117_120UL, ["PrivatePageCount"] = 566_231_040UL, ["UserModeTime"] = 3_300_000_000UL, ["KernelModeTime"] = 520_000_000UL,
            ["ReadTransferCount"] = 1000UL, ["WriteTransferCount"] = 24UL,
        }));
        var p = Assert.Single((await new WmiResourceHogsSource(wmi, new NoRegistry()).ReadProcessesAsync(TestContext.Current.CancellationToken))!);
        Assert.Equal(new ProcessResourceRow("chrome.exe", 7010, 650_117_120, 382_000, 1024, ParentPid: 7000,
            StartTime: new DateTimeOffset(2026, 11, 19, 13, 30, 0, TimeSpan.Zero).ToUnixTimeSeconds(), PrivateBytes: 566_231_040), p);
    }

    private sealed class OneAnswerWmi(WmiRow row) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) => Task.FromResult(new WmiQueryResult(wmiNamespace, wql, [row]));
    }

    private sealed class NoRegistry : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) => Task.FromResult(new WmiQueryResult(read.Location, read.Describe(), []));
    }
}
