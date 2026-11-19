using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

/// <summary>Process-tree rollup and live CPU/disk sampling behind the "Top apps" card of Resource hogs.</summary>
public class ProcessTreeTests
{
    private const long MB = 1024 * 1024;
    private const long GB = 1024 * MB;

    private static ProcessResourceRow P(string name, int pid, int parent, long start = 1000, long ws = 100 * MB, long cpuMs = 1000, long disk = 0, long priv = 50 * MB) =>
        new(name, pid, ws, cpuMs, disk, parent, start, priv);

    /// <summary>A fake process table: Windows shell and services, Chrome with helpers, Teams with web views, and a service-started app.</summary>
    private static List<ProcessResourceRow> Table() =>
    [
        P("wininit.exe", 500, 400, start: 10),
        P("services.exe", 600, 500, start: 11),
        P("svchost.exe", 700, 600, start: 12, ws: 900 * MB),
        P("explorer.exe", 1000, 900, start: 20, ws: 200 * MB), // parent 900 (userinit) already exited
        P("chrome.exe", 2000, 1000, start: 100, ws: 400 * MB),
        P("chrome.exe", 2001, 2000, start: 101, ws: 1 * GB),
        P("chrome.exe", 2002, 2000, start: 102, ws: 2 * GB),
        P("crashpad_handler.exe", 2003, 2000, start: 103, ws: 10 * MB),
        P("ms-teams.exe", 3000, 1000, start: 200, ws: 300 * MB),
        P("msedgewebview2.exe", 3001, 3000, start: 201, ws: 250 * MB),
        P("msedgewebview2.exe", 3002, 3001, start: 202, ws: 150 * MB),
        P("msedgewebview2.exe", 3003, 3001, start: 203, ws: 150 * MB),
        P("SearchHost.exe", 4000, 700, start: 300, ws: 80 * MB), // started by svchost: its own app
        P("WmiPrvSE.exe", 4100, 700, start: 301, ws: 20 * MB),
    ];

    [Fact]
    public void RollUp_AttributesHelpersToTheTopLevelApp()
    {
        var apps = ProcessTree.RollUp(Table()).ToDictionary(a => a.Name, StringComparer.OrdinalIgnoreCase);

        var chrome = apps["chrome.exe"];
        Assert.Equal(4, chrome.ProcessCount);
        Assert.Equal(2000, chrome.RootPid);
        Assert.Equal(400 * MB + 3 * GB + 10 * MB, chrome.WorkingSetBytes);
        Assert.Equal(4 * 50 * MB, chrome.PrivateBytes);
        Assert.Equal("Includes crashpad_handler.exe.", chrome.HelpersText);

        // Teams' web views (two levels deep) belong to Teams, not to a separate msedgewebview2.exe entry.
        var teams = apps["ms-teams.exe"];
        Assert.Equal(4, teams.ProcessCount);
        Assert.Equal("Includes msedgewebview2.exe (3).", teams.HelpersText);
        Assert.False(apps.ContainsKey("msedgewebview2.exe"));

        // The walk stops at Explorer and the service hosts: apps aren't folded into explorer.exe or services.exe.
        Assert.Equal(1, apps["explorer.exe"].ProcessCount);
        Assert.Equal(1, apps["SearchHost.exe"].ProcessCount);
        Assert.Equal(1, apps["WmiPrvSE.exe"].ProcessCount);
        Assert.Equal(1, apps["services.exe"].ProcessCount);
        Assert.False(apps.ContainsKey("svchost.exe")); // hidden, as in the per-name list
    }

    [Fact]
    public void RollUp_ReusedParentPid_IsNotTreatedAsTheParent()
    {
        // Notepad's real parent (pid 5000) exited and the PID now belongs to Code, which started later.
        List<ProcessResourceRow> rows =
        [
            P("explorer.exe", 1000, 0, start: 20),
            P("Code.exe", 5000, 1000, start: 900),
            P("notepad.exe", 5100, 5000, start: 500),
        ];
        var apps = ProcessTree.RollUp(rows).ToDictionary(a => a.Name);
        Assert.Equal(1, apps["Code.exe"].ProcessCount);
        Assert.Equal(1, apps["notepad.exe"].ProcessCount);
    }

    [Fact]
    public void RollUp_ParentLoopAndMissingStartTimes_Terminate()
    {
        List<ProcessResourceRow> rows = [P("a.exe", 1, 2, start: 0), P("b.exe", 2, 1, start: 0), P("c.exe", 3, 3, start: 0)];
        var apps = ProcessTree.RollUp(rows);
        Assert.Equal(3, apps.Sum(a => a.ProcessCount));
        Assert.Contains(apps, a => a.Name == "c.exe");
    }

    [Fact]
    public void RollUp_SeparateTreesWithTheSameAppName_AreCombined()
    {
        List<ProcessResourceRow> rows =
        [
            P("explorer.exe", 1000, 0, start: 20),
            P("chrome.exe", 2000, 1000, start: 100, ws: 100 * MB),
            P("chrome.exe", 2001, 2000, start: 101),
            P("chrome.exe", 2500, 1000, start: 150, ws: 300 * MB), // a second Chrome profile, started on its own
            P("chrome.exe", 2501, 2500, start: 151),
        ];
        var chrome = Assert.Single(ProcessTree.RollUp(rows), a => a.Name == "chrome.exe");
        Assert.Equal(4, chrome.ProcessCount);
        Assert.Equal(2500, chrome.RootPid); // the bigger root represents the app
        Assert.Null(chrome.HelpersText);
    }

    [Fact]
    public void Rates_AreShareOfTheWholePc_AndSkipReusedPids()
    {
        List<ProcessResourceRow> before = [P("a.exe", 1, 0, start: 10, cpuMs: 1_000, disk: 0), P("b.exe", 2, 0, start: 10, cpuMs: 5_000), P("c.exe", 3, 0, start: 10)];
        List<ProcessResourceRow> after =
        [
            P("a.exe", 1, 0, start: 10, cpuMs: 5_000, disk: 20 * MB), // 4 s CPU in 2 s on 4 cores = 50%
            P("b.exe", 2, 0, start: 10, cpuMs: 5_000),                // idle
            P("x.exe", 3, 0, start: 99, cpuMs: 99_000),               // PID 3 reused: not compared with c.exe
            P("new.exe", 4, 0, start: 99),                            // started during the sample
        ];
        var rates = ProcessTree.Rates(before, after, TimeSpan.FromSeconds(2), logicalCores: 4);
        Assert.Equal(50, rates[1].CpuPercent, precision: 3);
        Assert.Equal(10 * MB, rates[1].DiskBytesPerSecond);
        Assert.Equal(0, rates[2].CpuPercent);
        Assert.False(rates.ContainsKey(3));
        Assert.False(rates.ContainsKey(4));
        Assert.Empty(ProcessTree.Rates(before, after, TimeSpan.Zero, 4));
    }

    [Fact]
    public void AppsCard_WithSample_ShowsCpuNow_AndWarnsOnABusyApp()
    {
        var rows = Table();
        var rates = new Dictionary<int, ProcessRate>
        {
            [3000] = new(5, 0), [3001] = new(30, 1 * MB), [3002] = new(20, 0), // Teams tree: 55% in total
            [2002] = new(2, 0),
        };
        var report = ResourceHogsModule.Build(null, rows, rates: rates);
        var card = report.Cards.Single(c => c.Id == "apps");
        Assert.Equal(["App", "Processes", "CPU now", "Memory", "Private memory", "Disk now"], card.Columns);
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Contains("Busiest now: ms-teams.exe (55% CPU)", card.Meta);
        Assert.Equal("chrome.exe (3.4 GB)", card.Headline);

        var teams = card.Rows.Single(r => r.Values[0] == "ms-teams.exe");
        Assert.Equal(AreaLevel.Warning, teams.Level);
        Assert.Equal("55%", teams.Values[2]);
        Assert.Equal("1 MB/s", teams.Values[5]);
        Assert.Equal("Includes msedgewebview2.exe (3).", teams.Detail);
        var endTask = Assert.Single(teams.Actions!);
        Assert.Equal(RemediationKind.EndProcessGroup, endTask.Kind);
        Assert.Equal("ms-teams.exe", endTask.Target);

        // Sorting by the CPU column uses the numeric key.
        Assert.Equal("ms-teams.exe", AreaSort.Sort(card.Rows, 2, descending: true)[0].Values[0]);

        // The existing per-name cards are unchanged and still list each executable on its own.
        var memCard = report.Cards.Single(c => c.Id == "memory");
        Assert.Equal(["App", "Instances", "Memory", "CPU time", "Disk I/O"], memCard.Columns);
        Assert.Contains(memCard.Rows, r => r.Values[0] == "msedgewebview2.exe" && r.Values[1] == "3");
    }

    [Fact]
    public void AppsCard_WithoutSample_ShowsCumulativeTotals()
    {
        var card = ResourceHogsModule.Build(null, Table()).Cards.Single(c => c.Id == "apps");
        Assert.Equal(["App", "Processes", "Memory", "Private memory", "CPU time", "Disk I/O"], card.Columns);
        Assert.Equal("chrome.exe", card.Rows[0].Values[0]);
        Assert.Equal("4", card.Rows[0].Values[1]);
        Assert.Contains("process", card.Meta);
    }

    [Fact]
    public void CommitCard_ComparesCommitChargeWithInstalledRam()
    {
        var up = new SystemUptimeInfo(3600, 0, 1, 0, false);
        var over = new MemoryUse(15 * GB, 4 * GB)
        {
            CommitUsedBytes = 20 * GB, CommitLimitBytes = 32 * GB, InstalledBytes = 16 * GB, PagefileUsedBytes = 3 * GB, PagefileSizeBytes = 16 * GB,
        };
        var card = ResourceHogsModule.Build(up, [], over).Cards.Single(c => c.Id == "commit");
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.Equal("20 GB committed", card.Headline);
        Assert.Contains(card.Rows, r => r.Values[0] == "Installed RAM" && r.Values[1] == "16 GB");
        Assert.Contains(card.Rows, r => r.Values[0] == "Page file in use" && r.Values[1] == "3 GB of 16 GB");
        Assert.Contains("page file on disk", card.Rows[^1].Values[1]);

        var nearLimit = new MemoryUse(15 * GB, 1 * GB) { CommitUsedBytes = 30 * GB, CommitLimitBytes = 32 * GB, PagefileSizeBytes = 0 };
        var warn = ResourceHogsModule.Build(up, [], nearLimit).Cards.Single(c => c.Id == "commit");
        Assert.Equal(AreaLevel.Warning, warn.Level);
        Assert.Contains(warn.Rows, r => r.Values[0] == "Usable RAM");
        Assert.Contains(warn.Rows, r => r.Values[0] == "Page file" && r.Values[1] == "None");
        Assert.Contains("out of memory", warn.Rows[^1].Values[1]);

        // Not reported (older agent script, or a non-Windows test host): no card.
        Assert.DoesNotContain(ResourceHogsModule.Build(up, [], new MemoryUse(10 * GB, 6 * GB)).Cards, c => c.Id == "commit");
    }

    [Fact]
    public void ProcessRow_ReadsParentStartTimeAndPrivateBytes()
    {
        var row = ProcessResourceRow.FromRow(new Dictionary<string, string>
        {
            ["pid"] = "42", ["parent"] = "7", ["name"] = "app.exe", ["start_time"] = "1763500000", ["resident_size"] = "1000", ["total_size"] = "2000",
            ["user_time"] = "10", ["system_time"] = "5", ["disk_bytes_read"] = "1", ["disk_bytes_written"] = "2",
        });
        Assert.Equal(new ProcessResourceRow("app.exe", 42, 1000, 15, 3, 7, 1763500000, 2000), row);
        Assert.Contains("parent", ResourceUsage.ProcessesSql);
        Assert.Contains("total_size", ResourceUsage.ProcessesSql);
        Assert.Contains("Win32_PageFileUsage", ResourceHogsModule.FastStartupScript);
    }

    [Fact]
    public async Task Module_TakesTwoSnapshots_AndReportsCpuNow()
    {
        const string uptimeJson = """[{"days":"0","hours":"2","minutes":"0","total_seconds":"7200"}]""";
        static string Procs(long chromeCpu) => $$"""
        [
          {"pid":"1000","parent":"900","name":"explorer.exe","start_time":"20","resident_size":"104857600","total_size":"52428800","user_time":"0","system_time":"0","disk_bytes_read":"0","disk_bytes_written":"0"},
          {"pid":"2000","parent":"1000","name":"chrome.exe","start_time":"100","resident_size":"524288000","total_size":"262144000","user_time":"{{chromeCpu}}","system_time":"0","disk_bytes_read":"0","disk_bytes_written":"0"},
          {"pid":"2001","parent":"2000","name":"chrome.exe","start_time":"101","resident_size":"524288000","total_size":"262144000","user_time":"0","system_time":"0","disk_bytes_read":"0","disk_bytes_written":"0"}
        ]
        """;
        var procCalls = 0;
        var launcher = new ScriptedLauncher((file, args) =>
        {
            if (!file.StartsWith("osqueryi", StringComparison.OrdinalIgnoreCase)) return ScriptedLauncher.Ok("""{"FastStartup":"0"}""");
            var sql = args[^1];
            if (sql.Contains("uptime")) return ScriptedLauncher.Ok(uptimeJson);
            return ScriptedLauncher.Ok(Procs(Interlocked.Increment(ref procCalls) == 1 ? 0 : 1_000_000));
        });
        var module = new ResourceHogsModule(ScriptedLauncher.Osquery(launcher), new SystemCommandRunner(launcher), sampleWindow: TimeSpan.FromMilliseconds(20));
        var rep = Assert.IsType<AreaReport>((await module.RefreshAsync(null)).Payload);

        Assert.Equal(2, procCalls);
        var card = rep.Cards.Single(c => c.Id == "apps");
        Assert.Equal("CPU now", card.Columns[2]);
        var chrome = card.Rows.Single(r => r.Values[0] == "chrome.exe");
        Assert.Equal("2", chrome.Values[1]);
        Assert.NotEqual("0%", chrome.Values[2]); // CPU time grew between the snapshots
    }
}
