using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Checks;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

public class JsonCheckTests
{
    private static string SamplePath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "RemotePCDiagnostics.sln"))) dir = dir.Parent;
        return Path.Combine(dir!.FullName, "samples", "checks", "windows-update-service.json");
    }

    private static IReadOnlyDictionary<string, string> Row(params (string K, string V)[] kv) => kv.ToDictionary(x => x.K, x => x.V);

    [Fact]
    public void The_sample_check_parses_and_is_valid()
    {
        var c = JsonCheck.Parse(File.ReadAllText(SamplePath()));
        Assert.Null(c.Problem());
        Assert.Equal(ModuleGroups.Windows, c.Group);
        Assert.Equal(AreaLevel.Warning, c.EmptyLevel);
        Assert.Equal(ModuleKind.Check, c.ToDescriptor().Kind);
    }

    [Theory]
    [InlineData("DELETE FROM x", "must be a SELECT")]
    [InlineData("SELECT1 FROM x", "must be a SELECT")]
    [InlineData("WITHOUT ROWID", "must be a SELECT")]
    [InlineData("SELECT 1; SELECT 2", "one statement")]
    [InlineData("SELECT * FROM curl WHERE url = 'http://x'", "may not use")]
    [InlineData("SELECT * FROM main.curl WHERE url = 'http://x'", "may not use")]
    [InlineData("SELECT * FROM \"curl\" WHERE url = 'http://x'", "may not use")]
    [InlineData("WITH a AS (SELECT 1) SELECT * FROM a", null)]
    [InlineData("WITH\r\n  a AS (SELECT 1)\r\nSELECT * FROM a", null)]
    [InlineData("SELECT\n  *\nFROM services;", null)]
    [InlineData("SELECT\t*\tFROM services", null)]
    [InlineData("SELECT * FROM services;", null)]
    public void Only_a_single_read_only_select_is_accepted(string query, string? problem)
    {
        var c = JsonCheck.Parse(File.ReadAllText(SamplePath())) with { Query = query };
        if (problem is null) Assert.Null(c.Problem());
        else Assert.Contains(problem, c.Problem());
    }

    [Fact]
    public void Rows_take_the_worst_rule_they_match()
    {
        var c = JsonCheck.Parse(File.ReadAllText(SamplePath()));
        var report = c.Evaluate([
            Row(("display_name", "Windows Update"), ("status", "STOPPED"), ("start_type", "DISABLED")),
            Row(("display_name", "BITS"), ("status", "RUNNING"), ("start_type", "AUTO_START")),
        ]);
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Equal("1 problem", report.Summary);
        var card = Assert.Single(report.Cards);
        Assert.Equal(["Service", "Status", "Start type"], card.Columns);
        Assert.Equal(AreaLevel.Error, card.Rows[0].Level);
        Assert.Contains("can't install updates", card.Rows[0].Detail);
        Assert.Equal(AreaLevel.Ok, card.Rows[1].Level);

        Assert.Equal("Update services can start", c.Evaluate([Row(("start_type", "AUTO_START"))]).Summary);
        Assert.Equal(DiagnosticStatus.Warning, c.Evaluate([]).Status);
    }

    [Theory]
    [InlineData("gt", "80", "90", true)]
    [InlineData("gt", "80", "70", false)]
    [InlineData("le", "5", "5", true)]
    [InlineData("contains", "err", "Some ERROR here", true)]
    [InlineData("notcontains", "err", "fine", true)]
    [InlineData("empty", null, "", true)]
    [InlineData("notEmpty", null, "x", true)]
    [InlineData("gt", "80", "n/a", false)]
    public void Rule_ops(string op, string? value, string cell, bool matches) =>
        Assert.Equal(matches, new JsonCheckRule { Column = "c", Op = op, Value = value }.Matches(Row(("c", cell))));

    [Fact]
    public async Task The_module_runs_the_query_and_reports()
    {
        var c = JsonCheck.Parse(File.ReadAllText(SamplePath()));
        string? asked = null;
        var module = new JsonCheckModule(c, (sql, _) =>
        {
            asked = sql;
            return Task.FromResult(new OsqueryQueryResult(sql, [Row(("display_name", "Windows Update"), ("start_type", "DISABLED"))], null));
        });
        var r = await new DiagnosticsService(new ResultStore(), [module]).RunAsync(c.Slug);
        Assert.Equal(c.Query, asked);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.IsType<AreaReport>(r.Payload);

        var failing = new JsonCheckModule(c, (sql, _) => Task.FromResult(new OsqueryQueryResult(sql, null, "no such table")));
        Assert.Contains("no such table", (await failing.RefreshAsync(null)).Message);
    }

    [Fact]
    public void Loading_a_folder_skips_bad_and_duplicate_checks()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpcd-checks-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var sample = File.ReadAllText(SamplePath());
            File.WriteAllText(Path.Combine(dir, "a.json"), sample);
            File.WriteAllText(Path.Combine(dir, "b.json"), sample); // same id
            File.WriteAllText(Path.Combine(dir, "c.json"), "{ not json");
            File.WriteAllText(Path.Combine(dir, "d.json"), sample.Replace("0b6f6a43-8c1d-4f33-9a59-2f0c1e2d7b10", ModuleIds.Services.ToString("D")).Replace("sample.windows-update-service", "sample.other"));
            var ids = BuiltInModules.Descriptors.ToDictionary(d => d.Id, d => d.Slug);
            var problems = new List<(string File, string Problem)>();
            var checks = JsonCheckModule.LoadFolder(dir, ids, new HashSet<string>(StringComparer.OrdinalIgnoreCase), problems);
            Assert.Single(checks);
            Assert.Equal(3, problems.Count);
            Assert.Contains(problems, p => p.File.EndsWith("d.json") && p.Problem.Contains(ModuleSlugs.Services));
        }
        finally { Directory.Delete(dir, true); }
    }
}
