using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Security;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public sealed class SecurityAuditTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpd-sa-test-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> _log = new();
    private string ReportPath => Path.Combine(_dir, "report.csv");

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    public const string SampleCsv =
        "\"ID\",\"Category\",\"Name\",\"Severity\",\"Result\",\"Recommended\",\"TestResult\",\"SeverityFinding\",\"DefaultValue\",\"Filter\"\r\n" +
        "\"1000\",\"Features\",\"SMBv1 Support\",\"Passed\",\"Disabled\",\"Disabled\",\"Passed\",\"High\",\"Disabled\",\"\"\r\n" +
        "\"1103\",\"Account Policies\",\"Store passwords using reversible encryption\",\"High\",\"1\",\"0\",\"Failed\",\"High\",\"0\",\"\"\r\n" +
        "\"1200\",\"User Rights\",\"Name with, comma and \"\"quotes\"\"\",\"Low\",\"\",\"BUILTIN\\Administrators\",\"Failed\",\"Low\",\"\",\"\"\r\n" +
        "\"1300\",\"Misc\",\"Multi\nline\",\"Medium\",\"2\",\"1\",\"Failed\",\"Medium\",\"\",\"\"\r\n" +
        "\"1400\",\"Misc\",\"Unknown\",\"\",\"\",\"\",\"\",\"\",\"\",\"\"\r\n";

    private SecurityAuditModule Module(IProcessLauncher l, bool admin = true, bool toolPresent = true, bool psPresent = true, TimeSpan? timeout = null) =>
        new(new SecurityAuditOptions
        {
            ModuleFolder = Path.Combine(_dir, "hk"), PowerShellPath = Path.Combine(_dir, "powershell.exe"),
            FileExists = p => p.EndsWith(".psd1") ? toolPresent : p.EndsWith("powershell.exe") ? psPresent : File.Exists(p),
            ReportPathFactory = () => ReportPath, IsAdministrator = () => admin,
            Timeout = timeout ?? TimeSpan.FromMinutes(5), Log = new LineLogger(s => { lock (_log) _log.Add(s); }),
        }, l);

    private ScriptedLauncher WritesReport(string csv) => new((_, args) =>
    {
        Assert.Contains("Bypass", args);
        var script = args[^1];
        Assert.Contains("Invoke-HardeningKitty -Mode Audit -Report -ReportFile", script);
        File.WriteAllText(ReportPath, csv);
        return ScriptedLauncher.Ok("lots of raw output C:\\secret\\path");
    });

    private static void AssertFriendly(string msg)
    {
        Assert.DoesNotContain(":\\", msg);
        Assert.DoesNotContain("exit", msg, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("powershell.exe", msg, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HardeningKitty", msg);
    }

    [Fact]
    public void Csv_parses_quotes_commas_newlines_and_classifies()
    {
        var f = HardeningKittyCsv.Parse(SampleCsv);
        Assert.Equal(5, f.Count);
        Assert.Equal(AuditOutcome.Passed, f[0].Outcome);
        Assert.Equal("High", f[0].Severity);
        Assert.Equal(AuditOutcome.Failed, f[1].Outcome);
        Assert.Equal("1", f[1].CurrentValue);
        Assert.Equal("0", f[1].RecommendedValue);
        Assert.Equal("Account Policies", f[1].Category);
        Assert.Equal("Name with, comma and \"quotes\"", f[2].Name);
        Assert.Equal(AuditOutcome.Warning, f[2].Outcome);
        Assert.Equal("Multi\nline", f[3].Name);
        Assert.Equal(AuditOutcome.Failed, f[3].Outcome);
        Assert.Equal(AuditOutcome.NotChecked, f[4].Outcome);
    }

    [Fact]
    public void Csv_with_bom_and_missing_columns()
    {
        Assert.Single(HardeningKittyCsv.Parse("\uFEFFID,Name,TestResult\n1,x,Passed\n"));
        Assert.Throws<FormatException>(() => HardeningKittyCsv.Parse("Foo,Bar\n1,2\n"));
        Assert.Empty(HardeningKittyCsv.Parse(""));
    }

    [Fact]
    public void Arguments_bypass_policy_for_process_only_and_escape_quotes()
    {
        var a = SecurityAuditModule.BuildArguments(@"C:\a'b\HardeningKitty.psd1", @"C:\t\r.csv");
        Assert.Equal(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"], a.Take(5));
        Assert.Contains(@"Import-Module -Name 'C:\a''b\HardeningKitty.psd1'", a[5]);
        Assert.Contains("-Mode Audit", a[5]);
        Assert.DoesNotContain("Set-ExecutionPolicy", a[5]);
    }

    [Fact]
    public async Task Run_parses_report_into_summary()
    {
        var m = Module(WritesReport(SampleCsv));
        Assert.True((await m.CheckAvailabilityAsync()).IsAvailable);
        var r = await m.RefreshAsync(null);
        var rep = Assert.IsType<SecurityAuditReport>(r.Payload);
        Assert.Equal((1, 1, 2, 1), (rep.Passed, rep.Warnings, rep.Failed, rep.NotChecked));
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal("1 high-risk · 2 failed, 1 warning, 1 passed, 1 not checked", r.Message);
        Assert.Null(rep.Notice);
        Assert.Contains(_log, l => l.Contains("stdout_head"));
    }

    [Fact]
    public async Task Non_admin_still_runs_with_friendly_notice()
    {
        var r = await Module(WritesReport(SampleCsv), admin: false).RefreshAsync(null);
        var rep = Assert.IsType<SecurityAuditReport>(r.Payload);
        Assert.Equal(SecurityAuditModule.NotAdminNotice, rep.Notice);
        AssertFriendly(rep.Notice!);
    }

    [Fact]
    public async Task Missing_tool_or_powershell_is_friendly_and_logged()
    {
        var l = new ScriptedLauncher((_, _) => throw new InvalidOperationException("should not run"));
        var a = await Module(l, toolPresent: false).CheckAvailabilityAsync();
        Assert.False(a.IsAvailable);
        Assert.Equal(SecurityAuditModule.ToolMissingMessage, a.Reason);
        Assert.Contains(_log, x => x.Contains("HardeningKitty.psd1"));
        var b = await Module(l, psPresent: false).CheckAvailabilityAsync();
        Assert.Equal(SecurityAuditModule.PowerShellMissingMessage, b.Reason);
        AssertFriendly(a.Reason!); AssertFriendly(b.Reason!);

        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [Module(l, toolPresent: false)]);
        var res = await svc.RunAsync(SecurityAuditModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Error, res.Status);
        Assert.Equal(SecurityAuditModule.ToolMissingMessage, res.Message);
        Assert.Empty(l.Calls);
    }

    [Fact]
    public async Task Timeout_is_reported_friendly()
    {
        TimeSpan seen = default;
        var l = new DelegateLauncher((_, _, t, _) => { seen = t; return Task.FromResult(new ProcessResult(-1, "", "", TimedOut: true)); });
        var r = await Module(l, timeout: TimeSpan.FromMinutes(5)).RefreshAsync(null);
        Assert.Equal(TimeSpan.FromMinutes(5), seen);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Contains("longer than 5 minutes", r.Message);
        AssertFriendly(r.Message);
    }

    [Fact]
    public void Default_timeout_is_five_minutes() => Assert.Equal(TimeSpan.FromMinutes(5), new SecurityAuditOptions().Timeout);

    [Fact]
    public async Task Cancel_stops_run_via_token()
    {
        var started = new TaskCompletionSource();
        var l = new DelegateLauncher(async (_, _, _, ct) => { started.SetResult(); await Task.Delay(Timeout.Infinite, ct); return new ProcessResult(0, "", ""); });
        var m = Module(l);
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);
        var run = svc.RunAsync(SecurityAuditModule.ModuleName);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(DiagnosticStatus.Running, store.Get(m.Name).Status);
        m.Cancel();
        var r = await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal(SecurityAuditModule.CancelledMessage, r.Message);
        Assert.Equal(SecurityAuditModule.CancelledMessage, store.Get(m.Name).Message);
    }

    [Fact]
    public async Task Process_failure_or_bad_report_is_friendly()
    {
        var noReport = await Module(new ScriptedLauncher((_, _) => ScriptedLauncher.Fail("Import-Module : not found C:\\x"))).RefreshAsync(null);
        Assert.Equal(SecurityAuditModule.FailedMessage, noReport.Message);
        var garbage = await Module(WritesReport("nonsense\n1\n")).RefreshAsync(null);
        Assert.Equal(SecurityAuditModule.FailedMessage, garbage.Message);
        var throws = await Module(new DelegateLauncher((_, _, _, _) => throw new System.ComponentModel.Win32Exception("nope"))).RefreshAsync(null);
        Assert.Equal(SecurityAuditModule.FailedMessage, throws.Message);
        Assert.Contains(_log, x => x.Contains("not found C:\\x"));
    }

    [Fact]
    public async Task Not_part_of_run_all()
    {
        var l = new ScriptedLauncher((_, _) => throw new InvalidOperationException("should not run"));
        var m = Module(l);
        Assert.False(((IDiagnosticModule)m).IncludeInRunAll);
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m, new FakeModule("Other", _ => Task.FromResult(FakeModule.Ok("Other")))]);
        var all = await svc.RunAllAsync();
        Assert.Single(all);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get(m.Name).Status);
        Assert.Empty(l.Calls);
    }

    [Fact]
    public async Task Real_launcher_cancel_kills_process_tree()
    {
        if (!OperatingSystem.IsWindows()) return; // CI runs on windows-latest
        var ps = Core.Areas.SystemCommandRunner.PowerShell;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SystemProcessLauncher().RunAsync(ps, ["-NoProfile", "-Command", "Start-Sleep -Seconds 120"], TimeSpan.FromMinutes(5), cts.Token));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30));
        var t = await new SystemProcessLauncher().RunAsync(ps, ["-NoProfile", "-Command", "Start-Sleep -Seconds 120"], TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert.True(t.TimedOut);
    }
}

internal sealed class DelegateLauncher(Func<string, IReadOnlyList<string>, TimeSpan, CancellationToken, Task<ProcessResult>> run) : IProcessLauncher
{
    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct) => run(fileName, arguments, timeout, ct);
}
