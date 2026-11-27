using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>The audit runs in the Agent (the app never runs as administrator), or in the app with the skipped checks named.</summary>
public sealed class SecurityAuditElevatedTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpd-sae-test-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> _log = new();
    private string ReportPath => Path.Combine(_dir, "report.csv");

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    /// <summary>What HardeningKitty 0.9.4 prints for checks it skips without administrator rights (Write-NotAdminError).</summary>
    private const string SkippedOutput =
        "[*] 11/20/2026 12:40:01 PM - Starting Category Features\r\n" +
        "[!] 11/20/2026 12:40:01 PM - ID 1000, SMBv1 Support, Method WindowsOptionalFeature requires admin privileges. Test skipped.\r\n" +
        "[!] 11/20/2026 12:40:02 PM - ID 1103, Store passwords using reversible encryption, Method secedit requires admin privileges. Test skipped.\r\n" +
        "[!] 11/20/2026 12:40:03 PM - ID 1500, Credential Validation, Method auditpol requires admin privileges. Test skipped.\r\n" +
        "[!] 11/20/2026 12:40:04 PM - ID 1708, BitLocker Drive Encryption: Volume status, Method BitLockerVolume requires admin privileges. Test skipped.\r\n" +
        "[!] 11/20/2026 12:40:04 PM - ID 1708, BitLocker Drive Encryption: Volume status, Method BitLockerVolume requires admin privileges. Test skipped.\r\n" +
        "[!] 11/20/2026 12:40:05 PM - ID 1953, Force use of Data Execution Prevention (DEP), Method bcdedit requires admin privileges. Test skipped.\r\n" +
        "RPD_PROFILE=domain=False;entra=False;mdm=False;edition=Core\r\n";

    /// <summary>Only the checks that work without administrator rights (the report leaves the skipped ones out).</summary>
    private const string PartialCsv =
        "ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding\n" +
        "1100,Account Policies,Account lockout threshold,Medium,0,5,Failed,Medium\n" +
        "1418,Windows Firewall,EnableFirewall (Domain Profile),Passed,1,1,Passed,Medium\n";

    private const string FullCsv = PartialCsv +
        "1000,Features,SMBv1 Support,Passed,Disabled,Disabled,Passed,High\n" +
        "1103,Account Policies,Store passwords using reversible encryption,Passed,0,0,Passed,High\n";

    private const string Catalog =
        "ID,Category,Name,Method,Severity\n" +
        "1000,Features,SMBv1 Support,WindowsOptionalFeature,High\n" +
        "1103,Account Policies,Store passwords using reversible encryption,secedit,High\n" +
        "1708,\"Administrative Templates: Windows Components\",BitLocker Drive Encryption: Volume status,BitLockerVolume,High\n";

    private SecurityAuditModule Module(IProcessLauncher l, IElevatedCommandBridge? bridge = null, Func<CancellationToken, Task<bool>>? elevate = null)
    {
        var hk = Path.Combine(_dir, "hk");
        Directory.CreateDirectory(Path.Combine(hk, "lists"));
        File.WriteAllText(Path.Combine(hk, "lists", SecurityAuditModule.DefaultFindingList), Catalog);
        return new(new SecurityAuditOptions
        {
            ModuleFolder = hk, PowerShellPath = Path.Combine(_dir, "powershell.exe"),
            FileExists = p => p.EndsWith(".psd1") || p.EndsWith("powershell.exe") || File.Exists(p),
            ReportPathFactory = () => ReportPath,
            Log = new LineLogger(s => { lock (_log) _log.Add(s); }),
            ElevatedBridge = bridge, RequestElevation = elevate,
        }, l);
    }

    private ScriptedLauncher LocalRun(string csv, string stdout) => new((_, _) =>
    {
        File.WriteAllText(ReportPath, csv);
        return ScriptedLauncher.Ok(stdout);
    });

    private static ScriptedLauncher NoLocalRun() => new((_, _) => throw new InvalidOperationException("the audit should run in the helper"));

    [Fact]
    public void Skipped_checks_are_read_from_the_output_once_each()
    {
        var skipped = SkippedForAdmin.Parse(SkippedOutput, SkippedForAdmin.Catalog(Catalog));
        Assert.Equal(["1000", "1103", "1500", "1708", "1953"], skipped.Select(f => f.Id));
        Assert.All(skipped, f => Assert.Equal(AuditOutcome.NotChecked, f.Outcome));
        Assert.All(skipped, f => Assert.True(f.NeedsAdmin));
        Assert.Equal("BitLocker Drive Encryption: Volume status", skipped[3].Name);
        Assert.Equal(("Administrative Templates: Windows Components", "High"), (skipped[3].Category, skipped[3].Severity));
        Assert.Equal("Force use of Data Execution Prevention (DEP)", skipped[4].Name);
        Assert.Equal("", skipped[2].Category); // not in the catalog
        Assert.Contains("administrator rights", skipped[0].Explanation);
        Assert.Empty(SkippedForAdmin.Parse("nothing here\n[!] some other error"));
        Assert.Empty(SkippedForAdmin.Parse(null));
    }

    [Fact]
    public void Notice_names_the_shown_skipped_checks_in_plain_words()
    {
        var skipped = SkippedForAdmin.Parse(SkippedOutput);
        var business = new SecurityAuditReport(skipped, Profile: new PcProfile(true, false, false, "Professional"));
        Assert.Equal("5 checks need administrator rights and weren't run: SMBv1 file sharing turned off, Passwords not stored with reversible " +
            "encryption, BitLocker drive encryption and 2 more. To include them, start the audit again and choose Yes when Windows asks for permission.",
            SkippedForAdmin.Notice(business, atThePc: true));

        // A home PC shows only the home checks: three of the five.
        var home = new SecurityAuditReport(skipped, Profile: new PcProfile(false, false, false, "Core"));
        Assert.Equal("3 checks need administrator rights and weren't run: SMBv1 file sharing turned off, Passwords not stored with reversible " +
            "encryption and BitLocker drive encryption. To include them, ask the person at the PC to start the audit and choose Yes when Windows asks for permission.",
            SkippedForAdmin.Notice(home, atThePc: false));

        var one = new SecurityAuditReport([skipped[0]], Profile: new PcProfile(false, false, false, "Core"));
        Assert.Equal("1 check needs administrator rights and wasn't run: SMBv1 file sharing turned off. To include it, start the audit again and choose Yes " +
            "when Windows asks for permission.", SkippedForAdmin.Notice(one, atThePc: true));

        // Only enterprise-only checks were skipped, and a home PC hides those: nothing is missing from what the page shows.
        var hidden = new SecurityAuditReport([skipped[2], skipped[4]], Profile: new PcProfile(false, false, false, "Core"));
        Assert.Null(SkippedForAdmin.Notice(hidden, atThePc: true));
    }

    [Fact]
    public async Task Without_a_helper_the_skipped_checks_are_listed_as_not_checked_and_named()
    {
        var r = await Module(LocalRun(PartialCsv, SkippedOutput)).RefreshAsync(null);
        var rep = Assert.IsType<SecurityAuditReport>(r.Payload);
        Assert.Equal(7, rep.Findings.Count);
        Assert.Equal(5, rep.Findings.Count(f => f.NeedsAdmin));
        Assert.True(rep.HomePc);
        Assert.Equal(3, rep.NotChecked); // SMBv1, reversible passwords, BitLocker; the two enterprise ones are hidden
        Assert.StartsWith("3 checks need administrator rights and weren't run: SMBv1 file sharing turned off", rep.Notice);
        Assert.DoesNotContain("close the app", rep.Notice);
        Assert.Contains(_log, l => l.Contains("skippedForAdmin=5"));
    }

    [Fact]
    public async Task Without_skip_lines_there_is_no_notice()
    {
        var r = await Module(LocalRun(PartialCsv, "")).RefreshAsync(null);
        Assert.Null(Assert.IsType<SecurityAuditReport>(r.Payload).Notice);
    }

    [Fact]
    public async Task With_a_helper_the_audit_runs_there_with_no_notice()
    {
        var bridge = new FakeBridge { Run = new SecurityAuditRun(new ProcessResult(0, "RPD_PROFILE=domain=False;entra=False;mdm=False;edition=Core", ""), FullCsv) };
        var r = await Module(NoLocalRun(), bridge).RefreshAsync(null);
        var rep = Assert.IsType<SecurityAuditReport>(r.Payload);
        Assert.Null(rep.Notice);
        Assert.Equal(4, rep.Findings.Count);
        Assert.Equal(0, rep.NotChecked);
        Assert.Equal(1, bridge.Calls);
        Assert.Equal(TimeSpan.FromMinutes(5), bridge.Timeout);
        Assert.Contains(_log, l => l.Contains("inAgent=True"));
    }

    [Fact]
    public async Task At_the_pc_the_helper_is_started_first()
    {
        var bridge = new FakeBridge { Connected = false, Run = new SecurityAuditRun(new ProcessResult(0, "", ""), FullCsv) };
        var asked = 0;
        var progress = new List<string>();
        var r = await Module(NoLocalRun(), bridge, _ => { asked++; bridge.Connected = true; return Task.FromResult(true); })
            .RefreshAsync(new SyncProgress(progress.Add));
        Assert.Equal(1, asked);
        Assert.Null(Assert.IsType<SecurityAuditReport>(r.Payload).Notice);
        Assert.Contains("Asking Windows for administrator permission…", progress);
    }

    [Fact]
    public async Task Declined_permission_runs_the_audit_without_administrator_rights()
    {
        var bridge = new FakeBridge { Connected = false };
        var r = await Module(LocalRun(PartialCsv, SkippedOutput), bridge, _ => Task.FromResult(false)).RefreshAsync(null);
        Assert.Equal(0, bridge.Calls);
        Assert.Contains("weren't run", Assert.IsType<SecurityAuditReport>(r.Payload).Notice);
    }

    [Fact]
    public async Task An_older_helper_that_cant_run_the_audit_falls_back_to_running_it_here()
    {
        var bridge = new FakeBridge { Run = null };
        var r = await Module(LocalRun(PartialCsv, SkippedOutput), bridge).RefreshAsync(null);
        Assert.Equal(1, bridge.Calls);
        Assert.Contains("weren't run", Assert.IsType<SecurityAuditReport>(r.Payload).Notice);
    }

    [Fact]
    public async Task Cancelling_an_elevated_run_reports_cancelled()
    {
        var started = new TaskCompletionSource();
        var bridge = new FakeBridge { Wait = async ct => { started.SetResult(); await Task.Delay(Timeout.Infinite, ct); } };
        var m = Module(NoLocalRun(), bridge);
        var run = m.RefreshAsync(null);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        m.Cancel();
        var r = await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(r.Cancelled);
        Assert.Equal(SecurityAuditModule.CancelledMessage, r.Message);
    }

    [Fact]
    public async Task Pipe_runs_the_audit_in_the_helper_and_an_old_helper_says_no()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var seen = TimeSpan.Zero;
        IReadOnlyList<string>? seenIds = ["not called"];
        var (server, serverTask, client) = await StartAsync((t, ids, _) =>
        {
            seen = t;
            seenIds = ids;
            return Task.FromResult(new SecurityAuditRun(new ProcessResult(0, SkippedOutput, ""), FullCsv));
        }, cts.Token);
        // The server ends once the client closes; it's disposed only after that, so its last write isn't cut off.
        using (server)
        {
            await using (client)
            {
                var run = await client.RunSecurityAuditAsync(TimeSpan.FromMinutes(5), cts.Token);
                Assert.NotNull(run);
                Assert.Equal(FullCsv, run!.ReportCsv);
                Assert.Equal(SkippedOutput, run.Process.StdOut);
                Assert.Equal(TimeSpan.FromMinutes(5), seen);
                Assert.Null(seenIds); // the whole audit
                Assert.NotNull(await client.RunSecurityAuditAsync(TimeSpan.FromMinutes(5), ["1601", "1704"], cts.Token));
                Assert.Equal(["1601", "1704"], seenIds); // a re-check of just these
                Assert.True((await client.PingAsync(cts.Token)).Ok);
            }
            await serverTask;
        }

        var (old, oldTask, oldClient) = await StartAsync(null, cts.Token);
        using (old)
        {
            await using (oldClient)
                Assert.Null(await oldClient.RunSecurityAuditAsync(TimeSpan.FromMinutes(5), cts.Token));
            await oldTask;
        }
    }

    [Fact]
    public async Task Pipe_cancel_stops_the_helpers_run_and_the_pipe_stays_usable()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var started = new TaskCompletionSource();
        var stopped = new TaskCompletionSource();
        var (server, serverTask, client) = await StartAsync(async (_, _, ct) =>
        {
            started.SetResult();
            try { await Task.Delay(Timeout.Infinite, ct); }
            finally { stopped.TrySetResult(); }
            throw new InvalidOperationException("unreachable");
        }, cts.Token);
        using (server)
        {
            await using (client)
            {
                using var runCts = new CancellationTokenSource();
                var run = client.RunSecurityAuditAsync(TimeSpan.FromMinutes(5), runCts.Token);
                await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
                runCts.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
                await stopped.Task.WaitAsync(TimeSpan.FromSeconds(10));
                Assert.True(client.IsConnected);
                var ping = await client.PingAsync(cts.Token); // reads its own answer, not the cancelled audit's
                Assert.True(ping.Ok);
                Assert.Equal(Environment.ProcessId, ping.HelperPid);
            }
            await serverTask;
        }
    }

    [Fact]
    public async Task Elevated_runner_uses_the_apps_own_folder_and_removes_its_report()
    {
        var app = Path.Combine(_dir, "app");
        Directory.CreateDirectory(Path.Combine(app, SecurityAuditModule.RelativeFolder));
        File.WriteAllText(Path.Combine(app, SecurityAuditModule.RelativeFolder, SecurityAuditModule.ManifestFile), "");
        string? report = null;
        var launcher = new ScriptedLauncher((_, args) =>
        {
            Assert.Contains($"Import-Module -Name '{Path.Combine(app, SecurityAuditModule.RelativeFolder, SecurityAuditModule.ManifestFile)}'", args[^1]);
            var start = args[^1].IndexOf("-ReportFile '", StringComparison.Ordinal) + "-ReportFile '".Length;
            report = args[^1][start..args[^1].IndexOf('\'', start)];
            File.WriteAllText(report, FullCsv);
            return ScriptedLauncher.Ok("out");
        });
        var run = await SecurityAuditModule.ElevatedRunner(app, launcher: launcher)(TimeSpan.FromMinutes(1), null, CancellationToken.None);
        Assert.Equal(FullCsv, run.ReportCsv);
        Assert.False(Directory.Exists(Path.GetDirectoryName(report!)));

        await Assert.ThrowsAsync<FileNotFoundException>(() => SecurityAuditModule.ElevatedRunner(Path.Combine(_dir, "none"), launcher: launcher)(TimeSpan.FromMinutes(1), null, CancellationToken.None));
    }

    [Fact]
    public async Task Elevated_runner_rechecks_only_the_named_findings_and_drops_ids_that_are_not_digits()
    {
        var app = Path.Combine(_dir, "app");
        Directory.CreateDirectory(Path.Combine(app, SecurityAuditModule.RelativeFolder));
        File.WriteAllText(Path.Combine(app, SecurityAuditModule.RelativeFolder, SecurityAuditModule.ManifestFile), "");
        var scripts = new List<string>();
        var launcher = new ScriptedLauncher((_, args) =>
        {
            scripts.Add(args[^1]);
            var start = args[^1].IndexOf("-ReportFile '", StringComparison.Ordinal) + "-ReportFile '".Length;
            File.WriteAllText(args[^1][start..args[^1].IndexOf('\'', start)], FullCsv);
            return ScriptedLauncher.Ok("out");
        });
        var runner = SecurityAuditModule.ElevatedRunner(app, launcher: launcher);
        await runner(TimeSpan.FromMinutes(1), ["1601", "1704';Remove-Item C:\\", "x", "1601"], CancellationToken.None);
        Assert.Contains("-Filter {$_.ID -in @('1601')}", scripts[0]);
        Assert.DoesNotContain("Remove-Item", scripts[0]);

        await runner(TimeSpan.FromMinutes(1), ["abc"], CancellationToken.None);
        Assert.DoesNotContain("-Filter", scripts[1]); // nothing valid: the whole audit
        Assert.Equal([], SecurityAuditModule.RecheckIds(Enumerable.Range(1000, SecurityAuditModule.MaxRecheckIds + 1).Select(i => i.ToString())));
    }

    private const string HomeCsv =
        "ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding\n" +
        "1601,Administrative Templates: Network,DNS Client: Turn off multicast name resolution (LLMNR),Medium,,0,Failed,Medium\n" +
        "1704,Administrative Templates: Windows Components,AutoPlay Policies: Turn off Autoplay,Passed,255,255,Passed,Medium\n" +
        "1100,Account Policies,Account lockout threshold,Low,Never,10,Failed,Low\n";

    private const string HomeProfile = "RPD_PROFILE=domain=False;entra=False;mdm=False;edition=Professional\r\n";

    [Fact]
    public async Task Recheck_runs_only_the_failed_settings_in_the_Agent_and_merges_them_into_the_last_report()
    {
        var bridge = new FakeBridge { Run = new SecurityAuditRun(new ProcessResult(0, HomeProfile, ""), HomeCsv) };
        var m = Module(NoLocalRun(), bridge);
        var first = await m.RefreshAsync(null);
        var rep = Assert.IsType<SecurityAuditReport>(first.Payload);
        Assert.Equal(DiagnosticStatus.Error, first.Status); // one Medium setting failed: the audit fails
        Assert.StartsWith("1 failed, 1 warning, 1 passed", first.Message);
        Assert.Equal(["1601", "1100"], rep.NeedsAttention.Select(f => f.Id));
        Assert.Contains(_log, l => l.Contains("needs attention: 1601 DNS Client"));

        // LLMNR was fixed; the re-check reads only it and the warning.
        bridge.RecheckRun = new SecurityAuditRun(new ProcessResult(0, HomeProfile, ""),
            "ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding\n" +
            "1601,Administrative Templates: Network,DNS Client: Turn off multicast name resolution (LLMNR),Passed,0,0,Passed,Medium\n" +
            "1100,Account Policies,Account lockout threshold,Low,Never,10,Failed,Low\n");
        m.RecheckOnNextRun(rep.NeedsAttention.Select(f => f.Id));
        Assert.Equal(["1601", "1100"], m.PendingRecheck);
        var again = await m.RefreshAsync(null);
        Assert.Equal(["1601", "1100"], bridge.RecheckIds);
        var merged = Assert.IsType<SecurityAuditReport>(again.Payload);
        Assert.Equal(3, merged.Findings.Count); // 1704 kept from the first run
        Assert.Equal(DiagnosticStatus.Warning, again.Status);
        Assert.Equal(["1100"], merged.NeedsAttention.Select(f => f.Id));
        Assert.Empty(m.PendingRecheck);

        // The next run audits everything again.
        await m.RefreshAsync(null);
        Assert.Equal(3, bridge.Calls);
        Assert.Equal(["1601", "1100"], bridge.RecheckIds); // unchanged: that run was the whole audit
    }

    [Fact]
    public async Task Recheck_before_any_audit_runs_the_whole_audit()
    {
        var bridge = new FakeBridge { Run = new SecurityAuditRun(new ProcessResult(0, HomeProfile, ""), HomeCsv) };
        var m = Module(NoLocalRun(), bridge);
        m.RecheckOnNextRun(["1601"]);
        await m.RefreshAsync(null);
        Assert.Null(bridge.RecheckIds);
        Assert.Equal(1, bridge.Calls);
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(Func<TimeSpan, IReadOnlyList<string>?, CancellationToken, Task<SecurityAuditRun>>? auditor, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), securityAuditor: auditor);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    private sealed class SyncProgress(Action<string> report) : IProgress<string>
    {
        public void Report(string value) => report(value);
    }

    private sealed class FakeBridge : IElevatedCommandBridge
    {
        public bool Connected { get; set; } = true;
        public SecurityAuditRun? Run { get; set; }
        public Func<CancellationToken, Task>? Wait { get; set; }
        public int Calls { get; private set; }
        public TimeSpan Timeout { get; private set; }
        public bool IsConnected => Connected;

        public IReadOnlyList<string>? RecheckIds { get; private set; }
        public SecurityAuditRun? RecheckRun { get; set; }

        public async Task<SecurityAuditRun?> RunSecurityAuditAsync(TimeSpan timeout, IReadOnlyList<string> onlyIds, CancellationToken ct = default)
        {
            RecheckIds = onlyIds;
            await RunSecurityAuditAsync(timeout, ct);
            return RecheckRun;
        }

        public async Task<SecurityAuditRun?> RunSecurityAuditAsync(TimeSpan timeout, CancellationToken ct = default)
        {
            Calls++;
            Timeout = timeout;
            if (Wait is not null) await Wait(ct);
            return Run;
        }

        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            throw new NotSupportedException();
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => throw new NotSupportedException();
    }
}
