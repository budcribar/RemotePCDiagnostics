using System.Diagnostics;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Security;

public sealed class SecurityAuditOptions
{
    /// <summary>Folder containing HardeningKitty.psd1. Null = RPD_HARDENINGKITTY_PATH or tools/HardeningKitty under the base directory.</summary>
    public string? ModuleFolder { get; set; }
    public string? BaseDirectory { get; set; }
    public string? PowerShellPath { get; set; }
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(5);
    /// <summary>Creates the per-run CSV report path (folder is created by the module). Default: %TEMP%\RemotePCDiagnostics\hk-&lt;guid&gt;\report.csv.</summary>
    public Func<string>? ReportPathFactory { get; set; }
    public Func<string, bool>? FileExists { get; set; }
    public ILogger? Log { get; set; }
    /// <summary>The Agent (its elevated helper, or the agent service): the audit runs there, with administrator rights. The app itself
    /// never runs as administrator.</summary>
    public IElevatedCommandBridge? ElevatedBridge { get; set; }
    /// <summary>
    /// Starts the elevated helper when none is connected (Windows asks the person at the PC for permission); true when it connected.
    /// Null = never ask (a remote session, where nobody may be there to answer).
    /// </summary>
    public Func<CancellationToken, Task<bool>>? RequestElevation { get; set; }
}

/// <summary>One HardeningKitty run: what PowerShell returned and the report CSV it wrote (null when it wrote none).</summary>
public sealed record SecurityAuditRun(ProcessResult Process, string? ReportCsv);

/// <summary>
/// On-demand Windows security baseline audit using the bundled HardeningKitty module (Audit mode: read-only). It runs in the Agent, which
/// has administrator rights; only when the Agent can't run it does it run in the app, without them, and the page names the checks skipped.
/// Not auto-run and excluded from Run All. Technical detail goes to the log only; results/messages are end-user text.
/// </summary>
public sealed class SecurityAuditModule : OnDemandModuleBase
{
    public const string ModuleName = ModuleSlugs.SecurityAudit;
    public const string PathEnvironmentVariable = "RPD_HARDENINGKITTY_PATH";
    public static readonly string RelativeFolder = Path.Combine("tools", "HardeningKitty");
    public const string ManifestFile = "HardeningKitty.psd1";

    public const string ToolMissingMessage = "The security audit tool wasn't found. Please reinstall the app.";
    public const string PowerShellMissingMessage = "Windows PowerShell isn't available on this PC, so the security audit can't run.";
    public new const string CancelledMessage = "The security audit was cancelled.";
    public const string FailedMessage = "The security audit couldn't finish on this PC. Please try again.";
    /// <summary>The finding list HardeningKitty audits against by default (its lists folder), read for the skipped checks' categories.</summary>
    public const string DefaultFindingList = "finding_list_0x6d69636b_machine.csv";

    private readonly IProcessLauncher _launcher;
    private readonly SecurityAuditOptions _o;
    private readonly Func<string, bool> _fileExists;

    public SecurityAuditModule(SecurityAuditOptions? options = null, IProcessLauncher? launcher = null)
        : base(options?.Log)
    {
        _o = options ?? new SecurityAuditOptions();
        _launcher = launcher ?? new SystemProcessLauncher();
        _fileExists = _o.FileExists ?? File.Exists;
        var configured = _o.ModuleFolder ?? Environment.GetEnvironmentVariable(PathEnvironmentVariable);
        ModuleFolder = !string.IsNullOrWhiteSpace(configured) ? Path.GetFullPath(configured)
            : Path.Combine(_o.BaseDirectory ?? AppContext.BaseDirectory, RelativeFolder);
        PowerShellPath = _o.PowerShellPath ?? SystemCommandRunner.PowerShell;
    }

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.SecurityAudit;
    public override string DisplayName => "Security audit";
    public TimeSpan Timeout => _o.Timeout;
    public string ModuleFolder { get; }
    public string ManifestPath => Path.Combine(ModuleFolder, ManifestFile);
    public string PowerShellPath { get; }

    public override Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        if (!_fileExists(ManifestPath))
        {
            LogWarn($"SecurityAudit: HardeningKitty not found at '{ManifestPath}' (set {PathEnvironmentVariable} or bundle third_party/HardeningKitty)");
            return Task.FromResult(ModuleAvailability.Unavailable(ToolMissingMessage));
        }
        if (!_fileExists(PowerShellPath))
        {
            LogWarn($"SecurityAudit: PowerShell not found at '{PowerShellPath}'");
            return Task.FromResult(ModuleAvailability.Unavailable(PowerShellMissingMessage));
        }
        return Task.FromResult(ModuleAvailability.Available);
    }

    private static string Quote(string s) => "'" + s.Replace("'", "''") + "'";

    public static string BuildScript(string manifestPath, string reportPath) =>
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" +
        $"Import-Module -Name {Quote(manifestPath)} -Force;" +
        $"Invoke-HardeningKitty -Mode Audit -Report -ReportFile {Quote(reportPath)} -SkipMachineInformation -SkipLanguageWarning | Out-Null;" + PcProfile.DetectScript;

    /// <summary>-ExecutionPolicy Bypass applies to this PowerShell process only; nothing system-wide is changed.</summary>
    public static IReadOnlyList<string> BuildArguments(string manifestPath, string reportPath) =>
        SystemCommandRunner.PowerShellArgs(BuildScript(manifestPath, reportPath));

    /// <summary>
    /// Runs HardeningKitty once and reads its report: the one run both the app and the elevated helper make. Creates the report's folder;
    /// the caller deletes it. Throws when PowerShell can't start, and on cancellation (the process tree is killed).
    /// </summary>
    public static async Task<SecurityAuditRun> RunProcessAsync(IProcessLauncher launcher, string powerShellPath, string manifestPath, string reportPath,
        TimeSpan timeout, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
        var pr = await launcher.RunAsync(powerShellPath, BuildArguments(manifestPath, reportPath), timeout, ct).ConfigureAwait(false);
        var csv = File.Exists(reportPath) ? await File.ReadAllTextAsync(reportPath, CancellationToken.None).ConfigureAwait(false) : null;
        return new SecurityAuditRun(pr, csv);
    }

    /// <summary>
    /// What the elevated helper and the agent service run for the app's audit: HardeningKitty from <paramref name="appFolder"/> (the
    /// installed app's own folder, never a path the app passes), the report in a temp folder of the elevated account, removed afterwards.
    /// </summary>
    public static Func<TimeSpan, CancellationToken, Task<SecurityAuditRun>> ElevatedRunner(string appFolder, ILogger? log = null, IProcessLauncher? launcher = null) =>
        async (timeout, ct) =>
        {
            var manifest = Path.Combine(appFolder, RelativeFolder, ManifestFile);
            if (!File.Exists(manifest)) throw new FileNotFoundException("HardeningKitty isn't installed next to the app.", manifest);
            var reportPath = DefaultReportPath();
            var sw = Stopwatch.StartNew();
            try
            {
                var run = await RunProcessAsync(launcher ?? new SystemProcessLauncher(), SystemCommandRunner.PowerShell, manifest, reportPath, timeout, ct).ConfigureAwait(false);
                log.Info($"[security-audit] elevated run exit={run.Process.ExitCode} timedOut={run.Process.TimedOut} ms={sw.ElapsedMilliseconds} report_len={run.ReportCsv?.Length ?? -1}");
                return run;
            }
            finally
            {
                try { Directory.Delete(Path.GetDirectoryName(reportPath)!, recursive: true); } catch { }
            }
        };

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        string? reportPath = null;
        try
        {
            var sw = Stopwatch.StartNew();
            SecurityAuditRun? run;
            var inAgent = false;
            try
            {
                run = await RunInAgentAsync(progress, ct).ConfigureAwait(false);
                if (run is not null) inAgent = true;
                else
                {
                    reportPath = (_o.ReportPathFactory ?? DefaultReportPath)();
                    Log($"SecurityAudit: start in the app timeout={Timeout} cmd={PowerShellPath} {string.Join(' ', BuildArguments(ManifestPath, reportPath))}");
                    progress?.Report("Auditing security settings…");
                    run = await RunProcessAsync(_launcher, PowerShellPath, ManifestPath, reportPath, Timeout, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                Log($"SecurityAudit: cancelled after {sw.ElapsedMilliseconds} ms (process tree killed)");
                return Result(DiagnosticStatus.Warning, CancelledMessage, null) with { Cancelled = true };
            }
            catch (Exception ex)
            {
                LogError($"SecurityAudit: failed to start PowerShell: {ex}");
                return Result(DiagnosticStatus.Error, FailedMessage, null);
            }
            var pr = run.Process;
            var head = pr.StdOut.Length > 2048 ? pr.StdOut[..2048] : pr.StdOut;
            Log($"SecurityAudit: exit={pr.ExitCode} timedOut={pr.TimedOut} inAgent={inAgent} ms={sw.ElapsedMilliseconds} stdout_len={pr.StdOut.Length} stderr=\"{pr.StdErr.Trim()}\" stdout_head=\"{head.Replace("\r", "").Replace("\n", " ")}\"");
            if (pr.TimedOut)
                return Result(DiagnosticStatus.Error, $"The security audit took longer than {FormatDuration(Timeout)} and was stopped. Please try again later.", null);

            if (run.ReportCsv is not { } csv)
            {
                LogWarn($"SecurityAudit: no report produced (inAgent={inAgent})");
                return Result(DiagnosticStatus.Error, FailedMessage, null);
            }
            IReadOnlyList<AuditFinding> findings;
            try { findings = HardeningKittyCsv.Parse(csv); }
            catch (FormatException ex)
            {
                LogWarn($"SecurityAudit: report unreadable: {ex.Message}");
                return Result(DiagnosticStatus.Error, FailedMessage, null);
            }
            if (findings.Count == 0)
            {
                LogWarn("SecurityAudit: report had no rows");
                return Result(DiagnosticStatus.Error, FailedMessage, null);
            }
            var profile = PcProfile.Parse(pr.StdOut);
            // The Agent has administrator rights, so nothing is skipped there; the app's own run skips the checks that need them.
            var skipped = inAgent ? [] : SkippedForAdmin.Parse(pr.StdOut, ReadCatalog());
            if (skipped.Count > 0)
            {
                var reported = findings.Select(f => f.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
                findings = [.. findings, .. skipped.Where(f => !reported.Contains(f.Id))];
            }
            var report = new SecurityAuditReport(findings, null, profile);
            if (skipped.Count > 0)
                report = report with { Notice = SkippedForAdmin.Notice(report, _o.RequestElevation is not null) };
            LogWarn($"SecurityAudit: profile={(profile is null ? "unknown" : $"managed={profile.Managed} domain={profile.Domain} entra={profile.EntraJoined} mdm={profile.Mdm} edition={profile.Edition}")} hidden={report.Hidden} parsed {findings.Count} findings passed={report.Passed} warn={report.Warnings} failed={report.Failed} notChecked={report.NotChecked} skippedForAdmin={skipped.Count} ({string.Join(",", skipped.Select(f => f.Id))})");
            return Result(report.Status, report.Summary, report);
        }
        finally
        {
            if (reportPath is not null && _o.ReportPathFactory is null) TryDelete(Path.GetDirectoryName(reportPath)!);
        }
    }

    /// <summary>
    /// Runs the audit in the Agent (the elevated helper, or the agent service), first asking Windows to start the helper when none is
    /// connected and asking is allowed. Null when there's no Agent, or it can't run the audit (an older one), so the audit runs in the
    /// app instead. Throws only on cancellation.
    /// </summary>
    private async Task<SecurityAuditRun?> RunInAgentAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var bridge = _o.ElevatedBridge;
        if (bridge is null) return null;
        if (!bridge.IsConnected && _o.RequestElevation is { } request)
        {
            progress?.Report("Asking Windows for administrator permission…");
            bool started;
            try { started = await request(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { LogWarn($"SecurityAudit: starting the elevated helper failed: {ex.Message}"); started = false; }
            Log($"SecurityAudit: elevated helper requested, connected={started && bridge.IsConnected}");
        }
        if (!bridge.IsConnected) return null;
        progress?.Report("Auditing security settings with administrator rights…");
        Log($"SecurityAudit: running in the Agent, timeout={Timeout}");
        try
        {
            var run = await bridge.RunSecurityAuditAsync(Timeout, ct).ConfigureAwait(false);
            if (run is null) LogWarn("SecurityAudit: the Agent can't run the audit; running it in the app, without administrator rights");
            return run;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            LogWarn($"SecurityAudit: the Agent's run failed, running it in the app, without administrator rights: {ex.Message}");
            return null;
        }
    }

    private IReadOnlyDictionary<string, (string Category, string Severity)>? ReadCatalog()
    {
        try
        {
            var path = Path.Combine(ModuleFolder, "lists", DefaultFindingList);
            return File.Exists(path) ? SkippedForAdmin.Catalog(File.ReadAllText(path)) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            LogWarn($"SecurityAudit: finding list unreadable: {ex.Message}");
            return null;
        }
    }

    private DiagnosticResult Result(DiagnosticStatus s, string msg, SecurityAuditReport? r) =>
        new DiagnosticResult<SecurityAuditReport>(Name, s, msg, DateTimeOffset.Now, r);

    public static string FormatDuration(TimeSpan t) =>
        t.TotalMinutes >= 1 ? AreaModuleBase.Plural((int)Math.Round(t.TotalMinutes), "minute") : AreaModuleBase.Plural((int)Math.Max(1, Math.Round(t.TotalSeconds)), "second");

    private static string DefaultReportPath() =>
        Path.Combine(Path.GetTempPath(), "RemotePCDiagnostics", "hk-" + Guid.NewGuid().ToString("N"), "report.csv");

    private void TryDelete(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
        catch (Exception ex) { LogWarn($"SecurityAudit: couldn't delete temp folder: {ex.Message}"); }
    }
}

