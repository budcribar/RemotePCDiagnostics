using System.Diagnostics;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

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
    public Func<bool>? IsAdministrator { get; set; }
    public Func<string, bool>? FileExists { get; set; }
    public Action<string>? Log { get; set; }
}

/// <summary>
/// On-demand Windows security baseline audit using the bundled HardeningKitty module (Audit mode: read-only).
/// Not auto-run and excluded from Run All. Technical detail goes to the log only; results/messages are end-user text.
/// </summary>
public sealed class SecurityAuditModule : IDiagnosticModule
{
    public const string ModuleName = "SecurityAudit";
    public const string PathEnvironmentVariable = "RPD_HARDENINGKITTY_PATH";
    public static readonly string RelativeFolder = Path.Combine("tools", "HardeningKitty");
    public const string ManifestFile = "HardeningKitty.psd1";

    public const string ToolMissingMessage = "The security audit tool wasn't found. Please reinstall the app.";
    public const string PowerShellMissingMessage = "Windows PowerShell isn't available on this PC, so the security audit can't run.";
    public const string CancelledMessage = "The security audit was cancelled.";
    public const string FailedMessage = "The security audit couldn't finish on this PC. Please try again.";
    public const string NotAdminNotice = "Some checks need administrator rights and couldn't be completed. For a full audit, close the app and start it again as an administrator.";

    private readonly IProcessLauncher _launcher;
    private readonly SecurityAuditOptions _o;
    private readonly Func<string, bool> _fileExists;
    private CancellationTokenSource? _runCts;
    private readonly object _gate = new();

    public SecurityAuditModule(SecurityAuditOptions? options = null, IProcessLauncher? launcher = null)
    {
        _o = options ?? new SecurityAuditOptions();
        _launcher = launcher ?? new SystemProcessLauncher();
        _fileExists = _o.FileExists ?? File.Exists;
        var configured = _o.ModuleFolder ?? Environment.GetEnvironmentVariable(PathEnvironmentVariable);
        ModuleFolder = !string.IsNullOrWhiteSpace(configured) ? Path.GetFullPath(configured)
            : Path.Combine(_o.BaseDirectory ?? AppContext.BaseDirectory, RelativeFolder);
        PowerShellPath = _o.PowerShellPath ?? SystemCommandRunner.PowerShell;
    }

    public string Name => ModuleName;
    public Guid Id => ModuleIds.SecurityAudit;
    public string DisplayName => "Security audit";
    public bool IncludeInRunAll => false;
    public TimeSpan Timeout => _o.Timeout;
    public string ModuleFolder { get; }
    public string ManifestPath => Path.Combine(ModuleFolder, ManifestFile);
    public string PowerShellPath { get; }
    public event EventHandler<DiagnosticResult>? Updated;

    /// <summary>Stops the in-flight audit (the launcher kills the PowerShell process tree).</summary>
    public void Cancel()
    {
        lock (_gate) { try { _runCts?.Cancel(); } catch (ObjectDisposedException) { } }
    }

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        if (!_fileExists(ManifestPath))
        {
            Log($"SecurityAudit: HardeningKitty not found at '{ManifestPath}' (set {PathEnvironmentVariable} or bundle third_party/HardeningKitty)");
            return Task.FromResult(ModuleAvailability.Unavailable(ToolMissingMessage));
        }
        if (!_fileExists(PowerShellPath))
        {
            Log($"SecurityAudit: PowerShell not found at '{PowerShellPath}'");
            return Task.FromResult(ModuleAvailability.Unavailable(PowerShellMissingMessage));
        }
        return Task.FromResult(ModuleAvailability.Available);
    }

    private static string Quote(string s) => "'" + s.Replace("'", "''") + "'";

    public static string BuildScript(string manifestPath, string reportPath) =>
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" +
        $"Import-Module -Name {Quote(manifestPath)} -Force;" +
        $"Invoke-HardeningKitty -Mode Audit -Report -ReportFile {Quote(reportPath)} -SkipMachineInformation -SkipLanguageWarning | Out-Null";

    /// <summary>-ExecutionPolicy Bypass applies to this PowerShell process only; nothing system-wide is changed.</summary>
    public static IReadOnlyList<string> BuildArguments(string manifestPath, string reportPath) =>
        ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", BuildScript(manifestPath, reportPath)];

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_gate) _runCts = cts;
        string? reportPath = null;
        try
        {
            var admin = IsAdmin();
            reportPath = (_o.ReportPathFactory ?? DefaultReportPath)();
            Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
            var args = BuildArguments(ManifestPath, reportPath);
            Log($"SecurityAudit: start admin={admin} timeout={Timeout} cmd={PowerShellPath} {string.Join(' ', args)}");
            progress?.Report("Auditing security settings…");
            var sw = Stopwatch.StartNew();
            ProcessResult pr;
            try { pr = await _launcher.RunAsync(PowerShellPath, args, Timeout, cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                Log($"SecurityAudit: cancelled after {sw.ElapsedMilliseconds} ms (process tree killed)");
                return Result(DiagnosticStatus.Warning, CancelledMessage, null) with { Cancelled = true };
            }
            catch (Exception ex)
            {
                Log($"SecurityAudit: failed to start PowerShell: {ex}");
                return Result(DiagnosticStatus.Error, FailedMessage, null);
            }
            var head = pr.StdOut.Length > 2048 ? pr.StdOut[..2048] : pr.StdOut;
            Log($"SecurityAudit: exit={pr.ExitCode} timedOut={pr.TimedOut} ms={sw.ElapsedMilliseconds} stdout_len={pr.StdOut.Length} stderr=\"{pr.StdErr.Trim()}\" stdout_head=\"{head.Replace("\r", "").Replace("\n", " ")}\"");
            if (pr.TimedOut)
                return Result(DiagnosticStatus.Error, $"The security audit took longer than {FormatDuration(Timeout)} and was stopped. Please try again later.", null);

            if (!File.Exists(reportPath))
            {
                Log($"SecurityAudit: no report produced at '{reportPath}'");
                return Result(DiagnosticStatus.Error, FailedMessage, null);
            }
            IReadOnlyList<AuditFinding> findings;
            try { findings = HardeningKittyCsv.Parse(await File.ReadAllTextAsync(reportPath, CancellationToken.None).ConfigureAwait(false)); }
            catch (Exception ex) when (ex is FormatException or IOException)
            {
                Log($"SecurityAudit: report unreadable: {ex.Message}");
                return Result(DiagnosticStatus.Error, FailedMessage, null);
            }
            if (findings.Count == 0)
            {
                Log("SecurityAudit: report had no rows");
                return Result(DiagnosticStatus.Error, FailedMessage, null);
            }
            var report = new SecurityAuditReport(findings, admin ? null : NotAdminNotice);
            Log($"SecurityAudit: parsed {findings.Count} findings passed={report.Passed} warn={report.Warnings} failed={report.Failed} notChecked={report.NotChecked}");
            return Result(report.Status, report.Summary, report);
        }
        finally
        {
            lock (_gate) _runCts = null;
            if (reportPath is not null && _o.ReportPathFactory is null) TryDelete(Path.GetDirectoryName(reportPath)!);
        }
    }

    private DiagnosticResult Result(DiagnosticStatus s, string msg, SecurityAuditReport? r) =>
        new DiagnosticResult<SecurityAuditReport>(Name, s, msg, DateTimeOffset.Now, r);

    public static string FormatDuration(TimeSpan t) =>
        t.TotalMinutes >= 1 ? AreaModuleBase.Plural((int)Math.Round(t.TotalMinutes), "minute") : AreaModuleBase.Plural((int)Math.Max(1, Math.Round(t.TotalSeconds)), "second");

    private bool IsAdmin()
    {
        if (_o.IsAdministrator is { } f) return f();
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static string DefaultReportPath() =>
        Path.Combine(Path.GetTempPath(), "RemotePCDiagnostics", "hk-" + Guid.NewGuid().ToString("N"), "report.csv");

    private void TryDelete(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
        catch (Exception ex) { Log($"SecurityAudit: couldn't delete temp folder: {ex.Message}"); }
    }

    private void Log(string s) { try { _o.Log?.Invoke(s); } catch { } }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
