using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows side of the service workflow: a "continue after sign-in" task, temporary automatic sign-in, restarts, and the saved report.
/// What needs administrator rights is done by the Agent (<paramref name="bridge"/>): the app never runs as administrator.
/// </summary>
public sealed class WindowsWorkflowSystem(SystemCommandRunner commands, ISessionContext session, ILogger? log = null, IElevatedCommandBridge? bridge = null) : IWorkflowSystem
{
    public const string TaskName = WorkflowService.ResumeTaskName;
    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string PasswordLessKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device";
    private void Log(string m) => log.Info("[workflow] " + m);
    private void LogWarn(string m) => log.Warn("[workflow] " + m);

    private async Task<bool> AgentScriptAsync(AdminPipeScript script, CancellationToken ct)
    {
        var r = await commands.RunAgentScriptAsync(script, null, ct).ConfigureAwait(false);
        Log($"{script.Name} exit={r?.ExitCode} err={r?.StdErr.Trim()}");
        return r is { ExitCode: 0 };
    }


    // ---- continue after sign-in ----
    // Task Scheduler starts the Agent's launcher with highest privileges (no UAC prompt, unlike RunOnce); the launcher starts the app
    // un-elevated in the user's session with its admin pipe, so the rest of the workflow has the Agent from the start.
    // A task with highest privileges can only be registered with administrator rights: the Agent registers it, from its own folder and
    // a script it builds itself (AgentScripts.ResumeTaskRegister); the app sends only the user and its launch arguments.
    public Task<bool> RegisterResumeAsync(CancellationToken ct)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("No process path");
        if (bridge is not { IsConnected: true }) { LogWarn("register resume task: the Agent isn't connected"); return Task.FromResult(false); }
        var full = SessionLaunchOptions.BuildResumeCommandLine(exe, session.Mode, session.ServerUri, session.SessionId, session.Unattended, session.Voice, session.Group);
        var launch = ResumeTaskScript.LaunchArguments(exe, full).Append(SessionLaunchOptions.WorkflowArg);
        var user = $"{Environment.UserDomainName}\\{Environment.UserName}";
        var script = AgentScripts.Of(AgentScripts.ResumeTaskRegister, [AgentScripts.WorkflowTask, user, .. launch]);
        Log($"register resume task (Agent): {string.Join(' ', script.Args ?? [])}");
        return AgentScriptAsync(script, ct);
    }

    /// <summary>Removes the task (a missing task is fine) and fails only when it's still registered afterwards.</summary>
    public Task<bool> RemoveResumeAsync(CancellationToken ct) =>
        AgentScriptAsync(AgentScripts.Of(AgentScripts.ResumeTaskRemove, AgentScripts.WorkflowTask), ct);

    // ---- restart ----
    public async Task<bool> RestartAsync(TimeSpan delay, string message, CancellationToken ct)
    {
        // /g = /r plus Automatic Restart Sign-On (same user signed back in, screen locked) where Windows allows it; otherwise a plain restart.
        var r = await commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/g", "/t", ((int)delay.TotalSeconds).ToString(), "/c", message], ct).ConfigureAwait(false);
        return r is { ExitCode: 0 };
    }

    public async Task AbortRestartAsync(CancellationToken ct) =>
        await commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/a"], ct).ConfigureAwait(false);

    public TimeSpan Uptime => TimeSpan.FromMilliseconds(Environment.TickCount64);

    // ---- automatic sign-in ----
    public AutoLogonStatus GetAutoLogonStatus()
    {
        var user = Environment.UserName; var domain = Environment.UserDomainName;
        using var wl = Registry.LocalMachine.OpenSubKey(WinlogonKey);
        var already = (wl?.GetValue("AutoAdminLogon") as string) == "1";
        using var pl = Registry.LocalMachine.OpenSubKey(PasswordLessKey);
        var helloOnly = pl?.GetValue("DevicePasswordLessBuildVersion") is int v && v == 2;
        return new(user, domain, already, helloOnly, helloOnly
            ? "This PC has \"Only allow Windows Hello sign-in\" turned on. Automatic sign-in will temporarily turn that off for the two restarts and turn it back on during cleanup (or tick Skip so the client signs in after each restart)."
            : already ? "This PC already signs in automatically." : null, FindMicrosoftAccountEmail());
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetUserNameEx(int nameFormat, System.Text.StringBuilder name, ref uint size);

    /// <summary>
    /// The signed-in user's Microsoft account email, or null for a local/domain account. Read-only; never throws.
    /// Sources in order: IdentityStore cache (HKLM, keyed by the user's SID), IdentityCRL UserExtendedProperties (HKCU, subkeys named by email),
    /// then the user principal name (only if it looks like an email and the IdentityStore says nothing else).
    /// </summary>
    private string? FindMicrosoftAccountEmail()
    {
        static string? Email(object? v) => v is string s && s.Contains('@') && !s.Contains(' ') ? s.Trim() : null;
        try
        {
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
            if (sid is not null)
            {
                using var ic = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\IdentityStore\Cache\{sid}\IdentityCache\{sid}");
                if (Email(ic?.GetValue("UserName")) is { } e1) return e1;
            }
        }
        catch (Exception ex) { Log("identity store lookup: " + ex.Message); }
        try
        {
            using var ux = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\IdentityCRL\UserExtendedProperties");
            if (ux?.GetSubKeyNames().Select(Email).FirstOrDefault(e => e is not null) is { } e2) return e2;
        }
        catch (Exception ex) { Log("IdentityCRL lookup: " + ex.Message); }
        try
        {
            uint size = 256; var sb = new System.Text.StringBuilder((int)size);
            if (GetUserNameEx(8 /* NameUserPrincipal */, sb, ref size) && Email(sb.ToString()) is { } e3
                && string.Equals(Environment.UserDomainName, Environment.MachineName, StringComparison.OrdinalIgnoreCase)) return e3;
        }
        catch (Exception ex) { Log("UPN lookup: " + ex.Message); }
        return null;
    }

    // Checking the password and turning automatic sign-in on and off write HKLM and an LSA secret: the Agent does it (WindowsAutoLogon).
    private IElevatedCommandBridge Agent => bridge is { IsConnected: true } b
        ? b : throw new InvalidOperationException("The Agent isn't connected. " + ElevationService.AdminRepairHint);

    public Task<bool> ValidateCredentialsAsync(string user, string domain, string password, CancellationToken ct = default) =>
        Agent.ValidateCredentialsAsync(user, domain, password, ct);

    public Task<AutoLogonBackup> EnableAutoLogonAsync(string user, string domain, string password, int logons, CancellationToken ct = default) =>
        Agent.EnableAutoLogonAsync(user, domain, password, logons, ct);

    public async Task DisableAutoLogonAsync(AutoLogonBackup? backup, CancellationToken ct = default)
    {
        await Agent.DisableAutoLogonAsync(backup, ct).ConfigureAwait(false);
        Log("automatic sign-in off (Agent); stored password removed and previous sign-in settings restored");
    }

    // ---- report ----
    public string ReportFile(DateTimeOffset when) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "Remote PC Diagnostics", $"Service report {when.LocalDateTime:yyyy-MM-dd HHmm}.html");

    public string CertificateFile(DateTimeOffset when, string certificateId) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "Remote PC Diagnostics", $"Hardware QA Certificate {certificateId}.html");

    public void SaveReport(string path, string html)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, html);
    }
}
