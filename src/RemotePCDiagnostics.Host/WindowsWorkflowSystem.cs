using System.IO;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows side of the service workflow: a "continue after sign-in" task, restarts that sign back in (shutdown /g), and the saved report.
/// What needs administrator rights is done by the Agent (<paramref name="bridge"/>): the app never runs as administrator.
/// </summary>
public sealed class WindowsWorkflowSystem(SystemCommandRunner commands, ISessionContext session, ILogger? log = null, IElevatedCommandBridge? bridge = null) : IWorkflowSystem
{
    public const string TaskName = WorkflowService.ResumeTaskName;
    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string PolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
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
        var secs = ((int)delay.TotalSeconds).ToString();
        // /g = /r plus Automatic Restart Sign-On (same user signed back in, screen locked) where Windows allows it.
        // When routed through the Session-0 SYSTEM Agent, Windows can reject /g; fall back to a standard /r restart.
        var r = await commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/g", "/t", secs, "/c", message], ct).ConfigureAwait(false);
        if (r is not { ExitCode: 0 })
            r = await commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/r", "/t", secs, "/c", message], ct).ConfigureAwait(false);
        return r is { ExitCode: 0 };
    }

    public async Task AbortRestartAsync(CancellationToken ct) =>
        await commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/a"], ct).ConfigureAwait(false);

    public TimeSpan Uptime => TimeSpan.FromMilliseconds(Environment.TickCount64);

    // ---- signing back in after a restart ----
    /// <summary>
    /// Read-only (HKLM values every user can read). Automatic Restart Sign-On is off when policy turns it off
    /// (DisableAutomaticRestartSignOn=1) or the user turned off "Use my sign-in info..." (Winlogon\UserARSO\{SID} OptOut=1). With no
    /// choice saved, Windows signs back in on a PC nobody manages; on a domain PC it can't be told (null).
    /// </summary>
    public RestartSignInStatus GetRestartSignIn()
    {
        using var wl = Registry.LocalMachine.OpenSubKey(WinlogonKey);
        var already = (wl?.GetValue("AutoAdminLogon") as string) == "1";
        return new(already, RestartSignOn(wl));
    }

    private bool? RestartSignOn(RegistryKey? winlogon)
    {
        try
        {
            using var policy = Registry.LocalMachine.OpenSubKey(PolicyKey);
            if (policy?.GetValue("DisableAutomaticRestartSignOn") is int disabled)
                return disabled == 0;
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
            using var user = sid is null ? null : winlogon?.OpenSubKey(@"UserARSO\" + sid);
            if (user?.GetValue("OptOut") is int optOut)
                return optOut == 0;
            return string.Equals(Environment.UserDomainName, Environment.MachineName, StringComparison.OrdinalIgnoreCase) ? true : null;
        }
        catch (Exception ex) { Log("restart sign-on status: " + ex.Message); return null; }
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
