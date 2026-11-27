namespace RemotePCDiagnostics.Agent.Core;

/// <summary>
/// Runs Setup outside the service control manager's job. That job kills every child when the service process
/// exits, and it does not allow <c>CREATE_BREAKAWAY_FROM_JOB</c>. A one-shot SYSTEM task is not in the job, so
/// Setup (and the <c>Agent.exe install</c> it starts) keeps running after the agent that launched the update is stopped.
/// </summary>
public static class ScheduledSetup
{
    public const string BatchFileName = "rpcd-setup-run.cmd";
    public const string ExitCodeFileName = "rpcd-setup-exit.txt";
    public const string TaskXmlFileName = "rpcd-setup-task.xml";

    /// <summary>Task Scheduler's SCHED_S_TASK_RUNNING (0x41301).</summary>
    public const int TaskRunningResult = 267009;

    public static string BatchScript(string setupExe, string arguments, string exitCodePath)
    {
        var args = string.IsNullOrWhiteSpace(arguments)
            ? ""
            : " " + arguments.Replace("%", "%%", StringComparison.Ordinal);
        // Redirect first so a one-digit ERRORLEVEL is not eaten as a cmd handle (`echo 1> file`).
        return "@echo off\r\n"
            + WindowsCommandLine.Quote(setupExe) + args + "\r\n"
            + "> " + WindowsCommandLine.Quote(exitCodePath) + " echo %ERRORLEVEL%\r\n";
    }

    public static bool IsAscii(string text)
    {
        foreach (var ch in text)
        {
            if (ch > 127)
                return false;
        }
        return true;
    }

    public static string TaskXml(string command, string arguments, string? workingDirectory)
    {
        var work = string.IsNullOrWhiteSpace(workingDirectory)
            ? ""
            : "      <WorkingDirectory>" + Xml(workingDirectory) + "</WorkingDirectory>\r\n";
        return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
            + "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
            + "  <RegistrationInfo>\r\n"
            + "    <Description>Runs Remote PC Diagnostics Setup outside the agent service job.</Description>\r\n"
            + "  </RegistrationInfo>\r\n"
            + "  <Triggers>\r\n"
            + "    <TimeTrigger>\r\n"
            + "      <StartBoundary>2000-01-01T00:00:00</StartBoundary>\r\n"
            + "      <Enabled>false</Enabled>\r\n"
            + "    </TimeTrigger>\r\n"
            + "  </Triggers>\r\n"
            + "  <Principals>\r\n"
            + "    <Principal id=\"Author\">\r\n"
            + "      <UserId>S-1-5-18</UserId>\r\n"
            + "      <LogonType>ServiceAccount</LogonType>\r\n"
            + "      <RunLevel>HighestAvailable</RunLevel>\r\n"
            + "    </Principal>\r\n"
            + "  </Principals>\r\n"
            + "  <Settings>\r\n"
            + "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
            + "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
            + "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
            + "    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
            + "    <StartWhenAvailable>false</StartWhenAvailable>\r\n"
            + "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
            + "    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
            + "    <Enabled>true</Enabled>\r\n"
            + "    <Hidden>true</Hidden>\r\n"
            + "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n"
            + "    <WakeToRun>false</WakeToRun>\r\n"
            + "    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>\r\n"
            + "    <Priority>7</Priority>\r\n"
            + "  </Settings>\r\n"
            + "  <Actions Context=\"Author\">\r\n"
            + "    <Exec>\r\n"
            + "      <Command>" + Xml(command) + "</Command>\r\n"
            + "      <Arguments>" + Xml(arguments) + "</Arguments>\r\n"
            + work
            + "    </Exec>\r\n"
            + "  </Actions>\r\n"
            + "</Task>\r\n";
    }

    public static string Xml(string value) =>
        value.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal);

    /// <summary>The exit code reported when the task stopped, or ran out of time, without its script writing one.</summary>
    public const int NoExitCode = -1;

    /// <summary>The task's 2-hour limit plus time for Task Scheduler to end it. A wait never runs longer than this.</summary>
    public static readonly TimeSpan WaitLimit = TimeSpan.FromHours(2) + TimeSpan.FromMinutes(10);

    /// <summary>How long after the start the task's state is first checked, and how often after that.</summary>
    public static readonly TimeSpan StateCheckAfter = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan StateCheckEvery = TimeSpan.FromSeconds(15);

    /// <summary>
    /// The PowerShell that prints the Setup task's state. <c>State</c> is an enum, so the name is the same in every Windows language;
    /// schtasks /Query prints a translated status. Prints <c>Missing</c> when the task is gone.
    /// </summary>
    public static string StateQuery(string taskName) =>
        "$t = Get-ScheduledTask -TaskName '" + taskName.Replace("'", "''", StringComparison.Ordinal) + "' -ErrorAction SilentlyContinue; "
        + "if ($null -eq $t) { 'Missing' } else { [string]$t.State }";

    /// <summary>
    /// False when the task is known to have stopped: <c>Ready</c>, <c>Disabled</c> or <c>Missing</c>.
    /// A failed or empty query is not proof, so it keeps waiting (until <see cref="WaitLimit"/>).
    /// </summary>
    public static bool MayStillRun(string? state)
    {
        if (string.IsNullOrWhiteSpace(state))
            return true;
        var name = state.Trim();
        return !(name.Equals("Ready", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Disabled", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Missing", StringComparison.OrdinalIgnoreCase));
    }

    public static int? ParseExitCode(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        return int.TryParse(text.Trim(), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var code)
            ? code
            : null;
    }
}
