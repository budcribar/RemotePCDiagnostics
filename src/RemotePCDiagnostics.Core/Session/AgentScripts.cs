using System.Globalization;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// One <see cref="AdminPipeFraming.OpAgentScript"/> request: which change (<see cref="Name"/>) and its arguments. The app never sends
/// PowerShell to the Agent: the Agent builds the script itself from <see cref="AgentScripts"/>, after checking the arguments.
/// </summary>
public sealed record AdminPipeScript(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("args")] IReadOnlyList<string>? Args = null);

/// <summary>
/// What the Agent does with administrator rights for the app, by name. Each entry checks its arguments, then either builds PowerShell from
/// this app's own code or names a change the Agent makes in C# (<see cref="AgentNativeAction"/>); anything else is refused. Replaces
/// sending scripts through <c>run_command</c>.
/// </summary>
public static class AgentScripts
{
    /// <summary>Args: the <see cref="SecurityFixes"/> key. Prints the current value (journaled before the change).</summary>
    public const string SecurityRead = "security_read";
    /// <summary>Args: the key. Makes the change and reads it back (exit 3 when Windows didn't keep it).</summary>
    public const string SecurityApply = "security_apply";
    /// <summary>Args: the key and the journaled previous value (<see cref="SecurityFixes.ParsePrevious"/>).</summary>
    public const string SecurityRestore = "security_restore";
    /// <summary>Args: drive letters ("C", "DE").</summary>
    public const string OptimizeVolume = "optimize_volume";
    /// <summary>Args: the Windows Update ID (a GUID).</summary>
    public const string InstallUpdate = "install_update";
    /// <summary>Args: "drivers" or "software".</summary>
    public const string WindowsUpdate = "windows_update";
    public const string CleanTemp = "clean_temp";
    /// <summary>Args: a process name (not protected, no wildcards). Prints the memory it freed.</summary>
    public const string StopProcess = "stop_process";
    /// <summary>Args: <see cref="RebootTask"/> or <see cref="WorkflowTask"/>, the user (DOMAIN\name), then the app's launch arguments.</summary>
    public const string ResumeTaskRegister = "resume_task_register";
    /// <summary>Args: <see cref="RebootTask"/> or <see cref="WorkflowTask"/>. Fails only when the task is still there afterwards.</summary>
    public const string ResumeTaskRemove = "resume_task_remove";
    /// <summary>Args: full Task Scheduler path (e.g. <c>\Folder\Task</c>) and <c>"false"</c> or <c>"true"</c>.</summary>
    public const string TaskWakeToRun = "task_wake_to_run";
    /// <summary>Args: allowlisted system dump path under <c>%SystemRoot%\Minidump</c>, <c>LiveKernelReports</c>, or <c>MEMORY.DMP</c>.</summary>
    public const string AnalyzeCrashDump = "analyze_crash_dump";
    /// <summary>Args: "microphone" or "webcam", then "Allow", "Deny" or "" (delete). The device-wide (HKLM) ConsentStore switch only.</summary>
    public const string CapturePrivacySet = "capture_privacy_set";
    /// <summary>Args: "start", "restart" (Windows Audio) or "restart_all" (the Endpoint Builder too). Only the two Windows Audio services.</summary>
    public const string AudioServices = "audio_services";
    /// <summary>Silently installs an allowlisted .NET SDK (10 or 11) side-by-side into Program Files\dotnet via the elevated Agent.</summary>
    public const string InstallDotNetSdk = "install_dotnet_sdk";
    /// <summary>Args: an HP battery charging BIOS setting's name (<see cref="Battery.HpBatteryCharge.IsSetting"/>). Prints its value.</summary>
    public const string HpBatteryRead = "hp_battery_read";
    /// <summary>Args: the setting's name and the value to set (the Agent checks the setting lists it).</summary>
    public const string HpBatterySet = "hp_battery_set";
    /// <summary>Args: "list"; "set", "windows" or "maker" and the mode's id; or "restore". Windows' power mode and the PC maker's thermal
    /// profile for the cooling test (<see cref="Cooling.AgentCoolingModes"/>); prints <see cref="Cooling.CoolingModesAnswer"/> JSON.</summary>
    public const string CoolingModes = "cooling_modes";

    public const string RebootTask = "reboot";
    public const string WorkflowTask = "workflow";

    public static AdminPipeScript Of(string name, params string[] args) => new(name, args);

    /// <summary>
    /// What the Agent does for <paramref name="request"/>: PowerShell, or a change it makes in C#. Null with <paramref name="refusal"/>
    /// saying why when it isn't done.
    /// </summary>
    /// <param name="appFolder">The installed app's folder: the resume task runs the Agent launcher from there (never a path the app sent).</param>
    public static AgentPlan? Plan(AdminPipeScript request, string? appFolder, out string? refusal, DateTimeOffset? now = null)
    {
        string? why = null;
        var plan = Plan(request, appFolder, now, r => why = r);
        refusal = plan is null ? why ?? "That change isn't allowed." : null;
        return plan;
    }

    /// <summary>The PowerShell for <paramref name="request"/>, or null with <paramref name="refusal"/> (also for a change the Agent makes in C#).</summary>
    public static string? Build(AdminPipeScript request, string? appFolder, out string? refusal, DateTimeOffset? now = null)
    {
        var plan = Plan(request, appFolder, out refusal, now);
        if (plan is { Script: null }) refusal = "The Agent makes this change itself, without PowerShell.";
        return plan?.Script;
    }

    private static AgentPlan? Plan(AdminPipeScript request, string? appFolder, DateTimeOffset? now, Action<string> refused)
    {
        var a = request.Args ?? [];
        string? Arg(int i) => i < a.Count ? a[i] : null;
        AgentPlan? Refuse(string why) { refused(why); return null; }
        static AgentPlan Native(AgentNativeAction action) => new(null, action);

        switch (request.Name)
        {
            case SecurityRead or SecurityApply:
                if (a.Count != 1 || SecurityFixes.Find(Arg(0)) is not { } fix) return Refuse("That isn't a security setting this app changes.");
                return Native(request.Name == SecurityRead ? new SecurityReadAction(fix.Key) : new SecurityApplyAction(fix.Key));

            case SecurityRestore:
                if (a.Count != 2 || SecurityFixes.Find(Arg(0)) is not { } restore) return Refuse("That isn't a security setting this app changes.");
                return SecurityFixes.ParsePrevious(restore.Key, Arg(1)) is { } previous
                    ? Native(new SecurityRestoreAction(restore.Key, previous)) : Refuse("The original setting wasn't recorded in a form this app wrote.");

            case OptimizeVolume:
                var letters = a.Count == 1 ? RemediationService.DriveLetters(Arg(0)) : "";
                if (letters.Length == 0) return Refuse("That isn't a drive letter.");
                return Native(new OptimizeVolumeAction(letters));

            case InstallUpdate:
                return a.Count == 1 && Guid.TryParse(Arg(0), out var updateId) ? Native(new InstallUpdateAction(updateId)) : Refuse("That isn't a Windows Update ID.");

            case WindowsUpdate:
                return a.Count == 1 && Arg(0) is "drivers" or "software"
                    ? Native(new WindowsUpdateAction(Arg(0) == "drivers")) : Refuse("Only driver or software updates.");

            case CleanTemp:
                return a.Count == 0 ? Native(new CleanTempAction()) : Refuse("Cleaning temporary files takes no arguments.");

            case StopProcess:
                var name = a.Count == 1 ? Arg(0)?.Trim() : null;
                if (!IsProcessName(name) || ProcessProtection.IsProtected(name!)) return Refuse("That process is protected or isn't a process name.");
                return Native(new StopProcessAction(name!));

            case ResumeTaskRegister:
                if (a.Count < 3 || TaskName(Arg(0)) is not { } task) return Refuse("That isn't a sign-in task this app creates.");
                if (!IsAccountName(Arg(1))) return Refuse("That isn't a Windows account name.");
                var launch = a.Skip(2).ToList();
                if (!launch.All(IsLaunchArgument)) return Refuse("Those aren't arguments the app starts with.");
                if (string.IsNullOrEmpty(appFolder)) return Refuse("The app's folder isn't known.");
                // A Windows path, joined the same way wherever this runs (the task is for Task Scheduler).
                appFolder = appFolder.TrimEnd('\\', '/');
                var agent = appFolder + "\\" + ElevationService.AdminHelperExeName;
                // The reboot task stops firing once the saved restart state would have expired; the workflow's runs until the workflow removes it.
                DateTimeOffset? end = Arg(0) == RebootTask ? (now ?? DateTimeOffset.Now).Add(SessionLaunchOptions.PendingRebootMaxAge) : null;
                return Native(new RegisterTaskAction(task, Arg(1)!,
                    ResumeTaskXml.Build(agent, "--launch " + string.Join(' ', launch), appFolder, Arg(1)!, end, highest: true)));

            case ResumeTaskRemove:
                return a.Count == 1 && TaskName(Arg(0)) is { } remove ? Native(new RemoveTaskAction(remove)) : Refuse("That isn't a sign-in task this app creates.");

            case TaskWakeToRun:
                if (a.Count != 2 || !Areas.DeviceWake.IsSafeTaskPath(Arg(0)) || Arg(1) is not ("true" or "false"))
                    return Refuse("That isn't a valid scheduled task wake setting.");
                return Native(new SetTaskWakeToRunAction(Arg(0)!, Arg(1) == "true"));

            case AnalyzeCrashDump:
                if (a.Count != 1 || !Areas.CrashDumpDebugger.IsAllowedSystemDumpPath(Arg(0)))
                    return Refuse("That dump path isn't in a Windows system dump folder.");
                return Native(new AnalyzeCrashDumpAction(Arg(0)!.Trim()));

            case CapturePrivacySet:
                if (a.Count != 2 || !Audio.CapturePrivacy.IsCapability(Arg(0)) || !Audio.CapturePrivacy.IsValue(Arg(1)))
                    return Refuse("That isn't a privacy switch this app changes.");
                return Native(new SetCapturePrivacyAction(Arg(0)!, Arg(1) is { Length: > 0 } v ? v : null));

            case AudioServices:
                if (a.Count != 1 || !Audio.AudioServices.IsVerb(Arg(0))) return Refuse("That isn't something this app does to Windows Audio.");
                return Native(new AudioServicesAction(Arg(0)!));

            case InstallDotNetSdk:
                if (a.Count != 1 || !int.TryParse(Arg(0), out var sdkMajor) || !AgentDotNetSdkInstaller.IsAllowedMajor(sdkMajor))
                    return Refuse("Only .NET 10 and .NET 11 SDKs can be installed.");
                return Native(new InstallDotNetSdkAction(sdkMajor));

            case HpBatteryRead:
                return a.Count == 1 && Battery.HpBatteryCharge.IsSetting(Arg(0))
                    ? Native(new Battery.HpBatteryReadAction(Arg(0)!)) : Refuse("That isn't an HP battery setting this app changes.");

            case HpBatterySet:
                return a.Count == 2 && Battery.HpBatteryCharge.IsSetting(Arg(0)) && Battery.HpBatteryCharge.IsValue(Arg(1))
                    ? Native(new Battery.HpBatterySetAction(Arg(0)!, Arg(1)!)) : Refuse("That isn't an HP battery setting this app changes.");

            case CoolingModes:
                return Cooling.CoolingModesAction.Parse(a) is { } cooling ? Native(cooling) : Refuse("That isn't a thermal mode request this app sends.");

            default:
                return Refuse($"Unknown script '{request.Name}'.");
        }
    }

    public static string? TaskName(string? kind) => kind switch
    {
        RebootTask => RebootResumeCoordinator.ResumeTaskName,
        WorkflowTask => WorkflowService.ResumeTaskName,
        _ => null,
    };

    /// <summary>A process name as Task Manager shows it: no path, no wildcards, no quotes.</summary>
    public static bool IsProcessName(string? name) =>
        name is { Length: > 0 and <= 128 } && name.All(c => char.IsLetterOrDigit(c) || c is ' ' or '.' or '-' or '_' or '(' or ')' or '+');

    /// <summary>DOMAIN\name (or a local name), as Windows writes a sign-in task's user.</summary>
    public static bool IsAccountName(string? user)
    {
        if (user is not { Length: > 0 and <= 256 } || user.Any(c => char.IsControl(c) || c is '"' or '/' or '[' or ']' or ':' or ';' or '|' or '=' or ',' or '+' or '*' or '?' or '<' or '>' or '@'))
            return false;
        var parts = user.Split('\\');
        return parts.Length is 1 or 2 && parts.All(p => p.Trim().Length > 0);
    }

    /// <summary>One argument <see cref="SessionLaunchOptions.BuildResumeCommandLine"/> writes (plus the workflow's), and nothing else.</summary>
    public static bool IsLaunchArgument(string? arg)
    {
        if (string.IsNullOrEmpty(arg)) return false;
        if (arg is SessionLaunchOptions.PostRebootArg or SessionLaunchOptions.WorkflowArg or SessionLaunchOptions.UnattendedArg
            or SessionLaunchOptions.VoiceArg or SessionLaunchOptions.AdminArg or "--no-admin")
            return true;
        if (arg.StartsWith("-u=", StringComparison.Ordinal))
            return Uri.TryCreate(arg[3..], UriKind.Absolute, out var u) && u.Scheme is "https" or "http" && arg.All(c => c > ' ' && c is not ('"' or '\'' or '`'));
        if (arg.StartsWith("-i=", StringComparison.Ordinal)) return Guid.TryParseExact(arg[3..], "D", out _);
        if (arg.StartsWith("-g=", StringComparison.Ordinal))
            return arg.Length is > 3 and <= 67 && arg[3..].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
        return false;
    }
}

/// <summary>The "continue after the restart" sign-in tasks (the restart fix and benchmark, and the service workflow).</summary>
public static class ResumeTaskScript
{
    private static string Q(string s) => s.Replace("'", "''");

    /// <summary>
    /// The arguments of <paramref name="commandLine"/> (<see cref="SessionLaunchOptions.BuildResumeCommandLine"/>: the quoted
    /// <paramref name="executablePath"/>, then arguments without spaces), one by one, as the Agent checks them.
    /// </summary>
    public static IReadOnlyList<string> LaunchArguments(string executablePath, string commandLine)
    {
        var quotedExe = $"\"{executablePath.Trim('"')}\"";
        var rest = commandLine.StartsWith(quotedExe, StringComparison.OrdinalIgnoreCase) ? commandLine[quotedExe.Length..] : SessionLaunchOptions.PostRebootArg;
        return rest.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>
    /// At <paramref name="user"/>'s sign-in, runs <paramref name="execute"/> <paramref name="arguments"/>. <paramref name="highest"/> only for the
    /// Agent's launcher (it starts the app un-elevated); the app itself only ever gets limited rights.
    /// </summary>
    public static string Register(string taskName, string execute, string arguments, string? workDir, string user, DateTimeOffset? endBoundary, bool highest) =>
        "$ErrorActionPreference='Stop';" +
        $"$a=New-ScheduledTaskAction -Execute '{Q(execute)}' -Argument '{Q(arguments)}'" + (string.IsNullOrEmpty(workDir) ? "" : $" -WorkingDirectory '{Q(workDir)}'") + ";" +
        $"$t=New-ScheduledTaskTrigger -AtLogOn -User '{Q(user)}';" +
        (endBoundary is { } end ? $"$t.EndBoundary='{end.LocalDateTime.ToString("s", CultureInfo.InvariantCulture)}';" : "") +
        $"$p=New-ScheduledTaskPrincipal -UserId '{Q(user)}' -LogonType Interactive -RunLevel {(highest ? "Highest" : "Limited")};" +
        "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero);" +
        $"Register-ScheduledTask -TaskName '{Q(taskName)}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null";

    public static string Remove(string taskName) =>
        $"Unregister-ScheduledTask -TaskName '{Q(taskName)}' -Confirm:$false -ErrorAction SilentlyContinue; " +
        $"if (Get-ScheduledTask -TaskName '{Q(taskName)}' -ErrorAction SilentlyContinue) {{ exit 1 }}";
}
