using System.Text.Json;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Hard-coded list of Windows and self processes that <see cref="RemediationService"/> never terminates.</summary>
public static class ProcessProtection
{
    public static readonly IReadOnlySet<string> ProtectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Memory Compression",
        "smss", "smss.exe", "csrss", "csrss.exe", "wininit", "wininit.exe",
        "services", "services.exe", "lsass", "lsass.exe", "svchost", "svchost.exe",
        "winlogon", "winlogon.exe", "explorer", "explorer.exe", "dwm", "dwm.exe",
        "fontdrvhost", "fontdrvhost.exe", "spoolsv", "spoolsv.exe", "taskhostw", "taskhostw.exe",
        "sihost", "sihost.exe", "RuntimeBroker", "RuntimeBroker.exe", "SearchIndexer", "SearchIndexer.exe",
        "MsMpEng", "MsMpEng.exe", "SecurityHealthService", "SecurityHealthService.exe",
        "audiodg", "audiodg.exe", "conhost", "conhost.exe", "dllhost", "dllhost.exe",
        "WmiPrvSE", "WmiPrvSE.exe", "ctfmon", "ctfmon.exe",
        // Service-hosting collector: use its Manual-only service recommendation, never generic End task.
        "StandardCollector.Service", "StandardCollector.Service.exe",
    };

    public static bool IsProtected(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return true;
        var trimmed = name.Trim();
        if (ProtectedNames.Contains(trimmed)) return true;
        var noExt = Path.GetFileNameWithoutExtension(trimmed);
        if (ProtectedNames.Contains(noExt)) return true;
        // Same list the Memory page uses ("this app and its web view", security, shell), so End task can't kill them either.
        if (Optimizations.ProtectedProcesses.Names.Contains(trimmed) || Optimizations.ProtectedProcesses.Names.Contains(noExt)) return true;
        return ServiceProtection.IsSelfComponent(trimmed);
    }
}

public sealed record RemediationPlan(
    AreaAction Action,
    string Title,
    string WhatItIs,
    string WhatWillHappen,
    string? Warning,
    bool Allowed);

public sealed record RemediationResult(
    bool Success,
    string Message,
    long FreedDiskBytes = 0,
    int RemovedFiles = 0,
    long FreedMemoryBytes = 0,
    int UpdatesInstalled = 0,
    bool RestartNeeded = false);

/// <summary>A fix that is running now (started from a page or by a remote agent). It keeps running when its page is left.</summary>
public sealed record FixRun(AreaAction Action, string Title, string Origin, DateTimeOffset StartedUtc, string? Progress = null);

/// <summary>How the last fix started with <see cref="RemediationService.RunTrackedAsync"/> ended. <see cref="Seq"/> grows with every result.</summary>
public sealed record FixRunResult(int Seq, AreaAction Action, string Origin, bool Success, string Message, bool RestartNeeded, DateTimeOffset FinishedUtc);

public sealed record RemediationRecord(
    DateTime When,
    string Actor,
    RemediationKind Kind,
    string Target,
    bool Success,
    string Message,
    long FreedDiskBytes = 0,
    int RemovedFiles = 0,
    long FreedMemoryBytes = 0,
    int UpdatesInstalled = 0);

/// <summary>
/// Plans, executes, and audits one-click automated fixes across the 4 diagnostic remediation areas:
/// (1) Drivers &amp; Windows Updates, (2) Performance/Power/Uptime, (3) Network/Proxy/DNS, and (4) Storage/Temp Cleanup.
/// </summary>
public sealed class RemediationService(
    SystemCommandRunner commands,
    ISessionContext? session = null,
    ILogger? log = null,
    RebootResumeCoordinator? rebootResume = null,
    Changes.IChangeJournal? journal = null,
    RetrimLog? retrimLog = null,
    ISystemSettings? settings = null,
    Bios.IBiosUpdateService? bios = null)
{
    /// <summary>This app's record of successful retrims (so Drive health stops offering it right away).</summary>
    public RetrimLog? RetrimLog => retrimLog;

    public const int MaxRecent = 50;
    public const string BalancedPlanGuid = "381b4222-f694-41f0-9685-ff5bb260df2e";

    private readonly List<RemediationRecord> _recent = [];
    private readonly object _gate = new();

    public RebootResumeCoordinator RebootResume { get; } = rebootResume ?? new RebootResumeCoordinator(commands, log: log);

    public event Action<RemediationRecord>? ActionCompleted;

    public IReadOnlyList<RemediationRecord> Recent
    {
        get { lock (_gate) return _recent.ToList(); }
    }

    public string Actor => ServiceActor.From(session);

    private void Log(string m) => (log ?? commands.Log).Info("[remediation] " + m);
    private void LogWarn(string m) => (log ?? commands.Log).Warn("[remediation] " + m);
    private void LogError(string m) => (log ?? commands.Log).Error("[remediation] " + m);

    public RemediationPlan Plan(AreaAction action)
    {
        var label = string.IsNullOrWhiteSpace(action.TargetLabel) ? action.Target : action.TargetLabel;
        return action.Kind switch
        {
            // 1. Drivers & Windows Updates
            RemediationKind.CheckAndInstallDriverUpdates => new(
                action,
                "Check & install driver updates?",
                "Searches Windows Update for pending hardware driver updates for this PC.",
                "If driver updates are available, Windows will download and install them (or open Optional Driver Updates if confirmation is needed).",
                "Installing display or network drivers may briefly flicker the screen or reconnect the network.",
                true),

            RemediationKind.CheckAndInstallWindowsUpdates => new(
                action,
                "Check & install Windows updates?",
                "Searches Windows Update for pending security and quality updates.",
                "Windows will scan for pending updates and start downloading and installing them.",
                "Some updates may require a restart after installation finishes.",
                true),

            RemediationKind.RestartDevice => new(
                action,
                $"Restart {label}?",
                $"Resets hardware device '{label}' in Device Manager via pnputil.",
                "Windows will stop and restart the device driver without rebooting the PC.",
                commands.HasAdminRights
                    ? "If this is a network or display device, it may briefly disconnect or flicker."
                    : "Requires administrator privileges. If this is a network or display device, it may briefly disconnect or flicker.",
                !string.IsNullOrWhiteSpace(action.Target)),

            RemediationKind.EnableDevice => new(
                action,
                $"Enable {label}?",
                $"Re-enables disabled device '{label}' in Device Manager via pnputil.",
                "Windows will enable the device and load its driver.",
                commands.HasAdminRights ? null : "Requires administrator privileges.",
                !string.IsNullOrWhiteSpace(action.Target)),

            RemediationKind.ScanHardwareChanges => new(
                action,
                "Scan for hardware changes?",
                "Triggers a Plug and Play device rescan across the system.",
                "Windows will check all buses for newly connected or reset hardware devices.",
                null,
                true),

            // 2. Performance, Power Plan & Uptime
            RemediationKind.SetBalancedPowerPlan => new(
                action,
                "Switch to Balanced power plan?",
                "The PC is currently using a Power Saver scheme that caps CPU clock speeds.",
                "Windows will activate the standard Balanced power plan immediately so the processor can boost to full speed when needed.",
                null,
                true),

            RemediationKind.DisableFastStartup => new(
                action,
                "Turn off Windows Fast Startup?",
                "Fast Startup (Hiberboot) saves kernel state to disk on Shut Down instead of performing a full reset, which can cause multi-week uptimes and driver quirks.",
                "Sets HiberbootEnabled = 0 in the Windows registry so every Shut Down performs a clean boot.",
                "Requires administrator privileges.",
                true),

            RemediationKind.ScheduleCleanRestart => new(
                action,
                session?.Mode == SessionMode.Remote
                    ? "Schedule a clean PC restart in 60 seconds (and auto-resume this remote session)?"
                    : "Schedule a clean PC restart in 60 seconds?",
                "Records current memory and process usage, registers a sign-in task to relaunch Remote PC Diagnostics into the same session, and restarts the PC in 60 seconds. Where Windows allows it, the same user is signed back in automatically with the screen locked.",
                session?.Mode == SessionMode.Remote
                    ? "After the PC reboots and signs back in, Remote PC Diagnostics will automatically reconnect to this exact remote session link, re-measure running resources, and log the RAM/process reduction in History."
                    : "After the PC reboots and signs back in, Remote PC Diagnostics will automatically relaunch, re-measure running resources, and log the RAM/process reduction in History.",
                session?.Mode == SessionMode.Remote
                    ? "Remote mode: the connection will pause while Windows restarts and automatically resume once the user signs back in. Make sure any unsaved documents are saved."
                    : "Make sure any unsaved documents are saved before restarting.",
                true),

            RemediationKind.CancelScheduledRestart => new(
                action,
                "Cancel scheduled restart?",
                "Aborts a pending timed Windows shutdown or restart and clears the post-reboot auto-resume entry.",
                "Runs 'shutdown /a' and removes the pending sign-in task so the PC stays on.",
                null,
                true),

            RemediationKind.EndProcessGroup => PlanEndProcess(action, label),

            RemediationKind.DisableDeviceWake => new(
                action,
                $"Stop {label} from waking the PC?",
                $"'{label}' is allowed to wake this PC from sleep. A mouse nudged in a bag, a network adapter or a USB controller often wakes a PC by itself and drains the battery.",
                $"Runs 'powercfg /devicedisablewake' for this one device. The PC then stays asleep when the device is used; the power button (and the lid, on a laptop) still wake it. Undo lets the device wake the PC again.",
                DeviceWake.IsSafeName(action.Target) ? "Requires administrator privileges." : "This isn't a device name this app can change.",
                DeviceWake.IsSafeName(action.Target)),

            // 3. Network & Connectivity Fixes
            RemediationKind.DisableSystemProxy => new(
                action,
                "Disable Windows system HTTP proxy?",
                "A system-wide proxy is currently enabled in Windows Internet Settings.",
                "Turns off ProxyEnable for the current Windows user so browsers and apps connect directly to the internet.",
                "If this PC is on a corporate network that requires a proxy server, disabling it may block web access.",
                true),

            RemediationKind.FlushDnsAndRenewIp => new(
                action,
                "Flush DNS cache & renew IP address?",
                "Clears stale DNS records and refreshes the DHCP lease on active network adapters.",
                "Runs 'ipconfig /flushdns' and 'ipconfig /renew'.",
                session?.Mode == SessionMode.Remote
                    ? "Running in Remote mode: renewing the IP lease may briefly pause this remote session for a few seconds."
                    : null,
                true),

            RemediationKind.SetPublicDns => new(
                action,
                $"Use Cloudflare & Google DNS on {label}?",
                $"Configures adapter '{label}' to use fast, reliable public DNS servers (1.1.1.1 and 8.8.8.8).",
                "Updates the IPv4 DNS server addresses on this adapter.",
                "Requires administrator privileges.",
                !string.IsNullOrWhiteSpace(action.Target)),

            RemediationKind.ResetDhcpDns => new(
                action,
                $"Reset DNS to automatic (DHCP) on {label}?",
                (action.CurrentSetting is { Length: > 0 } dns ? $"Current DNS servers on {label} at last check: {DnsSpeedTest.FormatServers(dns)}. " : "") +
                $"Restores automatic DNS settings on adapter '{label}'.",
                "Clears custom static DNS server addresses so Windows uses the DNS provided by the router/DHCP.",
                "Requires administrator privileges.",
                !string.IsNullOrWhiteSpace(action.Target)),

            // 4. Storage & Disk Space Cleanup
            RemediationKind.CleanTempFiles => new(
                action,
                "Clean up temporary files & Recycle Bin?",
                "Removes unlocked temporary files in %TEMP%, C:\\Windows\\Temp (older than 24 hours), and empties the Recycle Bin.",
                "Frees disk space without touching personal documents, downloads, or active app files.",
                null,
                true),

            RemediationKind.OptimizeSsd => new(
                action,
                $"Optimize / Retrim {label}?",
                "Sends TRIM / ReTrim optimization commands to the solid-state drive so it can maintain peak write speeds.",
                DriveLetters(action.Target) is { Length: > 0 } dl ? $"Runs 'Optimize-Volume -DriveLetter {string.Join(",", dl.ToCharArray())} -ReTrim'." : "Nothing will run.",
                DriveLetters(action.Target).Length > 0 ? "Requires administrator privileges." : "This drive has no drive letter to optimize.",
                DriveLetters(action.Target).Length > 0),

            // 5. Windows repair
            RemediationKind.RepairComponentStore => new(
                action,
                "Repair the Windows component store (DISM RestoreHealth)?",
                "Repairs corruption DISM found in the Windows component store (the copies Windows uses to fix its own files)."
                    + (action.Target == "needs-source" ? " DISM reported the store cannot be repaired from local files: this needs Windows Update (internet) or a matching installation source." : ""),
                "Runs 'dism.exe /English /Online /Cleanup-Image /RestoreHealth' (10–30 minutes; may download files from Windows Update). Not undoable.",
                "Requires administrator privileges.",
                true),

            RemediationKind.RepairSystemFiles => new(
                action,
                "Repair protected system files (SFC /scannow)?",
                "Replaces corrupt or changed protected Windows files with good copies from the component store.",
                "Runs 'sfc.exe /scannow' (10–20 minutes), after DISM RestoreHealth when both run. Not undoable.",
                "Requires administrator privileges.",
                true),

            RemediationKind.AnalyzeComponentStore => new(
                action,
                "Analyze the Windows component store?",
                "Measures the component store (WinSxS) and reports whether a cleanup is recommended.",
                "Runs 'dism.exe /English /Online /Cleanup-Image /AnalyzeComponentStore' (a few minutes). Changes nothing on the PC.",
                "Requires administrator privileges.",
                true),

            RemediationKind.CleanUpComponentStore => new(
                action,
                "Clean up the Windows component store?",
                "Removes older versions of Windows components that newer updates have replaced.",
                "Runs 'dism.exe /English /Online /Cleanup-Image /StartComponentCleanup' (10–30 minutes). Installed updates can still be uninstalled afterwards. Not undoable.",
                "Requires administrator privileges. Restart the PC afterwards, before repairing the store again.",
                true),

            RemediationKind.RepairComponentStoreFromImage => new(
                action,
                "Repair the Windows component store from a Windows image?",
                $"Repairs the component store from '{label}' instead of Windows Update, for when Windows Update doesn't have the files.",
                "Finds the image of this PC's Windows edition, then runs 'dism.exe /English /Online /Cleanup-Image /RestoreHealth /Source:… /LimitAccess' (10–30 minutes). Not undoable.",
                WindowsRepair.IsImagePath(action.Target)
                    ? "Requires administrator privileges. The image must be the same Windows version and edition as this PC; another version usually fails."
                    : "This isn't a Windows image file (.wim or .esd) this app can use.",
                WindowsRepair.IsImagePath(action.Target)),

            RemediationKind.InstallUpdate => new(
                action,
                $"Install {label}?",
                "Installs this one update from Windows Update and leaves the other pending updates alone.",
                "Windows downloads the update if needed and installs it. Not undoable from here.",
                Guid.TryParse(action.Target, out _) ? "The update may need a restart to finish. A display or network driver may briefly flicker the screen or reconnect the network."
                    : "This update has no Windows Update ID.",
                Guid.TryParse(action.Target, out _)),

            RemediationKind.ApplySecuritySetting => Security.SecurityFixes.Find(action.Target) is { } sf
                ? new(action, $"{sf.ButtonText}?", sf.WhatItIs, sf.WhatHappens, sf.Caveat, true)
                : new(action, action.ButtonText, "", "This setting isn't one this app changes.", "This setting isn't one this app changes.", Allowed: false),

            RemediationKind.InstallBiosUpdate => new(
                action,
                string.IsNullOrWhiteSpace(label) ? "Update BIOS to latest version?" : $"Update BIOS to {label}?",
                "Downloads, verifies, and stages the official vendor BIOS/UEFI firmware update for this PC.",
                "Checks AC power, battery level, BitLocker, and administrator prerequisites, suspends BitLocker for one reboot if active, verifies the signed vendor package, and stages the BIOS update. Not undoable.",
                bios is null
                    ? "BIOS update service is not available in this session."
                    : "Requires administrator privileges, AC power, and a restart to finish flashing. Do not turn off or unplug the PC while the BIOS update is applying.",
                bios is not null),

            _ => new(action, action.ButtonText, "", "", null, true),
        };
    }

    private static RemediationPlan PlanEndProcess(AreaAction action, string label)
    {
        if (ProcessProtection.IsProtected(action.Target))
        {
            return new(
                action,
                $"End {label}?",
                $"{label} is a core Windows or diagnostics process.",
                "This process cannot be terminated from here.",
                $"{label} is protected by Windows and cannot be stopped.",
                Allowed: false);
        }

        return new(
            action,
            $"End {label}?",
            $"Closes all running instances of '{action.Target}'.",
            "Windows will terminate the process immediately to free its memory and CPU usage.",
            "Any unsaved work inside that app will be lost.",
            Allowed: true);
    }

    public async Task<RemediationResult> ExecuteAsync(AreaAction action, CancellationToken ct = default)
    {
        var actor = Actor;
        var plan = Plan(action);
        Log($"{actor} requested {action.Kind} target='{action.Target}'");

        RemediationResult result;
        if (!plan.Allowed)
        {
            result = new(false, plan.Warning ?? "This action is not allowed.");
        }
        else
        {
            try
            {
                var before = await CaptureBeforeAsync(action, ct).ConfigureAwait(false);
                result = await RunActionAsync(action, ct).ConfigureAwait(false);
                if (result.Success && before is not null) try { journal?.Add(before); } catch (Exception ex) { Log($"journal: {ex.Message}"); }
                // Permanent changes are journaled too, so "Undo all" can say what it left as is. Update checks that installed nothing changed nothing.
                // Temp cleanup writes its own TempFiles record (with the amount freed), so it isn't recorded twice.
                var permanent = Changes.Undoability.Of(action.Kind) == Changes.UndoSupport.None && action.Kind != RemediationKind.CleanTempFiles
                    && (action.Kind is not (RemediationKind.CheckAndInstallWindowsUpdates or RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.InstallUpdate or RemediationKind.InstallBiosUpdate) || result.UpdatesInstalled > 0);
                if (result.Success && permanent)
                    try { journal?.Add(Changes.Undoability.Permanent($"{action.Kind}:{action.Target}:{Guid.NewGuid():N}", $"{plan.Title.TrimEnd('?')}: {result.Message}", actor)); }
                    catch (Exception ex) { Log($"journal: {ex.Message}"); }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                result = new(false, "Cancelled. Windows may still finish the operation in the background.");
            }
            catch (Exception ex)
            {
                LogError($"{action.Kind} failed: {ex}");
                result = new(false, $"Couldn't complete '{action.ButtonText}'. " + ElevationService.AdminRepairHint);
            }
        }

        if (action.Kind == RemediationKind.OptimizeSsd && result.Success)
            try { retrimLog?.Record(action.Target, DateTimeOffset.Now); } catch (Exception ex) { Log($"retrim log: {ex.Message}"); }
        RecordCompleted(
            actor,
            action.Kind,
            action.TargetLabel.Length > 0 ? action.TargetLabel : action.Target,
            result.Success,
            result.Message,
            result.FreedDiskBytes,
            result.RemovedFiles,
            result.FreedMemoryBytes,
            result.UpdatesInstalled);
        return result;
    }

    /// <summary>Records a completed remediation (including post-reboot verification) and notifies <see cref="ActionCompleted"/> listeners.</summary>
    public RemediationRecord RecordCompleted(
        string actor,
        RemediationKind kind,
        string target,
        bool success,
        string message,
        long freedDiskBytes = 0,
        int removedFiles = 0,
        long freedMemoryBytes = 0,
        int updatesInstalled = 0)
    {
        var rec = new RemediationRecord(
            DateTime.Now,
            actor,
            kind,
            target,
            success,
            message,
            freedDiskBytes,
            removedFiles,
            freedMemoryBytes,
            updatesInstalled);
        lock (_gate)
        {
            _recent.Insert(0, rec);
            if (_recent.Count > MaxRecent) _recent.RemoveAt(_recent.Count - 1);
        }
        Log($"AUDIT when={rec.When:O} actor='{actor}' kind={kind} target='{target}' success={success} freedDisk={freedDiskBytes} freedMem={freedMemoryBytes} message='{message}'");
        try { ActionCompleted?.Invoke(rec); } catch (Exception ex) { LogError($"ActionCompleted handler failed: {ex}"); }
        return rec;
    }

    private async Task<RemediationResult> RunActionAsync(AreaAction action, CancellationToken ct) => action.Kind switch
    {
        RemediationKind.CheckAndInstallDriverUpdates => await RunWindowsUpdateAsync(driversOnly: true, ct).ConfigureAwait(false),
        RemediationKind.CheckAndInstallWindowsUpdates => await RunWindowsUpdateAsync(driversOnly: false, ct).ConfigureAwait(false),
        RemediationKind.RestartDevice => await RunPnpUtilAsync(["/restart-device", action.Target], $"Restarted {Display(action)}", $"Couldn't restart {Display(action)} (administrator rights required).", ct).ConfigureAwait(false),
        RemediationKind.EnableDevice => await RunPnpUtilAsync(["/enable-device", action.Target], $"Enabled {Display(action)}", $"Couldn't enable {Display(action)} (administrator rights required).", ct).ConfigureAwait(false),
        RemediationKind.ScanHardwareChanges => await RunPnpUtilAsync(["/scan-devices"], "Scanned for hardware changes.", "Couldn't scan for hardware changes.", ct).ConfigureAwait(false),

        RemediationKind.SetBalancedPowerPlan => await RunSimpleAsync(
            SystemCommandRunner.SystemTool("powercfg.exe"),
            ["/setactive", BalancedPlanGuid],
            "Switched active power plan to Balanced.",
            "Couldn't switch the power plan.",
            ct).ConfigureAwait(false),

        RemediationKind.DisableFastStartup => Apply(s => s.SetFastStartup(0),
            "Turned off Fast Startup (future shutdowns will perform a full reset).",
            "Couldn't turn off Fast Startup (administrator rights required)."),

        RemediationKind.ScheduleCleanRestart => await RunScheduleCleanRestartAsync(action, ct).ConfigureAwait(false),

        RemediationKind.CancelScheduledRestart => await RunCancelScheduledRestartAsync(ct).ConfigureAwait(false),

        RemediationKind.EndProcessGroup => await RunEndProcessAsync(action, ct).ConfigureAwait(false),

        RemediationKind.DisableSystemProxy => Apply(s => s.SetUserProxyEnable(0),
            "Disabled the Windows system HTTP proxy.",
            "Couldn't disable the system proxy."),

        RemediationKind.FlushDnsAndRenewIp => await RunFlushAndRenewAsync(ct).ConfigureAwait(false),

        RemediationKind.SetPublicDns => Apply(s => s.SetAdapterDns(AdapterName(action.Target), PublicDns),
            $"Configured {Display(action)} to use Cloudflare (1.1.1.1) and Google (8.8.8.8) DNS.",
            $"Couldn't set DNS on {Display(action)} (administrator rights required)."),

        RemediationKind.ResetDhcpDns => Apply(s => s.SetAdapterDns(AdapterName(action.Target), []),
            $"Reset DNS on {Display(action)} to automatic (DHCP).",
            $"Couldn't reset DNS on {Display(action)} (administrator rights required)."),

        RemediationKind.CleanTempFiles => await RunCleanTempFilesAsync(ct).ConfigureAwait(false),

        RemediationKind.ApplySecuritySetting => Security.SecurityFixes.Find(action.Target) is { } sf
            ? await RunAgentScriptAsync(AgentScripts.Of(AgentScripts.SecurityApply, sf.Key), sf.Done,
                $"Couldn't change {sf.Label.ToLowerInvariant()} (Windows refused the change; Tamper Protection or an organization policy may be blocking it).", ct).ConfigureAwait(false)
            : new(false, "This setting isn't one this app changes."),

        RemediationKind.RepairComponentStore or RemediationKind.RepairSystemFiles or RemediationKind.AnalyzeComponentStore
            or RemediationKind.CleanUpComponentStore or RemediationKind.RepairComponentStoreFromImage
            => ToResult(LastRepair = await RepairAsync(action, RepairProgress, ct).ConfigureAwait(false)),

        RemediationKind.InstallUpdate => await RunInstallUpdateAsync(action, ct).ConfigureAwait(false),

        RemediationKind.DisableDeviceWake => await RunDisableDeviceWakeAsync(action, ct).ConfigureAwait(false),

        RemediationKind.InstallBiosUpdate => await RunInstallBiosUpdateAsync(ct).ConfigureAwait(false),

        RemediationKind.OptimizeSsd => await RunAgentScriptAsync(
            AgentScripts.Of(AgentScripts.OptimizeVolume, DriveLetters(action.Target)),
            $"Optimized / Retrimmed {Display(action)}.",
            $"Couldn't optimize {Display(action)} (administrator rights required).",
            ct, OptimizeTimeout).ConfigureAwait(false),

        _ => new(false, "Unsupported action."),
    };

    private async Task<RemediationResult> RunInstallBiosUpdateAsync(CancellationToken ct)
    {
        if (bios is null)
            return new(false, "BIOS update service is not available in this session.");

        RepairProgress?.Report("Checking current BIOS version and vendor catalog…");
        var outcome = await bios.CheckForUpdateAsync(ct).ConfigureAwait(false);
        if (outcome.Latest.Status == Bios.BiosCheckStatus.UpToDate)
            return new(true, string.IsNullOrWhiteSpace(outcome.Latest.Message) ? "BIOS is already up to date." : outcome.Latest.Message);

        if (outcome.Latest.Status != Bios.BiosCheckStatus.UpdateAvailable)
            return new(false, outcome.Latest.Message ?? "No installable BIOS update is available.");

        var request = new Bios.BiosInstallRequest(
            System: outcome.System,
            Current: outcome.Current,
            Target: outcome.Latest,
            Approved: true,
            ApprovedBy: Actor,
            AllowReboot: false,
            SuspendBitLocker: true);

        IProgress<Bios.BiosInstallProgress>? progress = RepairProgress is { } rp
            ? new Progress<Bios.BiosInstallProgress>(p =>
            {
                var msg = string.IsNullOrWhiteSpace(p.Detail) ? p.Stage.ToString() : p.Detail;
                rp.Report(p.Percent is > 0 and < 100 ? $"{msg} ({p.Percent}%)" : msg);
            })
            : null;

        var install = await bios.InstallUpdateAsync(request, progress, ct).ConfigureAwait(false);
        var message = string.IsNullOrWhiteSpace(install.Message)
            ? (install.Succeeded ? $"BIOS update to {install.TargetVersion} staged." : "BIOS update failed.")
            : install.Message;
        var installedCount = install.Succeeded && install.Status != Bios.BiosInstallStatus.AlreadyUpToDate ? 1 : 0;
        return new(install.Succeeded, message, UpdatesInstalled: installedCount, RestartNeeded: install.RequiresReboot);
    }

    /// <summary>Only a device Windows lists as wake-armed right now, by the name Windows gives it.</summary>
    private async Task<RemediationResult> RunDisableDeviceWakeAsync(AreaAction action, CancellationToken ct)
    {
        var armed = await DeviceWake.QueryArmedAsync(commands, ct).ConfigureAwait(false);
        if (armed is null) return new(false, "Couldn't read which devices can wake this PC.");
        if (DeviceWake.FindArmed(armed, action.Target) is not { } device)
            return new(true, $"{Display(action)} already can't wake the PC.");
        return await RunAdminSimpleAsync(DeviceWake.PowerCfg, ["/devicedisablewake", device],
            $"{Display(action)} no longer wakes the PC from sleep.",
            $"Couldn't stop {Display(action)} from waking the PC (administrator rights required).", ct).ConfigureAwait(false);
    }

    private static RemediationResult ToResult(RepairResult r) => new(r.Success, r.Summary, RestartNeeded: r.RebootRequired);

    /// <summary>The repair step a fix kind runs; null for kinds that aren't Windows repair steps.</summary>
    public static RepairStep? StepOf(RemediationKind kind) => kind switch
    {
        RemediationKind.AnalyzeComponentStore => RepairStep.AnalyzeStore,
        RemediationKind.CleanUpComponentStore => RepairStep.CleanUpStore,
        RemediationKind.RepairComponentStore => RepairStep.RestoreHealth,
        RemediationKind.RepairComponentStoreFromImage => RepairStep.RestoreHealthFromImage,
        RemediationKind.RepairSystemFiles => RepairStep.SfcScanNow,
        _ => null,
    };

    /// <summary>True for a fix that only reads (it leaves nothing to verify, so its check isn't run again afterwards).</summary>
    public static bool IsReadOnly(RemediationKind kind) => kind == RemediationKind.AnalyzeComponentStore;

    // ---- One fix at a time, kept running when its page is left ------------------------------------------------------------

    private FixRun? _running;
    private FixRunResult? _lastRun;
    private CancellationTokenSource? _runCts;
    private int _runSeq;

    /// <summary>The fix running now, if any.</summary>
    public FixRun? Running { get { lock (_gate) return _running; } }
    /// <summary>How the last tracked fix ended.</summary>
    public FixRunResult? LastRun { get { lock (_gate) return _lastRun; } }
    /// <summary>Raised when a tracked fix starts, reports progress or ends.</summary>
    public event Action? RunChanged;

    private void RaiseRunChanged()
    {
        try { RunChanged?.Invoke(); } catch (Exception ex) { LogError($"RunChanged handler failed: {ex}"); }
    }

    /// <summary>
    /// Runs a fix to its end whatever happens to the page that started it (a repair takes up to half an hour; leaving the page must not
    /// cut it off). One at a time: a second request while one runs is refused. <paramref name="origin"/> is the check the fix belongs to.
    /// </summary>
    public async Task<RemediationResult> RunTrackedAsync(AreaAction action, string origin)
    {
        CancellationTokenSource cts;
        lock (_gate)
        {
            if (_running is not null) return new(false, $"{_running.Title} is still running. Wait for it to finish, or cancel it.");
            cts = _runCts = new CancellationTokenSource();
            _running = new(action, Plan(action).Title.TrimEnd('?'), origin, DateTimeOffset.UtcNow);
        }
        var ownsProgress = RepairProgress is null;
        if (ownsProgress)
            RepairProgress = new InlineRunProgress(p =>
            {
                lock (_gate) { if (_running is not null) _running = _running with { Progress = p }; }
                RaiseRunChanged();
            });
        RaiseRunChanged();
        RemediationResult result;
        try
        {
            result = await Task.Run(() => ExecuteAsync(action, cts.Token)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LogError($"{action.Kind} failed: {ex}");
            result = new(false, $"Couldn't complete '{action.ButtonText}'.");
        }
        finally
        {
            if (ownsProgress) RepairProgress = null;
        }
        lock (_gate)
        {
            _lastRun = new(++_runSeq, action, origin, result.Success, result.Message, result.RestartNeeded, DateTimeOffset.UtcNow);
            _running = null;
            _runCts = null;
        }
        cts.Dispose();
        RaiseRunChanged();
        return result;
    }

    /// <summary>Asks the running fix to stop. Windows may still finish what it started.</summary>
    public void CancelRunning()
    {
        lock (_gate)
        {
            try { _runCts?.Cancel(); } catch (ObjectDisposedException) { }
        }
    }

    private sealed class InlineRunProgress(Action<string> report) : IProgress<string>
    {
        public void Report(string value) => report(value);
    }

    /// <summary>Full result of the last DISM/SFC repair run through <see cref="ExecuteAsync"/> (for the workflow report).</summary>
    public RepairResult? LastRepair { get; private set; }
    /// <summary>Receives "Repair 45% complete" while a DISM/SFC repair runs through <see cref="ExecuteAsync"/>.</summary>
    public IProgress<string>? RepairProgress { get; set; }

    /// <summary>DISM RestoreHealth or SFC /scannow with the full finding (output, exit code, log excerpts, restart needed).</summary>
    public Task<RepairResult> RepairAsync(AreaAction action, IProgress<string>? progress, CancellationToken ct) =>
        WindowsRepair.RunStepAsync(commands, StepOf(action.Kind) ?? RepairStep.SfcScanNow,
            action.Kind == RemediationKind.RepairComponentStoreFromImage ? action.Target : null, progress, ct);

    private async Task<RemediationResult> RunScheduleCleanRestartAsync(AreaAction action, CancellationToken ct)
    {
        var state = await RebootResume.PrepareForRebootAsync(Actor, session, action.Target, ct).ConfigureAwait(false);
        var pr = await commands.RunAsync(
            SystemCommandRunner.SystemTool("shutdown.exe"),
            // /g = /r plus Automatic Restart Sign-On: where Windows allows it, the same user is signed back in and the screen locked,
            // so the resume task runs without anyone at the PC. Where it is turned off, /g is a plain restart.
            ["/g", "/t", "60", "/c", "Remote PC Diagnostics: clean restart scheduled in 60 seconds. Session will automatically resume after sign-in."],
            ct).ConfigureAwait(false);

        if (pr is not { ExitCode: 0 })
        {
            await RebootResume.CancelPendingRebootAsync(ct).ConfigureAwait(false);
            return new(false, Failure(pr, "Couldn't schedule a restart."));
        }

        var baselineNote = state.PreUsedMemoryBytes > 0
            ? $" Recorded pre-reboot baseline ({HardwareInventory.FormatBytes(state.PreUsedMemoryBytes)} across {state.PreProcessCount} processes); Remote PC Diagnostics will automatically relaunch after sign-in and log the resource reduction in History."
            : " Remote PC Diagnostics will automatically relaunch onto the same session after sign-in and log the resource reduction in History.";
        return new(true, "Clean restart scheduled for 60 seconds from now." + baselineNote);
    }

    private async Task<RemediationResult> RunCancelScheduledRestartAsync(CancellationToken ct)
    {
        var pr = await commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/a"], ct).ConfigureAwait(false);
        await RebootResume.CancelPendingRebootAsync(ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 }
            ? new(true, "Cancelled the scheduled restart and cleared the post-reboot auto-resume entry.")
            : new(false, SystemCommandRunner.AgentFailure(pr) ?? "No scheduled restart was active to cancel.");
    }

    private static string Display(AreaAction a) =>
        !string.IsNullOrWhiteSpace(a.TargetLabel) ? a.TargetLabel : !string.IsNullOrWhiteSpace(a.Target) ? a.Target : "item";


    /// <summary>The DNS servers "Use public DNS" sets: Cloudflare, then Google.</summary>
    public static readonly IReadOnlyList<string> PublicDns = ["1.1.1.1", "8.8.8.8"];

    private static string AdapterName(string? target) =>
        SystemSettingsRules.IsAdapterName(target) ? target! : throw new ArgumentException("Invalid network adapter name.");

    /// <summary>Runs an in-process settings change; any refusal from Windows is the fix's failure message.</summary>
    private RemediationResult Apply(Action<ISystemSettings> change, string okMsg, string failMsg)
    {
        if (settings is null) return new(false, failMsg);
        try { change(settings); return new(true, okMsg); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn($"{failMsg} {ex.GetType().Name}: {ex.Message}");
            return new(false, AdminRequiredException.MessageOr(ex, failMsg));
        }
    }

    /// <summary>Volume letters of an OptimizeSsd target ("C", "DE", "C:"), upper-cased and de-duplicated; empty when anything else is in it.</summary>
    public static string DriveLetters(string? target)
    {
        var t = (target ?? "").Replace(":", "").Replace(",", "").Trim().ToUpperInvariant();
        return t.Length > 0 && t.All(c => c is >= 'A' and <= 'Z') ? new string(t.Distinct().ToArray()) : "";
    }

    private async Task<RemediationResult> RunSimpleAsync(string exe, IReadOnlyList<string> args, string okMsg, string failMsg, CancellationToken ct)
    {
        var pr = await commands.RunAsync(exe, args, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(true, okMsg) : new(false, Failure(pr, failMsg));
    }

    private async Task<RemediationResult> RunAdminSimpleAsync(string exe, IReadOnlyList<string> args, string okMsg, string failMsg, CancellationToken ct)
    {
        var pr = await commands.RunAdminToolAsync(exe, args, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(true, okMsg) : new(false, Failure(pr, failMsg));
    }

    /// <summary>
    /// The failure text: what the Agent said when it couldn't run the command (<see cref="SystemCommandRunner.AgentFailure"/>), else
    /// <paramref name="failMsg"/>, plus <see cref="ElevationService.AdminRepairHint"/> when the Agent wasn't there to run it.
    /// </summary>
    private string Failure(ProcessResult? pr, string failMsg) =>
        SystemCommandRunner.AgentFailure(pr)
        ?? (commands.ElevatedBridge is { IsConnected: true } || commands.IsScripted ? failMsg : failMsg + " " + ElevationService.AdminRepairHint);

    private async Task<RemediationResult> RunPnpUtilAsync(IReadOnlyList<string> args, string okMsg, string failMsg, CancellationToken ct)
    {
        var pr = await commands.RunAdminToolAsync(SystemCommandRunner.SystemTool("pnputil.exe"), args, ct).ConfigureAwait(false);
        if (pr is { ExitCode: 0 }) return new(true, okMsg);
        // ERROR_SUCCESS_REBOOT_REQUIRED (3010): pnputil succeeded, Windows needs a restart to finish.
        if (pr is { ExitCode: 3010 }) return new(true, $"{okMsg} Restart the PC to finish.", RestartNeeded: true);
        if (SystemCommandRunner.AgentFailure(pr) is { } agentWhy) return new(false, agentWhy);
        if (pr is not null && commands.HasAdminRights)
        {
            var detail = FirstUsefulLine(pr.StdErr) ?? FirstUsefulLine(pr.StdOut);
            var cleanFail = failMsg.Replace(" (administrator rights required).", ".").Replace(" (administrator rights required)", "");
            return new(false, detail is not null ? $"{cleanFail} ({detail})" : $"{cleanFail} (pnputil exit code {pr.ExitCode}).");
        }
        return new(false, Failure(pr, failMsg));
    }

    private static string? FirstUsefulLine(string? output)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;
        var lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var match = lines.LastOrDefault(l => !l.StartsWith("Microsoft PnP Utility", StringComparison.OrdinalIgnoreCase)
            && !l.StartsWith("Instance ID:", StringComparison.OrdinalIgnoreCase));
        return string.IsNullOrWhiteSpace(match) ? null : AreaReportExport.Text(match, 200);
    }

    /// <summary>Time limits for fixes that legitimately take minutes (the default limit is 60 s).</summary>
    public static readonly TimeSpan CleanupTimeout = TimeSpan.FromMinutes(10), UpdateTimeout = TimeSpan.FromMinutes(45), OptimizeTimeout = TimeSpan.FromMinutes(15);

    /// <summary>A named script the Agent builds and runs with administrator rights (<see cref="AgentScripts"/>).</summary>
    private async Task<RemediationResult> RunAgentScriptAsync(AdminPipeScript script, string okMsg, string failMsg, CancellationToken ct, TimeSpan? timeout = null)
    {
        var pr = await commands.RunAgentScriptAsync(script, timeout, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(true, okMsg) : new(false, Failure(pr, failMsg));
    }

    private async Task<RemediationResult> RunEndProcessAsync(AreaAction action, CancellationToken ct)
    {
        if (ProcessProtection.IsProtected(action.Target))
            return new(false, $"{Display(action)} is protected by Windows and cannot be stopped.");

        var procName = Path.GetFileNameWithoutExtension(action.Target.Trim());
        // Through the Agent (an elevated process can only be ended with administrator rights); it checks the name again.
        var pr = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.StopProcess, procName), null, ct).ConfigureAwait(false);
        if (pr is not { ExitCode: 0 })
            return new(false, SystemCommandRunner.AgentFailure(pr) ?? $"Couldn't close {Display(action)} (it may have already exited, or it runs as administrator and the Agent isn't connected).");

        long freedMem = 0;
        if (!string.IsNullOrWhiteSpace(pr.StdOut))
        {
            try
            {
                using var doc = JsonDocument.Parse(pr.StdOut);
                if (doc.RootElement.TryGetProperty("FreedMemoryBytes", out var m) && m.TryGetInt64(out var mb))
                    freedMem = Math.Max(0, mb);
            }
            catch { }
        }
        var msg = freedMem > 0
            ? $"Closed {Display(action)} ({HardwareInventory.FormatBytes(freedMem)} RAM freed)."
            : $"Closed {Display(action)}.";
        return new(true, msg, FreedMemoryBytes: freedMem);
    }

    private async Task<RemediationResult> RunFlushAndRenewAsync(CancellationToken ct)
    {
        var ipconfig = SystemCommandRunner.SystemTool("ipconfig.exe");
        var flush = await commands.RunAsync(ipconfig, ["/flushdns"], ct).ConfigureAwait(false);
        var renew = await commands.RunAsync(ipconfig, ["/renew"], ct).ConfigureAwait(false);
        if (flush is { ExitCode: 0 } && renew is { ExitCode: 0 })
            return new(true, "Flushed DNS cache and renewed IP configuration.");
        if (flush is { ExitCode: 0 })
            return new(true, "Flushed DNS cache (IP lease renewal wasn't needed or uses static IP).");
        return new(false, Failure(flush, "Couldn't flush DNS cache or renew IP configuration."));
    }

    private async Task<RemediationResult> RunWindowsUpdateAsync(bool driversOnly, CancellationToken ct)
    {
        var kindWord = driversOnly ? "driver" : "Windows";
        var pr = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.WindowsUpdate, driversOnly ? "drivers" : "software"), UpdateTimeout, ct).ConfigureAwait(false);
        PendingUpdates.Invalidate();
        if (pr is not { ExitCode: 0 } || string.IsNullOrWhiteSpace(pr.StdOut))
            return new(false, SystemCommandRunner.AgentFailure(pr)
                ?? (pr?.StdErr.Trim() is { Length: > 0 } why ? $"Couldn't check Windows Update for {kindWord} updates: {AreaReportExport.Text(why, 300)}"
                    : $"Couldn't check Windows Update for {kindWord} updates."));

        try
        {
            using var doc = JsonDocument.Parse(pr.StdOut);
            var root = doc.RootElement;
            var count = root.TryGetProperty("Count", out var c) && c.TryGetInt32(out var ci) ? ci : 0;
            var installed = root.TryGetProperty("Installed", out var ins) && ins.TryGetInt32(out var ii) ? ii : 0;
            // IUpdateInstaller ResultCode: 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted; -1/absent = no install attempted.
            var installResult = root.TryGetProperty("InstallResult", out var ir) && ir.TryGetInt32(out var iri) ? iri : -1;
            var restart = root.TryGetProperty("RebootRequired", out var rb) && rb.ValueKind == JsonValueKind.True;
            var titles = new List<string>();
            if (root.TryGetProperty("Titles", out var tEl))
            {
                if (tEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var x in tEl.EnumerateArray())
                        if (x.GetString() is { Length: > 0 } s) titles.Add(s);
                }
                else if (tEl.ValueKind == JsonValueKind.String && tEl.GetString() is { Length: > 0 } single)
                {
                    titles.Add(single);
                }
            }

            if (count == 0)
                return new(true, driversOnly ? "All drivers are up to date (no pending driver updates found)." : "Windows is up to date (no pending updates found).");

            // Installed updates are permanent, so name them all (up to 10) for the record; otherwise a short sample.
            var shown = installed > 0 ? 10 : 2;
            var sample = string.Join(", ", titles.Take(shown));
            if (titles.Count > shown) sample += $" (+{titles.Count - shown} more)";
            if (installed > 0)
                return new(true, $"Installed {installed} of {count} {kindWord} update(s): {sample}." + (restart ? " Restart the PC to finish." : ""),
                    UpdatesInstalled: installed, RestartNeeded: restart);
            if (installResult is 4 or 5)
            {
                var why = root.TryGetProperty("Error", out var er) && er.GetString() is { Length: > 0 } e ? $" ({AreaReportExport.Text(e, 300)})" : "";
                return new(false, $"Found {count} {kindWord} update(s) ({sample}) but Windows couldn't install them{why}. Try again from Settings > Windows Update.");
            }
            return new(true, $"Found {count} available {kindWord} update(s) ({sample}) and triggered Windows Update scan/download.");
        }
        catch
        {
            return new(false, $"Couldn't read Windows Update results for {kindWord} updates.");
        }
    }

    private async Task<RemediationResult> RunInstallUpdateAsync(AreaAction action, CancellationToken ct)
    {
        if (!Guid.TryParse(action.Target, out var updateId)) return new(false, "This update has no Windows Update ID.");
        var pr = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.InstallUpdate, updateId.ToString("D")), UpdateTimeout, ct).ConfigureAwait(false);
        PendingUpdates.Invalidate();
        return ParseInstallUpdate(pr is { ExitCode: 0 } ? pr.StdOut : null, Display(action));
    }

    /// <summary>The install script's JSON → the fix result. <paramref name="label"/> names the update when the script couldn't.</summary>
    public static RemediationResult ParseInstallUpdate(string? json, string label)
    {
        if (string.IsNullOrWhiteSpace(json)) return new(false, $"Couldn't ask Windows Update to install {label}.");
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            bool Flag(string n) => root.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True;
            int Number(string n) => root.TryGetProperty(n, out var v) && v.TryGetInt32(out var i) ? i : -1;
            var title = root.TryGetProperty("Title", out var t) && t.GetString() is { Length: > 0 } s ? s : label;
            var error = root.TryGetProperty("Error", out var e) ? e.GetString() ?? "" : "";
            if (error.Length > 0) return new(false, $"Windows Update couldn't install {title}: {AreaReportExport.Text(error, 300)}");
            if (!Flag("Found")) return new(false, $"Windows Update no longer offers {title}. It may be installed already, or replaced by a newer update. Run the check again.");
            var restart = Flag("RebootRequired");
            // IUpdateInstaller ResultCode: 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted; -1 = nothing was installed.
            var code = Number("ResultCode");
            if (Flag("Installed"))
                return new(true, $"Installed {title}." + (restart ? " Restart the PC to finish." : ""), UpdatesInstalled: 1, RestartNeeded: restart);
            if (code is 4 or 5)
            {
                var hr = Number("HResult");
                return new(false, $"Windows couldn't install {title}" + (hr is not (0 or -1) ? $" (0x{unchecked((uint)hr):X8})." : ".") + " Try again from Settings > Windows Update.", RestartNeeded: restart);
            }
            return new(false, $"Windows couldn't download {title}. Check the internet connection and try again.");
        }
        catch (JsonException)
        {
            return new(false, $"Couldn't read Windows Update's answer for {label}.");
        }
    }

    private async Task<RemediationResult> RunCleanTempFilesAsync(CancellationToken ct)
    {
        var pr = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.CleanTemp), CleanupTimeout, ct).ConfigureAwait(false);
        if (pr is not { ExitCode: 0 } || string.IsNullOrWhiteSpace(pr.StdOut))
            return new(false, "Couldn't clean temporary files.");

        try
        {
            using var doc = JsonDocument.Parse(pr.StdOut);
            var root = doc.RootElement;
            var count = root.TryGetProperty("RemovedFiles", out var c) && c.TryGetInt32(out var ci) ? ci : 0;
            var bytes = root.TryGetProperty("FreedBytes", out var b) && b.TryGetInt64(out var bi) ? bi : 0L;
            if (bytes > 0) try { journal?.Add(Changes.ChangeRecord.New(Changes.ChangeKind.TempFiles, Guid.NewGuid().ToString("N"), $"{count}:{bytes}", $"Temporary files cleaned ({HardwareInventory.FormatBytes(bytes)})", Actor)); } catch { }
            return new(
                true,
                $"Cleaned {count} temporary file(s) ({HardwareInventory.FormatBytes(bytes)} freed) and emptied the Recycle Bin.",
                FreedDiskBytes: Math.Max(0, bytes),
                RemovedFiles: Math.Max(0, count));
        }
        catch
        {
            return new(true, "Cleaned temporary files and emptied the Recycle Bin.");
        }
    }

    // ---- Undo support: what a setting was before a reversible fix changes it ----


    private async Task<Changes.ChangeRecord?> CaptureBeforeAsync(AreaAction action, CancellationToken ct)
    {
        if (journal is null) return null;
        try
        {
            Changes.ChangeRecord Rec(Changes.ChangeKind k, string target, string? prev, string label, bool restart = false) => Changes.ChangeRecord.New(k, target, prev, label, Actor, restart);
            switch (action.Kind)
            {
                case RemediationKind.SetBalancedPowerPlan:
                    var pr = await commands.RunAsync(SystemCommandRunner.SystemTool("powercfg.exe"), ["/getactivescheme"], ct).ConfigureAwait(false);
                    return Changes.UndoService.ParseSchemeGuid(pr?.StdOut) is { } g && !g.Equals(BalancedPlanGuid, StringComparison.OrdinalIgnoreCase)
                        ? Rec(Changes.ChangeKind.PowerPlan, "", g, "Power plan switched to Balanced") : null;
                case RemediationKind.DisableFastStartup:
                    return settings?.GetFastStartup() == 1
                        ? Rec(Changes.ChangeKind.FastStartup, "", "1", "Fast Startup turned off", restart: true) : null;
                case RemediationKind.DisableSystemProxy:
                    return settings?.GetUserProxyEnable() == 1
                        ? Rec(Changes.ChangeKind.SystemProxy, "", "1", "System proxy turned off") : null;
                case RemediationKind.ApplySecuritySetting when Security.SecurityFixes.Find(action.Target) is { } sf:
                    var cur = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.SecurityRead, sf.Key), null, ct).ConfigureAwait(false);

                    var prev = cur is { ExitCode: 0 } ? cur.StdOut.Trim() : null;
                    return prev is not null && Security.SecurityFixes.ParsePrevious(sf.Key, prev) is not null
                        ? Rec(Changes.ChangeKind.SecuritySetting, sf.Key, prev, sf.Done.TrimEnd('.')) : null;
                case RemediationKind.DisableDeviceWake:
                    // Journaled only when the device is armed now, under Windows' own spelling of its name.
                    var armed = await DeviceWake.QueryArmedAsync(commands, ct).ConfigureAwait(false);
                    return armed is not null && DeviceWake.FindArmed(armed, action.Target) is { } device
                        ? Rec(Changes.ChangeKind.DeviceWake, device, "armed", $"{device} can't wake the PC") : null;
                case RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns when SystemSettingsRules.IsAdapterName(action.Target):
                    var dns = settings?.GetAdapterDns(action.Target);
                    return dns is null ? null : Rec(Changes.ChangeKind.AdapterDns, action.Target, dns,
                        action.Kind == RemediationKind.SetPublicDns ? $"Public DNS set on {Display(action)}" : $"DNS reset to automatic on {Display(action)}");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"Couldn't record the previous setting for {action.Kind}: {ex.Message}"); }
        return null;
    }
}
