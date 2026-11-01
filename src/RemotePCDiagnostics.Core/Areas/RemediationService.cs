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
    };

    public static bool IsProtected(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return true;
        var trimmed = name.Trim();
        if (ProtectedNames.Contains(trimmed)) return true;
        var noExt = Path.GetFileNameWithoutExtension(trimmed);
        if (ProtectedNames.Contains(noExt)) return true;
        // Same list the Memory page uses ("this app and its web view", security, shell), so End task can't kill them either.
        if (Memory.ProtectedProcesses.Names.Contains(trimmed) || Memory.ProtectedProcesses.Names.Contains(noExt)) return true;
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
    int UpdatesInstalled = 0);

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
    Action<string>? log = null,
    RebootResumeCoordinator? rebootResume = null,
    Changes.IChangeJournal? journal = null)
{
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

    private void Log(string m)
    {
        try { (log ?? commands.Log)?.Invoke("[remediation] " + m); } catch { }
    }

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
                "Requires administrator privileges. If this is a network or display device, it may briefly disconnect or flicker.",
                !string.IsNullOrWhiteSpace(action.Target)),

            RemediationKind.EnableDevice => new(
                action,
                $"Enable {label}?",
                $"Re-enables disabled device '{label}' in Device Manager via pnputil.",
                "Windows will enable the device and load its driver.",
                "Requires administrator privileges.",
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
                "Records current memory and process usage, registers a Windows RunOnce entry to relaunch Remote PC Diagnostics into the same session after sign-in, and restarts the PC in 60 seconds.",
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
                "Runs 'shutdown /a' and removes the pending RunOnce startup entry so the PC stays on.",
                null,
                true),

            RemediationKind.EndProcessGroup => PlanEndProcess(action, label),

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
                $"Restores default router/ISP DNS settings on adapter '{label}'.",
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
                    && (action.Kind is not (RemediationKind.CheckAndInstallWindowsUpdates or RemediationKind.CheckAndInstallDriverUpdates) || result.UpdatesInstalled > 0);
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
                Log($"{action.Kind} failed: {ex}");
                result = new(false, $"Couldn't complete '{action.ButtonText}'. Make sure the app is running as administrator.");
            }
        }

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
        try { ActionCompleted?.Invoke(rec); } catch (Exception ex) { Log($"ActionCompleted handler failed: {ex}"); }
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

        RemediationKind.DisableFastStartup => await RunPowerShellAsync(
            "$ErrorActionPreference='Stop'; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name HiberbootEnabled -Value 0 -Type DWord",
            "Turned off Fast Startup (future shutdowns will perform a full reset).",
            "Couldn't turn off Fast Startup (administrator rights required).",
            ct).ConfigureAwait(false),

        RemediationKind.ScheduleCleanRestart => await RunScheduleCleanRestartAsync(action, ct).ConfigureAwait(false),

        RemediationKind.CancelScheduledRestart => await RunCancelScheduledRestartAsync(ct).ConfigureAwait(false),

        RemediationKind.EndProcessGroup => await RunEndProcessAsync(action, ct).ConfigureAwait(false),

        RemediationKind.DisableSystemProxy => await RunPowerShellAsync(
            "$ErrorActionPreference='Stop'; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0 -Type DWord",
            "Disabled the Windows system HTTP proxy.",
            "Couldn't disable the system proxy.",
            ct).ConfigureAwait(false),

        RemediationKind.FlushDnsAndRenewIp => await RunFlushAndRenewAsync(ct).ConfigureAwait(false),

        RemediationKind.SetPublicDns => await RunPowerShellAsync(
            $"$ErrorActionPreference='Stop'; Set-DnsClientServerAddress -InterfaceAlias '{EscapeSingleQuotes(action.Target)}' -ServerAddresses @('1.1.1.1','8.8.8.8')",
            $"Configured {Display(action)} to use Cloudflare (1.1.1.1) and Google (8.8.8.8) DNS.",
            $"Couldn't set DNS on {Display(action)} (administrator rights required).",
            ct).ConfigureAwait(false),

        RemediationKind.ResetDhcpDns => await RunPowerShellAsync(
            $"$ErrorActionPreference='Stop'; Set-DnsClientServerAddress -InterfaceAlias '{EscapeSingleQuotes(action.Target)}' -ResetServerAddresses",
            $"Reset DNS on {Display(action)} to automatic (DHCP).",
            $"Couldn't reset DNS on {Display(action)} (administrator rights required).",
            ct).ConfigureAwait(false),

        RemediationKind.CleanTempFiles => await RunCleanTempFilesAsync(ct).ConfigureAwait(false),

        RemediationKind.OptimizeSsd => await RunPowerShellAsync(
            $"$ErrorActionPreference='Stop'; Optimize-Volume -DriveLetter {string.Join(",", DriveLetters(action.Target).ToCharArray())} -ReTrim",
            $"Optimized / Retrimmed {Display(action)}.",
            $"Couldn't optimize {Display(action)} (administrator rights required).",
            ct, OptimizeTimeout).ConfigureAwait(false),

        _ => new(false, "Unsupported action."),
    };

    private async Task<RemediationResult> RunScheduleCleanRestartAsync(AreaAction action, CancellationToken ct)
    {
        var state = await RebootResume.PrepareForRebootAsync(Actor, session, action.Target, ct).ConfigureAwait(false);
        var pr = await commands.RunAsync(
            SystemCommandRunner.SystemTool("shutdown.exe"),
            ["/r", "/t", "60", "/c", "Remote PC Diagnostics: clean restart scheduled in 60 seconds. Session will automatically resume after sign-in."],
            ct).ConfigureAwait(false);

        if (pr is not { ExitCode: 0 })
        {
            await RebootResume.CancelPendingRebootAsync(ct).ConfigureAwait(false);
            return new(false, "Couldn't schedule a restart.");
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
            : new(false, "No scheduled restart was active to cancel.");
    }

    private static string Display(AreaAction a) =>
        !string.IsNullOrWhiteSpace(a.TargetLabel) ? a.TargetLabel : !string.IsNullOrWhiteSpace(a.Target) ? a.Target : "item";

    private static string EscapeSingleQuotes(string s) => s.Replace("'", "''");

    /// <summary>Volume letters of an OptimizeSsd target ("C", "DE", "C:"), upper-cased and de-duplicated; empty when anything else is in it.</summary>
    public static string DriveLetters(string? target)
    {
        var t = (target ?? "").Replace(":", "").Replace(",", "").Trim().ToUpperInvariant();
        return t.Length > 0 && t.All(c => c is >= 'A' and <= 'Z') ? new string(t.Distinct().ToArray()) : "";
    }

    private async Task<RemediationResult> RunSimpleAsync(string exe, IReadOnlyList<string> args, string okMsg, string failMsg, CancellationToken ct)
    {
        var pr = await commands.RunAsync(exe, args, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(true, okMsg) : new(false, failMsg);
    }

    private async Task<RemediationResult> RunPnpUtilAsync(IReadOnlyList<string> args, string okMsg, string failMsg, CancellationToken ct)
    {
        var pr = await commands.RunAsync(SystemCommandRunner.SystemTool("pnputil.exe"), args, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(true, okMsg) : new(false, failMsg);
    }

    /// <summary>Time limits for fixes that legitimately take minutes (the default limit is 60 s).</summary>
    public static readonly TimeSpan CleanupTimeout = TimeSpan.FromMinutes(10), UpdateTimeout = TimeSpan.FromMinutes(45), OptimizeTimeout = TimeSpan.FromMinutes(15);

    private async Task<RemediationResult> RunPowerShellAsync(string script, string okMsg, string failMsg, CancellationToken ct, TimeSpan? timeout = null)
    {
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(true, okMsg) : new(false, failMsg);
    }

    private async Task<RemediationResult> RunEndProcessAsync(AreaAction action, CancellationToken ct)
    {
        if (ProcessProtection.IsProtected(action.Target))
            return new(false, $"{Display(action)} is protected by Windows and cannot be stopped.");

        var procName = Path.GetFileNameWithoutExtension(action.Target.Trim());
        var escaped = EscapeSingleQuotes(procName);
        var script = $"$ErrorActionPreference='Stop'; " +
                     $"$mem = [int64]((Get-Process -Name '{escaped}' -ErrorAction SilentlyContinue | Measure-Object WorkingSet64 -Sum).Sum); " +
                     $"Stop-Process -Name '{escaped}' -Force; " +
                     $"[pscustomobject]@{{ FreedMemoryBytes = $mem }} | ConvertTo-Json -Compress";
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], ct).ConfigureAwait(false);
        if (pr is not { ExitCode: 0 })
            return new(false, $"Couldn't close {Display(action)} (it may have already exited or requires administrator rights).");

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
        return new(false, "Couldn't flush DNS cache or renew IP configuration.");
    }

    public static string BuildWindowsUpdateScript(bool driversOnly)
    {
        var criteria = driversOnly ? "IsInstalled=0 and Type='Driver'" : "IsInstalled=0 and Type='Software'";
        return "$ErrorActionPreference='SilentlyContinue'; " +
               "$s = New-Object -ComObject Microsoft.Update.Session; " +
               "$searcher = $s.CreateUpdateSearcher(); " +
               $"$res = $searcher.Search(\"{criteria}\"); " +
               "if ($null -eq $res -or $res.Updates.Count -eq 0) { " +
               "  [pscustomobject]@{ Count = 0; Installed = 0; Titles = @() } | ConvertTo-Json -Compress; exit 0 " +
               "} " +
               "$titles = @($res.Updates | ForEach-Object { [string]$_.Title }); " +
               "$toDownload = New-Object -ComObject Microsoft.Update.UpdateColl; " +
               "foreach ($u in $res.Updates) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$toDownload.Add($u) }; " +
               "$dl = $s.CreateUpdateDownloader(); $dl.Updates = $toDownload; $dlRes = $dl.Download(); " +
               "$toInstall = New-Object -ComObject Microsoft.Update.UpdateColl; " +
               "foreach ($u in $res.Updates) { if ($u.IsDownloaded) { [void]$toInstall.Add($u) } }; " +
               "$installed = 0; $installResult = -1; " +
               "if ($toInstall.Count -gt 0) { " +
               "  $inst = $s.CreateUpdateInstaller(); $inst.Updates = $toInstall; $instRes = $inst.Install(); " +
               "  $installResult = [int]$instRes.ResultCode; " +
               "  if ($installResult -eq 2 -or $installResult -eq 3) { $installed = $toInstall.Count } " +
               "} else { " +
               "  Start-Process 'UsoClient.exe' -ArgumentList 'StartInteractiveScan' -WindowStyle Hidden -ErrorAction SilentlyContinue " +
               "} " +
               "[pscustomobject]@{ Count = $titles.Count; Installed = $installed; InstallResult = $installResult; Titles = $titles } | ConvertTo-Json -Compress";
    }

    private async Task<RemediationResult> RunWindowsUpdateAsync(bool driversOnly, CancellationToken ct)
    {
        var kindWord = driversOnly ? "driver" : "Windows";
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", BuildWindowsUpdateScript(driversOnly)], UpdateTimeout, ct).ConfigureAwait(false);
        if (pr is not { ExitCode: 0 } || string.IsNullOrWhiteSpace(pr.StdOut))
            return new(false, $"Couldn't check Windows Update for {kindWord} updates.");

        try
        {
            using var doc = JsonDocument.Parse(pr.StdOut);
            var root = doc.RootElement;
            var count = root.TryGetProperty("Count", out var c) && c.TryGetInt32(out var ci) ? ci : 0;
            var installed = root.TryGetProperty("Installed", out var ins) && ins.TryGetInt32(out var ii) ? ii : 0;
            // IUpdateInstaller ResultCode: 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted; -1/absent = no install attempted.
            var installResult = root.TryGetProperty("InstallResult", out var ir) && ir.TryGetInt32(out var iri) ? iri : -1;
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
                return new(true, $"Installed {installed} of {count} {kindWord} update(s): {sample}.", UpdatesInstalled: installed);
            if (installResult is 4 or 5)
                return new(false, $"Found {count} {kindWord} update(s) ({sample}) but Windows couldn't install them. Try again from Settings > Windows Update.");
            return new(true, $"Found {count} available {kindWord} update(s) ({sample}) and triggered Windows Update scan/download.");
        }
        catch
        {
            return new(false, $"Couldn't read Windows Update results for {kindWord} updates.");
        }
    }

    public const string CleanTempScript =
        "$ErrorActionPreference='SilentlyContinue'; " +
        "$cutoff = (Get-Date).AddHours(-24); " +
        "$paths = @($env:TEMP, (Join-Path $env:SystemRoot 'Temp')) | Where-Object { $_ -and (Test-Path $_) }; " +
        "$freed = [int64]0; $count = 0; " +
        "foreach ($p in $paths) { " +
        "  Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff } | ForEach-Object { " +
        "    $len = $_.Length; Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue; " +
        "    if (-not (Test-Path -LiteralPath $_.FullName)) { $freed += $len; $count++ } " +
        "  } " +
        "}; " +
        "Clear-RecycleBin -Force -ErrorAction SilentlyContinue; " +
        "[pscustomobject]@{ RemovedFiles = $count; FreedBytes = $freed } | ConvertTo-Json -Compress";

    private async Task<RemediationResult> RunCleanTempFilesAsync(CancellationToken ct)
    {
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", CleanTempScript], CleanupTimeout, ct).ConfigureAwait(false);
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

    public const string ReadFastStartupScript = "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled";
    public const string ReadProxyScript = "(Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable";

    /// <summary>Static DNS servers set on the adapter ("" = automatic), from the adapter's Tcpip NameServer value.</summary>
    public static string ReadDnsScript(string alias) =>
        $"$a=Get-NetAdapter -Name '{EscapeSingleQuotes(alias)}' -ErrorAction Stop; (Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($a.InterfaceGuid)\" -Name NameServer -ErrorAction SilentlyContinue).NameServer";

    private async Task<string?> ReadPsAsync(string script, CancellationToken ct)
    {
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? pr.StdOut.Trim() : null;
    }

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
                    return await ReadPsAsync(ReadFastStartupScript, ct).ConfigureAwait(false) is "1"
                        ? Rec(Changes.ChangeKind.FastStartup, "", "1", "Fast Startup turned off", restart: true) : null;
                case RemediationKind.DisableSystemProxy:
                    return await ReadPsAsync(ReadProxyScript, ct).ConfigureAwait(false) is "1"
                        ? Rec(Changes.ChangeKind.SystemProxy, "", "1", "System proxy turned off") : null;
                case RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns when !string.IsNullOrWhiteSpace(action.Target):
                    var dns = await ReadPsAsync(ReadDnsScript(action.Target), ct).ConfigureAwait(false);
                    return dns is null ? null : Rec(Changes.ChangeKind.AdapterDns, action.Target, dns.Replace(' ', ','),
                        action.Kind == RemediationKind.SetPublicDns ? $"Public DNS set on {Display(action)}" : $"DNS reset to automatic on {Display(action)}");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Couldn't record the previous setting for {action.Kind}: {ex.Message}"); }
        return null;
    }
}
