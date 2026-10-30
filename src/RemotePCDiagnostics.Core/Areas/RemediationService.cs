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

public sealed record RemediationResult(bool Success, string Message);

public sealed record RemediationRecord(
    DateTime When,
    string Actor,
    RemediationKind Kind,
    string Target,
    bool Success,
    string Message);

/// <summary>
/// Plans, executes, and audits one-click automated fixes across the 4 diagnostic remediation areas:
/// (1) Drivers &amp; Windows Updates, (2) Performance/Power/Uptime, (3) Network/Proxy/DNS, and (4) Storage/Temp Cleanup.
/// </summary>
public sealed class RemediationService(
    SystemCommandRunner commands,
    ISessionContext? session = null,
    Action<string>? log = null)
{
    public const int MaxRecent = 20;
    public const string BalancedPlanGuid = "381b4222-f694-41f0-9685-ff5bb260df2e";

    private readonly List<RemediationRecord> _recent = [];
    private readonly object _gate = new();

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
                "Schedule a clean PC restart in 60 seconds?",
                "This PC has been running for an extended period without a full reboot.",
                "Windows will warn the signed-in user and restart the PC in 60 seconds (you can cancel it anytime before the timer expires).",
                "Make sure any unsaved documents are saved before restarting.",
                true),

            RemediationKind.CancelScheduledRestart => new(
                action,
                "Cancel scheduled restart?",
                "Aborts a pending timed Windows shutdown or restart.",
                "Runs 'shutdown /a' so the PC stays on.",
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
                result = await RunActionAsync(action, ct).ConfigureAwait(false);
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

        var rec = new RemediationRecord(DateTime.Now, actor, action.Kind, action.TargetLabel.Length > 0 ? action.TargetLabel : action.Target, result.Success, result.Message);
        lock (_gate)
        {
            _recent.Insert(0, rec);
            if (_recent.Count > MaxRecent) _recent.RemoveAt(_recent.Count - 1);
        }
        Log($"AUDIT when={rec.When:O} actor='{actor}' kind={action.Kind} target='{action.Target}' success={result.Success} message='{result.Message}'");
        try { ActionCompleted?.Invoke(rec); } catch (Exception ex) { Log($"ActionCompleted handler failed: {ex}"); }
        return result;
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

        RemediationKind.ScheduleCleanRestart => await RunSimpleAsync(
            SystemCommandRunner.SystemTool("shutdown.exe"),
            ["/r", "/t", "60", "/c", "Remote PC Diagnostics: clean restart scheduled in 60 seconds. Save your work."],
            "Clean restart scheduled for 60 seconds from now.",
            "Couldn't schedule a restart.",
            ct).ConfigureAwait(false),

        RemediationKind.CancelScheduledRestart => await RunSimpleAsync(
            SystemCommandRunner.SystemTool("shutdown.exe"),
            ["/a"],
            "Cancelled the scheduled restart.",
            "No scheduled restart was active to cancel.",
            ct).ConfigureAwait(false),

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
            ct).ConfigureAwait(false),

        _ => new(false, "Unsupported action."),
    };

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

    private async Task<RemediationResult> RunPowerShellAsync(string script, string okMsg, string failMsg, CancellationToken ct)
    {
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(true, okMsg) : new(false, failMsg);
    }

    private async Task<RemediationResult> RunEndProcessAsync(AreaAction action, CancellationToken ct)
    {
        if (ProcessProtection.IsProtected(action.Target))
            return new(false, $"{Display(action)} is protected by Windows and cannot be stopped.");

        var procName = Path.GetFileNameWithoutExtension(action.Target.Trim());
        var script = $"$ErrorActionPreference='Stop'; Stop-Process -Name '{EscapeSingleQuotes(procName)}' -Force";
        return await RunPowerShellAsync(script, $"Closed {Display(action)}.", $"Couldn't close {Display(action)} (it may have already exited or requires administrator rights).", ct).ConfigureAwait(false);
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
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", BuildWindowsUpdateScript(driversOnly)], ct).ConfigureAwait(false);
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

            var sample = string.Join(", ", titles.Take(2));
            if (titles.Count > 2) sample += $" (+{titles.Count - 2} more)";
            if (installed > 0)
                return new(true, $"Installed {installed} of {count} {kindWord} update(s): {sample}.");
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
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", CleanTempScript], ct).ConfigureAwait(false);
        if (pr is not { ExitCode: 0 } || string.IsNullOrWhiteSpace(pr.StdOut))
            return new(false, "Couldn't clean temporary files.");

        try
        {
            using var doc = JsonDocument.Parse(pr.StdOut);
            var root = doc.RootElement;
            var count = root.TryGetProperty("RemovedFiles", out var c) && c.TryGetInt32(out var ci) ? ci : 0;
            var bytes = root.TryGetProperty("FreedBytes", out var b) && b.TryGetInt64(out var bi) ? bi : 0L;
            return new(true, $"Cleaned {count} temporary file(s) ({HardwareInventory.FormatBytes(bytes)} freed) and emptied the Recycle Bin.");
        }
        catch
        {
            return new(true, "Cleaned temporary files and emptied the Recycle Bin.");
        }
    }
}
