using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Core.Changes;

/// <param name="Skipped">A permanent change (installed updates, removed apps): reported, not attempted, not a failure.</param>
public sealed record UndoItemResult(ChangeRecord Change, bool Success, string Message, bool Skipped = false);

public sealed record UndoAllResult(IReadOnlyList<UndoItemResult> Items)
{
    public int Succeeded => Items.Count(i => i.Success);
    public int Failed => Items.Count(i => !i.Success && !i.Skipped);
    public int Skipped => Items.Count(i => i.Skipped);
    public IEnumerable<UndoItemResult> Permanent => Items.Where(i => i.Skipped);
    public bool NeedsRestart => Items.Any(i => i.Success && i.Change.NeedsRestart);
    private int Attempted => Items.Count - Skipped;
    public string Summary => Items.Count == 0 ? "Nothing to undo."
        : (Attempted == 0 ? "Nothing that can be undone"
            : $"Undid {Succeeded} of {Attempted} change{(Attempted == 1 ? "" : "s")}" + (Failed > 0 ? $"; {Failed} couldn't be undone" : ""))
          + (Skipped > 0 ? $"; {Skipped} permanent change{(Skipped == 1 ? " was" : "s were")} left as is (can't be reversed)" : "")
          + (NeedsRestart ? ". Restart to finish (Fast Startup, page file, Widgets, Search highlights)." : ".");
}

/// <summary>
/// Reverts the journaled changes, newest first. Only puts back settings this app changed. Permanent changes (installed updates,
/// removed apps) and deleted temporary files are reported as skipped; deleted files are never recreated.
/// </summary>
public sealed class UndoService(IChangeJournal journal, SystemCommandRunner commands, IMemorySystem? memory = null, IServiceControlBackend? services = null,
    Action<LogLevel, string>? events = null, Action<string>? log = null)
{
    public const string NotUndoableNote = "Installed updates, removed apps, and deleted temporary files, caches or Recycle Bin items can't be put back; undo lists them as left as is.";
    private void Log(string m) { try { log?.Invoke("[undo] " + m); } catch { } }

    public IReadOnlyList<ChangeRecord> Pending => journal.All;

    public async Task<UndoAllResult> UndoAllAsync(string actor, CancellationToken ct = default)
    {
        var results = new List<UndoItemResult>();
        foreach (var c in journal.All.OrderByDescending(x => x.TimeUtc).ToList())
        {
            ct.ThrowIfCancellationRequested();
            UndoItemResult r;
            try { r = await UndoOneAsync(c, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log($"{c.Kind} '{c.Target}' failed: {ex}");
                r = new(c, false, "Windows didn't allow undoing it.");
            }
            // Permanent changes are reported once, then forgotten (there's nothing to retry).
            if (r.Success || r.Skipped) journal.Remove(c.Id);
            results.Add(r);
            Log($"{c.Kind} '{c.Target}': {(r.Success ? "undone" : r.Skipped ? "permanent, skipped" : "failed")} — {r.Message}");
        }
        var all = new UndoAllResult(results);
        try
        {
            events?.Invoke(all.Failed > 0 ? LogLevel.Warning : LogLevel.Information,
                $"Undo all changes\r\nActor: {actor}\r\nResult: {all.Summary}\r\n" + string.Join("\r\n", results.Select(i => $"  {(i.Success ? "OK" : i.Skipped ? "LEFT AS IS" : "FAILED")}: {i.Change.Label} — {i.Message}")));
        }
        catch { }
        return all;
    }

    private async Task<UndoItemResult> UndoOneAsync(ChangeRecord c, CancellationToken ct)
    {
        UndoItemResult Ok(string m) => new(c, true, m);
        UndoItemResult Fail(string m) => new(c, false, m);
        switch (c.Kind)
        {
            case ChangeKind.NotUndoable:
                return new(c, false, "Permanent change; Windows has no way to put it back.", Skipped: true);

            case ChangeKind.DefenderExclusion:
                var sep = c.Target.IndexOf('|');
                if (sep <= 0) return Fail("The exclusion wasn't recorded.");
                var (kindD, value) = (c.Target[..sep], c.Target[(sep + 1)..]);
                var removeScript = kindD == "process" ? DefenderProbe.RemoveScript([], [value]) : DefenderProbe.RemoveScript([value], []);
                return await Ps(removeScript, c, $"Defender scans {(kindD == "process" ? "files opened by " + Path.GetFileName(value) : value)} again.", ct).ConfigureAwait(false);

            case ChangeKind.HiberFileType:
                var hr = await commands.RunAsync(SystemCommandRunner.SystemTool("powercfg.exe"), ["/h", "/type", "full"], ct).ConfigureAwait(false);
                return hr is { ExitCode: 0 } ? Ok("Hibernation file back to full size; Hibernate is available again.") : Fail("Windows didn't allow changing the hibernation file back.");

            case ChangeKind.RegistryValue:
                if (memory is null) return Fail("Not available.");
                var (regOk, regMessage) = RegistryAllowlist.Restore(memory, c.Target, c.Previous);
                return new(c, regOk, regMessage);

            case ChangeKind.DefaultPrinter:
                if (memory is null) return Fail("Not available.");
                var (prOk, prMessage) = DefaultPrinter.Restore(memory, c.Target, c.Previous);
                return new(c, prOk, prMessage);

            case ChangeKind.ExtensionBlock:
                if (memory is null) return Fail("Not available.");
                var (extOk, extMessage) = BrowserExtensions.RemoveBlock(memory, c.Target, c.Previous);
                return new(c, extOk, extMessage);

            case ChangeKind.StartupApp:
                if (memory is null) return Fail("Not available.");
                memory.SetStartupApproved(c.Target, c.Previous is null ? null : Convert.FromBase64String(c.Previous));
                return Ok("Starts with Windows again.");

            case ChangeKind.ServiceStartType:
                if (memory is null || !MemorySuggestionService.StartTypes.Contains(c.Previous)) return Fail("The original setting wasn't recorded.");
                memory.SetServiceStartType(c.Target, c.Previous!);
                return Ok($"Start-up type restored to {c.Previous}.");

            case ChangeKind.ServiceRunning:
                if (services is null) return Fail("Service control isn't available.");
                var targetState = c.Previous == "Running" ? ServiceState.Running : ServiceState.Stopped;
                if (services.GetState(c.Target) == targetState) return Ok(c.Previous == "Running" ? "Already running." : "Already stopped.");
                if (c.Previous == "Running") services.Start(c.Target); else services.Stop(c.Target);
                var target = c.Previous == "Running" ? ServiceState.Running : ServiceState.Stopped;
                return await services.WaitForStateAsync(c.Target, target, TimeSpan.FromSeconds(30), ct).ConfigureAwait(false)
                    ? Ok(c.Previous == "Running" ? "Started again." : "Stopped again.") : Fail("Windows didn't confirm the service changed in time.");

            case ChangeKind.BrowserSettings:
                if (memory is null || c.Previous is null) return Fail("The original setting wasn't recorded.");
                var kind = Enum.Parse<BrowserKind>(c.Target);
                if (memory.IsBrowserRunning(kind)) return Fail($"Close {BrowserPrefs.Label(kind)} first, then undo.");
                memory.WriteBrowserLocalState(kind, c.Previous);
                return Ok("Browser setting restored.");

            case ChangeKind.BrowserLocalStateValue:
                if (memory is null) return Fail("Not available.");
                var (bgOk, bgMessage) = await BrowserBackground.RestoreAsync(memory, c.Target, c.Previous, ct).ConfigureAwait(false);
                return new(c, bgOk, bgMessage);

            case ChangeKind.Transparency:
                if (memory is null) return Fail("Not available.");
                memory.SetTransparency(c.Previous != "0");
                return Ok(c.Previous != "0" ? "Transparency effects back on." : "Transparency effects left off.");

            case ChangeKind.FastStartup:
                return await Ps($"$ErrorActionPreference='Stop'; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name HiberbootEnabled -Value {Dword(c.Previous)} -Type DWord",
                    c, "Fast Startup setting restored (full effect after the next restart).", ct).ConfigureAwait(false);

            case ChangeKind.PowerPlan:
                if (c.Previous is null || !Guid.TryParse(c.Previous, out var g)) return Fail("The original power plan wasn't recorded.");
                var pr = await commands.RunAsync(SystemCommandRunner.SystemTool("powercfg.exe"), ["/setactive", g.ToString()], ct).ConfigureAwait(false);
                return pr is { ExitCode: 0 } ? Ok("Previous power plan active again.") : Fail("Couldn't switch the power plan back.");

            case ChangeKind.SystemProxy:
                return await Ps($"$ErrorActionPreference='Stop'; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value {Dword(c.Previous)} -Type DWord",
                    c, "System proxy setting restored.", ct).ConfigureAwait(false);

            case ChangeKind.AdapterDns:
                var alias = c.Target.Replace("'", "''");
                var servers = (c.Previous ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(IsIp).ToList();
                var script = servers.Count == 0
                    ? $"$ErrorActionPreference='Stop'; Set-DnsClientServerAddress -InterfaceAlias '{alias}' -ResetServerAddresses"
                    : $"$ErrorActionPreference='Stop'; Set-DnsClientServerAddress -InterfaceAlias '{alias}' -ServerAddresses @({string.Join(",", servers.Select(s => $"'{s}'"))})";
                return await Ps(script, c, servers.Count == 0 ? "DNS back to automatic." : $"DNS back to {string.Join(", ", servers)}.", ct).ConfigureAwait(false);

            case ChangeKind.TempFiles:
                return new(c, false, "Deleted temporary files and emptied Recycle Bin items cannot be restored.", Skipped: true);

            case ChangeKind.ScheduledTask:
                if (memory is null) return Fail("Not available.");
                if (!ScheduledTaskAllowlist.IsAllowed(c.Target)) return Fail("That scheduled task isn't one this app changes, so it was left as is.");
                var taskState = await memory.GetScheduledTaskStateAsync(c.Target, ct).ConfigureAwait(false);
                if (taskState == ScheduledTaskAllowlist.Missing) return Ok("The task no longer exists (it was removed with its app); nothing to turn back on.");
                if (ScheduledTaskAllowlist.IsEnabledState(taskState)) return Ok("The task is already on.");
                return ScheduledTaskAllowlist.IsEnabledState(await memory.SetScheduledTaskEnabledAsync(c.Target, true, ct).ConfigureAwait(false))
                    ? Ok("Scheduled task turned back on.") : Fail("Windows didn't allow turning the task back on (administrator rights needed).");

            case ChangeKind.PageFile:
                if (memory is null || c.Previous is null) return Fail("The original page file size wasn't recorded.");
                var o = await memory.RestorePageFileAsync(c.Previous, ct).ConfigureAwait(false);
                return new(c, o.Success, o.Message);
        }
        return Fail("Unknown change.");
    }

    private static int Dword(string? v) => int.TryParse(v, out var i) && i is >= 0 and <= 1 ? i : 1;
    private static bool IsIp(string s) => System.Net.IPAddress.TryParse(s, out _);

    private async Task<UndoItemResult> Ps(string script, ChangeRecord c, string ok, CancellationToken ct)
    {
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(c, true, ok) : new(c, false, "Couldn't put it back (administrator rights required).");
    }

    // ---- helpers used when recording "before" values ----

    /// <summary>Scheme GUID from "powercfg /getactivescheme" output.</summary>
    public static string? ParseSchemeGuid(string? output) =>
        output is null ? null : Regex.Match(output, "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}") is { Success: true } m ? m.Value : null;
}
