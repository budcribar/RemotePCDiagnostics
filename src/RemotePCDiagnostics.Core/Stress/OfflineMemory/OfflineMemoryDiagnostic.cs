using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>One answer from the Agent's boot memory test requests: the answer, or why there is none.</summary>
public sealed record MemoryDiagnosticReply(MemoryDiagnosticAnswer? Answer, string? Error, bool NoAgent = false)
{
    public static MemoryDiagnosticReply Failed(string why, bool noAgent = false) => new(null, why, noAgent);
}

/// <summary>The Agent's <see cref="AgentScripts.MemoryDiagnostic"/> requests, behind an interface so record/replay can keep them.</summary>
public interface IMemoryDiagnosticSource
{
    /// <summary>Args as <see cref="AgentScripts.MemoryDiagnostic"/> takes them ("status", or "schedule" and "extended").</summary>
    Task<MemoryDiagnosticReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct);
}

/// <summary>Sends each request to the Agent (bcdedit and the BitLocker readings need administrator rights).</summary>
public sealed class AgentMemoryDiagnosticSource(SystemCommandRunner commands) : IMemoryDiagnosticSource
{
    public async Task<MemoryDiagnosticReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        var r = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.MemoryDiagnostic, [.. args]), TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
        if (SystemCommandRunner.AgentFailure(r) is { } noAgent) return MemoryDiagnosticReply.Failed(noAgent, noAgent: true);
        if (r is null) return MemoryDiagnosticReply.Failed("The Agent didn't answer in time.");
        if (r.ExitCode != 0) return MemoryDiagnosticReply.Failed(r.StdErr.Trim() is { Length: > 0 } why ? why : $"The Agent's memory test request failed (exit code {r.ExitCode}).");
        return MemoryDiagnosticAnswer.Parse(r.StdOut) is { } answer ? new(answer, null) : MemoryDiagnosticReply.Failed("The Agent's answer couldn't be read.");
    }
}

[JsonConverter(typeof(JsonStringEnumConverter<OfflineMemoryOutcome>))]
public enum OfflineMemoryOutcome { NoErrors, Errors }

/// <summary>A result Windows Memory Diagnostic wrote to the System log (provider Microsoft-Windows-MemoryDiagnostics-Results) after its boot test.</summary>
public sealed record OfflineMemoryResult(OfflineMemoryOutcome Outcome, DateTimeOffset TimeUtc, int EventId, string Message)
{
    public const string Provider = "Microsoft-Windows-MemoryDiagnostics-Results";
    /// <summary>The newest results first.</summary>
    public static readonly string Query = $"*[System[Provider[@Name='{Provider}']]]";

    public string Headline => Outcome == OfflineMemoryOutcome.NoErrors ? "No errors found" : "Hardware problems were detected";

    public string Explanation => Outcome == OfflineMemoryOutcome.NoErrors
        ? "Windows' boot memory test checked this PC's memory before Windows started and found no problems."
        : "Windows' boot memory test found faulty memory. Faulty memory causes crashes and lost work: have the memory checked or replaced.";

    /// <summary>
    /// The result an event reports. Windows writes event 1201 (older versions 1101) for no errors and 1202 (1102) when it found errors;
    /// any other event from the provider counts by its level (error or critical = problems found).
    /// </summary>
    public static OfflineMemoryResult? FromEvent(WinEvent e)
    {
        if (!e.Provider.Equals(Provider, StringComparison.OrdinalIgnoreCase)) return null;
        var outcome = e.EventId switch
        {
            1101 or 1201 => OfflineMemoryOutcome.NoErrors,
            1102 or 1202 => OfflineMemoryOutcome.Errors,
            _ => e.Level is 1 or 2 ? OfflineMemoryOutcome.Errors : OfflineMemoryOutcome.NoErrors,
        };
        return new(outcome, e.Time.ToUniversalTime(), e.EventId, e.ShortMessage);
    }

    public static OfflineMemoryResult? Latest(IEnumerable<WinEvent>? events) =>
        events?.Select(FromEvent).OfType<OfflineMemoryResult>().OrderByDescending(r => r.TimeUtc).FirstOrDefault();
}

/// <summary>Where the boot memory test stands, as the Memory test page shows it.</summary>
public enum OfflineMemoryPhase
{
    /// <summary>Not read yet.</summary>
    Loading,
    /// <summary>No Agent (Store edition, or not connected): the test can't be scheduled from here. The last result still shows.</summary>
    NeedsAgent,
    /// <summary>The Agent answered with an error.</summary>
    Unavailable,
    /// <summary>Nothing scheduled.</summary>
    Idle,
    /// <summary>Set for the next start; waiting for a restart.</summary>
    Scheduled,
    /// <summary>Set, and this app has scheduled the restart.</summary>
    Restarting,
    /// <summary>The PC restarted after the request; Windows writes the result a few minutes after sign-in.</summary>
    WaitingForResult,
    /// <summary>The PC restarted a while ago and Windows wrote no result: the test didn't run.</summary>
    NotRun,
    /// <summary>The result of the request is in.</summary>
    Done,
}

public enum OfflineMemoryWhen { Now, NextRestart }

/// <summary>Something the person should know before the PC restarts into the test.</summary>
public sealed record OfflineMemoryWarning(string Id, string Text, bool Serious);

public sealed record OfflineMemoryState(
    OfflineMemoryPhase Phase,
    MemoryDiagnosticAnswer? Agent,
    OfflineMemoryResult? LastResult,
    string? Error = null,
    string? Message = null)
{
    public static readonly OfflineMemoryState Initial = new(OfflineMemoryPhase.Loading, null, null);
    public bool CanSchedule => Phase is OfflineMemoryPhase.Idle or OfflineMemoryPhase.Done or OfflineMemoryPhase.NotRun;
    public bool CanCancel => Phase is OfflineMemoryPhase.Scheduled or OfflineMemoryPhase.Restarting;
}

/// <summary>
/// The Windows boot memory test, scheduled through the Agent and read back from the System log: together with the in-Windows
/// <see cref="MemoryTest"/> it makes the Memory test page report both tests in one place. "Restart now" goes through
/// <see cref="RemediationService"/>'s clean restart, so the restart is recorded and the app comes back into the same session (and a
/// running Service workflow carries on) with the reboot-resume coordinator.
/// </summary>
public sealed class OfflineMemoryDiagnostic(IMemoryDiagnosticSource source, WindowsEventLog events, Func<RemediationService?>? remediation = null,
    ILogger? log = null, Func<DateTimeOffset>? clock = null)
{
    /// <summary>After this long since the restart without a result, the test counts as not run (Windows writes it soon after sign-in).</summary>
    public static readonly TimeSpan ResultGrace = TimeSpan.FromMinutes(20);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private OfflineMemoryState _state = OfflineMemoryState.Initial;
    private DateTimeOffset? _restartScheduledUtc;
    private DateTimeOffset? _completedRequestUtc;

    public OfflineMemoryState State => _state;
    public event EventHandler? Changed;

    private DateTimeOffset Now => clock?.Invoke() ?? DateTimeOffset.UtcNow;

    private void Set(OfflineMemoryState s)
    {
        _state = s;
        try { Changed?.Invoke(this, EventArgs.Empty); } catch (Exception ex) { log.Warn($"Memory test: state listener failed: {ex.Message}"); }
    }

    public async Task<OfflineMemoryState> RefreshAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var reply = await source.RunAsync(["status"], ct).ConfigureAwait(false);
            var result = await ReadResultAsync(ct).ConfigureAwait(false);
            var state = Evaluate(reply, result, _state.Message);
            if (state.Phase == OfflineMemoryPhase.Done && reply.Answer?.RequestedAtUtc is { } requested)
            {
                // Matched: the request is finished. The Agent drops it (its test mix is already back).
                _completedRequestUtc = requested;
                log.Info($"Memory test: boot test result {result!.Outcome} at {result.TimeUtc:O} for the request of {requested:O}");
                var cleared = await source.RunAsync(["clear"], ct).ConfigureAwait(false);
                if (cleared.Answer is { } after) state = state with { Agent = after };
            }
            Set(state);
            return state;
        }
        finally { _gate.Release(); }
    }

    private async Task<OfflineMemoryResult?> ReadResultAsync(CancellationToken ct)
    {
        try { return OfflineMemoryResult.Latest(await events.QueryAsync("System", OfflineMemoryResult.Query, 5, ct).ConfigureAwait(false)); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.Warn($"Memory test: the System log couldn't be read: {ex.Message}"); return null; }
    }

    private OfflineMemoryState Evaluate(MemoryDiagnosticReply reply, OfflineMemoryResult? result, string? message)
    {
        if (reply.NoAgent) return new(OfflineMemoryPhase.NeedsAgent, null, result, reply.Error);
        if (reply.Answer is not { } a) return new(OfflineMemoryPhase.Unavailable, null, result, reply.Error);
        var now = Now;
        if (a.Scheduled)
        {
            var restarting = _restartScheduledUtc is { } r && now - r < RebootResumeCoordinator.AbandonedAfter;
            return new(restarting ? OfflineMemoryPhase.Restarting : OfflineMemoryPhase.Scheduled, a, result, Message: message);
        }
        if (a.RequestedAtUtc is { } requested)
        {
            if (result is not null && result.TimeUtc > requested) return new(OfflineMemoryPhase.Done, a, result);
            if (a.BootTimeUtc is { } boot && boot > requested)
                return new(now - boot > ResultGrace ? OfflineMemoryPhase.NotRun : OfflineMemoryPhase.WaitingForResult, a, result);
        }
        // A result already matched in this session stays the run's result.
        if (_completedRequestUtc is { } done && result is not null && result.TimeUtc > done) return new(OfflineMemoryPhase.Done, a, result);
        return new(OfflineMemoryPhase.Idle, a, result, Message: message);
    }

    /// <summary>What to tell the person before the restart, for the request they are about to make.</summary>
    public static IReadOnlyList<OfflineMemoryWarning> Warnings(MemoryDiagnosticAnswer? a, OfflineMemoryWhen when, OfflineMemoryMix mix)
    {
        var list = new List<OfflineMemoryWarning>();
        if (a?.BitLockerOn == true && a.RecoveryPassword == false)
            list.Add(new("bitlocker-no-key", "BitLocker is on, but the system drive has no recovery key. If Windows asks for one after the restart, "
                + "there is no way back in. Add and save a recovery key first (Control Panel > BitLocker Drive Encryption > Back up your recovery key).", true));
        else if (a?.BitLockerOn == true)
            list.Add(new("bitlocker-key", "BitLocker is on. The test doesn't normally ask for the recovery key, but make sure you know where it is "
                + "saved (for a Microsoft account: aka.ms/myrecoverykey) before you restart. This app can't see whether it was backed up.", false));
        if (a?.FastStartup == true && when == OfflineMemoryWhen.NextRestart)
            list.Add(new("fast-startup", "Fast Startup is on, so Shut down and then turning the PC on skips the test. Use Restart.", false));
        if (mix == OfflineMemoryMix.Extended)
            list.Add(new("extended-long", "The extended test can take several hours on a PC with a lot of memory. Keep it plugged in.", false));
        return list;
    }

    /// <summary>
    /// Sets the boot test for the next start, then with <see cref="OfflineMemoryWhen.Now"/> schedules the clean restart (60 seconds).
    /// Call only after the person agreed: the restart closes their programs.
    /// </summary>
    public async Task<OfflineMemoryState> ScheduleAsync(OfflineMemoryMix mix, OfflineMemoryWhen when, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        MemoryDiagnosticReply reply;
        try
        {
            reply = await source.RunAsync(["schedule", AgentMemoryDiagnostic.MixArg(mix)], ct).ConfigureAwait(false);
            log.Info($"Memory test: schedule boot test mix={mix} when={when}: {(reply.Answer is null ? reply.Error : "set")}");
            if (reply.Answer is null)
            {
                var failed = Evaluate(await source.RunAsync(["status"], ct).ConfigureAwait(false), _state.LastResult, null) with
                    { Error = reply.Error, Message = "The boot memory test couldn't be set: " + reply.Error };
                Set(failed);
                return failed;
            }
            _completedRequestUtc = null;
        }
        finally { _gate.Release(); }

        string message = "The boot memory test is set for the next time Windows restarts.";
        if (when == OfflineMemoryWhen.Now)
        {
            var r = remediation?.Invoke();
            var restart = r is null ? null : await r.ExecuteAsync(
                new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart for the memory test", "", "Restart to run the Windows memory test"), ct).ConfigureAwait(false);
            if (restart is { Success: true })
            {
                _restartScheduledUtc = Now;
                message = "The PC restarts in 60 seconds and runs the memory test before Windows starts. It restarts again by itself when the test is done, "
                    + "and this app shows the result after sign-in.";
            }
            else
                message = "The test is set for the next restart, but the restart couldn't be scheduled"
                    + (restart?.Message is { Length: > 0 } why ? ": " + why : ".") + " Restart the PC to run it.";
        }
        var state = Evaluate(reply, _state.LastResult, message);
        Set(state);
        return state;
    }

    /// <summary>Takes the test off the next start (and calls off a restart this app scheduled for it).</summary>
    public async Task<OfflineMemoryState> CancelAsync(CancellationToken ct = default)
    {
        string? note = null;
        if (_restartScheduledUtc is not null && remediation?.Invoke() is { } r)
        {
            var called = await r.ExecuteAsync(new AreaAction(RemediationKind.CancelScheduledRestart, "Cancel the restart", "", "Cancel the restart"), ct).ConfigureAwait(false);
            note = called.Success ? " The restart is called off." : " The restart couldn't be called off: " + called.Message;
            _restartScheduledUtc = null;
        }
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var reply = await source.RunAsync(["cancel"], ct).ConfigureAwait(false);
            var state = reply.Answer is null
                ? _state with { Error = reply.Error, Message = "The boot memory test couldn't be taken off: " + reply.Error }
                : Evaluate(reply, _state.LastResult, "The boot memory test won't run." + note);
            Set(state);
            return state;
        }
        finally { _gate.Release(); }
    }
}

/// <summary>The boot memory test's state for browser agents (memdiag-data on the Memory test page).</summary>
public static class OfflineMemoryExport
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Phase(OfflineMemoryPhase p) => p switch
    {
        OfflineMemoryPhase.NeedsAgent => "needs-agent",
        OfflineMemoryPhase.WaitingForResult => "waiting-for-result",
        OfflineMemoryPhase.NotRun => "not-run",
        _ => p.ToString().ToLowerInvariant(),
    };

    public static string Mix(OfflineMemoryMix m) => AgentMemoryDiagnostic.MixArg(m);
    public static string When(OfflineMemoryWhen w) => w == OfflineMemoryWhen.Now ? "now" : "next";

    public static string ToJson(OfflineMemoryState s, OfflineMemoryMix mix, OfflineMemoryWhen when, bool confirming) =>
        JsonSerializer.Serialize(new
        {
            schema = 1,
            phase = Phase(s.Phase),
            mode = Mix(mix),
            when = When(when),
            confirming,
            canSchedule = s.CanSchedule,
            canCancel = s.CanCancel,
            requestedAt = s.Agent?.RequestedAtUtc?.ToString("O"),
            requestedMode = s.Agent?.Mix is { } m ? Mix(m) : null,
            lastResult = s.LastResult is { } r ? new
            {
                outcome = r.Outcome == OfflineMemoryOutcome.NoErrors ? "no-errors" : "errors",
                headline = r.Headline,
                time = r.TimeUtc.ToString("O"),
                eventId = r.EventId,
                message = AreaReportExport.Text(r.Message, AreaReportExport.MaxTextLength),
            } : null,
            bitLockerOn = s.Agent?.BitLockerOn,
            recoveryPassword = s.Agent?.RecoveryPassword,
            fastStartup = s.Agent?.FastStartup,
            warnings = OfflineMemoryDiagnostic.Warnings(s.Agent, when, mix).Select(w => new { id = w.Id, text = w.Text, serious = w.Serious }).ToList(),
            error = AreaReportExport.Text(s.Error, AreaReportExport.MaxTextLength),
            message = AreaReportExport.Text(s.Message, AreaReportExport.MaxTextLength),
        }, Json);
}
