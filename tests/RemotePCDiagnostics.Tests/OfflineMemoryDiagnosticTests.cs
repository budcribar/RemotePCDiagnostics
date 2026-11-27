using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>The Windows boot memory test (RPCD #290): the Agent's bcdedit steps, its allow-list, and the app's phases and warnings.</summary>
public sealed class OfflineMemoryDiagnosticTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "memdiag-" + Guid.NewGuid().ToString("N"));
    private string StatePath => Path.Combine(_dir, AgentMemoryDiagnostic.StateFileName);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    /// <summary>A boot store with the parts bcdedit touches: the one-time boot sequence and the memory test's testmix.</summary>
    private sealed class FakeBcd : IBootConfig
    {
        public List<string> Sequence { get; } = [];
        public string? TestMix { get; set; }
        public bool HasMemDiag { get; set; } = true;
        public bool FailSet { get; set; }
        public bool FailAdd { get; set; }
        public List<string> Calls { get; } = [];

        public ProcessResult Run(IReadOnlyList<string> args)
        {
            Calls.Add(string.Join(' ', args));
            var id = AgentMemoryDiagnostic.MemDiagId;
            switch (args)
            {
                case ["/enum", "{bootmgr}", "/v"]:
                    var lines = new List<string> { "Windows Boot Manager", "--------------------", "identifier              {9dea862c-5cdd-4e70-acc1-f32b344d4795}" };
                    for (var i = 0; i < Sequence.Count; i++) lines.Add(i == 0 ? $"bootsequence            {Sequence[i]}" : $"                        {Sequence[i]}");
                    lines.Add("timeout                 30");
                    return new(0, string.Join("\r\n", lines) + "\r\n", "");
                case ["/enum", var e, "/v"] when e == id:
                    if (!HasMemDiag) return new(1, "", "The specified entry identifier is not valid.");
                    return new(0, $"Windows Memory Tester\r\n---------------------\r\nidentifier              {id}\r\ndescription             Windows Memory Diagnostic\r\n"
                        + (TestMix is null ? "" : $"testmix                 {TestMix}\r\n"), "");
                case ["/set", var s, "testmix", var v] when s == id:
                    if (FailSet) return new(1, "", "The parameter is incorrect.");
                    TestMix = v; return new(0, "The operation completed successfully.", "");
                case ["/deletevalue", var d, "testmix"] when d == id:
                    TestMix = null; return new(0, "", "");
                case ["/bootsequence", var b, "/addfirst"] when b == id:
                    if (FailAdd) return new(1, "", "Access is denied.");
                    Sequence.Remove(id); Sequence.Insert(0, id); return new(0, "", "");
                case ["/bootsequence", var r, "/remove"] when r == id:
                    Sequence.Remove(id); return new(0, "", "");
                default:
                    return new(1, "", "unexpected " + string.Join(' ', args));
            }
        }
    }

    private sealed class FakeMachine : IMemoryDiagnosticMachine
    {
        public bool? BitLocker { get; set; } = false;
        public bool? Recovery { get; set; }
        public bool? Fast { get; set; } = true;
        public DateTimeOffset? Boot { get; set; } = DateTimeOffset.Parse("2026-11-27T08:00:00Z");
        public bool? BitLockerOn() => BitLocker;
        public bool? HasRecoveryPassword() => Recovery;
        public bool? FastStartupOn() => Fast;
        public DateTimeOffset? BootTimeUtc() => Boot;
    }

    private static readonly DateTimeOffset Requested = DateTimeOffset.Parse("2026-11-27T10:00:00Z");

    private MemoryDiagnosticAnswer Run(FakeBcd bcd, string verb, OfflineMemoryMix? mix = null, FakeMachine? machine = null)
    {
        var r = AgentMemoryDiagnostic.Run(bcd, machine ?? new FakeMachine(), StatePath, new MemoryDiagnosticAction(verb, mix), Requested);
        Assert.True(r.ExitCode == 0, r.StdErr);
        return MemoryDiagnosticAnswer.Parse(r.StdOut)!;
    }

    [Fact]
    public void Schedule_extended_puts_the_test_first_in_the_boot_sequence_and_sets_the_mix()
    {
        var bcd = new FakeBcd();
        bcd.Sequence.Add("{11111111-0000-0000-0000-000000000000}");
        var a = Run(bcd, "schedule", OfflineMemoryMix.Extended);

        Assert.True(a.Scheduled);
        Assert.Equal(Requested, a.RequestedAtUtc);
        Assert.Equal(OfflineMemoryMix.Extended, a.Mix);
        Assert.Equal("extended", bcd.TestMix);
        Assert.Equal(AgentMemoryDiagnostic.MemDiagId, bcd.Sequence[0]);
        Assert.True(a.FastStartup);
    }

    [Fact]
    public void After_the_test_ran_status_puts_the_old_mix_back_and_keeps_the_request()
    {
        var bcd = new FakeBcd { TestMix = "Basic" };
        Run(bcd, "schedule", OfflineMemoryMix.Extended);
        bcd.Sequence.Clear(); // the boot manager used the entry at this boot

        var a = Run(bcd, "status");
        Assert.False(a.Scheduled);
        Assert.Equal(Requested, a.RequestedAtUtc);
        Assert.Equal("basic", bcd.TestMix);
        Assert.True(AgentMemoryDiagnostic.Read(StatePath)!.Restored);

        // Read again: nothing is put back twice.
        bcd.TestMix = "extended";
        Run(bcd, "status");
        Assert.Equal("extended", bcd.TestMix);

        Run(bcd, "clear");
        Assert.False(File.Exists(StatePath));
    }

    [Fact]
    public void Standard_on_a_store_with_no_mix_changes_nothing_and_clear_keeps_a_scheduled_request()
    {
        var bcd = new FakeBcd();
        var a = Run(bcd, "schedule", OfflineMemoryMix.Standard);
        Assert.True(a.Scheduled);
        Assert.Null(bcd.TestMix);
        Assert.DoesNotContain(bcd.Calls, c => c.StartsWith("/set", StringComparison.Ordinal));

        Run(bcd, "clear");
        Assert.True(File.Exists(StatePath));
    }

    [Fact]
    public void Cancel_removes_the_test_and_puts_the_mix_back()
    {
        var bcd = new FakeBcd();
        Run(bcd, "schedule", OfflineMemoryMix.Extended);
        var a = Run(bcd, "cancel");

        Assert.False(a.Scheduled);
        Assert.Null(a.RequestedAtUtc);
        Assert.Null(bcd.TestMix);
        Assert.Empty(bcd.Sequence);
        Assert.False(File.Exists(StatePath));
    }

    [Fact]
    public void A_refused_boot_sequence_leaves_nothing_changed()
    {
        var bcd = new FakeBcd { TestMix = "basic", FailAdd = true };
        var r = AgentMemoryDiagnostic.Run(bcd, new FakeMachine(), StatePath, new MemoryDiagnosticAction("schedule", OfflineMemoryMix.Extended), Requested);

        Assert.Equal(1, r.ExitCode);
        Assert.Contains("Access is denied", r.StdErr);
        Assert.Equal("basic", bcd.TestMix);
        Assert.False(File.Exists(StatePath));
    }

    [Fact]
    public void A_refused_mix_is_reported_and_nothing_is_scheduled()
    {
        var bcd = new FakeBcd { FailSet = true };
        var r = AgentMemoryDiagnostic.Run(bcd, new FakeMachine(), StatePath, new MemoryDiagnosticAction("schedule", OfflineMemoryMix.Extended), Requested);
        Assert.Equal(1, r.ExitCode);
        Assert.Contains("extended", r.StdErr);
        Assert.Empty(bcd.Sequence);
    }

    [Fact]
    public void A_pc_without_the_memory_test_entry_says_so()
    {
        var r = AgentMemoryDiagnostic.Run(new FakeBcd { HasMemDiag = false }, new FakeMachine(), StatePath, new MemoryDiagnosticAction("schedule", OfflineMemoryMix.Standard), Requested);
        Assert.Equal(1, r.ExitCode);
        Assert.Contains("no Windows memory test", r.StdErr);
    }

    [Theory]
    [InlineData("bootsequence            {b2721d73-1db4-4c62-bf78-c548a880142d}\r\ntimeout 30", true)]
    [InlineData("bootsequence            {11111111-0000-0000-0000-000000000000}\r\n                        {b2721d73-1db4-4c62-bf78-c548a880142d}\r\ntimeout 30", true)]
    [InlineData("bootsequence            {memdiag}", true)]
    [InlineData("displayorder            {current}\r\n                        {b2721d73-1db4-4c62-bf78-c548a880142d}\r\ntimeout 30", false)]
    [InlineData("toolsdisplayorder       {memdiag}", false)]
    [InlineData("", false)]
    public void Boot_sequence_reading(string output, bool expected) =>
        Assert.Equal(expected, AgentMemoryDiagnostic.BootSequenceHasMemDiag(output));

    [Theory]
    [InlineData(new[] { "status" }, true)]
    [InlineData(new[] { "cancel" }, true)]
    [InlineData(new[] { "clear" }, true)]
    [InlineData(new[] { "schedule", "standard" }, true)]
    [InlineData(new[] { "schedule", "extended" }, true)]
    [InlineData(new[] { "schedule", "basic" }, false)]
    [InlineData(new[] { "schedule" }, false)]
    [InlineData(new[] { "status", "x" }, false)]
    [InlineData(new[] { "bcdedit", "/set" }, false)]
    [InlineData(new string[0], false)]
    public void Agent_allow_list(string[] args, bool allowed)
    {
        var plan = AgentScripts.Plan(AgentScripts.Of(AgentScripts.MemoryDiagnostic, args), null, out var refusal);
        Assert.Equal(allowed, plan?.Native is MemoryDiagnosticAction);
        if (!allowed) Assert.NotNull(refusal);
    }

    // ---- The app's side ---------------------------------------------------------------------------------------------

    private sealed class FakeSource : IMemoryDiagnosticSource
    {
        public MemoryDiagnosticReply Status { get; set; } = new(new MemoryDiagnosticAnswer(), null);
        public MemoryDiagnosticReply? ScheduleReply { get; set; }
        public List<string> Calls { get; } = [];

        public Task<MemoryDiagnosticReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            var request = string.Join(' ', args);
            Calls.Add(request);
            if (args[0] == "schedule")
            {
                if (ScheduleReply is { } r) return Task.FromResult(r);
                Status = new(new MemoryDiagnosticAnswer { Scheduled = true, RequestedAtUtc = Requested, Mix = AgentMemoryDiagnostic.ParseMix(args[1]) }, null);
            }
            if (args[0] is "cancel" or "clear") Status = new(new MemoryDiagnosticAnswer(), null);
            return Task.FromResult(Status);
        }
    }

    private static string ResultEvent(int id, int level, string time, string message) =>
        EventLogTests.Ev(OfflineMemoryResult.Provider, id, level, time, message);

    private static (OfflineMemoryDiagnostic Diag, FakeSource Source) Make(string eventsXml, DateTimeOffset now, Func<RemediationService?>? remediation = null)
    {
        var launcher = new ScriptedLauncher((file, args) => file == "wevtutil.exe" ? ScriptedLauncher.Ok(eventsXml) : ScriptedLauncher.Fail());
        var commands = new SystemCommandRunner(launcher);
        var source = new FakeSource();
        return (new OfflineMemoryDiagnostic(source, new WindowsEventLog(commands), remediation, clock: () => now), source);
    }

    [Fact]
    public async Task Without_the_agent_it_needs_the_agent_and_still_shows_the_last_result()
    {
        var (diag, source) = Make(ResultEvent(1201, 4, "2026-11-01T09:00:00.0000000Z", "The Windows Memory Diagnostic tested the computer's memory and detected no errors"), Requested);
        source.Status = MemoryDiagnosticReply.Failed("The Agent isn't connected.", noAgent: true);

        var s = await diag.RefreshAsync();
        Assert.Equal(OfflineMemoryPhase.NeedsAgent, s.Phase);
        Assert.Equal(OfflineMemoryOutcome.NoErrors, s.LastResult!.Outcome);
        Assert.False(s.CanSchedule);
        Assert.Contains("\"phase\":\"needs-agent\"", OfflineMemoryExport.ToJson(s, OfflineMemoryMix.Standard, OfflineMemoryWhen.Now, false));
    }

    [Fact]
    public async Task Next_restart_schedules_without_restarting()
    {
        var (diag, source) = Make("", Requested.AddMinutes(1));
        Assert.Equal(OfflineMemoryPhase.Idle, (await diag.RefreshAsync()).Phase);

        var s = await diag.ScheduleAsync(OfflineMemoryMix.Extended, OfflineMemoryWhen.NextRestart);
        Assert.Equal(OfflineMemoryPhase.Scheduled, s.Phase);
        Assert.Contains("schedule extended", source.Calls);
        Assert.True(s.CanCancel);

        var cancelled = await diag.CancelAsync();
        Assert.Equal(OfflineMemoryPhase.Idle, cancelled.Phase);
        Assert.Contains("won't run", cancelled.Message);
    }

    [Fact]
    public async Task A_failed_schedule_says_why()
    {
        var (diag, source) = Make("", Requested);
        source.ScheduleReply = MemoryDiagnosticReply.Failed("Access is denied.");
        var s = await diag.ScheduleAsync(OfflineMemoryMix.Standard, OfflineMemoryWhen.NextRestart);
        Assert.Equal(OfflineMemoryPhase.Idle, s.Phase);
        Assert.Contains("Access is denied", s.Message);
    }

    [Fact]
    public async Task Restart_now_without_a_restart_service_leaves_the_test_set_for_the_next_restart()
    {
        var (diag, _) = Make("", Requested);
        var s = await diag.ScheduleAsync(OfflineMemoryMix.Standard, OfflineMemoryWhen.Now);
        Assert.Equal(OfflineMemoryPhase.Scheduled, s.Phase);
        Assert.Contains("couldn't be scheduled", s.Message);
    }

    [Theory]
    [InlineData(1201, 4, OfflineMemoryOutcome.NoErrors)]
    [InlineData(1101, 4, OfflineMemoryOutcome.NoErrors)]
    [InlineData(1202, 2, OfflineMemoryOutcome.Errors)]
    [InlineData(1102, 2, OfflineMemoryOutcome.Errors)]
    [InlineData(1999, 2, OfflineMemoryOutcome.Errors)]
    public async Task After_the_restart_the_result_finishes_the_request(int id, int level, OfflineMemoryOutcome outcome)
    {
        var events = ResultEvent(id, level, "2026-11-27T10:20:00.0000000Z", "The Windows Memory Diagnostic tested the computer's memory")
            + ResultEvent(1201, 4, "2026-10-01T10:20:00.0000000Z", "older run");
        var (diag, source) = Make(events, Requested.AddMinutes(25));
        source.Status = new(new MemoryDiagnosticAnswer { RequestedAtUtc = Requested, Mix = OfflineMemoryMix.Standard, BootTimeUtc = Requested.AddMinutes(18) }, null);

        var s = await diag.RefreshAsync();
        Assert.Equal(OfflineMemoryPhase.Done, s.Phase);
        Assert.Equal(outcome, s.LastResult!.Outcome);
        Assert.Equal(DateTimeOffset.Parse("2026-11-27T10:20:00Z"), s.LastResult.TimeUtc);
        Assert.Contains("clear", source.Calls);

        // The request is gone on the Agent, but the page keeps showing this run as finished.
        Assert.Equal(OfflineMemoryPhase.Done, (await diag.RefreshAsync()).Phase);

        using var doc = JsonDocument.Parse(OfflineMemoryExport.ToJson(s, OfflineMemoryMix.Standard, OfflineMemoryWhen.Now, false));
        Assert.Equal("done", doc.RootElement.GetProperty("phase").GetString());
        Assert.Equal(outcome == OfflineMemoryOutcome.NoErrors ? "no-errors" : "errors", doc.RootElement.GetProperty("lastResult").GetProperty("outcome").GetString());
    }

    [Fact]
    public async Task Restarted_without_a_result_waits_then_says_the_test_did_not_run()
    {
        var old = ResultEvent(1201, 4, "2026-10-01T10:20:00.0000000Z", "older run");
        var boot = Requested.AddMinutes(5);
        var answer = new MemoryDiagnosticAnswer { RequestedAtUtc = Requested, Mix = OfflineMemoryMix.Standard, BootTimeUtc = boot };
        var now = boot.AddMinutes(3);

        var launcher = new ScriptedLauncher((file, _) => file == "wevtutil.exe" ? ScriptedLauncher.Ok(old) : ScriptedLauncher.Fail());
        var source = new FakeSource { Status = new(answer, null) };
        var diag = new OfflineMemoryDiagnostic(source, new WindowsEventLog(new SystemCommandRunner(launcher)), clock: () => now);

        Assert.Equal(OfflineMemoryPhase.WaitingForResult, (await diag.RefreshAsync()).Phase);
        Assert.DoesNotContain("clear", source.Calls);

        // Once ResultGrace elapses after first check, it marks NotRun and clears memdiag.json so future sessions aren't stuck.
        now = now + OfflineMemoryDiagnostic.ResultGrace + TimeSpan.FromMinutes(1);
        var s = await diag.RefreshAsync();
        Assert.Equal(OfflineMemoryPhase.NotRun, s.Phase);
        Assert.True(s.CanSchedule);
        Assert.Contains("clear", source.Calls);

        // Current session keeps showing NotRun even after memdiag.json is cleared.
        Assert.Equal(OfflineMemoryPhase.NotRun, (await diag.RefreshAsync()).Phase);
    }

    [Fact]
    public async Task Sitting_at_lock_screen_past_grace_still_waits_after_sign_in()
    {
        var old = ResultEvent(1201, 4, "2026-10-01T10:20:00.0000000Z", "older run");
        var boot = Requested.AddMinutes(5);
        var answer = new MemoryDiagnosticAnswer { RequestedAtUtc = Requested, Mix = OfflineMemoryMix.Standard, BootTimeUtc = boot };
        // User signed in 2 hours after the 2nd restart.
        var now = boot.AddHours(2);

        var launcher = new ScriptedLauncher((file, _) => file == "wevtutil.exe" ? ScriptedLauncher.Ok(old) : ScriptedLauncher.Fail());
        var source = new FakeSource { Status = new(answer, null) };
        var diag = new OfflineMemoryDiagnostic(source, new WindowsEventLog(new SystemCommandRunner(launcher)), clock: () => now);

        Assert.Equal(OfflineMemoryPhase.WaitingForResult, (await diag.RefreshAsync()).Phase);

        now = now.AddMinutes(10);
        Assert.Equal(OfflineMemoryPhase.WaitingForResult, (await diag.RefreshAsync()).Phase);

        now = now + OfflineMemoryDiagnostic.ResultGrace;
        Assert.Equal(OfflineMemoryPhase.NotRun, (await diag.RefreshAsync()).Phase);
        Assert.Contains("clear", source.Calls);
    }

    [Fact]
    public async Task External_bcd_removal_before_reboot_clears_saved_request()
    {
        var (diag, source) = Make("", Requested.AddMinutes(5));
        source.Status = new(new MemoryDiagnosticAnswer { Scheduled = false, RequestedAtUtc = Requested, Mix = OfflineMemoryMix.Standard, BootTimeUtc = Requested.AddHours(-1) }, null);

        var s = await diag.RefreshAsync();
        Assert.Equal(OfflineMemoryPhase.Idle, s.Phase);
        Assert.Contains("clear", source.Calls);
    }

    [Fact]
    public void Unknown_event_ids_never_map_to_no_errors()
    {
        var warn = new WinEvent(DateTimeOffset.UtcNow, "System", OfflineMemoryResult.Provider, 1999, 3, "Unexpected warning", [], new Dictionary<string, string>());
        Assert.Equal(OfflineMemoryOutcome.Errors, OfflineMemoryResult.FromEvent(warn)?.Outcome);

        var info = new WinEvent(DateTimeOffset.UtcNow, "System", OfflineMemoryResult.Provider, 1999, 4, "Unexpected info", [], new Dictionary<string, string>());
        Assert.Null(OfflineMemoryResult.FromEvent(info));
    }

    [Fact]
    public void Warnings_for_bitlocker_fast_startup_and_extended()
    {
        var noKey = OfflineMemoryDiagnostic.Warnings(new MemoryDiagnosticAnswer { BitLockerOn = true, RecoveryPassword = false, FastStartup = true },
            OfflineMemoryWhen.NextRestart, OfflineMemoryMix.Extended);
        Assert.Equal(["bitlocker-no-key", "fast-startup", "extended-long"], noKey.Select(w => w.Id));
        Assert.True(noKey[0].Serious);

        var withKey = OfflineMemoryDiagnostic.Warnings(new MemoryDiagnosticAnswer { BitLockerOn = true, RecoveryPassword = true, FastStartup = true },
            OfflineMemoryWhen.Now, OfflineMemoryMix.Standard);
        Assert.Equal(["bitlocker-key"], withKey.Select(w => w.Id));

        // JSON export always surfaces fast-startup when enabled, even for default when="now".
        var exported = OfflineMemoryExport.ToJson(
            new OfflineMemoryState(OfflineMemoryPhase.Idle, new MemoryDiagnosticAnswer { FastStartup = true }, null),
            OfflineMemoryMix.Standard, OfflineMemoryWhen.Now, false);
        Assert.Contains("\"fast-startup\"", exported);

        Assert.Empty(OfflineMemoryDiagnostic.Warnings(new MemoryDiagnosticAnswer { BitLockerOn = false, FastStartup = false }, OfflineMemoryWhen.NextRestart, OfflineMemoryMix.Standard));
    }

    [Fact]
    public void Recorded_answers_replay_the_same_way()
    {
        var answer = new MemoryDiagnosticAnswer { Scheduled = true, RequestedAtUtc = Requested, Mix = OfflineMemoryMix.Extended, BitLockerOn = true, RecoveryPassword = true };
        var call = RecordedCall.FromMemoryDiagnostic(["status"], new(answer, null));
        Assert.Equal("memdiag status", call.Describe());
        Assert.Equal(answer, call.ToMemoryDiagnosticReply().Answer);

        var noAgent = RecordedCall.FromMemoryDiagnostic(["status"], MemoryDiagnosticReply.Failed("The Agent isn't connected.", noAgent: true)).ToMemoryDiagnosticReply();
        Assert.True(noAgent.NoAgent);
        Assert.Null(noAgent.Answer);
    }
}
