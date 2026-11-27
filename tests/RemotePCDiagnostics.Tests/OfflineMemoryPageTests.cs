using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Stress;
using RemotePCDiagnostics.Modules.MemoryTest;
using RemotePCDiagnostics.UI;

namespace RemotePCDiagnostics.Tests;

/// <summary>The Windows boot memory test on the Memory test page (RPCD #290): the agent copy, the confirm step and its warnings.</summary>
public class OfflineMemoryPageTests : BunitContext
{
    private const long GB = MemorySizing.GB;

    private sealed class Source : IMemoryDiagnosticSource
    {
        public MemoryDiagnosticReply Status { get; set; } = new(new MemoryDiagnosticAnswer { BitLockerOn = true, RecoveryPassword = false, FastStartup = true }, null);
        public List<string> Calls { get; } = [];

        public Task<MemoryDiagnosticReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            Calls.Add(string.Join(' ', args));
            if (args[0] == "schedule")
                Status = new(Status.Answer! with { Scheduled = true, RequestedAtUtc = DateTimeOffset.UtcNow, Mix = AgentMemoryDiagnostic.ParseMix(args[1]) }, null);
            if (args[0] == "clear")
                Status = new(Status.Answer! with { Scheduled = false, RequestedAtUtc = null, Mix = null }, null);
            return Task.FromResult(Status);
        }
    }

    private (IRenderedComponent<MemoryTestPage> Page, Source Source) RenderPage(Source? source = null, Func<string>? events = null, Func<DateTimeOffset>? clock = null)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        source ??= new Source();
        var getEvents = events ?? (() => "");
        var commands = new SystemCommandRunner(new ScriptedLauncher((file, _) => file == "wevtutil.exe" ? ScriptedLauncher.Ok(getEvents()) : ScriptedLauncher.Fail()));
        var offline = new OfflineMemoryDiagnostic(source, new WindowsEventLog(commands), clock: clock);
        var module = new MemoryTestModule(new FakeMemoryInfo(16 * GB), new FakeHelperLauncher(), new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false),
            new FakeMdsched(), offline: offline);
        var store = new ResultStore();
        var diagnostics = new DiagnosticsService(store, [module]);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices());
        var page = Render<MemoryTestPage>(p => p.Add(c => c.DiagnosticModule, module));
        return (page, source);
    }

    [Fact]
    public void Shows_the_last_result_and_schedules_for_the_next_restart_after_the_warnings()
    {
        var events = EventLogTests.Ev(OfflineMemoryResult.Provider, 1202, 2, "2026-11-20T10:00:00.0000000Z", "The Windows Memory Diagnostic tested the computer's memory and detected hardware errors");
        var (page, source) = RenderPage(events: () => events);
        page.WaitForAssertion(() => Assert.Equal("idle", page.Find("[data-testid='memdiag']").GetAttribute("data-phase")));
        Assert.Equal("errors", page.Find("[data-testid='memdiag-result']").GetAttribute("data-outcome"));
        Assert.Contains("Hardware problems were detected", page.Find("[data-testid='memdiag-result']").TextContent);
        Assert.Empty(page.FindAll("[data-testid='memtest-mdsched']")); // the Agent schedules it: no Windows dialog
        // Default when="now" still surfaces fast-startup warning in memdiag-data for automation.
        var initialData = page.Find("[data-testid='memdiag-data']").GetAttribute("data-report")!;
        Assert.Contains("\"fast-startup\"", initialData);

        page.Find("[data-testid='memdiag-mode']").Change("extended");
        page.Find("[data-testid='memdiag-when']").Change("next");
        page.Find("[data-testid='memdiag-schedule']").Click();
        var warnings = page.FindAll("[data-testid='memdiag-warning']").Select(w => w.GetAttribute("data-warning-id")).ToList();
        Assert.Equal(["bitlocker-no-key", "fast-startup", "extended-long"], warnings);
        Assert.DoesNotContain(source.Calls, c => c.StartsWith("schedule", StringComparison.Ordinal));
        var data = page.Find("[data-testid='memdiag-data']").GetAttribute("data-report")!;
        Assert.Contains("\"confirming\":true", data);
        Assert.Contains("\"when\":\"next\"", data);

        page.Find("[data-testid='memdiag-confirm-yes']").Click();
        page.WaitForAssertion(() => Assert.Equal("scheduled", page.Find("[data-testid='memdiag']").GetAttribute("data-phase")));
        Assert.Contains("schedule extended", source.Calls);
        Assert.Contains("extended test", page.Find("[data-testid='memdiag-status']").TextContent);
        Assert.NotNull(page.Find("[data-testid='memdiag-cancel']"));
    }

    [Fact]
    public void Refresh_button_picks_up_result_while_waiting_for_result()
    {
        var requested = DateTimeOffset.Parse("2026-11-27T10:00:00Z");
        var boot = requested.AddMinutes(5);
        var currentEvents = "";
        var source = new Source
        {
            Status = new(new MemoryDiagnosticAnswer { Scheduled = false, RequestedAtUtc = requested, Mix = OfflineMemoryMix.Standard, BootTimeUtc = boot }, null),
        };
        var (page, _) = RenderPage(source, events: () => currentEvents, clock: () => boot.AddMinutes(2));

        page.WaitForAssertion(() => Assert.Equal("waiting-for-result", page.Find("[data-testid='memdiag']").GetAttribute("data-phase")));
        Assert.NotNull(page.Find("[data-testid='memdiag-refresh']"));

        currentEvents = EventLogTests.Ev(OfflineMemoryResult.Provider, 1201, 4, "2026-11-27T10:08:00.0000000Z", "The Windows Memory Diagnostic tested the computer's memory and detected no errors");
        page.Find("[data-testid='memdiag-refresh']").Click();

        page.WaitForAssertion(() => Assert.Equal("done", page.Find("[data-testid='memdiag']").GetAttribute("data-phase")));
        Assert.Equal("no-errors", page.Find("[data-testid='memdiag-result']").GetAttribute("data-outcome"));
        Assert.Contains("clear", source.Calls);
    }

    [Fact]
    public void Without_the_agent_it_says_so_and_keeps_the_windows_dialog()
    {
        var source = new Source { Status = MemoryDiagnosticReply.Failed("The Agent isn't connected.", noAgent: true) };
        var (page, _) = RenderPage(source);
        page.WaitForAssertion(() => Assert.Equal("needs-agent", page.Find("[data-testid='memdiag']").GetAttribute("data-phase")));
        Assert.Contains("Needs the Agent", page.Find("[data-testid='memdiag-status']").TextContent);
        Assert.Empty(page.FindAll("[data-testid='memdiag-schedule']"));
        Assert.NotNull(page.Find("[data-testid='memtest-mdsched']"));
        Assert.NotNull(page.Find("[data-testid='memdiag-no-result']"));
    }
}
