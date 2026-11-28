using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Tests;

/// <summary>The System and Application logs don't need administrator rights, so an Agent that didn't answer doesn't make them unreadable.</summary>
public class EventLogAgentFallbackTests
{
    private const string OneEvent =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-USB-USBHUB3'/>"
        + "<EventID>43</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-28T10:00:00Z'/><Channel>System</Channel></System>"
        + "<RenderingInfo><Message>A device was reset.</Message></RenderingInfo></Event>";

    private sealed class SilentAgent : IElevatedCommandBridge
    {
        public int Calls;
        public bool IsConnected => true; // "Waiting for agent": the pipe looks up but nothing answers
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult<ProcessResult?>(null);
        }
        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
    }

    private static (WindowsEventLog Log, ScriptedLauncher Launcher, SilentAgent Agent) Make()
    {
        var launcher = new ScriptedLauncher((file, _) => file.EndsWith("wevtutil.exe", StringComparison.OrdinalIgnoreCase)
            ? new ProcessResult(0, OneEvent, "") : new ProcessResult(1, "", "unexpected"));
        var agent = new SilentAgent();
        var commands = new SystemCommandRunner(launcher, elevatedBridge: agent, isProcessElevated: () => false);
        return (new WindowsEventLog(commands), launcher, agent);
    }

    [Theory]
    [InlineData("System")]
    [InlineData("Application")]
    public async Task The_app_reads_the_log_itself_when_the_Agent_does_not_answer(string channel)
    {
        var (log, launcher, agent) = Make();
        var events = await log.QueryAsync(channel, "*", 10, CancellationToken.None);
        Assert.Equal(1, agent.Calls);
        Assert.Equal(43, Assert.Single(events!).EventId);
        Assert.Single(launcher.Calls);
    }

    [Fact]
    public async Task Other_logs_still_need_the_Agent()
    {
        var (log, launcher, agent) = Make();
        Assert.Null(await log.QueryAsync("Security", "*", 10, CancellationToken.None));
        Assert.Equal(1, agent.Calls);
        Assert.Empty(launcher.Calls);
    }
}
