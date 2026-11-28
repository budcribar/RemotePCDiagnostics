using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>The Agent's answer to one self-test request: the drives it read, or why there is no answer.</summary>
/// <param name="NoAgent">True when no Agent is connected (the Store edition without one): the test is skipped, not failed.</param>
public sealed record SelfTestReply(SelfTestAnswer? Answer, string? Error, bool NoAgent = false)
{
    public bool Ok => Answer is not null;

    public static SelfTestReply Failed(string why, bool noAgent = false) => new(null, why, noAgent);
}

/// <summary>
/// Where <see cref="DriveSelfTestModule"/> asks the drives (through the Agent: <see cref="AgentScripts.DriveSelfTest"/>). One method for
/// every request, so a recording keeps each one with its answer (<see cref="Recording.RecordedCall.SelfTestKind"/>) and replays them in order.
/// </summary>
public interface IDriveSelfTestSource
{
    /// <param name="args">The request: <c>list</c>; <c>status N</c>; <c>start N short|extended</c>; <c>abort N</c>.</param>
    Task<SelfTestReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct);
}

public static class DriveSelfTestSourceExtensions
{
    public static Task<SelfTestReply> ListAsync(this IDriveSelfTestSource s, CancellationToken ct) => s.RunAsync(["list"], ct);
    public static Task<SelfTestReply> StatusAsync(this IDriveSelfTestSource s, int disk, CancellationToken ct) => s.RunAsync(["status", Num(disk)], ct);
    public static Task<SelfTestReply> StartAsync(this IDriveSelfTestSource s, int disk, SelfTestKind kind, CancellationToken ct) =>
        s.RunAsync(["start", Num(disk), AgentDriveSelfTest.KindArg(kind)], ct);
    public static Task<SelfTestReply> AbortAsync(this IDriveSelfTestSource s, int disk, CancellationToken ct) => s.RunAsync(["abort", Num(disk)], ct);

    private static string Num(int n) => n.ToString(System.Globalization.CultureInfo.InvariantCulture);
}

/// <summary>The real source: each request goes to the Agent, which talks to the drives.</summary>
public sealed class AgentDriveSelfTestSource(SystemCommandRunner commands) : IDriveSelfTestSource
{
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromMinutes(2);

    public async Task<SelfTestReply> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        var r = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.DriveSelfTest, [.. args]), RequestTimeout, ct).ConfigureAwait(false);
        if (r is null) return SelfTestReply.Failed("The Agent didn't answer.");
        if (r.ExitCode == SystemCommandRunner.AgentFailedExitCode && !commands.HasAdminRights)
            return SelfTestReply.Failed(string.IsNullOrWhiteSpace(r.StdErr) ? "The Agent isn't connected." : r.StdErr.Trim(), noAgent: true);
        if (r.TimedOut) return SelfTestReply.Failed("The Agent didn't answer in time.");
        if (r.ExitCode != 0) return SelfTestReply.Failed(string.IsNullOrWhiteSpace(r.StdErr) ? $"The Agent answered with exit code {r.ExitCode}." : r.StdErr.Trim());
        return SelfTestAnswer.Parse(r.StdOut) is { } answer ? new(answer, null) : SelfTestReply.Failed("The Agent's answer couldn't be read.");
    }
}
