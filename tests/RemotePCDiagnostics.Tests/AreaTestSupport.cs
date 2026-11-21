using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Launcher fake keyed on the executable file name (osqueryi, powershell, wevtutil) and full argument list. It also stands in for the
/// changes the Agent makes in C# (<see cref="IAgentNativeOps"/>): each goes to <c>run</c> as file "agent:&lt;action&gt;" with the action's
/// values as arguments, and is recorded in <see cref="NativeCalls"/> (not <see cref="Calls"/>).
/// </summary>
internal sealed class ScriptedLauncher(Func<string, IReadOnlyList<string>, ProcessResult> run) : IProcessLauncher, IAgentNativeOps
{
    public List<(string File, IReadOnlyList<string> Args)> Calls { get; } = new();
    public List<AgentNativeAction> NativeCalls { get; } = new();

    public Task<ProcessResult> RunAsync(AgentNativeAction action, CancellationToken ct)
    {
        lock (NativeCalls) NativeCalls.Add(action);
        IReadOnlyList<string> args = action switch
        {
            StopProcessAction s => [s.ProcessName],
            OptimizeVolumeAction o => [o.DriveLetters],
            RegisterTaskAction r => [r.TaskName, r.User, r.TaskXml],
            RemoveTaskAction r => [r.TaskName],
            _ => [],
        };
        return Task.FromResult(run(NativeName(action), args));
    }

    /// <summary>"agent:StopProcess", "agent:CleanTemp", …: the file name <c>run</c> gets for a change the Agent makes in C#.</summary>
    public static string NativeName(AgentNativeAction action) => "agent:" + action.GetType().Name.Replace("Action", "");
    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
    {
        lock (Calls) Calls.Add((fileName, arguments));
        return Task.FromResult(run(Path.GetFileName(fileName).Replace('\\', '/').Split('/')[^1], arguments));
    }

    public static ProcessResult Ok(string stdout) => new(0, stdout, "");
    public static ProcessResult Fail(string stderr = "boom") => new(1, "", stderr);

    public static OsqueryRunner Osquery(IProcessLauncher l, List<string>? log = null) =>
        new(options: new OsqueryOptions { ExecutablePath = "/x/osqueryi.exe", Log = log is null ? null : new LineLogger(s => { lock (log) log.Add(s); }) }, launcher: l, fileExists: _ => true);
}

/// <summary>In-memory <see cref="ISystemSettings"/>: records every write as "fast-startup=0", "proxy=1", "dns:Wi-Fi=1.1.1.1,8.8.8.8" ("" = automatic).
/// <see cref="FailWrites"/> names the settings whose write Windows refuses ("proxy", "fast-startup", "dns").</summary>
internal sealed class FakeSystemSettings : ISystemSettings
{
    public int? FastStartup { get; set; }
    public int? ProxyEnable { get; set; }
    public Dictionary<string, string> Dns { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>DNS of an adapter not in <see cref="Dns"/> (null: no such adapter).</summary>
    public string? DefaultDns { get; set; }
    public HashSet<string> FailWrites { get; } = [];
    public List<string> Calls { get; } = [];

    public int? GetFastStartup() => FastStartup;
    public void SetFastStartup(int value) { Write("fast-startup", $"fast-startup={value}"); FastStartup = value; }
    public int? GetUserProxyEnable() => ProxyEnable;
    public void SetUserProxyEnable(int value) { Write("proxy", $"proxy={value}"); ProxyEnable = value; }
    public string? GetAdapterDns(string alias) => Dns.TryGetValue(alias, out var d) ? d : DefaultDns;
    public void SetAdapterDns(string alias, IReadOnlyList<string> servers) { Write("dns", $"dns:{alias}={string.Join(",", servers)}"); Dns[alias] = string.Join(",", servers); }

    private void Write(string what, string call)
    {
        Calls.Add(call);
        if (FailWrites.Contains(what)) throw new UnauthorizedAccessException("Access denied");
    }
}
