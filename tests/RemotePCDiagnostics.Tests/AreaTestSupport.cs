using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

/// <summary>Launcher fake keyed on the executable file name (osqueryi, powershell, wevtutil) and full argument list.</summary>
internal sealed class ScriptedLauncher(Func<string, IReadOnlyList<string>, ProcessResult> run) : IProcessLauncher
{
    public List<(string File, IReadOnlyList<string> Args)> Calls { get; } = new();
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
