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
        new(options: new OsqueryOptions { ExecutablePath = "/x/osqueryi.exe", Log = log is null ? null : s => { lock (log) log.Add(s); } }, launcher: l, fileExists: _ => true);
}
