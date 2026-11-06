using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// The latest result of an unsigned module, handed from the app to the module's UI host so its details UI shows the app's last run
/// (<see cref="ModuleDetails.LastResult"/>) instead of starting blank. One <see cref="ModuleHostMessage"/> "result" line over the UI host's
/// stdin: once when the module page opens, then after every run.
/// </summary>
public static class ModuleUiState
{
    /// <summary>The line the app sends for <paramref name="result"/>. One-click actions are removed, as everywhere for unsigned modules.</summary>
    public static string ToLine(DiagnosticResult result) => new ModuleHostMessage
    {
        Type = "result", Status = result.Status, Message = result.Message, Cancelled = result.Cancelled ? true : null, When = result.Timestamp,
        Report = result.Payload is AreaReport r ? UserModeModuleProxy.WithoutActions(r) : null,
    }.ToLine();

    /// <summary>The result a UI host received, or null when the line isn't a result.</summary>
    public static DiagnosticResult? FromLine(string moduleName, string? line) =>
        ModuleHostMessage.Parse(line) is { Type: "result" } m
            ? new DiagnosticResult<AreaReport>(moduleName, m.Status ?? DiagnosticStatus.NotRun, m.Message ?? "", m.When ?? DateTimeOffset.Now, m.Report) { Cancelled = m.Cancelled == true }
            : null;

    /// <summary>
    /// Holds the latest result in a UI host: <see cref="Read"/> takes lines until the input ends; <see cref="Changed"/> fires for each one.
    /// </summary>
    public sealed class Receiver(string moduleName)
    {
        private DiagnosticResult _current = DiagnosticResult.NotRun(moduleName);
        public DiagnosticResult Current => Volatile.Read(ref _current);
        public event Action<DiagnosticResult>? Changed;

        /// <summary>Applies one line; returns whether it was a result.</summary>
        public bool Apply(string? line)
        {
            if (FromLine(moduleName, line) is not { } r) return false;
            Volatile.Write(ref _current, r);
            Changed?.Invoke(r);
            return true;
        }

        /// <summary>Reads lines from <paramref name="input"/> until it ends (the app closed it or went away).</summary>
        public async Task ReadAsync(TextReader input, CancellationToken ct = default)
        {
            while (await input.ReadLineAsync(ct).ConfigureAwait(false) is { } line) Apply(line);
        }
    }
}
