using MelLevel = Microsoft.Extensions.Logging.LogLevel;
using MelILogger = Microsoft.Extensions.Logging.ILogger;

namespace RemotePCDiagnostics.Logging;

/// <summary>Lines whose wording comes from somewhere else (a helper's output): the level is read from the text. Info, Warn and Error
/// (<see cref="LoggerLines"/>) live in the contract assembly.</summary>
public static class ClassifiedLines
{
    /// <summary>Writes <paramref name="message"/> at the level <see cref="Core.Logging.LogLevels.Classify"/> reads from it.</summary>
    public static void Line(this MelILogger? log, string message) => LoggerLines.Write(log, Core.Logging.LogLevels.Classify(message) switch
    {
        Core.Logging.LogLevel.Error => MelLevel.Error,
        Core.Logging.LogLevel.Warning => MelLevel.Warning,
        _ => MelLevel.Information,
    }, message);
}
