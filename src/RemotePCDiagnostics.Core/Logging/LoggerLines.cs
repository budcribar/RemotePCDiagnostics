using MelLevel = Microsoft.Extensions.Logging.LogLevel;
using MelILogger = Microsoft.Extensions.Logging.ILogger;

// Its own namespace (imported project-wide with an ILogger alias), so files don't also import Microsoft.Extensions.Logging, whose
// LogLevel would clash with the app's RemotePCDiagnostics.Core.Logging.LogLevel.
namespace RemotePCDiagnostics.Logging;

/// <summary>
/// Plain-text lines on an <see cref="MelILogger"/>: the caller picks the level, and a null logger writes nothing. The text is the
/// whole message (not a message template), so braces in it are kept as they are.
/// </summary>
public static class LoggerLines
{
    public static void Info(this MelILogger? log, string message) => Write(log, MelLevel.Information, message);
    public static void Warn(this MelILogger? log, string message) => Write(log, MelLevel.Warning, message);
    public static void Error(this MelILogger? log, string message) => Write(log, MelLevel.Error, message);

    /// <summary>A line whose wording comes from somewhere else (a plugin, a helper's output): its level is read from the text
    /// (<see cref="Core.Logging.LogLevels.Classify"/>).</summary>
    public static void Line(this MelILogger? log, string message) => Write(log, Core.Logging.LogLevels.Classify(message) switch
    {
        Core.Logging.LogLevel.Error => MelLevel.Error,
        Core.Logging.LogLevel.Warning => MelLevel.Warning,
        _ => MelLevel.Information,
    }, message);

    /// <summary>For an API that still takes a text callback (the plugin contract's <c>Action&lt;string&gt;</c>): each line's level is read from its text.</summary>
    public static Action<string>? AsAction(this MelILogger? log) => log is null ? null : log.Line;

    private static void Write(MelILogger? log, MelLevel level, string message)
    {
        if (log is null || !log.IsEnabled(level)) return;
        try { log.Log(level, default, message, null, static (s, _) => s); } catch { /* logging must never break the caller */ }
    }
}

/// <summary>An <see cref="MelILogger"/> that hands each line's text to a callback, without level or category (tests, the plugin
/// contract's text log, minimal hosts). An exception is summarised on the line the way the app logger does it.</summary>
public sealed class LineLogger(Action<string> write) : MelILogger
{
    /// <summary>A logger over the callback, or null when there is none.</summary>
    public static MelILogger? From(Action<string>? write) => write is null ? null : new LineLogger(write);

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(MelLevel logLevel) => logLevel != MelLevel.None;

    public void Log<TState>(MelLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;
        try
        {
            var message = formatter(state, exception);
            if (exception is not null) message = $"{message} ({exception.GetType().Name}: {exception.Message})";
            write(message);
        }
        catch { /* logging must never break the caller */ }
    }
}
