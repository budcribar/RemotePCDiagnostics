using MelLevel = Microsoft.Extensions.Logging.LogLevel;
using MelILogger = Microsoft.Extensions.Logging.ILogger;

// Its own namespace (imported project-wide with an ILogger alias), so files don't also import Microsoft.Extensions.Logging, whose
// LogLevel would clash with the app's RemotePCDiagnostics.Core.Logging.LogLevel. In the contract assembly so plugins can use it too.
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

    /// <summary>Writes <paramref name="message"/> at <paramref name="level"/>. Never throws.</summary>
    public static void Write(MelILogger? log, MelLevel level, string message)
    {
        if (log is null || !log.IsEnabled(level)) return;
        try { log.Log(level, default, message, null, static (s, _) => s); } catch { /* logging must never break the caller */ }
    }
}

/// <summary>An <see cref="MelILogger"/> that hands each line's text to a callback, without level or category (tests, minimal hosts).
/// An exception is summarised on the line the way the app logger does it.</summary>
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

/// <summary>Puts "[<paramref name="prefix"/>] " in front of every line and passes it on at the same level (a plugin's log).</summary>
public sealed class PrefixedLogger(MelILogger? inner, string prefix) : MelILogger
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => inner?.BeginScope(state);
    public bool IsEnabled(MelLevel logLevel) => inner?.IsEnabled(logLevel) == true;

    public void Log<TState>(MelLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (inner is null || !inner.IsEnabled(logLevel)) return;
        try { inner.Log(logLevel, eventId, $"[{prefix}] {formatter(state, exception)}", exception, static (s, _) => s); }
        catch { /* logging must never break the caller */ }
    }
}
