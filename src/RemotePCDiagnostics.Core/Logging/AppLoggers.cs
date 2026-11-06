using Microsoft.Extensions.Logging;
using MelLevel = Microsoft.Extensions.Logging.LogLevel;

namespace RemotePCDiagnostics.Core.Logging;

/// <summary>
/// Microsoft.Extensions.Logging over the app's own sinks (file log, and the Windows Event Log for warnings and errors). Code that takes an
/// <see cref="ILogger"/> says how serious each line is (<see cref="RemotePCDiagnostics.Logging.LoggerLines"/>), so nothing has to guess it
/// from the wording; plugins log through the same <see cref="ILogger"/> (contract 2.0). Only text whose wording comes from elsewhere
/// (<see cref="RemotePCDiagnostics.Logging.ClassifiedLines.Line"/>) has its level read from the text (<see cref="LogLevels.Classify"/>).
/// Framework categories (Microsoft.*, System.*) log warnings and up only.
/// </summary>
public sealed class AppLoggerFactory(Action<LogLevel, string, string> write) : ILoggerFactory
{
    /// <summary>A factory that writes "[category] message" lines to an <c>Action&lt;string&gt;</c> log (tests, minimal hosts).</summary>
    public static AppLoggerFactory From(Action<string>? log) => new((_, category, message) => log?.Invoke($"[{ShortName(category)}] {message}"));

    public ILogger CreateLogger(string categoryName) => new AppLogger(categoryName, write);
    public void AddProvider(ILoggerProvider provider) { } // one sink: the app's own
    public void Dispose() { }

    /// <summary>The type name without its namespace ("RemotePCDiagnostics.Host.ModuleUiFrames" → "ModuleUiFrames").</summary>
    public static string ShortName(string category) => category.LastIndexOf('.') is var i and >= 0 ? category[(i + 1)..] : category;

    /// <summary>The app's three levels: Trace, Debug and Information are Information; Critical is Error.</summary>
    public static LogLevel ToAppLevel(MelLevel level) => level switch
    {
        MelLevel.Warning => LogLevel.Warning,
        MelLevel.Error or MelLevel.Critical => LogLevel.Error,
        _ => LogLevel.Information,
    };

    private sealed class AppLogger(string category, Action<LogLevel, string, string> write) : ILogger
    {
        private readonly MelLevel _minimum = category.StartsWith("Microsoft.", StringComparison.Ordinal) || category.StartsWith("System.", StringComparison.Ordinal)
            ? MelLevel.Warning : MelLevel.Information;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(MelLevel logLevel) => logLevel != MelLevel.None && logLevel >= _minimum;

        public void Log<TState>(MelLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            try
            {
                var message = formatter(state, exception);
                if (exception is not null) message = $"{message} ({exception.GetType().Name}: {exception.Message})";
                write(ToAppLevel(logLevel), category, message);
            }
            catch { /* logging must never break the caller */ }
        }
    }
}
