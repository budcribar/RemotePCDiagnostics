namespace RpcdReplayHost;

public sealed record ReplayHostOptions(string RecordingFolder, int Port, string? FaultsFile, bool Store)
{
    public static ReplayHostOptions Current { get; set; } = new("", 5099, null, false);

    public string RecordingName => Path.GetFileName(Path.TrimEndingDirectorySeparator(RecordingFolder));

    public static ReplayHostOptions Parse(string[] args)
    {
        string? recording = null, faults = null;
        int port = 5099;
        var store = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--recording": recording = args[++i]; break;
                case "--port": port = int.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture); break;
                case "--faults": faults = args[++i]; break;
                case "--store": store = true; break;
                default: throw new ArgumentException($"Unknown argument {args[i]}. Use --recording <folder> [--port 5099] [--faults plan.json] [--store].");
            }
        }
        if (recording is null || !File.Exists(Path.Combine(recording, "calls.json")))
            throw new ArgumentException("--recording must name a recording folder (one with calls.json).");
        return new(recording, port, faults, store);
    }
}

/// <summary>Errors logged while the host runs (an unhandled exception in a page or a check), for the tests to read.</summary>
public sealed class ErrorLog : Microsoft.Extensions.Logging.ILoggerProvider
{
    private readonly List<string> _entries = [];

    public IReadOnlyList<string> Entries { get { lock (_entries) return [.. _entries]; } }
    public void Clear() { lock (_entries) _entries.Clear(); }

    public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);
    public void Dispose() { }

    private sealed class Logger(ErrorLog log, string category) : Microsoft.Extensions.Logging.ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => logLevel >= Microsoft.Extensions.Logging.LogLevel.Error;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var text = $"{category}: {formatter(state, exception)}{(exception is null ? "" : $" {exception.GetType().Name}: {exception.Message}")}";
            lock (log._entries) log._entries.Add(text);
        }
    }
}
