using System.Text;

namespace RemotePCDiagnostics.Core.Logging;

/// <summary>
/// Plain-text log file that rolls over by size: when the file passes <c>maxBytes</c> it becomes <c>name.1.log</c> (older ones shift up,
/// the oldest beyond <c>keep</c> is deleted). Thread-safe; never throws (a log must not break a run).
/// </summary>
public sealed class RollingFileLog(string path, long maxBytes = RollingFileLog.DefaultMaxBytes, int keep = RollingFileLog.DefaultKeep)
{
    public const long DefaultMaxBytes = 5L * 1024 * 1024;
    public const int DefaultKeep = 5;
    private readonly object _gate = new();
    public string Path { get; } = path;

    /// <summary>%LOCALAPPDATA%\RemotePCDiagnostics\logs\RemotePCDiagnostics.log</summary>
    public static string DefaultPath() =>
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "logs", "RemotePCDiagnostics.log");

    public string BackupPath(int n) =>
        System.IO.Path.Combine(System.IO.Path.GetDirectoryName(Path) ?? "", $"{System.IO.Path.GetFileNameWithoutExtension(Path)}.{n}{System.IO.Path.GetExtension(Path)}");

    public void Write(string line)
    {
        try
        {
            lock (_gate)
            {
                var dir = System.IO.Path.GetDirectoryName(Path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                if (File.Exists(Path) && new FileInfo(Path).Length >= maxBytes) Roll();
                File.AppendAllText(Path, line + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch { /* logging must never throw */ }
    }

    private void Roll()
    {
        try
        {
            var oldest = BackupPath(keep);
            if (File.Exists(oldest)) File.Delete(oldest);
            for (int i = keep - 1; i >= 1; i--)
                if (File.Exists(BackupPath(i))) File.Move(BackupPath(i), BackupPath(i + 1));
            File.Move(Path, BackupPath(1));
        }
        catch { /* if rolling fails keep appending */ }
    }
}

/// <summary>Decides whether a free-text log line is a warning or error, so it also reaches the Windows Event Log.</summary>
public static class LogLevels
{
    private static readonly string[] WarningMarkers =
    [
        " failed", "failed:", "couldn't", "could not", "unable to", "timed out", "overran", "overrun", "ran past",
        "stopped responding", "mismatch", "abort", "not responding",
    ];

    public static LogLevel Classify(string? message)
    {
        if (string.IsNullOrEmpty(message)) return LogLevel.Information;
        if (message.StartsWith("Unhandled:", StringComparison.Ordinal) || message.StartsWith("Fatal:", StringComparison.Ordinal)
            || message.Contains("Exception", StringComparison.Ordinal)) return LogLevel.Error;
        foreach (var m in WarningMarkers)
            if (message.Contains(m, StringComparison.OrdinalIgnoreCase)) return LogLevel.Warning;
        return LogLevel.Information;
    }
}

/// <summary>Keeps repeated or chatty warnings from flooding the Event Log: the same text is let through once per window, and at most
/// <c>maxPerMinute</c> entries go out per minute.</summary>
public sealed class EventLogGate(Func<DateTimeOffset>? now = null, TimeSpan? repeatWindow = null, int maxPerMinute = 30)
{
    private readonly Func<DateTimeOffset> _now = now ?? (() => DateTimeOffset.Now);
    private readonly TimeSpan _repeat = repeatWindow ?? TimeSpan.FromMinutes(5);
    private readonly Dictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly Queue<DateTimeOffset> _recent = new();
    private readonly object _gate = new();

    public bool Allow(string message)
    {
        lock (_gate)
        {
            var t = _now();
            while (_recent.Count > 0 && t - _recent.Peek() >= TimeSpan.FromMinutes(1)) _recent.Dequeue();
            if (_seen.TryGetValue(message, out var last) && t - last < _repeat) return false;
            if (_recent.Count >= maxPerMinute) return false;
            if (_seen.Count > 500) _seen.Clear();
            _seen[message] = t;
            _recent.Enqueue(t);
            return true;
        }
    }
}
