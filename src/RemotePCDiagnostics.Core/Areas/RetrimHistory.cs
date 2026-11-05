using System.Text.Json;

namespace RemotePCDiagnostics.Core.Areas;

public enum RetrimSource { Windows, ThisApp }

/// <summary>When a volume was last retrimmed, and who reported it.</summary>
public sealed record RetrimRecord(DateTimeOffset When, RetrimSource Source)
{
    public string SourceText => Source == RetrimSource.ThisApp ? "by this app" : "by Windows";
}

/// <summary>Last retrim per drive letter (upper-case). Read-only; never throws to callers that catch nothing.</summary>
public interface IRetrimHistory
{
    Task<IReadOnlyDictionary<char, RetrimRecord>> LatestAsync(CancellationToken ct = default);
}

/// <summary>Windows' own record (Application log, Microsoft-Windows-Defrag event 258). Implemented in the Host; none elsewhere.</summary>
public interface IWindowsRetrimEvents
{
    /// <summary>Retrims Windows logged, newest first or in any order (letter, time).</summary>
    IReadOnlyList<(char Letter, DateTimeOffset When)> Read(TimeSpan window);
}

/// <summary>
/// This app's own record of successful "Optimize / Retrim SSD" fixes, per drive letter, saved to
/// %LOCALAPPDATA%\RemotePCDiagnostics\retrim.json so a later run (or the workflow's second pass) sees it at once,
/// without waiting for Windows' event. <paramref name="path"/> null = memory only (tests).
/// </summary>
public sealed class RetrimLog(string? path = null, ILogger? log = null)
{
    private readonly object _gate = new();
    private Dictionary<char, DateTimeOffset>? _cache;

    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "retrim.json");

    public void Record(string letters, DateTimeOffset when)
    {
        var l = RemediationService.DriveLetters(letters);
        if (l.Length == 0) return;
        lock (_gate)
        {
            var d = LoadLocked();
            foreach (var c in l) if (!d.TryGetValue(c, out var old) || old < when) d[c] = when;
            if (path is null) return;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, JsonSerializer.Serialize(d.ToDictionary(k => k.Key.ToString(), k => k.Value)));
            }
            catch (Exception ex) { log.Info($"retrim log save: {ex.Message}"); }
        }
    }

    public IReadOnlyDictionary<char, DateTimeOffset> All() { lock (_gate) return new Dictionary<char, DateTimeOffset>(LoadLocked()); }

    private Dictionary<char, DateTimeOffset> LoadLocked()
    {
        if (_cache is not null) return _cache;
        _cache = [];
        if (path is null || !File.Exists(path)) return _cache;
        try
        {
            var raw = JsonSerializer.Deserialize<Dictionary<string, DateTimeOffset>>(File.ReadAllText(path)) ?? [];
            foreach (var (k, v) in raw) if (k.Length == 1 && char.IsAsciiLetter(k[0])) _cache[char.ToUpperInvariant(k[0])] = v;
        }
        catch (Exception ex) { log.Info($"retrim log read: {ex.Message}"); }
        return _cache;
    }
}

/// <summary>Newest retrim per letter from Windows' event log and this app's own record.</summary>
public sealed class RetrimHistory(RetrimLog? app, IWindowsRetrimEvents? windows = null, ILogger? log = null) : IRetrimHistory
{
    /// <summary>How far back Windows' log is read.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromDays(60);

    public Task<IReadOnlyDictionary<char, RetrimRecord>> LatestAsync(CancellationToken ct = default) => Task.Run(() =>
    {
        var best = new Dictionary<char, RetrimRecord>();
        void Take(char c, DateTimeOffset when, RetrimSource src)
        {
            c = char.ToUpperInvariant(c);
            if (!best.TryGetValue(c, out var cur) || when > cur.When) best[c] = new(when, src);
        }
        if (windows is not null)
        {
            try { foreach (var (c, w) in windows.Read(Window)) Take(c, w, RetrimSource.Windows); }
            catch (Exception ex) { log.Info($"retrim events: {ex.Message}"); }
        }
        if (app is not null) foreach (var (c, w) in app.All()) Take(c, w, RetrimSource.ThisApp);
        return (IReadOnlyDictionary<char, RetrimRecord>)best;
    }, ct);
}
