using System.Text.Json;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Persists user-ignored file paths for the Top Large Files scan so ignored files are filtered out
/// immediately in the UI and skipped in subsequent scans until unignored.
/// </summary>
public sealed class LargeFileIgnoreStore
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
    private readonly object _gate = new();
    private readonly string _filePath;
    private HashSet<string>? _cache;

    public static LargeFileIgnoreStore Default { get; } = new(DefaultStorePath());

    public LargeFileIgnoreStore(string filePath)
    {
        _filePath = filePath;
    }

    private static string DefaultStorePath()
    {
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(baseDir))
            baseDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(baseDir))
            baseDir = AppContext.BaseDirectory;
        return Path.Combine(baseDir, "RemotePCDiagnostics", "ignored-large-files.json");
    }

    public IReadOnlySet<string> GetIgnoredPaths()
    {
        lock (_gate)
        {
            return new HashSet<string>(LoadUnlocked(), StringComparer.OrdinalIgnoreCase);
        }
    }

    public bool IsIgnored(string? fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return false;
        lock (_gate)
        {
            return LoadUnlocked().Contains(Normalize(fullPath));
        }
    }

    public void Ignore(string fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return;
        lock (_gate)
        {
            var set = LoadUnlocked();
            if (set.Add(Normalize(fullPath)))
                SaveUnlocked(set);
        }
    }

    public void Unignore(string fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return;
        lock (_gate)
        {
            var set = LoadUnlocked();
            if (set.Remove(Normalize(fullPath)))
                SaveUnlocked(set);
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            var set = LoadUnlocked();
            if (set.Count > 0)
            {
                set.Clear();
                SaveUnlocked(set);
            }
        }
    }

    private static string Normalize(string path) => path.Trim();

    private HashSet<string> LoadUnlocked()
    {
        if (_cache is not null) return _cache;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (File.Exists(_filePath))
            {
                var json = File.ReadAllText(_filePath);
                var items = JsonSerializer.Deserialize<List<string>>(json);
                if (items is not null)
                {
                    foreach (var p in items)
                    {
                        if (!string.IsNullOrWhiteSpace(p))
                            set.Add(Normalize(p));
                    }
                }
            }
        }
        catch { }
        _cache = set;
        return set;
    }

    private void SaveUnlocked(HashSet<string> set)
    {
        try
        {
            var dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            var ordered = set.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
            File.WriteAllText(_filePath, JsonSerializer.Serialize(ordered, JsonOpts));
        }
        catch { }
    }
}
