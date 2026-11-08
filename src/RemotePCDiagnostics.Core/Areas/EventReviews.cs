using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Local review state for individual Windows event occurrences.</summary>
public static class EventReviews
{
    private static readonly object Gate = new();
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RemotePCDiagnostics", "reviewed-events.json");

    public static string Key(WinEvent e) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{Environment.MachineName}\n{e.Channel}\n{e.Provider}\n{e.EventId}\n{e.Time.UtcTicks}\n{e.Message}\n{string.Join("\n", e.Data)}")));

    public static HashSet<string> Read()
    {
        lock (Gate)
        {
            try { return JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(FilePath)) ?? []; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { return []; }
        }
    }

    public static async Task<IReadOnlyCollection<string>> ReadAsync(Plugins.IHostQueries? host, CancellationToken ct = default)
    {
        if (host is null) return Read();
        try { return await host.ReadEventReviewsAsync(ct).ConfigureAwait(false); }
        catch (Plugins.HostQueryException) { return []; }
    }


    public static void Set(IReadOnlyList<string> keys, bool reviewed)
    {
        lock (Gate)
        {
            var state = Read();
            if (reviewed) state.UnionWith(keys);
            else state.ExceptWith(keys);
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            var temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(state));
            File.Move(temp, FilePath, overwrite: true);
        }
    }
}
