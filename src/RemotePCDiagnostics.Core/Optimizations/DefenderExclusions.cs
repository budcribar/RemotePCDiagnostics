using System.Text.Json;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>Reads Defender's status and exclusions (the Developer setup check and the build benchmark's temporary exclusion use it).</summary>
public static class DefenderProbe
{
    public sealed record Status(bool Active, IReadOnlyList<string> Paths, IReadOnlyList<string> Processes, bool ExclusionsReadable);

    /// <summary>Null when the output can't be read. Non-admin reads return "N/A: Must be an administrator…" instead of the lists.</summary>
    public static Status? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            var on = r.TryGetProperty("On", out var o) && string.Equals(o.GetString(), "True", StringComparison.OrdinalIgnoreCase);
            var mode = r.TryGetProperty("Mode", out var m) ? m.GetString() : null;
            // "Normal" = Defender is the active antivirus; "Passive Mode" / "EDR Block Mode" = another antivirus is.
            var active = on && (string.IsNullOrEmpty(mode) || mode.Equals("Normal", StringComparison.OrdinalIgnoreCase));
            var paths = Strings(r, "Paths");
            var procs = Strings(r, "Procs");
            var readable = !paths.Concat(procs).Any(x => x.StartsWith("N/A", StringComparison.OrdinalIgnoreCase));
            return new(active, readable ? paths : [], readable ? procs : [], readable);
        }
        catch (JsonException) { return null; }
    }

    private static List<string> Strings(JsonElement r, string name)
    {
        if (!r.TryGetProperty(name, out var e)) return [];
        if (e.ValueKind == JsonValueKind.String) return e.GetString() is { Length: > 0 } one ? [one] : [];
        if (e.ValueKind != JsonValueKind.Array) return [];
        return e.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).Where(x => x.Length > 0).ToList();
    }

    /// <summary>An existing exclusion covers a folder when it is that folder or a parent of it (C:\src and C:\src\* both cover C:\src\app).</summary>
    public static bool Covers(string existing, string folder)
    {
        var e = Normalize(existing);
        if (e.EndsWith("\\*", StringComparison.Ordinal)) e = e[..^2];
        if (e.Contains('*') || e.Contains('?')) return false; // other wildcards: don't guess
        var f = Normalize(folder);
        return f.Equals(e, StringComparison.OrdinalIgnoreCase) || f.StartsWith(e + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string p) => Environment.ExpandEnvironmentVariables(p.Trim().Trim('"')).Replace('/', '\\').TrimEnd('\\');
}
