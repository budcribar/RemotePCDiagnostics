using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Agent.Core;

/// <summary><c>manifest.json</c> of a release (docs/agent-design.md, "Manifest"). Only trusted after <see cref="ManifestSignature.Verify"/>.</summary>
public sealed class ReleaseManifest
{
    public const string ProductName = "RemotePCDiagnostics";
    public const long MaxSize = 4L * 1024 * 1024 * 1024;

    [JsonPropertyName("product")] public string Product { get; set; } = "";
    [JsonPropertyName("version")] public string Version { get; set; } = "";
    [JsonPropertyName("file")] public string File { get; set; } = "";
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("entry")] public string Entry { get; set; } = "";
    [JsonPropertyName("published")] public string? Published { get; set; }

    /// <summary>Parses and checks the manifest. Returns null and an error in plain words when anything is off.</summary>
    public static ReleaseManifest? Parse(ReadOnlySpan<byte> json, out string error)
    {
        ReleaseManifest? m;
        try { m = JsonSerializer.Deserialize(json, AgentJsonContext.Default.ReleaseManifest); }
        catch (JsonException) { error = "The release manifest isn't valid JSON."; return null; }
        if (m is null) { error = "The release manifest is empty."; return null; }
        error = Validate(m) ?? "";
        if (error.Length > 0) return null;
        m.Sha256 = m.Sha256.ToLowerInvariant();
        return m;
    }

    /// <summary>Null when the manifest is acceptable; otherwise why not.</summary>
    public static string? Validate(ReleaseManifest m)
    {
        if (m.Product != ProductName) return $"The release manifest is for '{m.Product}', not {ProductName}.";
        if (!IsSafeVersion(m.Version)) return "The release manifest has an invalid version.";
        if (!IsSafeFileName(m.File, ".zip")) return "The release manifest names an invalid download file.";
        if (!IsSafeFileName(m.Entry, ".exe")) return "The release manifest names an invalid program file.";
        if (m.Size <= 0 || m.Size > MaxSize) return "The release manifest has an invalid size.";
        if (!IsSha256Hex(m.Sha256)) return "The release manifest has an invalid SHA-256.";
        if (!ReleaseUrls.IsReleaseDownloadUrl(m.Url)) return "The release manifest points outside the RemotePCDiagnostics GitHub releases.";
        if (!new Uri(m.Url).AbsolutePath.EndsWith("/" + m.File, StringComparison.Ordinal)) return "The release manifest's url doesn't match its file name.";
        return null;
    }

    /// <summary>A version that's also a safe folder name: digits and dots (2 to 4 parts), optionally -/+ and a [0-9A-Za-z.-] suffix, at most 64 characters,
    /// ending with a letter or digit.</summary>
    public static bool IsSafeVersion(string? v)
    {
        if (string.IsNullOrEmpty(v) || v.Length > 64 || !char.IsAsciiLetterOrDigit(v[^1])) return false;
        var i = 0;
        var parts = 0;
        while (true)
        {
            var start = i;
            while (i < v.Length && char.IsAsciiDigit(v[i])) i++;
            if (i == start) return false;
            parts++;
            if (i < v.Length && v[i] == '.') { i++; continue; }
            break;
        }
        if (parts < 2 || parts > 4) return false;
        if (i == v.Length) return true;
        if (v[i] != '-' && v[i] != '+') return false;
        i++;
        if (i == v.Length) return false;
        for (; i < v.Length; i++)
            if (!(char.IsAsciiLetterOrDigit(v[i]) || v[i] is '.' or '-' or '+')) return false;
        return !v.Contains("..", StringComparison.Ordinal);
    }

    /// <summary>A plain file name (no folders) made of [0-9A-Za-z._-], with the given extension.</summary>
    public static bool IsSafeFileName(string? name, string extension)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 100 || name.Length <= extension.Length) return false;
        if (!name.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) return false;
        if (name[0] == '.' || name.Contains("..", StringComparison.Ordinal)) return false;
        foreach (var ch in name)
            if (!(char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-' or '_')) return false;
        return true;
    }

    public static bool IsSha256Hex(string? s) => s is { Length: 64 } && s.All(char.IsAsciiHexDigit);
}
