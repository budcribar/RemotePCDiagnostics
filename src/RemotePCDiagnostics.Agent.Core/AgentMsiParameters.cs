using System.Buffers.Text;
using System.Text;

namespace RemotePCDiagnostics.Agent.Core;

public sealed record AgentMsiMetadata(
    string Server,
    string Key,
    ConsentCeiling Consent,
    AgentLifetime Lifetime);

/// <summary>
/// Encodes and parses per-download enrollment parameters in an <c>.msi</c> file name so the
/// MSI binary itself stays byte-identical and Authenticode-signable (SignPath compatible).
/// <para>
/// Format: <c>RemotePCDiagnostics-Agent.{mode}.{key}[.h.{base64url(server)}].pkg.msi</c>,
/// where <c>{mode}</c> is <c>as</c> (ask+session), <c>ap</c> (ask+persistent),
/// <c>us</c> (unattended+session), or <c>up</c> (unattended+persistent).
/// Browser duplicate suffixes placed after <c>.pkg</c> (such as <c>.pkg (1).msi</c> or <c>.pkg-2.msi</c>)
/// are ignored automatically.
/// </para>
/// </summary>
public static class AgentMsiParameters
{
    public const string FilePrefix = "RemotePCDiagnostics-Agent.";
    public const string PackageMarker = ".pkg";

    public static string FormatFileName(
        string server,
        string key,
        ConsentCeiling consent,
        AgentLifetime lifetime)
    {
        if (!AgentCommandLine.TryNormalizeServer(server, out var normalizedServer))
            throw new ArgumentException($"Invalid relay server URL '{server}'.", nameof(server));

        key = (key ?? "").Trim();
        if (!IsSafeToken(key))
            throw new ArgumentException("Enrollment key must contain only URL-safe token characters [A-Za-z0-9_-].", nameof(key));

        var mode = (consent, lifetime) switch
        {
            (ConsentCeiling.Ask, AgentLifetime.Session) => "as",
            (ConsentCeiling.Ask, AgentLifetime.Persistent) => "ap",
            (ConsentCeiling.Unattended, AgentLifetime.Session) => "us",
            (ConsentCeiling.Unattended, AgentLifetime.Persistent) => "up",
            _ => "ap",
        };

        if (string.Equals(normalizedServer, AgentCommandLine.DefaultServer, StringComparison.OrdinalIgnoreCase))
            return $"{FilePrefix}{mode}.{key}{PackageMarker}.msi";

        var encodedServer = Base64UrlEncodeUtf8(normalizedServer);
        return $"{FilePrefix}{mode}.{key}.h.{encodedServer}{PackageMarker}.msi";
    }

    /// <summary>
    /// Extracts tokenized enrollment metadata from <paramref name="msiPath"/> when present.
    /// Returns <c>true</c> with <paramref name="metadata"/> = <c>null</c> when <paramref name="msiPath"/> is a plain,
    /// untokenized MSI name (such as <c>RemotePCDiagnostics.Agent-1.2.0-win-x64.msi</c>).
    /// Returns <c>false</c> with <paramref name="error"/> when a tokenized <c>RemotePCDiagnostics-Agent.*.msi</c>
    /// file name is malformed.
    /// </summary>
    public static bool TryParseFileName(string? msiPath, out AgentMsiMetadata? metadata, out string? error)
    {
        metadata = null;
        error = null;

        if (string.IsNullOrWhiteSpace(msiPath))
        {
            error = "--from-msi requires a path to the .msi database.";
            return false;
        }

        var fileName = ExtractFileNameCrossPlatform(msiPath.Trim().Trim('"'));
        if (!fileName.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
        {
            error = $"--from-msi path '{fileName}' does not end with .msi.";
            return false;
        }

        var stem = fileName[..^4].Trim();
        if (!stem.StartsWith(FilePrefix, StringComparison.OrdinalIgnoreCase))
        {
            // Plain static MSI (e.g., RemotePCDiagnostics.Agent-1.2.0-win-x64.msi): allow CLI properties or upgrade config.
            return true;
        }

        var pkgIdx = stem.LastIndexOf(PackageMarker, StringComparison.OrdinalIgnoreCase);
        if (pkgIdx <= FilePrefix.Length)
        {
            error = $"Tokenized MSI filename '{fileName}' is missing the '{PackageMarker}.msi' marker.";
            return false;
        }

        var payload = stem[FilePrefix.Length..pkgIdx];
        var parts = payload.Split('.');
        if (parts.Length is not (2 or 4))
        {
            error = $"Tokenized MSI filename '{fileName}' has an unexpected field count.";
            return false;
        }

        if (!TryParseMode(parts[0], out var consent, out var lifetime))
        {
            error = $"Tokenized MSI filename '{fileName}' has invalid mode '{parts[0]}'.";
            return false;
        }

        var key = parts[1].Trim();
        if (!IsSafeToken(key))
        {
            error = $"Tokenized MSI filename '{fileName}' has an invalid enrollment key token.";
            return false;
        }

        var server = AgentCommandLine.DefaultServer;
        if (parts.Length == 4)
        {
            if (!string.Equals(parts[2], "h", StringComparison.OrdinalIgnoreCase)
                || !TryBase64UrlDecodeUtf8(parts[3], out var decodedServer)
                || !AgentCommandLine.TryNormalizeServer(decodedServer, out server))
            {
                error = $"Tokenized MSI filename '{fileName}' has an invalid relay server tag.";
                return false;
            }
        }

        metadata = new AgentMsiMetadata(server, key, consent, lifetime);
        return true;
    }

    private static string ExtractFileNameCrossPlatform(string path)
    {
        var slash = Math.Max(path.LastIndexOf('/'), path.LastIndexOf('\\'));
        return slash >= 0 ? path[(slash + 1)..] : path;
    }

    private static bool TryParseMode(string mode, out ConsentCeiling consent, out AgentLifetime lifetime)
    {
        switch (mode.ToLowerInvariant())
        {
            case "as":
                consent = ConsentCeiling.Ask;
                lifetime = AgentLifetime.Session;
                return true;
            case "ap":
                consent = ConsentCeiling.Ask;
                lifetime = AgentLifetime.Persistent;
                return true;
            case "us":
                consent = ConsentCeiling.Unattended;
                lifetime = AgentLifetime.Session;
                return true;
            case "up":
                consent = ConsentCeiling.Unattended;
                lifetime = AgentLifetime.Persistent;
                return true;
            default:
                consent = ConsentCeiling.Ask;
                lifetime = AgentLifetime.Persistent;
                return false;
        }
    }

    private static bool IsSafeToken(string value) =>
        value.Length is >= 1 and <= 256
        && value.All(ch => (ch is >= 'a' and <= 'z') || (ch is >= 'A' and <= 'Z') || (ch is >= '0' and <= '9') || ch is '_' or '-');

    public static string Base64UrlEncodeUtf8(string value) =>
        Base64Url.EncodeToString(Encoding.UTF8.GetBytes(value));

    public static bool TryBase64UrlDecodeUtf8(string encoded, out string decoded)
    {
        decoded = "";
        if (string.IsNullOrWhiteSpace(encoded) || encoded.Length > 512)
            return false;

        try
        {
            var bytes = Base64Url.DecodeFromChars(encoded);
            decoded = Encoding.UTF8.GetString(bytes);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
