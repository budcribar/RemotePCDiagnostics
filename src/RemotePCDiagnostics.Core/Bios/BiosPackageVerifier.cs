using System.Security.Cryptography;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>Shared URL validation and SHA-256 verification helpers for vendor BIOS packages.</summary>
public static class BiosPackageVerifier
{
    /// <summary>Returns <c>true</c> only for well-formed absolute <c>https://</c> URLs (optionally restricted to allowed host suffixes).</summary>
    public static bool IsSafeDownloadUrl(string? url, IReadOnlyList<string>? allowedHostSuffixes = null)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return false;
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return false;
        if (string.IsNullOrWhiteSpace(uri.Host))
            return false;
        if (allowedHostSuffixes is { Count: > 0 })
        {
            var matched = allowedHostSuffixes.Any(suffix =>
            {
                var clean = suffix.Trim().TrimStart('.');
                return clean.Length > 0 && (
                    string.Equals(uri.Host, clean, StringComparison.OrdinalIgnoreCase)
                    || uri.Host.EndsWith("." + clean, StringComparison.OrdinalIgnoreCase));
            });
            if (!matched)
                return false;
        }
        return true;
    }

    /// <summary>Computes the lowercase hex SHA-256 digest of a downloaded package file.</summary>
    public static async Task<string> ComputeSha256HexAsync(string filePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        const int maxAttempts = 6;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await using var stream = new FileStream(
                    filePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read | FileShare.Delete,
                    64 * 1024,
                    useAsync: true);
                var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
                return Convert.ToHexString(hash).ToLowerInvariant();
            }
            catch (IOException) when (attempt < maxAttempts && File.Exists(filePath))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(25 * attempt), ct).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Verifies <paramref name="filePath"/> against an expected 64-character hex SHA-256 digest using constant-time comparison.</summary>
    public static async Task<(bool Valid, string ActualSha256)> VerifyFileSha256Async(string filePath, string expectedSha256, CancellationToken ct = default)
    {
        var actual = await ComputeSha256HexAsync(filePath, ct).ConfigureAwait(false);
        var normalized = (expectedSha256 ?? "").Trim().ToLowerInvariant();
        if (normalized.Length != 64)
            return (false, actual);
        var actualBytes = System.Text.Encoding.ASCII.GetBytes(actual);
        var expectedBytes = System.Text.Encoding.ASCII.GetBytes(normalized);
        var match = actualBytes.Length == expectedBytes.Length && CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
        return (match, actual);
    }
}
