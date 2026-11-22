using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using System.Xml;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>Outcome of downloading a BIOS update package to a staging path.</summary>
public sealed record BiosDownloadResult(
    bool Succeeded,
    string? FilePath = null,
    long BytesDownloaded = 0,
    string? ErrorMessage = null,
    HttpStatusCode? StatusCode = null)
{
    public static BiosDownloadResult Ok(string filePath, long bytesDownloaded) =>
        new(true, FilePath: filePath, BytesDownloaded: bytesDownloaded);

    public static BiosDownloadResult Fail(string errorMessage, HttpStatusCode? statusCode = null) =>
        new(false, ErrorMessage: errorMessage, StatusCode: statusCode);
}

/// <summary>
/// Shared redirect-safe HTTPS client, bounded <c>.part</c> streaming downloader,
/// and uniform HTTP/network failure classifier for all BIOS update providers.
/// </summary>
public static class BiosProviderHttp
{
    public const int DefaultMaxRedirects = 5;
    public const long DefaultMaxDownloadBytes = 512L * 1024 * 1024;
    public const string DefaultUserAgent = "RemotePCDiagnostics-BiosUpdater/1.0";

    private const int MaxUrlLength = 4096;
    private const int CopyBufferSize = 81920;

    /// <summary>
    /// Shared <see cref="HttpClient"/> configured with <c>AllowAutoRedirect = false</c>,
    /// pooled connection refresh, gzip/deflate decompression, and a 30-second timeout.
    /// </summary>
    public static HttpClient SharedClient { get; } = CreateSharedClient();

    /// <summary>Creates an <see cref="HttpClient"/> over a custom <see cref="HttpMessageHandler"/> (e.g., for DI or offline tests).</summary>
    public static HttpClient CreateClient(HttpMessageHandler handler, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(handler);
        var client = new HttpClient(handler, disposeHandler: false)
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(DefaultUserAgent);
        return client;
    }

    /// <summary>
    /// Sends a GET request validating both the initial URL and every HTTP <c>301/302/303/307/308</c>
    /// redirect target against <see cref="BiosPackageVerifier.IsSafeDownloadUrl"/>.
    /// </summary>
    public static async Task<HttpResponseMessage> GetFollowingAllowedRedirectsAsync(
        HttpClient client,
        string url,
        IReadOnlyList<string> allowedHostSuffixes,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead,
        CancellationToken ct = default,
        int maxRedirects = DefaultMaxRedirects,
        Action<HttpRequestMessage>? configureRequest = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentOutOfRangeException.ThrowIfNegative(maxRedirects);

        if (!TryValidateHttpsUrl(url, allowedHostSuffixes, out var current, out var initialReason))
            throw new InvalidOperationException($"Disallowed URL: {initialReason}");

        var visited = new HashSet<string>(StringComparer.Ordinal) { current.AbsoluteUri };

        for (var hop = 0; hop <= maxRedirects; hop++)
        {
            ct.ThrowIfCancellationRequested();

            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            configureRequest?.Invoke(request);

            var response = await client.SendAsync(request, completionOption, ct).ConfigureAwait(false);
            if (!IsRedirectStatusCode(response.StatusCode))
            {
                if (response.RequestMessage?.RequestUri is { } finalUri)
                {
                    if (!finalUri.IsAbsoluteUri
                        || !TryValidateHttpsUrl(finalUri.AbsoluteUri, allowedHostSuffixes, out _, out var finalReason)
                        || HasUnsafePathSegments(finalUri.AbsoluteUri)
                        || (!string.IsNullOrWhiteSpace(finalUri.OriginalString)
                            && (!TryValidateHttpsUrl(finalUri.OriginalString, allowedHostSuffixes, out _, out _)
                                || HasUnsafePathSegments(finalUri.OriginalString))))
                    {
                        response.Dispose();
                        throw new InvalidOperationException("Rejected redirect target: final response URL failed HTTPS/domain/path validation.");
                    }
                }
                else
                {
                    response.RequestMessage = new HttpRequestMessage(HttpMethod.Get, current);
                }

                return response;
            }

            string? rawNonValidated = null;
            var locationCount = 0;
            if (response.Headers.NonValidated.TryGetValues("Location", out var rawLocs))
            {
                foreach (var val in rawLocs)
                {
                    locationCount++;
                    if (locationCount > 1)
                    {
                        response.Dispose();
                        throw new InvalidOperationException("Rejected ambiguous redirect with multiple Location headers.");
                    }

                    rawNonValidated = val;
                }
            }

            if (response.Headers.TryGetValues("Location", out var parsedLocs))
            {
                var parsedCount = 0;
                foreach (var _ in parsedLocs)
                {
                    parsedCount++;
                    if (parsedCount > 1)
                    {
                        response.Dispose();
                        throw new InvalidOperationException("Rejected ambiguous redirect with multiple Location headers.");
                    }
                }
            }

            var location = response.Headers.Location;
            response.Dispose();

            if (hop == maxRedirects)
                throw new InvalidOperationException($"Exceeded maximum redirect limit ({maxRedirects}).");

            if (locationCount == 0 && location is null)
                throw new InvalidOperationException("Rejected redirect target: Redirect response is missing a Location header.");

            if (!TryResolveRedirectTarget(current, rawNonValidated, location, allowedHostSuffixes, out var nextUri, out var redirectReason))
                throw new InvalidOperationException($"Rejected redirect target: {redirectReason}");

            if (!visited.Add(nextUri.AbsoluteUri))
                throw new InvalidOperationException("Redirect loop detected.");

            current = nextUri;
        }

        throw new InvalidOperationException($"Exceeded maximum redirect limit ({maxRedirects}).");
    }

    /// <summary>
    /// Streams a verified HTTPS package into a <c>.part</c> file under <paramref name="stagingDir"/>,
    /// enforcing <paramref name="maxBytes"/> on both <c>Content-Length</c> and actual streamed bytes,
    /// reporting <see cref="BiosInstallStage.Downloading"/> progress, and atomically moving on success.
    /// </summary>
    public static async Task<BiosDownloadResult> DownloadToStagingAsync(
        HttpClient client,
        string url,
        IReadOnlyList<string> allowedHostSuffixes,
        string stagingDir,
        string defaultFileName,
        IProgress<BiosInstallProgress>? progress,
        CancellationToken ct,
        long maxBytes = DefaultMaxDownloadBytes)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);

        if (!TryValidateHttpsUrl(url, allowedHostSuffixes, out _, out var urlError))
            return BiosDownloadResult.Fail($"Download URL rejected: {urlError}");

        var createdTempDir = string.IsNullOrWhiteSpace(stagingDir);
        var rawStagingDir = createdTempDir
            ? Path.Combine(Path.GetTempPath(), $"rpd-bios-dl-{Guid.NewGuid():N}")
            : stagingDir;
        var resolvedStagingDir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rawStagingDir));

        var fileName = BiosVendorIdentity.SanitizeFileName(url, defaultFileName);
        var finalPath = Path.Combine(resolvedStagingDir, fileName);
        var partPath = $"{finalPath}.{Guid.NewGuid():N}.part";
        var createdPart = false;
        var moved = false;

        try
        {
            if (HasSymlinkOrReparseAncestorOrSelf(resolvedStagingDir) || File.Exists(resolvedStagingDir))
                return BiosDownloadResult.Fail("Staging directory or an ancestor path is an unsafe symbolic link or reparse point.");

            Directory.CreateDirectory(resolvedStagingDir);

            if (HasSymlinkOrReparseAncestorOrSelf(resolvedStagingDir))
                return BiosDownloadResult.Fail("Staging directory or an ancestor path is an unsafe symbolic link or reparse point.");

            if (IsSymlinkOrReparsePath(finalPath) || Directory.Exists(finalPath))
                return BiosDownloadResult.Fail("Target package path is an unsafe symbolic link or reparse point.");

            if (IsSymlinkOrReparsePath(partPath))
                return BiosDownloadResult.Fail("Temporary download path is an unsafe symbolic link or reparse point.");

            progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 0, $"Downloading {fileName}..."));

            using var response = await GetFollowingAllowedRedirectsAsync(
                client,
                url,
                allowedHostSuffixes,
                HttpCompletionOption.ResponseHeadersRead,
                ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return BiosDownloadResult.Fail(
                    $"Download failed with HTTP {(int)response.StatusCode} ({response.StatusCode}).",
                    response.StatusCode);

            var contentLength = response.Content.Headers.ContentLength;
            if (contentLength is > 0 && contentLength.Value > maxBytes)
                return BiosDownloadResult.Fail(
                    $"Package size ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxBytes} bytes).");

            long downloaded = 0;
            var lastPercent = 0;

            await using (var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            await using (var dest = new FileStream(partPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, CopyBufferSize, useAsync: true))
            {
                createdPart = true;
                var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
                try
                {
                    while (true)
                    {
                        var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                        if (read == 0)
                            break;

                        downloaded += read;
                        if (downloaded > maxBytes)
                            return BiosDownloadResult.Fail(
                                $"Downloaded package exceeded maximum allowed size ({maxBytes} bytes).");

                        await dest.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);

                        if (contentLength is > 0)
                        {
                            var percent = (int)Math.Clamp(downloaded * 100L / contentLength.Value, 0L, 100L);
                            if (percent > lastPercent)
                            {
                                lastPercent = percent;
                                progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, percent, $"Downloading {fileName} ({percent}%)..."));
                            }
                        }
                    }

                    await dest.FlushAsync(ct).ConfigureAwait(false);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }

            if (downloaded == 0)
                return BiosDownloadResult.Fail("Downloaded package is empty (0 bytes).");

            if (HasSymlinkOrReparseAncestorOrSelf(resolvedStagingDir) || IsSymlinkOrReparsePath(finalPath) || Directory.Exists(finalPath))
                return BiosDownloadResult.Fail("Target package path is an unsafe symbolic link or reparse point.");

            if (lastPercent < 100)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 100, $"Downloaded {fileName}."));

            File.Move(partPath, finalPath, overwrite: true);
            moved = true;
            return BiosDownloadResult.Ok(finalPath, downloaded);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return BiosDownloadResult.Fail("Package download timed out.");
        }
        catch (InvalidOperationException ex)
        {
            return BiosDownloadResult.Fail(ex.Message);
        }
        catch (HttpRequestException ex)
        {
            return BiosDownloadResult.Fail($"Network error while downloading package: {ex.Message}", ex.StatusCode);
        }
        catch (SocketException ex)
        {
            return BiosDownloadResult.Fail($"Socket error while downloading package: {ex.Message}");
        }
        catch (IOException ex)
        {
            return BiosDownloadResult.Fail($"I/O error while downloading package: {ex.Message}");
        }
        finally
        {
            if (!moved)
            {
                if (createdPart)
                    TryDeleteFile(partPath);
                if (createdTempDir)
                    TryDeleteDirectoryIfEmpty(resolvedStagingDir);
            }
        }
    }

    /// <summary>
    /// Classifies exceptions thrown while querying a vendor BIOS catalog into a uniform <see cref="BiosLatestInfo"/>.
    /// Rethrows caller-initiated cancellations.
    /// </summary>
    public static BiosLatestInfo ClassifyHttpFailure(
        string vendorId,
        string displayName,
        Exception ex,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ex);

        if (ex is OperationCanceledException oce)
        {
            var isCallerCancellation = ct.IsCancellationRequested
                || (ct == default && oce.CancellationToken.IsCancellationRequested && oce.InnerException is not TimeoutException);

            if (isCallerCancellation)
                ExceptionDispatchInfo.Capture(oce).Throw();

            return BiosLatestInfo.Offline(vendorId, $"{displayName} BIOS catalog request timed out.");
        }

        if (ex is InvalidDataException or FormatException or JsonException or XmlException)
            return BiosLatestInfo.Failed(vendorId, $"{displayName} BIOS catalog response could not be parsed: {ex.Message}");

        if (ex is HttpRequestException or SocketException or IOException)
            return BiosLatestInfo.Offline(vendorId, $"Unable to reach {displayName} BIOS catalog: {ex.Message}");

        return BiosLatestInfo.Failed(vendorId, $"{displayName} BIOS catalog check failed: {ex.Message}");
    }

    /// <summary>
    /// Classifies non-success HTTP status codes from a vendor BIOS catalog into <see cref="BiosLatestInfo"/>.
    /// </summary>
    public static BiosLatestInfo ClassifyHttpStatus(
        string vendorId,
        string displayName,
        HttpStatusCode statusCode,
        string? context = null)
    {
        var suffix = string.IsNullOrWhiteSpace(context) ? "" : $" ({context})";
        var code = (int)statusCode;

        if (statusCode == HttpStatusCode.NotFound)
            return BiosLatestInfo.Unsupported(vendorId, $"{displayName} has no BIOS catalog entry for this hardware{suffix}.");

        if (statusCode == HttpStatusCode.TooManyRequests || code is >= 500 and <= 599)
            return BiosLatestInfo.Unavailable(vendorId, $"{displayName} BIOS catalog is temporarily unavailable (HTTP {code}){suffix}.");

        return BiosLatestInfo.Failed(vendorId, $"{displayName} BIOS catalog returned HTTP {code} ({statusCode}){suffix}.");
    }

    internal static bool TryValidateHttpsUrl(
        string? url,
        IReadOnlyList<string>? allowedHostSuffixes,
        out Uri uri,
        out string error)
    {
        uri = null!;
        error = "";

        if (string.IsNullOrWhiteSpace(url))
        {
            error = "URL is empty.";
            return false;
        }

        var trimmed = url.Trim();
        if (trimmed.Length > MaxUrlLength)
        {
            error = "URL exceeds maximum allowed length.";
            return false;
        }

        foreach (var c in trimmed)
        {
            if (char.IsControl(c) || char.IsWhiteSpace(c) || c == '\\')
            {
                error = "URL contains disallowed characters.";
                return false;
            }
        }

        if (!BiosPackageVerifier.IsSafeDownloadUrl(trimmed, allowedHostSuffixes))
        {
            error = "URL must be HTTPS on an approved vendor domain.";
            return false;
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var parsed) || parsed is null)
        {
            error = "URL is not a valid absolute URI.";
            return false;
        }

        if (!string.IsNullOrEmpty(parsed.UserInfo))
        {
            error = "URL must not contain embedded user credentials.";
            return false;
        }

        if (HasUnsafePathSegments(trimmed) || HasUnsafePathSegments(parsed.AbsoluteUri))
        {
            error = "URL contains disallowed path traversal or encoded separators.";
            return false;
        }

        uri = parsed;
        return true;
    }

    private static bool TryResolveRedirectTarget(
        Uri current,
        string? rawLocation,
        Uri? location,
        IReadOnlyList<string> allowedHostSuffixes,
        out Uri nextUri,
        out string error)
    {
        nextUri = null!;
        error = "";

        var originalFromUri = location?.OriginalString?.Trim();
        var raw = !string.IsNullOrWhiteSpace(originalFromUri)
            ? originalFromUri
            : rawLocation?.Trim();

        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "Redirect response is missing a Location header.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rawLocation)
            && !IsSafeRawRedirectLocation(rawLocation.Trim(), out error))
        {
            return false;
        }

        if (!IsSafeRawRedirectLocation(raw, out error))
            return false;

        Uri? resolved;
        // On Linux, new Uri("/path", UriKind.RelativeOrAbsolute) produces an absolute file:/// URI.
        // Always treat leading '/' (not "//") as a root-relative path against the current HTTPS origin.
        if (raw.StartsWith('/'))
        {
            if (!Uri.TryCreate(raw, UriKind.Relative, out var rel) || !Uri.TryCreate(current, rel, out resolved))
            {
                error = "Unable to resolve root-relative redirect URI.";
                return false;
            }
        }
        else if (location is { IsAbsoluteUri: true })
        {
            resolved = location;
        }
        else if (Uri.TryCreate(raw, UriKind.Absolute, out var absUri))
        {
            resolved = absUri;
        }
        else if (Uri.TryCreate(raw, UriKind.Relative, out var relUri))
        {
            if (!Uri.TryCreate(current, relUri, out resolved))
            {
                error = "Unable to resolve relative redirect URI.";
                return false;
            }
        }
        else
        {
            error = "Unable to parse redirect Location header.";
            return false;
        }

        if (resolved is null)
        {
            error = "Redirect target resolved to null.";
            return false;
        }

        if (HasUnsafePathSegments(resolved.AbsoluteUri))
        {
            error = "Redirect target contains unsafe path segments.";
            return false;
        }

        return TryValidateHttpsUrl(resolved.AbsoluteUri, allowedHostSuffixes, out nextUri, out error);
    }

    private static bool IsSafeRawRedirectLocation(string candidate, out string error)
    {
        error = "";
        if (candidate.Length == 0 || candidate.Length > MaxUrlLength)
        {
            error = "Redirect Location header exceeds maximum length.";
            return false;
        }

        foreach (var c in candidate)
        {
            if (char.IsControl(c) || char.IsWhiteSpace(c) || c == '\\')
            {
                error = "Redirect Location header contains disallowed characters.";
                return false;
            }
        }

        if (candidate.StartsWith("//", StringComparison.Ordinal))
        {
            error = "Protocol-relative redirect URLs are disallowed.";
            return false;
        }

        var firstDelim = candidate.IndexOfAny(['/', '?', '#']);
        var firstSegment = firstDelim >= 0 ? candidate[..firstDelim] : candidate;
        if (firstSegment.Contains(':', StringComparison.Ordinal)
            && !candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            error = "Redirect Location header uses a disallowed scheme or non-hierarchical URI syntax.";
            return false;
        }

        if (HasUnsafeRedirectLocationPath(candidate))
        {
            error = "Redirect Location header contains disallowed path traversal or encoded separators.";
            return false;
        }

        return true;
    }

    private static bool HasUnsafeRedirectLocationPath(string rawLocation)
    {
        var queryOrFragIdx = rawLocation.IndexOfAny(['?', '#']);
        var beforeQuery = queryOrFragIdx >= 0 ? rawLocation[..queryOrFragIdx] : rawLocation;
        if (beforeQuery.IndexOf("://", StringComparison.Ordinal) >= 0)
            return HasUnsafePathSegments(rawLocation);

        var pathPart = beforeQuery.TrimStart('/');
        if (pathPart.Length == 0)
            return false;

        foreach (var seg in pathPart.Split('/'))
        {
            if (seg.Length == 0)
                continue;

            if (IsUnsafePathSegment(seg))
                return true;
        }

        return false;
    }

    internal static bool HasUnsafePathSegments(string url)
    {
        var schemeSep = url.IndexOf("://", StringComparison.Ordinal);
        if (schemeSep < 0)
            return true;

        var afterScheme = url[(schemeSep + 3)..];
        var slashIdx = afterScheme.IndexOf('/');
        if (slashIdx < 0)
            return false;

        var pathPart = afterScheme[(slashIdx + 1)..];
        var queryOrFragIdx = pathPart.IndexOfAny(['?', '#']);
        if (queryOrFragIdx >= 0)
            pathPart = pathPart[..queryOrFragIdx];

        if (pathPart.Length == 0)
            return false;

        foreach (var seg in pathPart.Split('/'))
        {
            if (seg.Length == 0)
                continue;

            if (IsUnsafePathSegment(seg))
                return true;
        }

        return false;
    }

    private static bool IsUnsafePathSegment(string segment)
    {
        var current = segment;
        for (var round = 0; round < 5; round++)
        {
            if (current is "." or ".." || current.Trim() is "." or "..")
                return true;

            if (current.Contains("%2e", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%2f", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%5c", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%00", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            for (var i = 0; i < current.Length; i++)
            {
                var c = current[i];
                if (char.IsControl(c) || c is '/' or '\\' or '?' or '#')
                    return true;

                if (c == '%')
                {
                    if (i + 2 >= current.Length
                        || !Uri.IsHexDigit(current[i + 1])
                        || !Uri.IsHexDigit(current[i + 2]))
                    {
                        return true;
                    }
                }
            }

            if (!current.Contains('%', StringComparison.Ordinal))
                return false;

            string decoded;
            try
            {
                decoded = Uri.UnescapeDataString(current);
            }
            catch
            {
                return true;
            }

            if (string.Equals(decoded, current, StringComparison.Ordinal))
                return false;

            current = decoded;
        }

        return true;
    }

    internal static bool HasSymlinkOrReparseAncestorOrSelf(string fullPath)
    {
        try
        {
            var current = Path.TrimEndingDirectorySeparator(Path.GetFullPath(fullPath));
            var visited = 0;
            while (!string.IsNullOrEmpty(current) && visited++ < 256)
            {
                if (IsSymlinkOrReparsePath(current))
                    return true;

                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent) || string.Equals(parent, current, StringComparison.Ordinal))
                    break;

                current = Path.TrimEndingDirectorySeparator(parent);
            }

            return false;
        }
        catch
        {
            return true;
        }
    }

    internal static bool IsSymlinkOrReparsePath(string path)
    {
        try
        {
            var normalized = Path.TrimEndingDirectorySeparator(path);
            var fi = new FileInfo(normalized);
            if (fi.LinkTarget is not null)
                return true;

            var di = new DirectoryInfo(normalized);
            if (di.LinkTarget is not null)
                return true;

            if (fi.Exists)
                return (fi.Attributes & FileAttributes.ReparsePoint) != 0;

            if (di.Exists)
                return (di.Attributes & FileAttributes.ReparsePoint) != 0;

            return false;
        }
        catch
        {
            return true;
        }
    }

    private static bool IsRedirectStatusCode(HttpStatusCode statusCode) => (int)statusCode is 301 or 302 or 303 or 307 or 308;

    private static HttpClient CreateSharedClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        };
        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(30),
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(DefaultUserAgent);
        return client;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Best-effort cleanup of incomplete staging file.
        }
    }

    private static void TryDeleteDirectoryIfEmpty(string dir)
    {
        try
        {
            if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                Directory.Delete(dir, recursive: false);
        }
        catch
        {
            // Best-effort cleanup of empty temporary staging directory.
        }
    }
}
