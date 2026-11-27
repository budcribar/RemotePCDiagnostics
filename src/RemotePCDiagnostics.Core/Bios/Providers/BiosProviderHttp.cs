using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using System.Xml;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

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
    private sealed class PathGate
    {
        public SemaphoreSlim Semaphore { get; } = new(1, 1);
        public int RefCount;
    }

    private static readonly Lock StagingPathGatesLock = new();
    private static readonly Dictionary<string, PathGate> StagingPathGates = new(StringComparer.OrdinalIgnoreCase);

    private static async Task<IDisposable> AcquireStagingPathGateAsync(string finalPath, CancellationToken ct)
    {
        var key = Path.GetFullPath(finalPath);
        PathGate gate;
        lock (StagingPathGatesLock)
        {
            if (!StagingPathGates.TryGetValue(key, out gate!))
            {
                gate = new PathGate();
                StagingPathGates[key] = gate;
            }
            gate.RefCount++;
        }

        try
        {
            await gate.Semaphore.WaitAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            ReleaseStagingPathGate(key, gate, acquired: false);
            throw;
        }

        return new StagingPathGateReleaser(key, gate);
    }

    private static void ReleaseStagingPathGate(string key, PathGate gate, bool acquired)
    {
        if (acquired)
            gate.Semaphore.Release();

        bool dispose;
        lock (StagingPathGatesLock)
        {
            gate.RefCount--;
            dispose = gate.RefCount == 0 && StagingPathGates.TryGetValue(key, out var current) && ReferenceEquals(current, gate);
            if (dispose)
                StagingPathGates.Remove(key);
        }

        if (dispose)
            gate.Semaphore.Dispose();
    }

    private sealed class StagingPathGateReleaser(string key, PathGate gate) : IDisposable
    {
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                ReleaseStagingPathGate(key, gate, acquired: true);
        }
    }

    /// <summary>
    /// Moves a finished download into place. Serializes per <paramref name="finalPath"/> so two concurrent downloads of the same
    /// package do not overwrite <paramref name="finalPath"/> while the first caller is hashing or launching it: if <paramref name="finalPath"/>
    /// already exists with the exact bytes just downloaded, it is reused as is (returns false, and the caller deletes its own .part).
    /// </summary>
    public static async Task<bool> MoveIntoPlaceOrReuseIdenticalAsync(string partPath, string finalPath, CancellationToken ct)
    {
        using var _ = await AcquireStagingPathGateAsync(finalPath, ct).ConfigureAwait(false);

        if (IsSymlinkOrReparsePath(finalPath))
            throw new IOException("Target package path is an unsafe symbolic link or reparse point.");

        if (File.Exists(finalPath))
        {
            try
            {
                var ours = await BiosPackageVerifier.ComputeSha256HexAsync(partPath, ct).ConfigureAwait(false);
                var theirs = await BiosPackageVerifier.ComputeSha256HexAsync(finalPath, ct).ConfigureAwait(false);
                if (string.Equals(ours, theirs, StringComparison.Ordinal))
                    return false;
            }
            catch (IOException)
            {
                // Fall through to the move + retry path if finalPath disappeared or was busy.
            }
        }

        // An external process (e.g., AV scanner or another process) can still briefly hold finalPath on Windows,
        // so retry a few times before giving up.
        const int attempts = 8;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(partPath, finalPath, overwrite: true);
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (IsSymlinkOrReparsePath(finalPath))
                    throw;
                if (!File.Exists(finalPath))
                {
                    if (attempt >= attempts) throw;
                }
                else
                {
                    bool? identical;
                    try
                    {
                        var ours = await BiosPackageVerifier.ComputeSha256HexAsync(partPath, ct).ConfigureAwait(false);
                        var theirs = await BiosPackageVerifier.ComputeSha256HexAsync(finalPath, ct).ConfigureAwait(false);
                        identical = string.Equals(ours, theirs, StringComparison.Ordinal);
                    }
                    catch (IOException) when (attempt < attempts)
                    {
                        identical = null; // the file is busy: wait and try the move again
                    }
                    if (identical == false) throw;
                    if (identical == true) return false;
                    if (attempt >= attempts) throw;
                }
            }
            await Task.Delay(TimeSpan.FromMilliseconds(50 * attempt), ct).ConfigureAwait(false);
        }
    }

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

            var copy = await CopyResponseToPartFileAsync(
                response.Content, partPath, fileName, contentLength, maxBytes, progress, ct).ConfigureAwait(false);
            createdPart = copy.CreatedPart;
            if (!copy.Succeeded)
                return BiosDownloadResult.Fail(copy.ErrorMessage!);

            var downloaded = copy.DownloadedBytes;
            var lastPercent = copy.LastPercent;

            if (HasSymlinkOrReparseAncestorOrSelf(resolvedStagingDir) || IsSymlinkOrReparsePath(finalPath) || Directory.Exists(finalPath))
                return BiosDownloadResult.Fail("Target package path is an unsafe symbolic link or reparse point.");

            if (lastPercent < 100)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 100, $"Downloaded {fileName}."));

            moved = await MoveIntoPlaceOrReuseIdenticalAsync(partPath, finalPath, ct).ConfigureAwait(false);
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

        if (HasUnsafePathSegments(resolved.AbsoluteUri))
        {
            error = "Redirect target contains unsafe path segments.";
            return false;
        }

        return TryValidateHttpsUrl(resolved.AbsoluteUri, allowedHostSuffixes, out nextUri, out error);
    }

    internal static bool TryValidateVendorUrl(string? rawUrl, IReadOnlyList<string> allowedHostSuffixes, out Uri uri)
    {
        uri = null!;
        if (string.IsNullOrWhiteSpace(rawUrl))
            return false;

        var trimmed = rawUrl.Trim();
        if (trimmed.StartsWith("//", StringComparison.Ordinal))
            return false;

        if (!TryValidateHttpsUrl(trimmed, allowedHostSuffixes, out var parsed, out _))
            return false;

        if (HasUnsafePathSegments(trimmed, rejectAtSign: true))
            return false;

        uri = parsed;
        return true;
    }

    internal static async Task<HttpResponseMessage> GetVendorUrlWithSafeRedirectsAsync(
        HttpClient httpClient,
        string initialUrl,
        IReadOnlyList<string> allowedHostSuffixes,
        string vendorLabel,
        string? acceptHeader,
        CancellationToken ct,
        int maxRedirects = DefaultMaxRedirects,
        string? disallowedUrlMessage = null,
        Action<Uri, bool>? validateUri = null)
    {
        if (!TryValidateVendorUrl(initialUrl, allowedHostSuffixes, out var current))
            throw new InvalidOperationException(disallowedUrlMessage ?? $"Disallowed {vendorLabel} catalog URL.");

        validateUri?.Invoke(current, false);

        var visited = new HashSet<string>(StringComparer.Ordinal) { current.AbsoluteUri };

        for (var hop = 0; hop <= maxRedirects; hop++)
        {
            ct.ThrowIfCancellationRequested();

            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            if (!string.IsNullOrWhiteSpace(acceptHeader))
                request.Headers.Accept.ParseAdd(acceptHeader);

            var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!IsRedirectStatusCode(response.StatusCode))
            {
                var effectiveUri = current;
                if (response.RequestMessage?.RequestUri is { } finalUri)
                {
                    if (!finalUri.IsAbsoluteUri
                        || !TryValidateVendorUrl(finalUri.AbsoluteUri, allowedHostSuffixes, out var validatedFinal)
                        || (!string.IsNullOrWhiteSpace(finalUri.OriginalString)
                            && !TryValidateVendorUrl(finalUri.OriginalString, allowedHostSuffixes, out _)))
                    {
                        response.Dispose();
                        throw new InvalidOperationException("Rejected redirect target: final response URL failed vendor HTTPS/domain/path validation.");
                    }

                    effectiveUri = validatedFinal;
                }

                if (validateUri is not null)
                {
                    try
                    {
                        validateUri(effectiveUri, true);
                    }
                    catch
                    {
                        response.Dispose();
                        throw;
                    }
                }

                return response;
            }

            string? rawNonValidated = null;
            if (response.Headers.NonValidated.TryGetValues("Location", out var rawLocs))
            {
                var count = 0;
                foreach (var val in rawLocs)
                {
                    count++;
                    if (count > 1)
                    {
                        response.Dispose();
                        throw new InvalidOperationException("Rejected ambiguous redirect with multiple Location headers.");
                    }

                    rawNonValidated = val;
                }
            }

            var locationUri = response.Headers.Location;
            response.Dispose();

            if (hop == maxRedirects)
                throw new InvalidOperationException($"Exceeded maximum redirect limit ({maxRedirects}).");

            if (!TryResolveSafeVendorRedirectTarget(current, rawNonValidated, locationUri, allowedHostSuffixes, out var nextUri))
                throw new InvalidOperationException("Rejected redirect target: failed vendor HTTPS/domain/path validation.");

            validateUri?.Invoke(nextUri, true);

            if (!visited.Add(nextUri.AbsoluteUri))
                throw new InvalidOperationException("Redirect loop detected.");

            current = nextUri;
        }

        throw new InvalidOperationException($"Exceeded maximum redirect limit ({maxRedirects}).");
    }

    internal static bool ValidateStagingDirectorySafe(string stagingDir, out string error)
    {
        error = "";
        try
        {
            var fullStaging = Path.TrimEndingDirectorySeparator(Path.GetFullPath(stagingDir));
            if (string.IsNullOrWhiteSpace(fullStaging))
            {
                error = "Staging directory path is invalid.";
                return false;
            }

            if (IsSymlinkOrReparsePath(fullStaging))
            {
                error = "Staging directory is a symbolic link or reparse point.";
                return false;
            }

            if (HasSymlinkOrReparseAncestorOrSelf(fullStaging))
            {
                error = "Staging directory has a symbolic link or reparse point ancestor.";
                return false;
            }

            if (File.Exists(fullStaging))
            {
                error = "Staging directory path collides with an existing file.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = $"Staging directory path is invalid: {ex.Message}";
            return false;
        }
    }

    internal static async Task<BiosVerifiedPackageResult> DownloadAndVerifyVendorPackageAsync(
        string vendorId,
        IBiosSignatureVerifier signatureVerifier,
        Func<string, CancellationToken, Task<HttpResponseMessage>> getPackageAsync,
        BiosInstallRequest request,
        string stagingDir,
        string fileName,
        IProgress<BiosInstallProgress>? progress,
        ILogger? log,
        CancellationToken ct,
        long maxBytes = DefaultMaxDownloadBytes)
    {
        var downloadUrl = request.Target.DownloadUrl!;
        var finalPath = Path.Combine(stagingDir, fileName);
        var partPath = $"{finalPath}.{Guid.NewGuid():N}.part";
        var createdPart = false;
        var moved = false;
        var keepFile = false;

        try
        {
            if (IsSymlinkOrReparsePath(stagingDir)
                || HasSymlinkOrReparseAncestorOrSelf(stagingDir)
                || File.Exists(stagingDir)
                || IsSymlinkOrReparsePath(finalPath)
                || Directory.Exists(finalPath)
                || IsSymlinkOrReparsePath(partPath))
            {
                const string symMsg = "Staging directory or target package file is a symbolic link, reparse point, or conflicting directory.";
                log?.Warn($"[{vendorId}] {symMsg}");
                return BiosVerifiedPackageResult.Fail(symMsg);
            }

            Directory.CreateDirectory(stagingDir);

            if (IsSymlinkOrReparsePath(stagingDir)
                || HasSymlinkOrReparseAncestorOrSelf(stagingDir)
                || IsSymlinkOrReparsePath(finalPath)
                || Directory.Exists(finalPath)
                || IsSymlinkOrReparsePath(partPath))
            {
                const string symMsg = "Staging directory or target package file became a symbolic link, reparse point, or conflicting directory.";
                log?.Warn($"[{vendorId}] {symMsg}");
                return BiosVerifiedPackageResult.Fail(symMsg);
            }

            progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 0, $"Downloading {fileName}..."));

            using var response = await getPackageAsync(downloadUrl, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var err = $"Download failed with HTTP {(int)response.StatusCode} ({response.StatusCode}).";
                log?.Warn($"[{vendorId}] BIOS package download failed: {err}");
                return BiosVerifiedPackageResult.Fail(err);
            }

            var contentLength = response.Content.Headers.ContentLength;
            if (contentLength is > 0 && contentLength.Value > maxBytes)
            {
                var err = $"Package size ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxBytes} bytes).";
                log?.Warn($"[{vendorId}] BIOS package download failed: {err}");
                return BiosVerifiedPackageResult.Fail(err);
            }

            if (IsSymlinkOrReparsePath(stagingDir)
                || HasSymlinkOrReparseAncestorOrSelf(stagingDir)
                || IsSymlinkOrReparsePath(finalPath)
                || Directory.Exists(finalPath)
                || IsSymlinkOrReparsePath(partPath))
            {
                const string symMsg = "Target package file or .part path is a symbolic link, reparse point, or conflicting directory.";
                log?.Warn($"[{vendorId}] {symMsg}");
                return BiosVerifiedPackageResult.Fail(symMsg);
            }

            var copy = await CopyResponseToPartFileAsync(
                response.Content, partPath, fileName, contentLength, maxBytes, progress, ct).ConfigureAwait(false);
            createdPart = copy.CreatedPart;
            if (!copy.Succeeded)
            {
                log?.Warn($"[{vendorId}] BIOS package download failed: {copy.ErrorMessage}");
                return BiosVerifiedPackageResult.Fail(copy.ErrorMessage!);
            }

            var downloaded = copy.DownloadedBytes;
            var lastPercent = copy.LastPercent;

            if (IsSymlinkOrReparsePath(stagingDir)
                || HasSymlinkOrReparseAncestorOrSelf(stagingDir)
                || IsSymlinkOrReparsePath(finalPath)
                || Directory.Exists(finalPath)
                || IsSymlinkOrReparsePath(partPath))
            {
                const string symMsg = "Target package file or .part path became a symbolic link, reparse point, or conflicting directory.";
                log?.Warn($"[{vendorId}] {symMsg}");
                return BiosVerifiedPackageResult.Fail(symMsg);
            }

            if (lastPercent < 100)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 100, $"Downloaded {fileName}."));

            moved = await MoveIntoPlaceOrReuseIdenticalAsync(partPath, finalPath, ct).ConfigureAwait(false);

            if (request.VerifyHash && !string.IsNullOrWhiteSpace(request.Target.Sha256))
            {
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 0, "Verifying package SHA-256 digest..."));

                var (valid, actual) = await BiosPackageVerifier.VerifyFileSha256Async(
                    finalPath,
                    request.Target.Sha256,
                    ct).ConfigureAwait(false);

                if (!valid)
                {
                    log?.Warn($"[{vendorId}] BIOS package SHA-256 mismatch (actual={actual}). Deleting unverified file.");
                    return BiosVerifiedPackageResult.Fail("Downloaded BIOS package failed SHA-256 verification.", actual);
                }

                keepFile = true;
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 100, "Package SHA-256 verified."));
                return BiosVerifiedPackageResult.Ok(
                    finalPath,
                    downloaded,
                    actualSha256: actual,
                    verifiedBySha256: true);
            }

            progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 0, "Verifying package Authenticode signature..."));

            var allowedSigners = BiosAgentInstallModes.AllowedSignerOrganizationsForVendor(vendorId);
            var signed = allowedSigners.Count > 0
                && await signatureVerifier.VerifyAuthenticodeAsync(finalPath, allowedSigners, ct).ConfigureAwait(false);
            if (!signed)
            {
                log?.Warn($"[{vendorId}] BIOS package failed Authenticode signature verification. Deleting unverified file.");
                return BiosVerifiedPackageResult.Fail("Downloaded BIOS package failed Authenticode signature verification.");
            }

            keepFile = true;
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 100, "Package Authenticode signature verified."));
            return BiosVerifiedPackageResult.Ok(
                finalPath,
                downloaded,
                verifiedByAuthenticode: true);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            const string err = "Package download timed out.";
            log?.Warn($"[{vendorId}] BIOS package download failed: {err}");
            return BiosVerifiedPackageResult.Fail(err);
        }
        catch (InvalidOperationException ex)
        {
            log?.Warn($"[{vendorId}] BIOS package download failed: {ex.Message}");
            return BiosVerifiedPackageResult.Fail(ex.Message);
        }
        catch (HttpRequestException ex)
        {
            var err = $"Network error while downloading package: {ex.Message}";
            log?.Warn($"[{vendorId}] BIOS package download failed: {err}");
            return BiosVerifiedPackageResult.Fail(err);
        }
        catch (SocketException ex)
        {
            var err = $"Socket error while downloading package: {ex.Message}";
            log?.Warn($"[{vendorId}] BIOS package download failed: {err}");
            return BiosVerifiedPackageResult.Fail(err);
        }
        catch (IOException ex)
        {
            var err = $"I/O error while downloading package: {ex.Message}";
            log?.Warn($"[{vendorId}] BIOS package download failed: {err}");
            return BiosVerifiedPackageResult.Fail(err);
        }
        finally
        {
            if (createdPart && !moved)
                TryDeleteFile(partPath);
            if (moved && !keepFile)
                TryDeleteFile(finalPath);
        }
    }

    internal static bool TryResolveSafeVendorRedirectTarget(
        Uri current,
        string? rawLocation,
        Uri? locationUri,
        IReadOnlyList<string> allowedHostSuffixes,
        out Uri nextUri)
    {
        nextUri = null!;
        var originalFromUri = locationUri?.OriginalString?.Trim();
        var raw = !string.IsNullOrWhiteSpace(originalFromUri)
            ? originalFromUri
            : rawLocation?.Trim();
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > MaxUrlLength)
            return false;

        if (!string.IsNullOrWhiteSpace(rawLocation)
            && !IsSafeRawRedirectLocation(rawLocation.Trim(), out _, rejectAtSign: true))
        {
            return false;
        }

        if (!IsSafeRawRedirectLocation(raw, out _, rejectAtSign: true))
            return false;

        Uri? resolved;
        if (raw.StartsWith('/'))
        {
            if (!Uri.TryCreate(raw, UriKind.Relative, out var rel) || !Uri.TryCreate(current, rel, out resolved))
                return false;
        }
        else if (locationUri is { IsAbsoluteUri: true })
        {
            resolved = locationUri;
        }
        else if (Uri.TryCreate(raw, UriKind.Absolute, out var absUri))
        {
            resolved = absUri;
        }
        else if (Uri.TryCreate(raw, UriKind.Relative, out var relUri))
        {
            if (!Uri.TryCreate(current, relUri, out resolved))
                return false;
        }
        else
        {
            return false;
        }

        return TryValidateVendorUrl(resolved.AbsoluteUri, allowedHostSuffixes, out nextUri);
    }

    internal static async Task<byte[]> ReadBoundedBytesAsync(
        HttpContent content,
        long maxBytes,
        string label,
        CancellationToken ct,
        int maxInitialCapacity = 256 * 1024)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > maxBytes)
            throw new InvalidDataException($"{label} ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxBytes} bytes).");

        var initialCap = contentLength is > 0
            ? (int)Math.Min(contentLength.Value, maxInitialCapacity)
            : 4096;

        using var ms = new MemoryStream(initialCap);
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        long totalRead = 0;

        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (read == 0)
                    break;

                totalRead += read;
                if (totalRead > maxBytes)
                    throw new InvalidDataException($"{label} exceeded maximum allowed size ({maxBytes} bytes).");

                await ms.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return ms.ToArray();
    }

    internal static async Task<JsonDocument> ReadBoundedJsonDocumentAsync(
        HttpContent content,
        long maxBytes,
        string vendorLabel,
        CancellationToken ct,
        int maxInitialCapacity = 256 * 1024)
    {
        var label = $"{vendorLabel} BIOS catalog response";
        var rawBytes = await ReadBoundedBytesAsync(content, maxBytes, label, ct, maxInitialCapacity).ConfigureAwait(false);

        if (rawBytes.Length == 0)
            throw new InvalidDataException($"{label} body is empty.");

        var offset = 0;
        var length = rawBytes.Length;

        if (length >= 3 && rawBytes[0] == 0xEF && rawBytes[1] == 0xBB && rawBytes[2] == 0xBF)
        {
            offset = 3;
            length -= 3;
        }

        var hasNonWhitespace = false;
        for (var i = offset; i < offset + length; i++)
        {
            var b = rawBytes[i];
            if (b is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'))
            {
                hasNonWhitespace = true;
                break;
            }
        }

        if (!hasNonWhitespace)
            throw new InvalidDataException($"{label} body is empty or whitespace.");

        return JsonDocument.Parse(
            new ReadOnlyMemory<byte>(rawBytes, offset, length),
            new JsonDocumentOptions
            {
                MaxDepth = 64,
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
            });
    }

    internal static bool IsSafeRawRedirectLocation(string candidate, out string error, bool rejectAtSign = false)
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

        if (HasUnsafeRedirectLocationPath(candidate, rejectAtSign))
        {
            error = "Redirect Location header contains disallowed path traversal or encoded separators.";
            return false;
        }

        return true;
    }

    internal static bool HasUnsafeRedirectLocationPath(string rawLocation, bool rejectAtSign = false)
    {
        var queryOrFragIdx = rawLocation.IndexOfAny(['?', '#']);
        var beforeQuery = queryOrFragIdx >= 0 ? rawLocation[..queryOrFragIdx] : rawLocation;
        if (beforeQuery.IndexOf("://", StringComparison.Ordinal) >= 0)
            return HasUnsafePathSegments(rawLocation, rejectAtSign);

        var pathPart = beforeQuery.TrimStart('/');
        if (pathPart.Length == 0)
            return false;

        foreach (var seg in pathPart.Split('/'))
        {
            if (seg.Length == 0)
                continue;

            if (IsUnsafePathSegment(seg, rejectAtSign))
                return true;
        }

        return false;
    }

    internal static bool HasUnsafePathSegments(string url, bool rejectAtSign = false)
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

            if (IsUnsafePathSegment(seg, rejectAtSign))
                return true;
        }

        return false;
    }

    internal static bool IsUnsafePathSegment(string segment, bool rejectAtSign = false)
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
                if (char.IsControl(c) || c is '/' or '\\' or '?' or '#' || (rejectAtSign && c == '@'))
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

    internal static void TryDeleteFile(string path)
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

    internal static void TryDeleteDirectoryIfEmpty(string dir)
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

    internal static void TryDeleteDirectoryRecursive(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch
        {
            // Best-effort cleanup of temporary staging directory.
        }
    }

    private readonly record struct StreamDownloadResult(
        bool Succeeded,
        long DownloadedBytes,
        int LastPercent,
        bool CreatedPart,
        string? ErrorMessage);

    private static async Task<StreamDownloadResult> CopyResponseToPartFileAsync(
        HttpContent content,
        string partPath,
        string fileName,
        long? contentLength,
        long maxBytes,
        IProgress<BiosInstallProgress>? progress,
        CancellationToken ct)
    {
        long downloaded = 0;
        var lastPercent = 0;
        var createdPart = false;

        try
        {
            await using var source = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            await using var dest = new FileStream(partPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, CopyBufferSize, useAsync: true);
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
                    {
                        return new StreamDownloadResult(
                            false,
                            downloaded,
                            lastPercent,
                            createdPart,
                            $"Downloaded package exceeded maximum allowed size ({maxBytes} bytes).");
                    }

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
        catch
        {
            if (createdPart)
                TryDeleteFile(partPath);
            throw;
        }

        if (downloaded == 0)
        {
            return new StreamDownloadResult(
                false,
                0,
                lastPercent,
                createdPart,
                "Downloaded package is empty (0 bytes).");
        }

        return new StreamDownloadResult(true, downloaded, lastPercent, createdPart, null);
    }

    internal static async Task<BiosLatestInfo> FetchAndEvaluateModelJsonCatalogAsync(
        HttpClient httpClient,
        string vendorId,
        string displayName,
        string catalogEndpoint,
        IReadOnlyList<string> allowedHostSuffixes,
        long maxCatalogJsonBytes,
        BiosSystemIdentity system,
        BiosCurrentInfo current,
        ILogger? log,
        Func<JsonDocument, BiosCurrentInfo, string, string?, BiosLatestInfo> evaluateCatalog,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(system);
        ArgumentNullException.ThrowIfNull(current);
        ct.ThrowIfCancellationRequested();

        if (!BiosProviderCommon.TryResolveModelIdentifier(system, out var modelToken, out var invalidReason))
        {
            log?.Warn(BiosProviderCommon.RedactText($"[BIOS/{displayName}] Unable to determine valid {displayName} model identifier: {invalidReason}", system.SerialNumber));
            return BiosProviderCommon.RedactLatestInfo(
                BiosLatestInfo.Unsupported(vendorId, $"Unable to determine a valid {displayName} model or board product identifier: {invalidReason}"),
                system.SerialNumber);
        }

        var requestUrl = BiosProviderCommon.BuildCatalogUrl(catalogEndpoint, modelToken);
        if (!TryValidateVendorUrl(requestUrl, allowedHostSuffixes, out _))
        {
            log?.Warn(BiosProviderCommon.RedactText($"[BIOS/{displayName}] Configured {displayName} catalog endpoint failed HTTPS/domain/path validation.", system.SerialNumber));
            return BiosProviderCommon.RedactLatestInfo(
                BiosLatestInfo.Failed(vendorId, $"{displayName} BIOS catalog endpoint URL failed security validation."),
                system.SerialNumber);
        }

        try
        {
            using var response = await GetVendorUrlWithSafeRedirectsAsync(
                httpClient, requestUrl, allowedHostSuffixes, displayName, "application/json", ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var statusInfo = ClassifyHttpStatus(vendorId, displayName, response.StatusCode, $"model '{modelToken}'");
                return BiosProviderCommon.RedactLatestInfo(statusInfo, system.SerialNumber);
            }

            using var doc = await ReadBoundedJsonDocumentAsync(
                response.Content, maxCatalogJsonBytes, displayName, ct).ConfigureAwait(false);
            var evaluated = evaluateCatalog(doc, current, modelToken, system.SerialNumber);
            return BiosProviderCommon.RedactLatestInfo(evaluated, system.SerialNumber);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            log?.Warn(BiosProviderCommon.RedactText($"[BIOS/{displayName}] Catalog lookup failed for '{modelToken}': {ex.Message}", system.SerialNumber));
            return BiosProviderCommon.RedactLatestInfo(
                ClassifyHttpFailure(vendorId, displayName, ex, ct),
                system.SerialNumber);
        }
    }

    internal static bool TryResolveAndValidateStagingDirectory(
        BiosInstallRequest request,
        string tempDirPrefix,
        string? serial,
        ILogger? log,
        IProgress<BiosInstallProgress>? progress,
        string? previousVersion,
        string? targetVersion,
        out BiosInstallRequest effectiveRequest,
        out string? autoStagingDir,
        out BiosInstallResult? failureResult)
    {
        autoStagingDir = null;
        effectiveRequest = request;
        failureResult = null;

        if (string.IsNullOrWhiteSpace(request.StagingDirectory))
        {
            autoStagingDir = Path.Combine(Path.GetTempPath(), $"{tempDirPrefix}-{Guid.NewGuid():N}");
            effectiveRequest = request with { StagingDirectory = autoStagingDir };
            return true;
        }

        if (!ValidateStagingDirectorySafe(request.StagingDirectory, out var stagingErr))
        {
            var safeStagingErr = BiosProviderCommon.RedactText(stagingErr, serial);
            log?.Warn(safeStagingErr);
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeStagingErr));
            failureResult = BiosInstallResult.Failed(safeStagingErr, previousVersion, targetVersion);
            return false;
        }

        return true;
    }

    internal static async Task<BiosInstallResult> DownloadVerifyAndRunExecutableInstallerAsync(
        HttpClient httpClient,
        BiosInstallRequest request,
        string vendorId,
        string displayName,
        IReadOnlyList<string> allowedHostSuffixes,
        string defaultFileName,
        IBiosSignatureVerifier signatureVerifier,
        SystemCommandRunner? commands,
        IElevatedCommandBridge? elevatedBridge,
        Func<bool>? isProcessElevated,
        ILogger? log,
        IProgress<BiosInstallProgress>? progress,
        Func<string, BiosLatestInfo, string> resolveInstallMode,
        IReadOnlySet<int> rebootSuccessExitCodes,
        TimeSpan installerTimeout,
        CancellationToken ct,
        bool reportInstallingProgress = false)
    {
        var prev = request.Current?.Version;
        var target = request.Target?.LatestVersion;

        string? autoStagingDir = null;
        var effectiveRequest = request;
        if (string.IsNullOrWhiteSpace(request.StagingDirectory))
        {
            autoStagingDir = Path.Combine(Path.GetTempPath(), $"rpd-bios-{vendorId}-{Guid.NewGuid():N}");
            effectiveRequest = request with { StagingDirectory = autoStagingDir };
        }

        try
        {
            var verified = await BiosPackageVerification.DownloadAndVerifyAsync(
                httpClient,
                effectiveRequest,
                vendorId,
                allowedHostSuffixes,
                defaultFileName,
                signatureVerifier,
                progress,
                log,
                ct).ConfigureAwait(false);

            if (!verified.Succeeded || string.IsNullOrWhiteSpace(verified.FilePath))
            {
                var err = verified.ErrorMessage ?? $"{displayName} BIOS package download or verification failed.";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, err));
                return BiosInstallResult.Failed(err, prev, target);
            }

            if (!BiosPackageVerification.TryEnsureExecutableExtension(verified.FilePath, displayName, out var packagePath, out var extError))
            {
                TryDeleteFile(verified.FilePath);
                var safeExtError = BiosInstallerRunner.RedactSerialNumber(extError, request.System?.SerialNumber);
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeExtError));
                return BiosInstallResult.Failed(safeExtError, prev, target);
            }

            var bitLocker = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
                effectiveRequest,
                commands,
                progress,
                log,
                ct,
                bridge: elevatedBridge,
                isProcessElevated: isProcessElevated).ConfigureAwait(false);

            if (bitLocker.BlocksInstall)
            {
                var msg = bitLocker.Message
                    ?? $"Administrator rights (or the elevated Agent service) are required to suspend BitLocker. {ElevationService.AdminRepairHint}";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
                return BiosInstallResult.Failed(msg, prev, target, exitCode: SystemCommandRunner.AgentFailedExitCode);
            }

            var installMode = resolveInstallMode(packagePath, request.Target!);
            var arguments = BiosAgentInstallModes.BuildArguments(installMode, request.AllowReboot);

            var expectedSha256 = !string.IsNullOrWhiteSpace(verified.ActualSha256)
                ? verified.ActualSha256
                : await BiosPackageVerifier.ComputeSha256HexAsync(packagePath, ct).ConfigureAwait(false);

            var agentRequest = new BiosAgentInstallRequest(
                VendorId: vendorId,
                InstallMode: installMode,
                PackagePath: packagePath,
                ExpectedSha256: expectedSha256,
                AllowReboot: request.AllowReboot,
                InfRelativePath: null,
                TimeoutMs: (int)installerTimeout.TotalMilliseconds);

            progress?.Report(new BiosInstallProgress(
                BiosInstallStage.Staging,
                0,
                $"Staging {displayName} BIOS update…"));
            if (reportInstallingProgress)
            {
                progress?.Report(new BiosInstallProgress(
                    BiosInstallStage.Installing,
                    50,
                    $"Running {displayName} BIOS installer ({installMode})..."));
            }

            var result = await BiosInstallerRunner.RunInstallerAsync(
                commands: commands,
                executablePath: packagePath,
                arguments: arguments,
                request: effectiveRequest,
                bitLockerSuspended: bitLocker.Suspended,
                rebootSuccessExitCodes: rebootSuccessExitCodes,
                completedSuccessExitCodes: null,
                timeout: installerTimeout,
                log: log,
                ct: ct,
                workingDirectory: Path.GetDirectoryName(packagePath),
                agentRequest: agentRequest,
                bridge: elevatedBridge,
                isProcessElevated: isProcessElevated).ConfigureAwait(false);

            if (result.Succeeded && result.RequiresReboot)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.RebootRequired, 100, result.Message));
            else if (result.Succeeded)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Completed, 100, result.Message));
            else
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, result.Message));

            return result;
        }
        finally
        {
            if (autoStagingDir is not null)
                TryDeleteDirectoryRecursive(autoStagingDir);
        }
    }
}
