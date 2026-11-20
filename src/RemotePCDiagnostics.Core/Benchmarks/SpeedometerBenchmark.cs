using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>An installed Chromium-family browser that RPCD can drive via CDP for Speedometer 3.</summary>
public sealed record SpeedometerBrowser(string Engine, string DisplayName, string ExecutablePath, string? Version = null);

/// <summary>Structured identity of a Speedometer 3 run, persisted so Before/After comparisons only pair matching runs.</summary>
public sealed record SpeedometerRunIdentity(
    string Engine,
    string BrowserName,
    string? BrowserVersion,
    string SpeedometerVersion,
    string LaunchMode)
{
    public const string HeadlessNewMode = "headless-new";

    public bool IsComparableTo(SpeedometerRunIdentity? other) =>
        other is not null
        && string.Equals(Engine, other.Engine, StringComparison.OrdinalIgnoreCase)
        && string.Equals(SpeedometerVersion, other.SpeedometerVersion, StringComparison.OrdinalIgnoreCase)
        && string.Equals(LaunchMode, other.LaunchMode, StringComparison.OrdinalIgnoreCase);

    public static string MismatchReason(SpeedometerRunIdentity before, SpeedometerRunIdentity after)
    {
        if (!string.Equals(before.Engine, after.Engine, StringComparison.OrdinalIgnoreCase))
            return $"Different browser ({before.BrowserName} before vs {after.BrowserName} after) — excluded from overall score.";
        if (!string.Equals(before.SpeedometerVersion, after.SpeedometerVersion, StringComparison.OrdinalIgnoreCase))
            return $"Different Speedometer version ({before.SpeedometerVersion} before vs {after.SpeedometerVersion} after) — excluded from overall score.";
        return $"Different launch mode ({before.LaunchMode} before vs {after.LaunchMode} after) — excluded from overall score.";
    }
}

/// <summary>Outcome of one Speedometer 3 pass (which runs 10 internal iterations).</summary>
public sealed record SpeedometerResult(
    double? Score,
    string? Engine = null,
    string? BrowserName = null,
    string? BrowserVersion = null,
    double? ConfidenceInterval = null,
    string? Note = null,
    string SpeedometerVersion = SpeedometerPackage.Version,
    string LaunchMode = SpeedometerRunIdentity.HeadlessNewMode)
{
    public bool Succeeded => Score is > 0;

    public SpeedometerRunIdentity? ToIdentity() =>
        !string.IsNullOrWhiteSpace(Engine) && !string.IsNullOrWhiteSpace(BrowserName)
            ? new(Engine, BrowserName, BrowserVersion, SpeedometerVersion, LaunchMode)
            : null;

    public string? FormatDetail()
    {
        if (!Succeeded) return Note;
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(BrowserName))
            parts.Add(string.IsNullOrWhiteSpace(BrowserVersion) ? BrowserName : $"{BrowserName} {BrowserVersion}");
        parts.Add("clean profile");
        if (ConfidenceInterval is > 0 and var ci)
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"±{ci:0.00}"));
        return string.Join(" · ", parts);
    }
}

/// <summary>
/// Locates, verifies (SHA-256), and safely extracts the pinned Speedometer 3 static bundle
/// (with Zip-Slip path-traversal confinement).
/// </summary>
public static class SpeedometerPackage
{
    public const string Version = "3.1";
    public const string BundleFileName = "speedometer-3.1.zip";
    /// <summary>Pinned commit on WebKit/Speedometer <c>release/3.1</c> (vendored under <c>third_party/speedometer/speedometer-3.1.zip</c> with BSD LICENSE).</summary>
    public const string DefaultReleaseUrl = "https://github.com/WebKit/Speedometer/archive/1386415be8fef2f6b6bbdbe1828872471c5d802a.zip";
    public const string ExpectedSha256 = "545A561B3FE5FDBEF2D1403EF30DD86D212C73F7FE1F111EED084773347C1F5E";

    public static string DefaultCacheDir() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "RemotePCDiagnostics", "benchmarks", "speedometer", Version);

    public static string DefaultBundledZipPath() =>
        Path.Combine(AppContext.BaseDirectory, "benchmarks", BundleFileName);

    /// <summary>
    /// Ensures the extracted Speedometer directory containing <c>index.html</c> is ready.
    /// Checks existing cache first, then a bundled zip next to the app, then optional download.
    /// </summary>
    public static async Task<(string? RootDir, string? Error)> EnsureAssetsAsync(
        string? cacheDir = null,
        string? bundledZipPath = null,
        string? downloadUrl = null,
        string? expectedSha256 = null,
        HttpClient? http = null,
        CancellationToken ct = default)
    {
        var target = cacheDir ?? DefaultCacheDir();
        var existingRoot = FindReadyRoot(target);
        if (existingRoot is not null)
            return (existingRoot, null);

        var zipPath = bundledZipPath ?? DefaultBundledZipPath();
        if (File.Exists(zipPath))
        {
            try
            {
                using var fs = File.OpenRead(zipPath);
                var root = ExtractToCache(fs, target, expectedSha256);
                return root is not null ? (root, null) : (null, "Bundled Speedometer archive does not contain index.html.");
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException or CryptographicException)
            {
                return (null, $"Bundled Speedometer archive could not be extracted: {ex.Message}");
            }
        }

        if (string.IsNullOrWhiteSpace(downloadUrl))
            return (null, "Speedometer 3 assets are not installed on this PC.");

        try
        {
            using var ownedClient = http is null ? new HttpClient { Timeout = TimeSpan.FromSeconds(45) } : null;
            var client = http ?? ownedClient!;
            using var resp = await client.GetAsync(downloadUrl, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return (null, $"Could not download Speedometer 3 (HTTP {(int)resp.StatusCode}).");
            await using var ms = new MemoryStream();
            await resp.Content.CopyToAsync(ms, ct).ConfigureAwait(false);
            ms.Position = 0;
            var root = ExtractToCache(ms, target, expectedSha256);
            return root is not null ? (root, null) : (null, "Downloaded Speedometer archive does not contain index.html.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return (null, $"Could not download Speedometer 3: {ex.Message}");
        }
    }

    /// <summary>Written into the cache folder only after every entry is extracted.</summary>
    public const string CompleteMarkerFileName = ".rpcd-extracted";

    /// <summary>The cache's <c>index.html</c> root, only when a previous extraction finished (an interrupted one leaves no marker).</summary>
    public static string? FindReadyRoot(string dir) =>
        File.Exists(Path.Combine(dir, CompleteMarkerFileName)) ? FindIndexRoot(dir) : null;

    /// <summary>
    /// Extracts into a clean <paramref name="target"/> and marks it complete. <c>index.html</c> is one of the first
    /// entries in the archive, so without the marker an extraction cut short (app closed, disk full) would look ready
    /// and every later run would serve a bundle with files missing.
    /// </summary>
    private static string? ExtractToCache(Stream zipStream, string target, string? expectedSha256)
    {
        if (Directory.Exists(target))
            Directory.Delete(target, recursive: true);
        ExtractZipSafely(zipStream, target, expectedSha256);
        var root = FindIndexRoot(target);
        if (root is not null)
            File.WriteAllText(Path.Combine(target, CompleteMarkerFileName), Version);
        return root;
    }

    /// <summary>
    /// Verifies optional SHA-256 and extracts a zip stream into <paramref name="destinationDir"/>,
    /// rejecting any Zip-Slip entry whose canonical path escapes the target directory.
    /// </summary>
    public static void ExtractZipSafely(Stream zipStream, string destinationDir, string? expectedSha256 = null)
    {
        if (!string.IsNullOrWhiteSpace(expectedSha256))
        {
            if (!zipStream.CanSeek)
            {
                using var copy = new MemoryStream();
                zipStream.CopyTo(copy);
                copy.Position = 0;
                ExtractZipSafely(copy, destinationDir, expectedSha256);
                return;
            }
            zipStream.Position = 0;
            var actual = Convert.ToHexString(SHA256.HashData(zipStream));
            var expected = expectedSha256.Trim().Replace("-", "").ToUpperInvariant();
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(expected)))
                throw new CryptographicException($"SHA-256 mismatch (expected {expected}, got {actual}).");
            zipStream.Position = 0;
        }

        Directory.CreateDirectory(destinationDir);
        var fullRoot = Path.GetFullPath(destinationDir);
        if (!fullRoot.EndsWith(Path.DirectorySeparatorChar))
            fullRoot += Path.DirectorySeparatorChar;

        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name) && entry.FullName.EndsWith('/'))
                continue;

            var destPath = Path.GetFullPath(Path.Combine(fullRoot, entry.FullName));
            if (!destPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Zip entry escapes target directory: {entry.FullName}");

            var parent = Path.GetDirectoryName(destPath);
            if (!string.IsNullOrEmpty(parent))
                Directory.CreateDirectory(parent);

            using var src = entry.Open();
            using var dst = File.Create(destPath);
            src.CopyTo(dst);
        }
    }

    /// <summary>Finds the directory containing <c>index.html</c> (handles both flat zips and single top-level folder zips).</summary>
    public static string? FindIndexRoot(string dir)
    {
        if (!Directory.Exists(dir)) return null;
        if (File.Exists(Path.Combine(dir, "index.html"))) return dir;
        foreach (var sub in Directory.EnumerateDirectories(dir))
        {
            if (File.Exists(Path.Combine(sub, "index.html")))
                return sub;
        }
        return null;
    }
}

/// <summary>
/// Minimal static HTTP/1.1 server bound strictly to <c>127.0.0.1</c> on an OS-assigned ephemeral port.
/// Uses <see cref="TcpListener"/> so no Windows URL ACLs or admin privileges are required.
/// </summary>
public sealed class SpeedometerLocalServer : IAsyncDisposable
{
    private readonly string _rootDir;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;

    public int Port { get; }
    public Uri BaseUri { get; }

    public SpeedometerLocalServer(string rootDir)
    {
        _rootDir = Path.GetFullPath(rootDir);
        if (!_rootDir.EndsWith(Path.DirectorySeparatorChar))
            _rootDir += Path.DirectorySeparatorChar;

        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        BaseUri = new Uri($"http://127.0.0.1:{Port}/");
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { break; }

            _ = Task.Run(() => HandleClientAsync(client, ct), ct);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                await using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
                var requestLine = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(requestLine)) return;

                // Drain headers
                string? header;
                while (!string.IsNullOrEmpty(header = await reader.ReadLineAsync(ct).ConfigureAwait(false))) { }

                var parts = requestLine.Split(' ');
                if (parts.Length < 2 || (!string.Equals(parts[0], "GET", StringComparison.OrdinalIgnoreCase) && !string.Equals(parts[0], "HEAD", StringComparison.OrdinalIgnoreCase)))
                {
                    await WriteStatusAsync(stream, "405 Method Not Allowed", ct).ConfigureAwait(false);
                    return;
                }

                var isHead = string.Equals(parts[0], "HEAD", StringComparison.OrdinalIgnoreCase);
                var rawTarget = parts[1];
                var qIdx = rawTarget.IndexOf('?');
                var pathOnly = qIdx >= 0 ? rawTarget[..qIdx] : rawTarget;
                var decoded = Uri.UnescapeDataString(pathOnly).TrimStart('/');
                if (string.IsNullOrEmpty(decoded)) decoded = "index.html";

                var candidate = Path.GetFullPath(Path.Combine(_rootDir, decoded.Replace('/', Path.DirectorySeparatorChar)));
                if (!candidate.StartsWith(_rootDir, StringComparison.OrdinalIgnoreCase) || !File.Exists(candidate))
                {
                    await WriteStatusAsync(stream, "404 Not Found", ct).ConfigureAwait(false);
                    return;
                }

                var bytes = await File.ReadAllBytesAsync(candidate, ct).ConfigureAwait(false);
                var mime = MimeType(candidate);
                var responseHead = $"HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {bytes.Length}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
                var headBytes = Encoding.ASCII.GetBytes(responseHead);
                await stream.WriteAsync(headBytes, ct).ConfigureAwait(false);
                if (!isHead)
                    await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
            }
            catch (Exception) { /* client disconnected or server stopping */ }
        }
    }

    private static async Task WriteStatusAsync(NetworkStream stream, string status, CancellationToken ct)
    {
        var resp = Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(resp, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private static string MimeType(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".html" or ".htm" => "text/html; charset=utf-8",
        ".js" or ".mjs" => "application/javascript; charset=utf-8",
        ".css" => "text/css; charset=utf-8",
        ".json" => "application/json; charset=utf-8",
        ".svg" => "image/svg+xml",
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".woff2" => "font/woff2",
        ".wasm" => "application/wasm",
        _ => "application/octet-stream",
    };

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { }
        try { await _acceptLoop.ConfigureAwait(false); } catch { }
        _cts.Dispose();
    }
}

/// <summary>
/// Minimal Chrome DevTools Protocol client over <see cref="ClientWebSocket"/> (zero extra dependencies).
/// Connects only to loopback endpoints and polls Speedometer 3 for completion.
/// </summary>
public sealed class CdpClient : IAsyncDisposable
{
    private readonly ClientWebSocket _ws = new();
    private int _nextId;

    /// <summary>False once the browser closed the DevTools connection (the browser, or the benchmark tab, is gone).</summary>
    public bool IsOpen => _ws.State == WebSocketState.Open;

    /// <summary>
    /// Asks the browser on <paramref name="cdpPort"/> to close itself (<c>Browser.close</c> on the browser target). Needed because
    /// on Windows the chrome.exe RPCD started can hand the browser to another process and exit, so killing the started process's
    /// tree doesn't reach it. Best effort; returns false when the browser couldn't be reached.
    /// </summary>
    public static async Task<bool> CloseBrowserAsync(int cdpPort, TimeSpan timeout)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeout);
            using var http = new HttpClient { Timeout = timeout };
            var json = await http.GetStringAsync($"http://127.0.0.1:{cdpPort}/json/version", cts.Token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("webSocketDebuggerUrl", out var wsProp)
                || !Uri.TryCreate(wsProp.GetString(), UriKind.Absolute, out var wsUri))
                return false;
            await using var browser = new CdpClient();
            await browser.ConnectAsync(wsUri, cts.Token).ConfigureAwait(false);
            var payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { id = 1, method = "Browser.close" }));
            await browser._ws.SendAsync(payload, WebSocketMessageType.Text, endOfMessage: true, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or WebSocketException or OperationCanceledException or JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>JavaScript probe evaluated over CDP to check Speedometer 3 completion and extract the score.</summary>
    public const string SpeedometerPollExpression = """
        (() => {
            const client = window.benchmarkClient;
            if (client && client._metrics && client._metrics.Score && typeof client._metrics.Score.mean === 'number' && client._metrics.Score.mean > 0) {
                return JSON.stringify({
                    done: true,
                    score: client._metrics.Score.mean,
                    ci: typeof client._metrics.Score.delta === 'number' ? client._metrics.Score.delta : null
                });
            }
            const el = document.querySelector('#result-number, .score-number, .result-number');
            const summary = document.querySelector('#summary, section.summary');
            const visible = summary && window.getComputedStyle(summary).display !== 'none';
            if (el && (visible || el.textContent.trim().length > 0)) {
                const raw = parseFloat(el.textContent.trim());
                if (Number.isFinite(raw) && raw > 0 && visible) {
                    return JSON.stringify({ done: true, score: raw, ci: null });
                }
            }
            if (client && client._hasResults && !client._isRunning) {
                return JSON.stringify({ done: true, error: true });
            }
            return JSON.stringify({ done: false });
        })()
        """;

    public static async Task<int?> WaitForDevToolsPortAsync(string profileDir, TimeSpan timeout, CancellationToken ct)
    {
        var portFile = Path.Combine(profileDir, "DevToolsActivePort");
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            if (File.Exists(portFile))
            {
                try
                {
                    var lines = await File.ReadAllLinesAsync(portFile, ct).ConfigureAwait(false);
                    if (lines.Length > 0 && int.TryParse(lines[0].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) && port is > 0 and <= 65535)
                        return port;
                }
                catch (IOException) { }
            }
            await Task.Delay(150, ct).ConfigureAwait(false);
        }
        return null;
    }

    public static async Task<Uri?> DiscoverPageWebSocketAsync(int cdpPort, TimeSpan timeout, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var json = await http.GetStringAsync($"http://127.0.0.1:{cdpPort}/json/list", ct).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    if (item.TryGetProperty("type", out var t) && t.GetString() == "page"
                        && item.TryGetProperty("webSocketDebuggerUrl", out var wsProp)
                        && Uri.TryCreate(wsProp.GetString(), UriKind.Absolute, out var wsUri)
                        && (wsUri.Host == "127.0.0.1" || wsUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)))
                    {
                        return wsUri;
                    }
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
            {
                if (ct.IsCancellationRequested) throw;
            }
            await Task.Delay(200, ct).ConfigureAwait(false);
        }
        return null;
    }

    public async Task ConnectAsync(Uri wsUri, CancellationToken ct)
    {
        if (wsUri.Host != "127.0.0.1" && !wsUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("CDP connection refused: non-loopback host.");
        await _ws.ConnectAsync(wsUri, ct).ConfigureAwait(false);
    }

    public async Task<string?> EvaluateStringAsync(string expression, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _nextId);
        var payload = JsonSerializer.Serialize(new
        {
            id,
            method = "Runtime.evaluate",
            @params = new { expression, returnByValue = true },
        });
        var sendBytes = Encoding.UTF8.GetBytes(payload);
        await _ws.SendAsync(sendBytes, WebSocketMessageType.Text, endOfMessage: true, ct).ConfigureAwait(false);

        var buffer = new byte[16 * 1024];
        while (true)
        {
            using var ms = new MemoryStream();
            WebSocketReceiveResult result;
            do
            {
                result = await _ws.ReceiveAsync(buffer, ct).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close) return null;
                ms.Write(buffer, 0, result.Count);
            } while (!result.EndOfMessage);

            using var doc = JsonDocument.Parse(ms.ToArray());
            if (!doc.RootElement.TryGetProperty("id", out var respId) || respId.GetInt32() != id)
                continue; // skip CDP event notifications

            if (doc.RootElement.TryGetProperty("result", out var res)
                && res.TryGetProperty("result", out var inner)
                && inner.TryGetProperty("value", out var val)
                && val.ValueKind == JsonValueKind.String)
            {
                return val.GetString();
            }
            return null;
        }
    }

    /// <summary>True when <see cref="SpeedometerPollExpression"/> reports that the run finished without a score.</summary>
    public static bool IsErrorJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.True;
        }
        catch (JsonException) { return false; }
    }

    /// <summary>Parses the JSON payload returned by <see cref="SpeedometerPollExpression"/>.</summary>
    public static bool TryParseScoreJson(string? json, out double score, out double? ci)
    {
        score = 0;
        ci = null;
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("done", out var doneProp) || !doneProp.GetBoolean())
                return false;
            if (!root.TryGetProperty("score", out var scoreProp) || !scoreProp.TryGetDouble(out var s) || !double.IsFinite(s) || s <= 0)
                return false;
            score = s;
            if (root.TryGetProperty("ci", out var ciProp) && ciProp.ValueKind == JsonValueKind.Number && ciProp.TryGetDouble(out var d) && double.IsFinite(d) && d >= 0)
                ci = d;
            return true;
        }
        catch (JsonException) { return false; }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_ws.State == WebSocketState.Open)
                await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None).ConfigureAwait(false);
        }
        catch { }
        _ws.Dispose();
    }
}

/// <summary>
/// Orchestrates one headless Chromium Speedometer 3 pass: serves extracted assets on loopback,
/// launches the browser with an isolated temp profile and ephemeral CDP port, polls for the score,
/// and guarantees process-tree and temp-profile cleanup.
/// </summary>
public static class SpeedometerProcessRunner
{
    public const string TempProfilePrefix = "rpcd-speedometer-";

    public static void CleanupOrphanedProfiles(string? tempRoot = null)
    {
        var root = tempRoot ?? Path.GetTempPath();
        if (!Directory.Exists(root)) return;
        foreach (var dir in Directory.EnumerateDirectories(root, TempProfilePrefix + "*"))
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    public static async Task<SpeedometerResult> RunAsync(
        SpeedometerBrowser browser,
        string assetsRootDir,
        TimeSpan timeout,
        ILogger? log = null,
        CancellationToken ct = default)
    {
        if (!File.Exists(browser.ExecutablePath))
            return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: $"{browser.DisplayName} executable was not found.");

        var profileDir = Path.Combine(Path.GetTempPath(), TempProfilePrefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(profileDir);

        await using var server = new SpeedometerLocalServer(assetsRootDir);
        var runUrl = $"{server.BaseUri}?startAutomatically=true";

        var psi = new ProcessStartInfo(browser.ExecutablePath) { UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add("--headless=new");
        psi.ArgumentList.Add($"--user-data-dir={profileDir}");
        psi.ArgumentList.Add("--no-first-run");
        psi.ArgumentList.Add("--no-default-browser-check");
        psi.ArgumentList.Add("--disable-extensions");
        psi.ArgumentList.Add("--disable-sync");
        psi.ArgumentList.Add("--remote-debugging-address=127.0.0.1");
        psi.ArgumentList.Add("--remote-debugging-port=0");
        psi.ArgumentList.Add(runUrl);

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);

        Process? proc = null;
        int? port = null;
        try
        {
            log.Info($"[benchmark] speedometer start: browser={browser.DisplayName} url={runUrl}");
            proc = Process.Start(psi);
            if (proc is null)
                return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: $"Could not launch {browser.DisplayName}.");

            var cdpPort = await CdpClient.WaitForDevToolsPortAsync(profileDir, TimeSpan.FromSeconds(15), linked.Token).ConfigureAwait(false);
            if (cdpPort is null)
                return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: $"{browser.DisplayName} did not open a local DevTools port.");

            var wsUri = await CdpClient.DiscoverPageWebSocketAsync(cdpPort.Value, TimeSpan.FromSeconds(10), linked.Token).ConfigureAwait(false);
            if (wsUri is null)
                return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: $"Could not attach to {browser.DisplayName} benchmark tab.");

            port = cdpPort;
            await using var cdp = new CdpClient();
            await cdp.ConnectAsync(wsUri, linked.Token).ConfigureAwait(false);

            var launcherExitLogged = false;
            while (!linked.Token.IsCancellationRequested)
            {
                // The DevTools connection is what tells us the browser is still running. On Windows the chrome.exe we started
                // often hands the browser to another chrome.exe and exits within a second, so its exit alone means nothing.
                if (!cdp.IsOpen)
                    return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: $"{browser.DisplayName} closed before Speedometer finished.");
                if (proc.HasExited && !launcherExitLogged)
                {
                    launcherExitLogged = true;
                    log.Info($"[benchmark] speedometer: started {browser.DisplayName} process exited (code {SafeExitCode(proc)}); the browser is still answering, so the run continues.");
                }

                string? raw;
                try { raw = await cdp.EvaluateStringAsync(CdpClient.SpeedometerPollExpression, linked.Token).ConfigureAwait(false); }
                catch (WebSocketException)
                {
                    return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: $"{browser.DisplayName} closed before Speedometer finished.");
                }
                if (CdpClient.IsErrorJson(raw))
                    return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: "Speedometer 3 stopped with an error in the browser.");
                if (CdpClient.TryParseScoreJson(raw, out var score, out var ci))
                {
                    log.Info($"[benchmark] speedometer done: browser={browser.DisplayName} score={score:0.00}");
                    return new(Math.Round(score, 2), browser.Engine, browser.DisplayName, browser.Version, ci);
                }

                await Task.Delay(1000, linked.Token).ConfigureAwait(false);
            }

            return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: "Speedometer timed out before finishing.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: $"Speedometer timed out after {timeout.TotalMinutes:0.#} minutes.");
        }
        finally
        {
            // Close the browser through DevTools first: it reaches the browser even when the process we started already exited.
            if (port is { } p && await CdpClient.CloseBrowserAsync(p, TimeSpan.FromSeconds(3)).ConfigureAwait(false))
                await WaitForProfileReleaseAsync(profileDir, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            try
            {
                if (proc is not null && !proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch { }
            proc?.Dispose();
            try { Directory.Delete(profileDir, recursive: true); } catch { }
        }
    }

    private static string SafeExitCode(Process proc)
    {
        try { return proc.ExitCode.ToString(CultureInfo.InvariantCulture); }
        catch { return "unknown"; }
    }

    /// <summary>Waits until the browser lets go of its profile (Chrome deletes DevToolsActivePort as it shuts down).</summary>
    private static async Task WaitForProfileReleaseAsync(string profileDir, TimeSpan timeout)
    {
        var portFile = Path.Combine(profileDir, "DevToolsActivePort");
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline && File.Exists(portFile))
            await Task.Delay(200).ConfigureAwait(false);
    }
}
