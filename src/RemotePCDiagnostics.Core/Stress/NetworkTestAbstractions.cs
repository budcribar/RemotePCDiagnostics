using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>Endpoints and caps for the network stability test. Override the speed server with REMOTEPC_SPEEDTEST_URL (see README).</summary>
public sealed record NetworkTestSettings
{
    public const string SpeedServerEnvironmentVariable = "REMOTEPC_SPEEDTEST_URL";
    public const string DefaultSpeedServer = "https://speed.cloudflare.com";
    public static readonly string[] DefaultPublicHosts = ["1.1.1.1", "8.8.8.8"];

    public IReadOnlyList<string> PublicHosts { get; init; } = DefaultPublicHosts;
    /// <summary>Base URL of a server with the Cloudflare speed-test API: GET {base}/__down?bytes=N and POST {base}/__up.</summary>
    public string SpeedServer { get; init; } = DefaultSpeedServer;
    public long DownloadBytes { get; init; } = 25_000_000;
    public long UploadBytes { get; init; } = 10_000_000;
    public TimeSpan TransferTimeout { get; init; } = TimeSpan.FromSeconds(20);

    public string DownloadUrl(long bytes) => $"{SpeedServer.TrimEnd('/')}/__down?bytes={bytes}";
    public string UploadUrl => $"{SpeedServer.TrimEnd('/')}/__up";

    public static NetworkTestSettings FromEnvironment(Func<string, string?> getEnv)
    {
        var url = getEnv(SpeedServerEnvironmentVariable)?.Trim();
        return Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme is "https" or "http" ? new NetworkTestSettings { SpeedServer = u.ToString() } : new NetworkTestSettings();
    }
}

public sealed record PingReply(bool Success, double? RoundTripMs);

public interface IPinger
{
    Task<PingReply> PingAsync(string host, TimeSpan timeout, CancellationToken cancellationToken);
}

public interface IGatewayResolver
{
    /// <summary>The default gateway (router) address, or null when there's no active connection.</summary>
    string? GetDefaultGateway();
}

/// <summary>Measured transfer: bytes moved in the elapsed time (null bytes = failed).</summary>
public sealed record TransferResult(long Bytes, TimeSpan Elapsed, string? Error = null)
{
    public double? Mbps => Error is null && Bytes > 0 && Elapsed > TimeSpan.Zero ? Bytes * 8 / 1e6 / Elapsed.TotalSeconds : null;
}

public interface ISpeedTester
{
    /// <summary>Downloads at most <paramref name="maxBytes"/>; never transfers more.</summary>
    Task<TransferResult> DownloadAsync(long maxBytes, TimeSpan timeout, CancellationToken cancellationToken);
    /// <summary>Uploads exactly <paramref name="bytes"/> (capped by the caller).</summary>
    Task<TransferResult> UploadAsync(long bytes, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Total error and drop counters over all adapters.</summary>
public sealed record AdapterTotals(long Errors, long Drops);

public interface IAdapterCounters
{
    Task<AdapterTotals?> ReadAsync(CancellationToken cancellationToken);
}

public sealed class SystemPinger : IPinger
{
    public async Task<PingReply> PingAsync(string host, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            using var p = new Ping();
            var r = await p.SendPingAsync(host, timeout, cancellationToken: cancellationToken).ConfigureAwait(false);
            return r.Status == IPStatus.Success ? new PingReply(true, r.RoundtripTime) : new PingReply(false, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return new PingReply(false, null); }
    }
}

public sealed class SystemGatewayResolver : IGatewayResolver
{
    public string? GetDefaultGateway()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                .Select(g => g.Address)
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(System.Net.IPAddress.Any))
                .Select(a => a.ToString())
                .FirstOrDefault();
        }
        catch (NetworkInformationException) { return null; }
    }
}

/// <summary>HTTPS download/upload against a Cloudflare-style speed endpoint, with hard byte caps.</summary>
public sealed class HttpSpeedTester(NetworkTestSettings settings, HttpClient? client = null, Action<string>? log = null) : ISpeedTester, IDisposable
{
    private readonly bool _ownsClient = client is null;
    private readonly HttpClient _http = client ?? new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

    public void Dispose() { if (_ownsClient) _http.Dispose(); }

    public async Task<TransferResult> DownloadAsync(long maxBytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        long total = 0;
        try
        {
            using var resp = await _http.GetAsync(settings.DownloadUrl(maxBytes), HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            await using var s = await resp.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            var buf = new byte[81920];
            sw.Restart();
            while (total < maxBytes)
            {
                var n = await s.ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, maxBytes - total)), cts.Token).ConfigureAwait(false);
                if (n == 0) break;
                total += n;
            }
            return new TransferResult(total, sw.Elapsed);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && total > 0)
        {
            return new TransferResult(total, sw.Elapsed); // timed out part-way: still a valid measurement
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log?.Invoke($"Network test: download failed: {ex.GetType().Name}: {ex.Message}");
            return new TransferResult(total, sw.Elapsed, ex.Message);
        }
    }

    public async Task<TransferResult> UploadAsync(long bytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var sw = new Stopwatch();
        try
        {
            var payload = new byte[bytes];
            Random.Shared.NextBytes(payload);
            using var content = new ByteArrayContent(payload);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            sw.Restart();
            using var resp = await _http.PostAsync(settings.UploadUrl, content, cts.Token).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            return new TransferResult(bytes, sw.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log?.Invoke($"Network test: upload failed: {ex.GetType().Name}: {ex.Message}");
            return new TransferResult(0, sw.Elapsed, ex.Message);
        }
    }
}

/// <summary>Adapter error/drop totals from Windows Get-NetAdapterStatistics (same script as the Network adapters area).</summary>
public sealed class SystemAdapterCounters(SystemCommandRunner commands) : IAdapterCounters
{
    public async Task<AdapterTotals?> ReadAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var pr = await commands.RunAsync(SystemCommandRunner.PowerShell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", NetworkModule.StatsScript], cancellationToken).ConfigureAwait(false);
        if (pr is not { ExitCode: 0 }) return null;
        try { return Sum(OsqueryJson.ParseRows(pr.StdOut)); }
        catch (FormatException ex) { commands.Log?.Invoke($"Network test: adapter statistics unreadable: {ex.Message}"); return null; }
    }

    public static AdapterTotals Sum(IReadOnlyList<IReadOnlyDictionary<string, string>> rows) => new(
        rows.Sum(r => (r.Long("ierrors") ?? 0) + (r.Long("oerrors") ?? 0)),
        rows.Sum(r => (r.Long("idrops") ?? 0) + (r.Long("odrops") ?? 0)));
}
