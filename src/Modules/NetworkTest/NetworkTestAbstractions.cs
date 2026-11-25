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
    /// <summary>Byte budget per direction on ordinary (unrestricted) connections.</summary>
    public long OrdinaryDownloadBytes { get; init; } = 250_000_000;
    public long OrdinaryUploadBytes { get; init; } = 100_000_000;
    /// <summary>Maximum per-request chunk size (Cloudflare per-request caps).</summary>
    public long MaxDownloadChunkBytes { get; init; } = 50_000_000;
    public long MaxUploadChunkBytes { get; init; } = 25_000_000;
    /// <summary>Time ceiling per direction (~5 seconds; bufferbloat appears within 2-3 s of saturation).</summary>
    public TimeSpan DirectionTimeCeiling { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan TransferTimeout { get; init; } = TimeSpan.FromSeconds(20);

    public string DownloadUrl(long bytes) => $"{SpeedServer.TrimEnd('/')}/__down?bytes={bytes}";
    public string UploadUrl => $"{SpeedServer.TrimEnd('/')}/__up";

    public static NetworkTestSettings FromEnvironment(Func<string, string?> getEnv)
    {
        var url = getEnv(SpeedServerEnvironmentVariable)?.Trim();
        return Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme is "https" or "http" ? new NetworkTestSettings { SpeedServer = u.ToString() } : new NetworkTestSettings();
    }
}

public enum ConnectionCostKind { Unknown, Unrestricted, Metered }

public interface IConnectionCostProvider
{
    ConnectionCostKind GetConnectionCost();
}

/// <summary>Reads Windows connection cost via COM <c>INetworkCostManager</c> when available; falls back to <see cref="ConnectionCostKind.Unknown"/> (conservative 25/10 MB caps).</summary>
public sealed class WindowsConnectionCostProvider : IConnectionCostProvider
{
    public ConnectionCostKind GetConnectionCost()
    {
        if (!OperatingSystem.IsWindows()) return ConnectionCostKind.Unknown;
        try
        {
            var t = Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B"));
            if (t is null) return ConnectionCostKind.Unknown;
            var obj = Activator.CreateInstance(t);
            if (obj is null) return ConnectionCostKind.Unknown;
            try
            {
                if (obj is INetworkCostManager mgr)
                {
                    mgr.GetCost(out var cost, IntPtr.Zero);
                    // NLM_CONNECTION_COST_UNRESTRICTED = 0x1; FIXED = 0x2; VARIABLE = 0x4; OVERDATALIMIT = 0x10000; ROAMING = 0x40000
                    if ((cost & 0x00000006u) != 0 || (cost & 0x00050000u) != 0)
                        return ConnectionCostKind.Metered;
                    if ((cost & 0x00000001u) != 0)
                        return ConnectionCostKind.Unrestricted;
                }
            }
            finally
            {
                if (System.Runtime.InteropServices.Marshal.IsComObject(obj))
                    System.Runtime.InteropServices.Marshal.ReleaseComObject(obj);
            }
        }
        catch { }
        return ConnectionCostKind.Unknown;
    }

    [System.Runtime.InteropServices.ComImport]
    [System.Runtime.InteropServices.Guid("DCB00008-570F-4A9B-8D69-199FDBA5723B")]
    [System.Runtime.InteropServices.InterfaceType(System.Runtime.InteropServices.ComInterfaceType.InterfaceIsIUnknown)]
    private interface INetworkCostManager
    {
        void GetCost(out uint pCost, IntPtr pDestIPAddr);
    }
}

public interface IWifiLinkRateReader
{
    Task<string?> ReadLinkRateTextAsync(CancellationToken ct);
}

public sealed class NetshWifiLinkRateReader(SystemCommandRunner commands) : IWifiLinkRateReader
{
    public async Task<string?> ReadLinkRateTextAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var res = await commands.RunAsync(WifiConfigModule.Netsh, ["wlan", "show", "interfaces"], ct).ConfigureAwait(false);
            if (res is not { ExitCode: 0 }) return null;
            var wifi = WifiConfigModule.ParseNetshWlan(res.StdOut);
            if (wifi is not { Connected: true }) return null;
            var rx = wifi.ReceiveRateMbps?.Trim();
            var tx = wifi.TransmitRateMbps?.Trim();
            if (!string.IsNullOrEmpty(rx) && !string.IsNullOrEmpty(tx)) return $"{rx} / {tx} Mbps";
            if (!string.IsNullOrEmpty(rx)) return $"{rx} Mbps";
            if (!string.IsNullOrEmpty(tx)) return $"{tx} Mbps";
            return null;
        }
        catch { return null; }
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

/// <summary>Measured transfer: bytes moved in the elapsed time (null bytes = failed). ClientObservedBytes tracks bytes sent/received even on timeout/error so budgets stay bounded.</summary>
public sealed record TransferResult(
    long Bytes,
    TimeSpan Elapsed,
    string? Error = null,
    TimeSpan? FirstPayloadByteAt = null,
    TimeSpan? LastPayloadByteAt = null,
    long ClientObservedBytes = 0)
{
    public double? Mbps => Error is null && Bytes > 0 && Elapsed > TimeSpan.Zero ? Bytes * 8 / 1e6 / Elapsed.TotalSeconds : null;
    public long BudgetBytes => Math.Max(Bytes, ClientObservedBytes);
}

public interface ISpeedTester
{
    /// <summary>Downloads at most <paramref name="maxBytes"/>; never transfers more.</summary>
    Task<TransferResult> DownloadAsync(long maxBytes, TimeSpan timeout, CancellationToken cancellationToken);
    /// <summary>Uploads at most <paramref name="bytes"/> (capped by the caller).</summary>
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

/// <summary>HTTPS download/upload against a Cloudflare-style speed endpoint, with hard byte caps and client-observed payload-window timestamps.</summary>
public sealed class HttpSpeedTester(NetworkTestSettings settings, HttpClient? client = null, ILogger? log = null, IStressClock? clock = null) : ISpeedTester, IDisposable
{
    private readonly bool _ownsClient = client is null;
    private readonly HttpClient _http = client ?? new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    private readonly IStressClock _clock = clock ?? new StopwatchStressClock();

    public void Dispose() { if (_ownsClient) _http.Dispose(); }

    public async Task<TransferResult> DownloadAsync(long maxBytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        long total = 0;
        TimeSpan? firstByte = null;
        TimeSpan? lastByte = null;
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
                var now = _clock.Elapsed;
                firstByte ??= now;
                lastByte = now;
                total += n;
            }
            return new TransferResult(total, sw.Elapsed, FirstPayloadByteAt: firstByte, LastPayloadByteAt: lastByte, ClientObservedBytes: total);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && total > 0)
        {
            return new TransferResult(total, sw.Elapsed, FirstPayloadByteAt: firstByte, LastPayloadByteAt: lastByte, ClientObservedBytes: total);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log.Error($"Network test: download failed: {ex.GetType().Name}: {ex.Message}");
            return new TransferResult(0, sw.Elapsed, ex.Message, firstByte, lastByte, total);
        }
    }

    public async Task<TransferResult> UploadAsync(long bytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var sw = new Stopwatch();
        using var content = new TrackedUploadContent(bytes, _clock);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        try
        {
            sw.Restart();
            using var resp = await _http.PostAsync(settings.UploadUrl, content, cts.Token).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            return new TransferResult(bytes, sw.Elapsed, FirstPayloadByteAt: content.FirstByteAt, LastPayloadByteAt: content.LastByteAt, ClientObservedBytes: content.BytesWritten);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log.Error($"Network test: upload failed: {ex.GetType().Name}: {ex.Message}");
            // Partial upload timed out or failed: track client-observed bytes for budget accounting without implying server receipt.
            return new TransferResult(0, sw.Elapsed, ex.Message, content.FirstByteAt, content.LastByteAt, content.BytesWritten);
        }
    }

    private sealed class TrackedUploadContent(long totalBytes, IStressClock clock) : HttpContent
    {
        private const int BlockSize = 65536;
        public long BytesWritten { get; private set; }
        public TimeSpan? FirstByteAt { get; private set; }
        public TimeSpan? LastByteAt { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context, CancellationToken cancellationToken)
        {
            var block = new byte[(int)Math.Min(BlockSize, Math.Max(1, totalBytes))];
            Random.Shared.NextBytes(block);
            long remaining = totalBytes;
            while (remaining > 0)
            {
                var n = (int)Math.Min(block.Length, remaining);
                await stream.WriteAsync(block.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                var now = clock.Elapsed;
                FirstByteAt ??= now;
                LastByteAt = now;
                BytesWritten += n;
                remaining -= n;
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = totalBytes;
            return true;
        }
    }
}

/// <summary>Adapter error/drop totals via .NET NetworkInfoReader (with scripted PowerShell fallback for tests).</summary>
public sealed class SystemAdapterCounters(SystemCommandRunner commands) : IAdapterCounters
{
    public async Task<AdapterTotals?> ReadAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) return null;
        if (!commands.IsScripted)
        {
            var stats = Platform.NetworkInfoReader.ReadAdapterStatistics();
            return new AdapterTotals(
                stats.Values.Sum(s => s.ErrorsIn + s.ErrorsOut),
                stats.Values.Sum(s => s.DropsIn + s.DropsOut));
        }

        var pr = await commands.RunPowerShellAsync(Scripts.PowerShellScripts.Get("NetAdapterStatistics"), cancellationToken).ConfigureAwait(false);
        if (pr is not { ExitCode: 0 }) return null;

        try { return Sum(OsqueryJson.ParseRows(pr.StdOut)); }
        catch (FormatException ex) { commands.Log.Info($"Network test: adapter statistics unreadable: {ex.Message}"); return null; }
    }

    public static AdapterTotals Sum(IReadOnlyList<IReadOnlyDictionary<string, string>> rows) => new(
        rows.Sum(r => (r.Long("ierrors") ?? 0) + (r.Long("oerrors") ?? 0)),
        rows.Sum(r => (r.Long("idrops") ?? 0) + (r.Long("odrops") ?? 0)));
}
