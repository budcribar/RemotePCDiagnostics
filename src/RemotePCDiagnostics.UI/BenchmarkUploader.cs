using Microsoft.JSInterop;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.UI;

/// <summary>
/// Sends the latest benchmark pass and this PC's hardware to the shop's Admin site (the comparison on its Benchmarks page). The
/// Benchmark page's Upload results calls it, and it uploads by itself whenever a pass finishes, so the comparison is never stale.
/// The state (message, link, failed) is shared, so the page shows an automatic upload too.
/// </summary>
public sealed class BenchmarkUploader
{
    private readonly BenchmarkService _bench;
    private readonly AppServices _app;
    private readonly ISessionContext _session;
    private readonly ShopRelayClient _fallbackRelay = new();
    private int _uploading;

    public BenchmarkUploader(BenchmarkService bench, AppServices app, ISessionContext session)
    {
        _bench = bench;
        _app = app;
        _session = session;
        bench.PassFinished += run =>
        {
            if (run.Measurements.Count > 0 && CanUpload)
                _ = UploadAsync(automatic: true);
        };
    }

    public event Action? Changed;
    public bool Uploading => Volatile.Read(ref _uploading) == 1;
    public bool Failed { get; private set; }
    public string? Message { get; private set; }
    public string? CompareUrl { get; private set; }
    /// <summary>Goes up with every finished upload, so an agent can tell a new result from the one it saw before clicking.</summary>
    public int Seq { get; private set; }
    /// <summary>When the last upload finished, and whether it ran by itself after a pass.</summary>
    public DateTimeOffset? LastAt { get; private set; }
    public bool LastAutomatic { get; private set; }

    private string? RelayServerUrl =>
        !string.IsNullOrWhiteSpace(_app.Preferences?.Current.RelayServerUrl) ? _app.Preferences!.Current.RelayServerUrl : _session.ServerUri?.ToString();

    private string ApiKey => _app.Preferences?.Current.ShopApiKey?.Trim() ?? "";

    public bool CanUpload =>
        ApiKey.StartsWith(ShopRelayClient.ApiKeyPrefix, StringComparison.Ordinal) && ApiKey.Length > ShopRelayClient.ApiKeyPrefix.Length
        && ShopRelayClient.TryParseRelayUri(RelayServerUrl, out _);

    public async Task UploadAsync(bool automatic = false)
    {
        if (!CanUpload || !ShopRelayClient.TryParseRelayUri(RelayServerUrl, out var relayUri) || relayUri is null) return;
        if (Interlocked.CompareExchange(ref _uploading, 1, 0) != 0) return;
        Failed = false;
        Message = automatic ? "Uploading the results to your shop…" : "Reading this PC's hardware…";
        Raise();
        try
        {
            var hardware = _app.Commands is { } commands ? await HardwareIdentityProbe.ReadAsync(commands, CancellationToken.None) : new BenchmarkHardware();
            var request = BenchmarkUpload.Build(BenchmarkUpload.LatestRun(_bench.Before, _bench.After), MachineIdentity.Read(_session.MachineName), _session.MachineName, hardware);
            if (request is null)
            {
                Fail("There are no measured results to upload yet.");
                return;
            }
            Message = "Uploading…";
            Raise();
            var result = await (_app.ShopRelay ?? _fallbackRelay).UploadBenchmarkAsync(relayUri, ApiKey, request);
            switch (result)
            {
                case ShopBenchmarkUploadResult.Uploaded up:
                    CompareUrl = up.CompareUrl;
                    Message = (automatic ? "Uploaded by itself after the pass: " : "Uploaded ") + (up.Computers is > 1
                        ? $"{request.Results.Count} results. Your shop now has {up.Computers} computers to compare."
                        : $"{request.Results.Count} results. Upload from another computer to compare them.");
                    break;
                case ShopBenchmarkUploadResult.Unauthorized:
                    Fail("The shop API key was rejected. Check your rpd_live_… key on QA & branding.");
                    break;
                case ShopBenchmarkUploadResult.PaymentRequired:
                    Fail("The shop's subscription or trial is inactive. Renew it on the Admin site's Shop page.");
                    break;
                case ShopBenchmarkUploadResult.InvalidRequest bad:
                    Fail($"Admin did not accept the results: {bad.Error}");
                    break;
                case ShopBenchmarkUploadResult.NetworkError net:
                    Fail($"Could not reach the Admin site: {net.Message}");
                    break;
            }
        }
        catch (Exception ex)
        {
            Fail($"The upload failed: {ex.Message}");
        }
        finally
        {
            LastAt = DateTimeOffset.UtcNow;
            LastAutomatic = automatic;
            Seq++;
            Volatile.Write(ref _uploading, 0);
            Raise();
        }
    }

    /// <summary>
    /// Uploads the latest benchmark pass through the technician's signed-in Admin browser session
    /// (<c>POST /api/shop/benchmarks</c> with same-origin cookie auth), so target PCs do not need a local API key.
    /// </summary>
    public async Task UploadViaBrowserAsync(Microsoft.JSInterop.IJSRuntime js)
    {
        if (Interlocked.CompareExchange(ref _uploading, 1, 0) != 0) return;
        Failed = false;
        Message = "Reading this PC's hardware…";
        Raise();
        try
        {
            var hardware = _app.Commands is { } commands ? await HardwareIdentityProbe.ReadAsync(commands, CancellationToken.None) : new BenchmarkHardware();
            var request = BenchmarkUpload.Build(BenchmarkUpload.LatestRun(_bench.Before, _bench.After), MachineIdentity.Read(_session.MachineName), _session.MachineName, hardware);
            if (request is null)
            {
                Fail("There are no measured results to upload yet.");
                return;
            }
            Message = "Uploading…";
            Raise();
            var payloadJson = System.Text.Json.JsonSerializer.Serialize(request, BrowserUploadJson);
            var res = await js.InvokeAsync<BrowserBenchmarkUploadResult>("rpdSession.uploadBenchmark", payloadJson);
            if (res.Ok)
            {
                CompareUrl = res.CompareUrl;
                Message = "Uploaded " + (res.Computers > 1
                    ? $"{request.Results.Count} results. Your shop now has {res.Computers} computers to compare."
                    : $"{request.Results.Count} results. Upload from another computer to compare them.");
            }
            else if (res.Status == 401)
            {
                Fail("Sign in to your Admin portal in this browser to upload benchmark results.");
            }
            else if (res.Status == 402)
            {
                Fail("The shop's subscription or trial is inactive. Renew it on the Admin site's Shop page.");
            }
            else
            {
                Fail($"Could not upload results: {res.Error ?? $"HTTP {res.Status}"}");
            }
        }
        catch (Exception ex)
        {
            Fail($"The upload failed: {ex.Message}");
        }
        finally
        {
            LastAt = DateTimeOffset.UtcNow;
            LastAutomatic = false;
            Seq++;
            Volatile.Write(ref _uploading, 0);
            Raise();
        }
    }

    private static readonly System.Text.Json.JsonSerializerOptions BrowserUploadJson = new(System.Text.Json.JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed record BrowserBenchmarkUploadResult(
        bool Ok,
        int Status,
        string? MachineId,
        string? CompareUrl,
        int Computers,
        string? Error);

    private void Fail(string message)
    {
        Failed = true;
        Message = message;
    }

    private void Raise() { try { Changed?.Invoke(); } catch { } }
}
