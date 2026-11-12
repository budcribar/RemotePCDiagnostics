using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Workflow;

public sealed record ShopBrandingDto(
    string? Group = null,
    bool Active = true,
    string? ShopName = null,
    string? LogoDataUri = null,
    string? Phone = null,
    string? Email = null,
    string? Website = null,
    string? Address = null,
    string? TechnicianName = null,
    string? WarrantyFooter = null,
    string? VerificationBaseUrl = null);

public abstract record ShopRelayBrandingResult
{
    private ShopRelayBrandingResult() { }

    public sealed record Found(ShopBranding Branding, string GroupSlug) : ShopRelayBrandingResult;
    public sealed record NotFoundOrInactive(string GroupSlug) : ShopRelayBrandingResult;
    public sealed record NetworkError(string Message) : ShopRelayBrandingResult;
}

public sealed record ShopReportUploadRequest(
    string Id,
    string Kind,
    string Title,
    string Html,
    string? MachineName = null,
    string? ManufacturerModel = null,
    string? SerialNumber = null,
    string? Verdict = null,
    string? VerificationHash = null,
    string? SummaryJson = null);

public sealed record ShopReportCreatedDto(
    string? Id = null,
    string? Url = null,
    string? ShortHash = null);

public abstract record ShopReportPublishResult
{
    private ShopReportPublishResult() { }

    public sealed record Published(string Id, string Url, string ShortHash) : ShopReportPublishResult;
    public sealed record Unauthorized(string Error = "unauthorized") : ShopReportPublishResult;
    public sealed record PaymentRequired(string Error = "payment_required") : ShopReportPublishResult;
    public sealed record InvalidRequest(string Error) : ShopReportPublishResult;
    public sealed record NetworkError(string Message) : ShopReportPublishResult;
}

/// <summary>
/// HTTP client for talking to a <c>RemoteWebViewService</c> shop relay:
/// <list type="bullet">
/// <item><c>GET {relayBase}/api/shops/{group}/branding</c> — anonymous shop identity lookup &amp; active-subscription check.</item>
/// <item><c>POST {relayBase}/api/reports</c> — authenticated (<c>Bearer rpd_live_...</c>) hosted QR certificate &amp; client service report publishing.</item>
/// </list>
/// </summary>
public sealed partial class ShopRelayClient(HttpClient? httpClient = null, ILogger? log = null)
{
    public const string ApiKeyPrefix = "rpd_live_";
    public const string KindQaCertificate = "qa_certificate";
    public const string KindServiceReport = "service_report";

    private static readonly HttpClient SharedHttpClient = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    {
        Timeout = TimeSpan.FromSeconds(15),
    };

    private static readonly JsonSerializerOptions ReadJsonOptions = new(JsonSerializerDefaults.Web);

    private static readonly JsonSerializerOptions WriteJsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http = httpClient ?? SharedHttpClient;

    private void LogInfo(string message) => log.Info("[shop-relay] " + message);
    private void LogWarn(string message) => log.Warn("[shop-relay] " + message);

    /// <summary>Parses a user-entered relay server URL (prepending <c>https://</c> if omitted) into an absolute HTTP/HTTPS <see cref="Uri"/>.</summary>
    public static bool TryParseRelayUri(string? raw, out Uri? uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(raw)) return false;
        var trimmed = raw.Trim();
        if (trimmed.Any(char.IsWhiteSpace)) return false;
        var candidate = trimmed.Contains("://", StringComparison.Ordinal) ? trimmed : "https://" + trimmed;
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var parsed)) return false;
        if (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp) return false;
        if (string.IsNullOrWhiteSpace(parsed.Host)) return false;
        uri = new UriBuilder(parsed) { Query = "", Fragment = "" }.Uri;
        return true;
    }

    public static string BaseUrl(Uri relayServerUri)
    {
        ArgumentNullException.ThrowIfNull(relayServerUri);
        return new UriBuilder(relayServerUri) { Query = "", Fragment = "" }.Uri.AbsoluteUri.TrimEnd('/');
    }

    /// <summary>Fetches live shop branding and active status from <c>GET {relayBase}/api/shops/{group}/branding</c>.</summary>
    public async Task<ShopRelayBrandingResult> FetchBrandingAsync(Uri relayServerUri, string groupSlug, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(relayServerUri);
        var normalizedGroup = SessionLaunchOptions.NormalizeGroup(groupSlug);
        if (string.IsNullOrEmpty(normalizedGroup))
            return new ShopRelayBrandingResult.NetworkError("Enter a shop code first.");

        var relayBase = BaseUrl(relayServerUri);
        var requestUri = new Uri($"{relayBase}/api/shops/{Uri.EscapeDataString(normalizedGroup)}/branding", UriKind.Absolute);

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, requestUri);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                LogInfo($"Shop group '{normalizedGroup}' not found or inactive on {relayBase}");
                return new ShopRelayBrandingResult.NotFoundOrInactive(normalizedGroup);
            }

            if (!resp.IsSuccessStatusCode)
            {
                var statusMsg = $"Relay returned HTTP {(int)resp.StatusCode} ({resp.ReasonPhrase}).";
                LogWarn($"FetchBrandingAsync failed for '{normalizedGroup}': {statusMsg}");
                return new ShopRelayBrandingResult.NetworkError(statusMsg);
            }

            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var dto = JsonSerializer.Deserialize<ShopBrandingDto>(json, ReadJsonOptions);
            if (dto is null || !dto.Active)
                return new ShopRelayBrandingResult.NotFoundOrInactive(normalizedGroup);

            var verificationBase = !string.IsNullOrWhiteSpace(dto.VerificationBaseUrl)
                ? dto.VerificationBaseUrl.Trim()
                : $"{relayBase}/r";

            var branding = new ShopBranding
            {
                ShopName = dto.ShopName,
                LogoDataUri = dto.LogoDataUri,
                Phone = dto.Phone,
                Email = dto.Email,
                Website = dto.Website,
                Address = dto.Address,
                TechnicianName = dto.TechnicianName,
                WarrantyFooter = dto.WarrantyFooter,
                VerificationBaseUrl = verificationBase,
            }.Normalized();

            var resolvedGroup = SessionLaunchOptions.NormalizeGroup(dto.Group) ?? normalizedGroup;
            LogInfo($"Verified active shop '{branding.ShopName ?? resolvedGroup}' (group={resolvedGroup}) on {relayBase}");
            return new ShopRelayBrandingResult.Found(branding, resolvedGroup);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            var msg = ex is TaskCanceledException
                ? $"Timed out connecting to {relayBase}."
                : ex.Message;
            LogWarn($"FetchBrandingAsync error for '{normalizedGroup}' on {relayBase}: {msg}");
            return new ShopRelayBrandingResult.NetworkError(msg);
        }
    }

    /// <summary>Uploads a self-contained HTML certificate or service report to <c>POST {relayBase}/api/reports</c> using <c>Bearer rpd_live_...</c>.</summary>
    public async Task<ShopReportPublishResult> PublishReportAsync(
        Uri relayServerUri,
        string apiKey,
        ShopReportUploadRequest request,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(relayServerUri);
        ArgumentNullException.ThrowIfNull(request);

        var trimmedKey = apiKey?.Trim() ?? "";
        if (!trimmedKey.StartsWith(ApiKeyPrefix, StringComparison.Ordinal) || trimmedKey.Length <= ApiKeyPrefix.Length)
            return new ShopReportPublishResult.InvalidRequest("Shop API key must start with 'rpd_live_'.");

        if (string.IsNullOrWhiteSpace(request.Id) || !ReportIdRegex().IsMatch(request.Id))
            return new ShopReportPublishResult.InvalidRequest("invalid_id");

        if (!string.Equals(request.Kind, KindQaCertificate, StringComparison.Ordinal)
            && !string.Equals(request.Kind, KindServiceReport, StringComparison.Ordinal))
            return new ShopReportPublishResult.InvalidRequest("invalid_kind");

        if (string.IsNullOrWhiteSpace(request.Html))
            return new ShopReportPublishResult.InvalidRequest("empty_html");

        var relayBase = BaseUrl(relayServerUri);
        var endpoint = new Uri($"{relayBase}/api/reports", UriKind.Absolute);

        try
        {
            var payload = JsonSerializer.Serialize(request, WriteJsonOptions);
            using var req = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json"),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", trimmedKey);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (resp.StatusCode is HttpStatusCode.Created or HttpStatusCode.OK)
            {
                var created = string.IsNullOrWhiteSpace(body)
                    ? null
                    : JsonSerializer.Deserialize<ShopReportCreatedDto>(body, ReadJsonOptions);
                var id = !string.IsNullOrWhiteSpace(created?.Id) ? created.Id! : request.Id;
                var rawUrl = !string.IsNullOrWhiteSpace(created?.Url)
                    ? created.Url!
                    : $"{relayBase}/r/{Uri.EscapeDataString(id)}";
                var resolvedUrl = rawUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                    || rawUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                    ? rawUrl
                    : $"{relayBase}/{rawUrl.TrimStart('/')}";
                var shortHash = created?.ShortHash ?? (request.VerificationHash is { Length: >= 12 } vh ? vh[..12].ToLowerInvariant() : "");
                LogInfo($"Published hosted {request.Kind} id={id} url={resolvedUrl}");
                return new ShopReportPublishResult.Published(id, resolvedUrl, shortHash);
            }

            var serverError = TryReadErrorCode(body);
            if (resp.StatusCode == HttpStatusCode.Unauthorized)
                return new ShopReportPublishResult.Unauthorized(serverError ?? "unauthorized");

            if (resp.StatusCode == HttpStatusCode.PaymentRequired)
                return new ShopReportPublishResult.PaymentRequired(serverError ?? "payment_required");

            if ((int)resp.StatusCode is >= 400 and < 500)
                return new ShopReportPublishResult.InvalidRequest(serverError ?? $"HTTP {(int)resp.StatusCode}");

            var msg = $"Relay returned HTTP {(int)resp.StatusCode} ({resp.ReasonPhrase}).";
            LogWarn($"PublishReportAsync failed for '{request.Id}': {msg}");
            return new ShopReportPublishResult.NetworkError(msg);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            var msg = ex is TaskCanceledException
                ? $"Timed out uploading report to {relayBase}."
                : ex.Message;
            LogWarn($"PublishReportAsync error for '{request.Id}' on {relayBase}: {msg}");
            return new ShopReportPublishResult.NetworkError(msg);
        }
    }

    public static string ComputeSha256Hex(string content) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content ?? "")));

    public static string BuildServiceReportId(DateTimeOffset generated, string sha256Hex)
    {
        var suffix = !string.IsNullOrWhiteSpace(sha256Hex) && sha256Hex.Length >= 6
            ? sha256Hex[..6].ToUpperInvariant()
            : "000000";
        return $"SR-{generated.UtcDateTime:yyyyMMdd}-{suffix}";
    }

    public static ShopReportUploadRequest CreateQaCertificateRequest(HardwareQaSnapshot snapshot, string html)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var model = !string.Equals(snapshot.ManufacturerModel, "Not reported", StringComparison.OrdinalIgnoreCase)
            ? snapshot.ManufacturerModel
            : null;
        var serial = !string.Equals(snapshot.SerialNumber, "Not reported", StringComparison.OrdinalIgnoreCase)
            ? snapshot.SerialNumber
            : null;
        var verdict = snapshot.Verdict switch
        {
            HardwareQaVerdict.CertifiedPass => "PASS",
            HardwareQaVerdict.PassedWithNotes => "PASS_NOTES",
            HardwareQaVerdict.AttentionRequired => "ATTENTION",
            _ => "INTAKE",
        };
        var subject = model ?? snapshot.MachineName;
        return new ShopReportUploadRequest(
            Id: snapshot.CertificateId,
            Kind: KindQaCertificate,
            Title: $"Hardware QA Certificate — {subject}",
            Html: html,
            MachineName: snapshot.MachineName,
            ManufacturerModel: model,
            SerialNumber: serial,
            Verdict: verdict,
            VerificationHash: snapshot.VerificationHash);
    }

    public static ShopReportUploadRequest CreateServiceReportRequest(string machineName, string html, DateTimeOffset? generated = null)
    {
        var when = generated ?? DateTimeOffset.UtcNow;
        var hash = ComputeSha256Hex(html);
        var id = BuildServiceReportId(when, hash);
        var resolvedMachine = string.IsNullOrWhiteSpace(machineName) ? "Windows PC" : machineName.Trim();
        return new ShopReportUploadRequest(
            Id: id,
            Kind: KindServiceReport,
            Title: $"PC Service Report — {resolvedMachine}",
            Html: html,
            MachineName: resolvedMachine,
            Verdict: "COMPLETED",
            VerificationHash: hash);
    }

    private static string? TryReadErrorCode(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("error", out var errProp)
                && errProp.ValueKind == JsonValueKind.String)
                return errProp.GetString();
        }
        catch (JsonException) { }
        return null;
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_-]{2,79}$", RegexOptions.CultureInvariant)]
    private static partial Regex ReportIdRegex();
}
