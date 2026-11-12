using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// White-label repair shop or refurbisher identity embedded into self-contained HTML client reports and 1-page buyer Hardware QA
/// certificates. Stored locally in <see cref="Preferences.UserPreferences.Branding"/> (and later synced from the relay shop profile)
/// and snapshotted onto <see cref="WorkflowState.Branding"/> when a report is written.
/// </summary>
public sealed partial record ShopBranding
{
    /// <summary>Maximum allowed length of an inline base64 raster <c>data:image/...</c> URI (~60 KB binary image).</summary>
    public const int MaxLogoDataUriLength = 80_000;

    public string? ShopName { get; init; }
    /// <summary>Self-contained <c>data:image/(png|jpeg|jpg|webp|gif);base64,...</c> URI so offline/printed HTML reports never fetch external images.</summary>
    public string? LogoDataUri { get; init; }
    public string? Phone { get; init; }
    public string? Email { get; init; }
    public string? Website { get; init; }
    public string? Address { get; init; }
    public string? TechnicianName { get; init; }
    public string? TechnicianNotes { get; init; }
    public string? WarrantyFooter { get; init; }
    /// <summary>Optional base URL (e.g. <c>https://reports.example.com/r</c>) encoded into buyer QR certificates when hosted verification is enabled.</summary>
    public string? VerificationBaseUrl { get; init; }

    public string? SafeLogoDataUri => SanitizeLogoDataUri(LogoDataUri);
    public string? SafeWebsiteHref => SanitizeHttpUrl(Website);
    public string? SafeVerificationBaseUrl => SanitizeHttpUrl(VerificationBaseUrl)?.TrimEnd('/');

    public bool HasHeader =>
        !string.IsNullOrWhiteSpace(ShopName)
        || SafeLogoDataUri is not null
        || !string.IsNullOrWhiteSpace(Phone)
        || !string.IsNullOrWhiteSpace(Email)
        || SafeWebsiteHref is not null
        || !string.IsNullOrWhiteSpace(Address);

    public bool HasAny =>
        HasHeader
        || !string.IsNullOrWhiteSpace(TechnicianName)
        || !string.IsNullOrWhiteSpace(TechnicianNotes)
        || !string.IsNullOrWhiteSpace(WarrantyFooter);

    public ShopBranding Normalized() => new()
    {
        ShopName = TrimOrNull(ShopName, 120),
        LogoDataUri = SanitizeLogoDataUri(LogoDataUri),
        Phone = TrimOrNull(Phone, 60),
        Email = TrimOrNull(Email, 120),
        Website = TrimOrNull(Website, 200),
        Address = TrimOrNull(Address, 200),
        TechnicianName = TrimOrNull(TechnicianName, 80),
        TechnicianNotes = TrimOrNull(TechnicianNotes, 2_000),
        WarrantyFooter = TrimOrNull(WarrantyFooter, 500),
        VerificationBaseUrl = TrimOrNull(VerificationBaseUrl, 200),
    };

    /// <summary>
    /// Accepts only bounded base64 raster <c>data:image/(png|jpeg|jpg|webp|gif);base64,...</c> URIs. Rejects <c>image/svg+xml</c>,
    /// <c>http(s):</c> tracking pixels, and script URIs so reports stay 100% self-contained and XSS-safe.
    /// </summary>
    public static string? SanitizeLogoDataUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        if (trimmed.Length > MaxLogoDataUriLength) return null;
        return RasterDataUriRegex().IsMatch(trimmed) ? trimmed : null;
    }

    /// <summary>
    /// Normalizes a website or verification URL to an <c>http://</c> or <c>https://</c> absolute URI, prepending <c>https://</c>
    /// when a bare domain like <c>acmerepair.com</c> is entered, and rejecting <c>javascript:</c>, <c>data:</c>, or malformed URIs.
    /// </summary>
    public static string? SanitizeHttpUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        if (trimmed.Length > 300 || trimmed.Any(char.IsWhiteSpace)) return null;
        var candidate = trimmed.Contains("://", StringComparison.Ordinal) ? trimmed : "https://" + trimmed;
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) return null;
        if (string.IsNullOrWhiteSpace(uri.Host) || !uri.Host.Contains('.', StringComparison.Ordinal) && !string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
            return null;
        return uri.AbsoluteUri;
    }

    private static string? TrimOrNull(string? s, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var t = s.Trim();
        return t.Length <= maxLength ? t : t[..maxLength].TrimEnd();
    }

    [GeneratedRegex(@"^data:image/(?:png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=\r\n]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RasterDataUriRegex();
}
