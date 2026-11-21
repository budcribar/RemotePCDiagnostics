using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Shared offline SMBIOS vendor matching, strict identifier allowlists, OS build parsing,
/// and cross-platform filename sanitization for BIOS update providers.
/// </summary>
public static partial class BiosVendorIdentity
{
    private static readonly HashSet<string> WindowsReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    [GeneratedRegex(@"^(?:0[xX])?([0-9A-Fa-f]{4})$", RegexOptions.CultureInvariant)]
    private static partial Regex FourHexRegex();

    [GeneratedRegex(@"^LENOVO_MT_([A-Za-z0-9]{4})(?:_[A-Za-z0-9 ._\-/+()]*)?$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LenovoSkuMtmRegex();

    [GeneratedRegex(@"^([A-Za-z0-9]{4})$", RegexOptions.CultureInvariant)]
    private static partial Regex ExactFourAlnumRegex();

    [GeneratedRegex(@"^([A-Za-z0-9]{4})-?[A-Za-z0-9]{6}$", RegexOptions.CultureInvariant)]
    private static partial Regex TenCharMtmRegex();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._\-/+()]{0,95}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeModelTokenRegex();

    [GeneratedRegex(@"(?<![\d.])10\.0\.(\d{5,})(?!\d)", RegexOptions.CultureInvariant)]
    private static partial Regex Windows10BuildRegex();

    /// <summary>
    /// Case-insensitive word-boundary token match (alphanumeric boundaries) so short vendor
    /// tokens like <c>"HP"</c> never match <c>"Ship"</c> and <c>"MSI"</c> never matches <c>"CustomSI"</c>.
    /// </summary>
    public static bool MatchesVendorToken(string? text, string token)
    {
        if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(token))
            return false;

        var start = 0;
        while (start <= text.Length - token.Length)
        {
            var idx = text.IndexOf(token, start, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
                return false;

            var leftOk = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
            var rightIdx = idx + token.Length;
            var rightOk = rightIdx == text.Length || !char.IsLetterOrDigit(text[rightIdx]);
            if (leftOk && rightOk)
                return true;

            start = idx + 1;
        }

        return false;
    }

    /// <summary>
    /// Returns <c>true</c> if either <see cref="BiosSystemIdentity.Manufacturer"/> or
    /// <see cref="BiosSystemIdentity.BoardManufacturer"/> matches any of <paramref name="tokens"/> on word boundaries.
    /// </summary>
    public static bool MatchesVendor(BiosSystemIdentity? system, params string[] tokens)
    {
        if (system is null || tokens is null || tokens.Length == 0)
            return false;

        foreach (var token in tokens)
        {
            if (MatchesVendorToken(system.Manufacturer, token) || MatchesVendorToken(system.BoardManufacturer, token))
                return true;
        }

        return false;
    }

    public static bool IsHp(BiosSystemIdentity? system) =>
        MatchesVendor(system, "HP", "Hewlett-Packard", "Hewlett Packard");

    public static bool IsDell(BiosSystemIdentity? system) =>
        MatchesVendor(system, "Dell", "Alienware");

    public static bool IsLenovo(BiosSystemIdentity? system) =>
        MatchesVendor(system, "Lenovo");

    public static bool IsAsus(BiosSystemIdentity? system) =>
        MatchesVendor(system, "ASUS", "ASUSTeK");

    public static bool IsAcer(BiosSystemIdentity? system) =>
        MatchesVendor(system, "Acer");

    public static bool IsMsi(BiosSystemIdentity? system) =>
        MatchesVendor(system, "MSI", "Micro-Star", "Micro Star");

    public static bool IsFramework(BiosSystemIdentity? system) =>
        MatchesVendor(system, "Framework");

    /// <summary>
    /// Matches Microsoft Surface devices while explicitly excluding Hyper-V virtual machines
    /// (which also report <c>Manufacturer = "Microsoft Corporation"</c>).
    /// </summary>
    public static bool IsMicrosoftSurface(BiosSystemIdentity? system)
    {
        if (system is null)
            return false;

        if (!MatchesVendor(system, "Microsoft"))
            return false;

        if (ContainsVirtualMachine(system.Model) || ContainsVirtualMachine(system.BoardProduct))
            return false;

        return MatchesVendorToken(system.Model, "Surface") || MatchesVendorToken(system.BoardProduct, "Surface");
    }

    /// <summary>
    /// Extracts a strict 4-hex-digit uppercase identifier (stripping optional <c>0x</c> prefix).
    /// Used for HP SystemId (<c>BoardProduct</c>) and Dell SystemSku.
    /// </summary>
    public static bool TryExtractFourHex(string? value, out string hex)
    {
        hex = "";
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var match = FourHexRegex().Match(value.Trim());
        if (!match.Success)
            return false;

        hex = match.Groups[1].Value.ToUpperInvariant();
        return true;
    }

    /// <summary>
    /// Extracts a strict 4-character alphanumeric Lenovo MTM prefix from <see cref="BiosSystemIdentity.SystemSku"/>
    /// (checking <c>LENOVO_MT_XXXX_...</c> first) or <see cref="BiosSystemIdentity.Model"/>.
    /// </summary>
    public static bool TryExtractLenovoMtm(BiosSystemIdentity? system, out string mtm)
    {
        mtm = "";
        if (system is null)
            return false;

        var sku = system.SystemSku?.Trim() ?? "";
        if (sku.Length > 0)
        {
            var skuMatch = LenovoSkuMtmRegex().Match(sku);
            if (skuMatch.Success)
            {
                mtm = skuMatch.Groups[1].Value.ToUpperInvariant();
                return true;
            }
        }

        if (TryExtractLenovoMtmFromField(system.Model, out mtm))
            return true;

        return TryExtractLenovoMtmFromField(sku, out mtm);
    }

    /// <summary>
    /// Validates and trims an SMBIOS model/board token against a strict allowlist while rejecting path traversal (<c>..</c>).
    /// </summary>
    public static bool TrySanitizeModelToken(string? raw, out string token)
    {
        token = "";
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        var trimmed = raw.Trim();
        if (trimmed.Contains("..", StringComparison.Ordinal))
            return false;

        if (!SafeModelTokenRegex().IsMatch(trimmed))
            return false;

        token = trimmed;
        return true;
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="osVersion"/> indicates Windows 11 (either explicitly or via build &gt;= 22000).
    /// </summary>
    public static bool IsWindows11(string? osVersion)
    {
        if (string.IsNullOrWhiteSpace(osVersion))
            return false;

        if (osVersion.Contains("Windows 11", StringComparison.OrdinalIgnoreCase))
            return true;

        var match = Windows10BuildRegex().Match(osVersion);
        if (match.Success && int.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var build))
            return build >= 22000;

        return false;
    }

    /// <summary>
    /// Extracts a safe cross-platform filename from a URL or path, rejecting traversal, invalid characters,
    /// control characters, and Windows reserved device names.
    /// </summary>
    public static string SanitizeFileName(string? urlOrName, string fallback = "bios-update.bin")
    {
        var safeFallback = string.IsNullOrWhiteSpace(fallback) ? "bios-update.bin" : fallback.Trim();
        if (string.IsNullOrWhiteSpace(urlOrName))
            return safeFallback;

        var raw = urlOrName.Trim();
        string pathPart;
        if (Uri.TryCreate(raw, UriKind.Absolute, out var uri)
            && (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                || string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
        {
            pathPart = Uri.UnescapeDataString(uri.AbsolutePath);
        }
        else
        {
            var cutIdx = raw.IndexOfAny(['?', '#']);
            pathPart = cutIdx >= 0 ? raw[..cutIdx] : raw;
        }

        var normalized = pathPart.Replace('\\', '/').TrimEnd('/');
        var lastSlash = normalized.LastIndexOf('/');
        var candidate = lastSlash >= 0 ? normalized[(lastSlash + 1)..] : normalized;

        if (string.IsNullOrWhiteSpace(candidate))
            return safeFallback;

        var invalidChars = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(candidate.Length);
        foreach (var c in candidate)
        {
            if (char.IsControl(c) || c is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*')
                continue;
            if (Array.IndexOf(invalidChars, c) >= 0)
                continue;
            sb.Append(c);
        }

        var cleaned = TrimEdgeWhitespaceAndDots(sb.ToString());
        if (cleaned.Length > 128)
            cleaned = TrimEdgeWhitespaceAndDots(cleaned[..128]);

        if (string.IsNullOrWhiteSpace(cleaned) || cleaned is "." or "..")
            return safeFallback;

        var dotIndex = cleaned.IndexOf('.');
        var stem = TrimEdgeWhitespaceAndDots(dotIndex >= 0 ? cleaned[..dotIndex] : cleaned);
        if (string.IsNullOrWhiteSpace(stem) || WindowsReservedDeviceNames.Contains(stem))
            return safeFallback;

        return cleaned;
    }

    private static string TrimEdgeWhitespaceAndDots(string value)
    {
        var start = 0;
        var end = value.Length - 1;
        while (start <= end && (char.IsWhiteSpace(value[start]) || value[start] == '.'))
            start++;
        while (end >= start && (char.IsWhiteSpace(value[end]) || value[end] == '.'))
            end--;
        return start > end ? "" : value[start..(end + 1)];
    }

    private static bool ContainsVirtualMachine(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Contains("Virtual Machine", StringComparison.OrdinalIgnoreCase);

    private static bool TryExtractLenovoMtmFromField(string? value, out string mtm)
    {
        mtm = "";
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var trimmed = value.Trim();

        var exact = ExactFourAlnumRegex().Match(trimmed);
        if (exact.Success && trimmed.Any(char.IsAsciiDigit))
        {
            mtm = exact.Groups[1].Value.ToUpperInvariant();
            return true;
        }

        var ten = TenCharMtmRegex().Match(trimmed);
        if (ten.Success)
        {
            var prefix = ten.Groups[1].Value;
            if (prefix.Any(char.IsAsciiDigit))
            {
                mtm = prefix.ToUpperInvariant();
                return true;
            }
        }

        return false;
    }
}
