namespace RemotePCDiagnostics.Agent.Core;

/// <summary>Where the agent may download from: the RemotePCDiagnostics GitHub releases, and GitHub's release-asset hosts on redirects.</summary>
public static class ReleaseUrls
{
    public const string Repo = "budcribar/RemotePCDiagnostics";
    public const string ManifestUrl = "https://github.com/" + Repo + "/releases/latest/download/manifest.json";
    public const string SignatureUrl = "https://github.com/" + Repo + "/releases/latest/download/manifest.sig";
    /// <summary>Every manifest <c>url</c> must start with this.</summary>
    public const string DownloadPrefix = "https://github.com/" + Repo + "/releases/download/";
    public const int MaxRedirects = 5;

    private static readonly string[] RedirectHosts = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];

    /// <summary>True for <c>https://github.com/budcribar/RemotePCDiagnostics/releases/download/&lt;tag&gt;/&lt;file&gt;</c> (no user info, port,
    /// query, fragment, dot segments or escapes in the path).</summary>
    public static bool IsReleaseDownloadUrl(string? url)
    {
        if (!TryStrict(url, out var uri) || uri.Host != "github.com" || uri.Query.Length > 0) return false;
        if (!url!.StartsWith(DownloadPrefix, StringComparison.Ordinal)) return false;
        // Exactly <tag>/<file> after the prefix.
        var rest = url[DownloadPrefix.Length..];
        var parts = rest.Split('/');
        return parts.Length == 2 && parts.All(p => p.Length > 0 && p != "." && p != "..");
    }

    /// <summary>True when a redirect from a release URL may be followed: https to github.com or GitHub's release-asset hosts.</summary>
    public static bool IsAllowedRedirect(Uri? target)
    {
        if (target is null || !target.IsAbsoluteUri) return false;
        if (!TryStrict(target.OriginalString, out var uri)) return false;
        if (!RedirectHosts.Contains(uri.Host)) return false;
        // On github.com itself stay inside this repo's releases.
        return uri.Host != "github.com" || uri.AbsolutePath.StartsWith("/" + Repo + "/releases/", StringComparison.Ordinal);
    }

    /// <summary>Resolves a Location header against the request URL and checks it.</summary>
    public static Uri? ResolveRedirect(Uri requestUri, Uri? location)
    {
        if (location is null) return null;
        var target = location.IsAbsoluteUri ? location : new Uri(requestUri, location);
        return IsAllowedRedirect(target) ? target : null;
    }

    private static bool TryStrict(string? url, out Uri uri)
    {
        uri = null!;
        if (string.IsNullOrEmpty(url) || url.Length > 4096 || url.Any(char.IsWhiteSpace) || url.Contains('\\')) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
        if (u.Scheme != Uri.UriSchemeHttps || !u.IsDefaultPort || u.UserInfo.Length > 0 || u.Fragment.Length > 0) return false;
        // Reject dot segments and percent-escapes in the path (Uri would silently normalise "a/../b").
        var pathStart = url.IndexOf('/', "https://".Length);
        var path = pathStart < 0 ? "/" : url[pathStart..];
        var q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        if (path.Contains("/./", StringComparison.Ordinal) || path.Contains("/../", StringComparison.Ordinal) || path.EndsWith("/..", StringComparison.Ordinal)
            || path.EndsWith("/.", StringComparison.Ordinal)) return false;
        if (u.Host == "github.com" && path.Contains('%')) return false;
        uri = u;
        return true;
    }
}
