using Microsoft.Win32;
using RemotePCDiagnostics.Core.Bios;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Core.Session;

public enum AppInstallKind
{
    Standalone,
    MicrosoftStore,
}

public enum AppUpdateChannel
{
    Stable,
    Prerelease,
}

public sealed record AppUpdateInfo(
    bool UpdateAvailable,
    string InstalledVersion,
    string? LatestVersion,
    AppInstallKind InstallKind,
    string? ReleaseUrl = null,
    string? InstallerUrl = null,
    string? InstallerSha256Url = null,
    string? AgentMsiUrl = null,
    string? AgentMsiSha256Url = null,
    bool CanInstallSilently = false);

public sealed record AppUpdateProgress(string Stage, int? Percent = null, string? Message = null);

public sealed record AppUpdateResult(bool Ok, bool Restarting = false, string? Message = null, string? Error = null);

public sealed record StoreUpdateCheckResult(bool UpdateAvailable, bool CanInstallSilently, string? LatestVersion = null);

/// <summary>
/// Platform-specific Microsoft Store update bridge (implemented in the Windows Host using <c>Windows.Services.Store.StoreContext</c>).
/// </summary>
public interface IStoreUpdateBackend
{
    bool IsPackagedStoreApp { get; }
    Task<StoreUpdateCheckResult> CheckForUpdateAsync(CancellationToken ct = default);
    Task<AppUpdateResult> DownloadAndInstallAsync(Action<AppUpdateProgress>? progress = null, CancellationToken ct = default);
}

/// <summary>
/// One finished update check. <c>Error</c> is set only when the check itself failed, and it is a fixed sentence, never the exception text, a URL or a response body.
/// </summary>
public sealed record AppUpdateCheck(DateTimeOffset AtUtc, bool UpdateAvailable, string? LatestVersion, string? Error);

public interface IAppUpdateService
{
    AppUpdateInfo? Latest { get; }
    /// <summary>The last completed check in this process, or null when none has finished.</summary>
    AppUpdateCheck? LastCheck { get; }
    event Action? Changed;

    Task<AppUpdateInfo> CheckForUpdateAsync(bool force = false, CancellationToken ct = default);
    Task<AppUpdateResult> InstallUpdateAsync(Action<AppUpdateProgress>? progress = null, CancellationToken ct = default);
}

/// <summary>
/// Compares RPCD build versions (semver + optional <c>-ci.&lt;run&gt;.&lt;attempt&gt;</c>) and validates download URLs.
/// </summary>
public static class AppVersionComparer
{
    private static readonly Regex BuildVersion = new(
        @"\A(?<version>\d+\.\d+\.\d+(?:\.\d+)?)(?:-(?:ci\.(?<run>\d+)\.(?<attempt>\d+)|local))?(?:\+[0-9a-z.-]+)?\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static readonly Regex Sha256Hex = new(
        @"\b(?<hash>[0-9a-fA-F]{64})\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public const string ReleaseDownloadPrefix = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/";
    private const string ReleasePathPrefix = "/budcribar/RemotePCDiagnostics/releases/";
    private const int MaxRedirects = 5;

    private static readonly HashSet<string> AllowedRedirectHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    };

    public static AppUpdateChannel DefaultChannelFor(string? installedVersion) =>
        !string.IsNullOrWhiteSpace(installedVersion)
        && installedVersion.Contains("-ci.", StringComparison.OrdinalIgnoreCase)
            ? AppUpdateChannel.Prerelease
            : AppUpdateChannel.Stable;

    public static bool? IsNewer(string? candidate, string? installed)
    {
        if (Parse(candidate) is not { } latest || Parse(installed) is not { } current)
            return null;

        var order = latest.Version.CompareTo(current.Version);
        if (order != 0)
            return order > 0;

        if (latest.Run is not int latestRun || current.Run is not int currentRun)
            return null;

        return (latestRun, latest.Attempt).CompareTo((currentRun, current.Attempt)) > 0;
    }

    /// <summary>
    /// The comparable build identity: no leading <c>v</c>, no <c>+commit</c> metadata.
    /// Null when <paramref name="value"/> is not an RPCD version.
    /// </summary>
    public static string? Normalize(string? value)
    {
        if (Parse(value) is null || string.IsNullOrWhiteSpace(value))
            return null;
        var trimmed = value.Trim().TrimStart('v', 'V');
        var plus = trimmed.IndexOf('+');
        if (plus > 0)
            trimmed = trimmed[..plus];
        return trimmed;
    }

    public static bool IsTrustedDownloadUrl(string? url)
    {
        if (!TryStrictHttpsUri(url, out var uri)
            || !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase)
            || uri.Query.Length > 0)
            return false;
        var trimmed = url!.Trim();
        if (!trimmed.StartsWith(ReleaseDownloadPrefix, StringComparison.Ordinal))
            return false;
        var rest = trimmed[ReleaseDownloadPrefix.Length..];
        var parts = rest.Split('/');
        return parts.Length == 2 && parts.All(p => p.Length > 0 && p != "." && p != "..");
    }

    public static bool IsAllowedRedirectUrl(Uri? target)
    {
        if (target is null || !target.IsAbsoluteUri)
            return false;
        if (!TryStrictHttpsUri(target.OriginalString, out var uri))
            return false;
        if (!AllowedRedirectHosts.Contains(uri.Host))
            return false;
        return !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase)
            || uri.AbsolutePath.StartsWith(ReleasePathPrefix, StringComparison.Ordinal);
    }

    public static Uri? ResolveAllowedRedirect(Uri requestUri, Uri? location)
    {
        if (requestUri is null || !requestUri.IsAbsoluteUri || location is null)
            return null;
        var raw = location.OriginalString;
        if (string.IsNullOrEmpty(raw) || raw.Length > 4096 || raw.Any(char.IsWhiteSpace) || raw.Contains('\\') || raw.Contains('#'))
            return null;
        Uri? target;
        if (location.IsAbsoluteUri)
        {
            target = location;
        }
        else
        {
            if (raw.StartsWith("//", StringComparison.Ordinal))
                return null;
            if (!Uri.TryCreate(requestUri, location, out target))
                return null;
        }
        return IsAllowedRedirectUrl(target) ? target : null;
    }

    private static bool TryStrictHttpsUri(string? url, out Uri uri)
    {
        uri = null!;
        if (string.IsNullOrWhiteSpace(url))
            return false;
        var trimmed = url.Trim();
        if (trimmed.Length > 4096 || trimmed.Any(char.IsWhiteSpace) || trimmed.Contains('\\'))
            return false;
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var u))
            return false;
        if (!string.Equals(u.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !u.IsDefaultPort
            || u.UserInfo.Length > 0
            || u.Fragment.Length > 0)
            return false;
        var pathStart = trimmed.IndexOf('/', "https://".Length);
        var path = pathStart < 0 ? "/" : trimmed[pathStart..];
        var q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        if (path.Split('/').Any(s => s is "." or "..")
            || path.Contains("%2e", StringComparison.OrdinalIgnoreCase)
            || path.Contains("%2f", StringComparison.OrdinalIgnoreCase)
            || path.Contains("%5c", StringComparison.OrdinalIgnoreCase))
            return false;
        if (string.Equals(u.Host, "github.com", StringComparison.OrdinalIgnoreCase) && path.Contains('%'))
            return false;
        uri = u;
        return true;
    }

    public static string? ParseSha256Text(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        var match = Sha256Hex.Match(text);
        return match.Success ? match.Groups["hash"].Value.ToLowerInvariant() : null;
    }

    private static (Version Version, int? Run, int Attempt)? Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var match = BuildVersion.Match(value.Trim().TrimStart('v', 'V'));
        if (!match.Success || !Version.TryParse(match.Groups["version"].Value, out var version))
            return null;

        var normalized = new Version(version.Major, version.Minor, version.Build, Math.Max(version.Revision, 0));
        if (!match.Groups["run"].Success)
            return (normalized, null, 0);

        if (!int.TryParse(match.Groups["run"].Value, out var run)
            || !int.TryParse(match.Groups["attempt"].Value, out var attempt))
            return null;

        return (normalized, run, attempt);
    }
}

/// <summary>
/// Shared feed reader, download, and SHA-256 verification helper used by both <see cref="AppUpdateService"/> and
/// <c>RemotePCDiagnostics.Agent</c>'s elevated self-updater.
/// </summary>
public static class AppUpdateInstaller
{
    public const string DefaultFeedUrl = "https://admin.remoteblazorwebview.com/api/rpcd/latest";
    public const string FeedUrlEnvVar = "RPD_UPDATE_FEED_URL";
    public const long MaxInstallerBytes = 512L * 1024 * 1024;
    private const int MaxRedirects = 5;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public sealed record ReleaseFeedChannel(
        string? Version,
        string? ReleaseUrl,
        string? InstallerUrl,
        string? InstallerSha256Url,
        string? AgentMsiUrl,
        string? AgentMsiSha256Url,
        string? Arm64InstallerUrl = null,
        string? Arm64InstallerSha256Url = null,
        string? Arm64AgentMsiUrl = null,
        string? Arm64AgentMsiSha256Url = null)
    {
        public (string? InstallerUrl, string? InstallerSha256Url, string? AgentMsiUrl, string? AgentMsiSha256Url) ResolveDownloads(Architecture osArch)
        {
            if (osArch == Architecture.Arm64)
            {
                var instUrl = !string.IsNullOrWhiteSpace(Arm64InstallerUrl) ? Arm64InstallerUrl : InstallerUrl;
                var instSha = !string.IsNullOrWhiteSpace(Arm64InstallerUrl) ? Arm64InstallerSha256Url : InstallerSha256Url;
                var msiUrl = !string.IsNullOrWhiteSpace(Arm64AgentMsiUrl) ? Arm64AgentMsiUrl : AgentMsiUrl;
                var msiSha = !string.IsNullOrWhiteSpace(Arm64AgentMsiUrl) ? Arm64AgentMsiSha256Url : AgentMsiSha256Url;
                return (instUrl, instSha, msiUrl, msiSha);
            }
            return (InstallerUrl, InstallerSha256Url, AgentMsiUrl, AgentMsiSha256Url);
        }
    }

    public sealed record ReleaseFeed(ReleaseFeedChannel? Stable, ReleaseFeedChannel? Prerelease);

    /// <summary>Setup switch (see installer/RemotePCDiagnostics.iss): the Agent MSI Setup runs after it installs the app.</summary>
    public const string SetupAgentMsiParam = "AGENTMSI";

    /// <summary>Setup switch (see installer/RemotePCDiagnostics.iss): the app's command line Setup starts it with when it is done.</summary>
    public const string SetupRelaunchArgsParam = "RELAUNCHARGS";

    /// <summary>
    /// The Setup command line for an in-app update. Setup does the whole job, because it is the one process that outlives the
    /// app: Inno Setup closes the app (and with it the elevated helper that started Setup), so a follow-up step left to the
    /// helper never runs. With <paramref name="agentMsiPath"/>, Setup upgrades the persistent agent service after the app;
    /// with <paramref name="relaunchArguments"/>, it starts the app again with them, so a remote session comes back.
    /// Values with a double quote are left out, since Inno Setup cannot take them inside a quoted parameter.
    /// </summary>
    /// <summary>Setup switch: <c>install</c> the agent service again without replacing enrollment, consent, or lifetime.</summary>
    public const string SetupPreserveAgentParam = "PRESERVEAGENT";

    public static string BuildSetupArguments(
        bool verySilent,
        string? agentMsiPath,
        IReadOnlyList<string>? relaunchArguments,
        bool preserveAgentSettings = false,
        string? logPath = null,
        bool forceCloseApplications = false)
    {
        var parts = new List<string>
        {
            verySilent ? "/VERYSILENT" : "/SILENT",
            "/SUPPRESSMSGBOXES",
            "/CLOSEAPPLICATIONS",
            "/NORESTART",
        };
        // Silent Setup otherwise asks a locked file to close and, with /SUPPRESSMSGBOXES, answers Abort.
        if (forceCloseApplications)
            parts.Add("/FORCECLOSEAPPLICATIONS");
        if (preserveAgentSettings)
            parts.Add($"/{SetupPreserveAgentParam}");
        if (!string.IsNullOrWhiteSpace(agentMsiPath) && !agentMsiPath.Contains('"'))
            parts.Add($"\"/{SetupAgentMsiParam}={agentMsiPath}\"");
        if (relaunchArguments is { Count: > 0 } && relaunchArguments.All(a => !a.Contains('"')))
            parts.Add($"\"/{SetupRelaunchArgsParam}={string.Join(' ', relaunchArguments)}\"");
        // Always last so a path with spaces stays one argument. A quote in the path is refused: /LOG would make Setup exit 1.
        if (RpcdSetupLog.LogSwitch(logPath) is { } logSwitch)
            parts.Add(logSwitch);
        return string.Join(' ', parts);
    }

    public static string ResolveFeedUrl(string? configuredUrl = null, bool allowEnvOverride = true)
    {
        if (allowEnvOverride)
        {
            var env = Environment.GetEnvironmentVariable(FeedUrlEnvVar);
            if (!string.IsNullOrWhiteSpace(env))
                return env.Trim();
        }
        return string.IsNullOrWhiteSpace(configuredUrl) ? DefaultFeedUrl : configuredUrl.Trim();
    }

    public static async Task<ReleaseFeed?> FetchFeedAsync(HttpClient http, string feedUrl, CancellationToken ct)
    {
        using var response = await http.GetAsync(feedUrl, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            return null;
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<ReleaseFeed>(stream, Json, ct).ConfigureAwait(false);
    }

    private static async Task<HttpResponseMessage> GetFollowingAllowedRedirectsAsync(
        HttpClient http,
        string initialUrl,
        HttpCompletionOption completionOption,
        CancellationToken ct)
    {
        var current = new Uri(initialUrl, UriKind.Absolute);
        for (var hop = 0; hop <= MaxRedirects; hop++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, current);
            var response = await http.SendAsync(req, completionOption, ct).ConfigureAwait(false);
            if ((int)response.StatusCode is >= 300 and < 400)
            {
                var location = response.Headers.Location;
                response.Dispose();
                current = AppVersionComparer.ResolveAllowedRedirect(current, location)
                    ?? throw new InvalidOperationException("Update download redirect pointed to an untrusted host.");
                continue;
            }
            return response;
        }
        throw new InvalidOperationException("Too many redirects while downloading update.");
    }

    public const string MissingChecksumMessage = "The GitHub release has no SHA-256 checksum for the installer. The update was not installed.";

    /// <summary>
    /// Downloads an installer from a trusted release URL into <paramref name="stagingDirectory"/> and checks it against the
    /// release's <c>.sha256</c> file. Throws when there is no checksum URL, the checksum can't be read, or it doesn't match.
    /// </summary>
    public static async Task<string> DownloadAndVerifyAsync(
        HttpClient http,
        string downloadUrl,
        string? sha256Url,
        string stagingDirectory,
        Action<AppUpdateProgress>? progress,
        CancellationToken ct)
    {
        if (!AppVersionComparer.IsTrustedDownloadUrl(downloadUrl))
            throw new InvalidOperationException("Refusing to download update from an untrusted URL.");
        // Every caller runs the result elevated (Setup installs per machine and runs the Agent MSI), so a checksum is always required.
        if (string.IsNullOrWhiteSpace(sha256Url))
            throw new InvalidOperationException(MissingChecksumMessage);
        if (!AppVersionComparer.IsTrustedDownloadUrl(sha256Url))
            throw new InvalidOperationException("Refusing to download checksum from an untrusted URL.");

        Directory.CreateDirectory(stagingDirectory);
        var fileName = Path.GetFileName(new Uri(downloadUrl).AbsolutePath);
        if (string.IsNullOrWhiteSpace(fileName))
            fileName = "RemotePCDiagnostics-Setup.exe";
        var targetPath = Path.Combine(stagingDirectory, fileName);
        var tempPath = targetPath + ".part";

        try
        {
            progress?.Invoke(new AppUpdateProgress("downloading", 0, $"Downloading {fileName}..."));
            using (var response = await GetFollowingAllowedRedirectsAsync(http, downloadUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                var totalBytes = response.Content.Headers.ContentLength;
                if (totalBytes is > MaxInstallerBytes)
                    throw new InvalidOperationException("Update installer exceeds maximum allowed size.");

                await using var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                await using var dest = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                var buffer = new byte[81920];
                long downloaded = 0;
                int lastPercent = -1;
                int read;
                while ((read = await source.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                {
                    downloaded += read;
                    if (downloaded > MaxInstallerBytes)
                        throw new InvalidOperationException("Update installer exceeds maximum allowed size.");
                    await dest.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                    if (totalBytes is > 0)
                    {
                        var percent = (int)Math.Clamp(downloaded * 100L / totalBytes.Value, 0, 100);
                        if (percent != lastPercent)
                        {
                            lastPercent = percent;
                            progress?.Invoke(new AppUpdateProgress("downloading", percent, $"Downloading {fileName} ({percent}%)..."));
                        }
                    }
                }
            }

            progress?.Invoke(new AppUpdateProgress("verifying", null, "Verifying SHA-256 checksum..."));
            using (var shaResp = await GetFollowingAllowedRedirectsAsync(http, sha256Url, HttpCompletionOption.ResponseContentRead, ct).ConfigureAwait(false))
            {
                shaResp.EnsureSuccessStatusCode();
                var shaText = await shaResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                var expected = AppVersionComparer.ParseSha256Text(shaText)
                    ?? throw new InvalidOperationException("Could not parse SHA-256 checksum for update installer.");

                var actual = await ComputeFileSha256Async(tempPath, ct).ConfigureAwait(false);
                if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Update installer failed SHA-256 verification.");
            }

            File.Move(tempPath, targetPath, overwrite: true);
            return targetPath;
        }
        catch
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            throw;
        }
    }

    /// <summary>
    /// Downloads the Agent MSI the way <c>AgentSelfUpdater</c> and <see cref="AppUpdateService"/> do.
    /// <paramref name="required"/> false keeps that path: a missing URL, a missing checksum, or a failed check returns null
    /// (nothing unverified is handed to Setup) and <paramref name="onSkipped"/> hears why. <paramref name="required"/> true is the remote update: no MSI, no checksum,
    /// or a failed check throws, and the caller must not report success.
    /// </summary>
    public static async Task<string?> DownloadAgentMsiAsync(
        HttpClient http,
        string? msiUrl,
        string? sha256Url,
        string stagingDirectory,
        bool required,
        Action<AppUpdateProgress>? progress,
        Action<string>? onSkipped,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(msiUrl))
        {
            if (!required)
                return null;
            throw new InvalidOperationException("The GitHub release has no Agent MSI for this version. The update was not installed.");
        }

        if (required && string.IsNullOrWhiteSpace(sha256Url))
            throw new InvalidOperationException(RpcdGitHubRelease.AgentMsiChecksumMissing);

        try
        {
            return await DownloadAndVerifyAsync(http, msiUrl, sha256Url, stagingDirectory, progress, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (!required)
            {
                onSkipped?.Invoke(ex.Message);
                return null;
            }
            throw new InvalidOperationException("The Agent MSI could not be verified. The update was not installed. " + ex.Message, ex);
        }
    }

    public static async Task VerifyPublisherAsync(string path, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("Publisher verification requires Windows.");

        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var policy = machine.OpenSubKey(@"SOFTWARE\Policies\RemotePCDiagnostics");
        var pin = (policy?.GetValue("UpdateSignerSha256") as string)?.Trim();
        if (pin is null || pin.Length != 64 || !pin.All(Uri.IsHexDigit))
            throw new InvalidOperationException("The Remote PC Diagnostics update signer policy is missing or invalid.");

        if (!await WinVerifyTrustSignatureVerifier.Instance.VerifyPinnedPublisherAsync(path, pin, ct).ConfigureAwait(false))
            throw new InvalidOperationException("The update package was not signed by the trusted Remote PC Diagnostics publisher.");
    }

    public static async Task<string> ComputeFileSha256Async(string filePath, CancellationToken ct)
    {
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexStringLower(hash);
    }
}

/// <summary>
/// Unified RPCD update service supporting Microsoft Store (MSIX <c>StoreContext</c>), elevated Agent silent upgrades
/// (for remote technicians with zero UAC), and standalone local Inno Setup upgrades.
/// </summary>
public sealed class AppUpdateService : IAppUpdateService, IDisposable
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(15);

    private readonly string _installedVersion;
    private readonly AppUpdateChannel _channel;
    private readonly string _feedUrl;
    private readonly IStoreUpdateBackend? _storeBackend;
    private readonly Func<IElevatedCommandBridge?>? _getElevatedBridge;
    private readonly Action? _onExitForUpdate;
    private readonly Func<IReadOnlyList<string>?>? _getRelaunchArguments;
    private readonly IElevationContext? _elevation;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ILogger? _log;
    private readonly SemaphoreSlim _checkLock = new(1, 1);

    private AppUpdateInfo? _latest;
    private AppUpdateCheck? _lastCheck;
    private DateTimeOffset _checkedAtUtc;

    public AppUpdateInfo? Latest => Volatile.Read(ref _latest);
    public AppUpdateCheck? LastCheck => Volatile.Read(ref _lastCheck);
    public event Action? Changed;

    public AppUpdateService(
        string installedVersion,
        AppUpdateChannel channel = AppUpdateChannel.Stable,
        string? feedUrl = null,
        IStoreUpdateBackend? storeBackend = null,
        Func<IElevatedCommandBridge?>? getElevatedBridge = null,
        Action? onExitForUpdate = null,
        HttpClient? httpClient = null,
        ILogger? log = null,
        Func<IReadOnlyList<string>?>? getRelaunchArguments = null,
        IElevationContext? elevation = null)
    {
        _installedVersion = installedVersion;
        _channel = channel;
        _feedUrl = AppUpdateInstaller.ResolveFeedUrl(feedUrl);
        _storeBackend = storeBackend;
        _getElevatedBridge = getElevatedBridge;
        _onExitForUpdate = onExitForUpdate;
        _getRelaunchArguments = getRelaunchArguments;
        _elevation = elevation;
        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(15) };
        _log = log;
    }

    public async Task<AppUpdateInfo> CheckForUpdateAsync(bool force = false, CancellationToken ct = default)
    {
        await _checkLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!force && _latest is not null && DateTimeOffset.UtcNow - _checkedAtUtc < CacheDuration)
                return _latest;

            AppUpdateInfo info;
            var failed = false;
            if (_storeBackend is { IsPackagedStoreApp: true })
            {
                try
                {
                    var store = await _storeBackend.CheckForUpdateAsync(ct).ConfigureAwait(false);
                    info = new AppUpdateInfo(
                        UpdateAvailable: store.UpdateAvailable,
                        InstalledVersion: _installedVersion,
                        LatestVersion: store.LatestVersion,
                        InstallKind: AppInstallKind.MicrosoftStore,
                        CanInstallSilently: store.CanInstallSilently);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log?.Warn($"[app-update] Microsoft Store update check failed: {ex.Message}");
                    failed = true;
                    info = new AppUpdateInfo(false, _installedVersion, null, AppInstallKind.MicrosoftStore);
                }
            }
            else
            {
                try
                {
                    var feed = await AppUpdateInstaller.FetchFeedAsync(_http, _feedUrl, ct).ConfigureAwait(false);
                    var selected = _channel == AppUpdateChannel.Prerelease ? feed?.Prerelease : feed?.Stable;
                    var isNewer = AppVersionComparer.IsNewer(selected?.Version, _installedVersion) == true;
                    var hasAgentBridge = _elevation is not { HasAdminCapabilities: false } &&
                        _getElevatedBridge?.Invoke()?.IsConnected == true;
                    var downloads = selected?.ResolveDownloads(RuntimeInformation.OSArchitecture);
                    info = new AppUpdateInfo(
                        UpdateAvailable: isNewer,
                        InstalledVersion: _installedVersion,
                        LatestVersion: selected?.Version,
                        InstallKind: AppInstallKind.Standalone,
                        ReleaseUrl: selected?.ReleaseUrl,
                        InstallerUrl: downloads?.InstallerUrl,
                        InstallerSha256Url: downloads?.InstallerSha256Url,
                        AgentMsiUrl: downloads?.AgentMsiUrl,
                        AgentMsiSha256Url: downloads?.AgentMsiSha256Url,
                        CanInstallSilently: hasAgentBridge);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log?.Warn($"[app-update] Release feed check failed: {ex.Message}");
                    failed = true;
                    info = new AppUpdateInfo(false, _installedVersion, null, AppInstallKind.Standalone);
                }
            }

            var checkedAt = DateTimeOffset.UtcNow;
            Volatile.Write(ref _latest, info);
            // The About page publishes this. Keep the exception, the feed URL and the installer URLs out of it.
            Volatile.Write(ref _lastCheck, new AppUpdateCheck(checkedAt, info.UpdateAvailable, failed ? null : info.LatestVersion,
                failed ? "Update check failed." : null));
            _checkedAtUtc = checkedAt;
            Changed?.Invoke();
            return info;
        }
        finally
        {
            _checkLock.Release();
        }
    }

    public async Task<AppUpdateResult> InstallUpdateAsync(Action<AppUpdateProgress>? progress = null, CancellationToken ct = default)
    {
        var info = Latest ?? await CheckForUpdateAsync(force: true, ct).ConfigureAwait(false);
        if (!info.UpdateAvailable)
            return new AppUpdateResult(false, Error: "Remote PC Diagnostics is already up to date.");

        if (info.InstallKind == AppInstallKind.MicrosoftStore)
        {
            if (_storeBackend is null)
                return new AppUpdateResult(false, Error: "Microsoft Store update backend is not available.");
            return await _storeBackend.DownloadAndInstallAsync(progress, ct).ConfigureAwait(false);
        }

        // Setup starts the app again with this command line once it is done, so a remote session comes back after the update.
        IReadOnlyList<string>? relaunchArgs = null;
        try { relaunchArgs = _getRelaunchArguments?.Invoke(); }
        catch (Exception ex) { _log?.Warn($"[app-update] Could not build the relaunch command line: {ex.Message}"); }

        // Only the elevated helper downloads and stages packages for execution.
        if (_elevation is { HasAdminCapabilities: false })
        {
            var approval = await _elevation.EnableAdminModeAsync(ct).ConfigureAwait(false);
            if (!approval.Success)
                return new AppUpdateResult(false, Error: approval.Message);
        }

        var bridge = _getElevatedBridge?.Invoke();
        if (bridge is not { IsConnected: true })
            return new AppUpdateResult(false, Error: "The elevated update helper is unavailable.");

        progress?.Invoke(new AppUpdateProgress("installing", null, "Downloading and installing update via elevated agent..."));
        var result = await bridge.SelfUpdateAsync(_channel, relaunchArgs, ct).ConfigureAwait(false);
        if (result is { Ok: true, Restarting: true })
            _onExitForUpdate?.Invoke();
        return result ?? new AppUpdateResult(false, Error: "The elevated update helper disconnected.");
    }

    public void Dispose()
    {
        _checkLock.Dispose();
        if (_ownsHttp)
            _http.Dispose();
    }
}
