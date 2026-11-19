using System.Diagnostics;
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

public interface IAppUpdateService
{
    AppUpdateInfo? Latest { get; }
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

    private static readonly HashSet<string> TrustedDownloadHosts = new(StringComparer.OrdinalIgnoreCase)
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

    public static bool IsTrustedDownloadUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return false;
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return false;
        return TrustedDownloadHosts.Contains(uri.Host);
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

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public sealed record ReleaseFeedChannel(
        string? Version,
        string? ReleaseUrl,
        string? InstallerUrl,
        string? InstallerSha256Url,
        string? AgentMsiUrl,
        string? AgentMsiSha256Url);

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
    public static string BuildSetupArguments(bool verySilent, string? agentMsiPath, IReadOnlyList<string>? relaunchArguments)
    {
        var parts = new List<string>
        {
            verySilent ? "/VERYSILENT" : "/SILENT",
            "/SUPPRESSMSGBOXES",
            "/CLOSEAPPLICATIONS",
            "/NORESTART",
        };
        if (!string.IsNullOrWhiteSpace(agentMsiPath) && !agentMsiPath.Contains('"'))
            parts.Add($"\"/{SetupAgentMsiParam}={agentMsiPath}\"");
        if (relaunchArguments is { Count: > 0 } && relaunchArguments.All(a => !a.Contains('"')))
            parts.Add($"\"/{SetupRelaunchArgsParam}={string.Join(' ', relaunchArguments)}\"");
        return string.Join(' ', parts);
    }

    public static string ResolveFeedUrl(string? configuredUrl = null)
    {
        var env = Environment.GetEnvironmentVariable(FeedUrlEnvVar);
        if (!string.IsNullOrWhiteSpace(env))
            return env.Trim();
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
        if (!string.IsNullOrWhiteSpace(sha256Url) && !AppVersionComparer.IsTrustedDownloadUrl(sha256Url))
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
            using (var response = await http.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
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

            if (!string.IsNullOrWhiteSpace(sha256Url))
            {
                progress?.Invoke(new AppUpdateProgress("verifying", null, "Verifying SHA-256 checksum..."));
                var shaText = await http.GetStringAsync(sha256Url, ct).ConfigureAwait(false);
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
    private readonly Func<bool> _agentServiceInstalled;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ILogger? _log;
    private readonly SemaphoreSlim _checkLock = new(1, 1);

    private AppUpdateInfo? _latest;
    private DateTimeOffset _checkedAtUtc;

    public AppUpdateInfo? Latest => Volatile.Read(ref _latest);
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
        Func<bool>? agentServiceInstalled = null)
    {
        _installedVersion = installedVersion;
        _channel = channel;
        _feedUrl = AppUpdateInstaller.ResolveFeedUrl(feedUrl);
        _storeBackend = storeBackend;
        _getElevatedBridge = getElevatedBridge;
        _onExitForUpdate = onExitForUpdate;
        _getRelaunchArguments = getRelaunchArguments;
        _agentServiceInstalled = agentServiceInstalled ?? (() => File.Exists(AgentLayout.DefaultAgentExe()));
        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
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
                    var hasAgentBridge = _getElevatedBridge?.Invoke()?.IsConnected == true;
                    info = new AppUpdateInfo(
                        UpdateAvailable: isNewer,
                        InstalledVersion: _installedVersion,
                        LatestVersion: selected?.Version,
                        InstallKind: AppInstallKind.Standalone,
                        ReleaseUrl: selected?.ReleaseUrl,
                        InstallerUrl: selected?.InstallerUrl,
                        InstallerSha256Url: selected?.InstallerSha256Url,
                        AgentMsiUrl: selected?.AgentMsiUrl,
                        AgentMsiSha256Url: selected?.AgentMsiSha256Url,
                        CanInstallSilently: hasAgentBridge);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log?.Warn($"[app-update] Release feed check failed: {ex.Message}");
                    info = new AppUpdateInfo(false, _installedVersion, null, AppInstallKind.Standalone);
                }
            }

            Volatile.Write(ref _latest, info);
            _checkedAtUtc = DateTimeOffset.UtcNow;
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

        // Prefer the elevated Agent pipe when connected (remote technicians get a zero-UAC silent upgrade).
        var bridge = _getElevatedBridge?.Invoke();
        if (bridge is { IsConnected: true })
        {
            progress?.Invoke(new AppUpdateProgress("installing", null, "Downloading and installing update via elevated agent..."));
            var agentResult = await bridge.SelfUpdateAsync(_channel, relaunchArgs, ct).ConfigureAwait(false);
            if (agentResult is not null)
            {
                if (agentResult.Ok && agentResult.Restarting)
                    _onExitForUpdate?.Invoke();
                return agentResult;
            }
        }

        if (string.IsNullOrWhiteSpace(info.InstallerUrl))
            return new AppUpdateResult(false, Error: "No installer download URL is available for this release.");

        try
        {
            var stagingDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "RemotePCDiagnostics",
                "Updates");
            var installerPath = await AppUpdateInstaller.DownloadAndVerifyAsync(
                _http, info.InstallerUrl, info.InstallerSha256Url, stagingDir, progress, ct).ConfigureAwait(false);

            // The persistent agent service is upgraded by Setup too (it runs elevated), so it does not stay on the old build.
            string? agentMsiPath = null;
            if (!string.IsNullOrWhiteSpace(info.AgentMsiUrl) && _agentServiceInstalled())
            {
                try
                {
                    agentMsiPath = await AppUpdateInstaller.DownloadAndVerifyAsync(
                        _http, info.AgentMsiUrl, info.AgentMsiSha256Url, stagingDir, progress: null, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log?.Warn($"[app-update] Agent MSI download/verification skipped: {ex.Message}");
                }
            }

            progress?.Invoke(new AppUpdateProgress("installing", 100, "Launching installer..."));
            var psi = new ProcessStartInfo
            {
                FileName = installerPath,
                Arguments = AppUpdateInstaller.BuildSetupArguments(verySilent: false, agentMsiPath, relaunchArgs),
                UseShellExecute = true,
                WorkingDirectory = stagingDir,
            };
            var proc = Process.Start(psi);
            if (proc is null)
                return new AppUpdateResult(false, Error: "Failed to start the update installer.");

            _onExitForUpdate?.Invoke();
            return new AppUpdateResult(true, Restarting: true, Message: "Installer started. Remote PC Diagnostics will restart shortly.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.Warn($"[app-update] Install failed: {ex.Message}");
            return new AppUpdateResult(false, Error: ex.Message);
        }
    }

    public void Dispose()
    {
        _checkLock.Dispose();
        if (_ownsHttp)
            _http.Dispose();
    }
}
