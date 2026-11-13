using System.IO.Compression;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// File-system layout, ACL-hardened <c>agent.json</c> persistence, installed <c>RemotePCDiagnostics.Host.exe</c> discovery,
/// and verified <see cref="AppCache"/> release management.
/// </summary>
public static class AgentPaths
{
    public const string ServiceName = AgentLayout.ServiceName;
    public const string ServiceDisplayName = "Remote PC Diagnostics Agent";
    public const string ServiceDescription = "Maintains an outbound diagnostic enrollment connection so authorized technicians can start Remote PC Diagnostics sessions.";
    public const string ConfigPathEnvVar = AgentLayout.ConfigPathEnvVar;
    public const string HostExeEnvVar = "RPD_AGENT_HOST_EXE";

    public static string GetAgentVersion()
    {
        var asm = typeof(AgentPaths).Assembly;
        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(info))
        {
            var plus = info.IndexOf('+');
            return plus > 0 ? info[..plus] : info;
        }
        return asm.GetName().Version?.ToString(3) ?? "1.2.0";
    }

    public static string ProgramDataDir() => AgentLayout.ProgramDataDirectory();

    public static string ConfigPath() => AgentLayout.ConfigPath();

    public static string StatusPath() => AgentLayout.StatusPath();

    public static string HostWatchPath() => AgentLayout.HostWatchPath();

    public static string AppCacheRootDir() => AgentLayout.AppCacheDirectory();

    public static string DefaultInstallDir() => AgentLayout.DefaultInstallDirectory();

    public static string DefaultInstalledAgentExe() => AgentLayout.DefaultAgentExe();

    /// <summary>
    /// Writes <c>agent-status.json</c> so a standard user can read the link state. The file has no enrollment key.
    /// </summary>
    public static void WriteReadableStatus(AgentLinkStatus status) =>
        WriteUsersCanRead(StatusPath(), status.ToJson());

    public static void WriteHostWatch(AgentHostWatchState state) =>
        WriteUsersCanRead(HostWatchPath(), state.ToJson());

    public static AgentHostWatchState ReadHostWatch()
    {
        try
        {
            var path = HostWatchPath();
            if (!File.Exists(path)) return new AgentHostWatchState();
            return AgentHostWatchState.Parse(File.ReadAllText(path));
        }
        catch
        {
            return new AgentHostWatchState();
        }
    }

    private static void WriteUsersCanRead(string path, string contents)
    {
        var dir = Path.GetDirectoryName(path) ?? ProgramDataDir();
        Directory.CreateDirectory(dir);
        var tempPath = path + ".tmp";
        File.WriteAllText(tempPath, contents);
        if (OperatingSystem.IsWindows())
            TryApplyUsersCanReadFileAcl(tempPath);
        File.Move(tempPath, path, overwrite: true);
        if (OperatingSystem.IsWindows())
            TryApplyUsersCanReadFileAcl(path);
    }

    private static void TryApplyUsersCanReadFileAcl(string filePath)
    {
        try
        {
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var fileInfo = new FileInfo(filePath);
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Read, AccessControlType.Allow));
            fileInfo.SetAccessControl(security);
        }
        catch
        {
            // A non-Windows test, or a folder we cannot relabel, keeps the default ACL.
        }
    }

    public static AgentConfig? TryLoadConfig(out string? readError)
    {
        readError = null;
        var path = ConfigPath();
        if (!File.Exists(path))
            return null;

        try
        {
            var json = File.ReadAllText(path);
            var parsed = AgentConfig.Parse(json);
            if (parsed is null)
                readError = $"Configuration file '{path}' is invalid or damaged.";
            return parsed;
        }
        catch (UnauthorizedAccessException)
        {
            readError = $"Administrator rights are required to read '{path}'.";
            return null;
        }
        catch (Exception ex)
        {
            readError = $"Could not read '{path}': {ex.Message}";
            return null;
        }
    }

    /// <summary>
    /// Writes <c>%ProgramData%\RemotePCDiagnostics\agent.json</c> with Administrators + SYSTEM write/read ACL protection.
    /// Keeps <c>Users</c> ReadAndExecute on the parent <c>%ProgramData%\RemotePCDiagnostics</c> directory so
    /// <c>RemotePCDiagnostics.Host.exe</c>'s <c>ProtectedStateFolder</c> check and cached-app execution both work cleanly.
    /// </summary>
    public static void WriteSecuredConfig(AgentConfig config)
    {
        var path = ConfigPath();
        var dir = Path.GetDirectoryName(path) ?? ProgramDataDir();
        Directory.CreateDirectory(dir);

        if (OperatingSystem.IsWindows() && string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ConfigPathEnvVar)))
        {
            TryApplyParentDirectoryAcl(dir);
        }

        var tempPath = path + ".tmp";
        File.WriteAllText(tempPath, config.ToJson());

        if (OperatingSystem.IsWindows())
        {
            TryApplyAdminSystemOnlyFileAcl(tempPath);
        }

        File.Move(tempPath, path, overwrite: true);

        if (OperatingSystem.IsWindows())
        {
            TryApplyAdminSystemOnlyFileAcl(path);
        }
    }

    private static void TryApplyParentDirectoryAcl(string dirPath)
    {
        try
        {
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            const InheritanceFlags all = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            var dirInfo = new DirectoryInfo(dirPath);
            var security = new DirectorySecurity();
            security.SetOwner(admins);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute, all, PropagationFlags.None, AccessControlType.Allow));
            dirInfo.SetAccessControl(security);
        }
        catch
        {
            // Non-elevated test directories or restricted filesystems keep default ACLs.
        }
    }

    private static void TryApplyAdminSystemOnlyFileAcl(string filePath)
    {
        try
        {
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            var fileInfo = new FileInfo(filePath);
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
            fileInfo.SetAccessControl(security);
        }
        catch
        {
            // Best effort when running outside elevated Administrators/SYSTEM context in tests.
        }
    }

    public static string GetInstalledOrCachedAppVersion()
    {
        var cached = GetCachedVersion(AppCacheRootDir());
        if (!string.IsNullOrEmpty(cached))
            return cached;

        var installed = TryFindLocalInstalledHostExe();
        if (installed is not null)
        {
            try
            {
                var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(installed);
                if (!string.IsNullOrWhiteSpace(info.ProductVersion))
                {
                    var plus = info.ProductVersion.IndexOf('+');
                    return plus > 0 ? info.ProductVersion[..plus] : info.ProductVersion;
                }
                if (!string.IsNullOrWhiteSpace(info.FileVersion))
                    return info.FileVersion;
            }
            catch
            {
                // Ignore version inspection errors.
            }
            return "installed";
        }

        return "";
    }

    public static string GetCachedVersion(string appRoot)
    {
        if (!Directory.Exists(appRoot))
            return "";

        var folders = new List<CachedFolder>();
        try
        {
            foreach (var subDir in Directory.EnumerateDirectories(appRoot))
            {
                var name = Path.GetFileName(subDir);
                if (string.IsNullOrEmpty(name))
                    continue;

                var entryPath = Path.Combine(subDir, "RemotePCDiagnostics.Host.exe");
                var entryRecordPath = Path.Combine(subDir, AppCache.RecordFileName("RemotePCDiagnostics.Host.exe"));
                string? zipRecord = null;
                foreach (var shaFile in Directory.EnumerateFiles(subDir, "*.zip.sha256"))
                {
                    zipRecord = SafeReadText(shaFile);
                    break;
                }
                var entryRecord = File.Exists(entryRecordPath) ? SafeReadText(entryRecordPath) : null;
                folders.Add(new CachedFolder(name, File.Exists(entryPath), zipRecord, entryRecord));
            }
        }
        catch
        {
            return "";
        }

        return AppCache.PickCachedVersion(folders);
    }

    public static string? TryFindLocalInstalledHostExe()
    {
        var overrideExe = Environment.GetEnvironmentVariable(HostExeEnvVar)?.Trim();
        if (!string.IsNullOrEmpty(overrideExe) && File.Exists(overrideExe))
            return Path.GetFullPath(overrideExe);

        var candidates = new List<string>
        {
            Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Host.exe"),
        };

        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrEmpty(pf))
        {
            candidates.Add(Path.Combine(pf, "RemotePCDiagnostics", "RemotePCDiagnostics.Host.exe"));
            candidates.Add(Path.Combine(pf, "Remote PC Diagnostics", "RemotePCDiagnostics.Host.exe"));
        }

        var pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrEmpty(pfx86))
        {
            candidates.Add(Path.Combine(pfx86, "RemotePCDiagnostics", "RemotePCDiagnostics.Host.exe"));
            candidates.Add(Path.Combine(pfx86, "Remote PC Diagnostics", "RemotePCDiagnostics.Host.exe"));
        }

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }

    /// <summary>
    /// Locates an already-installed <c>RemotePCDiagnostics.Host.exe</c>, a verified cached copy under
    /// <c>%ProgramData%\RemotePCDiagnostics\app\</c>, or downloads and verifies the latest signed GitHub release.
    /// </summary>
    public static async Task<(string? ExePath, string? Error)> ResolveOrDownloadHostAsync(
        HttpClient http,
        Func<PeakSWC.RemoteWebView.Agent.LaunchStage, string, int, Task> reportStageAsync,
        CancellationToken ct)
    {
        var localInstalled = TryFindLocalInstalledHostExe();
        if (localInstalled is not null)
            return (localInstalled, null);

        var appRoot = AppCacheRootDir();
        var existingCachedVersion = GetCachedVersion(appRoot);
        if (!string.IsNullOrEmpty(existingCachedVersion) && !ManifestSignature.IsKeyConfigured(ManifestKey.PublicKeyPem))
        {
            var cachedExe = Path.Combine(appRoot, existingCachedVersion, "RemotePCDiagnostics.Host.exe");
            if (VerifyEntryHash(cachedExe))
                return (cachedExe, null);
        }

        if (!ManifestSignature.IsKeyConfigured(ManifestKey.PublicKeyPem))
        {
            return (null, "Remote PC Diagnostics is not installed on this computer (install Remote PC Diagnostics first or configure the release signing key).");
        }

        await reportStageAsync(PeakSWC.RemoteWebView.Agent.LaunchStage.StageVerifying, "Checking latest release manifest...", 0).ConfigureAwait(false);

        byte[] manifestBytes;
        string signatureText;
        try
        {
            manifestBytes = await FetchFollowingAllowedRedirectsAsync(http, new Uri(ReleaseUrls.ManifestUrl), ct).ConfigureAwait(false);
            var sigBytes = await FetchFollowingAllowedRedirectsAsync(http, new Uri(ReleaseUrls.SignatureUrl), ct).ConfigureAwait(false);
            signatureText = System.Text.Encoding.UTF8.GetString(sigBytes);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (null, $"Could not fetch release manifest: {ex.Message}");
        }

        if (!ManifestSignature.Verify(manifestBytes, signatureText, ManifestKey.PublicKeyPem))
            return (null, "Release manifest signature verification failed.");

        var manifest = ReleaseManifest.Parse(manifestBytes, out var manifestError);
        if (manifest is null)
            return (null, manifestError);

        Directory.CreateDirectory(appRoot);
        var versionDir = Path.Combine(appRoot, manifest.Version);
        var entryPath = Path.Combine(versionDir, manifest.Entry);
        var zipRecordPath = Path.Combine(versionDir, AppCache.RecordFileName(manifest.File));
        var entryRecordPath = Path.Combine(versionDir, AppCache.RecordFileName(manifest.Entry));

        var folder = Directory.Exists(versionDir)
            ? new CachedFolder(
                manifest.Version,
                File.Exists(entryPath),
                SafeReadText(zipRecordPath),
                SafeReadText(entryRecordPath))
            : null;

        if (AppCache.IsUsable(manifest, folder) && VerifyEntryHash(entryPath))
            return (entryPath, null);

        var stagingDir = versionDir + AppCache.StagingSuffix;
        if (Directory.Exists(stagingDir))
            Directory.Delete(stagingDir, recursive: true);
        Directory.CreateDirectory(stagingDir);

        var tempZip = Path.Combine(stagingDir, AppCache.DownloadFileName);
        try
        {
            await DownloadToFileWithProgressAsync(
                http,
                new Uri(manifest.Url),
                tempZip,
                manifest.Size,
                async (done, total) =>
                {
                    var (text, pct) = AppCache.Progress(done, total);
                    await reportStageAsync(PeakSWC.RemoteWebView.Agent.LaunchStage.StageDownloading, text, pct).ConfigureAwait(false);
                },
                ct).ConfigureAwait(false);

            await reportStageAsync(PeakSWC.RemoteWebView.Agent.LaunchStage.StageVerifying, "Verifying SHA-256 checksum...", 100).ConfigureAwait(false);

            var actualZipHash = ComputeFileSha256Hex(tempZip);
            if (!string.Equals(actualZipHash, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                return (null, "Downloaded archive SHA-256 did not match the signed release manifest.");

            ZipFile.ExtractToDirectory(tempZip, stagingDir, overwriteFiles: true);
            File.Delete(tempZip);

            var stagedEntry = Path.Combine(stagingDir, manifest.Entry);
            if (!File.Exists(stagedEntry))
                return (null, $"Extracted release did not contain '{manifest.Entry}'.");

            var entrySha = ComputeFileSha256Hex(stagedEntry);
            File.WriteAllText(Path.Combine(stagingDir, AppCache.RecordFileName(manifest.File)), AppCache.FormatRecord(actualZipHash, manifest.File));
            File.WriteAllText(Path.Combine(stagingDir, AppCache.RecordFileName(manifest.Entry)), AppCache.FormatRecord(entrySha, manifest.Entry));

            if (Directory.Exists(versionDir))
                Directory.Delete(versionDir, recursive: true);
            Directory.Move(stagingDir, versionDir);

            var siblings = Directory.GetDirectories(appRoot).Select(Path.GetFileName).Where(n => !string.IsNullOrEmpty(n)).Cast<string>();
            foreach (var obsolete in AppCache.FoldersToDelete(siblings, manifest.Version))
            {
                try { Directory.Delete(Path.Combine(appRoot, obsolete), recursive: true); } catch { }
            }

            return (entryPath, null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            try { if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, recursive: true); } catch { }
            return (null, $"Failed to download or verify Remote PC Diagnostics: {ex.Message}");
        }
    }

    private static bool VerifyEntryHash(string entryPath)
    {
        if (!File.Exists(entryPath))
            return false;
        var recordPath = entryPath + ".sha256";
        var expected = AppCache.ParseRecord(SafeReadText(recordPath), Path.GetFileName(entryPath));
        if (expected is null)
            return false;
        var actual = ComputeFileSha256Hex(entryPath);
        return string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase);
    }

    private static string ComputeFileSha256Hex(string path)
    {
        using var stream = File.OpenRead(path);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(stream, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task<byte[]> FetchFollowingAllowedRedirectsAsync(HttpClient http, Uri uri, CancellationToken ct)
    {
        var current = uri;
        for (var hop = 0; hop <= ReleaseUrls.MaxRedirects; hop++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, current);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if ((int)resp.StatusCode is >= 300 and < 400)
            {
                var next = ReleaseUrls.ResolveRedirect(current, resp.Headers.Location)
                    ?? throw new InvalidOperationException("Release redirect pointed to an untrusted host.");
                current = next;
                continue;
            }
            resp.EnsureSuccessStatusCode();
            return await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        }
        throw new InvalidOperationException("Too many redirects while fetching release asset.");
    }

    private static async Task DownloadToFileWithProgressAsync(
        HttpClient http,
        Uri uri,
        string destinationFile,
        long expectedTotal,
        Func<long, long, Task> onProgress,
        CancellationToken ct)
    {
        var current = uri;
        for (var hop = 0; hop <= ReleaseUrls.MaxRedirects; hop++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, current);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if ((int)resp.StatusCode is >= 300 and < 400)
            {
                var next = ReleaseUrls.ResolveRedirect(current, resp.Headers.Location)
                    ?? throw new InvalidOperationException("Download redirect pointed to an untrusted host.");
                current = next;
                continue;
            }

            resp.EnsureSuccessStatusCode();
            var total = resp.Content.Headers.ContentLength ?? expectedTotal;
            await using var src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            await using var dst = File.Create(destinationFile);
            var buffer = new byte[65536];
            long done = 0;
            var lastReport = DateTime.UtcNow;

            while (true)
            {
                var read = await src.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (read == 0)
                    break;
                if (done + read > ReleaseManifest.MaxSize)
                    throw new InvalidOperationException("Download exceeded maximum permitted size.");
                await dst.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                done += read;
                if ((DateTime.UtcNow - lastReport).TotalMilliseconds >= 500)
                {
                    lastReport = DateTime.UtcNow;
                    await onProgress(done, total).ConfigureAwait(false);
                }
            }

            await onProgress(done, total).ConfigureAwait(false);
            return;
        }

        throw new InvalidOperationException("Too many redirects while downloading release archive.");
    }

    private static string? SafeReadText(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path) : null; }
        catch { return null; }
    }
}
