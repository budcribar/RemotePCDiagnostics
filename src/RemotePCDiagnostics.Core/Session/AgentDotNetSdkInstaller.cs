using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>Parsed download metadata for one official Microsoft .NET SDK zip archive.</summary>
public sealed record DotNetSdkZipAsset(string SdkVersion, string Url, string Sha512);

/// <summary>
/// Headless, zero-popup .NET SDK side-by-side installer that runs inside the elevated Agent.
/// Downloads Microsoft's official release-metadata JSON, fetches the native <c>win-x64</c> or <c>win-arm64</c>
/// SDK zip, verifies its SHA-512 hash, and extracts it side-by-side into <c>%ProgramFiles%\dotnet</c>.
/// No winget, no UAC prompt, and no taskbar/installer window.
/// </summary>
public static class AgentDotNetSdkInstaller
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(10) };

    public static bool IsAllowedMajor(int major) => major is 10 or 11;

    public static bool IsTrustedMicrosoftDownloadHost(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttps
        && (uri.Host.Equals("builds.dotnet.microsoft.com", StringComparison.OrdinalIgnoreCase)
            || uri.Host.Equals("download.visualstudio.microsoft.com", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Parses Microsoft's official <c>releases.json</c> for the latest SDK zip matching <paramref name="rid"/>
    /// (<c>win-x64</c> or <c>win-arm64</c>).
    /// </summary>
    public static DotNetSdkZipAsset? TryParseReleaseZipFromMetadata(string releasesJson, string rid)
    {
        if (string.IsNullOrWhiteSpace(releasesJson) || string.IsNullOrWhiteSpace(rid))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(releasesJson);
            if (!doc.RootElement.TryGetProperty("releases", out var releases) || releases.ValueKind != JsonValueKind.Array)
                return null;

            foreach (var rel in releases.EnumerateArray())
            {
                // Prefer "sdks" array (contains all feature bands) then fall back to single "sdk".
                if (rel.TryGetProperty("sdks", out var sdks) && sdks.ValueKind == JsonValueKind.Array)
                {
                    foreach (var sdk in sdks.EnumerateArray())
                    {
                        if (TryExtractFromSdkElement(sdk, rid) is { } found)
                            return found;
                    }
                }
                if (rel.TryGetProperty("sdk", out var singleSdk) && singleSdk.ValueKind == JsonValueKind.Object)
                {
                    if (TryExtractFromSdkElement(singleSdk, rid) is { } found)
                        return found;
                }
            }
        }
        catch { }
        return null;
    }

    private static DotNetSdkZipAsset? TryExtractFromSdkElement(JsonElement sdk, string rid)
    {
        var version = sdk.TryGetProperty("version", out var v) ? v.GetString() : null;
        if (string.IsNullOrWhiteSpace(version)) return null;
        if (!sdk.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array)
            return null;

        foreach (var file in files.EnumerateArray())
        {
            var fileRid = file.TryGetProperty("rid", out var r) ? r.GetString() : null;
            var name = file.TryGetProperty("name", out var n) ? n.GetString() : null;
            var url = file.TryGetProperty("url", out var u) ? u.GetString() : null;
            var hash = file.TryGetProperty("hash", out var h) ? h.GetString() : null;
            if (!string.Equals(fileRid, rid, StringComparison.OrdinalIgnoreCase)) continue;
            if (name is null || !name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(hash)) continue;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !IsTrustedMicrosoftDownloadHost(uri)) continue;
            return new DotNetSdkZipAsset(version, url, hash.Trim());
        }
        return null;
    }

    public static async Task<ProcessResult> InstallAsync(int majorVersion, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return WindowsAgentNativeOps.Failed("Installing the .NET SDK requires Windows.");
        if (!IsAllowedMajor(majorVersion))
            return WindowsAgentNativeOps.Failed("Only .NET 10 and .NET 11 SDKs can be installed.");

        var rid = RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "win-arm64" : "win-x64";
        var metadataUrl = $"https://builds.dotnet.microsoft.com/dotnet/release-metadata/{majorVersion}.0/releases.json";

        string metadataJson;
        try
        {
            metadataJson = await Http.GetStringAsync(metadataUrl, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return WindowsAgentNativeOps.Failed($"Could not fetch Microsoft .NET {majorVersion}.0 release metadata: {ex.Message}");
        }

        var asset = TryParseReleaseZipFromMetadata(metadataJson, rid);
        if (asset is null)
            return WindowsAgentNativeOps.Failed($"No official .NET {majorVersion} SDK zip for {rid} was found in Microsoft release metadata.");

        var installRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet");
        var sdkTargetDir = Path.Combine(installRoot, "sdk", asset.SdkVersion);
        if (Directory.Exists(sdkTargetDir))
            return WindowsAgentNativeOps.Ok(new { SdkVersion = asset.SdkVersion, InstallDir = installRoot, AlreadyInstalled = true });

        var tempZip = Path.Combine(Path.GetTempPath(), $"rpcd-dotnet-sdk-{asset.SdkVersion}-{Guid.NewGuid():N}.zip");
        try
        {
            using (var resp = await Http.GetAsync(asset.Url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
            {
                resp.EnsureSuccessStatusCode();
                await using var netStream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                await using var fileStream = new FileStream(tempZip, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                await netStream.CopyToAsync(fileStream, ct).ConfigureAwait(false);
            }

            // Verify SHA-512 against Microsoft's official release metadata before extracting a single byte.
            string actualHash;
            await using (var verifyStream = File.OpenRead(tempZip))
            {
                var hashBytes = await SHA512.HashDataAsync(verifyStream, ct).ConfigureAwait(false);
                actualHash = Convert.ToHexString(hashBytes);
            }
            if (!string.Equals(actualHash, asset.Sha512, StringComparison.OrdinalIgnoreCase))
                return WindowsAgentNativeOps.Failed($"Downloaded .NET {asset.SdkVersion} SDK archive failed SHA-512 verification.");

            Directory.CreateDirectory(installRoot);
            ExtractSideBySide(tempZip, installRoot);
            return WindowsAgentNativeOps.Ok(new { SdkVersion = asset.SdkVersion, InstallDir = installRoot, AlreadyInstalled = false });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return WindowsAgentNativeOps.Failed($"Failed to install .NET {asset.SdkVersion} SDK: {ex.Message}");
        }
        finally
        {
            try { if (File.Exists(tempZip)) File.Delete(tempZip); } catch { }
        }
    }

    /// <summary>
    /// Extracts a .NET SDK zip side-by-side into <paramref name="installRoot"/>. Existing versioned SDK/runtime folders
    /// are preserved; top-level host files are skipped if locked by a running dotnet process.
    /// </summary>
    private static void ExtractSideBySide(string zipPath, string installRoot)
    {
        var fullRoot = Path.GetFullPath(installRoot);
        if (!fullRoot.EndsWith(Path.DirectorySeparatorChar))
            fullRoot += Path.DirectorySeparatorChar;

        using var archive = ZipFile.OpenRead(zipPath);
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name))
                continue;

            var destPath = Path.GetFullPath(Path.Combine(fullRoot, entry.FullName));
            if (!destPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Archive entry escapes install root.");

            var dir = Path.GetDirectoryName(destPath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var isTopLevelHost = !entry.FullName.Contains('/') && !entry.FullName.Contains('\\');
            try
            {
                entry.ExtractToFile(destPath, overwrite: true);
            }
            catch (IOException) when (isTopLevelHost && File.Exists(destPath))
            {
                // dotnet.exe or LICENSE at root may be in use; existing host already discovers the newly extracted sdk/<version> folder.
            }
        }
    }
}
