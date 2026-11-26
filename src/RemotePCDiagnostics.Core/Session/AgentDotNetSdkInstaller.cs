using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>Parsed download metadata for one official Microsoft .NET SDK Windows installer.</summary>
public sealed record DotNetSdkInstallerAsset(string SdkVersion, string Url, string Sha512);

/// <summary>
/// Headless, zero-popup .NET SDK side-by-side installer that runs inside the elevated Agent.
/// Downloads Microsoft's official release-metadata JSON, fetches the native <c>win-x64</c> or <c>win-arm64</c>
/// signed <c>.exe</c> installer, verifies its SHA-512 hash, and runs it silently with
/// <c>/install /quiet /norestart</c>. Using Microsoft's official MSI/Burn bundle avoids file-lock and
/// MSI-owned catalog ACL failures in <c>%ProgramFiles%\dotnet</c>, registers cleanly in Windows, and
/// produces zero UAC prompts or windows.
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
    /// Parses Microsoft's official <c>releases.json</c> for the latest Windows <c>.exe</c> SDK installer
    /// matching <paramref name="rid"/> (<c>win-x64</c> or <c>win-arm64</c>).
    /// </summary>
    public static DotNetSdkInstallerAsset? TryParseReleaseInstallerFromMetadata(string releasesJson, string rid)
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

    private static DotNetSdkInstallerAsset? TryExtractFromSdkElement(JsonElement sdk, string rid)
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
            if (name is null || !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(hash)) continue;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !IsTrustedMicrosoftDownloadHost(uri)) continue;
            return new DotNetSdkInstallerAsset(version, url, hash.Trim());
        }
        return null;
    }

    /// <summary>
    /// Verifies that an extracted <c>sdk\&lt;version&gt;</c> directory contains both the SDK host
    /// (<c>dotnet.dll</c>) and <c>Microsoft.NET.Sdk</c> so half-extracted folders are never treated as installed.
    /// </summary>
    public static bool IsCompleteSdkInstall(string? sdkVersionDir) =>
        !string.IsNullOrWhiteSpace(sdkVersionDir)
        && File.Exists(Path.Combine(sdkVersionDir, "dotnet.dll"))
        && File.Exists(Path.Combine(sdkVersionDir, "Sdks", "Microsoft.NET.Sdk", "Sdk", "Sdk.props"));

    /// <summary>
    /// Returns true if a WiX Burn / Windows Installer exit code indicates a successful installation:
    /// <c>0</c> (success), <c>3010</c> (reboot required), <c>1641</c> (reboot initiated), or <c>1638</c> (already installed).
    /// </summary>
    public static bool IsSuccessExitCode(int exitCode) => exitCode is 0 or 3010 or 1641 or 1638;

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

        var asset = TryParseReleaseInstallerFromMetadata(metadataJson, rid);
        if (asset is null)
            return WindowsAgentNativeOps.Failed($"No official .NET {majorVersion} SDK installer for {rid} was found in Microsoft release metadata.");

        var installRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet");
        var sdkTargetDir = Path.Combine(installRoot, "sdk", asset.SdkVersion);
        if (IsCompleteSdkInstall(sdkTargetDir))
            return WindowsAgentNativeOps.Ok(new { SdkVersion = asset.SdkVersion, InstallDir = installRoot, AlreadyInstalled = true });

        var runId = Guid.NewGuid().ToString("N");
        var tempExe = Path.Combine(Path.GetTempPath(), $"rpcd-dotnet-sdk-{asset.SdkVersion}-{runId}.exe");
        var tempLog = Path.Combine(Path.GetTempPath(), $"rpcd-dotnet-sdk-{asset.SdkVersion}-{runId}.log");
        try
        {
            using (var resp = await Http.GetAsync(asset.Url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
            {
                resp.EnsureSuccessStatusCode();
                await using var netStream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                await using var fileStream = new FileStream(tempExe, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                await netStream.CopyToAsync(fileStream, ct).ConfigureAwait(false);
            }

            // Verify SHA-512 against Microsoft's official release metadata before executing a single byte.
            string actualHash;
            await using (var verifyStream = File.OpenRead(tempExe))
            {
                var hashBytes = await SHA512.HashDataAsync(verifyStream, ct).ConfigureAwait(false);
                actualHash = Convert.ToHexString(hashBytes);
            }
            if (!string.Equals(actualHash, asset.Sha512, StringComparison.OrdinalIgnoreCase))
                return WindowsAgentNativeOps.Failed($"Downloaded .NET {asset.SdkVersion} SDK installer failed SHA-512 verification.");

            // Remove any leftover half-extracted sdk/<version> folder from earlier attempts before running the official installer.
            if (Directory.Exists(sdkTargetDir) && !IsCompleteSdkInstall(sdkTargetDir))
            {
                try { Directory.Delete(sdkTargetDir, recursive: true); } catch { }
            }

            var psi = new ProcessStartInfo
            {
                FileName = tempExe,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("/install");
            psi.ArgumentList.Add("/quiet");
            psi.ArgumentList.Add("/norestart");
            psi.ArgumentList.Add("/log");
            psi.ArgumentList.Add(tempLog);

            using var proc = Process.Start(psi);
            if (proc is null)
                return WindowsAgentNativeOps.Failed($"Could not start Microsoft .NET {asset.SdkVersion} SDK installer.");

            var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            _ = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);

            if (!IsSuccessExitCode(proc.ExitCode))
            {
                var logDetail = TryReadLastErrorFromInstallerLog(tempLog) ?? stderr?.Trim();
                var suffix = string.IsNullOrWhiteSpace(logDetail) ? "" : $": {logDetail}";
                return WindowsAgentNativeOps.Failed($"Microsoft .NET {asset.SdkVersion} SDK installer exited with code {proc.ExitCode}{suffix}");
            }

            if (!IsCompleteSdkInstall(sdkTargetDir) && !HasAnyCompleteSdkForMajor(installRoot, majorVersion))
                return WindowsAgentNativeOps.Failed($"Microsoft .NET {asset.SdkVersion} SDK installer completed (exit {proc.ExitCode}), but no complete .NET {majorVersion} SDK was found under {installRoot}.");

            return WindowsAgentNativeOps.Ok(new { SdkVersion = asset.SdkVersion, InstallDir = installRoot, AlreadyInstalled = false, ExitCode = proc.ExitCode });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return WindowsAgentNativeOps.Failed($"Failed to install .NET {asset.SdkVersion} SDK: {ex.Message}");
        }
        finally
        {
            try { if (File.Exists(tempExe)) File.Delete(tempExe); } catch { }
            try { if (File.Exists(tempLog)) File.Delete(tempLog); } catch { }
        }
    }

    private static bool HasAnyCompleteSdkForMajor(string installRoot, int majorVersion)
    {
        var sdkRoot = Path.Combine(installRoot, "sdk");
        if (!Directory.Exists(sdkRoot)) return false;
        var prefix = $"{majorVersion}.";
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(sdkRoot))
            {
                var name = Path.GetFileName(dir);
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && IsCompleteSdkInstall(dir))
                    return true;
            }
        }
        catch { }
        return false;
    }

    private static string? TryReadLastErrorFromInstallerLog(string logPath)
    {
        try
        {
            if (!File.Exists(logPath)) return null;
            var lines = File.ReadLines(logPath);
            string? lastErr = null;
            foreach (var line in lines)
            {
                if (line.Contains("Error 0x", StringComparison.OrdinalIgnoreCase)
                    || line.Contains("Failed to ", StringComparison.OrdinalIgnoreCase))
                {
                    lastErr = line.Trim();
                }
            }
            return lastErr;
        }
        catch { return null; }
    }
}
