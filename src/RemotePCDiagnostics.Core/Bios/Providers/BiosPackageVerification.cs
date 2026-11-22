using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>Verifies an Authenticode digital signature on a downloaded installer binary.</summary>
public interface IBiosSignatureVerifier
{
    Task<bool> VerifyAuthenticodeAsync(string filePath, CancellationToken ct = default);
}

/// <summary>
/// Pure-C# Authenticode signature verifier invoking Windows <c>wintrust.dll!WinVerifyTrust</c>
/// (<c>WINTRUST_ACTION_GENERIC_VERIFY_V2</c>). Fails closed (<c>false</c>) on non-Windows or on any verification error.
/// </summary>
public sealed class WinVerifyTrustSignatureVerifier : IBiosSignatureVerifier
{
    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly IntPtr InvalidHandleValue = new(-1);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

    public static WinVerifyTrustSignatureVerifier Instance { get; } = new();

    public Task<bool> VerifyAuthenticodeAsync(string filePath, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
            return Task.FromResult(false);

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return Task.FromResult(false);

        return Task.Run(() => OperatingSystem.IsWindows() && VerifyAuthenticodeWindows(filePath, ct), ct);
    }

    [SupportedOSPlatform("windows")]
    private static bool VerifyAuthenticodeWindows(string filePath, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var filePathPtr = IntPtr.Zero;
        var fileInfoPtr = IntPtr.Zero;
        var actionGuid = WinTrustActionGenericVerifyV2;
        var trustData = default(WINTRUST_DATA);
        var stateOpened = false;

        try
        {
            filePathPtr = Marshal.StringToHGlobalUni(filePath);
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePathPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };

            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = 0,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero,
            };

            stateOpened = true;
            var status = WinVerifyTrust(InvalidHandleValue, ref actionGuid, ref trustData);
            return status == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (stateOpened)
            {
                try
                {
                    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                    _ = WinVerifyTrust(InvalidHandleValue, ref actionGuid, ref trustData);
                }
                catch
                {
                    // Best-effort state cleanup.
                }
            }

            if (fileInfoPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(fileInfoPtr);

            if (filePathPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(filePathPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
}

/// <summary>Outcome of downloading and verifying a BIOS update package.</summary>
public sealed record BiosVerifiedPackageResult(
    bool Succeeded,
    string? FilePath = null,
    long BytesDownloaded = 0,
    string? ActualSha256 = null,
    bool VerifiedBySha256 = false,
    bool VerifiedByAuthenticode = false,
    string? ErrorMessage = null)
{
    public static BiosVerifiedPackageResult Ok(
        string filePath,
        long bytesDownloaded,
        string? actualSha256 = null,
        bool verifiedBySha256 = false,
        bool verifiedByAuthenticode = false) =>
        new(true, filePath, bytesDownloaded, actualSha256, verifiedBySha256, verifiedByAuthenticode);

    public static BiosVerifiedPackageResult Fail(string errorMessage, string? actualSha256 = null) =>
        new(false, ActualSha256: actualSha256, ErrorMessage: errorMessage);
}

/// <summary>
/// Shared download + integrity verification helper enforcing vendor HTTPS allowlists,
/// constant-time SHA-256 verification, and Authenticode fallback with immediate deletion on failure.
/// </summary>
public static class BiosPackageVerification
{
    public static async Task<BiosVerifiedPackageResult> DownloadAndVerifyAsync(
        HttpClient client,
        BiosInstallRequest request,
        string vendorId,
        IReadOnlyList<string> allowedHostSuffixes,
        string defaultFileName,
        IBiosSignatureVerifier? signatureVerifier,
        IProgress<BiosInstallProgress>? progress,
        ILogger? log,
        CancellationToken ct,
        long maxBytes = BiosProviderHttp.DefaultMaxDownloadBytes)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(request);

        var serial = request.System?.SerialNumber;
        var downloadUrl = request.Target.DownloadUrl;
        if (!BiosProviderHttp.TryValidateHttpsUrl(downloadUrl, allowedHostSuffixes, out _, out var urlReason))
        {
            var safeReason = BiosInstallerRunner.RedactSerialNumber(urlReason, serial);
            log?.Warn($"[{vendorId}] BIOS package download URL rejected: {safeReason}");
            return BiosVerifiedPackageResult.Fail($"BIOS package URL is not allowed: {safeReason}");
        }

        var createdTempDir = string.IsNullOrWhiteSpace(request.StagingDirectory);
        var stagingDir = createdTempDir
            ? Path.Combine(Path.GetTempPath(), $"rpd-bios-stage-{Guid.NewGuid():N}")
            : request.StagingDirectory!;

        string? filePath = null;
        var keepFile = false;

        try
        {
            var download = await BiosProviderHttp.DownloadToStagingAsync(
                client,
                downloadUrl!,
                allowedHostSuffixes,
                stagingDir,
                defaultFileName,
                progress,
                ct,
                maxBytes).ConfigureAwait(false);

            if (!download.Succeeded || string.IsNullOrWhiteSpace(download.FilePath))
            {
                var safeErr = BiosInstallerRunner.RedactSerialNumber(
                    download.ErrorMessage ?? "BIOS package download failed.",
                    serial);
                log?.Warn($"[{vendorId}] BIOS package download failed: {safeErr}");
                return BiosVerifiedPackageResult.Fail(safeErr);
            }

            filePath = download.FilePath;

            if (request.VerifyHash && !string.IsNullOrWhiteSpace(request.Target.Sha256))
            {
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 0, "Verifying package SHA-256 digest..."));

                var (valid, actual) = await BiosPackageVerifier.VerifyFileSha256Async(
                    filePath,
                    request.Target.Sha256,
                    ct).ConfigureAwait(false);

                if (!valid)
                {
                    log?.Warn($"[{vendorId}] BIOS package SHA-256 mismatch (actual={actual}). Deleting unverified file.");
                    return BiosVerifiedPackageResult.Fail("Downloaded BIOS package failed SHA-256 verification.", actual);
                }

                keepFile = true;
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 100, "Package SHA-256 verified."));
                return BiosVerifiedPackageResult.Ok(
                    filePath,
                    download.BytesDownloaded,
                    actualSha256: actual,
                    verifiedBySha256: true);
            }

            if (request.VerifyHash)
            {
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 0, "Verifying package Authenticode signature..."));

                var verifier = signatureVerifier ?? WinVerifyTrustSignatureVerifier.Instance;
                var signed = await verifier.VerifyAuthenticodeAsync(filePath, ct).ConfigureAwait(false);
                if (!signed)
                {
                    log?.Warn($"[{vendorId}] BIOS package failed Authenticode signature verification. Deleting unverified file.");
                    return BiosVerifiedPackageResult.Fail("Downloaded BIOS package failed Authenticode signature verification.");
                }

                keepFile = true;
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 100, "Package Authenticode signature verified."));
                return BiosVerifiedPackageResult.Ok(
                    filePath,
                    download.BytesDownloaded,
                    verifiedByAuthenticode: true);
            }

            keepFile = true;
            return BiosVerifiedPackageResult.Ok(filePath, download.BytesDownloaded);
        }
        finally
        {
            if (!keepFile)
            {
                if (!string.IsNullOrWhiteSpace(filePath))
                    TryDeleteFile(filePath);
                if (createdTempDir)
                    TryDeleteDirectoryIfEmpty(stagingDir);
            }
        }
    }

    internal static bool TryEnsureExecutableExtension(
        string filePath,
        string displayName,
        out string executablePath,
        out string error,
        string requiredExtension = ".exe")
    {
        executablePath = filePath;
        error = "";

        if (string.IsNullOrWhiteSpace(filePath))
        {
            error = $"Downloaded {displayName} BIOS installer package path is empty.";
            return false;
        }

        var ext = Path.GetExtension(filePath);
        if (string.Equals(ext, requiredExtension, StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.IsNullOrEmpty(ext))
        {
            var renamed = filePath + requiredExtension;
            if (BiosProviderHttp.IsSymlinkOrReparsePath(renamed) || Directory.Exists(renamed))
            {
                error = $"Target {displayName} BIOS package path '{Path.GetFileName(renamed)}' conflicts with an unsafe link or existing directory.";
                return false;
            }

            try
            {
                File.Move(filePath, renamed, overwrite: true);
                executablePath = renamed;
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                error = $"Failed to stage {displayName} BIOS package with '{requiredExtension}' extension: {ex.Message}";
                return false;
            }
        }

        error = $"{displayName} BIOS installer package must be an {requiredExtension} file (got '{ext}').";
        return false;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Best-effort deletion of unverified package.
        }
    }

    private static void TryDeleteDirectoryIfEmpty(string dir)
    {
        try
        {
            if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                Directory.Delete(dir, recursive: false);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}
