using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>Verifies an Authenticode digital signature on a downloaded installer binary.</summary>
public interface IBiosSignatureVerifier
{
    Task<bool> VerifyAuthenticodeAsync(string filePath, CancellationToken ct = default);

    /// <summary>
    /// True only when the signature is valid (revocation checked) and the signing certificate's organization (O=)
    /// is exactly one of <paramref name="allowedSignerOrganizations"/>. The elevated Agent uses only this overload.
    /// </summary>
    Task<bool> VerifyAuthenticodeAsync(string filePath, IReadOnlyCollection<string> allowedSignerOrganizations, CancellationToken ct = default);

    /// <summary>
    /// True only when <paramref name="catalogPath"/> has a valid Authenticode signature (revocation checked)
    /// from one of <paramref name="allowedSignerOrganizations"/> AND cryptographically covers
    /// <paramref name="memberFilePath"/> (the member file's catalog hash is verified against the signed catalog).
    /// </summary>
    Task<bool> VerifyCatalogMemberAsync(
        string catalogPath,
        string memberFilePath,
        IReadOnlyCollection<string> allowedSignerOrganizations,
        CancellationToken ct = default);
}

/// <summary>
/// Pure-C# Authenticode signature verifier invoking Windows <c>wintrust.dll!WinVerifyTrust</c>
/// (<c>WINTRUST_ACTION_GENERIC_VERIFY_V2</c>) and Windows catalog APIs (<c>CryptCATAdmin*</c> / <c>CryptCAT*</c>).
/// Fails closed (<c>false</c>) on non-Windows or on any verification error.
/// </summary>
public sealed class WinVerifyTrustSignatureVerifier : IBiosSignatureVerifier
{
    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
    private static readonly IntPtr InvalidHandleValue = new(-1);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x80;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const int MaxCatalogMembersToInspect = 4096;

    public static WinVerifyTrustSignatureVerifier Instance { get; } = new();

    public Task<bool> VerifyAuthenticodeAsync(string filePath, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
            return Task.FromResult(false);

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return Task.FromResult(false);

        return Task.Run(() => OperatingSystem.IsWindows() && VerifyAuthenticodeWindows(filePath, checkRevocation: false, ct), ct);
    }

    public Task<bool> VerifyAuthenticodeAsync(string filePath, IReadOnlyCollection<string> allowedSignerOrganizations, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows() || allowedSignerOrganizations is not { Count: > 0 })
            return Task.FromResult(false);

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return Task.FromResult(false);

        return Task.Run(() =>
            OperatingSystem.IsWindows()
            && VerifyAuthenticodeWindows(filePath, checkRevocation: true, ct)
            && IsAllowedSignerOrganization(ReadSignerOrganization(filePath), allowedSignerOrganizations), ct);
    }

    public Task<bool> VerifyCatalogMemberAsync(
        string catalogPath,
        string memberFilePath,
        IReadOnlyCollection<string> allowedSignerOrganizations,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows() || allowedSignerOrganizations is not { Count: > 0 })
            return Task.FromResult(false);

        if (string.IsNullOrWhiteSpace(catalogPath) || !File.Exists(catalogPath))
            return Task.FromResult(false);

        if (string.IsNullOrWhiteSpace(memberFilePath) || !File.Exists(memberFilePath))
            return Task.FromResult(false);

        return Task.Run(() =>
            OperatingSystem.IsWindows()
            && VerifyCatalogMemberWindows(catalogPath, memberFilePath, allowedSignerOrganizations, ct), ct);
    }

    /// <summary>Exact (case-insensitive) match of the signer's O= value against the allowlist. Null or empty never matches.</summary>
    public static bool IsAllowedSignerOrganization(string? organization, IReadOnlyCollection<string> allowedSignerOrganizations)
    {
        if (string.IsNullOrWhiteSpace(organization) || allowedSignerOrganizations is null)
            return false;
        var org = organization.Trim();
        foreach (var allowed in allowedSignerOrganizations)
        {
            if (string.Equals(org, allowed?.Trim(), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>The organization (O=) of the certificate that signed <paramref name="filePath"/>, or null.</summary>
    [SupportedOSPlatform("windows")]
    private static string? ReadSignerOrganization(string filePath)
    {
        try
        {
#pragma warning disable SYSLIB0057 // No loader replacement exists for reading the signer of an Authenticode-signed file.
            using var signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
            return OrganizationOf(signer.SubjectName);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>The O= (organizationName, 2.5.4.10) value of a distinguished name, or null.</summary>
    public static string? OrganizationOf(X500DistinguishedName name)
    {
        foreach (var rdn in name.EnumerateRelativeDistinguishedNames())
        {
            if (rdn.GetSingleElementType().Value == "2.5.4.10")
                return rdn.GetSingleElementValue();
        }
        return null;
    }

    /// <summary>
    /// Returns a concise diagnostic summary (filename, size, WinVerifyTrust status hex, signer O=) for logging when
    /// Authenticode verification fails on Windows. Returns <c>null</c> on non-Windows.
    /// </summary>
    internal static string? DescribeAuthenticodeStatus(string filePath, IReadOnlyCollection<string> allowedSignerOrganizations)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return null;

        try
        {
            var size = new FileInfo(filePath).Length;
            var status = VerifyAuthenticodeStatusWindows(filePath, checkRevocation: true, CancellationToken.None);
            var org = ReadSignerOrganization(filePath) ?? "<none>";
            return $"file={Path.GetFileName(filePath)}, size={size}, wvt=0x{status:X8}, signer='{org}', allowed=[{string.Join(", ", allowedSignerOrganizations)}]";
        }
        catch (Exception ex)
        {
            return $"file={Path.GetFileName(filePath)}, diagError={ex.GetType().Name}";
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool VerifyAuthenticodeWindows(string filePath, bool checkRevocation, CancellationToken ct) =>
        VerifyAuthenticodeStatusWindows(filePath, checkRevocation, ct) == 0;

    /// <summary>
    /// True when <paramref name="filePath"/> has a valid Authenticode signature (whole chain revocation checked) and
    /// <paramref name="verifySigner"/> accepts the signing certificate and the root of the chain WinVerifyTrust built.
    /// Both certificates come from WinVerifyTrust's own state, not from a second read of the file.
    /// </summary>
    internal static bool VerifySignerChain(string filePath, Func<X509Certificate2, X509Certificate2, bool> verifySigner, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return false;
        var accepted = false;
        var status = VerifyAuthenticodeStatusWindows(filePath, checkRevocation: true, ct, state =>
        {
            accepted = ReadSignerChain(state) is var (leaf, root) && Accept(leaf, root, verifySigner);
        });
        return status == 0 && accepted;
    }

    private static bool Accept(X509Certificate2 leaf, X509Certificate2 root, Func<X509Certificate2, X509Certificate2, bool> verifySigner)
    {
        using (leaf)
        using (root)
            return verifySigner(leaf, root);
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint counterSignerIndex);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint certificateIndex);

    // CRYPT_PROVIDER_SGNR starts with DWORD cbStruct, FILETIME sftVerifyAsOf, DWORD csCertChain.
    private const int SignerCertChainCountOffset = 12;

    /// <summary>The signing certificate and the chain root from an open WinVerifyTrust state, or null.</summary>
    [SupportedOSPlatform("windows")]
    private static (X509Certificate2 Leaf, X509Certificate2 Root)? ReadSignerChain(IntPtr state)
    {
        var provider = WTHelperProvDataFromStateData(state);
        if (provider == IntPtr.Zero)
            return null;
        var signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if (signer == IntPtr.Zero)
            return null;
        var count = Marshal.ReadInt32(signer, SignerCertChainCountOffset);
        if (count < 2)
            return null;
        var leaf = CertificateAt(signer, 0);
        var root = CertificateAt(signer, (uint)(count - 1));
        if (leaf is null || root is null)
        {
            leaf?.Dispose();
            root?.Dispose();
            return null;
        }
        return (leaf, root);
    }

    [SupportedOSPlatform("windows")]
    private static X509Certificate2? CertificateAt(IntPtr signer, uint index)
    {
        var entry = WTHelperGetProvCertFromChain(signer, index);
        if (entry == IntPtr.Zero)
            return null;
        // CRYPT_PROVIDER_CERT: DWORD cbStruct, then PCCERT_CONTEXT pCert (pointer aligned).
        var context = Marshal.ReadIntPtr(entry, IntPtr.Size);
        return context == IntPtr.Zero ? null : new X509Certificate2(context);
    }

    [SupportedOSPlatform("windows")]
    private static uint VerifyAuthenticodeStatusWindows(string filePath, bool checkRevocation, CancellationToken ct,
        Action<IntPtr>? inspectState = null)
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
                fdwRevocationChecks = checkRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = checkRevocation ? WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT : 0,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero,
            };

            stateOpened = true;
            var status = WinVerifyTrust(InvalidHandleValue, ref actionGuid, ref trustData);
            if (status == 0 && inspectState is not null)
                inspectState(trustData.hWVTStateData);
            return status;
        }
        catch
        {
            return 0xFFFFFFFF;
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

    [SupportedOSPlatform("windows")]
    private static bool VerifyCatalogMemberWindows(
        string catalogPath,
        string memberFilePath,
        IReadOnlyCollection<string> allowedSignerOrganizations,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // 1. Verify the catalog file itself has a valid, non-revoked Authenticode signature from an allowlisted signer.
        if (!VerifyAuthenticodeWindows(catalogPath, checkRevocation: true, ct))
            return false;

        if (!IsAllowedSignerOrganization(ReadSignerOrganization(catalogPath), allowedSignerOrganizations))
            return false;

        // 2. Calculate the target member file's SHA-256 catalog hash and verify that this exact signed catalog covers it.
        var hCatAdmin = IntPtr.Zero;
        var hCatalog = IntPtr.Zero;
        var driverActionGuid = DriverActionVerify;

        try
        {
            if (!CryptCATAdminAcquireContext2(out hCatAdmin, ref driverActionGuid, "SHA256", IntPtr.Zero, 0)
                || hCatAdmin == IntPtr.Zero)
            {
                return false;
            }

            using var memberFileHandle = File.OpenHandle(memberFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);

            uint hashLength = 0;
            _ = CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, memberFileHandle, ref hashLength, null, 0);
            if (hashLength == 0 || hashLength > 128)
                return false;

            var hashBytes = new byte[hashLength];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, memberFileHandle, ref hashLength, hashBytes, 0)
                || hashLength == 0
                || hashLength > hashBytes.Length)
            {
                return false;
            }

            // Standard Inf2Cat / WHQL catalogs use the uppercase hex hash as the member reference tag.
            var hexTag = Convert.ToHexString(hashBytes.AsSpan(0, (int)hashLength));
            if (VerifyCatalogMemberWithWinVerifyTrust(
                    catalogPath,
                    memberFilePath,
                    IntPtr.Zero,
                    hexTag,
                    hashBytes,
                    hashLength,
                    hCatAdmin,
                    ct))
            {
                return true;
            }

            // Fallback for signed catalogs whose member reference tags are filenames or custom identifiers:
            // enumerate member tags in the catalog and let WinVerifyTrust verify the calculated hash against each.
            hCatalog = CryptCATOpen(catalogPath, fdwOpenFlags: 0, hProv: IntPtr.Zero, dwPublicVersion: 0, dwEncodingType: 0);
            if (hCatalog == IntPtr.Zero || hCatalog == InvalidHandleValue)
                return false;

            var prevMember = IntPtr.Zero;
            for (var inspected = 0; inspected < MaxCatalogMembersToInspect; inspected++)
            {
                ct.ThrowIfCancellationRequested();

                prevMember = CryptCATEnumerateMember(hCatalog, prevMember);
                if (prevMember == IntPtr.Zero)
                    break;

                var header = Marshal.PtrToStructure<CRYPTCATMEMBER_HEADER>(prevMember);
                if (header.pwszReferenceTag == IntPtr.Zero)
                    continue;

                var tag = Marshal.PtrToStringUni(header.pwszReferenceTag);
                if (string.IsNullOrEmpty(tag) || string.Equals(tag, hexTag, StringComparison.Ordinal))
                    continue;

                if (VerifyCatalogMemberWithWinVerifyTrust(
                        catalogPath,
                        memberFilePath,
                        IntPtr.Zero,
                        tag,
                        hashBytes,
                        hashLength,
                        hCatAdmin,
                        ct))
                {
                    return true;
                }
            }

            return false;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hCatalog != IntPtr.Zero && hCatalog != InvalidHandleValue)
            {
                try { _ = CryptCATClose(hCatalog); } catch { }
            }

            if (hCatAdmin != IntPtr.Zero)
            {
                try { _ = CryptCATAdminReleaseContext(hCatAdmin, 0); } catch { }
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool VerifyCatalogMemberWithWinVerifyTrust(
        string catalogPath,
        string memberFilePath,
        IntPtr memberFileHandle,
        string memberTag,
        byte[] hashBytes,
        uint hashLength,
        IntPtr hCatAdmin,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var catalogPathPtr = IntPtr.Zero;
        var memberTagPtr = IntPtr.Zero;
        var memberPathPtr = IntPtr.Zero;
        var catalogInfoPtr = IntPtr.Zero;
        var hashPin = default(GCHandle);
        var actionGuid = WinTrustActionGenericVerifyV2;
        var trustData = default(WINTRUST_DATA);
        var stateOpened = false;

        try
        {
            catalogPathPtr = Marshal.StringToHGlobalUni(catalogPath);
            memberTagPtr = Marshal.StringToHGlobalUni(memberTag);
            memberPathPtr = Marshal.StringToHGlobalUni(memberFilePath);
            hashPin = GCHandle.Alloc(hashBytes, GCHandleType.Pinned);

            var catalogInfo = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = catalogPathPtr,
                pcwszMemberTag = memberTagPtr,
                pcwszMemberFilePath = memberPathPtr,
                hMemberFile = memberFileHandle,
                pbCalculatedFileHash = hashPin.AddrOfPinnedObject(),
                cbCalculatedFileHash = hashLength,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = hCatAdmin,
            };

            catalogInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(catalogInfo, catalogInfoPtr, fDeleteOld: false);

            trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pFile = catalogInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
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

            if (catalogInfoPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(catalogInfoPtr);

            if (hashPin.IsAllocated)
                hashPin.Free();

            if (memberPathPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(memberPathPtr);

            if (memberTagPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(memberTagPtr);

            if (catalogPathPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(catalogPathPtr);
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
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPTCATMEMBER_HEADER
    {
        public uint cbStruct;
        public IntPtr pwszReferenceTag;
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

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        ref Guid pgSubsystem,
        string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        ref uint pcbHash,
        byte[]? pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CryptCATOpen(
        string pwszFileName,
        uint fdwOpenFlags,
        IntPtr hProv,
        uint dwPublicVersion,
        uint dwEncodingType);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATClose(IntPtr hCatalog);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATEnumerateMember(IntPtr hCatalog, IntPtr pPrevMember);
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

            // Even when VerifyHash is false or the catalog omitted a SHA-256 digest,
            // never allow an unverified package through — always require a pinned Authenticode signature.
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 0, "Verifying package Authenticode signature..."));

            var verifier = signatureVerifier ?? WinVerifyTrustSignatureVerifier.Instance;
            var allowedSigners = BiosAgentInstallModes.AllowedSignerOrganizationsForVendor(vendorId);
            var signed = allowedSigners.Count > 0
                && await verifier.VerifyAuthenticodeAsync(filePath, allowedSigners, ct).ConfigureAwait(false);
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
