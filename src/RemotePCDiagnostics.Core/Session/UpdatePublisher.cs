using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Who may sign Setup and the Agent MSI that the elevated updater runs. A release's own <c>.sha256</c> file only proves
/// the download matches that release, so the updater also requires an Authenticode signature from this publisher.
/// </summary>
/// <param name="SubjectCommonName">The signing certificate's CN, e.g. the name Artifact Signing validated.</param>
/// <param name="IdentityEkuOid">
/// The identity EKU Artifact Signing puts in every certificate of one certificate profile
/// (<c>1.3.6.1.4.1.311.97.…</c>). It stays the same when the short-lived certificate renews.
/// </param>
/// <param name="RootCertificateSha256">SHA-256 of the root certificate the signature chains to.</param>
public sealed record UpdatePublisherPin(string SubjectCommonName, string IdentityEkuOid, string RootCertificateSha256);

public static class UpdatePublisher
{
    private const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";

    /// <summary>
    /// The pinned release publisher. Null until releases are signed (docs/update-signing.md): the check is then off
    /// and updates are verified by SHA-256 only. Once set, every update path fails closed on an unsigned package,
    /// a package from another publisher, or a non-Windows OS.
    /// </summary>
    public static UpdatePublisherPin? Pin { get; } = null;

    /// <summary>True when <paramref name="leaf"/> and <paramref name="root"/> are the pinned publisher's signing chain.</summary>
    public static bool Matches(X509Certificate2 leaf, X509Certificate2 root, UpdatePublisherPin pin)
    {
        if (string.IsNullOrWhiteSpace(pin.SubjectCommonName)
            || string.IsNullOrWhiteSpace(pin.IdentityEkuOid)
            || string.IsNullOrWhiteSpace(pin.RootCertificateSha256))
            return false;

        if (!string.Equals(leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false), pin.SubjectCommonName, StringComparison.Ordinal))
            return false;

        if (!string.Equals(root.GetCertHashString(HashAlgorithmName.SHA256), pin.RootCertificateSha256.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        var hasCodeSigning = false;
        var hasIdentity = false;
        foreach (var extension in leaf.Extensions)
        {
            if (extension is not X509EnhancedKeyUsageExtension eku)
                continue;
            foreach (var oid in eku.EnhancedKeyUsages)
            {
                if (oid.Value == CodeSigningEku)
                    hasCodeSigning = true;
                else if (oid.Value == pin.IdentityEkuOid)
                    hasIdentity = true;
            }
        }
        return hasCodeSigning && hasIdentity;
    }

    /// <summary>
    /// Throws unless <paramref name="path"/> has a valid Authenticode signature (revocation checked) from the pinned
    /// publisher. Does nothing while <see cref="Pin"/> is null.
    /// </summary>
    public static Task VerifyAsync(string path, CancellationToken ct) => VerifyAsync(path, Pin, ct);

    internal static async Task VerifyAsync(string path, UpdatePublisherPin? pin, CancellationToken ct)
    {
        if (pin is null)
            return;
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("Update publisher verification requires Windows. The update was not installed.");

        var ok = await Task.Run(
            () => WinVerifyTrustSignatureVerifier.VerifySignerChain(path, (leaf, root) => Matches(leaf, root, pin), ct),
            ct).ConfigureAwait(false);
        if (!ok)
            throw new InvalidOperationException(
                $"{Path.GetFileName(path)} is not signed by the Remote PC Diagnostics publisher. The update was not installed.");
    }
}
