using System.Security.Cryptography;

namespace RemotePCDiagnostics.Agent.Core;

/// <summary>
/// <c>manifest.sig</c>: base64 of an ECDSA P-256 / SHA-256 signature in IEEE P1363 form (r || s, 64 bytes) over the exact bytes of
/// <c>manifest.json</c>, made by the release workflow with the <c>MANIFEST_SIGNING_KEY</c> secret.
/// </summary>
public static class ManifestSignature
{
    public const int SignatureBytes = 64;
    private const string P256Oid = "1.2.840.10045.3.1.7";

    /// <summary>True when the PEM looks like a public key at all (ManifestKey.cs is empty until tools/New-ManifestSigningKey.ps1 runs).</summary>
    public static bool IsKeyConfigured(string? publicKeyPem) =>
        !string.IsNullOrWhiteSpace(publicKeyPem) && publicKeyPem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal);

    /// <summary>Verifies <paramref name="signatureText"/> (base64; surrounding whitespace allowed) over <paramref name="manifestBytes"/>.
    /// Returns false for a malformed signature or key, a key that isn't P-256, or a wrong signature. Never throws.</summary>
    public static bool Verify(ReadOnlySpan<byte> manifestBytes, string? signatureText, string publicKeyPem)
    {
        if (!IsKeyConfigured(publicKeyPem) || string.IsNullOrWhiteSpace(signatureText)) return false;
        byte[] signature;
        try { signature = Convert.FromBase64String(signatureText.Trim()); }
        catch (FormatException) { return false; }
        if (signature.Length != SignatureBytes) return false;
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(publicKeyPem);
            var p = key.ExportParameters(false);
            if (key.KeySize != 256 || !(p.Curve.Oid?.Value == P256Oid || p.Curve.Oid?.FriendlyName is "nistP256" or "ECDSA_P256" or "prime256v1")) return false;
            return key.VerifyData(manifestBytes, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException) { return false; }
    }
}
