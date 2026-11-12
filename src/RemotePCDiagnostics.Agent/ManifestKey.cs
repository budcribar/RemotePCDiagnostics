namespace RemotePCDiagnostics.Agent;

/// <summary>
/// ECDSA P-256 public key PEM used to verify <c>manifest.sig</c> when downloading app releases from GitHub.
/// Populated by <c>tools/New-ManifestSigningKey.ps1</c>; while empty, the agent launches locally installed
/// <c>RemotePCDiagnostics.Host.exe</c> builds and refuses unverified network downloads.
/// </summary>
public static class ManifestKey
{
    public const string PublicKeyPem = "";
}
