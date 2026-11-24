# Standalone update signing

Standalone desktop and fleet updates require a matching SHA-256 checksum and a valid Authenticode signature from the configured RPCD publisher. Microsoft Store updates continue to use the Store update path.

Before rolling this out:

1. Obtain the release publisher's code-signing certificate. Keep its private key in the signing service or on a protected signing machine with access independent of GitHub release publishing credentials.
2. Sign and timestamp the x64 and ARM64 Setup EXEs and Agent MSIs for stable and prerelease releases. Sign the Agent MSI before embedding it in Setup, then sign Setup after building it. Regenerate the adjacent `.sha256` sidecars from the final signed files before publishing.
3. Deploy a 64-bit registry string named `UpdateSignerSha256` under `HKLM\SOFTWARE\Policies\RemotePCDiagnostics` with the 64-character SHA-256 hash of the DER-encoded signing certificate. Distribute this policy through an administrator-controlled channel. On the signing machine, the certificate hash can be obtained with `$certificate.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)`.
4. Verify update installation on a Windows client with the policy in place. Exercise both a desktop installation that requires UAC and a fleet installation with the app closed. Verify that an unsigned package, an unexpected signer, or a missing policy causes the update to fail before Setup starts.

Unsigned legacy assets cannot be installed by these update paths. Coordinate certificate rotation with the deployment of the new machine policy. Fleet updates wait for the installed desktop app to close. A technician can still initiate an update through the elevated desktop flow.
