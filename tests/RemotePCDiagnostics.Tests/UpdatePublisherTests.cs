using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public class UpdatePublisherTests
{
    private const string IdentityEku = "1.3.6.1.4.1.311.97.123456789.1";
    private const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";

    [Fact]
    public void Check_is_off_until_a_publisher_is_pinned()
    {
        // Releases are not signed yet. Turning the check on is a one-line change once they are (docs/update-signing.md).
        Assert.Null(UpdatePublisher.Pin);
    }

    [Fact]
    public async Task No_pin_leaves_the_file_alone()
    {
        var path = Path.GetTempFileName();
        try
        {
            await UpdatePublisher.VerifyAsync(path, pin: null, CancellationToken.None);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task A_pin_fails_closed_on_an_unsigned_file()
    {
        using var root = CreateRoot("Test Root");
        var pin = new UpdatePublisherPin("Bud Cribar", IdentityEku, root.GetCertHashString(HashAlgorithmName.SHA256));
        var path = Path.GetTempFileName();
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => UpdatePublisher.VerifyAsync(path, pin, CancellationToken.None));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Matching_chain_is_accepted()
    {
        using var root = CreateRoot("Test Root");
        using var leaf = CreateLeaf(root, "Bud Cribar", CodeSigningEku, IdentityEku);
        Assert.True(UpdatePublisher.Matches(leaf, root, PinFor(root)));
    }

    [Fact]
    public void Another_subject_is_refused()
    {
        using var root = CreateRoot("Test Root");
        using var leaf = CreateLeaf(root, "Someone Else", CodeSigningEku, IdentityEku);
        Assert.False(UpdatePublisher.Matches(leaf, root, PinFor(root)));
    }

    [Fact]
    public void Same_subject_without_the_identity_eku_is_refused()
    {
        // Another CA can issue a certificate with the same name, but not under the pinned root and identity.
        using var root = CreateRoot("Test Root");
        using var leaf = CreateLeaf(root, "Bud Cribar", CodeSigningEku, "1.3.6.1.4.1.311.97.999.1");
        Assert.False(UpdatePublisher.Matches(leaf, root, PinFor(root)));
    }

    [Fact]
    public void Identity_eku_without_code_signing_is_refused()
    {
        using var root = CreateRoot("Test Root");
        using var leaf = CreateLeaf(root, "Bud Cribar", IdentityEku);
        Assert.False(UpdatePublisher.Matches(leaf, root, PinFor(root)));
    }

    [Fact]
    public void Same_names_under_another_root_are_refused()
    {
        using var pinnedRoot = CreateRoot("Test Root");
        using var otherRoot = CreateRoot("Test Root");
        using var leaf = CreateLeaf(otherRoot, "Bud Cribar", CodeSigningEku, IdentityEku);
        Assert.False(UpdatePublisher.Matches(leaf, otherRoot, PinFor(pinnedRoot)));
    }

    [Fact]
    public void Incomplete_pin_matches_nothing()
    {
        using var root = CreateRoot("Test Root");
        using var leaf = CreateLeaf(root, "Bud Cribar", CodeSigningEku, IdentityEku);
        Assert.False(UpdatePublisher.Matches(leaf, root, PinFor(root) with { IdentityEkuOid = "" }));
        Assert.False(UpdatePublisher.Matches(leaf, root, PinFor(root) with { SubjectCommonName = " " }));
    }

    private static UpdatePublisherPin PinFor(X509Certificate2 root) =>
        new("Bud Cribar", IdentityEku, root.GetCertHashString(HashAlgorithmName.SHA256));

    private static X509Certificate2 CreateRoot(string name)
    {
        // Not disposed: the returned certificate keeps using this key to sign leaves.
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 issuer, string subject, params string[] ekus)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={subject}, O={subject}", key, HashAlgorithmName.SHA256);
        var usages = new OidCollection();
        foreach (var eku in ekus)
            usages.Add(new Oid(eku));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
        var serial = RandomNumberGenerator.GetBytes(8);
        return request.Create(issuer, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(3), serial);
    }
}
