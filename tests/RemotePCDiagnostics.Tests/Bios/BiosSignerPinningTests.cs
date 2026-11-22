using System.Security.Cryptography.X509Certificates;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests.Bios;

/// <summary>The elevated Agent only runs BIOS packages signed by that vendor (Admin security issue 148).</summary>
public sealed class BiosSignerPinningTests
{
    [Theory]
    [InlineData(BiosAgentInstallModes.HpSoftPaq, "HP Inc.")]
    [InlineData(BiosAgentInstallModes.HpBiosUpdRec, "HP Inc.")]
    [InlineData(BiosAgentInstallModes.DellBiosExe, "Dell Inc")]
    [InlineData(BiosAgentInstallModes.DellDcuCli, "Dell Inc")]
    [InlineData(BiosAgentInstallModes.LenovoWinUptp, "Lenovo")]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, "lenovo")]
    [InlineData(BiosAgentInstallModes.MicrosoftSurfaceMsi, "Microsoft Corporation")]
    [InlineData(BiosAgentInstallModes.FrameworkBiosExe, "Framework Computer Inc")]
    [InlineData(BiosAgentInstallModes.FrameworkCabCapsule, "Framework Computer Inc")]
    public void Each_mode_accepts_its_own_vendor(string mode, string organization) =>
        Assert.True(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization(organization, BiosAgentInstallModes.AllowedSignerOrganizations(mode)));

    [Theory]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, "HP Inc.")]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, "Microsoft Corporation")]
    [InlineData(BiosAgentInstallModes.HpSoftPaq, "Dell Inc")]
    [InlineData(BiosAgentInstallModes.DellBiosExe, "Dell")]
    [InlineData(BiosAgentInstallModes.DellBiosExe, "Dell Inc Evil")]
    [InlineData(BiosAgentInstallModes.MicrosoftSurfaceMsi, "Microsoft Corporation Ltd")]
    [InlineData(BiosAgentInstallModes.FrameworkBiosExe, "Some Code Signing LLC")]
    [InlineData(BiosAgentInstallModes.HpSoftPaq, "")]
    [InlineData(BiosAgentInstallModes.HpSoftPaq, null)]
    [InlineData("unknown_mode", "HP Inc.")]
    public void Other_signers_are_refused(string mode, string? organization) =>
        Assert.False(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization(organization, BiosAgentInstallModes.AllowedSignerOrganizations(mode)));

    [Fact]
    public void Capsule_catalogs_must_be_signed_by_Microsoft()
    {
        Assert.True(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization("Microsoft Corporation", BiosAgentInstallModes.AllowedCatalogSignerOrganizations));
        Assert.False(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization("Framework Computer Inc", BiosAgentInstallModes.AllowedCatalogSignerOrganizations));
    }

    [Theory]
    [InlineData("CN=HP Inc., O=HP Inc., L=Palo Alto, S=California, C=US", "HP Inc.")]
    [InlineData("CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", "Microsoft Corporation")]
    [InlineData("CN=Dell Inc, O=Dell Inc, L=Round Rock, S=Texas, C=US", "Dell Inc")]
    [InlineData("CN=No Organization, C=US", null)]
    public void Organization_is_read_from_the_O_field_not_the_CN(string subject, string? expected) =>
        Assert.Equal(expected, WinVerifyTrustSignatureVerifier.OrganizationOf(new X500DistinguishedName(subject)));

    [Fact]
    public async Task Pinned_verification_fails_closed_without_an_allowlist_or_off_Windows()
    {
        var file = Path.GetTempFileName();
        try
        {
            Assert.False(await WinVerifyTrustSignatureVerifier.Instance.VerifyAuthenticodeAsync(file, Array.Empty<string>()));
            if (!OperatingSystem.IsWindows())
                Assert.False(await WinVerifyTrustSignatureVerifier.Instance.VerifyAuthenticodeAsync(file, ["HP Inc."]));
        }
        finally
        {
            File.Delete(file);
        }
    }
}
