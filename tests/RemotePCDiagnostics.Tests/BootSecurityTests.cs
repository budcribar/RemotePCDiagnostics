using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Tests;

public class BootSecurityTests
{
    // Real tpmtool output from a Lenovo 82R4 (AMD fTPM) with Secure Boot off.
    private const string TpmOutput = """

        -TPM Present: True
        -TPM Version: 2.0
        -TPM Manufacturer ID: AMD
        -TPM Manufacturer Full Name: AMD
        -TPM Manufacturer Version: 3.92.0.5
        -PPI Version: 1.3
        -Is Initialized: True
        -Ready For Storage: True
        -Ready For Attestation: False
        -Bitlocker PCR7 Binding State: Binding Not Possible
        -TPM Spec Version: 1.38
        """;

    private static TpmFacts Tpm2 => new(true, "2.0", true, "AMD", "Bound");

    private static AreaCard Card(AreaReport r, string id) => r.Cards.Single(c => c.Id == id);

    [Fact]
    public void ParseTpm_reads_tpmtool_lines()
    {
        var t = BootSecurityModule.ParseTpm(TpmOutput)!;
        Assert.True(t.Present);
        Assert.True(t.IsVersion2);
        Assert.True(t.ReadyForStorage);
        Assert.Equal("AMD", t.Manufacturer);
        Assert.False(t.Pcr7BindingPossible);
        Assert.Null(BootSecurityModule.ParseTpm("tpmtool: unknown command"));
    }

    [Fact]
    public void ParseProbe_reads_key_values_and_blanks_as_unknown()
    {
        var f = BootSecurityModule.ParseProbe("SecureBoot=0\r\nFirmware=UEFI\r\nEdition=Core\r\nSystemDrive=C:\r\nEncryption=0\r\n", null);
        Assert.False(f.SecureBoot);
        Assert.True(f.IsUefi);
        Assert.True(f.IsHome);
        Assert.Equal(0, f.Encryption);

        var blank = BootSecurityModule.ParseProbe("SecureBoot=\nFirmware=Legacy\nEdition=Professional\nEncryption=\n", null);
        Assert.Null(blank.SecureBoot);
        Assert.Null(blank.Encryption);
        Assert.True(blank.IsLegacy);
        Assert.False(blank.IsHome);
    }

    [Fact]
    public void Secure_boot_off_explains_why_device_encryption_is_missing()
    {
        var rep = BootSecurityModule.Build(new(false, "UEFI", "Core", 0, BootSecurityModule.ParseTpm(TpmOutput)));
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        Assert.Equal("Secure Boot off · TPM 2.0 · C: not encrypted", rep.Summary);

        var sb = Card(rep, "secureboot");
        Assert.Equal(AreaLevel.Warning, sb.Level);
        Assert.Contains("F2", sb.Note);
        Assert.Equal(AreaLevel.Ok, Card(rep, "tpm").Level);

        var enc = Card(rep, "encryption");
        Assert.Equal(AreaLevel.Warning, enc.Level);
        Assert.Equal("Device encryption", enc.Meta);
        Assert.StartsWith("Secure Boot is off", enc.Note);
        Assert.Contains(enc.Rows, r => r.Values[0] == "Can it be turned on?" && r.Values[1].StartsWith("Not yet"));
    }

    [Fact]
    public void Everything_on_passes()
    {
        var rep = BootSecurityModule.Build(new(true, "UEFI", "Professional", 1, Tpm2));
        Assert.Equal(DiagnosticStatus.Ok, rep.Status);
        Assert.Equal("Secure Boot on · TPM 2.0 · C: encrypted", rep.Summary);
        Assert.Null(Card(rep, "encryption").Note);
        Assert.Equal("BitLocker", Card(rep, "encryption").Meta);
    }

    [Fact]
    public void Ready_but_not_encrypted_points_to_the_settings_page()
    {
        var home = BootSecurityModule.Build(new(true, "UEFI", "Core", 8, Tpm2));
        Assert.Contains("Settings > Privacy & security > Device encryption", Card(home, "encryption").Note);
        Assert.Contains(Card(home, "encryption").Rows, r => r.Values[0] == "Can it be turned on?" && r.Values[1] == "Yes");
    }

    [Fact]
    public void No_tpm_and_legacy_bios_are_named_as_the_blocker()
    {
        var noTpm = new BootSecurityFacts(true, "UEFI", "Core", 2, new(false, null, null, null, null));
        Assert.Contains("TPM", BootSecurityModule.EncryptionBlocker(noTpm));
        Assert.Equal("No TPM found", Card(BootSecurityModule.Build(noTpm), "tpm").Headline);

        var legacy = new BootSecurityFacts(null, "Legacy", "Core", 0, Tpm2);
        Assert.Contains("legacy BIOS", BootSecurityModule.EncryptionBlocker(legacy));
        Assert.Equal("Legacy BIOS mode", Card(BootSecurityModule.Build(legacy), "secureboot").Headline);
    }

    [Fact]
    public void Suspended_and_unknown_encryption()
    {
        Assert.Equal(AreaLevel.Warning, Card(BootSecurityModule.Build(new(true, "UEFI", "Professional", 5, Tpm2)), "encryption").Level);
        var unknown = BootSecurityModule.Build(new(true, "UEFI", "Professional", null, null));
        Assert.Equal(AreaLevel.Neutral, Card(unknown, "encryption").Level);
        Assert.Equal("Couldn't read the TPM", Card(unknown, "tpm").Headline);
        Assert.Equal(DiagnosticStatus.Ok, unknown.Status);
    }

    [Fact]
    public void Is_a_security_check_in_run_all()
    {
        var d = new ModuleCatalog().Get(ModuleIds.BootSecurity)!;
        Assert.Equal(ModuleKind.Check, d.Kind);
        Assert.Equal(ModuleGroups.Security, d.Group);
        var m = new BootSecurityModule(new SystemCommandRunner());
        Assert.True(((IDiagnosticModule)m).IncludeInRunAll);
        Assert.Equal(ModuleSlugs.BootSecurity, m.Name);
    }
}
