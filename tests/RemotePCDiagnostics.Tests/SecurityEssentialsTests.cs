using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Tests;

public class SecurityEssentialsTests
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

    private static SecurityFacts Hardened => new(true, "UEFI", "Professional", 1, Tpm2)
    {
        DefenderMode = "Normal", RealTimeProtection = true, TamperProtection = true, Pua = 1, NetworkProtection = 1,
        AsrRules = SecurityFixes.SafeAsrRules.ToDictionary(r => r.Id, _ => 1), Antivirus = ["Windows Defender"],
        Firewall = new Dictionary<string, bool> { ["Domain"] = true, ["Private"] = true, ["Public"] = true },
        LlmnrPolicy = 0, AutoRunPolicy = 255, InsecureGuest = 0,
    };

    // Probe output shaped like Budslaptop's (Windows 11 Home, Defender active, nothing hardened), with the public firewall off.
    private const string ProbeOutput = """
        SecureBoot=0
        Firmware=UEFI
        Edition=Core
        SystemDrive=C:
        Encryption=0
        DefenderMode=Normal
        RealTime=True
        Tamper=True
        Pua=0
        NetworkProtection=0
        Asr=
        Antivirus=Windows Defender
        Firewall=Domain:True,Private:True,Public:False
        Llmnr=
        AutoRun=
        InsecureGuest=
        """;

    private static AreaCard Card(AreaReport r, string id) => r.Cards.Single(c => c.Id == id);

    [Fact]
    public void ParseTpm_reads_tpmtool_lines()
    {
        var t = SecurityEssentialsModule.ParseTpm(TpmOutput)!;
        Assert.True(t.Present);
        Assert.True(t.IsVersion2);
        Assert.True(t.ReadyForStorage);
        Assert.Equal("AMD", t.Manufacturer);
        Assert.False(t.Pcr7BindingPossible);
        Assert.Null(SecurityEssentialsModule.ParseTpm("tpmtool: unknown command"));
    }

    [Fact]
    public void ParseProbe_reads_key_values_and_blanks_as_unknown()
    {
        var f = SecurityEssentialsModule.ParseProbe("SecureBoot=0\r\nFirmware=UEFI\r\nEdition=Core\r\nSystemDrive=C:\r\nEncryption=0\r\n", null);
        Assert.False(f.SecureBoot);
        Assert.True(f.IsUefi);
        Assert.True(f.IsHome);
        Assert.Equal(0, f.Encryption);

        var blank = SecurityEssentialsModule.ParseProbe("SecureBoot=\nFirmware=Legacy\nEdition=Professional\nEncryption=\n", null);
        Assert.Null(blank.SecureBoot);
        Assert.Null(blank.Encryption);
        Assert.True(blank.IsLegacy);
        Assert.False(blank.IsHome);
    }

    [Fact]
    public void Secure_boot_off_explains_why_device_encryption_is_missing()
    {
        var rep = SecurityEssentialsModule.Build(new(false, "UEFI", "Core", 0, SecurityEssentialsModule.ParseTpm(TpmOutput)));
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        Assert.StartsWith("4 settings worth changing (2 can be fixed here) · Drive C: isn't encrypted · Secure Boot is off", rep.Summary);

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
        var rep = SecurityEssentialsModule.Build(Hardened);
        Assert.Equal(DiagnosticStatus.Ok, rep.Status);
        Assert.Equal("All key security settings look good", rep.Summary);
        Assert.All(rep.Cards, c => Assert.Null(c.Actions));
        Assert.Null(Card(rep, "encryption").Note);
        Assert.Equal("BitLocker", Card(rep, "encryption").Meta);
    }

    [Fact]
    public void Ready_but_not_encrypted_points_to_the_settings_page()
    {
        var home = SecurityEssentialsModule.Build(new(true, "UEFI", "Core", 8, Tpm2));
        Assert.Contains("Settings > Privacy & security > Device encryption", Card(home, "encryption").Note);
        Assert.Contains(Card(home, "encryption").Rows, r => r.Values[0] == "Can it be turned on?" && r.Values[1] == "Yes");
    }

    [Fact]
    public void No_tpm_and_legacy_bios_are_named_as_the_blocker()
    {
        var noTpm = new SecurityFacts(true, "UEFI", "Core", 2, new(false, null, null, null, null));
        Assert.Contains("TPM", SecurityEssentialsModule.EncryptionBlocker(noTpm));
        Assert.Equal("No TPM found", Card(SecurityEssentialsModule.Build(noTpm), "tpm").Headline);

        var legacy = new SecurityFacts(null, "Legacy", "Core", 0, Tpm2);
        Assert.Contains("legacy BIOS", SecurityEssentialsModule.EncryptionBlocker(legacy));
        Assert.Equal("Legacy BIOS mode", Card(SecurityEssentialsModule.Build(legacy), "secureboot").Headline);
    }

    [Fact]
    public void Suspended_and_unknown_encryption()
    {
        Assert.Equal(AreaLevel.Warning, Card(SecurityEssentialsModule.Build(new(true, "UEFI", "Professional", 5, Tpm2)), "encryption").Level);
        var unknown = SecurityEssentialsModule.Build(Hardened with { Encryption = null, Tpm = null });
        Assert.Equal(AreaLevel.Neutral, Card(unknown, "encryption").Level);
        Assert.Equal("Couldn't read the TPM", Card(unknown, "tpm").Headline);
        Assert.Equal(DiagnosticStatus.Ok, unknown.Status);
    }

    [Fact]
    public void Is_a_security_check_in_run_all()
    {
        var d = new ModuleCatalog().Get(ModuleIds.SecurityEssentials)!;
        Assert.Equal(ModuleKind.Check, d.Kind);
        Assert.Equal(ModuleGroups.Security, d.Group);
        var m = new SecurityEssentialsModule(new SystemCommandRunner());
        Assert.True(((IDiagnosticModule)m).IncludeInRunAll);
        Assert.Equal(ModuleSlugs.SecurityEssentials, m.Name);
    }
}
