using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Security;

/// <summary>What the boot-security probe read. Null fields couldn't be read.</summary>
/// <param name="SecureBoot">UEFISecureBootEnabled: true on, false off, null when the key is missing (legacy BIOS or no Secure Boot support).</param>
/// <param name="Firmware">"UEFI" or "Legacy" (Windows' firmware_type), or null.</param>
/// <param name="Edition">EditionID, e.g. "Core" (Home) or "Professional".</param>
/// <param name="Encryption">Shell property System.Volume.BitLockerProtection of the system drive, or null.</param>
/// <param name="Tpm">tpmtool details, or null when tpmtool couldn't run.</param>
public sealed record BootSecurityFacts(bool? SecureBoot, string? Firmware, string? Edition, int? Encryption, TpmFacts? Tpm, string SystemDrive = "C:")
{
    public bool IsUefi => string.Equals(Firmware, "UEFI", StringComparison.OrdinalIgnoreCase);
    public bool IsLegacy => string.Equals(Firmware, "Legacy", StringComparison.OrdinalIgnoreCase);
    public bool IsHome => Edition is { } e && e.StartsWith("Core", StringComparison.OrdinalIgnoreCase);
}

/// <summary>The lines of <c>tpmtool getdeviceinformation</c> this check uses.</summary>
public sealed record TpmFacts(bool Present, string? Version, bool? ReadyForStorage, string? Manufacturer, string? Pcr7Binding)
{
    public bool IsVersion2 => Version is { } v && v.TrimStart().StartsWith("2", StringComparison.Ordinal);
    public bool Pcr7BindingPossible => Pcr7Binding is null || !Pcr7Binding.Contains("Not Possible", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Secure Boot, TPM and system-drive encryption, read without administrator rights: the Secure Boot state from the registry, the TPM
/// from <c>tpmtool</c>, and encryption from the Shell's BitLocker property. Explains in plain words why Device encryption / BitLocker is
/// unavailable (most often Secure Boot turned off in the firmware).
/// </summary>
public sealed class BootSecurityModule(SystemCommandRunner commands) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = ModuleSlugs.BootSecurity;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.BootSecurity;
    public override string DisplayName => "Secure Boot & encryption";
    protected override string FailedMessage => "Couldn't read Secure Boot and encryption settings on this PC.";

    public static string TpmTool => SystemCommandRunner.SystemTool("tpmtool.exe");

    /// <summary>Read-only probe: registry values and one Shell property, printed as key=value lines.</summary>
    public const string ProbeScript =
        "$ErrorActionPreference='SilentlyContinue';" +
        "$s=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State';" +
        "if($s -and $null -ne $s.UEFISecureBootEnabled){'SecureBoot='+$s.UEFISecureBootEnabled}else{'SecureBoot='};" +
        "'Firmware='+$env:firmware_type;" +
        "'Edition='+(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').EditionID;" +
        "'SystemDrive='+$env:SystemDrive;" +
        "try{'Encryption='+(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive+'\\').Self.ExtendedProperty('System.Volume.BitLockerProtection')}catch{'Encryption='}";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Checking Secure Boot and encryption…");
        var probe = await commands.RunAsync(SystemCommandRunner.PowerShell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ProbeScript], ct).ConfigureAwait(false);
        progress.ReportStep(2, 2, "Checking the security chip (TPM)…");
        var tpm = await commands.RunAsync(TpmTool, ["getdeviceinformation"], ct).ConfigureAwait(false);
        if (probe is not { ExitCode: 0 } && tpm is not { ExitCode: 0 }) return AreaReport.Failed(FailedMessage);
        var facts = ParseProbe(probe is { ExitCode: 0 } ? probe.StdOut : null, tpm is { ExitCode: 0 } ? ParseTpm(tpm.StdOut) : null);
        Log($"{Name}: secureBoot={facts.SecureBoot?.ToString() ?? "?"} firmware={facts.Firmware ?? "?"} edition={facts.Edition ?? "?"} encryption={facts.Encryption?.ToString() ?? "?"} " +
            $"tpm={(facts.Tpm is { } t ? $"present={t.Present} v={t.Version} ready={t.ReadyForStorage} pcr7={t.Pcr7Binding}" : "?")}");
        return Build(facts);
    }

    private static Dictionary<string, string> KeyValues(string? text, char separator)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim().TrimStart('-').Trim();
            var i = line.IndexOf(separator);
            if (i <= 0) continue;
            d[line[..i].Trim()] = line[(i + 1)..].Trim();
        }
        return d;
    }

    public static BootSecurityFacts ParseProbe(string? stdout, TpmFacts? tpm)
    {
        var kv = KeyValues(stdout, '=');
        string? Str(string k) => kv.TryGetValue(k, out var v) && v.Length > 0 ? v : null;
        bool? secureBoot = Str("SecureBoot") is { } sb && int.TryParse(sb, out var n) ? n != 0 : null;
        int? enc = Str("Encryption") is { } e && int.TryParse(e, out var x) ? x : null;
        return new(secureBoot, Str("Firmware"), Str("Edition"), enc, tpm, Str("SystemDrive") ?? "C:");
    }

    /// <summary>Parses <c>tpmtool getdeviceinformation</c> ("-TPM Present: True" lines). Null when the output has no TPM Present line.</summary>
    public static TpmFacts? ParseTpm(string? stdout)
    {
        var kv = KeyValues(stdout, ':');
        if (!kv.TryGetValue("TPM Present", out var present)) return null;
        bool? Bool(string k) => kv.TryGetValue(k, out var v) && bool.TryParse(v, out var b) ? b : null;
        string? Str(string k) => kv.TryGetValue(k, out var v) && v.Length > 0 ? v : null;
        return new(bool.TryParse(present, out var p) && p, Str("TPM Version"), Bool("Ready For Storage"),
            Str("TPM Manufacturer Full Name") ?? Str("TPM Manufacturer ID"), Str("Bitlocker PCR7 Binding State"));
    }

    /// <summary>System.Volume.BitLockerProtection: 1 on, 3 encrypting, 5 suspended, 6 locked; 2, 8 (waiting for activation) and 0 are not protected.</summary>
    public enum DriveProtection { Unknown, Protected, Encrypting, Suspended, NotProtected }

    public static DriveProtection Protection(int? value) => value switch
    {
        1 or 6 => DriveProtection.Protected,
        3 => DriveProtection.Encrypting,
        5 => DriveProtection.Suspended,
        0 or 2 or 4 or 8 => DriveProtection.NotProtected,
        _ => DriveProtection.Unknown,
    };

    public const string FirmwareHint = "Restart and open the firmware (BIOS/UEFI) setup, usually with F2, F10, F12 or Del at the maker's logo, then set Secure Boot to Enabled on the Security or Boot tab.";

    /// <summary>Why encryption can't be turned on yet, or null when nothing on this PC blocks it.</summary>
    public static string? EncryptionBlocker(BootSecurityFacts f)
    {
        if (f.Tpm is { Present: false }) return "This PC has no working security chip (TPM). Turn on the firmware TPM (AMD fTPM or Intel PTT) in the firmware setup.";
        if (f.IsLegacy) return "This PC starts in legacy BIOS mode, which can't use Device encryption.";
        if (f.SecureBoot == false) return "Secure Boot is off, so Windows can't tie encryption to the security chip. " + FirmwareHint;
        if (f.Tpm is { } t && !t.Pcr7BindingPossible) return "Windows reports this PC doesn't meet the Device encryption requirements, even with Secure Boot on.";
        return null;
    }

    public static AreaReport Build(BootSecurityFacts f)
    {
        var cards = new List<AreaCard>();
        var parts = new List<string>();

        // Secure Boot
        {
            var (level, headline, impact) = f.SecureBoot switch
            {
                true => (AreaLevel.Ok, "Secure Boot is on", "Only trusted, signed startup software can load before Windows."),
                false => (AreaLevel.Warning, "Secure Boot is off", "Malware that loads before Windows (a bootkit) isn't blocked, and Device encryption can't be turned on."),
                null when f.IsLegacy => (AreaLevel.Warning, "Legacy BIOS mode", "This PC starts in legacy BIOS mode, so Secure Boot isn't available."),
                _ => (AreaLevel.Neutral, "Not reported", "Windows didn't report a Secure Boot state on this PC."),
            };
            var rows = new List<AreaRow>
            {
                new(level, ["Secure Boot", f.SecureBoot switch { true => "On", false => "Off", _ => "Not available" }]),
                new(AreaLevel.Neutral, ["Startup mode", f.IsUefi ? "UEFI" : f.IsLegacy ? "Legacy BIOS" : "Not reported"]),
                new(AreaLevel.Neutral, ["What it means", impact]),
            };
            cards.Add(new("secureboot", "Secure Boot", level, headline, f.IsUefi ? "UEFI startup" : "", ["Detail", "Value"], rows,
                Note: f.SecureBoot == false ? FirmwareHint + " Windows already starts in UEFI mode, so it keeps booting normally. Only unsigned boot software (for example some Linux installs) would stop loading." : null));
            parts.Add(f.SecureBoot switch { true => "Secure Boot on", false => "Secure Boot off", _ => "Secure Boot not available" });
        }

        // TPM
        if (f.Tpm is not { } tpm)
        {
            cards.Add(new("tpm", "Security chip (TPM)", AreaLevel.Neutral, "Couldn't read the TPM", "", ["Detail", "Value"],
                [new(AreaLevel.Neutral, ["TPM", "Not reported"])]));
        }
        else
        {
            var level = !tpm.Present ? AreaLevel.Warning : !tpm.IsVersion2 ? AreaLevel.Warning : tpm.ReadyForStorage == false ? AreaLevel.Warning : AreaLevel.Ok;
            var headline = !tpm.Present ? "No TPM found" : string.Join(" ", new[] { "TPM", VersionLabel(tpm.Version), tpm.ReadyForStorage == false ? "(not ready)" : "ready" }.Where(x => x.Length > 0));
            var rows = new List<AreaRow> { new(tpm.Present ? AreaLevel.Ok : AreaLevel.Warning, ["Present", tpm.Present ? "Yes" : "No"]) };
            if (tpm.Present)
            {
                rows.Add(new(tpm.IsVersion2 ? AreaLevel.Ok : AreaLevel.Warning, ["Version", tpm.Version ?? "Not reported"]));
                if (tpm.ReadyForStorage is { } ready) rows.Add(new(ready ? AreaLevel.Ok : AreaLevel.Warning, ["Ready to protect keys", ready ? "Yes" : "No"]));
                if (tpm.Manufacturer is { Length: > 0 } m) rows.Add(new(AreaLevel.Neutral, ["Maker", m]));
            }
            cards.Add(new("tpm", "Security chip (TPM)", level, headline, tpm.Present ? tpm.Manufacturer ?? "" : "", ["Detail", "Value"], rows,
                Note: !tpm.Present ? "Windows 11 and Device encryption need a TPM 2.0. Most PCs from 2016 on have one built into the processor; turn on AMD fTPM or Intel PTT in the firmware setup."
                    : !tpm.IsVersion2 ? "This is an older TPM 1.2. Windows 11 and Device encryption need TPM 2.0." : null));
            parts.Add(tpm.Present ? $"TPM {VersionLabel(tpm.Version)}".Trim() : "No TPM");
        }

        // Encryption
        {
            var prot = Protection(f.Encryption);
            var name = f.IsHome ? "Device encryption" : "BitLocker";
            var blocker = EncryptionBlocker(f);
            var (level, headline) = prot switch
            {
                DriveProtection.Protected => (AreaLevel.Ok, $"Drive {f.SystemDrive} is encrypted"),
                DriveProtection.Encrypting => (AreaLevel.Ok, $"Drive {f.SystemDrive} is being encrypted"),
                DriveProtection.Suspended => (AreaLevel.Warning, $"Encryption of {f.SystemDrive} is paused"),
                DriveProtection.NotProtected => (AreaLevel.Warning, $"Drive {f.SystemDrive} isn't encrypted"),
                _ => (AreaLevel.Neutral, "Encryption not reported"),
            };
            var how = prot == DriveProtection.NotProtected
                ? blocker ?? (f.IsHome ? "Turn on Device encryption in Settings > Privacy & security > Device encryption. The recovery key is saved to your Microsoft account."
                    : "Turn on BitLocker in Settings > Privacy & security > Device encryption, or Control Panel > BitLocker Drive Encryption. Save the recovery key somewhere safe.")
                : prot == DriveProtection.Suspended ? $"{name} is paused (often during an update). Resume it in Control Panel > BitLocker Drive Encryption." : null;
            var rows = new List<AreaRow>
            {
                new(level, [$"Drive {f.SystemDrive}", prot switch
                {
                    DriveProtection.Protected => "Encrypted", DriveProtection.Encrypting => "Encrypting", DriveProtection.Suspended => "Encrypted, protection paused",
                    DriveProtection.NotProtected => "Not encrypted", _ => "Not reported",
                }]),
                new(AreaLevel.Neutral, ["Windows edition", f.IsHome ? "Home (Device encryption)" : f.Edition is { } ed ? $"{ed} (BitLocker)" : "Not reported"]),
                new(AreaLevel.Neutral, ["What it means", prot == DriveProtection.NotProtected
                    ? "If this PC is lost or stolen, anyone who removes the drive can read your files."
                    : "Files on this drive can't be read if the drive is removed from the PC."]),
            };
            if (prot == DriveProtection.NotProtected) rows.Add(new(blocker is null ? AreaLevel.Neutral : AreaLevel.Warning, ["Can it be turned on?", blocker is null ? "Yes" : "Not yet: " + blocker]));
            cards.Add(new("encryption", "Drive encryption", level, headline, name, ["Detail", "Value"], rows, Note: how));
            parts.Add(prot switch
            {
                DriveProtection.Protected or DriveProtection.Encrypting => $"{f.SystemDrive} encrypted", DriveProtection.Suspended => "encryption paused",
                DriveProtection.NotProtected => $"{f.SystemDrive} not encrypted", _ => "encryption not reported",
            });
        }

        return new(cards, string.Join(" · ", parts), AreaReport.Worst(cards.Select(c => c.Level)));
    }

    private static string VersionLabel(string? v) =>
        v is null ? "" : v.Split(',', StringSplitOptions.TrimEntries)[0];
}
