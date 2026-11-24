using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Security;

/// <summary>
/// The security settings that matter most on a typical PC, each explained in plain words:
/// Secure Boot, TPM and drive encryption; antivirus and firewall; Defender's PUA blocking, network protection and a safe set of
/// Attack Surface Reduction rules; LLMNR, AutoRun and insecure guest logons. The settings this app can change safely carry a fix
/// (<see cref="RemediationKind.ApplySecuritySetting"/>), which puts them in the fix list with Undo. Read from <paramref name="source"/>: WMI
/// through the Agent plus the registry and tpmtool in the app, or the PowerShell probe in the Store edition without an Agent.
/// </summary>
public sealed class SecurityEssentialsModule(ISecurityEssentialsSource source, ILogger? log = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.SecurityEssentials;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.SecurityEssentials;
    public override string DisplayName => "Security essentials";
    protected override string FailedMessage => "Couldn't read this PC's security settings.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        if (await source.ReadAsync(progress, ct).ConfigureAwait(false) is not { } facts) return AreaReport.Failed(FailedMessage);
        Log($"{Name}: secureBoot={facts.SecureBoot?.ToString() ?? "?"} firmware={facts.Firmware ?? "?"} edition={facts.Edition ?? "?"} encryption={facts.Encryption?.ToString() ?? "?"} " +
            $"tpm={(facts.Tpm is { } t ? $"present={t.Present} v={t.Version} ready={t.ReadyForStorage} pcr7={t.Pcr7Binding}" : "?")} defender={facts.DefenderMode ?? "?"} pua={facts.Pua} np={facts.NetworkProtection} " +
            $"asr={facts.AsrRules?.Count.ToString(CultureInfo.InvariantCulture) ?? "?"} av='{string.Join(";", facts.Antivirus)}' fw={string.Join(",", facts.Firewall.Select(kv => $"{kv.Key}:{kv.Value}"))} " +
            $"llmnr={facts.LlmnrPolicy} autorun={facts.AutoRunPolicy}/{facts.AutoRunUserPolicy}/{facts.AutoRunLetterPolicy} drives={string.Join(",", facts.Drives.Select(kv => $"{kv.Key}:{kv.Value}"))} guest={facts.InsecureGuest}");
        return Build(facts);
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
    public static string? EncryptionBlocker(SecurityFacts f)
    {
        if (f.Tpm is { Present: false }) return "This PC has no working security chip (TPM). Turn on the firmware TPM (AMD fTPM or Intel PTT) in the firmware setup.";
        if (f.IsLegacy) return "This PC starts in legacy BIOS mode, which can't use Device encryption.";
        if (f.SecureBoot == false) return "Secure Boot is off, so Windows can't tie encryption to the security chip. " + FirmwareHint;
        if (f.Tpm is { } t && !t.Pcr7BindingPossible) return "Windows reports this PC doesn't meet the Device encryption requirements, even with Secure Boot on.";
        return null;
    }

    private static readonly string[] Cols = ["Detail", "Value"];
    private static AreaRow Row(AreaLevel l, string label, string value) => new(l, [label, value]);
    private static AreaRow Means(string text) => Row(AreaLevel.Neutral, "Why it matters", text);
    private static AreaAction Fix(string key) => SecurityFixes.Find(key) is { } f
        ? new(RemediationKind.ApplySecuritySetting, f.ButtonText, f.Key, f.Label)
        : throw new ArgumentException(key);

    /// <summary>The ten checks, most important first. Only the cards that matter are Warning/Error; the rest pass quietly.</summary>
    public static AreaReport Build(SecurityFacts f)
    {
        var cards = new List<AreaCard>
        {
            EncryptionCard(f), SecureBootCard(f), TpmCard(f), AntivirusCard(f), FirewallCard(f),
            PuaCard(f), NetworkProtectionCard(f), AsrCard(f), LlmnrCard(f), AutoRunCard(f), GuestCard(f),
        };
        var issues = cards.Count(c => c.Level is AreaLevel.Warning or AreaLevel.Error);
        var fixable = cards.Count(c => c.Level is AreaLevel.Warning or AreaLevel.Error && c.Actions is { Count: > 0 } acts && acts.Any(a => a.Kind != RemediationKind.OpenSettings));
        var summary = issues == 0 ? "All key security settings look good"
            : $"{Plural(issues, "setting")} worth changing" + (fixable > 0 ? $" ({fixable} can be fixed here)" : "")
              + " · " + string.Join(" · ", cards.Where(c => c.Level is AreaLevel.Warning or AreaLevel.Error).Take(3).Select(c => c.Headline));
        return new(cards, summary, AreaReport.Worst(cards.Select(c => c.Level)));
    }

    private static AreaAction OpenSettings(string buttonText, string uri, string label) =>
        new(RemediationKind.OpenSettings, buttonText, uri, label);

    private static AreaCard SecureBootCard(SecurityFacts f)
    {
        var (level, headline, impact) = f.SecureBoot switch
        {
            true => (AreaLevel.Ok, "Secure Boot is on", "Only trusted, signed startup software can load before Windows."),
            false => (AreaLevel.Warning, "Secure Boot is off", "Malware that loads before Windows (a bootkit) isn't blocked, and Device encryption can't be turned on."),
            null when f.IsLegacy => (AreaLevel.Warning, "Legacy BIOS mode", "This PC starts in legacy BIOS mode, so Secure Boot isn't available."),
            _ => (AreaLevel.Neutral, "Secure Boot not reported", "Windows didn't report a Secure Boot state on this PC."),
        };
        var rows = new List<AreaRow>
        {
            Row(level, "Secure Boot", f.SecureBoot switch { true => "On", false => "Off", _ => "Not available" }),
            Row(AreaLevel.Neutral, "Startup mode", f.IsUefi ? "UEFI" : f.IsLegacy ? "Legacy BIOS" : "Not reported"),
        };
        if (f.SecureBootServicing is { } sbs)
        {
            var (certLevel, certText) = FormatSecureBoot2023Status(sbs);
            if (certText is not null)
                rows.Add(Row(certLevel, "2023 Secure Boot certs", certText));

            if (sbs.UefiCa2023Error is > 0)
            {
                var errHex = $"0x{unchecked((uint)sbs.UefiCa2023Error.Value):X8}";
                var errText = sbs.UefiCa2023ErrorEvent is > 0
                    ? $"{errHex} (Event {sbs.UefiCa2023ErrorEvent.Value})"
                    : errHex;
                rows.Add(Row(AreaLevel.Warning, "2023 cert servicing error", errText));
            }

            if (sbs.AvailableUpdates is > 0)
                rows.Add(Row(AreaLevel.Neutral, "Pending Secure Boot updates", $"0x{unchecked((uint)sbs.AvailableUpdates.Value):X4}"));
        }
        rows.Add(Means(impact));
        return new("secureboot", "Secure Boot", level, headline, f.IsUefi ? "UEFI startup" : "", Cols, rows,
            Note: f.SecureBoot == false ? FirmwareHint + " Windows already starts in UEFI mode, so it keeps booting normally. Only unsigned boot software (for example some Linux installs) would stop loading." : null);
    }

    private static (AreaLevel Level, string? Text) FormatSecureBoot2023Status(SecureBootServicingFacts sbs)
    {
        var status = sbs.UefiCa2023Status?.Trim();
        return sbs.WindowsUefiCa2023Capable switch
        {
            2 => (AreaLevel.Ok, string.IsNullOrEmpty(status) ? "Updated (2023 CA & boot manager)" : $"{status} (2023 CA & boot manager)"),
            1 => (AreaLevel.Neutral, string.IsNullOrEmpty(status) ? "2023 CA in firmware (boot manager pending)" : $"{status} (2023 CA in firmware)"),
            0 => (AreaLevel.Neutral, string.IsNullOrEmpty(status) ? "Not yet in firmware" : $"{status} (not yet in firmware)"),
            _ => string.IsNullOrEmpty(status)
                ? (AreaLevel.Neutral, null)
                : (string.Equals(status, "Updated", StringComparison.OrdinalIgnoreCase) ? AreaLevel.Ok : AreaLevel.Neutral, status),
        };
    }

    private static AreaCard TpmCard(SecurityFacts f)
    {
        if (f.Tpm is not { } tpm)
            return new("tpm", "Security chip (TPM)", AreaLevel.Neutral, "Couldn't read the TPM", "", Cols, [Row(AreaLevel.Neutral, "TPM", "Not reported")]);
        var level = !tpm.Present || !tpm.IsVersion2 || tpm.ReadyForStorage == false ? AreaLevel.Warning : AreaLevel.Ok;
        var headline = !tpm.Present ? "No TPM found"
            : string.Join(" ", new[] { "TPM", VersionLabel(tpm.Version), tpm.ReadyForStorage == false ? "(not ready)" : "ready" }.Where(x => x.Length > 0));
        var rows = new List<AreaRow> { Row(tpm.Present ? AreaLevel.Ok : AreaLevel.Warning, "Present", tpm.Present ? "Yes" : "No") };
        if (tpm.Present)
        {
            rows.Add(Row(tpm.IsVersion2 ? AreaLevel.Ok : AreaLevel.Warning, "Version", tpm.Version ?? "Not reported"));
            if (tpm.ReadyForStorage is { } ready) rows.Add(Row(ready ? AreaLevel.Ok : AreaLevel.Warning, "Ready to protect keys", ready ? "Yes" : "No"));
            if (tpm.Manufacturer is { Length: > 0 } m) rows.Add(Row(AreaLevel.Neutral, "Maker", m));
        }
        rows.Add(Means("The TPM keeps encryption keys and Windows Hello sign-in safe, even if someone takes the drive out."));
        return new("tpm", "Security chip (TPM)", level, headline, tpm.Present ? tpm.Manufacturer ?? "" : "", Cols, rows,
            Note: !tpm.Present ? "Windows 11 and Device encryption need a TPM 2.0. Most PCs from 2016 on have one built into the processor; turn on AMD fTPM or Intel PTT in the firmware setup."
                : !tpm.IsVersion2 ? "This is an older TPM 1.2. Windows 11 and Device encryption need TPM 2.0." : null);
    }

    private static AreaCard EncryptionCard(SecurityFacts f)
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
            Row(level, $"Drive {f.SystemDrive}", prot switch
            {
                DriveProtection.Protected => "Encrypted", DriveProtection.Encrypting => "Encrypting", DriveProtection.Suspended => "Encrypted, protection paused",
                DriveProtection.NotProtected => "Not encrypted", _ => "Not reported",
            }),
            Row(AreaLevel.Neutral, "Windows edition", f.IsHome ? "Home (Device encryption)" : f.Edition is { } ed ? $"{ed} (BitLocker)" : "Not reported"),
            Means(prot == DriveProtection.NotProtected
                ? "If this PC is lost or stolen, anyone who removes the drive can read your files."
                : "Files on this drive can't be read if the drive is removed from the PC."),
        };
        if (prot == DriveProtection.NotProtected) rows.Add(Row(blocker is null ? AreaLevel.Neutral : AreaLevel.Warning, "Can it be turned on?", blocker is null ? "Yes" : "Not yet: " + blocker));
        IReadOnlyList<AreaAction>? actions = prot == DriveProtection.NotProtected && blocker is null
            ? [OpenSettings("Open Device encryption", "ms-settings:deviceencryption", "Settings (Device encryption)")]
            : null;
        return new("encryption", "Drive encryption", level, headline, name, Cols, rows, Note: how, Actions: actions);
    }

    private static AreaCard AntivirusCard(SecurityFacts f)
    {
        var others = f.Antivirus.Where(n => !n.Contains("Defender", StringComparison.OrdinalIgnoreCase)).ToList();
        AreaLevel level; string headline; string? note = null;
        IReadOnlyList<AreaAction>? actions = null;
        if (f.DefenderActive)
        {
            var rtpOff = f.RealTimeProtection == false;
            level = rtpOff ? AreaLevel.Error : f.TamperProtection == false ? AreaLevel.Warning : AreaLevel.Ok;
            headline = rtpOff ? "Real-time protection is off" : f.TamperProtection == false ? "Tamper Protection is off" : "Microsoft Defender is protecting this PC";
            if (rtpOff)
            {
                note = "Turn on Real-time protection in Windows Security > Virus & threat protection > Manage settings.";
                actions = [OpenSettings("Open Windows Security", "windowsdefender://threatsettings", "Windows Security (Virus & threat protection settings)")];
            }
            else if (f.TamperProtection == false)
            {
                note = "Windows blocks apps from changing Tamper Protection directly. Open Windows Security > Virus & threat protection > Manage settings and switch Tamper Protection on, so malware can't switch Defender off.";
                actions = [OpenSettings("Open Windows Security", "windowsdefender://threatsettings", "Windows Security (Virus & threat protection settings)")];
            }
        }
        else if (others.Count > 0) { level = AreaLevel.Ok; headline = $"Protected by {others[0]}"; }
        else if (f.DefenderMode is null && f.Antivirus.Count == 0) { level = AreaLevel.Neutral; headline = "Antivirus not reported"; }
        else
        {
            level = AreaLevel.Error; headline = "No active antivirus";
            note = "Open Windows Security > Virus & threat protection and turn Microsoft Defender back on, or install another antivirus.";
            actions = [OpenSettings("Open Windows Security", "windowsdefender://threat", "Windows Security (Virus & threat protection)")];
        }
        var rows = new List<AreaRow>
        {
            Row(AreaLevel.Neutral, "Antivirus", f.Antivirus.Count > 0 ? string.Join(", ", f.Antivirus) : "Not reported"),
            Row(AreaLevel.Neutral, "Microsoft Defender", f.DefenderActive ? "Active" : f.DefenderMode ?? "Not reported"),
        };
        if (f.DefenderActive && f.RealTimeProtection is { } rtp) rows.Add(Row(rtp ? AreaLevel.Ok : AreaLevel.Error, "Real-time protection", rtp ? "On" : "Off"));
        if (f.DefenderActive && f.TamperProtection is { } tp) rows.Add(Row(tp ? AreaLevel.Ok : AreaLevel.Warning, "Tamper Protection", tp ? "On" : "Off"));
        rows.Add(Means("Antivirus with real-time protection blocks malware as it arrives, before it can run."));
        return new("antivirus", "Antivirus", level, headline, "", Cols, rows, Note: note, Actions: actions);
    }

    private static AreaCard FirewallCard(SecurityFacts f)
    {
        if (f.Firewall.Count == 0)
            return new("firewall", "Windows Firewall", AreaLevel.Neutral, "Firewall not reported", "", Cols, [Row(AreaLevel.Neutral, "Firewall", "Not reported")]);
        var off = f.Firewall.Where(kv => !kv.Value).Select(kv => kv.Key).ToList();
        var level = off.Count == 0 ? AreaLevel.Ok : off.Any(p => p.Equals("Public", StringComparison.OrdinalIgnoreCase)) ? AreaLevel.Error : AreaLevel.Warning;
        var rows = f.Firewall.Select(kv => Row(kv.Value ? AreaLevel.Ok : AreaLevel.Warning, $"{kv.Key} networks", kv.Value ? "On" : "Off")).ToList();
        rows.Add(Means("The firewall stops other devices on the network from connecting to programs on this PC."));
        return new("firewall", "Windows Firewall", level, off.Count == 0 ? "Firewall is on" : $"Firewall is off for {string.Join(" and ", off.Select(p => p.ToLowerInvariant()))} networks", "", Cols, rows,
            Note: off.Count > 0 ? "Turn it back on in Windows Security > Firewall & network protection, unless another security product manages the firewall." : null,
            Actions: off.Count > 0 ? [OpenSettings("Open Firewall settings", "windowsdefender://network", "Windows Security (Firewall & network protection)")] : null);
    }

    private static AreaCard DefenderSettingCard(SecurityFacts f, string id, string key, int? value, string onText, string offText)
    {
        var fix = SecurityFixes.Find(key)!;
        if (!f.DefenderActive || value is null)
            return new(id, fix.Label, AreaLevel.Neutral, f.DefenderActive ? "Not reported" : "Managed by your antivirus", "", Cols,
                [Row(AreaLevel.Neutral, fix.Label, f.DefenderActive ? "Not reported" : "Microsoft Defender isn't the active antivirus"), Means(fix.WhatItIs)]);
        var on = value == 1;
        var level = on ? AreaLevel.Ok : AreaLevel.Warning;
        return new(id, fix.Label, level, on ? onText : offText, value == 2 ? "Audit only" : "", Cols,
            [Row(level, fix.Label, value switch { 1 => "On (blocks)", 2 => "Audit only (logs, doesn't block)", _ => "Off" }), Means(fix.WhatItIs)],
            Note: on ? null : fix.WhatHappens + (fix.Caveat is { } c ? " " + c : ""), Actions: on ? null : [Fix(key)]);
    }

    private static AreaCard PuaCard(SecurityFacts f) => DefenderSettingCard(f, "pua", SecurityFixes.Pua, f.Pua, "Unwanted apps are blocked", "Unwanted app blocking is off");

    private static AreaCard NetworkProtectionCard(SecurityFacts f) =>
        DefenderSettingCard(f, "networkprotection", SecurityFixes.NetworkProtection, f.NetworkProtection, "Dangerous sites are blocked", "Network protection is off");

    private static AreaCard AsrCard(SecurityFacts f)
    {
        var fix = SecurityFixes.Find(SecurityFixes.AsrRules)!;
        if (!f.DefenderActive || f.AsrRules is not { } asr)
            return new("asr", fix.Label, AreaLevel.Neutral, f.DefenderActive ? "Not reported" : "Managed by your antivirus", "", Cols,
                [Row(AreaLevel.Neutral, fix.Label, f.DefenderActive ? "Not reported" : "Microsoft Defender isn't the active antivirus"), Means(fix.WhatItIs)]);
        var rows = SecurityFixes.SafeAsrRules.Select(r =>
        {
            var a = asr.GetValueOrDefault(r.Id, 0);
            return Row(a == 1 ? AreaLevel.Ok : AreaLevel.Warning, r.Name, a switch { 1 => "On (blocks)", 2 => "Audit only", 6 => "Warns", _ => "Off" });
        }).ToList();
        var onCount = SecurityFixes.SafeAsrRules.Count(r => asr.GetValueOrDefault(r.Id) == 1);
        var all = onCount == SecurityFixes.SafeAsrRules.Count;
        rows.Add(Means(fix.WhatItIs));
        return new("asr", fix.Label, all ? AreaLevel.Ok : AreaLevel.Warning,
            all ? "Key protection rules are on" : onCount == 0 ? "Protection rules are off" : $"{onCount} of {SecurityFixes.SafeAsrRules.Count} protection rules on",
            "Microsoft Defender", Cols, rows, Note: all ? null : fix.WhatHappens + " " + fix.Caveat, Actions: all ? null : [Fix(SecurityFixes.AsrRules)], PreserveRowOrder: true);
    }

    private static AreaCard LlmnrCard(SecurityFacts f)
    {
        var fix = SecurityFixes.Find(SecurityFixes.Llmnr)!;
        var off = f.LlmnrPolicy == 0;
        var level = off ? AreaLevel.Ok : AreaLevel.Warning;
        return new("llmnr", fix.Label, level, off ? "LLMNR is off" : "LLMNR is on", "", Cols,
            [Row(level, "LLMNR", off ? "Off" : f.LlmnrPolicy is null ? "On (Windows default)" : "On"), Means(fix.WhatItIs)],
            Note: off ? null : fix.WhatHappens, Actions: off ? null : [Fix(SecurityFixes.Llmnr)]);
    }

    /// <summary>Windows' NoDriveTypeAutoRun when no policy is set (0x91: off for unknown, network and other drive types).</summary>
    public const long AutoRunWindowsDefault = 0x91;
    private const long AllLetters = (1L << 26) - 1;

    /// <summary>The drive types NoDriveTypeAutoRun covers, in the order they're listed (bit 0x02, "no root folder", can't AutoRun).</summary>
    private static readonly (long Bit, int DriveType, string Name, string Row)[] AutoRunTypes =
    [
        (0x04, 2, "removable", "Removable drives (USB sticks, memory cards)"),
        (0x20, 5, "CD/DVD", "CD/DVD drives"),
        (0x08, 3, "fixed", "Fixed drives (internal and external disks)"),
        (0x10, 4, "network", "Network drives"),
        (0x40, 6, "RAM", "RAM disks"),
        (0x81, 0, "unknown", "Other drive types"),
    ];

    /// <summary>The NoDriveTypeAutoRun value in effect: the machine policy, else the user policy, else Windows' default.</summary>
    public static long EffectiveAutoRunTypes(SecurityFacts f) => f.AutoRunPolicy ?? f.AutoRunUserPolicy ?? AutoRunWindowsDefault;

    /// <summary>The drive types AutoRun is still on for, e.g. ["removable", "CD/DVD"]; empty when it's off everywhere.</summary>
    public static IReadOnlyList<string> AutoRunOnFor(SecurityFacts f)
    {
        if (((f.AutoRunLetterPolicy ?? 0) & AllLetters) == AllLetters) return [];
        var mask = EffectiveAutoRunTypes(f);
        return AutoRunTypes.Where(t => (mask & t.Bit) != t.Bit).Select(t => t.Name).ToList();
    }

    private static string JoinAnd(IReadOnlyList<string> items) =>
        items.Count <= 1 ? string.Concat(items) : string.Join(", ", items.Take(items.Count - 1)) + " and " + items[^1];

    private static AreaCard AutoRunCard(SecurityFacts f)
    {
        var fix = SecurityFixes.Find(SecurityFixes.AutoRun)!;
        var onFor = AutoRunOnFor(f);
        var off = onFor.Count == 0;
        var level = off ? AreaLevel.Ok : AreaLevel.Warning;
        var mask = EffectiveAutoRunTypes(f);
        var letterMask = f.AutoRunLetterPolicy ?? 0;
        bool LetterOff(char letter) => (letterMask & (1L << (letter - 'A'))) != 0;

        var rows = new List<AreaRow>();
        if (off) rows.Add(Row(level, "AutoRun", "Off for all drives"));
        else
        {
            var source = f.AutoRunPolicy is not null ? "" : f.AutoRunUserPolicy is not null ? " (your user policy)" : " (Windows default)";
            foreach (var t in AutoRunTypes.Where(t => (mask & t.Bit) != t.Bit))
            {
                var letters = f.Drives.Where(d => d.Value == t.DriveType && !LetterOff(d.Key)).Select(d => d.Key + ":").Order(StringComparer.Ordinal).ToList();
                rows.Add(Row(AreaLevel.Warning, t.Row, "On" + source + (letters.Count > 0 ? " · " + string.Join(", ", letters) : "")));
            }
            var offTypes = AutoRunTypes.Where(t => (mask & t.Bit) == t.Bit).Select(t => t.Name).ToList();
            if (offTypes.Count > 0) rows.Add(Row(AreaLevel.Ok, "Off for", JoinAnd(offTypes) + " drives"));
            var offLetters = Enumerable.Range(0, 26).Where(i => (letterMask & (1L << i)) != 0).Select(i => (char)('A' + i) + ":").ToList();
            if (offLetters.Count > 0) rows.Add(Row(AreaLevel.Ok, "Off by drive letter", string.Join(", ", offLetters)));
        }
        rows.Add(Means(fix.WhatItIs));
        return new("autorun", fix.Label, level, off ? "AutoRun is off" : $"AutoRun is on for {JoinAnd(onFor)} drives", "", Cols, rows,
            Note: off ? null : fix.WhatHappens, Actions: off ? null : [Fix(SecurityFixes.AutoRun)], PreserveRowOrder: true);
    }

    /// <summary>Fixable, but the fix isn't ticked by default in the fix list: turning guest logons off can cut off old network drives (NAS).
    /// Windows Home allows them unless a policy says otherwise; newer Pro and Enterprise builds turn them off by default.</summary>
    private static AreaCard GuestCard(SecurityFacts f)
    {
        var fix = SecurityFixes.Find(SecurityFixes.GuestLogons)!;
        var (level, headline, value) = f.InsecureGuest switch
        {
            0 => (AreaLevel.Ok, "Insecure guest logons are off", "Off"),
            1 => (AreaLevel.Warning, "Insecure guest logons are allowed", "Allowed"),
            _ when f.IsHome => (AreaLevel.Warning, "Insecure guest logons are allowed", "Allowed (Windows Home default)"),
            _ => (AreaLevel.Neutral, "Insecure guest logons: Windows default", "Windows default"),
        };
        var fixable = level == AreaLevel.Warning;
        return new("guest", fix.Label, level, headline, "", Cols, [Row(level, "Guest access to network drives", value), Means(fix.WhatItIs)],
            Note: fixable ? fix.WhatHappens + " " + fix.Caveat : null, Actions: fixable ? [Fix(SecurityFixes.GuestLogons)] : null);
    }

    private static string VersionLabel(string? v) => v is null ? "" : v.Split(',', StringSplitOptions.TrimEntries)[0];
}
