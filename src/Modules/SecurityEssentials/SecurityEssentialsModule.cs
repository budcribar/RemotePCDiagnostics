using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Security;

/// <summary>What the Security essentials probe read. Null fields couldn't be read.</summary>
/// <param name="SecureBoot">UEFISecureBootEnabled: true on, false off, null when the key is missing (legacy BIOS or no Secure Boot support).</param>
/// <param name="Firmware">"UEFI" or "Legacy" (Windows' firmware_type), or null.</param>
/// <param name="Edition">EditionID, e.g. "Core" (Home) or "Professional".</param>
/// <param name="Encryption">Shell property System.Volume.BitLockerProtection of the system drive, or null.</param>
/// <param name="Tpm">tpmtool details, or null when tpmtool couldn't run.</param>
public sealed record SecurityFacts(bool? SecureBoot, string? Firmware, string? Edition, int? Encryption, TpmFacts? Tpm, string SystemDrive = "C:")
{
    /// <summary>Get-MpComputerStatus AMRunningMode: "Normal" when Defender is the active antivirus; "Passive mode" / "EDR Block Mode" / null otherwise.</summary>
    public string? DefenderMode { get; init; }
    public bool? RealTimeProtection { get; init; }
    public bool? TamperProtection { get; init; }
    /// <summary>Get-MpPreference PUAProtection: 0 off, 1 block, 2 audit.</summary>
    public int? Pua { get; init; }
    /// <summary>Get-MpPreference EnableNetworkProtection: 0 off, 1 block, 2 audit.</summary>
    public int? NetworkProtection { get; init; }
    /// <summary>Configured ASR rules (lower-case id → action: 0 off, 1 block, 2 audit, 6 warn). Null = couldn't read.</summary>
    public IReadOnlyDictionary<string, int>? AsrRules { get; init; }
    /// <summary>Registered antivirus products (Security Center), e.g. ["Windows Defender"].</summary>
    public IReadOnlyList<string> Antivirus { get; init; } = [];
    /// <summary>Windows Firewall profile → on. Empty = couldn't read.</summary>
    public IReadOnlyDictionary<string, bool> Firewall { get; init; } = new Dictionary<string, bool>();
    /// <summary>Policy EnableMulticast (0 = LLMNR off), null when not set (Windows default: on).</summary>
    public long? LlmnrPolicy { get; init; }
    /// <summary>Policy NoDriveTypeAutoRun, null when not set (Windows default: AutoRun on for some drives).</summary>
    public long? AutoRunPolicy { get; init; }
    /// <summary>AllowInsecureGuestAuth (policy first, then the LanmanWorkstation parameter), null when neither is set.</summary>
    public long? InsecureGuest { get; init; }

    public bool IsUefi => string.Equals(Firmware, "UEFI", StringComparison.OrdinalIgnoreCase);
    public bool IsLegacy => string.Equals(Firmware, "Legacy", StringComparison.OrdinalIgnoreCase);
    public bool IsHome => Edition is { } e && e.StartsWith("Core", StringComparison.OrdinalIgnoreCase);
    /// <summary>Defender is the active antivirus, so its settings apply (another antivirus puts it in passive mode).</summary>
    public bool DefenderActive => string.Equals(DefenderMode, "Normal", StringComparison.OrdinalIgnoreCase);
}

/// <summary>The lines of <c>tpmtool getdeviceinformation</c> this check uses.</summary>
public sealed record TpmFacts(bool Present, string? Version, bool? ReadyForStorage, string? Manufacturer, string? Pcr7Binding)
{
    public bool IsVersion2 => Version is { } v && v.TrimStart().StartsWith("2", StringComparison.Ordinal);
    public bool Pcr7BindingPossible => Pcr7Binding is null || !Pcr7Binding.Contains("Not Possible", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// The security settings that matter most on a typical PC, each explained in plain words, read without administrator rights:
/// Secure Boot, TPM and drive encryption; antivirus and firewall; Defender's PUA blocking, network protection and a safe set of
/// Attack Surface Reduction rules; LLMNR, AutoRun and insecure guest logons. The settings this app can change safely carry a fix
/// (<see cref="RemediationKind.ApplySecuritySetting"/>), which puts them in the fix list with Undo.
/// </summary>
public sealed class SecurityEssentialsModule(SystemCommandRunner commands) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = ModuleSlugs.SecurityEssentials;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.SecurityEssentials;
    public override string DisplayName => "Security essentials";
    protected override string FailedMessage => "Couldn't read this PC's security settings.";

    public static string TpmTool => SystemCommandRunner.SystemTool("tpmtool.exe");

    /// <summary>Read-only probe: registry values, Defender status, firewall profiles and one Shell property, printed as key=value lines.</summary>
    public static readonly string ProbeScript =
        "$ErrorActionPreference='SilentlyContinue';" +
        "function D($k,$n){$v=(Get-ItemProperty -Path $k -Name $n).$n;if($null -eq $v){''}else{[int64]$v}};" +
        "$s=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State';" +
        "if($s -and $null -ne $s.UEFISecureBootEnabled){'SecureBoot='+$s.UEFISecureBootEnabled}else{'SecureBoot='};" +
        "'Firmware='+$env:firmware_type;" +
        "'Edition='+(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').EditionID;" +
        "'SystemDrive='+$env:SystemDrive;" +
        "try{'Encryption='+(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive+'\\').Self.ExtendedProperty('System.Volume.BitLockerProtection')}catch{'Encryption='};" +
        "$c=Get-MpComputerStatus;if($c){'DefenderMode='+$c.AMRunningMode;'RealTime='+$c.RealTimeProtectionEnabled;'Tamper='+$c.IsTamperProtected};" +
        "$p=Get-MpPreference;if($p){'Pua='+[int]$p.PUAProtection;'NetworkProtection='+[int]$p.EnableNetworkProtection;" +
        "$ids=@($p.AttackSurfaceReductionRules_Ids);$a=@($p.AttackSurfaceReductionRules_Actions);" +
        "'Asr='+((0..($ids.Count-1)|Where-Object{$ids[$_]}|ForEach-Object{$ids[$_]+':'+[int]$a[$_]}) -join ',')};" +
        "'Antivirus='+((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|ForEach-Object{$_.displayName}) -join ';');" +
        "'Firewall='+((Get-NetFirewallProfile|ForEach-Object{$_.Name+':'+$_.Enabled}) -join ',');" +
        "'Llmnr='+(D '" + SecurityFixes.LlmnrKey + "' '" + SecurityFixes.LlmnrValue + "');" +
        "'AutoRun='+(D '" + SecurityFixes.AutoRunKey + "' '" + SecurityFixes.AutoRunValue + "');" +
        "$g=D 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation' 'AllowInsecureGuestAuth';" +
        "if([string]$g -eq ''){$g=D 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' 'AllowInsecureGuestAuth'};'InsecureGuest='+$g";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Checking security settings…");
        var probe = await commands.RunPowerShellAsync(ProbeScript, ct).ConfigureAwait(false);
        progress.ReportStep(2, 2, "Checking the security chip (TPM)…");

        var tpm = await commands.RunAsync(TpmTool, ["getdeviceinformation"], ct).ConfigureAwait(false);
        if (probe is not { ExitCode: 0 } && tpm is not { ExitCode: 0 }) return AreaReport.Failed(FailedMessage);
        var facts = ParseProbe(probe is { ExitCode: 0 } ? probe.StdOut : null, tpm is { ExitCode: 0 } ? ParseTpm(tpm.StdOut) : null);
        Log($"{Name}: secureBoot={facts.SecureBoot?.ToString() ?? "?"} firmware={facts.Firmware ?? "?"} edition={facts.Edition ?? "?"} encryption={facts.Encryption?.ToString() ?? "?"} " +
            $"tpm={(facts.Tpm is { } t ? $"present={t.Present} v={t.Version} ready={t.ReadyForStorage} pcr7={t.Pcr7Binding}" : "?")} defender={facts.DefenderMode ?? "?"} pua={facts.Pua} np={facts.NetworkProtection} " +
            $"asr={facts.AsrRules?.Count.ToString(CultureInfo.InvariantCulture) ?? "?"} av='{string.Join(";", facts.Antivirus)}' fw={string.Join(",", facts.Firewall.Select(kv => $"{kv.Key}:{kv.Value}"))} " +
            $"llmnr={facts.LlmnrPolicy} autorun={facts.AutoRunPolicy} guest={facts.InsecureGuest}");
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

    public static SecurityFacts ParseProbe(string? stdout, TpmFacts? tpm)
    {
        var kv = KeyValues(stdout, '=');
        string? Str(string k) => kv.TryGetValue(k, out var v) && v.Length > 0 ? v : null;
        int? Int(string k) => Str(k) is { } s && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;
        long? Long(string k) => Str(k) is { } s && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;
        bool? Bool(string k) => Str(k) is { } s && bool.TryParse(s, out var b) ? b : null;

        IReadOnlyDictionary<string, int>? asr = null;
        if (kv.TryGetValue("Asr", out var asrText))
        {
            var d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in asrText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var c = part.LastIndexOf(':');
                if (c > 0 && int.TryParse(part[(c + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var act)) d[part[..c].ToLowerInvariant()] = act;
            }
            asr = d;
        }
        var fw = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in (Str("Firewall") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var c = part.IndexOf(':');
            if (c > 0) fw[part[..c]] = part[(c + 1)..].Equals("True", StringComparison.OrdinalIgnoreCase);
        }

        return new(Int("SecureBoot") is { } sb ? sb != 0 : null, Str("Firmware"), Str("Edition"), Int("Encryption"), tpm, Str("SystemDrive") ?? "C:")
        {
            DefenderMode = Str("DefenderMode"), RealTimeProtection = Bool("RealTime"), TamperProtection = Bool("Tamper"),
            Pua = Int("Pua"), NetworkProtection = Int("NetworkProtection"), AsrRules = asr,
            Antivirus = (Str("Antivirus") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Firewall = fw, LlmnrPolicy = Long("Llmnr"), AutoRunPolicy = Long("AutoRun"), InsecureGuest = Long("InsecureGuest"),
        };
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
        var fixable = cards.Count(c => c.Level is AreaLevel.Warning or AreaLevel.Error && c.Actions is { Count: > 0 });
        var summary = issues == 0 ? "All key security settings look good"
            : $"{Plural(issues, "setting")} worth changing" + (fixable > 0 ? $" ({fixable} can be fixed here)" : "")
              + " · " + string.Join(" · ", cards.Where(c => c.Level is AreaLevel.Warning or AreaLevel.Error).Take(3).Select(c => c.Headline));
        return new(cards, summary, AreaReport.Worst(cards.Select(c => c.Level)));
    }

    private static AreaCard SecureBootCard(SecurityFacts f)
    {
        var (level, headline, impact) = f.SecureBoot switch
        {
            true => (AreaLevel.Ok, "Secure Boot is on", "Only trusted, signed startup software can load before Windows."),
            false => (AreaLevel.Warning, "Secure Boot is off", "Malware that loads before Windows (a bootkit) isn't blocked, and Device encryption can't be turned on."),
            null when f.IsLegacy => (AreaLevel.Warning, "Legacy BIOS mode", "This PC starts in legacy BIOS mode, so Secure Boot isn't available."),
            _ => (AreaLevel.Neutral, "Secure Boot not reported", "Windows didn't report a Secure Boot state on this PC."),
        };
        return new("secureboot", "Secure Boot", level, headline, f.IsUefi ? "UEFI startup" : "", Cols,
        [
            Row(level, "Secure Boot", f.SecureBoot switch { true => "On", false => "Off", _ => "Not available" }),
            Row(AreaLevel.Neutral, "Startup mode", f.IsUefi ? "UEFI" : f.IsLegacy ? "Legacy BIOS" : "Not reported"),
            Means(impact),
        ], Note: f.SecureBoot == false ? FirmwareHint + " Windows already starts in UEFI mode, so it keeps booting normally. Only unsigned boot software (for example some Linux installs) would stop loading." : null);
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
        return new("encryption", "Drive encryption", level, headline, name, Cols, rows, Note: how);
    }

    private static AreaCard AntivirusCard(SecurityFacts f)
    {
        var others = f.Antivirus.Where(n => !n.Contains("Defender", StringComparison.OrdinalIgnoreCase)).ToList();
        AreaLevel level; string headline; string? note = null;
        if (f.DefenderActive)
        {
            var rtpOff = f.RealTimeProtection == false;
            level = rtpOff ? AreaLevel.Error : f.TamperProtection == false ? AreaLevel.Warning : AreaLevel.Ok;
            headline = rtpOff ? "Real-time protection is off" : f.TamperProtection == false ? "Tamper Protection is off" : "Microsoft Defender is protecting this PC";
            if (rtpOff) note = "Turn on Real-time protection in Windows Security > Virus & threat protection > Manage settings.";
            else if (f.TamperProtection == false) note = "Turn on Tamper Protection in Windows Security > Virus & threat protection > Manage settings, so malware can't switch Defender off.";
        }
        else if (others.Count > 0) { level = AreaLevel.Ok; headline = $"Protected by {others[0]}"; }
        else if (f.DefenderMode is null && f.Antivirus.Count == 0) { level = AreaLevel.Neutral; headline = "Antivirus not reported"; }
        else
        {
            level = AreaLevel.Error; headline = "No active antivirus";
            note = "Open Windows Security > Virus & threat protection and turn Microsoft Defender back on, or install another antivirus.";
        }
        var rows = new List<AreaRow>
        {
            Row(AreaLevel.Neutral, "Antivirus", f.Antivirus.Count > 0 ? string.Join(", ", f.Antivirus) : "Not reported"),
            Row(AreaLevel.Neutral, "Microsoft Defender", f.DefenderActive ? "Active" : f.DefenderMode ?? "Not reported"),
        };
        if (f.DefenderActive && f.RealTimeProtection is { } rtp) rows.Add(Row(rtp ? AreaLevel.Ok : AreaLevel.Error, "Real-time protection", rtp ? "On" : "Off"));
        if (f.DefenderActive && f.TamperProtection is { } tp) rows.Add(Row(tp ? AreaLevel.Ok : AreaLevel.Warning, "Tamper Protection", tp ? "On" : "Off"));
        rows.Add(Means("Antivirus with real-time protection blocks malware as it arrives, before it can run."));
        return new("antivirus", "Antivirus", level, headline, "", Cols, rows, Note: note);
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
            Note: off.Count > 0 ? "Turn it back on in Windows Security > Firewall & network protection, unless another security product manages the firewall." : null);
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

    private static AreaCard AutoRunCard(SecurityFacts f)
    {
        var fix = SecurityFixes.Find(SecurityFixes.AutoRun)!;
        var off = f.AutoRunPolicy is { } v && (v & SecurityFixes.AutoRunAllDrives) == SecurityFixes.AutoRunAllDrives;
        var level = off ? AreaLevel.Ok : AreaLevel.Warning;
        return new("autorun", fix.Label, level, off ? "AutoRun is off" : "AutoRun is on for some drives", "", Cols,
            [Row(level, "AutoRun", off ? "Off for all drives" : f.AutoRunPolicy is null ? "On for some drives (Windows default)" : "On for some drives"), Means(fix.WhatItIs)],
            Note: off ? null : fix.WhatHappens, Actions: off ? null : [Fix(SecurityFixes.AutoRun)]);
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
