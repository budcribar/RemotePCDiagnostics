using System.Globalization;
using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

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
    /// <summary>Get-MpPreference MAPSReporting: 0 off, 1 basic, 2 advanced.</summary>
    public int? CloudProtection { get; init; }
    /// <summary>Configured ASR rules (lower-case id → action: 0 off, 1 block, 2 audit, 6 warn). Null = couldn't read.</summary>
    public IReadOnlyDictionary<string, int>? AsrRules { get; init; }
    /// <summary>Registered antivirus products (Security Center), e.g. ["Windows Defender"].</summary>
    public IReadOnlyList<string> Antivirus { get; init; } = [];
    /// <summary>Windows Firewall profile → on. Empty = couldn't read.</summary>
    public IReadOnlyDictionary<string, bool> Firewall { get; init; } = new Dictionary<string, bool>();
    /// <summary>Policy EnableMulticast (0 = LLMNR off), null when not set (Windows default: on).</summary>
    public long? LlmnrPolicy { get; init; }
    /// <summary>Policy NoDriveTypeAutoRun (HKLM), null when not set (Windows default: AutoRun on for some drives).</summary>
    public long? AutoRunPolicy { get; init; }
    /// <summary>Policy NoDriveTypeAutoRun for the signed-in user (HKCU), null when not set. Used only when the HKLM value isn't set.</summary>
    public long? AutoRunUserPolicy { get; init; }
    /// <summary>Policy NoDriveAutoRun (drive letter bits, A: = bit 0), HKLM then HKCU, null when neither is set.</summary>
    public long? AutoRunLetterPolicy { get; init; }
    /// <summary>This PC's drives: letter → Windows drive type (2 removable, 3 fixed, 4 network, 5 CD/DVD, 6 RAM disk). Empty = couldn't read.</summary>
    public IReadOnlyDictionary<char, int> Drives { get; init; } = new Dictionary<char, int>();
    /// <summary>AllowInsecureGuestAuth (policy first, then the LanmanWorkstation parameter), null when neither is set.</summary>
    public long? InsecureGuest { get; init; }
    /// <summary>Secure Boot 2023 certificate servicing state from <c>Control\SecureBoot\Servicing</c>, or null when unavailable.</summary>
    public SecureBootServicingFacts? SecureBootServicing { get; init; }

    public bool IsUefi => string.Equals(Firmware, "UEFI", StringComparison.OrdinalIgnoreCase);
    public bool IsLegacy => string.Equals(Firmware, "Legacy", StringComparison.OrdinalIgnoreCase);
    public bool IsHome => Edition is { } e && e.StartsWith("Core", StringComparison.OrdinalIgnoreCase);
    /// <summary>Defender is the active antivirus, so its settings apply (another antivirus puts it in passive mode).</summary>
    public bool DefenderActive => string.Equals(DefenderMode, "Normal", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Read-only Secure Boot 2023 certificate servicing state under <c>HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot</c>.
/// </summary>
public sealed record SecureBootServicingFacts(
    string? UefiCa2023Status,
    int? WindowsUefiCa2023Capable,
    long? UefiCa2023Error,
    long? UefiCa2023ErrorEvent,
    long? AvailableUpdates)
{
    public bool HasAnyData =>
        !string.IsNullOrWhiteSpace(UefiCa2023Status)
        || WindowsUefiCa2023Capable.HasValue
        || UefiCa2023Error.HasValue
        || UefiCa2023ErrorEvent.HasValue
        || AvailableUpdates.HasValue;
}

/// <summary>The lines of <c>tpmtool getdeviceinformation</c> this check uses.</summary>
public sealed record TpmFacts(bool Present, string? Version, bool? ReadyForStorage, string? Manufacturer, string? Pcr7Binding)
{
    public bool IsVersion2 => Version is { } v && v.TrimStart().StartsWith("2", StringComparison.Ordinal);
    public bool Pcr7BindingPossible => Pcr7Binding is null || !Pcr7Binding.Contains("Not Possible", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Where Security essentials reads from. The app registers <see cref="WmiSecurityEssentialsSource"/> (WMI through the Agent, the registry and
/// tpmtool in the app); the Store edition also has the legacy PowerShell probe (RemotePCDiagnostics.Legacy) for when the Agent isn't connected.
/// </summary>
public interface ISecurityEssentialsSource
{
    /// <summary>What could be read, or null when nothing could.</summary>
    Task<SecurityFacts?> ReadAsync(IProgress<string>? progress, CancellationToken ct);
}

/// <summary><c>tpmtool getdeviceinformation</c>, which both paths use: it needs no administrator rights.</summary>
public static class TpmReader
{
    public static string TpmTool => SystemCommandRunner.SystemTool("tpmtool.exe");
    public static readonly string[] Args = ["getdeviceinformation"];

    /// <summary>The TPM, or null when tpmtool couldn't run or printed no TPM Present line.</summary>
    public static async Task<TpmFacts?> ReadAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        var pr = await commands.RunAsync(TpmTool, Args, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? Parse(pr.StdOut) : null;
    }

    /// <summary>Parses <c>tpmtool getdeviceinformation</c> ("-TPM Present: True" lines). Null when the output has no TPM Present line.</summary>
    public static TpmFacts? Parse(string? stdout)
    {
        var kv = KeyValues(stdout, ':');
        if (!kv.TryGetValue("TPM Present", out var present)) return null;
        bool? Bool(string k) => kv.TryGetValue(k, out var v) && bool.TryParse(v, out var b) ? b : null;
        string? Str(string k) => kv.TryGetValue(k, out var v) && v.Length > 0 ? v : null;
        return new(bool.TryParse(present, out var p) && p, Str("TPM Version"), Bool("Ready For Storage"),
            Str("TPM Manufacturer Full Name") ?? Str("TPM Manufacturer ID"), Str("Bitlocker PCR7 Binding State"));
    }

    /// <summary>"Key: value" (or "Key=value") lines, with a leading "-" dropped; the first separator splits.</summary>
    public static Dictionary<string, string> KeyValues(string? text, char separator)
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
}

/// <summary>
/// Security essentials without PowerShell: Defender, Security Center, the firewall, BitLocker and the drives from WMI (in the app, through the
/// Agent, which has the rights the Defender and BitLocker classes need); Secure Boot, the firmware type, the edition and the policies from the
/// registry (readable by a standard user, so the app reads it); the TPM from tpmtool. Each part that can't be read is left out (not reported).
/// </summary>
public sealed class WmiSecurityEssentialsSource(IWmiSource wmi, IRegistrySource registry, SystemCommandRunner commands) : ISecurityEssentialsSource
{
    public const string Cimv2 = @"root\cimv2";
    public const string DefenderNamespace = @"root\Microsoft\Windows\Defender";
    public const string SecurityCenterNamespace = @"root\SecurityCenter2";
    public const string BitLockerNamespace = @"root\cimv2\Security\MicrosoftVolumeEncryption";
    public const string FirewallNamespace = @"root\StandardCimv2";

    public const string OsSql = "SELECT SystemDrive FROM Win32_OperatingSystem";
    /// <summary>The same query Hardware inventory uses, so one recorded answer serves both.</summary>
    public const string DrivesSql = Areas.WmiHardwareInventorySource.LogicalDrivesSql;
    public const string EncryptionSql = "SELECT DriveLetter, ProtectionStatus, ConversionStatus, IsVolumeInitializedForProtection FROM Win32_EncryptableVolume";
    public const string DefenderStatusSql = "SELECT AMRunningMode, RealTimeProtectionEnabled, IsTamperProtected FROM MSFT_MpComputerStatus";
    public const string DefenderPreferenceSql = "SELECT PUAProtection, EnableNetworkProtection, MAPSReporting, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference";
    public const string AntivirusSql = "SELECT displayName FROM AntiVirusProduct";
    public const string FirewallSql = "SELECT Name, Enabled FROM MSFT_NetFirewallProfile";

    /// <summary>
    /// Only a PC that starts in UEFI mode has UEFISecureBootEnabled (0 or 1), so its presence also gives the firmware type. (PEFirmwareType
    /// under Control would say it directly, but Windows sets it only in Windows PE: both test laptops have none.)
    /// </summary>
    public const string SecureBootKey = @"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
    public const string SecureBootRootKey = @"SYSTEM\CurrentControlSet\Control\SecureBoot";
    public const string SecureBootServicingKey = @"SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing";
    public const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    public const string GuestParametersKey = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";

    public async Task<SecurityFacts?> ReadAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Checking security settings…");
        var anyRead = false;
        async Task<WmiRow?> One(RegistryRoot root, string path, params string[] values)
        {
            var r = await registry.ReadAsync(new RegistryRead(root, path, values), ct).ConfigureAwait(false);
            anyRead |= r.Success;
            return r.Rows?.FirstOrDefault();
        }
        async Task<IReadOnlyList<WmiRow>?> Wmi(string ns, string sql)
        {
            var r = await wmi.QueryAsync(ns, sql, ct).ConfigureAwait(false);
            anyRead |= r.Success;
            return r.Rows;
        }
        async Task<WmiRow?> Policy(string psKey, params string[] values) =>
            PsKey(psKey) is var (root, path) ? await One(root, path, values).ConfigureAwait(false) : null;

        var secureBoot = await One(RegistryRoot.LocalMachine, SecureBootKey, "UEFISecureBootEnabled").ConfigureAwait(false);
        var secureBootRoot = await One(RegistryRoot.LocalMachine, SecureBootRootKey, "AvailableUpdates").ConfigureAwait(false);
        var secureBootServicing = await One(
            RegistryRoot.LocalMachine,
            SecureBootServicingKey,
            "UEFICA2023Status",
            "WindowsUEFICA2023Capable",
            "UEFICA2023Error",
            "UEFICA2023ErrorEvent").ConfigureAwait(false);
        var edition = await One(RegistryRoot.LocalMachine, CurrentVersionKey, "EditionID").ConfigureAwait(false);
        var llmnr = await Policy(SecurityFixes.LlmnrKey, SecurityFixes.LlmnrValue).ConfigureAwait(false);
        var autoRun = await Policy(SecurityFixes.AutoRunKey, SecurityFixes.AutoRunValue, SecurityFixes.AutoRunLettersValue).ConfigureAwait(false);
        var autoRunUser = await Policy(SecurityFixes.AutoRunUserKey, SecurityFixes.AutoRunValue, SecurityFixes.AutoRunLettersValue).ConfigureAwait(false);
        var guestPolicy = await Policy(SecurityFixes.GuestKey, SecurityFixes.GuestValue).ConfigureAwait(false);
        var guestParameter = await One(RegistryRoot.LocalMachine, GuestParametersKey, SecurityFixes.GuestValue).ConfigureAwait(false);

        var os = (await Wmi(Cimv2, OsSql).ConfigureAwait(false))?.FirstOrDefault();
        var drives = await Wmi(Cimv2, DrivesSql).ConfigureAwait(false);
        var volumes = await Wmi(BitLockerNamespace, EncryptionSql).ConfigureAwait(false);
        var status = (await Wmi(DefenderNamespace, DefenderStatusSql).ConfigureAwait(false))?.FirstOrDefault();
        var preference = (await Wmi(DefenderNamespace, DefenderPreferenceSql).ConfigureAwait(false))?.FirstOrDefault();
        var antivirus = await Wmi(SecurityCenterNamespace, AntivirusSql).ConfigureAwait(false);
        var firewall = await Wmi(FirewallNamespace, FirewallSql).ConfigureAwait(false);

        progress.ReportStep(2, 2, "Checking the security chip (TPM)…");
        var tpm = await TpmReader.ReadAsync(commands, ct).ConfigureAwait(false);
        if (!anyRead && tpm is null) return null;

        var systemDrive = os?.Str("SystemDrive") is { Length: 2 } sd && char.IsAsciiLetter(sd[0]) && sd[1] == ':' ? char.ToUpperInvariant(sd[0]) + ":" : "C:";
        var volume = volumes?.FirstOrDefault(v => string.Equals(v.Str("DriveLetter"), systemDrive, StringComparison.OrdinalIgnoreCase));
        var secureBootValue = secureBoot?.Long("UEFISecureBootEnabled");
        var servicingFacts = new SecureBootServicingFacts(
            UefiCa2023Status: secureBootServicing?.Str("UEFICA2023Status") is { Length: > 0 } st ? st : null,
            WindowsUefiCa2023Capable: Int(secureBootServicing, "WindowsUEFICA2023Capable"),
            UefiCa2023Error: secureBootServicing?.Long("UEFICA2023Error"),
            UefiCa2023ErrorEvent: secureBootServicing?.Long("UEFICA2023ErrorEvent"),
            AvailableUpdates: secureBootRoot?.Long("AvailableUpdates"));
        return new SecurityFacts(
            secureBootValue is { } sb ? sb != 0 : null,
            secureBootValue is not null ? "UEFI" : null,
            edition?.Str("EditionID") is { Length: > 0 } ed ? ed : null,
            volume is null ? null : Protection(volume),
            tpm, systemDrive)
        {
            DefenderMode = status?.Str("AMRunningMode") is { Length: > 0 } mode ? mode : null,
            RealTimeProtection = status?.Bool("RealTimeProtectionEnabled"),
            TamperProtection = status?.Bool("IsTamperProtected"),
            Pua = Int(preference, "PUAProtection"),
            NetworkProtection = Int(preference, "EnableNetworkProtection"),
            CloudProtection = Int(preference, "MAPSReporting"),
            AsrRules = preference is null ? null : Asr(preference),
            Antivirus = (antivirus ?? []).Select(r => r.Str("displayName")).Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Firewall = Firewall(firewall),
            LlmnrPolicy = llmnr?.Long(SecurityFixes.LlmnrValue),
            AutoRunPolicy = autoRun?.Long(SecurityFixes.AutoRunValue),
            AutoRunUserPolicy = autoRunUser?.Long(SecurityFixes.AutoRunValue),
            AutoRunLetterPolicy = autoRun?.Long(SecurityFixes.AutoRunLettersValue) ?? autoRunUser?.Long(SecurityFixes.AutoRunLettersValue),
            Drives = Drives(drives),
            InsecureGuest = guestPolicy?.Long(SecurityFixes.GuestValue) ?? guestParameter?.Long(SecurityFixes.GuestValue),
            SecureBootServicing = servicingFacts.HasAnyData ? servicingFacts : null,
        };
    }

    /// <summary>A PowerShell registry path from <see cref="SecurityFixes"/> ("HKLM:\SOFTWARE\…") as a root and a path; null for any other root.</summary>
    public static (RegistryRoot Root, string Path)? PsKey(string psKey)
    {
        if (psKey.StartsWith(@"HKLM:\", StringComparison.OrdinalIgnoreCase)) return (RegistryRoot.LocalMachine, psKey[6..]);
        if (psKey.StartsWith(@"HKCU:\", StringComparison.OrdinalIgnoreCase)) return (RegistryRoot.CurrentUser, psKey[6..]);
        return null;
    }

    /// <summary>
    /// Win32_EncryptableVolume in the words of the Shell property the legacy path reads (System.Volume.BitLockerProtection), which the check
    /// understands: 1 on, 3 encrypting, 5 encrypted with protection suspended, 8 encrypted and waiting for activation (no key protector yet,
    /// as Device encryption is before a Microsoft account signs in), 6 locked, 2 not encrypted, 4 decrypting. Null when Windows didn't say.
    /// </summary>
    public static int? Protection(WmiRow volume)
    {
        var protection = volume.Long("ProtectionStatus");
        var conversion = volume.Long("ConversionStatus");
        return (protection, conversion) switch
        {
            (2, _) => 6,
            (1, 2 or 4) => 3,
            (1, _) => 1,
            (0, 0) => 2,
            (0, 1) => volume.Bool("IsVolumeInitializedForProtection") == false ? 8 : 5,
            (0, 2 or 4) => 3,
            (0, 3 or 5) => 4,
            (0, null) => 2,
            _ => null,
        };
    }

    private static int? Int(WmiRow? row, string name) => row?.Long(name) is { } v and >= int.MinValue and <= int.MaxValue ? (int)v : null;

    /// <summary>The configured rules: AttackSurfaceReductionRules_Ids paired with AttackSurfaceReductionRules_Actions, ids in lower case.</summary>
    public static IReadOnlyDictionary<string, int> Asr(WmiRow preference)
    {
        var ids = Array(preference, "AttackSurfaceReductionRules_Ids");
        var actions = Actions(preference);
        var d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < ids.Count; i++)
        {
            if (ids[i].ValueKind != JsonValueKind.String || ids[i].GetString()!.Trim() is not { Length: > 0 } id) continue;
            // As Get-MpPreference shows it: a rule without an action counts as off.
            var action = i < actions.Count ? actions[i] : 0;
            d[id.ToLowerInvariant()] = action;
        }
        return d;
    }

    /// <summary>
    /// AttackSurfaceReductionRules_Actions is a uint8[], which WMI hands over as bytes, so a recorded or Agent answer holds it as base64
    /// ("AQEBAQE=" is five 1s); a list of numbers is read too.
    /// </summary>
    private static IReadOnlyList<int> Actions(WmiRow preference)
    {
        if (!preference.Values.TryGetValue("AttackSurfaceReductionRules_Actions", out var v)) return [];
        if (v.ValueKind == JsonValueKind.String)
        {
            try { return [.. Convert.FromBase64String(v.GetString()!).Select(b => (int)b)]; }
            catch (FormatException) { return []; }
        }
        return v.ValueKind == JsonValueKind.Array
            ? [.. v.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var a) ? a : 0)]
            : [];
    }

    private static IReadOnlyList<JsonElement> Array(WmiRow row, string name) =>
        row.Values.TryGetValue(name, out var v) && v.ValueKind == JsonValueKind.Array ? [.. v.EnumerateArray()] : [];

    /// <summary>
    /// MSFT_NetFirewallProfile.Enabled is a GpoBoolean: 1 on, 0 off, 2 not configured, which in the local store means Windows' default (on).
    /// </summary>
    public static IReadOnlyDictionary<string, bool> Firewall(IReadOnlyList<WmiRow>? profiles)
    {
        var d = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in profiles ?? [])
        {
            if (p.Str("Name") is not { Length: > 0 } name) continue;
            var enabled = p.Long("Enabled") ?? (p.Bool("Enabled") is { } b ? (b ? 1 : 0) : null);
            if (enabled is 0 or 1 or 2) d[name] = enabled != 0;
        }
        return d;
    }

    /// <summary>Win32_LogicalDisk DeviceID ("C:") → DriveType.</summary>
    public static IReadOnlyDictionary<char, int> Drives(IReadOnlyList<WmiRow>? disks)
    {
        var d = new Dictionary<char, int>();
        foreach (var r in disks ?? [])
        {
            var id = r.Str("DeviceID");
            if (id.Length == 2 && char.IsAsciiLetter(id[0]) && id[1] == ':' && r.Long("DriveType") is { } type and >= 0 and <= 6)
                d[char.ToUpperInvariant(id[0])] = (int)type;
        }
        return d;
    }
}

/// <summary>Picks a source per read: the Agent's when it is connected, otherwise the fallback (the Store edition's legacy probe).</summary>
public sealed class AgentOrFallbackSecurityEssentialsSource(Session.IElevatedCommandBridge agent, ISecurityEssentialsSource withAgent, ISecurityEssentialsSource fallback)
    : ISecurityEssentialsSource
{
    public Task<SecurityFacts?> ReadAsync(IProgress<string>? progress, CancellationToken ct) =>
        (agent.IsConnected ? withAgent : fallback).ReadAsync(progress, ct);
}
