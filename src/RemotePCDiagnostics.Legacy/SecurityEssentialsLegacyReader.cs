using System.Globalization;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Legacy;

/// <summary>
/// Security essentials from one PowerShell probe (registry values, Get-MpComputerStatus, Get-MpPreference, Security Center, the firewall
/// profiles and one Shell property), run as a standard user, plus tpmtool. The Store edition's reader when the Agent isn't connected.
/// </summary>
public sealed class PowerShellSecurityEssentialsSource(SystemCommandRunner commands) : ISecurityEssentialsSource
{
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
        "$p=Get-MpPreference;if($p){'Pua='+[int]$p.PUAProtection;'NetworkProtection='+[int]$p.EnableNetworkProtection;'CloudProtection='+[int]$p.MAPSReporting;" +
        "$ids=@($p.AttackSurfaceReductionRules_Ids);$a=@($p.AttackSurfaceReductionRules_Actions);" +
        "'Asr='+((0..($ids.Count-1)|Where-Object{$ids[$_]}|ForEach-Object{$ids[$_]+':'+[int]$a[$_]}) -join ',')};" +
        "'Antivirus='+((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|ForEach-Object{$_.displayName}) -join ';');" +
        "'Firewall='+((Get-NetFirewallProfile|ForEach-Object{$_.Name+':'+$_.Enabled}) -join ',');" +
        "'Llmnr='+(D '" + SecurityFixes.LlmnrKey + "' '" + SecurityFixes.LlmnrValue + "');" +
        "'AutoRun='+(D '" + SecurityFixes.AutoRunKey + "' '" + SecurityFixes.AutoRunValue + "');" +
        "'AutoRunUser='+(D '" + SecurityFixes.AutoRunUserKey + "' '" + SecurityFixes.AutoRunValue + "');" +
        "$l=D '" + SecurityFixes.AutoRunKey + "' '" + SecurityFixes.AutoRunLettersValue + "';" +
        "if([string]$l -eq ''){$l=D '" + SecurityFixes.AutoRunUserKey + "' '" + SecurityFixes.AutoRunLettersValue + "'};'AutoRunLetters='+$l;" +
        "'Drives='+((Get-CimInstance Win32_LogicalDisk|ForEach-Object{$_.DeviceID+[int]$_.DriveType}) -join ',');" +
        "$g=D 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation' 'AllowInsecureGuestAuth';" +
        "if([string]$g -eq ''){$g=D 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' 'AllowInsecureGuestAuth'};'InsecureGuest='+$g";

    public async Task<SecurityFacts?> ReadAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Checking security settings…");
        var probe = await commands.RunPowerShellAsync(ProbeScript, ct).ConfigureAwait(false);
        progress.ReportStep(2, 2, "Checking the security chip (TPM)…");
        var tpm = await TpmReader.ReadAsync(commands, ct).ConfigureAwait(false);
        if (probe is not { ExitCode: 0 } && tpm is null) return null;
        return ParseProbe(probe is { ExitCode: 0 } ? probe.StdOut : null, tpm);
    }

    public static SecurityFacts ParseProbe(string? stdout, TpmFacts? tpm)
    {
        var kv = TpmReader.KeyValues(stdout, '=');
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

        // "C:3,D:5": drive letter, colon, Win32_LogicalDisk.DriveType.
        var drives = new Dictionary<char, int>();
        foreach (var part in (Str("Drives") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var c = part.IndexOf(':');
            if (c == 1 && char.IsAsciiLetter(part[0]) && int.TryParse(part[2..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var type))
                drives[char.ToUpperInvariant(part[0])] = type;
        }

        return new(Int("SecureBoot") is { } sb ? sb != 0 : null, Str("Firmware"), Str("Edition"), Int("Encryption"), tpm, Str("SystemDrive") ?? "C:")
        {
            DefenderMode = Str("DefenderMode"), RealTimeProtection = Bool("RealTime"), TamperProtection = Bool("Tamper"),
            Pua = Int("Pua"), NetworkProtection = Int("NetworkProtection"), CloudProtection = Int("CloudProtection"), AsrRules = asr,
            Antivirus = (Str("Antivirus") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Firewall = fw, LlmnrPolicy = Long("Llmnr"), AutoRunPolicy = Long("AutoRun"), AutoRunUserPolicy = Long("AutoRunUser"),
            AutoRunLetterPolicy = Long("AutoRunLetters"), Drives = drives, InsecureGuest = Long("InsecureGuest"),
        };
    }
}
